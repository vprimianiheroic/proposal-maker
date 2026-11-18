<#
.SYNOPSIS
  Installs (or verifies) the AI-RMM agent. Safe to run repeatedly, so it can be
  used interactively, from a GPO computer startup script, or from another RMM.

.DESCRIPTION
  - Picks the right build for this machine: x64 / x86 / ARM64, and the
    "legacy" build for Windows 7 SP1 / Server 2008 R2 / 2012 / 2012 R2 / 8.1.
  - Exits immediately if the agent service already exists and is running
    (unless -Force).
  - Writes a log to %SystemRoot%\Temp\airmm-install.log.

  Written for Windows PowerShell 2.0+ so it runs on stock Windows 7 / 2008 R2.
  (The agent's *tools* need Windows PowerShell 5.1 / WMF 5.1; the script warns
  if it is missing.)

.EXAMPLE
  .\Install-AIRMMAgent.ps1 -Server https://rmm.corp.local:8443 -Token et_xxx -PubKey 'base64=' -TlsPin abcd...

.EXAMPLE
  # GPO: Computer Configuration > Policies > Windows Settings > Scripts > Startup
  # Script: \\corp.local\NETLOGON\airmm\Install-AIRMMAgent.ps1
  # Parameters: -SourceDir \\corp.local\NETLOGON\airmm -ConfigFile \\corp.local\NETLOGON\airmm\airmm.conf
#>
[CmdletBinding()]
param(
  [string]$Server,
  [string]$Token,
  [string]$PubKey,
  [string]$TlsPin,
  # Folder holding rmm-agent-windows-<arch>[-legacy].exe (defaults to this script's folder)
  [string]$SourceDir,
  # Optional key=value file with server/token/pubkey/tlspin, so secrets aren't on the command line.
  [string]$ConfigFile,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$log = Join-Path $env:SystemRoot 'Temp\airmm-install.log'
function Log([string]$m) {
  $line = '{0} {1}' -f (Get-Date -Format 's'), $m
  Write-Host $line
  try { Add-Content -Path $log -Value $line } catch { }
}

try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script elevated (or as SYSTEM via GPO startup script).'
  }

  if (-not $SourceDir) { $SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
  if ($ConfigFile) {
    foreach ($l in (Get-Content -Path $ConfigFile)) {
      if ($l -match '^\s*([a-z_]+)\s*=\s*(.+?)\s*$') {
        switch ($matches[1]) {
          'server' { if (-not $Server) { $Server = $matches[2] } }
          'token'  { if (-not $Token)  { $Token  = $matches[2] } }
          'pubkey' { if (-not $PubKey) { $PubKey = $matches[2] } }
          'tlspin' { if (-not $TlsPin) { $TlsPin = $matches[2] } }
        }
      }
    }
  }

  $svc = Get-Service -Name 'AIRMMAgent' -ErrorAction SilentlyContinue
  if ($svc -and -not $Force) {
    if ($svc.Status -ne 'Running') { Log 'Agent installed but not running; starting it.'; Start-Service AIRMMAgent }
    else { Log 'Agent already installed and running. Nothing to do.' }
    exit 0
  }

  # --- choose build ---
  $arch = $env:PROCESSOR_ARCHITEW6432
  if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
  switch ($arch.ToUpper()) {
    'AMD64' { $goarch = 'amd64' }
    'ARM64' { $goarch = 'arm64' }
    default { $goarch = '386' }
  }
  $ver = [Environment]::OSVersion.Version
  $legacy = ($ver.Major -lt 10)   # 6.1 = 7/2008R2, 6.2 = 8/2012, 6.3 = 8.1/2012R2
  if ($ver.Major -eq 6 -and $ver.Minor -lt 1) { throw "Windows $ver is not supported (minimum: Windows 7 SP1 / Server 2008 R2)." }
  if ($legacy -and $goarch -eq 'arm64') { throw 'Unsupported combination.' }
  $name = 'rmm-agent-windows-' + $goarch + $(if ($legacy) { '-legacy' } else { '' }) + '.exe'
  $src = Join-Path $SourceDir $name
  if (-not (Test-Path $src)) { throw "Agent binary not found: $src" }
  Log "OS $ver ($arch) -> $name"

  $psv = $PSVersionTable.PSVersion
  try {
    $eng = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' -ErrorAction Stop).PowerShellVersion
    if ($eng) { $psv = [version]$eng }
  } catch { }
  if ($psv.Major -lt 5) { Log "WARNING: Windows PowerShell $psv detected. Most AI-RMM tools need WMF 5.1. Install WMF 5.1 (KB3191566 / KB3191564) on this machine." }

  # Copy locally first: running an .exe from a UNC path as SYSTEM is fragile.
  $tmp = Join-Path $env:SystemRoot ('Temp\' + $name)
  Copy-Item -Path $src -Destination $tmp -Force

  $a = @('install')
  if ($Server) {
    if (-not $Token -or -not $PubKey) { throw 'With -Server you must also give -Token and -PubKey.' }
    $a += @('--server', $Server, '--token', $Token, '--pubkey', $PubKey)
    if ($TlsPin) { $a += @('--tls-pin', $TlsPin) }
  }
  $out = & $tmp @a 2>&1
  $code = $LASTEXITCODE
  $out | ForEach-Object { Log "  $_" }
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  if ($code -ne 0) { throw "rmm-agent install exited with $code" }
  Log 'AI-RMM agent installed.'
  exit 0
} catch {
  Log ("ERROR: " + $_.Exception.Message)
  exit 1
}
