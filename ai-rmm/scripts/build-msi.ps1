<#
.SYNOPSIS
  Builds the agent MSIs from dist/ on a Windows machine with the WiX v4+ CLI:
    dotnet tool install --global wix
  Run scripts/build.sh (or the CI workflow) first so dist/ has the binaries.
#>
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$wxs = Join-Path $root 'installer\wix\Package.wxs'
# MSI ProductVersion must be numeric a.b.c
$msiVersion = ($Version -replace '^v', '') -replace '[^0-9.].*$', ''
$builds = @(
  @{ arch = 'x64';   exe = 'rmm-agent-windows-amd64.exe';        name = "airmm-agent-$Version-x64.msi" },
  @{ arch = 'x86';   exe = 'rmm-agent-windows-386.exe';          name = "airmm-agent-$Version-x86.msi" },
  @{ arch = 'arm64'; exe = 'rmm-agent-windows-arm64.exe';        name = "airmm-agent-$Version-arm64.msi" },
  @{ arch = 'x64';   exe = 'rmm-agent-windows-amd64-legacy.exe'; name = "airmm-agent-$Version-x64-legacy.msi" },
  @{ arch = 'x86';   exe = 'rmm-agent-windows-386-legacy.exe';   name = "airmm-agent-$Version-x86-legacy.msi" }
)
foreach ($b in $builds) {
  $exe = Join-Path $dist $b.exe
  if (-not (Test-Path $exe)) { Write-Warning "skip $($b.name): $($b.exe) not built"; continue }
  wix build $wxs -arch $b.arch -d "Version=$msiVersion" -d "AgentExe=$exe" -o (Join-Path $dist $b.name)
  if ($LASTEXITCODE -ne 0) { throw "wix failed for $($b.name)" }
  Write-Host "built $($b.name)"
}
