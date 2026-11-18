<#RMM-TOOL
{
  "name": "install_msi",
  "description": "Download an MSI or EXE installer from an internal URL or UNC path, verify its SHA-256, and install silently. The hash is mandatory so the exact approved binary is what runs.",
  "risk": "high",
  "timeout_sec": 3600,
  "params": { "type": "object", "properties": {
    "source": { "type": "string", "description": "https:// URL or \\\\server\\share\\path" },
    "sha256": { "type": "string" },
    "arguments": { "type": "string", "description": "Extra installer arguments. For MSI, /qn /norestart is always added" }
  }, "required": ["source", "sha256"] }
}
#>
$src = Get-RmmParam 'source'
$want = (Get-RmmParam 'sha256').ToUpper()
$extra = Get-RmmParam 'arguments' ''
$ext = [IO.Path]::GetExtension(($src -split '\?')[0]).ToLower()
if ($ext -notin '.msi', '.exe') { throw 'source must be a .msi or .exe' }
$dst = Join-Path $env:TEMP ("rmm-install-" + [guid]::NewGuid() + $ext)
if ($src -match '^https?://') {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  (New-Object Net.WebClient).DownloadFile($src, $dst)
} else { Copy-Item -LiteralPath $src -Destination $dst }
$sha = [Security.Cryptography.SHA256]::Create()
$fs = [IO.File]::OpenRead($dst); $got = -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('X2') }); $fs.Close()
if ($got -ne $want) { Remove-Item $dst -Force; throw "SHA-256 mismatch: expected $want, got $got" }
$log = "$dst.log"
if ($ext -eq '.msi') {
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$dst`" /qn /norestart /l*v `"$log`" $extra" -Wait -PassThru
} else {
  $p = Start-Process $dst -ArgumentList $extra -Wait -PassThru
}
$tail = if (Test-Path $log) { (Get-Content $log -Tail 30) -join "`n" } else { $null }
Remove-Item $dst -Force -ErrorAction SilentlyContinue
if ($p.ExitCode -notin 0, 3010, 1641) { throw "Installer exited with $($p.ExitCode). Log tail:`n$tail" }
[pscustomobject]@{ exit_code = $p.ExitCode; success = $true; reboot_required = $p.ExitCode -in 3010, 1641; log_tail = $tail }
