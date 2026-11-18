<#RMM-TOOL
{
  "name": "uninstall_software",
  "description": "Silently uninstall an MSI-installed application by exact display name (from installed_software). EXE-based uninstallers are not handled; write a specific tool for those.",
  "risk": "high",
  "timeout_sec": 1800,
  "params": { "type": "object", "properties": {
    "display_name": { "type": "string" }
  }, "required": ["display_name"] }
}
#>
$dn = Get-RmmParam 'display_name'
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$apps = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $dn })
if ($apps.Count -eq 0) { throw "No installed application named '$dn'." }
if ($apps.Count -gt 1) { throw "Multiple entries named '$dn'; refusing to guess." }
$code = $apps[0].PSChildName
if ($code -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { throw "'$dn' is not an MSI product (uninstall string: $($apps[0].UninstallString))." }
$p = Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait -PassThru
if ($p.ExitCode -notin 0, 3010, 1641, 1605) { throw "msiexec /x $code exited with $($p.ExitCode)" }
[pscustomobject]@{ product_code = $code; exit_code = $p.ExitCode; success = $true; reboot_required = $p.ExitCode -in 3010, 1641 }
