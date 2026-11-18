<#RMM-TOOL
{
  "name": "installed_software",
  "description": "Installed applications from the uninstall registry keys (64- and 32-bit), with version, publisher, install date and uninstall string.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "name_like": { "type": "string", "description": "Substring match on display name or publisher" }
  } }
}
#>
$like = Get-RmmParam 'name_like'
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent -and (-not $like -or $_.DisplayName -like "*$like*" -or $_.Publisher -like "*$like*") } |
  Sort-Object DisplayName -Unique | ForEach-Object {
    [pscustomobject]@{
      name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher
      install_date = $_.InstallDate; uninstall = $_.UninstallString
      arch = if ($_.PSPath -like '*WOW6432Node*') { 'x86' } else { 'native' }
    }
  }
