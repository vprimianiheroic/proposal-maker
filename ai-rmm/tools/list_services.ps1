<#RMM-TOOL
{
  "name": "list_services",
  "description": "List Windows services with state, start mode and run-as account. Filter by name/display-name substring, state, or show only auto-start services that are not running (the usual 'what is broken' view).",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "name_like": { "type": "string", "description": "Substring match on service name or display name" },
    "state": { "type": "string", "enum": ["Running", "Stopped", "Paused", "Start Pending", "Stop Pending"] },
    "stopped_auto_only": { "type": "boolean", "description": "Only Automatic services that are not running" }
  } }
}
#>
$like = Get-RmmParam 'name_like'
$state = Get-RmmParam 'state'
$broken = Get-RmmParam 'stopped_auto_only' $false
Get-WmiObject Win32_Service | Where-Object {
  (-not $like -or $_.Name -like "*$like*" -or $_.DisplayName -like "*$like*") -and
  (-not $state -or $_.State -eq $state) -and
  (-not $broken -or ($_.StartMode -eq 'Auto' -and $_.State -ne 'Running'))
} | Sort-Object Name | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; display_name = $_.DisplayName; state = $_.State; start_mode = $_.StartMode; account = $_.StartName; pid = $_.ProcessId; path = $_.PathName }
}
