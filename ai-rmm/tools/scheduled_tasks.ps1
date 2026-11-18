<#RMM-TOOL
{
  "name": "scheduled_tasks",
  "description": "Scheduled tasks with state, last/next run and last result. By default hides Microsoft built-in tasks.",
  "risk": "read",
  "timeout_sec": 90,
  "params": { "type": "object", "properties": {
    "include_microsoft": { "type": "boolean" },
    "name_like": { "type": "string" },
    "failed_only": { "type": "boolean", "description": "Only tasks whose last result was not 0" }
  } }
}
#>
$incMs = Get-RmmParam 'include_microsoft' $false
$like = Get-RmmParam 'name_like'
$failed = Get-RmmParam 'failed_only' $false
$q = Invoke-RmmNative 'schtasks.exe' '/query','/fo','csv','/v'
if ($q.exit_code -ne 0) { throw "schtasks failed: $($q.output)" }
$rows = $q.lines | ConvertFrom-Csv
$rows | Where-Object {
  $_.TaskName -ne 'TaskName' -and
  ($incMs -or $_.TaskName -notlike '\Microsoft\*') -and
  (-not $like -or $_.TaskName -like "*$like*") -and
  (-not $failed -or ($_.'Last Result' -ne '0' -and $_.'Last Result' -ne '267011'))
} | Sort-Object TaskName -Unique | ForEach-Object {
  [pscustomobject]@{
    name = $_.TaskName; status = $_.Status; next_run = $_.'Next Run Time'; last_run = $_.'Last Run Time'
    last_result = $_.'Last Result'; run_as = $_.'Run As User'; action = $_.'Task To Run'; schedule = $_.'Schedule Type'
  }
}
