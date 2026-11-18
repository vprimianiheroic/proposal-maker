<#RMM-TOOL
{
  "name": "event_log_query",
  "description": "Query a Windows event log (System, Application, Security, or any channel such as Microsoft-Windows-GroupPolicy/Operational) by level, source, event IDs and time window.",
  "risk": "read",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {
    "log": { "type": "string", "description": "Log/channel name. Default System" },
    "hours": { "type": "number", "minimum": 0.1, "maximum": 2160, "description": "Look back this many hours. Default 24" },
    "level": { "type": "string", "enum": ["critical", "error", "warning", "information", "error_and_worse", "warning_and_worse", "any"], "description": "Default error_and_worse" },
    "source": { "type": "string", "description": "Provider name, e.g. Service Control Manager, disk, Microsoft-Windows-Kernel-Power" },
    "event_ids": { "type": "array", "items": { "type": "integer" } },
    "max": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "Default 50" },
    "message_like": { "type": "string" }
  } }
}
#>
$log = Get-RmmParam 'log' 'System'
$hours = [double](Get-RmmParam 'hours' 24)
$level = Get-RmmParam 'level' 'error_and_worse'
$max = [int](Get-RmmParam 'max' 50)
$filter = @{ LogName = $log; StartTime = (Get-Date).AddHours(-$hours) }
switch ($level) {
  'critical' { $filter.Level = 1 }
  'error' { $filter.Level = 2 }
  'warning' { $filter.Level = 3 }
  'information' { $filter.Level = 4 }
  'error_and_worse' { $filter.Level = 1,2 }
  'warning_and_worse' { $filter.Level = 1,2,3 }
}
$src = Get-RmmParam 'source'
if ($src) { $filter.ProviderName = $src }
$ids = Get-RmmParam 'event_ids'
if ($ids) { $filter.Id = [int[]]$ids }
$like = Get-RmmParam 'message_like'
try {
  $events = Get-WinEvent -FilterHashtable $filter -MaxEvents ($max * $(if ($like) { 10 } else { 1 })) -ErrorAction Stop
} catch {
  if ($_.Exception.Message -like '*No events were found*') { return @() }
  throw
}
$events | Where-Object { -not $like -or $_.Message -like "*$like*" } | Select-Object -First $max | ForEach-Object {
  $msg = $_.Message; if ($msg -and $msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) + '...' }
  [pscustomobject]@{ time = $_.TimeCreated.ToString('s'); id = $_.Id; level = $_.LevelDisplayName; source = $_.ProviderName; message = $msg }
}
