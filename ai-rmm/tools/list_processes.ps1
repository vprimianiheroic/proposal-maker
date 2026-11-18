<#RMM-TOOL
{
  "name": "list_processes",
  "description": "Running processes sorted by CPU time or memory, with owner and command line. Use for 'machine is slow' triage.",
  "risk": "read",
  "timeout_sec": 90,
  "params": { "type": "object", "properties": {
    "sort_by": { "type": "string", "enum": ["memory", "cpu"], "description": "Default memory" },
    "top": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Default 25" },
    "name_like": { "type": "string" }
  } }
}
#>
$sort = Get-RmmParam 'sort_by' 'memory'
$top = [int](Get-RmmParam 'top' 25)
$like = Get-RmmParam 'name_like'
$procs = Get-WmiObject Win32_Process | Where-Object { -not $like -or $_.Name -like "*$like*" }
$rows = foreach ($p in $procs) {
  $owner = $null
  try { $o = $p.GetOwner(); if ($o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch { }
  [pscustomobject]@{
    pid = $p.ProcessId; name = $p.Name; owner = $owner
    memory_mb = [math]::Round($p.WorkingSetSize / 1MB, 1)
    cpu_seconds = [math]::Round(($p.KernelModeTime + $p.UserModeTime) / 1e7, 1)
    threads = $p.ThreadCount; handles = $p.HandleCount
    started = if ($p.CreationDate) { $p.ConvertToDateTime($p.CreationDate).ToString('s') } else { $null }
    command_line = $p.CommandLine
  }
}
$key = if ($sort -eq 'cpu') { 'cpu_seconds' } else { 'memory_mb' }
$os = Get-WmiObject Win32_OperatingSystem
$load = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
[pscustomobject]@{
  cpu_load_pct = $load
  memory_used_pct = [math]::Round(100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize), 1)
  process_count = @($procs).Count
  processes = @($rows | Sort-Object $key -Descending | Select-Object -First $top)
}
