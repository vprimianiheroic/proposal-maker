<#RMM-TOOL
{
  "name": "process_kill",
  "description": "Terminate a process by PID or by exact image name (e.g. hung_app.exe). Refuses critical system processes.",
  "risk": "change",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "pid": { "type": "integer" },
    "name": { "type": "string", "description": "Image name including .exe; kills all instances" },
    "tree": { "type": "boolean", "description": "Kill child processes too" }
  } }
}
#>
$procId = Get-RmmParam 'pid'
$name = Get-RmmParam 'name'
if (-not $procId -and -not $name) { throw 'Give pid or name.' }
$protected = 'system','smss.exe','csrss.exe','wininit.exe','winlogon.exe','services.exe','lsass.exe','svchost.exe','rmm-agent.exe','lsaiso.exe','fontdrvhost.exe','dwm.exe'
$tkArgs = @('/F')
if (Get-RmmParam 'tree' $false) { $tkArgs += '/T' }
$targets = if ($procId) { @(Get-WmiObject Win32_Process -Filter "ProcessId=$([int]$procId)") } else { @(Get-WmiObject Win32_Process -Filter "Name='$($name -replace "'", "''")'") }
if (-not $targets) { throw 'No matching process.' }
foreach ($t in $targets) {
  if ($protected -contains $t.Name.ToLower()) { throw "Refusing to kill protected process $($t.Name)." }
}
foreach ($t in $targets) {
  $r = Invoke-RmmNative 'taskkill.exe' ($tkArgs + @('/PID', "$($t.ProcessId)"))
  [pscustomobject]@{ pid = $t.ProcessId; name = $t.Name; exit_code = $r.exit_code; output = $r.output.Trim() }
}
