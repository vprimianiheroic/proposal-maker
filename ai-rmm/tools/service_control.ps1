<#RMM-TOOL
{
  "name": "service_control",
  "description": "Start, stop or restart a Windows service, and/or change its start mode. Waits for the target state and reports before/after.",
  "risk": "change",
  "timeout_sec": 180,
  "params": { "type": "object", "properties": {
    "name": { "type": "string", "description": "Service name (not display name), e.g. Spooler" },
    "action": { "type": "string", "enum": ["start", "stop", "restart", "none"] },
    "start_mode": { "type": "string", "enum": ["Automatic", "Manual", "Disabled"], "description": "Optional new start mode" },
    "force": { "type": "boolean", "description": "Also stop dependent services. Default false" }
  }, "required": ["name", "action"] }
}
#>
$name = Get-RmmParam 'name'
$action = Get-RmmParam 'action'
$mode = Get-RmmParam 'start_mode'
$force = Get-RmmParam 'force' $false
$svc = Get-Service -Name $name
$before = [pscustomobject]@{ status = "$($svc.Status)"; start_mode = (Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'").StartMode }
if ($mode) { Set-Service -Name $svc.Name -StartupType $mode }
switch ($action) {
  'start'   { Start-Service -Name $svc.Name; $svc.WaitForStatus('Running', '00:02:00') }
  'stop'    { Stop-Service -Name $svc.Name -Force:$force; $svc.WaitForStatus('Stopped', '00:02:00') }
  'restart' { Restart-Service -Name $svc.Name -Force:$force; $svc.WaitForStatus('Running', '00:02:00') }
}
$svc.Refresh()
[pscustomobject]@{ service = $svc.Name; display_name = $svc.DisplayName; before = $before; after = [pscustomobject]@{ status = "$($svc.Status)"; start_mode = (Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'").StartMode } }
