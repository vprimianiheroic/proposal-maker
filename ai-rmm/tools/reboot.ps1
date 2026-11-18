<#RMM-TOOL
{
  "name": "reboot",
  "description": "Restart the machine after a delay, with a message to logged-on users. Check logged_on_users first and never reboot production-floor (ot) machines without coordinating. Cancel with abort_reboot during the delay.",
  "risk": "high",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "delay_seconds": { "type": "integer", "minimum": 0, "maximum": 86400, "description": "Default 300" },
    "message": { "type": "string" },
    "only_if_pending": { "type": "boolean", "description": "Only reboot if a reboot is pending (updates etc). Default false" }
  } }
}
#>
$delay = [int](Get-RmmParam 'delay_seconds' 300)
$msg = Get-RmmParam 'message' 'IT maintenance: this computer will restart. Please save your work.'
if (Get-RmmParam 'only_if_pending' $false) {
  $p = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
       (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
  if (-not $p) { return [pscustomobject]@{ scheduled = $false; reason = 'no reboot pending' } }
}
$r = Invoke-RmmNative 'shutdown.exe' '/r','/t',"$delay",'/c',$msg,'/d','p:4:1'
if ($r.exit_code -ne 0) { throw "shutdown.exe failed: $($r.output)" }
[pscustomobject]@{ scheduled = $true; restart_at = (Get-Date).AddSeconds($delay).ToString('s'); delay_seconds = $delay }
