<#RMM-TOOL
{
  "name": "abort_reboot",
  "description": "Cancel a pending scheduled shutdown/restart (shutdown /a), e.g. one started by the reboot tool with a delay.",
  "risk": "change",
  "timeout_sec": 30,
  "params": { "type": "object", "properties": {} }
}
#>
$r = Invoke-RmmNative 'shutdown.exe' '/a'
[pscustomobject]@{ exit_code = $r.exit_code; output = $r.output.Trim(); aborted = ($r.exit_code -eq 0) }
