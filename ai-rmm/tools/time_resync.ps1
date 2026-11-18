<#RMM-TOOL
{
  "name": "time_resync",
  "description": "Force a Windows Time resync (w32tm /resync), restarting W32Time if needed. Optionally reset the machine to use the domain hierarchy (NT5DS) instead of a manual NTP source.",
  "risk": "change",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {
    "use_domain_hierarchy": { "type": "boolean", "description": "Set W32Time to sync from the domain (not for the PDC emulator). Default false" }
  } }
}
#>
$out = @()
if (Get-RmmParam 'use_domain_hierarchy' $false) {
  $out += (Invoke-RmmNative 'w32tm.exe' '/config','/syncfromflags:domhier','/update').output
}
if ((Get-Service W32Time).Status -ne 'Running') { Start-Service W32Time }
$r = Invoke-RmmNative 'w32tm.exe' '/resync','/force'
if ($r.exit_code -ne 0) { Restart-Service W32Time -Force; Start-Sleep 3; $r = Invoke-RmmNative 'w32tm.exe' '/resync','/force' }
$out += $r.output
[pscustomobject]@{ exit_code = $r.exit_code; output = ($out -join "`n").Trim(); source = (Invoke-RmmNative 'w32tm.exe' '/query','/source').output.Trim(); local_time = (Get-Date).ToString('o') }
