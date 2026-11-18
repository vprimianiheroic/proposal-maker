<#RMM-TOOL
{
  "name": "restart_print_spooler",
  "description": "Fix stuck printing: stop the spooler, optionally purge all queued jobs, start it again. Purging deletes every pending print job on this machine.",
  "risk": "change",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {
    "purge_queue": { "type": "boolean", "description": "Default true" }
  } }
}
#>
$purge = Get-RmmParam 'purge_queue' $true
Stop-Service Spooler -Force
(Get-Service Spooler).WaitForStatus('Stopped', '00:01:00')
$n = 0
if ($purge) {
  $files = @(Get-ChildItem "$env:SystemRoot\System32\spool\PRINTERS" -File -Force -ErrorAction SilentlyContinue)
  $n = $files.Count
  $files | Remove-Item -Force -ErrorAction SilentlyContinue
}
Start-Service Spooler
(Get-Service Spooler).WaitForStatus('Running', '00:01:00')
[pscustomobject]@{ spooler = "$((Get-Service Spooler).Status)"; spool_files_removed = $n }
