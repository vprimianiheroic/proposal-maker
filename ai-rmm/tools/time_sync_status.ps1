<#RMM-TOOL
{
  "name": "time_sync_status",
  "description": "Windows Time service status and configured source (w32tm), plus offset against a reference host. Clock skew over 5 minutes breaks Kerberos logons; skew also corrupts production/MES timestamps.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "compare_to": { "type": "string", "description": "Host to measure offset against (e.g. a DC or the NTP source). Optional" }
  } }
}
#>
$st = Invoke-RmmNative 'w32tm.exe' '/query','/status'
$src = Invoke-RmmNative 'w32tm.exe' '/query','/source'
$cfg = Invoke-RmmNative 'w32tm.exe' '/query','/configuration'
$off = $null
$ref = Get-RmmParam 'compare_to'
if ($ref) { $off = (Invoke-RmmNative 'w32tm.exe' '/stripchart',"/computer:$ref",'/samples:3','/dataonly').output }
[pscustomobject]@{
  service_state = (Get-WmiObject Win32_Service -Filter "Name='W32Time'").State
  source = $src.output.Trim()
  status = $st.output
  config_type = (($cfg.lines | Where-Object { $_ -match '^\s*Type:' }) -join '; ')
  ntp_server = (($cfg.lines | Where-Object { $_ -match '^\s*NtpServer:' }) -join '; ')
  local_time = (Get-Date).ToString('o')
  offset_samples = $off
}
