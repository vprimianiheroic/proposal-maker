<#RMM-TOOL
{
  "name": "listening_ports",
  "description": "TCP listening ports and (optionally) established connections with owning process. Use to confirm a service is listening or find what talks to a given host.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "include_established": { "type": "boolean" },
    "remote_like": { "type": "string", "description": "Filter established connections by remote address substring" }
  } }
}
#>
$est = Get-RmmParam 'include_established' $false
$rl = Get-RmmParam 'remote_like'
$names = @{}; Get-WmiObject Win32_Process | ForEach-Object { $names[[int]$_.ProcessId] = $_.Name }
$q = Invoke-RmmNative 'netstat.exe' '-ano','-p','TCP'
$rows = foreach ($l in $q.lines) {
  $f = $l.Trim() -split '\s+'
  if ($f.Count -ne 5 -or $f[0] -ne 'TCP') { continue }
  if ($f[3] -eq 'LISTENING' -or ($est -and $f[3] -eq 'ESTABLISHED' -and (-not $rl -or $f[2] -like "*$rl*"))) {
    [pscustomobject]@{ local = $f[1]; remote = $f[2]; state = $f[3]; pid = [int]$f[4]; process = $names[[int]$f[4]] }
  }
}
$rows | Sort-Object state, local
