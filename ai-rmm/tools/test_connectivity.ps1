<#RMM-TOOL
{
  "name": "test_connectivity",
  "description": "From this machine: DNS-resolve a host, ping it, and optionally test TCP ports. Use to check reachability of file servers, DCs, PLC/HMI gateways, printers, license servers, etc.",
  "risk": "read",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {
    "host": { "type": "string" },
    "ports": { "type": "array", "items": { "type": "integer" }, "description": "TCP ports to test, e.g. [445, 3389, 502]" },
    "ping_count": { "type": "integer", "minimum": 0, "maximum": 20, "description": "Default 4" },
    "timeout_ms": { "type": "integer", "minimum": 100, "maximum": 30000, "description": "Per-port connect timeout, default 2000" }
  }, "required": ["host"] }
}
#>
$h = Get-RmmParam 'host'
$count = [int](Get-RmmParam 'ping_count' 4)
$tmo = [int](Get-RmmParam 'timeout_ms' 2000)
$dns = $null; $dnsErr = $null
try { $dns = @([System.Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString }) } catch { $dnsErr = $_.Exception.InnerException.Message }
$pings = @()
$p = New-Object System.Net.NetworkInformation.Ping
for ($i = 0; $i -lt $count; $i++) {
  try { $r = $p.Send($h, 2000); $pings += [pscustomobject]@{ status = "$($r.Status)"; ms = $r.RoundtripTime } }
  catch { $pings += [pscustomobject]@{ status = 'error'; ms = $null } }
}
$ports = foreach ($port in @(Get-RmmParam 'ports' @())) {
  $c = New-Object System.Net.Sockets.TcpClient
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $open = $false; $err = $null
  try { $ar = $c.BeginConnect($h, [int]$port, $null, $null); if ($ar.AsyncWaitHandle.WaitOne($tmo)) { $c.EndConnect($ar); $open = $true } else { $err = 'timeout' } }
  catch { $err = $_.Exception.InnerException.Message }
  finally { $c.Close() }
  [pscustomobject]@{ port = $port; open = $open; ms = $sw.ElapsedMilliseconds; error = $err }
}
$ok = @($pings | Where-Object { $_.status -eq 'Success' })
[pscustomobject]@{
  host = $h; resolved = $dns; dns_error = $dnsErr
  ping_sent = $count; ping_received = $ok.Count
  ping_avg_ms = if ($ok.Count) { [math]::Round(($ok | Measure-Object ms -Average).Average, 1) } else { $null }
  ports = @($ports)
}
