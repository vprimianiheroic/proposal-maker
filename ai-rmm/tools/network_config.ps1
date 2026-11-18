<#RMM-TOOL
{
  "name": "network_config",
  "description": "IP-enabled network adapters with addresses, gateways, DNS servers, DHCP, MAC, link speed; plus the routing table summary and DNS client suffixes.",
  "risk": "read",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {} }
}
#>
# Query adapters per index: enumerating all of Win32_NetworkAdapter can take
# minutes on hosts with many virtual/hidden adapters.
$cfg = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
  $ad = @(Get-WmiObject Win32_NetworkAdapter -Filter "Index=$([int]$_.Index)")
  [pscustomobject]@{
    name = if ($ad.Count) { $ad[0].NetConnectionID } else { $null }
    description = $_.Description
    mac = $_.MACAddress
    ip = $_.IPAddress
    subnet = $_.IPSubnet
    gateway = $_.DefaultIPGateway
    dns_servers = $_.DNSServerSearchOrder
    dns_suffix = $_.DNSDomain
    dhcp = $_.DHCPEnabled
    dhcp_server = $_.DHCPServer
    speed_mbps = if ($ad.Count -and $ad[0].Speed) { [math]::Round($ad[0].Speed / 1e6) } else { $null }
  }
}
$routes = Get-WmiObject Win32_IP4RouteTable -Filter "Mask<>'255.255.255.255'" |
  Select-Object -First 40 | ForEach-Object { [pscustomobject]@{ dest = $_.Destination; mask = $_.Mask; next_hop = $_.NextHop; metric = $_.Metric1 } }
[pscustomobject]@{ adapters = @($cfg); routes = @($routes); hosts_file_entries = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[^#\s]' }) }
