<#RMM-TOOL
{
  "name": "network_config",
  "description": "Network interfaces that are up, with IPv4/IPv6 addresses, gateways, DNS servers, DNS suffix, DHCP, MAC and link speed; plus the IPv4 routing table and hosts-file entries.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {} }
}
#>
# .NET NetworkInterface is fast and identical on every Windows version; the
# WMI adapter classes can take minutes on hosts with many virtual adapters.
$adapters = foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
  if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback') { continue }
  $p = $nic.GetIPProperties()
  $v4 = $null; try { $v4 = $p.GetIPv4Properties() } catch { }
  $mac = ($nic.GetPhysicalAddress().GetAddressBytes() | ForEach-Object { $_.ToString('X2') }) -join ':'
  [pscustomobject]@{
    name        = $nic.Name
    description = $nic.Description
    type        = "$($nic.NetworkInterfaceType)"
    mac         = $mac
    speed_mbps  = if ($nic.Speed -gt 0) { [math]::Round($nic.Speed / 1e6) } else { $null }
    ip          = @($p.UnicastAddresses | ForEach-Object { "$($_.Address)/$($_.PrefixLength)" })
    gateway     = @($p.GatewayAddresses | ForEach-Object { "$($_.Address)" })
    dns_servers = @($p.DnsAddresses | ForEach-Object { "$_" })
    dns_suffix  = $p.DnsSuffix
    dhcp        = if ($v4) { $v4.IsDhcpEnabled } else { $null }
    dhcp_server = @($p.DhcpServerAddresses | ForEach-Object { "$_" })
  }
}
$routes = @()
$r = Invoke-RmmNative 'route.exe' 'print','-4'
$inTable = $false
foreach ($l in $r.lines) {
  if ($l -match '^\s*Network Destination') { $inTable = $true; continue }
  if ($inTable -and $l -match '^\s*=+') { if ($routes.Count) { break } else { continue } }
  if ($inTable -and $l -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)') {
    if ($matches[2] -ne '255.255.255.255') {
      $routes += [pscustomobject]@{ dest = $matches[1]; mask = $matches[2]; gateway = $matches[3]; interface = $matches[4]; metric = [int]$matches[5] }
    }
  }
}
$hosts = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' })
[pscustomobject]@{ adapters = @($adapters); routes = @($routes | Select-Object -First 60); hosts_file_entries = $hosts }
