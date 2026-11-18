<#RMM-TOOL
{
  "name": "firewall_status",
  "description": "Windows Firewall profile state (domain/private/public), current network profile, and optionally enabled inbound allow rules matching a filter.",
  "risk": "read",
  "timeout_sec": 90,
  "params": { "type": "object", "properties": {
    "rule_like": { "type": "string", "description": "If set, list enabled inbound rules whose name contains this text" }
  } }
}
#>
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$names = @{1='domain';2='private';4='public'}
$profiles = foreach ($k in 1,2,4) {
  [pscustomobject]@{ profile = $names[$k]; enabled = $fw.FirewallEnabled($k); default_inbound_block = $fw.DefaultInboundAction($k) -eq 0; active = (($fw.CurrentProfileTypes -band $k) -ne 0) }
}
$rules = $null
$like = Get-RmmParam 'rule_like'
if ($like) {
  $rules = @($fw.Rules | Where-Object { $_.Enabled -and $_.Direction -eq 1 -and $_.Action -eq 1 -and $_.Name -like "*$like*" } | Select-Object -First 100 | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; protocol = $_.Protocol; local_ports = $_.LocalPorts; remote_addresses = $_.RemoteAddresses; app = $_.ApplicationName; profiles = $_.Profiles }
  })
}
[pscustomobject]@{ profiles = @($profiles); rules = $rules }
