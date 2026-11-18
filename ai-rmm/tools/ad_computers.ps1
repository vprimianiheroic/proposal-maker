<#RMM-TOOL
{
  "name": "ad_computers",
  "description": "List enabled Active Directory computer accounts that logged on within N days, with DNS name, OS and last logon. Run on any domain-joined machine (a DC is fastest). Used to find machines without the agent.",
  "risk": "read",
  "timeout_sec": 180,
  "params": { "type": "object", "properties": {
    "active_days": { "type": "integer", "minimum": 1, "maximum": 3650, "description": "Default 30" },
    "name_like": { "type": "string", "description": "Wildcard on computer name, e.g. PLANT1-*" },
    "os_like": { "type": "string", "description": "Substring of operatingSystem, e.g. Windows 10, Server" },
    "include_servers": { "type": "boolean", "description": "Default true" },
    "max": { "type": "integer", "minimum": 1, "maximum": 20000, "description": "Default 5000" }
  } }
}
#>
$days = [int](Get-RmmParam 'active_days' 30)
$like = (Get-RmmParam 'name_like' '*') -replace '[()\\]', ''
if (-not $like) { $like = '*' }
$os = Get-RmmParam 'os_like'
$servers = Get-RmmParam 'include_servers' $true
$max = [int](Get-RmmParam 'max' 5000)
$cut = (Get-Date).AddDays(-$days).ToFileTimeUtc()
# Enabled computers (bit 2 of userAccountControl clear), Windows only.
$f = "(&(objectCategory=computer)(name=$like)(operatingSystem=Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp>=$cut))"
$s = [adsisearcher]$f
$s.PageSize = 500; $s.SizeLimit = $max
'name','dnshostname','operatingsystem','operatingsystemversion','lastlogontimestamp','distinguishedname' | ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
foreach ($r in $s.FindAll()) {
  $p = $r.Properties
  $o = "$($p['operatingsystem'])"
  if ($os -and $o -notlike "*$os*") { continue }
  if (-not $servers -and $o -like '*Server*') { continue }
  [pscustomobject]@{
    name = "$($p['name'])".ToUpper()
    dns_name = "$($p['dnshostname'])"
    os = $o
    os_version = "$($p['operatingsystemversion'])"
    last_logon = [datetime]::FromFileTimeUtc([int64]($p['lastlogontimestamp'] | Select-Object -First 1)).ToString('yyyy-MM-dd')
    dn = "$($p['distinguishedname'])"
  }
}
