<#RMM-TOOL
{
  "name": "ad_stale_computers",
  "description": "AD computer accounts whose lastLogonTimestamp is older than N days (candidates for cleanup), with OS and enabled state. Read-only.",
  "risk": "read",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {
    "days": { "type": "integer", "minimum": 14, "maximum": 3650, "description": "Default 90" }
  } }
}
#>
$days = [int](Get-RmmParam 'days' 90)
$cut = (Get-Date).AddDays(-$days).ToFileTimeUtc()
$s = [adsisearcher]"(&(objectCategory=computer)(lastLogonTimestamp<=$cut))"
$s.PageSize = 500
'name','operatingsystem','lastlogontimestamp','useraccountcontrol','distinguishedname' | ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
foreach ($r in $s.FindAll()) {
  $p = $r.Properties
  [pscustomobject]@{
    name = "$($p['name'])"; os = "$($p['operatingsystem'])"
    last_logon = [datetime]::FromFileTimeUtc([int64]($p['lastlogontimestamp'] | Select-Object -First 1)).ToString('yyyy-MM-dd')
    enabled = -not ([int]($p['useraccountcontrol'] | Select-Object -First 1) -band 2)
    dn = "$($p['distinguishedname'])"
  }
}
