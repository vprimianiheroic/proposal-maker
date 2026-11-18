<#RMM-TOOL
{
  "name": "ad_user_lookup",
  "description": "Look up Active Directory users by sAMAccountName, UPN, display name or email (wildcards allowed). Returns enabled/locked state, password age/expiry flags, last logon, group membership. Run on any domain-joined machine (a DC is most accurate).",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "query": { "type": "string", "description": "e.g. jsmith, j*smith, John Smith, jsmith@corp.com" },
    "max": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Default 20" },
    "include_groups": { "type": "boolean", "description": "Default true" }
  }, "required": ["query"] }
}
#>
$q = (Get-RmmParam 'query') -replace '[()\\]', ''
$max = [int](Get-RmmParam 'max' 20)
$withGroups = Get-RmmParam 'include_groups' $true
$s = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$q)(userPrincipalName=$q)(displayName=$q)(mail=$q)(cn=$q)))"
$s.PageSize = 200; $s.SizeLimit = $max
'samaccountname','userprincipalname','displayname','mail','useraccountcontrol','lockouttime','pwdlastset','lastlogontimestamp','memberof','distinguishedname','badpwdcount','accountexpires','whencreated','title','department','description' | ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
function FT($v) { if ($v -and [int64]$v -gt 0 -and [int64]$v -lt [int64]::MaxValue) { [datetime]::FromFileTimeUtc([int64]$v).ToString('s') + 'Z' } else { $null } }
foreach ($r in $s.FindAll()) {
  $p = $r.Properties
  $uac = [int]($p['useraccountcontrol'] | Select-Object -First 1)
  $lock = [int64]($p['lockouttime'] | Select-Object -First 1)
  [pscustomobject]@{
    sam = "$($p['samaccountname'])"; upn = "$($p['userprincipalname'])"; display_name = "$($p['displayname'])"; mail = "$($p['mail'])"
    title = "$($p['title'])"; department = "$($p['department'])"; description = "$($p['description'])"
    enabled = -not ($uac -band 2); locked_out = ($lock -gt 0); password_never_expires = [bool]($uac -band 0x10000)
    password_last_set = FT ($p['pwdlastset'] | Select-Object -First 1)
    last_logon_approx = FT ($p['lastlogontimestamp'] | Select-Object -First 1)
    bad_password_count = "$($p['badpwdcount'])"
    account_expires = FT ($p['accountexpires'] | Select-Object -First 1)
    created = "$($p['whencreated'])"
    dn = "$($p['distinguishedname'])"
    groups = if ($withGroups) { @($p['memberof'] | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) } else { $null }
  }
}
