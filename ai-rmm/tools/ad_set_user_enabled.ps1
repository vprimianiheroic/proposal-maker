<#RMM-TOOL
{
  "name": "ad_set_user_enabled",
  "description": "Enable or disable an AD user account (e.g. offboarding, or a compromised account). Run on a domain controller.",
  "risk": "high",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "sam_account_name": { "type": "string" },
    "enabled": { "type": "boolean" }
  }, "required": ["sam_account_name", "enabled"] }
}
#>
$sam = (Get-RmmParam 'sam_account_name') -replace '[()*\\]', ''
$en = [bool](Get-RmmParam 'enabled')
$r = ([adsisearcher]"(&(objectCategory=person)(objectClass=user)(sAMAccountName=$sam))").FindOne()
if (-not $r) { throw "User $sam not found." }
$u = $r.GetDirectoryEntry()
$uac = [int]$u.userAccountControl.Value
$before = -not ($uac -band 2)
if ($en) { $uac = $uac -band (-bnot 2) } else { $uac = $uac -bor 2 }
$u.userAccountControl.Value = $uac
$u.CommitChanges()
[pscustomobject]@{ user = $sam; dn = "$($u.distinguishedName)"; enabled_before = $before; enabled_now = $en }
