<#RMM-TOOL
{
  "name": "ad_unlock_user",
  "description": "Unlock a locked-out AD user account. Run on a domain controller (the agent runs as SYSTEM, which on a DC has rights to the directory).",
  "risk": "change",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "sam_account_name": { "type": "string" }
  }, "required": ["sam_account_name"] }
}
#>
$sam = (Get-RmmParam 'sam_account_name') -replace '[()*\\]', ''
$s = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(sAMAccountName=$sam))"
$r = $s.FindOne()
if (-not $r) { throw "User $sam not found." }
$u = $r.GetDirectoryEntry()
$before = [int64]$u.ConvertLargeIntegerToInt64($u.lockoutTime.Value)
$u.Properties['lockoutTime'].Value = 0
$u.CommitChanges()
[pscustomobject]@{ user = $sam; dn = "$($u.distinguishedName)"; was_locked = ($before -gt 0); unlocked = $true }
