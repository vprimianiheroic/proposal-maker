<#RMM-TOOL
{
  "name": "list_shares",
  "description": "SMB shares on this machine with path and share-level permissions; optionally current open sessions.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "include_sessions": { "type": "boolean" }
  } }
}
#>
$shares = Get-WmiObject Win32_Share | ForEach-Object {
  $acl = $null
  try {
    $sec = Get-WmiObject Win32_LogicalShareSecuritySetting -Filter "Name='$($_.Name -replace "'", "''")'" -ErrorAction Stop
    if ($sec) {
      $acl = @($sec.GetSecurityDescriptor().Descriptor.DACL | ForEach-Object {
        $r = switch ($_.AccessMask) { 2032127 { 'Full' } 1245631 { 'Change' } 1179817 { 'Read' } default { "$_" } }
        "$($_.Trustee.Domain)\$($_.Trustee.Name):$r"
      })
    }
  } catch { }
  [pscustomobject]@{ name = $_.Name; path = $_.Path; description = $_.Description; type = $_.Type; permissions = $acl }
}
$sess = $null
if (Get-RmmParam 'include_sessions' $false) {
  $sess = @(Get-WmiObject Win32_ServerConnection | ForEach-Object { [pscustomobject]@{ user = $_.UserName; from = $_.ComputerName; share = $_.ShareName; seconds = $_.ActiveTime } })
}
[pscustomobject]@{ shares = @($shares); sessions = $sess }
