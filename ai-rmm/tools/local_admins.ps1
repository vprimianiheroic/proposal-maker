<#RMM-TOOL
{
  "name": "local_admins",
  "description": "Members of a local group (default Administrators), including domain users and groups. Works on every Windows version.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "group": { "type": "string", "description": "Local group name, default Administrators. E.g. 'Remote Desktop Users'" }
  } }
}
#>
$g = Get-RmmParam 'group' 'Administrators'
$grp = [ADSI]"WinNT://$env:COMPUTERNAME/$g,group"
@($grp.psbase.Invoke('Members')) | ForEach-Object {
  $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
  $class = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
  $parts = $path -replace '^WinNT://', '' -split '/'
  [pscustomobject]@{
    member = ($parts[-2..-1] -join '\')
    class = $class
    scope = if ($parts[-2] -eq $env:COMPUTERNAME) { 'local' } else { 'domain' }
  }
}
