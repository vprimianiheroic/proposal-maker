<#RMM-TOOL
{
  "name": "ad_locked_out_users",
  "description": "List currently locked-out AD user accounts. On a DC, also return recent lockout events (4740) showing the source computer, which identifies where bad passwords come from.",
  "risk": "read",
  "timeout_sec": 120,
  "params": { "type": "object", "properties": {
    "hours": { "type": "number", "minimum": 1, "maximum": 168, "description": "Lookback for 4740 events. Default 24" }
  } }
}
#>
$hours = [double](Get-RmmParam 'hours' 24)
$s = [adsisearcher]'(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))'
$s.PageSize = 500
'samaccountname','displayname','lockouttime','badpwdcount' | ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
$domainPolicy = ([adsi]"LDAP://$(([adsi]'LDAP://RootDSE').defaultNamingContext)")
$durTicks = [math]::Abs([int64]$domainPolicy.ConvertLargeIntegerToInt64($domainPolicy.lockoutDuration.Value))
$users = foreach ($r in $s.FindAll()) {
  $t = [int64]($r.Properties['lockouttime'] | Select-Object -First 1)
  if ($t -le 0) { continue }
  $when = [datetime]::FromFileTimeUtc($t)
  # lockoutTime stays set until next logon; skip ones whose lockout duration already elapsed.
  if ($durTicks -gt 0 -and $when.AddTicks($durTicks) -lt (Get-Date).ToUniversalTime()) { continue }
  [pscustomobject]@{ sam = "$($r.Properties['samaccountname'])"; display_name = "$($r.Properties['displayname'])"; locked_at_utc = $when.ToString('s'); bad_password_count = "$($r.Properties['badpwdcount'])" }
}
$events = $null
if ((Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4) {
  try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddHours(-$hours) } -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ time = $_.TimeCreated.ToString('s'); user = $_.Properties[0].Value; source_computer = $_.Properties[1].Value }
    })
  } catch { $events = @() }
}
[pscustomobject]@{ locked_out = @($users); lockout_events_this_dc = $events; lockout_duration_minutes = [math]::Round($durTicks / 6e8) }
