<#RMM-TOOL
{
  "name": "logged_on_users",
  "description": "Interactive and RDP sessions on the machine (quser), with idle time and logon time. Check before rebooting or restarting user-facing apps.",
  "risk": "read",
  "timeout_sec": 30,
  "params": { "type": "object", "properties": {} }
}
#>
$q = Invoke-RmmNative 'quser.exe'
$sessions = @()
if ($q.exit_code -eq 0) {
  foreach ($line in ($q.lines | Select-Object -Skip 1)) {
    $l = $line.Substring(1)
    $f = $l -split '\s{2,}'
    if ($f.Count -eq 6) { $user, $session, $id, $state, $idle, $logon = $f }
    elseif ($f.Count -eq 5) { $user, $id, $state, $idle, $logon = $f; $session = $null }
    else { continue }
    $sessions += [pscustomobject]@{ user = $user.Trim(); session = $session; id = $id; state = $state; idle = $idle; logon_time = $logon }
  }
}
[pscustomobject]@{ console_user = (Get-WmiObject Win32_ComputerSystem).UserName; sessions = $sessions }
