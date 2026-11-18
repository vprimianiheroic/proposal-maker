<#RMM-TOOL
{
  "name": "install_windows_updates",
  "description": "Search, download and install applicable Windows updates through the Windows Update Agent (honours WSUS). Optionally reboots afterwards if required (with a delay and user warning); otherwise check reboot_required and use the reboot tool. Ideal for a save_schedule maintenance window.",
  "risk": "high",
  "timeout_sec": 7200,
  "params": { "type": "object", "properties": {
    "categories": { "type": "array", "items": { "type": "string" }, "description": "Limit to categories by name, e.g. [\"Security Updates\", \"Critical Updates\"]. Default: all software updates" },
    "kb_ids": { "type": "array", "items": { "type": "string" }, "description": "Only these KBs, e.g. [\"KB5034441\"]" },
    "exclude_drivers": { "type": "boolean", "description": "Default true" },
    "reboot_if_required": { "type": "boolean", "description": "Schedule a restart when an update requires it. Default false" },
    "reboot_delay_seconds": { "type": "integer", "minimum": 0, "maximum": 86400, "description": "Default 300" },
    "skip_if_user_logged_on": { "type": "boolean", "description": "With reboot_if_required: don't restart while someone is logged on interactively. Default true" }
  } }
}
#>
$cats = @(Get-RmmParam 'categories' @())
$kbs = @(Get-RmmParam 'kb_ids' @() | ForEach-Object { $_ -replace '^KB', '' })
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'AI-RMM'
$crit = "IsInstalled=0 and IsHidden=0"
if (Get-RmmParam 'exclude_drivers' $true) { $crit += " and Type='Software'" }
$found = $session.CreateUpdateSearcher().Search($crit).Updates
$todo = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $found) {
  if ($kbs.Count -and -not ($u.KBArticleIDs | Where-Object { $kbs -contains $_ })) { continue }
  if ($cats.Count -and -not ($u.Categories | Where-Object { $cats -contains $_.Name })) { continue }
  if (-not $u.EulaAccepted) { $u.AcceptEula() }
  [void]$todo.Add($u)
}
if ($todo.Count -eq 0) { return [pscustomobject]@{ installed = 0; message = 'No applicable updates.' } }
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $todo; [void]$dl.Download()
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $todo
$res = $inst.Install()
$codes = @{0='NotStarted';1='InProgress';2='Succeeded';3='SucceededWithErrors';4='Failed';5='Aborted'}
$detail = for ($i = 0; $i -lt $todo.Count; $i++) {
  [pscustomobject]@{ title = $todo.Item($i).Title; result = $codes[[int]$res.GetUpdateResult($i).ResultCode] }
}
$reboot = 'not requested'
if ($res.RebootRequired -and (Get-RmmParam 'reboot_if_required' $false)) {
  $user = (Get-WmiObject Win32_ComputerSystem).UserName
  if ($user -and (Get-RmmParam 'skip_if_user_logged_on' $true)) {
    $reboot = "skipped: $user is logged on"
  } else {
    $delay = [int](Get-RmmParam 'reboot_delay_seconds' 300)
    $r = Invoke-RmmNative 'shutdown.exe' '/r','/t',"$delay",'/c','IT maintenance: Windows updates were installed. This computer will restart.','/d','p:2:17'
    $reboot = if ($r.exit_code -eq 0) { "scheduled in $delay s" } else { "failed: $($r.output)" }
  }
}
[pscustomobject]@{ overall = $codes[[int]$res.ResultCode]; reboot_required = $res.RebootRequired; reboot = $reboot; updates = @($detail) }
