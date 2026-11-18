<#RMM-TOOL
{
  "name": "windows_update_status",
  "description": "Recently installed hotfixes, last update install time, WSUS/policy configuration, and (optionally) a live search for missing updates via the Windows Update Agent. The live search can take minutes.",
  "risk": "read",
  "timeout_sec": 900,
  "params": { "type": "object", "properties": {
    "search_missing": { "type": "boolean", "description": "Query WSUS/Microsoft Update for applicable updates not yet installed. Default false" }
  } }
}
#>
$hot = Get-WmiObject Win32_QuickFixEngineering | ForEach-Object {
  $d = $null; try { $d = [datetime]$_.InstalledOn } catch { }
  [pscustomobject]@{ kb = $_.HotFixID; type = $_.Description; installed = if ($d) { $d.ToString('yyyy-MM-dd') } else { $null } }
} | Sort-Object installed -Descending
$wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
$missing = $null
if (Get-RmmParam 'search_missing' $false) {
  $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $r = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $missing = foreach ($u in $r.Updates) {
    [pscustomobject]@{ title = $u.Title; kb = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','; severity = $u.MsrcSeverity; size_mb = [math]::Round($u.MaxDownloadSize / 1MB, 1); reboot_likely = $u.InstallationBehavior.RebootBehavior -ne 0 }
  }
}
[pscustomobject]@{
  hotfix_count = @($hot).Count
  most_recent = @($hot | Select-Object -First 15)
  wsus_server = $wu.WUServer
  target_group = $wu.TargetGroup
  au_options = $au.AUOptions
  no_auto_update = $au.NoAutoUpdate
  missing_updates = $missing
}
