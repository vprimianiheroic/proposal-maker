<#RMM-TOOL
{
  "name": "clear_temp_files",
  "description": "Free disk space by deleting old files from Windows temp, user temp folders, Windows Update download cache and (optionally) the recycle bin. dry_run (default true) only reports what would be removed.",
  "risk": "change",
  "timeout_sec": 1800,
  "params": { "type": "object", "properties": {
    "older_than_days": { "type": "integer", "minimum": 1, "maximum": 365, "description": "Default 7" },
    "dry_run": { "type": "boolean", "description": "Default true" },
    "include_wu_cache": { "type": "boolean", "description": "Clear SoftwareDistribution\\Download (stops wuauserv briefly). Default false" },
    "include_recycle_bin": { "type": "boolean", "description": "Default false" }
  } }
}
#>
$days = [int](Get-RmmParam 'older_than_days' 7)
$dry = Get-RmmParam 'dry_run' $true
$cut = (Get-Date).AddDays(-$days)
$roots = @("$env:SystemRoot\Temp")
$roots += Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' } | Where-Object { Test-Path $_ }
if (Get-RmmParam 'include_recycle_bin' $false) { $roots += "$env:SystemDrive\`$Recycle.Bin" }
$freeBefore = (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
$report = foreach ($r in $roots) {
  $files = @(Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut })
  $bytes = ($files | Measure-Object Length -Sum).Sum
  $failed = 0
  if (-not $dry) { foreach ($f in $files) { try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { $failed++ } } }
  [pscustomobject]@{ path = $r; files = $files.Count; mb = [math]::Round($bytes / 1MB, 1); failed = $failed }
}
if ((Get-RmmParam 'include_wu_cache' $false) -and -not $dry) {
  Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
  Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  Start-Service wuauserv -ErrorAction SilentlyContinue
  $report += [pscustomobject]@{ path = 'SoftwareDistribution\Download'; files = $null; mb = $null; failed = 0 }
}
$freeAfter = (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
[pscustomobject]@{ dry_run = $dry; older_than_days = $days; total_mb = [math]::Round((($report | Measure-Object mb -Sum).Sum), 1); freed_gb = [math]::Round(($freeAfter - $freeBefore) / 1GB, 2); details = @($report) }
