<#RMM-TOOL
{
  "name": "disk_usage",
  "description": "Free/used space for every local fixed volume, plus physical disk health status. Optionally list the largest folders under a path.",
  "risk": "read",
  "timeout_sec": 300,
  "params": { "type": "object", "properties": {
    "largest_under": { "type": "string", "description": "Optional folder (e.g. C:\\Users) to report the 15 largest subfolders of. Slow on big trees." }
  } }
}
#>
$vols = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
  [pscustomobject]@{
    drive    = $_.DeviceID
    label    = $_.VolumeName
    fs       = $_.FileSystem
    size_gb  = [math]::Round($_.Size / 1GB, 1)
    free_gb  = [math]::Round($_.FreeSpace / 1GB, 1)
    free_pct = if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { $null }
  }
}
$disks = Get-WmiObject Win32_DiskDrive | ForEach-Object {
  [pscustomobject]@{ model = $_.Model; size_gb = [math]::Round($_.Size / 1GB, 0); status = $_.Status; interface = $_.InterfaceType; media = $_.MediaType }
}
$predict = @()
try {
  $predict = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ instance = $_.InstanceName; predict_failure = $_.PredictFailure; reason = $_.Reason } }
} catch { }

$largest = $null
$root = Get-RmmParam 'largest_under'
if ($root) {
  $largest = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $sum = (Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    [pscustomobject]@{ path = $_.FullName; size_gb = [math]::Round($sum / 1GB, 2) }
  } | Sort-Object size_gb -Descending | Select-Object -First 15
}
[pscustomobject]@{ volumes = @($vols); physical_disks = @($disks); smart_failure_prediction = @($predict); largest_folders = $largest }
