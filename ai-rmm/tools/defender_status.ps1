<#RMM-TOOL
{
  "name": "defender_status",
  "description": "Microsoft Defender antivirus state (real-time protection, signature age, last scans) and recent threat detections. Also lists other AV products registered with Security Center on workstations.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {} }
}
#>
$res = [ordered]@{}
try {
  $s = Get-MpComputerStatus -ErrorAction Stop
  $res.defender = [pscustomobject]@{
    am_service_enabled = $s.AMServiceEnabled; realtime = $s.RealTimeProtectionEnabled; antivirus_enabled = $s.AntivirusEnabled
    tamper_protected = $s.IsTamperProtected; signature_age_days = $s.AntivirusSignatureAge
    signature_version = $s.AntivirusSignatureVersion; last_quick_scan = "$($s.QuickScanEndTime)"; last_full_scan = "$($s.FullScanEndTime)"
  }
  $res.recent_threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object {
    [pscustomobject]@{ time = "$($_.InitialDetectionTime)"; threat_id = $_.ThreatID; resources = $_.Resources; action_success = $_.ActionSuccess }
  })
} catch { $res.defender = "Defender cmdlets unavailable: $($_.Exception.Message)" }
try {
  $res.security_center_av = @(Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ name = $_.displayName; state_hex = ('{0:X6}' -f $_.productState) }
  })
} catch { $res.security_center_av = 'not available (servers have no Security Center)' }
[pscustomobject]$res
