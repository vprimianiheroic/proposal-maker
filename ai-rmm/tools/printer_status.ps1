<#RMM-TOOL
{
  "name": "printer_status",
  "description": "Installed printers (including label/barcode printers) with port, driver, status, default flag and queued jobs. Also reports the Print Spooler service state.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {} }
}
#>
$jobs = @(Get-WmiObject Win32_PrintJob)
$status = @{1='Other';2='Unknown';3='Idle';4='Printing';5='Warmup';6='Stopped';7='Offline'}
$printers = Get-WmiObject Win32_Printer | ForEach-Object {
  $n = $_.Name
  [pscustomobject]@{
    name = $n; share = $_.ShareName; port = $_.PortName; driver = $_.DriverName; default = $_.Default
    network = $_.Network; status = $status[[int]$_.PrinterStatus]; work_offline = $_.WorkOffline; error_state = $_.DetectedErrorState
    queued_jobs = @($jobs | Where-Object { $_.Name -like "$n,*" }).Count
  }
}
$ports = Get-WmiObject Win32_TCPIPPrinterPort | ForEach-Object { [pscustomobject]@{ name = $_.Name; host = $_.HostAddress; port = $_.PortNumber; protocol = $_.Protocol } }
[pscustomobject]@{
  spooler = (Get-WmiObject Win32_Service -Filter "Name='Spooler'").State
  printers = @($printers)
  tcp_ports = @($ports)
  jobs = @($jobs | ForEach-Object { [pscustomobject]@{ printer_job = $_.Name; owner = $_.Owner; status = $_.JobStatus; pages = $_.TotalPages; submitted = $_.TimeSubmitted } })
}
