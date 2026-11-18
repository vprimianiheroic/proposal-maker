<#RMM-TOOL
{
  "name": "system_info",
  "description": "OS, hardware, domain, uptime, memory, BIOS/serial, PowerShell version and pending-reboot state. Start here when looking at a machine.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {} }
}
#>
$os  = Get-WmiObject Win32_OperatingSystem
$cs  = Get-WmiObject Win32_ComputerSystem
$bios = Get-WmiObject Win32_BIOS
$cpu = @(Get-WmiObject Win32_Processor)
$boot = $os.ConvertToDateTime($os.LastBootUpTime)

$pending = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
$pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) { $pending += 'PendingFileRename' }

$roles = @{0='standalone_workstation';1='member_workstation';2='standalone_server';3='member_server';4='backup_dc';5='primary_dc'}
[pscustomobject]@{
  hostname        = $env:COMPUTERNAME
  domain          = $cs.Domain
  domain_role     = $roles[[int]$cs.DomainRole]
  os              = $os.Caption
  os_version      = $os.Version
  os_build        = $os.BuildNumber
  architecture    = $os.OSArchitecture
  install_date    = $os.ConvertToDateTime($os.InstallDate).ToString('s')
  last_boot       = $boot.ToString('s')
  uptime_hours    = [math]::Round(((Get-Date) - $boot).TotalHours, 1)
  manufacturer    = $cs.Manufacturer
  model           = $cs.Model
  serial_number   = $bios.SerialNumber
  bios_version    = $bios.SMBIOSBIOSVersion
  cpu             = ($cpu | Select-Object -First 1).Name
  cpu_sockets     = $cpu.Count
  logical_cpus    = $cs.NumberOfLogicalProcessors
  ram_gb          = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
  ram_free_gb     = [math]::Round($os.FreePhysicalMemory * 1KB / 1GB, 1)
  ps_version      = $PSVersionTable.PSVersion.ToString()
  timezone        = (Get-WmiObject Win32_TimeZone).Caption
  logged_on_user  = $cs.UserName
  pending_reboot  = ($pending.Count -gt 0)
  pending_reasons = $pending
}
