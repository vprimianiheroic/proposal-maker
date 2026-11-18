<#RMM-TOOL
{
  "name": "serial_usb_devices",
  "description": "Serial (COM) ports, USB-serial adapters and other PnP devices with problems. Useful for shop-floor PCs talking to CNCs, scales, PLCs or scanners over RS-232/USB.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "name_like": { "type": "string", "description": "Also list all PnP devices whose name contains this text" }
  } }
}
#>
$like = Get-RmmParam 'name_like'
$com = Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -match '\(COM\d+\)' } | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; status = $_.Status; manufacturer = $_.Manufacturer; device_id = $_.DeviceID; error_code = $_.ConfigManagerErrorCode }
}
$problem = Get-WmiObject Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; error_code = $_.ConfigManagerErrorCode; device_id = $_.DeviceID }
}
$match = $null
if ($like) { $match = @(Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -like "*$like*" } | ForEach-Object { [pscustomobject]@{ name = $_.Name; status = $_.Status; device_id = $_.DeviceID } }) }
[pscustomobject]@{ com_ports = @($com); problem_devices = @($problem); matching = $match }
