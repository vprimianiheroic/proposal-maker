<#RMM-TOOL
{
  "name": "dc_health",
  "description": "Domain controller health: dcdiag summary, AD replication summary, FSMO role holders, and SYSVOL/NETLOGON share presence. Run on a domain controller (group:domain-controllers).",
  "risk": "read",
  "timeout_sec": 600,
  "params": { "type": "object", "properties": {
    "full_dcdiag": { "type": "boolean", "description": "Include full dcdiag output instead of failures only. Default false" }
  } }
}
#>
$cs = Get-WmiObject Win32_ComputerSystem
if ($cs.DomainRole -lt 4) { throw "This machine is not a domain controller (DomainRole=$($cs.DomainRole))." }
$full = Get-RmmParam 'full_dcdiag' $false
$diag = Invoke-RmmNative 'dcdiag.exe' $(if ($full) { @() } else { @('/q') })
$repl = Invoke-RmmNative 'repadmin.exe' '/replsummary'
$fsmo = Invoke-RmmNative 'netdom.exe' 'query','fsmo'
$shares = @(Get-WmiObject Win32_Share | Where-Object { $_.Name -in 'SYSVOL','NETLOGON' } | ForEach-Object { $_.Name })
[pscustomobject]@{
  dcdiag_exit = $diag.exit_code
  dcdiag_clean = ($diag.exit_code -eq 0 -and -not $full -and [string]::IsNullOrWhiteSpace($diag.output))
  dcdiag = $diag.output
  replication_summary = $repl.output
  fsmo = $fsmo.output
  sysvol_netlogon_shared = $shares
  services = @(Get-WmiObject Win32_Service | Where-Object { $_.Name -in 'NTDS','DNS','Netlogon','KDC','DFSR','W32Time','ADWS' } | ForEach-Object { [pscustomobject]@{ name = $_.Name; state = $_.State } })
}
