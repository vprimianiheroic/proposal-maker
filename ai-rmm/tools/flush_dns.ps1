<#RMM-TOOL
{
  "name": "flush_dns",
  "description": "Flush the DNS resolver cache and optionally re-register this machine's DNS records.",
  "risk": "change",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "register": { "type": "boolean", "description": "Also run ipconfig /registerdns" }
  } }
}
#>
$f = Invoke-RmmNative 'ipconfig.exe' '/flushdns'
$r = $null
if (Get-RmmParam 'register' $false) { $r = (Invoke-RmmNative 'ipconfig.exe' '/registerdns').output.Trim() }
[pscustomobject]@{ flush = $f.output.Trim(); register = $r }
