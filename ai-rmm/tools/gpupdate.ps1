<#RMM-TOOL
{
  "name": "gpupdate",
  "description": "Refresh Group Policy (gpupdate /force by default) and return the summary of applied computer GPOs (gpresult).",
  "risk": "change",
  "timeout_sec": 600,
  "params": { "type": "object", "properties": {
    "target": { "type": "string", "enum": ["computer", "both"], "description": "Default computer (user policy needs a logged-on user)" },
    "force": { "type": "boolean", "description": "Default true" }
  } }
}
#>
$t = Get-RmmParam 'target' 'computer'
$a = @()
if ($t -eq 'computer') { $a += '/target:computer' }
if (Get-RmmParam 'force' $true) { $a += '/force' }
$g = Invoke-RmmNative 'gpupdate.exe' $a
$r = Invoke-RmmNative 'gpresult.exe' '/scope','computer','/r'
[pscustomobject]@{ gpupdate_exit = $g.exit_code; gpupdate = $g.output.Trim(); gpresult = $r.output }
