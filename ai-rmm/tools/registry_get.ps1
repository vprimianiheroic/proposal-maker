<#RMM-TOOL
{
  "name": "registry_get",
  "description": "Read a registry key's values and subkey names (64-bit view). Path in PowerShell form, e.g. HKLM:\\SOFTWARE\\Vendor\\App.",
  "risk": "read",
  "timeout_sec": 30,
  "params": { "type": "object", "properties": {
    "path": { "type": "string" },
    "value": { "type": "string", "description": "Only this value name" }
  }, "required": ["path"] }
}
#>
$path = Get-RmmParam 'path'
$val = Get-RmmParam 'value'
$key = Get-Item -LiteralPath $path
$values = foreach ($name in $key.GetValueNames()) {
  if ($val -and $name -ne $val) { continue }
  [pscustomobject]@{ name = $(if ($name) { $name } else { '(default)' }); type = "$($key.GetValueKind($name))"; data = $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames') }
}
[pscustomobject]@{ path = $path; values = @($values); subkeys = @($key.GetSubKeyNames()) }
