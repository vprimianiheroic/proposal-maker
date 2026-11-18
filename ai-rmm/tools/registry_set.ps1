<#RMM-TOOL
{
  "name": "registry_set",
  "description": "Create or update a single registry value (64-bit view). Returns the previous value so the change can be reverted.",
  "risk": "high",
  "timeout_sec": 30,
  "params": { "type": "object", "properties": {
    "path": { "type": "string", "description": "e.g. HKLM:\\SOFTWARE\\Vendor\\App" },
    "name": { "type": "string" },
    "type": { "type": "string", "enum": ["String", "ExpandString", "DWord", "QWord", "MultiString"] },
    "data": { "description": "String, number, or array of strings for MultiString" },
    "create_key": { "type": "boolean", "description": "Create the key if missing. Default false" }
  }, "required": ["path", "name", "type", "data"] }
}
#>
$path = Get-RmmParam 'path'; $name = Get-RmmParam 'name'; $type = Get-RmmParam 'type'; $data = Get-RmmParam 'data'
if (-not (Test-Path -LiteralPath $path)) {
  if (Get-RmmParam 'create_key' $false) { New-Item -Path $path -Force | Out-Null } else { throw "Key $path does not exist (set create_key to create it)." }
}
$prev = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
if ($type -eq 'MultiString') { $data = [string[]]$data }
New-ItemProperty -LiteralPath $path -Name $name -PropertyType $type -Value $data -Force | Out-Null
[pscustomobject]@{ path = $path; name = $name; type = $type; previous = $prev; now = (Get-ItemProperty -LiteralPath $path -Name $name).$name }
