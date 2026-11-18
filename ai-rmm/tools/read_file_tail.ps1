<#RMM-TOOL
{
  "name": "read_file_tail",
  "description": "Read the last N lines of a text file (application logs, MES/ERP client logs, setup logs), optionally only lines matching a pattern. Also lists a directory if the path is a folder.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "path": { "type": "string" },
    "lines": { "type": "integer", "minimum": 1, "maximum": 2000, "description": "Default 100" },
    "match": { "type": "string", "description": "Regex; only return matching lines" }
  }, "required": ["path"] }
}
#>
$path = Get-RmmParam 'path'
$n = [int](Get-RmmParam 'lines' 100)
$rx = Get-RmmParam 'match'
$item = Get-Item -LiteralPath $path -Force
if ($item.PSIsContainer) {
  return Get-ChildItem -LiteralPath $path -Force | Sort-Object LastWriteTime -Descending | Select-Object -First 200 | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; dir = $_.PSIsContainer; size_kb = if ($_.PSIsContainer) { $null } else { [math]::Round($_.Length / 1KB, 1) }; modified = $_.LastWriteTime.ToString('s') }
  }
}
if ($item.Length -gt 1GB) { throw "File is larger than 1GB; refusing to scan it." }
$fs = New-Object System.IO.FileStream($path, 'Open', 'Read', 'ReadWrite,Delete')
$sr = New-Object System.IO.StreamReader($fs)
$q = New-Object System.Collections.Generic.Queue[string]
while ($null -ne ($l = $sr.ReadLine())) {
  if ($rx -and $l -notmatch $rx) { continue }
  $q.Enqueue($l); if ($q.Count -gt $n) { [void]$q.Dequeue() }
}
$sr.Close()
[pscustomobject]@{ path = $path; size_kb = [math]::Round($item.Length / 1KB, 1); modified = $item.LastWriteTime.ToString('s'); lines = @($q.ToArray()) }
