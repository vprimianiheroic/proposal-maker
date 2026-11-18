<#RMM-TOOL
{
  "name": "certificate_expiry",
  "description": "Certificates in the LocalMachine stores (My, WebHosting, Remote Desktop) expiring within N days or already expired.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "days": { "type": "integer", "minimum": 1, "maximum": 3650, "description": "Default 45" }
  } }
}
#>
$days = [int](Get-RmmParam 'days' 45)
$limit = (Get-Date).AddDays($days)
foreach ($store in 'My', 'WebHosting', 'Remote Desktop') {
  $p = "Cert:\LocalMachine\$store"
  if (-not (Test-Path $p)) { continue }
  Get-ChildItem $p | Where-Object { $_.NotAfter -lt $limit } | ForEach-Object {
    [pscustomobject]@{ store = $store; subject = $_.Subject; issuer = $_.Issuer; not_after = $_.NotAfter.ToString('s'); days_left = [int]($_.NotAfter - (Get-Date)).TotalDays; thumbprint = $_.Thumbprint; has_private_key = $_.HasPrivateKey }
  }
}
