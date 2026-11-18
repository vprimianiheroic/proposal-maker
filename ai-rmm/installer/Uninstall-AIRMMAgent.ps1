<#
.SYNOPSIS
  Removes the AI-RMM agent installed by script (for MSI installs, uninstall the
  "AI-RMM Agent" product instead). -Purge also deletes config and logs, so a
  reinstall enrolls as a new machine.
#>
param([switch]$Purge)
$pf = $env:ProgramW6432; if (-not $pf) { $pf = $env:ProgramFiles }
$exe = Join-Path $pf 'AIRMM\rmm-agent.exe'
if (-not (Test-Path $exe)) { Write-Host 'AI-RMM agent not found.'; exit 0 }
$a = @('uninstall'); if ($Purge) { $a += '--purge' }
& $exe @a
exit $LASTEXITCODE
