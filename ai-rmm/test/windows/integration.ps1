<#
.SYNOPSIS
  End-to-end test of AI-RMM on a real Windows machine (GitHub Actions
  windows-2022 / windows-2025 runners, or a disposable lab VM).

  DESTRUCTIVE: installs/uninstalls the agent service, creates a local admin
  account, restarts the print spooler, edits HKLM:\SOFTWARE\AIRMMTest.
  Never run it on a machine you care about.

  Requires: elevated PowerShell 7, Go on PATH. Optional: WiX CLI (`wix`) for
  the MSI section. Run from anywhere:  pwsh ai-rmm/test/windows/integration.ps1
#>
param(
  [string]$WorkDir = (Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) 'airmm-itest'),
  [switch]$SkipMsi
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Port = 18443
$Url = "https://127.0.0.1:$Port"
$PF = Join-Path $env:ProgramFiles 'AIRMM'
$PD = Join-Path $env:ProgramData 'AIRMM'
$results = [System.Collections.Generic.List[object]]::new()
$script:procs = @()

function Log([string]$m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

function Step([string]$Name, [scriptblock]$Body) {
  Log "=== $Name"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    $note = & $Body
    $results.Add([pscustomobject]@{ Step = $Name; Result = 'PASS'; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Note = "$note" })
    Log "PASS $Name $note"
  } catch {
    $msg = ($_ | Out-String).Trim()
    $results.Add([pscustomobject]@{ Step = $Name; Result = 'FAIL'; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Note = $msg })
    Write-Host "::error title=$Name::$($_.Exception.Message)"
    Log "FAIL $Name`n$msg"
  }
}

function Assert($cond, [string]$msg) { if (-not $cond) { throw "Assertion failed: $msg" } }

function Wait-Until([scriptblock]$Cond, [int]$Seconds, [string]$What) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    try { if (& $Cond) { return } } catch { }
    Start-Sleep -Seconds 2
  }
  throw "Timed out after ${Seconds}s waiting for: $What"
}

function Api([string]$Method, [string]$Path, $Body = $null, [string]$Key = $script:AdminKey, [string]$InFile) {
  $p = @{ Method = $Method; Uri = "$Url/api/v1/$Path"; Headers = @{ Authorization = "Bearer $Key" }; SkipCertificateCheck = $true; TimeoutSec = 330 }
  if ($InFile) { $p.InFile = $InFile; $p.ContentType = 'application/octet-stream' }
  elseif ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = 'application/json' }
  try { Invoke-RestMethod @p }
  catch {
    $detail = $_.ErrorDetails.Message
    throw "API $Method $Path failed: $($_.Exception.Message) $detail"
  }
}

# Runs a tool on targets (admin key = no approval) and returns the job(s).
function Run-Tool([string]$Tool, [hashtable]$Params = @{}, [string[]]$Targets = @($script:AgentId), [int]$Wait = 300, [string]$Script, [int]$Timeout = 0) {
  $body = @{ tool = $Tool; targets = $Targets; params = $Params; reason = "integration test" }
  if ($Script) { $body = @{ script = $Script; targets = $Targets; reason = "integration test" } }
  if ($Timeout -gt 0) { $body.timeout_sec = $Timeout }
  $r = Api POST "jobs?wait=$Wait" $body
  return $r.jobs
}

function Agents { @(Api GET 'agents') }
function Agent([string]$Id) { Api GET "agents/$Id" }

function Build-Agent([string]$Out, [string]$Version) {
  Push-Location $Root
  try {
    & go build -trimpath -ldflags "-X main.version=$Version" -o $Out ./cmd/rmm-agent
    if ($LASTEXITCODE -ne 0) { throw "go build agent failed" }
  } finally { Pop-Location }
}

function Remove-AgentCompletely {
  if (Test-Path "$PF\rmm-agent.exe") { & "$PF\rmm-agent.exe" uninstall --purge 2>&1 | Out-Null }
  & sc.exe stop AIRMMAgent 2>&1 | Out-Null
  & sc.exe delete AIRMMAgent 2>&1 | Out-Null
  & schtasks.exe /delete /tn "AIRMM Watchdog" /f 2>&1 | Out-Null
  Start-Sleep -Seconds 4
  Remove-Item -Recurse -Force $PF, $PD -ErrorAction SilentlyContinue
}

# =====================================================================
Log "AI-RMM Windows integration test on $([Environment]::OSVersion.VersionString), PS $($PSVersionTable.PSVersion)"
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$ident).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run elevated." }
Remove-AgentCompletely
Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $WorkDir | Out-Null
$Data = Join-Path $WorkDir 'data'

Step 'Build server and agent' {
  Push-Location $Root
  try {
    & go build -trimpath -o "$WorkDir\rmm-server.exe" ./cmd/rmm-server; if ($LASTEXITCODE) { throw 'server build failed' }
  } finally { Pop-Location }
  Build-Agent "$WorkDir\rmm-agent.exe" '0.0.1'
  "ok"
}

Step 'Server init and start (TLS)' {
  $out = & "$WorkDir\rmm-server.exe" init --data $Data --url $Url --listen "127.0.0.1:$Port" --hosts 127.0.0.1 2>&1 | Out-String
  if ($LASTEXITCODE) { throw $out }
  $grab = { param($label) if ($out -match "(?m)^$([regex]::Escape($label)).*?:\s+(\S+)\s*$") { $matches[1] } else { throw "no '$label' in init output" } }
  $script:AdminKey = & $grab 'Admin API key'
  $script:AiKey = & $grab 'AI API key'
  $script:Token = & $grab 'Enrollment token'
  $script:PubKey = & $grab 'Job-signing public key'
  $script:Pin = & $grab 'TLS public-key pin'
  # Fast offline detection for the test.
  $cfgPath = Join-Path $Data 'config.json'
  $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
  $cfg.offline_after_sec = 60
  $cfg | ConvertTo-Json -Depth 10 | Set-Content $cfgPath
  $p = Start-Process -FilePath "$WorkDir\rmm-server.exe" -ArgumentList @('serve', '--data', $Data) -PassThru -NoNewWindow `
        -RedirectStandardOutput "$WorkDir\server.out.log" -RedirectStandardError "$WorkDir\server.log"
  $script:procs += $p
  Wait-Until { (Invoke-WebRequest "$Url/healthz" -SkipCertificateCheck -TimeoutSec 3).Content -eq 'ok' } 30 'server healthz'
  "pid $($p.Id)"
}

Step 'Agent install as service' {
  $o = & "$WorkDir\rmm-agent.exe" install --server $Url --token $Token --pubkey $PubKey --tls-pin $Pin 2>&1 | Out-String
  Assert ($LASTEXITCODE -eq 0) "install exit $LASTEXITCODE`: $o"
  Assert ((Get-Service AIRMMAgent).Status -eq 'Running') 'service running'
  Assert (Test-Path "$PF\rmm-agent.exe") 'binary in Program Files'
  Assert (Test-Path "$PF\rmm-watchdog.exe") 'watchdog copy'
  $acl = (Get-Acl $PD).Access | ForEach-Object { $_.IdentityReference.Value }
  Assert (-not ($acl -match 'Users|Everyone|Authenticated')) "ProgramData ACL too open: $($acl -join ', ')"
  $xml = (& schtasks.exe /query /tn "AIRMM Watchdog" /xml) -join "`n"
  Assert ($xml -match '<DisallowStartIfOnBatteries>false') 'watchdog task runs on battery'
  Assert ($xml -match 'S-1-5-18|SYSTEM') 'watchdog runs as SYSTEM'
  $sc = & sc.exe qfailure AIRMMAgent | Out-String
  Assert ($sc -match 'RESTART') "recovery actions: $sc"
  Wait-Until { @(Agents | Where-Object { $_.online }).Count -ge 1 } 60 'agent enrollment'
  $script:AgentId = (Agents)[0].id
  $a = Agent $AgentId
  Assert ($a.facts.os_name -match 'Windows') "facts os_name: $($a.facts.os_name)"
  Assert ($a.facts.os_arch -eq 'amd64') "os_arch $($a.facts.os_arch)"
  Assert (-not (Select-String -Path "$PD\agent.json" -Pattern 'enroll_token' -Quiet)) 'enroll token removed after enrollment'
  "agent $AgentId on $($a.facts.os_name) $($a.facts.os_version) PS $($a.facts.ps_version) type=$($a.facts.product_type)"
}

# ---------------- built-in tools ----------------
New-Item -ItemType Directory -Force 'C:\AIRMMTest' | Out-Null
1..300 | ForEach-Object { "line $_ $(if ($_ % 50 -eq 0) { 'ERROR something failed' } else { 'ok' })" } | Set-Content 'C:\AIRMMTest\sample.log'

# expect: ok = must succeed; nodomain = must fail cleanly because the runner is not domain-joined
$toolCases = @(
  @{ t = 'system_info' }
  @{ t = 'disk_usage' }
  @{ t = 'disk_usage'; p = @{ largest_under = 'C:\Windows\Logs' } }
  @{ t = 'list_services'; p = @{ stopped_auto_only = $true } }
  @{ t = 'list_services'; p = @{ name_like = 'Spool' }; check = { param($d) @($d).Count -ge 1 } }
  @{ t = 'list_processes'; p = @{ top = 5 }; check = { param($d) @($d.processes).Count -eq 5 } }
  @{ t = 'list_processes'; p = @{ sort_by = 'cpu'; name_like = 'svchost' } }
  @{ t = 'installed_software'; p = @{ name_like = 'Microsoft' } }
  @{ t = 'event_log_query'; p = @{ log = 'System'; hours = 48; max = 5; level = 'any' }; check = { param($d) @($d).Count -ge 1 } }
  @{ t = 'event_log_query'; p = @{ log = 'Application'; hours = 1; level = 'critical' } }
  @{ t = 'network_config'; check = { param($d) @($d.adapters).Count -ge 1 } }
  @{ t = 'test_connectivity'; p = @{ host = '127.0.0.1'; ports = @($Port, 1); ping_count = 2 }; check = { param($d) $d.ping_received -ge 1 -and (@($d.ports | Where-Object { $_.open }).Count -eq 1) } }
  @{ t = 'windows_update_status'; check = { param($d) $null -ne $d.hotfix_count } }
  @{ t = 'local_admins'; check = { param($d) @($d).Count -ge 1 } }
  @{ t = 'logged_on_users' }
  @{ t = 'defender_status' }
  @{ t = 'scheduled_tasks'; check = { param($d) @($d | Where-Object { $_.name -like '*AIRMM*' }).Count -ge 1 } }
  @{ t = 'scheduled_tasks'; p = @{ failed_only = $true } }
  @{ t = 'firewall_status'; p = @{ rule_like = 'Remote' }; check = { param($d) @($d.profiles).Count -eq 3 } }
  @{ t = 'certificate_expiry'; p = @{ days = 3650 } }
  @{ t = 'list_shares'; p = @{ include_sessions = $true } }
  @{ t = 'time_sync_status' }
  @{ t = 'printer_status' }
  @{ t = 'serial_usb_devices'; p = @{ name_like = 'Microsoft' } }
  @{ t = 'read_file_tail'; p = @{ path = 'C:\AIRMMTest\sample.log'; lines = 3; match = 'ERROR' }; check = { param($d) @($d.lines).Count -eq 3 -and $d.lines[-1] -match 'line 300' } }
  @{ t = 'read_file_tail'; p = @{ path = 'C:\AIRMMTest' } }
  @{ t = 'registry_get'; p = @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; value = 'ProductName' }; check = { param($d) $d.values[0].data -match 'Windows' } }
  @{ t = 'listening_ports'; check = { param($d) @($d | Where-Object { $_.local -match ":$Port$" }).Count -ge 1 } }
  @{ t = 'listening_ports'; p = @{ include_established = $true; remote_like = '127.0.0.1' } }
  @{ t = 'dc_health'; expect = 'nodomain' }
  @{ t = 'ad_user_lookup'; p = @{ query = 'administrator' }; expect = 'nodomain' }
  @{ t = 'ad_locked_out_users'; expect = 'nodomain' }
  @{ t = 'ad_stale_computers'; expect = 'nodomain' }
  @{ t = 'ad_computers'; expect = 'nodomain' }
  @{ t = 'ad_unlock_user'; p = @{ sam_account_name = 'nobody' }; expect = 'nodomain' }
  @{ t = 'ad_set_user_enabled'; p = @{ sam_account_name = 'nobody'; enabled = $true }; expect = 'nodomain' }
  @{ t = 'service_control'; p = @{ name = 'Spooler'; action = 'restart' }; check = { param($d) $d.after.status -eq 'Running' } }
  @{ t = 'clear_temp_files'; p = @{ dry_run = $true; older_than_days = 1 }; check = { param($d) $d.dry_run -eq $true } }
  @{ t = 'gpupdate' }
  @{ t = 'flush_dns' }
  @{ t = 'time_resync'; expect = 'any' }
  @{ t = 'restart_print_spooler'; check = { param($d) $d.spooler -eq 'Running' } }
  @{ t = 'abort_reboot'; check = { param($d) $d.aborted -eq $false } }
)
foreach ($c in $toolCases) {
  $label = "tool $($c.t) $(if ($c.p) { ($c.p | ConvertTo-Json -Compress) })"
  Step $label {
    $j = (Run-Tool $c.t ($c.p ?? @{}))[0]
    $expect = $c.expect ?? 'ok'
    $err = "$($j.result.stderr)".Trim()
    switch ($expect) {
      'ok' {
        Assert ($j.status -eq 'succeeded') "status=$($j.status) exit=$($j.result.exit_code) stderr=$err stdout=$($j.result.stdout)"
        if ($c.check) {
          $d = $j.result.data
          Assert (& $c.check $d) "check failed on data: $(($d | ConvertTo-Json -Depth 6 -Compress).Substring(0, [Math]::Min(1500, ($d | ConvertTo-Json -Depth 6 -Compress).Length)))"
        }
      }
      'nodomain' {
        Assert ($j.status -eq 'failed') "expected a clean failure off-domain, got $($j.status)"
        Assert ($err.Length -gt 0 -and $err.Length -lt 4000) "error should be a short message: $err"
      }
      'any' { Assert ($j.status -in 'succeeded', 'failed') "status $($j.status) $err" }
    }
    "$($j.status) in $($j.result.finished_at - $j.result.started_at)s"
  }
}

Step 'tool process_kill (spawned process)' {
  $p = Start-Process -FilePath ping.exe -ArgumentList '-n', '600', '127.0.0.1' -PassThru -WindowStyle Hidden
  $j = (Run-Tool 'process_kill' @{ pid = $p.Id })[0]
  Assert ($j.status -eq 'succeeded') "kill: $($j.status) $($j.result.stderr)"
  Start-Sleep 1
  Assert ($null -eq (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) 'process gone'
  $j = (Run-Tool 'process_kill' @{ name = 'lsass.exe' })[0]
  Assert ($j.status -eq 'failed' -and $j.result.stderr -match 'protected') 'refuses lsass'
}

Step 'tool registry_set + registry_get round trip' {
  $j = (Run-Tool 'registry_set' @{ path = 'HKLM:\SOFTWARE\AIRMMTest'; name = 'Greeting'; type = 'String'; data = 'Grüße ✓'; create_key = $true })[0]
  Assert ($j.status -eq 'succeeded') "set: $($j.result.stderr)"
  $j = (Run-Tool 'registry_get' @{ path = 'HKLM:\SOFTWARE\AIRMMTest'; value = 'Greeting' })[0]
  Assert ($j.result.data.values[0].data -eq 'Grüße ✓') "unicode round trip: $($j.result.data.values[0].data)"
  $j = (Run-Tool 'registry_set' @{ path = 'HKLM:\SOFTWARE\AIRMMTest'; name = 'Count'; type = 'DWord'; data = 42 })[0]
  Assert ($j.status -eq 'succeeded' -and $j.result.data.now -eq 42) "dword: $($j.result.stderr)"
}

Step 'tool reboot (delayed) then abort_reboot' {
  $j = (Run-Tool 'reboot' @{ delay_seconds = 3600; message = 'AI-RMM integration test - will be aborted' })[0]
  Assert ($j.status -eq 'succeeded' -and $j.result.data.scheduled) "reboot: $($j.result.stderr)"
  $j = (Run-Tool 'abort_reboot')[0]
  Assert ($j.result.data.aborted -eq $true) "abort: $($j.result.data | ConvertTo-Json -Compress)"
}

Step 'tool reboot only_if_pending' {
  $j = (Run-Tool 'reboot' @{ only_if_pending = $true; delay_seconds = 3600 })[0]
  Assert ($j.status -eq 'succeeded') $j.result.stderr
  if ($j.result.data.scheduled) { & shutdown.exe /a | Out-Null; "reboot was pending; aborted" } else { "no reboot pending: skipped as designed" }
}

Step 'ad-hoc PowerShell runs as 64-bit SYSTEM, PS 5.1, unicode output' {
  $j = (Run-Tool -Tool '' -Script '[pscustomobject]@{ user = [Environment]::UserName; x64 = [Environment]::Is64BitProcess; ps = $PSVersionTable.PSVersion.ToString(); text = "Grüße ✓ 日本" }')[0]
  Assert ($j.status -eq 'succeeded') "$($j.status) $($j.result.stderr)"
  $d = $j.result.data
  Assert ($d.x64 -eq $true) '64-bit PowerShell'
  Assert ($d.ps -like '5.1*') "Windows PowerShell 5.1, got $($d.ps)"
  Assert ($d.text -eq 'Grüße ✓ 日本') "unicode: $($d.text)"
  Assert ($d.user -match 'SYSTEM|\$$') "runs as SYSTEM: $($d.user)"
  "user=$($d.user) ps=$($d.ps)"
}

Step 'ad-hoc script error is reported' {
  $j = (Run-Tool -Tool '' -Script 'Write-Host "some host noise"; throw "deliberate failure 123"')[0]
  Assert ($j.status -eq 'failed' -and $j.result.stderr -match 'deliberate failure 123') "got $($j.status): $($j.result.stderr)"
}

Step 'job timeout kills the process tree' {
  $j = (Run-Tool -Tool '' -Script 'Start-Process ping.exe -ArgumentList "-n","600","127.0.0.2" -WindowStyle Hidden; Start-Sleep 120' -Timeout 8 -Wait 60)[0]
  Assert ($j.status -eq 'timeout') "status $($j.status)"
  Start-Sleep 3
  $left = @(Get-CimInstance Win32_Process -Filter "Name='ping.exe'" | Where-Object { $_.CommandLine -match '127\.0\.0\.2' })
  Assert ($left.Count -eq 0) "child processes left behind: $($left.Count)"
}

Step 'AllSigned machine policy does not block jobs' {
  New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Force | Out-Null
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name EnableScripts -Value 1 -Type DWord
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name ExecutionPolicy -Value 'AllSigned'
  try {
    $j = (Run-Tool 'system_info')[0]
    Assert ($j.status -eq 'succeeded') "under AllSigned: $($j.status) $($j.result.stderr)"
  } finally {
    Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Recurse -Force
  }
}

Step 'vault secret reaches script and is redacted from output' {
  Api PUT 'credentials/itest-generic' @{ kind = 'generic'; secrets = @{ apikey = 'S3cret-Value-XYZ-987' } } | Out-Null
  Api PUT 'tools/itest_secret' @{ description = 'reads a secret'; risk = 'read'; status = 'published'
    params = @{ type = 'object'; properties = @{ cred = @{ type = 'string' } } }; credential_params = @('cred')
    script = '$s = Get-RmmSecret ''cred.apikey''; Write-Host "secret on stdout: $s"; [pscustomobject]@{ len = $s.Length; echo = $s }' } | Out-Null
  $j = (Run-Tool 'itest_secret' @{ cred = 'itest-generic' })[0]
  Assert ($j.status -eq 'succeeded') $j.result.stderr
  $all = "$($j.result.stdout)$($j.result.stderr)$($j.result.data | ConvertTo-Json -Compress)"
  Assert ($all -notmatch 'S3cret-Value') "secret leaked: $all"
  Assert ($j.result.data.len -eq 20 -and $j.result.data.echo -eq '[REDACTED]') "redacted: $($j.result.data | ConvertTo-Json -Compress)"
  Assert (-not (Get-ChildItem "$PD\work" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -eq 'secrets.json')) 'secrets file deleted'
}

Step 'AI key: high-risk job waits for approval' {
  $r = Api POST 'jobs?wait=5' @{ tool = 'reboot'; targets = @($AgentId); params = @{ delay_seconds = 3600 }; reason = 'approval test' } $AiKey
  Assert ($r.jobs[0].status -eq 'pending_approval') "status $($r.jobs[0].status)"
  Api POST 'approvals' @{ batch_id = $r.batch_id; approve = $false; note = 'test' } | Out-Null
  $j = Api GET "jobs/$($r.jobs[0].id)"
  Assert ($j.status -eq 'denied') "after deny: $($j.status)"
}

Step 'native network_scan (ICMP + TCP) on loopback' {
  $j = (Run-Tool 'network_scan' @{ cidr = '127.0.0.1/32'; ports = @($Port, 1); ping = $true })[0]
  Assert ($j.status -eq 'succeeded') $j.result.stderr
  $h = $j.result.data.hosts[0]
  Assert ($h.ip -eq '127.0.0.1' -and $null -ne $h.ping_ms -and @($h.open_ports) -contains $Port) "scan: $($j.result.data | ConvertTo-Json -Compress -Depth 5)"
  "ping $($h.ping_ms) ms"
}

Step 'network monitoring: device goes up, then down' {
  $d = Api POST 'devices' @{ name = 'itest-loopback'; address = '127.0.0.1'; kind = 'server'; collector_agent_id = $AgentId; interval_sec = 30; ping = $true; tcp_ports = @($Port) }
  Wait-Until { (Api GET "devices/$($d.id)").status.state -eq 'up' } 150 'device up'
  $dv = Api GET "devices/$($d.id)"
  Assert ($dv.status.ping_ok -and $dv.status.ports.$Port) "status $($dv.status | ConvertTo-Json -Compress)"
  $d2 = Api POST 'devices' @{ name = 'itest-closed-port'; address = '127.0.0.1'; kind = 'other'; collector_agent_id = $AgentId; interval_sec = 30; tcp_ports = @(1) }
  Wait-Until { (Api GET "devices/$($d2.id)").status.state -eq 'down' } 180 'device down after two failed checks'
  Assert (@(Api GET 'events?type=device_down' | Where-Object { $_.subject -eq 'itest-closed-port' }).Count -ge 1) 'device_down event'
  Api DELETE "devices/$($d2.id)" | Out-Null
  "latency $($dv.status.latency_ms) ms"
}

# ---------------- watchdog ----------------
Step 'watchdog starts a stopped service' {
  Stop-Service AIRMMAgent -Force
  & "$PF\rmm-watchdog.exe" watchdog; Assert ($LASTEXITCODE -eq 0) "watchdog exit $LASTEXITCODE"
  Wait-Until { (Get-Service AIRMMAgent).Status -eq 'Running' } 30 'service running'
}

Step 'watchdog re-enables a disabled service' {
  Stop-Service AIRMMAgent -Force; Set-Service AIRMMAgent -StartupType Disabled
  & "$PF\rmm-watchdog.exe" watchdog
  Wait-Until { (Get-Service AIRMMAgent).Status -eq 'Running' } 30 'service running'
  Assert ((Get-Service AIRMMAgent).StartType -eq 'Automatic') "start type $((Get-Service AIRMMAgent).StartType)"
}

Step 'watchdog restores a quarantined (deleted) agent binary' {
  Stop-Service AIRMMAgent -Force
  Move-Item "$PF\rmm-agent.exe" "$WorkDir\quarantined.exe" -Force
  & "$PF\rmm-watchdog.exe" watchdog
  Wait-Until { (Get-Service AIRMMAgent).Status -eq 'Running' } 30 'service running'
  Assert (Test-Path "$PF\rmm-agent.exe") 'binary restored'
  Wait-Until { (Agent $AgentId).online } 60 'agent back online'
}

Step 'watchdog re-creates a deleted service with the same identity' {
  $before = @(Agents).Count
  Stop-Service AIRMMAgent -Force; & sc.exe delete AIRMMAgent | Out-Null
  Start-Sleep 2
  & "$PF\rmm-watchdog.exe" watchdog
  Wait-Until { (Get-Service AIRMMAgent -ErrorAction SilentlyContinue).Status -eq 'Running' } 60 'service re-created'
  Wait-Until { (Agent $AgentId).online } 90 'same agent online'
  Assert (@(Agents).Count -eq $before) 'no duplicate enrollment'
}

# ---------------- self-update and rollback ----------------
Step 'self-update to a new signed release' {
  Build-Agent "$WorkDir\rmm-agent-v2.exe" '0.0.2'
  $rel = Api POST 'releases?version=0.0.2&arch=amd64' -InFile "$WorkDir\rmm-agent-v2.exe"
  Assert ($rel.sha256.Length -eq 64) 'release published'
  Wait-Until { (Agent $AgentId).version -eq '0.0.2' -and (Agent $AgentId).online } 240 'agent reports 0.0.2'
  Assert (Test-Path "$PF\rmm-agent.exe.old") 'previous build kept for rollback'
  Wait-Until { -not (Test-Path "$PD\update-pending.json") } 120 'update confirmed healthy (marker cleared)'
  "updated; .old kept"
}

Step 'watchdog rolls back a broken update' {
  Stop-Service AIRMMAgent -Force
  Copy-Item "$PF\rmm-agent.exe" "$PF\rmm-agent.exe.old" -Force          # known-good build as rollback target
  [IO.File]::WriteAllBytes("$PF\rmm-agent.exe", [byte[]](1..4096 | ForEach-Object { 0x41 }))   # corrupt "new" build
  @{ from = '0.0.2'; to = '0.0.3'; started_at = [DateTimeOffset]::UtcNow.AddMinutes(-20).ToUnixTimeSeconds() } | ConvertTo-Json | Set-Content "$PD\update-pending.json"
  & "$PF\rmm-watchdog.exe" watchdog
  Wait-Until { (Get-Service AIRMMAgent).Status -eq 'Running' } 60 'service running after rollback'
  $before = [DateTimeOffset]::UtcNow
  Wait-Until { (Agent $AgentId).online -and [DateTimeOffset]::Parse((Agent $AgentId).last_seen) -ge $before.AddSeconds(-2) } 90 'agent reporting after rollback'
  Assert (-not (Test-Path "$PD\update-pending.json")) 'marker cleared'
  try { Get-Content "$PD\watchdog.log" -Tail 5 -ErrorAction Stop | ForEach-Object { Log "watchdog.log: $_" } } catch { Log "watchdog.log unreadable: $($_.Exception.Message)" }
}

Step 'watchdog repairs a corrupt binary without an update marker' {
  Stop-Service AIRMMAgent -Force
  Remove-Item "$PF\rmm-agent.exe.old" -Force -ErrorAction SilentlyContinue
  [IO.File]::WriteAllBytes("$PF\rmm-agent.exe", [byte[]](1..4096 | ForEach-Object { 0x41 }))
  & "$PF\rmm-watchdog.exe" watchdog
  Wait-Until { (Get-Service AIRMMAgent).Status -eq 'Running' } 60 'service running from watchdog copy'
  Wait-Until { (Agent $AgentId).online } 90 'agent online'
}

# ---------------- push install ----------------
$deployUser = 'rmmdeploy'
$deployPass = 'Itest-' + [guid]::NewGuid().ToString('N').Substring(0, 16) + '!a1'
Step 'push install: prepare local admin account and source agent' {
  & net.exe user $deployUser $deployPass /add /y | Out-Null
  & net.exe localgroup Administrators $deployUser /add | Out-Null
  # Local (non-domain) admin accounts are filtered over the network unless this is set.
  New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
  Api PUT 'credentials/itest-deploy' @{ kind = 'windows'; secrets = @{ username = "$env:COMPUTERNAME\$deployUser"; password = $deployPass } } | Out-Null
  Api PUT 'credentials/itest-badpw' @{ kind = 'windows'; secrets = @{ username = "$env:COMPUTERNAME\$deployUser"; password = 'wrong-password-1' } } | Out-Null
  # A second, foreground agent acts as the deployment source.
  $tok = (Api POST 'enroll-tokens' @{ name = 'itest-source'; groups = @('itest-source') }).token
  $srcDir = Join-Path $WorkDir 'source'
  & "$WorkDir\rmm-agent.exe" configure --config "$srcDir\agent.json" --server $Url --token $tok --pubkey $PubKey --tls-pin $Pin | Out-Null
  $p = Start-Process "$WorkDir\rmm-agent.exe" -ArgumentList 'run', '--config', "$srcDir\agent.json" -PassThru -NoNewWindow -RedirectStandardError "$WorkDir\source-agent.log"
  $script:procs += $p
  Wait-Until { @(Agents | Where-Object { $_.groups -contains 'itest-source' -and $_.online }).Count -eq 1 } 60 'source agent enrolled'
  $script:SourceId = (Agents | Where-Object { $_.groups -contains 'itest-source' })[0].id
}

function Deploy([hashtable]$Params) {
  $Params.computers = @($env:COMPUTERNAME)
  $j = (Run-Tool 'deploy_agent' $Params @($SourceId) 400)[0]
  if ($null -eq $j.result.data.results) {
    $tail = (Get-Content "$WorkDir\source-agent.log" -Tail 15 -ErrorAction SilentlyContinue) -join "`n"
    throw "deploy job has no per-computer results: status=$($j.status) stderr=$($j.result.stderr)`nsource agent log:`n$tail"
  }
  $j
}

Step 'push install: wrong password fails at authenticate' {
  $j = Deploy @{ credential = 'itest-badpw'; dry_run = $true }
  $r = $j.result.data.results[0]
  if ($r.status -eq 'failed') {
    Assert ($r.stage -eq 'authenticate') "wrong stage: $($r | ConvertTo-Json -Compress)"
    $r.detail
  } else {
    # Loopback SMB to the same machine can use the caller's own token, so a
    # bad password isn't detectable in a single-machine test.
    Assert ($r.status -in 'already_installed', 'ok_dry_run') "unexpected: $($r | ConvertTo-Json -Compress)"
    "loopback: Windows used local authentication; bad-password path needs a 2-machine test"
  }
}

Step 'push install: dry run sees the existing agent' {
  $j = Deploy @{ credential = 'itest-deploy'; dry_run = $true }
  $r = $j.result.data.results[0]
  Assert ($r.status -eq 'already_installed') "got $($r | ConvertTo-Json -Compress) / $($j.result.stderr)"
}

Step 'push install: fresh install onto a machine without the agent' {
  & "$PF\rmm-agent.exe" uninstall --purge | Out-Null
  Wait-Until { -not (Get-Service AIRMMAgent -ErrorAction SilentlyContinue) } 30 'service removed'
  Assert (-not (& schtasks.exe /query /tn "AIRMM Watchdog" 2>$null)) 'watchdog task removed on uninstall'
  Start-Sleep 5
  $j = Deploy @{ credential = 'itest-deploy'; dry_run = $true }
  Assert ($j.result.data.results[0].status -eq 'ok_dry_run') "dry run: $($j.result.data.results[0] | ConvertTo-Json -Compress)"
  $j = Deploy @{ credential = 'itest-deploy'; groups = @('itest-pushed') }
  $r = $j.result.data.results[0]
  Assert ($r.status -eq 'installed') "deploy: $($r | ConvertTo-Json -Compress) / $($j.result.stderr)"
  Assert ((Get-Service AIRMMAgent).Status -eq 'Running') 'service running'
  Wait-Until { @(Agents | Where-Object { $_.groups -contains 'itest-pushed' -and $_.online }).Count -eq 1 } 90 'pushed agent enrolled into its group'
  Assert (-not (Get-ChildItem "$env:SystemRoot\Temp" -Directory -Filter 'AIRMM-Setup*' -ErrorAction SilentlyContinue)) 'staging folder cleaned up'
  Assert (-not (Get-Service AIRMMSetup -ErrorAction SilentlyContinue)) 'setup service removed'
  $script:AgentId = (Agents | Where-Object { $_.groups -contains 'itest-pushed' })[0].id
  "installed in $($r.seconds)s"
}

Step 'push install: force reinstall keeps identity' {
  $before = @(Agents).Count
  $j = Deploy @{ credential = 'itest-deploy'; force = $true }
  Assert ($j.result.data.results[0].status -eq 'installed') "$($j.result.data.results[0] | ConvertTo-Json -Compress)"
  Start-Sleep 10
  Wait-Until { (Agent $AgentId).online } 90 'same agent online'
  Assert (@(Agents).Count -eq $before) 'no duplicate agent'
}

# ---------------- MSI and install script ----------------
if (-not $SkipMsi -and (Get-Command wix -ErrorAction SilentlyContinue)) {
  Step 'MSI: build, silent install, upgrade keeps identity, uninstall' {
    Remove-AgentCompletely
    $wxs = Join-Path $Root 'installer\wix\Package.wxs'
    & wix build $wxs -arch x64 -d Version=0.0.4 -d "AgentExe=$WorkDir\rmm-agent.exe" -o "$WorkDir\airmm-0.0.4.msi"; Assert ($LASTEXITCODE -eq 0) 'wix build 0.0.4'
    & wix build $wxs -arch x64 -d Version=0.0.5 -d "AgentExe=$WorkDir\rmm-agent-v2.exe" -o "$WorkDir\airmm-0.0.5.msi"; Assert ($LASTEXITCODE -eq 0) 'wix build 0.0.5'
    $tok = (Api POST 'enroll-tokens' @{ name = 'itest-msi'; groups = @('itest-msi') }).token
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$WorkDir\airmm-0.0.4.msi`" /qn /l*v `"$WorkDir\msi-install.log`" SERVER_URL=$Url ENROLL_TOKEN=$tok SERVER_PUBKEY=$PubKey TLS_PIN=$Pin" -Wait -PassThru
    Assert ($p.ExitCode -eq 0) "msiexec install exit $($p.ExitCode)"
    Assert ((Get-Service AIRMMAgent).Status -eq 'Running') 'service running after MSI'
    Wait-Until { @(Agents | Where-Object { $_.groups -contains 'itest-msi' -and $_.online }).Count -eq 1 } 60 'MSI agent enrolled'
    $id = (Agents | Where-Object { $_.groups -contains 'itest-msi' })[0].id
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$WorkDir\airmm-0.0.5.msi`" /qn /l*v `"$WorkDir\msi-upgrade.log`"" -Wait -PassThru
    Assert ($p.ExitCode -eq 0) "msiexec upgrade exit $($p.ExitCode)"
    Wait-Until { (Agent $id).online -and (Agent $id).version -eq '0.0.2' } 90 'upgraded agent online with same identity'
    $p = Start-Process msiexec.exe -ArgumentList "/x `"$WorkDir\airmm-0.0.5.msi`" /qn /l*v `"$WorkDir\msi-uninstall.log`"" -Wait -PassThru
    Assert ($p.ExitCode -eq 0) "msiexec uninstall exit $($p.ExitCode)"
    Assert (-not (Get-Service AIRMMAgent -ErrorAction SilentlyContinue)) 'service removed by MSI uninstall'
    Assert (-not (& schtasks.exe /query /tn "AIRMM Watchdog" 2>$null)) 'watchdog task removed by MSI uninstall'
  }
} else { Log "MSI section skipped (wix not installed or -SkipMsi)" }

Step 'Install-AIRMMAgent.ps1 (GPO-style) install, then idempotent re-run' {
  Remove-AgentCompletely
  $src = Join-Path $WorkDir 'netlogon'
  New-Item -ItemType Directory -Force $src | Out-Null
  Copy-Item "$WorkDir\rmm-agent.exe" "$src\rmm-agent-windows-amd64.exe"
  Copy-Item (Join-Path $Root 'installer\Install-AIRMMAgent.ps1') $src
  $tok = (Api POST 'enroll-tokens' @{ name = 'itest-gpo'; groups = @('itest-gpo') }).token
  "server = $Url`ntoken = $tok`npubkey = $PubKey`ntlspin = $Pin" | Set-Content "$src\airmm.conf"
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$src\Install-AIRMMAgent.ps1" -ConfigFile "$src\airmm.conf"
  Assert ($LASTEXITCODE -eq 0) "install script exit $LASTEXITCODE"
  Wait-Until { @(Agents | Where-Object { $_.groups -contains 'itest-gpo' -and $_.online }).Count -eq 1 } 60 'GPO-style agent enrolled'
  $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$src\Install-AIRMMAgent.ps1" -ConfigFile "$src\airmm.conf" | Out-String
  Assert ($LASTEXITCODE -eq 0 -and $out -match 'Nothing to do') "re-run: $out"
}

Step 'Uninstall script with -Purge leaves nothing behind' {
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'installer\Uninstall-AIRMMAgent.ps1') -Purge
  Start-Sleep 6
  Assert (-not (Get-Service AIRMMAgent -ErrorAction SilentlyContinue)) 'service gone'
  Assert (-not (Test-Path $PD)) 'ProgramData\AIRMM removed'
  Assert (-not (Test-Path $PF)) 'Program Files\AIRMM removed'
}

# =====================================================================
foreach ($p in $script:procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { } }
Remove-AgentCompletely
& net.exe user $deployUser /delete 2>&1 | Out-Null
Copy-Item "$PD\*.log" $WorkDir -ErrorAction SilentlyContinue

$failed = @($results | Where-Object Result -eq 'FAIL')
$table = $results | Format-Table -AutoSize -Wrap Result, Seconds, Step, @{ n = 'Note'; e = { if ($_.Note.Length -gt 160) { $_.Note.Substring(0, 160) + '...' } else { $_.Note } } } | Out-String -Width 300
Write-Host $table
if ($env:GITHUB_STEP_SUMMARY) {
  $md = @("## AI-RMM Windows integration: $($results.Count - $failed.Count)/$($results.Count) passed on $([Environment]::OSVersion.Version)", '', '| Result | Step | Note |', '|---|---|---|')
  foreach ($r in $results) { $md += "| $($r.Result) | $($r.Step -replace '\|','/') | $(($r.Note -replace '\r?\n',' ' -replace '\|','/').Substring(0, [Math]::Min(300, $r.Note.Length))) |" }
  $md -join "`n" | Add-Content $env:GITHUB_STEP_SUMMARY
}
Log "$($results.Count - $failed.Count)/$($results.Count) passed"
exit ([int]($failed.Count -gt 0))
