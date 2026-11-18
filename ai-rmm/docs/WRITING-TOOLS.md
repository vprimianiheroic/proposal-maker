# Writing snap-in tools

A tool is a single PowerShell file: a JSON header in a `<#RMM-TOOL ... #>` comment, then
the body.

```powershell
<#RMM-TOOL
{
  "name": "check_label_printer",
  "description": "Status of a Zebra label printer: spooler queue, TCP port reachability, last driver errors. Use when shipping labels stop printing.",
  "risk": "read",
  "timeout_sec": 60,
  "params": { "type": "object", "properties": {
    "printer": { "type": "string", "description": "Printer name as shown in printer_status" },
    "port": { "type": "integer", "minimum": 1, "maximum": 65535, "description": "Default 9100" }
  }, "required": ["printer"] }
}
#>
$name = Get-RmmParam 'printer'
$port = [int](Get-RmmParam 'port' 9100)
$p = Get-WmiObject Win32_Printer -Filter "Name='$($name -replace "'", "''")'"
if (-not $p) { throw "No printer named $name" }
$hostAddr = (Get-WmiObject Win32_TCPIPPrinterPort -Filter "Name='$($p.PortName)'").HostAddress
$c = New-Object Net.Sockets.TcpClient
$open = $false
try { $c.Connect($hostAddr, $port); $open = $true } catch { } finally { $c.Close() }
[pscustomobject]@{ printer = $name; host = $hostAddr; port_open = $open; queued = @(Get-WmiObject Win32_PrintJob | Where-Object { $_.Name -like "$name,*" }).Count }
```

## Where tools live

- **Built-in**: `tools/*.ps1`, embedded in `rmm-server` at build time. Add one, rebuild,
  restart the server. Agents need nothing new, because scripts ship with each job.
- **Custom**: created at runtime through MCP `save_tool`, REST `PUT /api/v1/tools/<name>`,
  or by an admin. Stored in `state.json`. AI-saved tools are **drafts**: every run needs
  approval until an admin clicks **Publish** in the console. Proven custom tools can be
  promoted to built-ins by copying them into `tools/`.

## Conventions

- **Inputs**: `Get-RmmParam 'name' <default>`. Parameters arrive as JSON, never
  string-interpolated into code, so there is no injection from parameter values. Still
  quote them properly when you build WQL/LDAP filters (see the `-replace "'", "''"`
  above, or strip `()*\` for LDAP).
- **Outputs**: emit objects (`[pscustomobject]@{...}`), not `Format-Table` text. The
  wrapper serialises them to JSON (depth 8) and the AI gets structured `data`. Convert
  dates to strings (`.ToString('s')`). Select only the properties you need, because raw
  WMI objects are huge.
- **Failure**: `throw`. `$ErrorActionPreference` is `Stop`, so any uncaught error fails
  the job and its message goes to `stderr`.
- **Native commands**: use `Invoke-RmmNative 'exe' 'arg1','arg2'`. It returns
  `exit_code`, `lines` and `output`, and does not trip `Stop` on stderr noise.
- **Compatibility**: target Windows PowerShell 5.1. Prefer `Get-WmiObject` and .NET
  classes, which also work on Server 2012 R2 / Win7 with WMF 5.1. Avoid PowerShell 7-only
  syntax (`??`, ternary, `-Parallel`) and modules that might be missing (`ActiveDirectory`,
  so use `[adsisearcher]`).
- **Context**: runs as `NT AUTHORITY\SYSTEM`, non-interactive, no profile, hidden window,
  working directory is a per-job temp folder. On a DC, SYSTEM has directory rights. On a
  member machine it acts as the computer account (`DOMAIN\HOST$`) on the network.
- **Risk**: be honest. `read` must not change state. `change` is reversible and narrow.
  Anything that reboots, installs, deletes user data, or touches AD accounts or security
  settings is `high`.
- **Scope**: one job per tool, with parameters for the variations. Prefer a `dry_run`
  parameter (default `true`) on anything destructive.
- **Timeouts**: the agent kills the whole process tree at `timeout_sec`.

## Testing a tool

On any Windows box, without the RMM:

```powershell
$env:RMM_PARAMS_FILE = "$env:TEMP\p.json"; '{"printer":"ZT410"}' | Set-Content $env:RMM_PARAMS_FILE
# paste the prelude from internal/agent/exec.go with %BODY% replaced by your script, or simply:
function Get-RmmParam($n, $d) { $v = (Get-Content $env:RMM_PARAMS_FILE -Raw | ConvertFrom-Json).$n; if ($null -eq $v) { $d } else { $v } }
. .\check_label_printer.ps1 | ConvertTo-Json -Depth 8
```

`go test ./internal/server` checks every built-in tool's header: valid schema, required
parameters declared, and every `Get-RmmParam` name declared.
