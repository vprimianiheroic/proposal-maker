# AI-RMM

A deliberately small RMM (remote monitoring & management) platform built for
**AI agents to operate**, with humans approving anything risky. It replaces
the parts of a ConnectWise Automate–style RMM that day-to-day Windows domain
administration needs, without the console sprawl.

- **Agent**: one static Windows binary running as a LocalSystem service. It
  holds no tool logic of its own. It verifies and runs PowerShell jobs that
  the server has signed. Builds cover Windows 10/11, Server 2016–2025
  (x64/x86/ARM64) and a *legacy* build for Windows 7 SP1, 8.1, Server 2008 R2,
  2012 and 2012 R2.
- **Server**: one binary with a JSON state file, no database. It serves the
  agent API, a REST API, an **MCP endpoint** that Claude or any MCP client
  uses to manage the fleet, and a small web console where humans approve jobs.
- **Snap-in tools**: each capability is a single `.ps1` file with a JSON
  header (name, description, risk level, parameter schema). 42 PowerShell
  tools and 2 native tools ship built in. The AI can write new ones at runtime. They start as drafts and
  run only with human approval until an admin publishes them.
- **Self-propagating rollout**: a managed machine can push-install the agent
  to the rest of the domain (PsExec-style over SMB/ADMIN$). It uses a
  deployment credential held in the server's encrypted vault, which the AI
  refers to by name but can never read, and mints a single-use enrollment
  token for each target. GPO, MSI and script installs still work.
- **Patching**: update status, installs with optional reboot, a fleet
  patch-compliance report, and approved recurring schedules that act as
  maintenance windows.
- **Never lose contact**: a watchdog scheduled task restarts or re-creates the
  service and rolls back a self-update that can't reach the server. Agents
  fail over between server addresses, and the server can push a new address
  list. Updates are signed and can be canaried by group. An agent running the
  wrong build for its OS (for example x86 on x64) is moved to the right one
  automatically.
- **Network monitoring**: agents act as collectors for switches, APs,
  firewalls, UPSs, printers and anything else with an IP. They use ping, TCP
  and SNMP v2c/v3, including interface up/down and error counts. Subnet
  discovery is built in. Alerts go to webhooks (Slack, Teams via workflow,
  and others).
- **No AI inside**: the platform exposes MCP and REST. Bring any MCP client
  (Claude Code, Claude Desktop, the Claude API/Agent SDK); no model API key
  lives in the RMM.
- **Guardrails**: every job carries a written reason and lands in an
  append-only audit log. Per-group policy decides which risk levels run
  without approval. Agents refuse any job not signed by the server's Ed25519
  key, so a compromised database or network path cannot push code. Secrets
  are redacted from tool output before it leaves the machine.

```
 Claude / MCP client ──HTTPS+API key──▶ ┌─────────────┐ ◀──HTTPS long-poll── rmm-agent (SYSTEM)
 Human (web console) ──HTTPS+API key──▶ │ rmm-server  │ ──signed jobs──────▶ powershell.exe
                                        │ state.json  │ ◀──results───────────
                                        │ audit.jsonl │
                                        └─────────────┘
```

## Quick start (lab)

```bash
VERSION=0.1.0 ./scripts/build.sh                 # -> dist/
./dist/rmm-server-linux-amd64 init --data ./rmm-data --url https://rmm.corp.local:8443
./dist/rmm-server-linux-amd64 serve --data ./rmm-data
```

`init` prints an admin key, an AI key, an enrollment token, the job-signing
public key, the TLS pin, and ready-to-paste install commands. On a Windows
test machine, in an elevated PowerShell:

```powershell
.\rmm-agent-windows-amd64.exe install --server https://rmm.corp.local:8443 --token et_... --pubkey <key> --tls-pin <pin>
```

Connect Claude Code:

```bash
# self-signed cert: let Node trust it
export NODE_EXTRA_CA_CERTS=/path/to/rmm-data/tls.crt
claude mcp add --transport http ai-rmm https://rmm.corp.local:8443/mcp --header "Authorization: Bearer rk_<ai key>"
```

Open `https://rmm.corp.local:8443/` with the admin key to approve jobs, publish
AI-written tools, manage groups and create enrollment tokens.

## Documentation

| Doc | For |
|---|---|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Server hosting, agent rollout (MSI, GPO, script), Windows version matrix, agent upgrades |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, trust boundaries, approval policy, hardening checklist |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the pieces fit, the wire protocol, job lifecycle, extending the code |
| [docs/WRITING-TOOLS.md](docs/WRITING-TOOLS.md) | Writing snap-in tools (for humans and the AI) |
| [docs/AI-OPERATOR-GUIDE.md](docs/AI-OPERATOR-GUIDE.md) | Drop-in `CLAUDE.md` for the AI session that runs the fleet |

## Built-in tools

| Tool | Risk | What it does |
|---|---|---|
| `ad_computers` | read | List enabled Active Directory computer accounts that logged on within N days, with DNS name, OS and last logon. |
| `ad_locked_out_users` | read | List currently locked-out AD user accounts. |
| `ad_stale_computers` | read | AD computer accounts whose lastLogonTimestamp is older than N days (candidates for cleanup), with OS and enabled state. |
| `ad_user_lookup` | read | Look up Active Directory users by sAMAccountName, UPN, display name or email (wildcards allowed). |
| `certificate_expiry` | read | Certificates in the LocalMachine stores (My, WebHosting, Remote Desktop) expiring within N days or already expired. |
| `dc_health` | read | Domain controller health: dcdiag summary, AD replication summary, FSMO role holders, and SYSVOL/NETLOGON share presence. |
| `defender_status` | read | Microsoft Defender antivirus state (real-time protection, signature age, last scans) and recent threat detections. |
| `disk_usage` | read | Free/used space for every local fixed volume, plus physical disk health status. |
| `event_log_query` | read | Query a Windows event log (System, Application, Security, or any channel such as Microsoft-Windows-GroupPolicy/Operational) by level, source, event IDs and time window. |
| `firewall_status` | read | Windows Firewall profile state (domain/private/public), current network profile, and optionally enabled inbound allow rules matching a filter. |
| `installed_software` | read | Installed applications from the uninstall registry keys (64- and 32-bit), with version, publisher, install date and uninstall string. |
| `list_processes` | read | Running processes sorted by CPU time or memory, with owner and command line. |
| `list_services` | read | List Windows services with state, start mode and run-as account. |
| `list_shares` | read | SMB shares on this machine with path and share-level permissions; optionally current open sessions. |
| `listening_ports` | read | TCP listening ports and (optionally) established connections with owning process. |
| `local_admins` | read | Members of a local group (default Administrators), including domain users and groups. |
| `logged_on_users` | read | Interactive and RDP sessions on the machine (quser), with idle time and logon time. |
| `network_config` | read | IP-enabled network adapters with addresses, gateways, DNS servers, DHCP, MAC, link speed; plus the routing table summary and DNS client suffixes. |
| `printer_status` | read | Installed printers (including label/barcode printers) with port, driver, status, default flag and queued jobs. |
| `read_file_tail` | read | Read the last N lines of a text file (application logs, MES/ERP client logs, setup logs), optionally only lines matching a pattern. |
| `registry_get` | read | Read a registry key's values and subkey names (64-bit view). |
| `scheduled_tasks` | read | Scheduled tasks with state, last/next run and last result. |
| `serial_usb_devices` | read | Serial (COM) ports, USB-serial adapters and other PnP devices with problems. |
| `system_info` | read | OS, hardware, domain, uptime, memory, BIOS/serial, PowerShell version and pending-reboot state. |
| `test_connectivity` | read | From this machine: DNS-resolve a host, ping it, and optionally test TCP ports. |
| `time_sync_status` | read | Windows Time service status and configured source (w32tm), plus offset against a reference host. |
| `windows_update_status` | read | Recently installed hotfixes, pending reboot, WSUS/policy configuration, and (optionally) a live search for missing updates via the Windows Update Agent (can take minutes). |
| `abort_reboot` | change | Cancel a pending scheduled shutdown/restart (shutdown /a), e.g. |
| `ad_unlock_user` | change | Unlock a locked-out AD user account. |
| `clear_temp_files` | change | Free disk space by deleting old files from Windows temp, user temp folders, Windows Update download cache and (optionally) the recycle bin. |
| `flush_dns` | change | Flush the DNS resolver cache and optionally re-register this machine's DNS records. |
| `gpupdate` | change | Refresh Group Policy (gpupdate /force by default) and return the summary of applied computer GPOs (gpresult). |
| `network_scan` (native) | change | Discover devices on a subnet: ping sweep, TCP ports, reverse DNS, SNMP identity and a device-type guess. |
| `process_kill` | change | Terminate a process by PID or by exact image name (e.g. |
| `restart_print_spooler` | change | Fix stuck printing: stop the spooler, optionally purge all queued jobs, start it again. |
| `service_control` | change | Start, stop or restart a Windows service, and/or change its start mode. |
| `time_resync` | change | Force a Windows Time resync (w32tm /resync), restarting W32Time if needed. |
| `ad_set_user_enabled` | high | Enable or disable an AD user account (e.g. |
| `deploy_agent` (native) | high | Push-install the agent to other domain computers over SMB/ADMIN$ and remote service control, using a vault credential and single-use enrollment tokens. |
| `install_msi` | high | Download an MSI or EXE installer from an internal URL or UNC path, verify its SHA-256, and install silently. |
| `install_windows_updates` | high | Search, download and install applicable Windows updates through the Windows Update Agent (honours WSUS). |
| `reboot` | high | Restart the machine after a delay, with a message to logged-on users. |
| `registry_set` | high | Create or update a single registry value (64-bit view). |
| `uninstall_software` | high | Silently uninstall an MSI-installed application by exact display name (from installed_software). |

## MCP tools exposed to the AI

| Area | Tools |
|---|---|
| Fleet | `list_agents`, `get_agent`, `set_agent_notes`, `get_events`, `get_audit_log` |
| Running work | `list_tools`, `get_tool`, `run_tool`, `run_powershell`, `get_results`, `list_jobs`, `list_pending_approvals`, `cancel_job` |
| Extending | `save_tool` (drafts), `list_credentials` |
| Rollout | `find_unmanaged_computers`, `deploy_agent` |
| Patching & scheduling | `patch_report`, `list_schedules`, `save_schedule`, `set_schedule_enabled`, `delete_schedule` |
| Network | `list_network_devices`, `get_network_device`, `save_network_device`, `remove_network_device` (discovery via `run_tool network_scan`) |

## Layout

```
cmd/rmm-server        control plane CLI (init, serve, apikey, enroll-token, release)
cmd/rmm-agent         endpoint agent CLI / Windows service
internal/protocol     wire types + job/update signing
internal/server       API, MCP, policy, jobs, store, web console
internal/agent        enroll, poll, execute, facts, service, self-update
tools/                built-in snap-in tool library (*.ps1, embedded in the server)
installer/            MSI (WiX), idempotent install script for GPO/manual use
scripts/              build.sh (cross-compile matrix), build-msi.ps1
deploy/               systemd unit, MCP client config example
```

## Development

```bash
go test -race ./...          # unit + end-to-end tests (server, agent, MCP, approvals, signing)
GOOS=windows go vet ./...
```

The module targets **Go 1.20** language and stdlib so the legacy agent still
compiles with the last toolchain that supports Windows 7 and 2008 R2. Do not
use `slices`, `maps`, `log/slog`, `min`/`max` or method-pattern `ServeMux`
routes. CI checks this.
