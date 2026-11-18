# Deployment

## 1. Host the server

**Recommendation:** run it on a small, *non-domain-joined* Linux VM (1 vCPU, 1 GB RAM
handles hundreds of agents). Keeping the RMM outside AD means a domain compromise does
not automatically hand an attacker the RMM, and the reverse holds too. A Windows host
also works (`rmm-server-windows-amd64.exe`; run it with a scheduled task or a service
wrapper).

```bash
useradd --system --home /var/lib/rmm-server --shell /usr/sbin/nologin rmm
install -m 0755 dist/rmm-server-linux-amd64 /usr/local/bin/rmm-server
sudo -u rmm rmm-server init --data /var/lib/rmm-server \
     --url https://rmm.corp.local:8443 --hosts rmm.corp.local,10.0.0.25
cp deploy/rmm-server.service /etc/systemd/system/ && systemctl enable --now rmm-server
```

Save the output of `init` to your password manager. The keys are not shown again.

- **DNS**: create `rmm.corp.local` in AD DNS pointing at the VM.
- **Firewall**: agents need outbound TCP 8443 to the server. Nothing listens on the
  endpoints. Restrict 8443 to internal subnets. Put the dashboard and MCP behind a VPN
  if the AI runs off-site.
- **TLS**: `init` makes a self-signed cert, and agents pin its public key (`--tls-pin`).
  To use a cert from your internal CA instead, replace `tls.crt`/`tls.key` and install
  agents without `--tls-pin`. They then validate against the Windows trust store, where
  your enterprise root already lives.
- **Backups**: back up the whole data dir. `signing.key` is the crown jewel. Lose it and
  every agent must be reinstalled with a new public key. Leak it and an attacker can
  sign jobs.

`config.json` (edit, then restart):

| Key | Meaning |
|---|---|
| `default_policy.auto_approve_max_risk` | `none` / `read` / `change` / `high`. Highest tool risk the AI may run without a human. Default `change`. |
| `default_policy.allow_adhoc_scripts` | Whether `run_powershell` is allowed at all (always high risk). |
| `group_policies` | Per-group overrides. **They can only tighten** the default. Defaults: `ot`, `servers` and `domain-controllers` allow `read` only. |
| `default_queue_min` | How long a job waits for an offline machine before it expires. |
| `job_retention` | Finished jobs kept in `state.json`. The audit log is never pruned. |
| `alert_webhooks` | URLs that receive a JSON POST for agent offline/online, device down/up, interface down, approval needed, schedule results. |
| `agent_server_urls` | Ordered server addresses pushed to every agent for failover and migration (see section 4). |
| `timezone` | IANA zone for schedules, e.g. `America/Chicago`. Default: the server's local time. |

Agents that report as a DC or server are put into `domain-controllers` / `servers`
automatically at enrollment.

## 2. Plan groups before rollout

Groups drive approval policy and targeting (`group:plant1`). Suggested for a
manufacturing site:

| Group | Members | Why |
|---|---|---|
| `ot` | HMIs, SCADA/historian clients, CNC/DNC PCs, QC lab PCs, anything on the line | read-only autonomy, so nothing on the floor changes without a human |
| `office` | front-office workstations | default policy |
| `servers`, `domain-controllers` | automatic | read-only autonomy |
| `plant1`, `plant2` | by site | targeting |

Create one enrollment token per group combination, so machines land in the right
groups automatically:

```bash
rmm-server enroll-token --data /var/lib/rmm-server --name floor --groups ot,plant1 --ttl 168h
rmm-server enroll-token --data /var/lib/rmm-server --name office --groups office,plant1 --ttl 168h
```

(Or use the console's **Enroll** tab while the server runs. Only admins can change an
agent's groups later, because the AI must not be able to move a machine out of `ot`.)

## 3. Roll out the agent

### Windows version matrix

| OS | Build | Notes |
|---|---|---|
| Windows 10 / 11, Server 2016 / 2019 / 2022 / 2025 | `rmm-agent-windows-amd64.exe` (or `-386`, `-arm64`) | Go 1.24 build |
| Windows 7 SP1, 8.1, Server 2008 R2 SP1, 2012, 2012 R2 | `rmm-agent-windows-amd64-legacy.exe` / `-386-legacy.exe` | Go 1.20 build. Install **WMF 5.1** first: the tools need PowerShell 5.1 and stock 7/2008 R2 ship 2.0. |
| XP, Vista, 2003, 2008 (non-R2) | not supported | isolate these; manage by hand |

`Install-AIRMMAgent.ps1` and the MSIs pick or ship the right build. The x86 agent on
64-bit Windows deliberately runs the native 64-bit PowerShell (via `Sysnative`), so tools
see the real registry and System32.

### Option A: GPO startup script (recommended for domain machines)

1. Copy `Install-AIRMMAgent.ps1`, every `rmm-agent-windows-*.exe` and an `airmm.conf`
   (from `airmm.conf.example`) to `\\corp.local\NETLOGON\airmm\`.
2. Create a GPO linked to the target OU:
   *Computer Configuration → Policies → Windows Settings → Scripts → Startup → Scripts tab*
   - Script name: `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`
   - Parameters: `-NoProfile -ExecutionPolicy Bypass -File \\corp.local\NETLOGON\airmm\Install-AIRMMAgent.ps1 -ConfigFile \\corp.local\NETLOGON\airmm\airmm.conf`
3. Machines install on next boot. Re-runs are no-ops once the service is running. Logs
   go to `C:\Windows\Temp\airmm-install.log`.

`airmm.conf` is readable by every domain computer. Use a dedicated token with a short
TTL, check new enrollments in the console during rollout, and let the token expire
afterwards. A leaked enrollment token lets someone register a fake agent. It does
**not** let them run anything on real machines.

### Option B: MSI (Intune, PDQ, SCCM, an existing RMM, or by hand)

```powershell
msiexec /i airmm-agent-1.2.0-x64.msi /qn SERVER_URL=https://rmm.corp.local:8443 ENROLL_TOKEN=et_... SERVER_PUBKEY=<key> TLS_PIN=<pin>
```

MSIs are built on Windows by `scripts/build-msi.ps1` or by the `msi` CI job: x64, x86,
arm64, x64-legacy and x86-legacy. A later MSI installed with no properties upgrades in
place and keeps the machine's identity.

### Option C: let the agent spread itself (push install)

Once a few machines have the agent (a DC is ideal), the AI or an admin can
push it to the rest of the domain without GPO:

1. **Create a deployment account**, e.g. `CORP\svc-rmm-deploy`, that is a
   local administrator on the target machines. Prefer a dedicated group (say
   `RMM Deployers`) added to local Administrators through your existing
   Restricted Groups / Group Policy Preferences policy, rather than Domain
   Admins. Disable the account between rollouts if you like; deploys fail
   cleanly with "account disabled".
2. **Store it in the vault**: console → *Credentials* → kind `windows`, or:
   ```bash
   printf 'password=%s\n' "$PW" | rmm-server credential set --data /var/lib/rmm-server \
       --name domain-deploy --kind windows --username 'CORP\svc-rmm-deploy'
   ```
   It is encrypted with `vault.key`. The AI can reference `domain-deploy` but can never read it.
3. **Publish a bootstrap build** (`rmm-server release ... --arch 386 --variant legacy`).
   This 32-bit legacy build runs on every supported Windows version, so it
   is pushed to unknown machines. After enrolling, each agent cross-grades
   itself to the ideal build for its OS (x64/ARM64, modern/legacy). With no
   release published, the source agent pushes its own binary instead.
4. **Ask the AI**: "find computers without the agent and deploy to them". It
   runs `find_unmanaged_computers` (an AD query on a managed machine), then
   `deploy_agent` with `dry_run` in batches of 25, grouped correctly (`ot`
   machines in their own batch). Each batch is one approval card in the console.

How it works on each target: the source machine takes on the vault
credential for outbound connections only (`LogonUser` NEW_CREDENTIALS,
which never clashes with existing SMB sessions, including to DCs). It
copies the agent and a bootstrap config holding a **single-use enrollment
token** (valid 3 hours, minted for that computer only) into a
randomly-named `%SystemRoot%\Temp` folder locked to SYSTEM and
Administrators, then creates a one-shot `AIRMMSetup` service. That service installs the agent normally
(Program Files, `AIRMMAgent` service, watchdog), deletes the token file and
exits. The setup service and files are then removed. Neither the password nor
the token ever appears on a command line.

**Requirements on targets:** TCP 445 reachable from the source machine and
the *File and Printer Sharing (SMB-In)* firewall rule allowed. Windows client
SKUs block this on the domain profile by default. If your workstations block
inbound SMB, enable that one rule scoped to the source machine's IP (a
one-time firewall GPO), or use Option A. `dry_run` reports exactly which
stage failed per machine: connect, authenticate, service_manager, and so on.

### Option D: one-off

```powershell
.\rmm-agent-windows-amd64.exe install --server https://rmm.corp.local:8443 --token et_... --pubkey <key> --tls-pin <pin>
```

### What gets installed

- `C:\Program Files\AIRMM\rmm-agent.exe`, service **AIRMMAgent** (LocalSystem, automatic,
  restarts on failure)
- `C:\ProgramData\AIRMM\` (ACL: SYSTEM + Administrators only): `agent.json`
  (identity and secret), `agent.log` (5 MB rotating), `work\` (per-job scratch, deleted
  after each job), `spool\` (results waiting for an unreachable server)

Uninstall: remove the MSI product, or run `Uninstall-AIRMMAgent.ps1 [-Purge]`, or
`rmm-agent.exe uninstall --purge`. To retire a machine on the server side, disable it in
the console.

## 4. Staying in contact

Several layers keep an agent reachable:

- **Service recovery**: the SCM restarts the service 5 s, 30 s and 2 min after any failure.
- **Watchdog**: a SYSTEM scheduled task (`AIRMM Watchdog`, every 10 min) runs a
  separate known-good copy of the agent (`rmm-watchdog.exe`). It:
  - re-creates the service if it was deleted, and re-enables it if it was disabled
  - starts it if it was stopped
  - restarts it if it has had no server contact for an hour
  - **rolls back** a self-update that hasn't reached the server within 15 minutes of first starting
  - restores the binary if antivirus quarantined or deleted it

  The watchdog task is set to run on battery too. Its copy, and the previous build kept as
  `rmm-agent.exe.old`, are replaced only after a new build has run with server contact for
  24 hours.
- **Address failover**: set `agent_server_urls` in `config.json`, e.g.
  `["https://rmm.corp.local:8443", "https://10.0.0.25:8443"]`. Every agent
  stores the list and fails over in order. It also keeps the address it was
  installed with as a last resort. To move the server, keep `tls.crt`,
  `tls.key` and `signing.key` (copy the data dir), add the new address to the
  list, wait for agents to check in, then cut over.
- **Alerts**: `alert_webhooks` in `config.json` receives `agent_offline`,
  `device_down` and the other events (Slack incoming webhooks work as-is; for
  Teams use a Workflows "post to channel when a webhook request is received"
  flow).

## 5. Upgrading agents

Agents update themselves. Publish a build, and every matching agent (same arch and
variant) downloads it on its next poll, checks the server's signature and the SHA-256,
swaps binaries and restarts:

```bash
systemctl stop rmm-server     # the release command edits state.json
rmm-server release --data /var/lib/rmm-server --file dist/rmm-agent-windows-amd64.exe --version 1.3.0 --arch amd64 --groups canary
rmm-server release --data /var/lib/rmm-server --file dist/rmm-agent-windows-amd64-legacy.exe --version 1.3.0 --arch amd64 --variant legacy
systemctl start rmm-server
```

`--groups canary` limits a release to those groups, so you can roll out in stages. Agents
never update mid-job. To roll back, publish the older build again: the newest *published*
release wins, whatever its version number. A broken build that can't reach the server is
rolled back automatically by the watchdog.

Publish every flavour you use (amd64, 386, arm64, amd64-legacy, 386-legacy). An agent
running a non-ideal build for its OS is moved to the ideal one when it is available.

## 6. Network monitoring

1. Store SNMP credentials in the vault (console → *Credentials*, kind `snmp`;
   v2c `community`, or v3 `version=3`, `username`, `auth_proto` SHA/SHA256,
   `auth_pass`, `priv_proto` AES/AES256, `priv_pass`). Read-only is all that's needed.
2. Pick a collector per site/VLAN: any managed, always-on machine (a server)
   that can reach the devices. Allow UDP 161 and ICMP from it.
3. Have the AI discover and add devices: `network_scan` (for example
   `10.10.0.0/24` with the SNMP credential), then `save_network_device` for the
   switches, APs, firewalls and UPSs worth watching. Or add them in bulk by POSTing
   to `/api/v1/devices`.

Each device is checked every `interval_sec` (default 60 s) with ping, any TCP
ports you list, and SNMP system info. The interface table (oper/admin state,
speed, errors, octets) is walked every 5th check. Two consecutive failures
mark a device `down`. Ports **with a description (ifAlias)** that go down
raise `interface_down`; unlabelled access ports are ignored to avoid noise
from PCs sleeping. Active scanning can upset fragile PLCs, so keep
`network_scan` off production-control subnets.

## 7. Connect the AI

Create a key per AI deployment so the audit log tells them apart:

```bash
rmm-server apikey --data /var/lib/rmm-server --name claude-helpdesk --role ai
```

Then add the MCP server to Claude Code (`claude mcp add ...`, see README) or drop
`deploy/mcp.json.example` into a workspace as `.mcp.json`. Put
[AI-OPERATOR-GUIDE.md](AI-OPERATOR-GUIDE.md) in that workspace as `CLAUDE.md`.
