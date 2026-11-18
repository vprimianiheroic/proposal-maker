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

### Option C: one-off

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

## 4. Upgrading agents

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
release wins, whatever its version number.

## 5. Connect the AI

Create a key per AI deployment so the audit log tells them apart:

```bash
rmm-server apikey --data /var/lib/rmm-server --name claude-helpdesk --role ai
```

Then add the MCP server to Claude Code (`claude mcp add ...`, see README) or drop
`deploy/mcp.json.example` into a workspace as `.mcp.json`. Put
[AI-OPERATOR-GUIDE.md](AI-OPERATOR-GUIDE.md) in that workspace as `CLAUDE.md`.
