# Architecture

## Design goals

1. **AI-first operation.** The primary operator is an LLM agent over MCP. Everything it
   needs (fleet state, tools with schemas, structured results, pending approvals, a place
   to keep notes about machines) is one tool call away, and results are shaped for a
   context window (structured `data` first, bounded text, a total budget per call).
2. **Thin agent, fat library.** The agent has no tool logic. It is a signed-script
   runner with inventory and self-update. New capabilities are PowerShell files, so most
   changes never need an agent release.
3. **Humans hold the keys.** Risk-tiered policy, approvals, drafts for AI-written code,
   and an audit trail for everything.
4. **Boring to run.** Two static binaries, a JSON file, no database, no message broker,
   no inbound ports on endpoints.

## Components

```
internal/protocol   Job, PollRequest/Response, JobResult, Facts; Ed25519 signing
internal/server
  server.go         lifecycle, signing key, audit log, background persist/reap
  store.go          State (agents, jobs, custom tools, keys, tokens, releases) + atomic JSON persistence
  config.go         config.json, Policy, EffectivePolicy (strictest wins)
  jobs.go           Submit (target resolution, policy, approval), Decide, dispatch, results, waiters
  tooldef.go        tool file format, built-in loader, param schema validation
  api.go            HTTP: agent endpoints, REST API, auth
  mcp.go            MCP JSON-RPC endpoint and AI-facing tool surface
  release.go        signed agent releases
  web/index.html    approval console (single file, embedded)
internal/agent
  agent.go          enroll, long-poll loop, concurrency, result retry + disk spool
  exec.go           PowerShell prelude, process control, output capture
  facts*.go         native inventory (registry, NetGetJoinInformation)
  service_*.go      Windows service, install/uninstall, ACLs, recovery actions
  update.go         signed self-update via rename-swap + SCM restart
tools/*.ps1         built-in tool library (go:embed)
```

## Job lifecycle

```
submit (AI/human, reason required)
   │  params validated against tool schema; targets resolved (id | hostname | group:x | all)
   │  per agent: policy check
   ├── needs approval ──▶ pending_approval ──deny──▶ denied
   │                           │ approve (admin key only)
   ▼                           ▼
 queued ──(agent polls)──▶ dispatched (signed, expires = timeout + 5m) ──▶ succeeded | failed | timeout | rejected
   │                                                    └─ no result by expiry + 2m ─▶ timeout
   └─ not picked up before queue deadline ─▶ expired
```

- Agents long-poll `POST /api/v1/agent/poll`. The server holds the request up to 25 s
  and answers immediately when a job is queued for that agent, so latency is sub-second
  with no inbound connectivity. An idle agent costs about one HTTPS request per 25 s.
- Up to 4 jobs run at once per agent (`max_concurrent`).
- Results that can't be delivered are spooled to disk and sent after the next good poll.
- `run_tool` / `?wait=N` block until all jobs finish or N seconds pass, whichever comes
  first. Slower jobs are fetched later with `get_results`.

## Script execution

The agent writes `params.json` and `script.ps1` (prelude + tool body) into
`%ProgramData%\AIRMM\work\<job>\` and starts:

```
powershell.exe -NoLogo -NoProfile -NonInteractive -InputFormat None -ExecutionPolicy Bypass
               -Command "& ([scriptblock]::Create([IO.File]::ReadAllText($env:RMM_SCRIPT_FILE)))"
```

Using `-Command` with a scriptblock, instead of `-File`, means a domain-enforced
`AllSigned` execution policy doesn't block jobs. Integrity comes from the job signature,
not Authenticode. The prelude defines `Get-RmmParam` and `Invoke-RmmNative`, sets
`$ErrorActionPreference = 'Stop'`, captures the body's output objects, and prints them as
JSON after a `<<<RMM-DATA>>>` marker. Anything before the marker is kept as `stdout`.

## Persistence

`state.json` is rewritten atomically (temp file + rename) at most every 2 s when dirty,
and on shutdown. That is enough for hundreds of agents and tens of thousands of retained
jobs. If the fleet outgrows it, `store` is the only place that needs to change, for
example to SQLite.

## Wire endpoints

| Path | Auth | Purpose |
|---|---|---|
| `POST /api/v1/agent/enroll` | enrollment token in body | returns agent ID + secret |
| `POST /api/v1/agent/poll` | agent bearer `id.secret` | heartbeat/facts in, jobs and update info out |
| `POST /api/v1/agent/result` | agent | job result |
| `GET /api/v1/agent/release/<file>` | agent | update binary |
| `/api/v1/{whoami,agents,tools,jobs,approvals,audit,enroll-tokens}` | API key | REST for console and automation |
| `POST /mcp` | API key | MCP Streamable HTTP (JSON responses) |
| `GET /` | — (key entered in page) | console |

## Native tools, monitoring, scheduling

- **Native tools** (`deploy_agent`, `network_scan`) are declared on the server
  (`native.go`) and implemented in the agent (`internal/agent/*`). The server
  can attach secrets at dispatch (`dispatchHooks`), and the signature covers them.
- **Monitoring**: the server derives each agent's collector assignment from
  `state.devices` and sends it in the poll response whenever its keyed hash
  (`monitor_version`) changes. Agents run one loop per device and POST batched
  `MonitorReport`s to `/api/v1/agent/monitor` every 15 s. The server keeps the
  current status, 24 h of up/down samples, and raises events.
- **Schedules**: `schedule.go`, evaluated every 15 s. Runs are submitted as
  role `schedule` (pre-approved) only while the schedule is approved and the
  tool version matches the one approved.
- **Events**: `events.go`, a bounded list in state plus webhook fan-out.
- **Watchdog/rollback**: `service_windows.go` (`Watchdog`, `installWatchdog`),
  `update.go` (marker file), `agent.go` (`touch` confirms the update and promotes
  the watchdog copy).

## Roadmap (not built yet)

- **Remote desktop for support staff**: planned as an on-demand, consented
  session. The agent would launch a viewer helper in the user's session and
  relay it over the existing outbound HTTPS connection through the server,
  so it needs no inbound ports (WebRTC or a TURN-style relay). It would be
  audited like any job and gated by policy (`ot` machines require approval).
- Two-person approval for `high` risk on `ot` / `domain-controllers`.
- SSO (Entra ID / OIDC) for the console, and key management UI.
- LAPS-aware deployment: read each machine's LAPS password on a DC instead of a shared deployment account.
- WinRM push path for networks that block SMB but allow WinRM.
- SSH/API tools for switch and firewall *configuration* (backup configs, port changes) using the same vault and approval model.
- Metrics history beyond up/down (interface throughput graphs) and thresholds (disk < 10 %) as events.
