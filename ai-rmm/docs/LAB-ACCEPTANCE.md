# Lab acceptance checklist (before the first client deployment)

The automated Windows suite (`test/windows/integration.ps1`, run by
`.github/workflows/ai-rmm-windows.yml` on Windows Server 2022, Server 2025
and the Go 1.20 legacy build) covers everything that can be proven on a
single, non-domain machine. These items need a small lab: one DC, one
member server, two workstations (one Windows 10/11, one Windows 7 SP1 or
Server 2008 R2 / 2012 R2 with WMF 5.1), and the RMM server VM.

Tick each one. Anything that fails is a blocker.

## 1. Active Directory tools (agent on the DC, `group:domain-controllers`)
- [ ] `dc_health` returns dcdiag, repadmin and FSMO output; `dcdiag_clean` is true on a healthy DC
- [ ] `ad_user_lookup` finds a test user by sAMAccountName, UPN, and display-name wildcard
- [ ] Lock out a test user (bad passwords), then `ad_locked_out_users` lists it **with the source computer**
- [ ] `ad_unlock_user` unlocks it; a normal logon then works
- [ ] `ad_set_user_enabled` disables and re-enables it (approval required by default)
- [ ] `ad_computers` / `find_unmanaged_computers` lists the lab machines that have no agent
- [ ] `time_sync_status` on a member shows the DC hierarchy as its source

## 2. Push install between two real machines
- [ ] Create `CORP\svc-rmm-deploy` (member of a group that is local admin via GPO) and store it as vault credential `domain-deploy`
- [ ] Publish a `386 legacy` release (it's the bootstrap build) and the `amd64` modern release
- [ ] From the DC agent: `deploy_agent` with `dry_run` to both workstations → `ok_dry_run`
- [ ] Same with a **wrong password** credential → fails at stage `authenticate` (can't be tested on one machine)
- [ ] Workstation with inbound SMB blocked → fails at stage `connect` with a clear message
- [ ] Real deploy → both enroll into the requested groups; the Win10 machine cross-grades from the 386 bootstrap build to amd64 within a few minutes
- [ ] No `AIRMM-Setup*` folder or `AIRMMSetup` service is left on the targets
- [ ] Watch `Security` log 4624/4672 on a target: logon is by `svc-rmm-deploy`, not the DC's machine account

## 3. Legacy Windows (7 SP1 / 2008 R2 / 2012 R2)
- [ ] `Install-AIRMMAgent.ps1` picks the `-legacy` build and installs; the agent enrolls
- [ ] Run `system_info`, `disk_usage`, `event_log_query`, `list_services`, `network_config`, `windows_update_status` → all succeed
- [ ] Watchdog task exists and runs (`schtasks /query /tn "AIRMM Watchdog" /v`)
- [ ] Without WMF 5.1 the installer prints the WMF warning (most tools need PS 5.1)

## 4. Site specifics
- [ ] GPO startup-script rollout to one OU (DEPLOYMENT.md, option A) installs on next boot
- [ ] SNMP: add one real switch and one AP with a v2c or v3 vault credential → `up`, interface table present; unplug a labelled port → `interface_down` event and webhook
- [ ] Alert webhook reaches your Teams/Slack channel (stop an agent's service for >2 minutes → `agent_offline`)
- [ ] A schedule created by the AI for `group:lab` appears under Approvals; after approval it runs at the set time
- [ ] Production-floor (`ot`) machine: a `change`-risk tool from the AI key waits for approval

Record results in the ticket for the rollout. Once all are ticked, roll out
by OU: IT first, then office, then servers, then `ot` last.
