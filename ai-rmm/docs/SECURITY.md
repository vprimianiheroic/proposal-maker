# Security model

An RMM is remote code execution as SYSTEM on every machine by design, so the
design question is *who can cause that code to run, and what stops them*.

## Trust boundaries

| Actor | Credential | Can | Cannot |
|---|---|---|---|
| Human admin | `admin` API key | everything: approve/deny, publish tools, change groups, create tokens | — |
| AI agent | `ai` API key | read everything, run tools up to policy, request anything else (queued for approval), write **draft** tools, annotate machines | approve its own jobs, publish tools, change groups/policy, disable agents, mint tokens/keys |
| Endpoint agent | per-agent secret (hashed server-side) | poll for its own jobs, post its own results, download releases | see other agents' jobs or any API |
| Enrollment token holder | `et_` token | register a *new* agent identity | affect existing agents; receive jobs targeting real machines |
| Network attacker / DB tamperer | — | — | get an agent to run anything (see job signing) |

## Job signing

Every job is signed by the server's Ed25519 key at dispatch. The signature covers job ID,
target agent ID, tool name, full script body, parameters, timeout, issue and expiry
times. The agent checks all of it against the public key it was installed with, and
refuses jobs that are unsigned, tampered, addressed to another agent, or expired. It
also keeps a replay guard of job IDs it has already executed.

So TLS interception, a malicious proxy, or someone editing `state.json` cannot push
code. Only the holder of `signing.key` can. Agent self-updates use the same key: the
binary's SHA-256 is signed per OS/arch/variant/version.

## Approval policy

- Tools declare a risk: `read` (observe only), `change` (reversible, small blast radius),
  `high` (reboots, installs, AD account changes, registry writes, ad-hoc scripts).
- An agent's effective policy is the **strictest** of the default policy and its groups'
  policies. Groups can only tighten.
- Draft (AI-written or AI-edited) tools always need approval, whatever risk they claim.
  An AI edit to a published tool sends it back to draft. This closes the obvious
  bypass of labelling a destructive script `read`.
- Built-in tool names cannot be shadowed by custom tools.
- The approval card in the console shows the requester, the reason, every target host,
  the parameters, and **the exact script that will run**.

## Audit

`audit.jsonl` is append-only: enrollments (including refused ones), job submissions with
reason, parameters and requester, approvals and denials, tool saves/publishes, group
changes, key/token creation, releases. Ship it to your SIEM. Job outputs live in
`state.json` up to `job_retention`.

## Residual risks / hardening checklist

- [ ] `signing.key` and `config.json` readable only by the service account. Data dir backed up and encrypted.
- [ ] Server not domain-joined. SSH and console access limited to admins.
- [ ] Port 8443 reachable only from internal subnets (and the AI host / VPN).
- [ ] Separate API keys per human and per AI deployment. Disable unused keys in `state.json` (`"disabled": true`).
- [ ] Enrollment tokens short-lived, one per group combination. Watch the audit log for `agent.enroll_refused` and for enrollments you did not expect.
- [ ] `ot` group applied to every production-floor machine before AI access is enabled.
- [ ] Review AI-written tools' source before publishing them, the same way you would a PR.
- [ ] Agent secret is protected by directory ACL (SYSTEM/Administrators). A local admin on an endpoint can read it and impersonate *that one* agent (send fake facts and results for it). They cannot run code elsewhere.
- [ ] Results and facts come from endpoints and are untrusted input to the AI. A compromised endpoint can try prompt injection through tool output. Policy and approvals are the backstop; keep autonomy on servers/DCs/OT at `read`.
- [ ] Constrained Language Mode / WDAC: if enforced, the agent's PowerShell host is subject to it. Allow-list `C:\Program Files\AIRMM\rmm-agent.exe` and test the tools.

## Not in scope (yet)

SSO for the console, per-human approval quorums, maintenance windows, mTLS for agents,
and encryption of results at rest. See ARCHITECTURE.md "Roadmap".
