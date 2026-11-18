package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// MCP (Model Context Protocol) endpoint, Streamable-HTTP transport with plain
// JSON responses. Point Claude Code (or any MCP client) at https://<server>/mcp
// with an "ai" API key as a Bearer token.

const mcpInstructions = `You are operating the AI-RMM for a Windows domain environment at a manufacturing client.

Ground rules:
- Look before you touch: use read-risk tools to diagnose before running change/high-risk tools.
- Every run needs a concrete "reason"; it is recorded in the audit log and shown to the human who approves.
- Jobs above an agent's auto-approve risk (see effective_policy on each agent) wait for a human. Do not try to route around approval (e.g. by re-expressing a high-risk action as a lower-risk custom tool). Tell the user what is pending and why.
- Machines in group "ot" are on or near the production floor. Prefer read-only investigation and schedule disruptive work with the user.
- Prefer existing tools. If none fits, write a new one with save_tool: small, single-purpose, parameterised via Get-RmmParam, returning objects (not formatted text), with an honest risk level. New tools are drafts until an admin publishes them; draft runs always need approval.
- Use run_powershell only for one-off investigation that no tool covers; it is always high risk.
- Record durable knowledge about a machine (its role, quirks, owner) with set_agent_notes so future sessions benefit.
- Targets can be agent IDs, hostnames, "group:<name>" or "all". Use "all" sparingly.
- Start a session with get_events (offline agents, devices down, pending approvals).
- Expanding coverage: find_unmanaged_computers -> deploy_agent (dry_run first, batches of 25, right groups per batch).
- Patching: patch_report -> windows_update_status(search_missing) where stale -> save_schedule for maintenance windows rather than ad-hoc installs.
- Network: run_tool network_scan to discover, save_network_device to monitor, get_network_device for interface detail. Never scan production-control (OT/PLC) subnets without explicit approval.
- Credentials are referenced by name (list_credentials); you never see or handle secrets.`

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, 405, errors.New("this MCP endpoint only supports POST (no server-initiated stream)"))
		return
	}
	var req rpcReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{-32700, "parse error: " + err.Error()}})
		return
	}
	if len(req.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	c := callerOf(r)
	resp := rpcResp{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = "2025-06-18"
		}
		resp.Result = map[string]interface{}{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{"listChanged": false}},
			"serverInfo":      map[string]string{"name": "ai-rmm", "version": s.Version},
			"instructions":    mcpInstructions,
		}
	case "ping":
		resp.Result = map[string]interface{}{}
	case "tools/list":
		resp.Result = map[string]interface{}{"tools": append(mcpToolDefs(), mcpExtToolDefs()...)}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcErr{-32602, err.Error()}
			break
		}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage(`{}`)
		}
		out, err := s.callMCPTool(r, c, p.Name, p.Arguments)
		if err != nil {
			resp.Result = map[string]interface{}{"isError": true, "content": []map[string]string{{"type": "text", "text": "Error: " + err.Error()}}}
		} else {
			resp.Result = map[string]interface{}{"content": []map[string]string{{"type": "text", "text": out}}}
		}
	default:
		resp.Error = &rpcErr{-32601, "method not found: " + req.Method}
	}
	writeJSON(w, 200, resp)
}

func schema(props string, required ...string) json.RawMessage {
	req, _ := json.Marshal(required)
	if required == nil {
		req = []byte("[]")
	}
	return json.RawMessage(`{"type":"object","properties":{` + props + `},"required":` + string(req) + `}`)
}

const targetsProp = `"targets":{"type":"array","items":{"type":"string"},"description":"Agent IDs, hostnames, \"group:<name>\", or \"all\""}`
const reasonProp = `"reason":{"type":"string","description":"Why you are running this. Recorded in the audit log and shown to approvers."}`
const waitProp = `"wait_seconds":{"type":"integer","description":"Seconds to wait for results before returning (default 45, max 240). Use get_results later for long jobs."}`

func mcpToolDefs() []map[string]interface{} {
	d := func(name, desc string, s json.RawMessage) map[string]interface{} {
		return map[string]interface{}{"name": name, "description": desc, "inputSchema": s}
	}
	return []map[string]interface{}{
		d("list_agents", "List managed machines with online state, groups, OS facts and effective approval policy.",
			schema(`"search":{"type":"string","description":"Substring match on hostname, IP, OS, group, notes"},"group":{"type":"string"},"online_only":{"type":"boolean"}`)),
		d("get_agent", "Get one machine's facts, groups, notes, policy and its 10 most recent jobs.",
			schema(`"agent":{"type":"string","description":"Agent ID or hostname"}`, "agent")),
		d("list_tools", "List the tool library (built-in and custom snap-ins) with risk level, status and parameter schema.",
			schema(`"search":{"type":"string"}`)),
		d("get_tool", "Get a tool's full definition including its PowerShell source.",
			schema(`"name":{"type":"string"}`, "name")),
		d("run_tool", "Run a library tool on one or more machines. Returns results if they finish within wait_seconds; jobs needing human approval return status pending_approval.",
			schema(`"tool":{"type":"string"},`+targetsProp+`,"params":{"type":"object","description":"Tool parameters per its schema"},`+reasonProp+`,`+waitProp+`,"queue_minutes":{"type":"integer","description":"How long to wait for an offline machine to check in (default 60)"}`, "tool", "targets", "reason")),
		d("run_powershell", "Run an ad-hoc PowerShell script (always HIGH risk; usually needs approval). Runs as SYSTEM in Windows PowerShell 5.1. Return objects from the script; they are serialised to JSON for you.",
			schema(targetsProp+`,"script":{"type":"string"},`+reasonProp+`,"timeout_sec":{"type":"integer"},`+waitProp, "targets", "script", "reason")),
		d("get_results", "Get status and output of jobs by batch_id or job_ids, optionally waiting for completion.",
			schema(`"batch_id":{"type":"string"},"job_ids":{"type":"array","items":{"type":"string"}},`+waitProp)),
		d("list_jobs", "List recent jobs (newest first).",
			schema(`"agent":{"type":"string","description":"Agent ID"},"status":{"type":"string"},"tool":{"type":"string"},"limit":{"type":"integer"}`)),
		d("list_pending_approvals", "List jobs waiting for a human to approve, with the reason approval is required.", schema(``)),
		d("cancel_job", "Cancel a queued or pending job.", schema(`"job_id":{"type":"string"}`, "job_id")),
		d("save_tool", "Create or update a custom snap-in tool. It is saved as a DRAFT: runs need human approval until an admin publishes it. Script conventions: read inputs with Get-RmmParam 'name' 'default'; emit objects (they become JSON); throw on failure.",
			schema(`"name":{"type":"string","description":"snake_case, e.g. check_label_printer"},"description":{"type":"string"},"risk":{"type":"string","enum":["read","change","high"]},"timeout_sec":{"type":"integer"},"params_schema":{"type":"object","description":"JSON Schema object describing parameters"},"script":{"type":"string"},"credential_params":{"type":"array","items":{"type":"string"},"description":"Params whose value is a vault credential name; the script reads fields with Get-RmmSecret '<param>.<field>' (e.g. 'cred.password'). Secrets are redacted from output."}`, "name", "description", "risk", "script")),
		d("set_agent_notes", "Replace the free-text notes on a machine (its role, owner, quirks). Use to remember things across sessions.",
			schema(`"agent":{"type":"string"},"notes":{"type":"string"}`, "agent", "notes")),
		d("get_audit_log", "Read the most recent audit log entries.", schema(`"limit":{"type":"integer"}`)),
	}
}

func (s *Server) callMCPTool(r *http.Request, c Caller, name string, raw json.RawMessage) (string, error) {
	var a struct {
		Search       string          `json:"search"`
		Group        string          `json:"group"`
		OnlineOnly   bool            `json:"online_only"`
		Agent        string          `json:"agent"`
		Name         string          `json:"name"`
		Tool         string          `json:"tool"`
		Targets      []string        `json:"targets"`
		Params       json.RawMessage `json:"params"`
		Reason       string          `json:"reason"`
		WaitSeconds  *int            `json:"wait_seconds"`
		QueueMinutes int             `json:"queue_minutes"`
		Script       string          `json:"script"`
		TimeoutSec   int             `json:"timeout_sec"`
		BatchID      string          `json:"batch_id"`
		JobIDs       []string        `json:"job_ids"`
		JobID        string          `json:"job_id"`
		Status       string          `json:"status"`
		Limit        int             `json:"limit"`
		Description  string          `json:"description"`
		Risk         protocol.Risk   `json:"risk"`
		ParamsSchema json.RawMessage `json:"params_schema"`
		CredParams   []string        `json:"credential_params"`
		Notes        *string         `json:"notes"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return "", fmt.Errorf("bad arguments: %w", err)
	}
	wait := 45
	if a.WaitSeconds != nil {
		wait = *a.WaitSeconds
	}
	if wait > 240 {
		wait = 240
	}

	switch name {
	case "list_agents":
		agents := s.ListAgents(a.Search, a.Group, a.OnlineOnly)
		type row struct {
			ID, Hostname, OS, LastSeen string
			Online                     bool
			Groups                     []string
			IPs                        []string
			AutoApprove                protocol.Risk
			Notes                      string `json:",omitempty"`
		}
		rows := make([]row, 0, len(agents))
		for _, v := range agents {
			rows = append(rows, row{v.ID, v.Hostname, v.Facts.OSName + " " + v.Facts.OSVersion, v.LastSeen, v.Online, v.Groups, v.Facts.IPs, v.Policy.AutoApproveMaxRisk, v.Notes})
		}
		return toText(map[string]interface{}{"count": len(rows), "agents": rows})

	case "get_agent":
		v, err := s.GetAgent(a.Agent)
		if err != nil {
			return "", err
		}
		jobs := s.ListJobs(JobFilter{AgentID: v.ID, Limit: 10})
		recent := make([]map[string]interface{}, 0, len(jobs))
		for _, j := range jobs {
			recent = append(recent, map[string]interface{}{"job_id": j.ID, "tool": j.Tool, "status": j.Status, "created": time.Unix(j.CreatedAt, 0).UTC().Format(time.RFC3339), "reason": j.Reason})
		}
		return toText(map[string]interface{}{"agent": v, "recent_jobs": recent})

	case "list_tools":
		var out []map[string]interface{}
		for _, t := range s.ListTools() {
			if a.Search != "" && !strings.Contains(strings.ToLower(t.Name+" "+t.Description), strings.ToLower(a.Search)) {
				continue
			}
			out = append(out, map[string]interface{}{"name": t.Name, "description": t.Description, "risk": t.Risk, "status": t.Status, "source": t.Source, "params": t.Params})
		}
		return toText(out)

	case "get_tool":
		t, ok := s.LookupTool(a.Name)
		if !ok {
			return "", fmt.Errorf("no tool %q", a.Name)
		}
		return toText(t)

	case "run_tool", "run_powershell":
		req := SubmitRequest{Tool: a.Tool, Targets: a.Targets, Params: a.Params, Reason: a.Reason, QueueMin: a.QueueMinutes, Timeout: a.TimeoutSec}
		if name == "run_powershell" {
			req.Tool, req.Script = AdHocTool, a.Script
		} else if a.Tool == AdHocTool {
			return "", errors.New("use run_powershell for ad-hoc scripts")
		}
		res, err := s.Submit(c, req)
		if err != nil {
			return "", err
		}
		jobs := res.Jobs
		if wait > 0 {
			jobs = s.WaitJobs(r.Context(), jobIDs(jobs), time.Duration(wait)*time.Second)
		}
		return toText(summarizeJobs(res.BatchID, jobs))

	case "get_results":
		var ids []string
		if a.BatchID != "" {
			ids = jobIDs(s.ListJobs(JobFilter{BatchID: a.BatchID, Limit: 10000}))
		}
		ids = append(ids, a.JobIDs...)
		if len(ids) == 0 {
			return "", errors.New("give batch_id or job_ids")
		}
		if a.WaitSeconds == nil {
			wait = 0
		}
		var jobs []*JobRecord
		if wait > 0 {
			jobs = s.WaitJobs(r.Context(), ids, time.Duration(wait)*time.Second)
		} else {
			jobs = s.GetJobs(ids)
		}
		return toText(summarizeJobs(a.BatchID, jobs))

	case "list_jobs":
		agentID := a.Agent
		if agentID != "" {
			if v, err := s.GetAgent(agentID); err == nil {
				agentID = v.ID
			}
		}
		jobs := s.ListJobs(JobFilter{AgentID: agentID, Status: a.Status, Tool: a.Tool, Limit: a.Limit})
		var out []map[string]interface{}
		for _, j := range jobs {
			out = append(out, map[string]interface{}{"job_id": j.ID, "batch_id": j.BatchID, "host": j.Hostname, "tool": j.Tool, "status": j.Status, "requested_by": j.RequestedBy, "reason": j.Reason, "created": time.Unix(j.CreatedAt, 0).UTC().Format(time.RFC3339)})
		}
		return toText(out)

	case "list_pending_approvals":
		jobs := s.ListJobs(JobFilter{Status: protocol.StatusPendingApproval, Limit: 500})
		var out []map[string]interface{}
		for _, j := range jobs {
			out = append(out, map[string]interface{}{"job_id": j.ID, "batch_id": j.BatchID, "host": j.Hostname, "tool": j.Tool, "risk": j.Risk, "why_approval": j.ApprovalReason, "reason": j.Reason, "requested_by": j.RequestedBy})
		}
		return toText(map[string]interface{}{"count": len(out), "pending": out, "note": "A human approves these in the RMM dashboard."})

	case "cancel_job":
		if err := s.Cancel(c, a.JobID); err != nil {
			return "", err
		}
		return "cancelled", nil

	case "save_tool":
		t := &Tool{Name: a.Name, Description: a.Description, Risk: a.Risk, TimeoutSec: a.TimeoutSec, Params: a.ParamsSchema, Script: a.Script, CredentialParams: a.CredParams}
		saved, err := s.SaveTool(c, t)
		if err != nil {
			return "", err
		}
		s.Audit(c.String(), "tool.save", map[string]interface{}{"tool": saved.Name, "version": saved.Version, "status": saved.Status, "risk": saved.Risk})
		return toText(map[string]interface{}{"saved": saved.Name, "version": saved.Version, "status": saved.Status,
			"note": "Draft tools run only with human approval until an admin publishes them in the dashboard."})

	case "set_agent_notes":
		v, err := s.GetAgent(a.Agent)
		if err != nil {
			return "", err
		}
		if a.Notes == nil {
			return "", errors.New("notes is required")
		}
		if _, err := s.PatchAgent(c, v.ID, AgentPatch{Notes: a.Notes}); err != nil {
			return "", err
		}
		return "notes saved for " + v.Hostname, nil

	case "get_audit_log":
		n := a.Limit
		if n <= 0 || n > 500 {
			n = 50
		}
		lines, err := s.ReadAudit(n)
		if err != nil {
			return "", err
		}
		return toText(lines)
	}
	if txt, handled, err := s.callMCPExt(r, c, name, raw); handled {
		return txt, err
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// summarizeJobs shapes job output for an LLM context window: structured data
// first, bounded text, and a total budget across all machines.
func summarizeJobs(batch string, jobs []*JobRecord) map[string]interface{} {
	budget := 80000
	per := budget
	if len(jobs) > 0 {
		per = budget / len(jobs)
		if per < 1500 {
			per = 1500
		}
	}
	counts := map[string]int{}
	var rows []map[string]interface{}
	for _, j := range jobs {
		counts[j.Status]++
		row := map[string]interface{}{"job_id": j.ID, "host": j.Hostname, "agent_id": j.AgentID, "tool": j.Tool, "status": j.Status}
		if j.Status == protocol.StatusPendingApproval {
			row["why_approval"] = j.ApprovalReason
		}
		if res := j.Result; res != nil {
			row["exit_code"] = res.ExitCode
			if res.FinishedAt > 0 && res.StartedAt > 0 {
				row["duration_sec"] = res.FinishedAt - res.StartedAt
			}
			if len(res.Data) > 0 {
				if len(res.Data) <= per {
					row["data"] = res.Data
				} else {
					row["data_truncated"] = string(res.Data[:per]) + "...[truncated; narrow the query or use parameters]"
				}
			} else if res.Stdout != "" {
				row["stdout"] = clip(res.Stdout, per)
			}
			if strings.TrimSpace(res.Stderr) != "" {
				row["stderr"] = clip(res.Stderr, 4000)
			}
		}
		rows = append(rows, row)
	}
	return map[string]interface{}{"batch_id": batch, "status_counts": counts, "jobs": rows}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

func toText(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", " ")
	return string(b), err
}
