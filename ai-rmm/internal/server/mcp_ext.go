package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// MCP tools for fleet expansion, patching, scheduling and network monitoring.

func mcpExtToolDefs() []map[string]interface{} {
	d := func(name, desc string, s json.RawMessage) map[string]interface{} {
		return map[string]interface{}{"name": name, "description": desc, "inputSchema": s}
	}
	return []map[string]interface{}{
		d("list_credentials", "List vault credentials by name and kind (secrets are never shown). Use their names with deploy_agent, network_scan and network devices.", schema(``)),
		d("find_unmanaged_computers", "Query Active Directory (via a managed, domain-joined source machine, ideally a DC) for enabled computer accounts active recently, and return those with no AI-RMM agent. First step of rolling the agent out across the domain.",
			schema(`"source_agent":{"type":"string","description":"Agent ID/hostname to run the AD query on"},"active_days":{"type":"integer","description":"Only computers that logged on within N days (default 30)"},"name_like":{"type":"string"},"os_like":{"type":"string","description":"e.g. Windows 10, Server"}`, "source_agent")),
		d("deploy_agent", "Push-install the agent from a managed source machine to up to 25 computers (see find_unmanaged_computers). Uses a 'windows' vault credential with local admin rights on the targets. High risk: normally waits for human approval. Run with dry_run first to check reachability and rights. New agents appear in list_agents within a few minutes.",
			schema(`"source_agent":{"type":"string"},"computers":{"type":"array","items":{"type":"string"}},"credential":{"type":"string"},"groups":{"type":"array","items":{"type":"string"},"description":"Groups for the new agents, e.g. [\"ot\",\"plant1\"]"},"dry_run":{"type":"boolean"},"force":{"type":"boolean"},`+reasonProp+`,`+waitProp, "source_agent", "computers", "credential", "reason")),
		d("patch_report", "Patch compliance across the fleet from each machine's latest windows_update_status result: missing updates, last patch date, pending reboot. Machines with no recent scan are listed so you can run windows_update_status (search_missing=true) on them.",
			schema(`"group":{"type":"string"},"only_noncompliant":{"type":"boolean"}`)),
		d("list_schedules", "List recurring scheduled jobs (patch windows, health sweeps) with approval state and next run.", schema(``)),
		d("save_schedule", "Create or update a recurring job, e.g. weekly patching in a maintenance window. AI-created or AI-edited schedules need one human approval of the whole schedule; after that its runs are pre-approved. window_minutes bounds how long offline machines may still pick the job up.",
			schema(`"id":{"type":"string","description":"Omit to create"},"name":{"type":"string"},"tool":{"type":"string"},`+targetsProp+`,"params":{"type":"object"},`+reasonProp+`,"days":{"type":"array","items":{"type":"string","enum":["mon","tue","wed","thu","fri","sat","sun"]},"description":"Empty = daily"},"time":{"type":"string","description":"HH:MM 24h in the server timezone"},"window_minutes":{"type":"integer"},"enabled":{"type":"boolean"}`, "name", "tool", "targets", "reason", "time")),
		d("set_schedule_enabled", "Pause or resume a schedule.", schema(`"id":{"type":"string"},"enabled":{"type":"boolean"}`, "id", "enabled")),
		d("delete_schedule", "Delete a schedule.", schema(`"id":{"type":"string"}`, "id")),
		d("list_network_devices", "Monitored network devices (switches, APs, firewalls, UPSs, printers...) with up/down state, latency and SNMP identity.", schema(`"state":{"type":"string","enum":["up","down","stale","unknown"]}`)),
		d("get_network_device", "One device's full status: SNMP system info, interface table (oper/admin state, speed, errors) and up/down history.",
			schema(`"device":{"type":"string","description":"Device ID, name or address"},"include_history":{"type":"boolean"},"include_interfaces":{"type":"boolean","description":"Default true"}`, "device")),
		d("save_network_device", "Start (or update) monitoring a network device. A managed agent on the same network acts as collector and checks it every interval_sec via ping, TCP ports and/or SNMP (with a vault credential). Find candidates with run_tool network_scan.",
			schema(`"id":{"type":"string","description":"Omit to create"},"name":{"type":"string"},"address":{"type":"string"},"kind":{"type":"string","enum":["switch","ap","wlc","firewall","router","ups","printer","server","plc","camera","other"]},"collector":{"type":"string","description":"Agent ID/hostname that polls it"},"interval_sec":{"type":"integer"},"ping":{"type":"boolean"},"tcp_ports":{"type":"array","items":{"type":"integer"}},"snmp_credential":{"type":"string"},"notes":{"type":"string"}`, "name", "address", "collector")),
		d("remove_network_device", "Stop monitoring a device.", schema(`"device":{"type":"string"}`, "device")),
		d("get_events", "Recent events: agent_offline/online, device_down/up, interface_down/up, device_stale, approval_needed, schedule_ran/failed/missed. Check this at the start of a session.",
			schema(`"since_hours":{"type":"number","description":"Default 24"},"type":{"type":"string"},"limit":{"type":"integer"}`)),
	}
}

func (s *Server) callMCPExt(r *http.Request, c Caller, name string, raw json.RawMessage) (string, bool, error) {
	var a struct {
		SourceAgent      string          `json:"source_agent"`
		ActiveDays       int             `json:"active_days"`
		NameLike         string          `json:"name_like"`
		OSLike           string          `json:"os_like"`
		Computers        []string        `json:"computers"`
		Credential       string          `json:"credential"`
		Groups           []string        `json:"groups"`
		DryRun           bool            `json:"dry_run"`
		Force            bool            `json:"force"`
		Reason           string          `json:"reason"`
		WaitSeconds      *int            `json:"wait_seconds"`
		Group            string          `json:"group"`
		OnlyNoncompliant bool            `json:"only_noncompliant"`
		ID               string          `json:"id"`
		Name             string          `json:"name"`
		Tool             string          `json:"tool"`
		Targets          []string        `json:"targets"`
		Params           json.RawMessage `json:"params"`
		Days             []string        `json:"days"`
		Time             string          `json:"time"`
		WindowMinutes    int             `json:"window_minutes"`
		Enabled          *bool           `json:"enabled"`
		State            string          `json:"state"`
		Device           string          `json:"device"`
		IncludeHistory   bool            `json:"include_history"`
		IncludeIfaces    *bool           `json:"include_interfaces"`
		Address          string          `json:"address"`
		Kind             string          `json:"kind"`
		Collector        string          `json:"collector"`
		IntervalSec      int             `json:"interval_sec"`
		Ping             bool            `json:"ping"`
		TCPPorts         []int           `json:"tcp_ports"`
		SNMPCredential   string          `json:"snmp_credential"`
		Notes            string          `json:"notes"`
		SinceHours       float64         `json:"since_hours"`
		Type             string          `json:"type"`
		Limit            int             `json:"limit"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return "", true, fmt.Errorf("bad arguments: %w", err)
	}
	wait := 60
	if a.WaitSeconds != nil {
		wait = *a.WaitSeconds
	}
	if wait > 240 {
		wait = 240
	}
	out := func(v interface{}) (string, bool, error) {
		t, err := toText(v)
		return t, true, err
	}

	switch name {
	case "list_credentials":
		return out(s.ListCredentials())

	case "find_unmanaged_computers":
		days := a.ActiveDays
		if days <= 0 {
			days = 30
		}
		params, _ := json.Marshal(map[string]interface{}{"active_days": days, "name_like": a.NameLike, "os_like": a.OSLike})
		res, err := s.Submit(c, SubmitRequest{Tool: "ad_computers", Targets: []string{a.SourceAgent}, Params: params, Reason: "find computers without the RMM agent"})
		if err != nil {
			return "", true, err
		}
		jobs := s.WaitJobs(r.Context(), jobIDs(res.Jobs), 120*time.Second)
		j := jobs[0]
		if j.Status != protocol.StatusSucceeded || j.Result == nil {
			return out(summarizeJobs(res.BatchID, jobs))
		}
		var comps []struct {
			Name      string `json:"name"`
			DNSName   string `json:"dns_name"`
			OS        string `json:"os"`
			LastLogon string `json:"last_logon"`
			DN        string `json:"dn"`
		}
		data := strings.TrimSpace(string(j.Result.Data))
		if strings.HasPrefix(data, "{") { // PowerShell serialises a single result as an object
			data = "[" + data + "]"
		}
		if data != "null" && data != "" {
			if err := json.Unmarshal([]byte(data), &comps); err != nil {
				return "", true, fmt.Errorf("unexpected ad_computers output: %v", err)
			}
		}
		managed := map[string]bool{}
		for _, ag := range s.ListAgents("", "", false) {
			managed[strings.ToUpper(ag.Hostname)] = true
		}
		var missing []interface{}
		for _, cp := range comps {
			if !managed[strings.ToUpper(cp.Name)] {
				missing = append(missing, cp)
			}
		}
		return out(map[string]interface{}{"ad_computers": len(comps), "managed": len(comps) - len(missing), "unmanaged_count": len(missing), "unmanaged": missing,
			"next": "Run deploy_agent with dry_run=true on batches of up to 25, then for real. Machines needing different groups (e.g. ot) should be deployed in separate batches."})

	case "deploy_agent":
		params, _ := json.Marshal(map[string]interface{}{"computers": a.Computers, "credential": a.Credential, "groups": a.Groups, "dry_run": a.DryRun, "force": a.Force})
		res, err := s.Submit(c, SubmitRequest{Tool: "deploy_agent", Targets: []string{a.SourceAgent}, Params: params, Reason: a.Reason})
		if err != nil {
			return "", true, err
		}
		jobs := res.Jobs
		if wait > 0 {
			jobs = s.WaitJobs(r.Context(), jobIDs(jobs), time.Duration(wait)*time.Second)
		}
		return out(summarizeJobs(res.BatchID, jobs))

	case "patch_report":
		return out(s.patchReport(a.Group, a.OnlyNoncompliant))

	case "list_schedules":
		return out(s.ListSchedules())
	case "save_schedule":
		sc := &Schedule{ID: a.ID, Name: a.Name, Tool: a.Tool, Targets: a.Targets, Params: a.Params, Reason: a.Reason, Days: a.Days, Time: a.Time, WindowMinutes: a.WindowMinutes, Enabled: true}
		if a.Enabled != nil {
			sc.Enabled = *a.Enabled
		}
		saved, err := s.SaveSchedule(c, sc)
		if err != nil {
			return "", true, err
		}
		note := "Approved; runs automatically."
		if !saved.Approved {
			note = "Saved but NOT approved: it will not run until an admin approves it in the console (Schedules tab)."
		}
		return out(map[string]interface{}{"schedule": saved, "next_run": time.Unix(saved.NextRun, 0).In(s.location()).Format(time.RFC1123), "note": note})
	case "set_schedule_enabled":
		if a.Enabled == nil {
			return "", true, errors.New("enabled is required")
		}
		return "ok", true, s.SetScheduleEnabled(c, a.ID, *a.Enabled)
	case "delete_schedule":
		return "deleted", true, s.DeleteSchedule(c, a.ID)

	case "list_network_devices":
		return out(s.ListDevices(a.State))
	case "get_network_device":
		d, err := s.GetDevice(a.Device)
		if err != nil {
			return "", true, err
		}
		if !a.IncludeHistory {
			d.History = nil
		}
		if a.IncludeIfaces != nil && !*a.IncludeIfaces {
			d.Status.Interfaces = nil
		}
		return out(d)
	case "save_network_device":
		saved, err := s.SaveDevice(c, &NetDevice{ID: a.ID, Name: a.Name, Address: a.Address, Kind: a.Kind, CollectorAgentID: a.Collector,
			IntervalSec: a.IntervalSec, Ping: a.Ping, TCPPorts: a.TCPPorts, SNMPCredential: a.SNMPCredential, Notes: a.Notes})
		if err != nil {
			return "", true, err
		}
		return out(map[string]interface{}{"device": saved, "note": "The collector picks this up on its next check-in; status appears within one interval."})
	case "remove_network_device":
		d, err := s.GetDevice(a.Device)
		if err != nil {
			return "", true, err
		}
		return "removed", true, s.DeleteDevice(c, d.ID)

	case "get_events":
		h := a.SinceHours
		if h <= 0 {
			h = 24
		}
		return out(s.ListEvents(now()-int64(h*3600), a.Type, a.Limit))
	}
	return "", false, nil
}

// patchReport summarises each agent's newest successful windows_update_status.
func (s *Server) patchReport(group string, onlyBad bool) map[string]interface{} {
	agents := s.ListAgents("", group, false)
	s.store.mu.Lock()
	latest := map[string]*JobRecord{}
	for _, j := range s.store.st.Jobs {
		if j.Tool != "windows_update_status" || j.Status != protocol.StatusSucceeded || j.Result == nil {
			continue
		}
		if cur, ok := latest[j.AgentID]; !ok || j.FinishedAt > cur.FinishedAt {
			latest[j.AgentID] = j
		}
	}
	type row struct {
		Host          string   `json:"host"`
		AgentID       string   `json:"agent_id"`
		OS            string   `json:"os"`
		LastScan      string   `json:"last_scan,omitempty"`
		Searched      bool     `json:"searched_missing"`
		MissingCount  *int     `json:"missing_count,omitempty"`
		Critical      int      `json:"critical_or_important,omitempty"`
		LastPatched   string   `json:"last_patched,omitempty"`
		PendingReboot bool     `json:"pending_reboot,omitempty"`
		MissingTitles []string `json:"missing,omitempty"`
		Compliant     bool     `json:"compliant"`
		NeedsScan     bool     `json:"needs_scan,omitempty"`
	}
	var rows []row
	summary := map[string]int{"machines": 0, "compliant": 0, "missing_updates": 0, "pending_reboot": 0, "no_recent_scan": 0}
	for _, a := range agents {
		rw := row{Host: a.Hostname, AgentID: a.ID, OS: a.Facts.OSName}
		summary["machines"]++
		j := latest[a.ID]
		if j == nil || now()-j.FinishedAt > 8*24*3600 {
			rw.NeedsScan = true
			summary["no_recent_scan"]++
		}
		if j != nil {
			rw.LastScan = time.Unix(j.FinishedAt, 0).UTC().Format(time.RFC3339)
			var d struct {
				MostRecent []struct {
					Installed string `json:"installed"`
				} `json:"most_recent"`
				PendingReboot bool `json:"pending_reboot"`
				Searched      bool `json:"searched_missing"`
				Missing       []struct {
					Title    string `json:"title"`
					Severity string `json:"severity"`
				} `json:"missing_updates"`
			}
			_ = json.Unmarshal(j.Result.Data, &d)
			if len(d.MostRecent) > 0 {
				rw.LastPatched = d.MostRecent[0].Installed
			}
			rw.PendingReboot, rw.Searched = d.PendingReboot, d.Searched
			if d.Searched {
				n := len(d.Missing)
				rw.MissingCount = &n
				for _, m := range d.Missing {
					if m.Severity == "Critical" || m.Severity == "Important" {
						rw.Critical++
					}
					if len(rw.MissingTitles) < 10 {
						rw.MissingTitles = append(rw.MissingTitles, m.Title)
					}
				}
				if n > 0 {
					summary["missing_updates"]++
				}
			}
			if rw.PendingReboot {
				summary["pending_reboot"]++
			}
		}
		rw.Compliant = !rw.NeedsScan && rw.Searched && rw.MissingCount != nil && *rw.MissingCount == 0 && !rw.PendingReboot
		if rw.Compliant {
			summary["compliant"]++
		}
		if onlyBad && rw.Compliant {
			continue
		}
		rows = append(rows, rw)
	}
	s.store.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Host < rows[j].Host })
	return map[string]interface{}{"summary": summary, "machines": rows}
}
