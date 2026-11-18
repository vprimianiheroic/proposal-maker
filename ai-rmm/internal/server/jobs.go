package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// Caller identifies who is asking (resolved from an API key).
type Caller struct {
	Name string
	Role string
}

func (c Caller) String() string { return c.Role + ":" + c.Name }

const AdHocTool = "adhoc_powershell"

type SubmitRequest struct {
	Tool     string          `json:"tool"`   // tool name, or empty when Script is set
	Script   string          `json:"script"` // ad-hoc PowerShell (risk high)
	Targets  []string        `json:"targets"`
	Params   json.RawMessage `json:"params"`
	Reason   string          `json:"reason"`
	QueueMin int             `json:"queue_minutes"`
	Timeout  int             `json:"timeout_sec"`
}

type SubmitResult struct {
	BatchID string       `json:"batch_id"`
	Jobs    []*JobRecord `json:"jobs"`
}

// LookupTool returns a copy of the named tool (builtin or custom).
func (s *Server) LookupTool(name string) (*Tool, bool) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	return s.lookupToolLocked(name)
}

func (s *Server) lookupToolLocked(name string) (*Tool, bool) {
	if t, ok := s.builtin[name]; ok {
		c := *t
		return &c, true
	}
	if t, ok := s.store.st.Tools[name]; ok {
		c := *t
		return &c, true
	}
	return nil, false
}

func (s *Server) ListTools() []*Tool {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	var out []*Tool
	for _, t := range s.builtin {
		c := *t
		out = append(out, &c)
	}
	for _, t := range s.store.st.Tools {
		c := *t
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SaveTool creates or updates a custom tool. Tools saved by an AI caller are
// always drafts; only an admin can publish.
func (s *Server) SaveTool(c Caller, t *Tool) (*Tool, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if _, ok := s.builtin[t.Name]; ok {
		return nil, fmt.Errorf("%q is a built-in tool; choose a different name", t.Name)
	}
	t.Source = "custom"
	t.Author = c.String()
	t.UpdatedAt = now()
	t.Version = 1
	if old, ok := s.store.st.Tools[t.Name]; ok {
		t.Version = old.Version + 1
	}
	if c.Role != RoleAdmin || t.Status == "" {
		t.Status = ToolDraft
	}
	if t.Status != ToolDraft && t.Status != ToolPublished {
		return nil, errors.New("status must be draft or published")
	}
	s.store.st.Tools[t.Name] = t
	s.store.markDirty()
	cp := *t
	return &cp, nil
}

func (s *Server) SetToolStatus(name, status string) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t, ok := s.store.st.Tools[name]
	if !ok {
		return errors.New("no such custom tool")
	}
	if status != ToolDraft && status != ToolPublished {
		return errors.New("status must be draft or published")
	}
	t.Status = status
	t.UpdatedAt = now()
	s.store.markDirty()
	return nil
}

func (s *Server) DeleteTool(name string) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if _, ok := s.store.st.Tools[name]; !ok {
		return errors.New("no such custom tool (built-ins cannot be deleted)")
	}
	delete(s.store.st.Tools, name)
	s.store.markDirty()
	return nil
}

// resolveTargetsLocked expands agent IDs, hostnames, "group:<name>" and "all".
func (s *Server) resolveTargetsLocked(targets []string) ([]*Agent, error) {
	if len(targets) == 0 {
		return nil, errors.New("at least one target is required (agent id, hostname, group:<name> or all)")
	}
	seen := map[string]bool{}
	var out []*Agent
	add := func(a *Agent) {
		if !seen[a.ID] && !a.Disabled {
			seen[a.ID] = true
			out = append(out, a)
		}
	}
	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		switch {
		case strings.EqualFold(t, "all"):
			for _, a := range s.store.st.Agents {
				add(a)
			}
		case strings.HasPrefix(strings.ToLower(t), "group:"):
			g := strings.ToLower(t[len("group:"):])
			n := 0
			for _, a := range s.store.st.Agents {
				for _, ag := range a.Groups {
					if strings.ToLower(ag) == g {
						add(a)
						n++
						break
					}
				}
			}
			if n == 0 {
				return nil, fmt.Errorf("group %q matches no agents", g)
			}
		default:
			if a, ok := s.store.st.Agents[t]; ok {
				add(a)
				continue
			}
			var matches []*Agent
			for _, a := range s.store.st.Agents {
				if strings.EqualFold(a.Hostname, t) || strings.EqualFold(a.Facts.Hostname+"."+a.Facts.Domain, t) {
					matches = append(matches, a)
				}
			}
			switch len(matches) {
			case 0:
				return nil, fmt.Errorf("target %q matches no agent", t)
			case 1:
				add(matches[0])
			default:
				// Hostnames are self-reported. Never fan out to every agent
				// claiming a name: a re-imaged PC or a rogue enrollment could
				// otherwise receive jobs meant for the real machine.
				ids := make([]string, 0, len(matches))
				for _, m := range matches {
					ids = append(ids, m.ID)
				}
				sort.Strings(ids)
				return nil, fmt.Errorf("hostname %q is ambiguous (agents %s); target by agent id, and disable stale duplicates", t, strings.Join(ids, ", "))
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("targets resolved to zero enabled agents")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

// Submit creates one job per resolved target, deciding per agent whether a
// human must approve first.
func (s *Server) Submit(c Caller, req SubmitRequest) (*SubmitResult, error) {
	if strings.TrimSpace(req.Reason) == "" {
		return nil, errors.New("reason is required: say why you are doing this (it goes in the audit log and the approval request)")
	}
	var tool *Tool
	adhoc := req.Tool == "" || req.Tool == AdHocTool
	if adhoc {
		if strings.TrimSpace(req.Script) == "" {
			return nil, errors.New("either tool or script is required")
		}
		to := req.Timeout
		if to <= 0 {
			to = 300
		}
		tool = &Tool{Name: AdHocTool, Risk: protocol.RiskHigh, TimeoutSec: to, Script: req.Script,
			Params: json.RawMessage(`{"type":"object"}`), Status: ToolPublished, Version: 1}
		if len(req.Params) == 0 {
			req.Params = json.RawMessage(`{}`)
		}
	} else {
		t, ok := s.LookupTool(req.Tool)
		if !ok {
			return nil, fmt.Errorf("unknown tool %q (use list_tools)", req.Tool)
		}
		tool = t
		p, err := ValidateParams(tool.Params, req.Params)
		if err != nil {
			return nil, err
		}
		req.Params = p
		if req.Timeout > 0 && req.Timeout < 4*3600 {
			tool.TimeoutSec = req.Timeout
		}
	}
	queueMin := req.QueueMin
	if queueMin <= 0 {
		queueMin = s.Cfg.DefaultQueueMin
	}
	if queueMin > 7*24*60 {
		queueMin = 7 * 24 * 60
	}

	s.store.mu.Lock()
	agents, err := s.resolveTargetsLocked(req.Targets)
	if err != nil {
		s.store.mu.Unlock()
		return nil, err
	}
	batch := newID("b")
	t0 := now()
	res := &SubmitResult{BatchID: batch}
	var wake []string
	for _, a := range agents {
		pol, sources := s.Cfg.EffectivePolicy(a.Groups)
		approval := ""
		if adhoc && !pol.AllowAdHocScripts && c.Role != RoleAdmin {
			s.store.mu.Unlock()
			return nil, fmt.Errorf("ad-hoc scripts are disabled by policy for %s (%s); write a tool instead", a.Hostname, strings.Join(sources, ","))
		}
		if c.Role != RoleAdmin {
			switch {
			case tool.Status == ToolDraft:
				approval = "tool '" + tool.Name + "' is an unpublished draft"
			case tool.Risk.Level() > pol.AutoApproveMaxRisk.Level():
				approval = fmt.Sprintf("risk '%s' exceeds auto-approve limit '%s' (%s)", tool.Risk, pol.AutoApproveMaxRisk, strings.Join(sources, ","))
			}
		}
		j := &JobRecord{
			ID: newID("j"), BatchID: batch, AgentID: a.ID, Hostname: a.Hostname,
			Tool: tool.Name, ToolVersion: tool.Version, Risk: tool.Risk, Params: req.Params,
			Script: tool.Script, TimeoutSec: tool.TimeoutSec, Reason: req.Reason,
			RequestedBy: c.String(), ApprovalReason: approval, CreatedAt: t0,
			QueueDeadline: t0 + int64(queueMin*60),
		}
		if approval != "" {
			j.Status = protocol.StatusPendingApproval
			// The queue clock starts at approval; give approvers a day.
			j.QueueDeadline = t0 + 24*3600
		} else {
			j.Status = protocol.StatusQueued
			wake = append(wake, a.ID)
		}
		s.store.st.Jobs[j.ID] = j
		cp := *j
		res.Jobs = append(res.Jobs, &cp)
	}
	s.store.markDirty()
	s.store.mu.Unlock()

	s.Audit(c.String(), "job.submit", map[string]interface{}{
		"batch": batch, "tool": tool.Name, "risk": tool.Risk, "targets": req.Targets,
		"agents": len(agents), "reason": req.Reason, "params": req.Params,
	})
	for _, id := range wake {
		s.wakeAgent(id)
	}
	return res, nil
}

// Decide approves or denies pending jobs, by batch and/or job IDs.
func (s *Server) Decide(c Caller, batchID string, jobIDs []string, approve bool, note string) (int, error) {
	if c.Role != RoleAdmin {
		return 0, errors.New("only an admin (human) key can approve or deny jobs")
	}
	want := map[string]bool{}
	for _, id := range jobIDs {
		want[id] = true
	}
	s.store.mu.Lock()
	n := 0
	t0 := now()
	var wake []string
	var denied []string
	for _, j := range s.store.st.Jobs {
		if j.Status != protocol.StatusPendingApproval {
			continue
		}
		if !(want[j.ID] || (batchID != "" && j.BatchID == batchID)) {
			continue
		}
		j.DecidedBy = c.String()
		if approve {
			j.Status = protocol.StatusQueued
			j.QueueDeadline = t0 + int64(s.Cfg.DefaultQueueMin*60)
			wake = append(wake, j.AgentID)
		} else {
			j.Status = protocol.StatusDenied
			j.FinishedAt = t0
			j.Result = &protocol.JobResult{JobID: j.ID, Status: protocol.StatusDenied, Stderr: "denied by " + c.String() + ": " + note}
			denied = append(denied, j.ID)
		}
		n++
	}
	if n > 0 {
		s.store.markDirty()
	}
	s.store.mu.Unlock()
	for _, id := range denied {
		s.closeDone(id)
	}
	for _, id := range wake {
		s.wakeAgent(id)
	}
	if n == 0 {
		return 0, errors.New("no pending jobs matched")
	}
	act := "job.deny"
	if approve {
		act = "job.approve"
	}
	s.Audit(c.String(), act, map[string]interface{}{"batch": batchID, "jobs": jobIDs, "count": n, "note": note})
	return n, nil
}

func (s *Server) Cancel(c Caller, jobID string) error {
	s.store.mu.Lock()
	j, ok := s.store.st.Jobs[jobID]
	if !ok {
		s.store.mu.Unlock()
		return errors.New("no such job")
	}
	if j.Status != protocol.StatusQueued && j.Status != protocol.StatusPendingApproval {
		s.store.mu.Unlock()
		return fmt.Errorf("job is %s; only queued or pending jobs can be cancelled", j.Status)
	}
	j.Status = protocol.StatusCancelled
	j.FinishedAt = now()
	s.store.markDirty()
	s.store.mu.Unlock()
	s.closeDone(jobID)
	s.Audit(c.String(), "job.cancel", map[string]string{"job": jobID})
	return nil
}

// takeJobs moves queued jobs for an agent to dispatched and signs them.
func (s *Server) takeJobs(agentID string, max int) []protocol.Job {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	var queued []*JobRecord
	for _, j := range s.store.st.Jobs {
		if j.AgentID == agentID && j.Status == protocol.StatusQueued {
			queued = append(queued, j)
		}
	}
	sort.Slice(queued, func(a, b int) bool { return queued[a].CreatedAt < queued[b].CreatedAt })
	var out []protocol.Job
	t0 := now()
	for _, j := range queued {
		if len(out) >= max {
			break
		}
		j.Status = protocol.StatusDispatched
		j.DispatchedAt = t0
		j.ExpiresAt = t0 + int64(j.TimeoutSec) + 300
		pj := protocol.Job{
			ID: j.ID, AgentID: j.AgentID, Tool: j.Tool, Script: j.Script, Params: j.Params,
			TimeoutSec: j.TimeoutSec, IssuedAt: t0, ExpiresAt: j.ExpiresAt,
		}
		pj.Sign(s.signKey)
		out = append(out, pj)
	}
	if len(out) > 0 {
		s.store.markDirty()
	}
	return out
}

func (s *Server) completeJob(agentID string, r *protocol.JobResult) error {
	s.store.mu.Lock()
	j, ok := s.store.st.Jobs[r.JobID]
	if !ok || j.AgentID != agentID {
		s.store.mu.Unlock()
		return errors.New("unknown job")
	}
	if protocol.IsTerminal(j.Status) {
		s.store.mu.Unlock()
		return nil // duplicate delivery after a retry
	}
	switch r.Status {
	case protocol.StatusSucceeded, protocol.StatusFailed, protocol.StatusTimeout, protocol.StatusRejected:
	default:
		r.Status = protocol.StatusFailed
	}
	const maxOut = 512 * 1024
	if len(r.Stdout) > maxOut {
		r.Stdout = r.Stdout[:maxOut] + "\n...[truncated by server]"
	}
	if len(r.Stderr) > maxOut {
		r.Stderr = r.Stderr[:maxOut] + "\n...[truncated by server]"
	}
	if len(r.Data) > 2*maxOut || (len(r.Data) > 0 && !json.Valid(r.Data)) {
		r.Data = nil
	}
	j.Status = r.Status
	j.Result = r
	j.FinishedAt = now()
	s.store.markDirty()
	s.store.mu.Unlock()
	s.closeDone(r.JobID)
	return nil
}

// reap expires jobs no agent picked up, and times out dispatched jobs whose
// agent never reported back.
func (s *Server) reap() {
	t0 := now()
	var done []string
	s.store.mu.Lock()
	for _, j := range s.store.st.Jobs {
		switch {
		case (j.Status == protocol.StatusQueued || j.Status == protocol.StatusPendingApproval) && t0 > j.QueueDeadline:
			j.Status = protocol.StatusExpired
			j.FinishedAt = t0
			done = append(done, j.ID)
		case j.Status == protocol.StatusDispatched && t0 > j.ExpiresAt+120:
			j.Status = protocol.StatusTimeout
			j.FinishedAt = t0
			j.Result = &protocol.JobResult{JobID: j.ID, Status: protocol.StatusTimeout, Stderr: "agent never reported a result"}
			done = append(done, j.ID)
		}
	}
	if len(done) > 0 {
		s.store.markDirty()
	}
	s.store.mu.Unlock()
	for _, id := range done {
		s.closeDone(id)
	}
}

// ---- notification plumbing ----

func (s *Server) agentChan(id string) chan struct{} {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	ch, ok := s.notify[id]
	if !ok {
		ch = make(chan struct{}, 1)
		s.notify[id] = ch
	}
	return ch
}

func (s *Server) wakeAgent(id string) {
	select {
	case s.agentChan(id) <- struct{}{}:
	default:
	}
}

func (s *Server) jobDone(id string) chan struct{} {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	ch, ok := s.doneCh[id]
	if !ok {
		ch = make(chan struct{})
		s.doneCh[id] = ch
	}
	return ch
}

func (s *Server) closeDone(id string) {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if ch, ok := s.doneCh[id]; ok {
		close(ch)
		delete(s.doneCh, id)
	}
}

// WaitJobs blocks until every job is terminal or the timeout passes, then
// returns current copies.
func (s *Server) WaitJobs(ctx context.Context, ids []string, timeout time.Duration) []*JobRecord {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for _, id := range ids {
		s.store.mu.Lock()
		j, ok := s.store.st.Jobs[id]
		terminal := !ok || protocol.IsTerminal(j.Status) || j.Status == protocol.StatusPendingApproval
		s.store.mu.Unlock()
		if terminal {
			continue
		}
		ch := s.jobDone(id)
		// Re-check after registering to avoid missing a completion in between.
		s.store.mu.Lock()
		j, ok = s.store.st.Jobs[id]
		terminal = !ok || protocol.IsTerminal(j.Status)
		s.store.mu.Unlock()
		if terminal {
			continue
		}
		select {
		case <-ch:
		case <-deadline.C:
			return s.GetJobs(ids)
		case <-ctx.Done():
			return s.GetJobs(ids)
		}
	}
	return s.GetJobs(ids)
}

func (s *Server) GetJobs(ids []string) []*JobRecord {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	var out []*JobRecord
	for _, id := range ids {
		if j, ok := s.store.st.Jobs[id]; ok {
			c := *j
			out = append(out, &c)
		}
	}
	return out
}

type JobFilter struct {
	AgentID string
	BatchID string
	Status  string
	Tool    string
	Limit   int
}

func (s *Server) ListJobs(f JobFilter) []*JobRecord {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	var out []*JobRecord
	for _, j := range s.store.st.Jobs {
		if (f.AgentID != "" && j.AgentID != f.AgentID) || (f.BatchID != "" && j.BatchID != f.BatchID) ||
			(f.Status != "" && j.Status != f.Status) || (f.Tool != "" && j.Tool != f.Tool) {
			continue
		}
		c := *j
		out = append(out, &c)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].CreatedAt != out[b].CreatedAt {
			return out[a].CreatedAt > out[b].CreatedAt
		}
		return out[a].ID > out[b].ID
	})
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}
