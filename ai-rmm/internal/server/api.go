package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/airmm/airmm/internal/protocol"
	"github.com/airmm/airmm/internal/server/web"
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/enroll", s.handleEnroll)
	mux.HandleFunc("/api/v1/agent/poll", s.agentAuth(s.handlePoll))
	mux.HandleFunc("/api/v1/agent/result", s.agentAuth(s.handleResult))
	mux.HandleFunc("/api/v1/agent/release/", s.agentAuth(s.handleRelease))
	mux.HandleFunc("/api/v1/", s.apiAuth(s.handleAPI))
	mux.HandleFunc("/mcp", s.apiAuth(s.handleMCP))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write(web.Index)
	})
	return mux
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	return dec.Decode(v)
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// ---- agent side ----

type ctxKey int

const (
	ctxAgent ctxKey = iota
	ctxCaller
)

func (s *Server) agentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		i := strings.IndexByte(tok, '.')
		if i < 0 {
			writeErr(w, 401, errors.New("unauthorized"))
			return
		}
		id, secret := tok[:i], tok[i+1:]
		s.store.mu.Lock()
		a, ok := s.store.st.Agents[id]
		valid := ok && !a.Disabled && secretMatches(a.SecretHash, secret)
		s.store.mu.Unlock()
		if !valid {
			writeErr(w, 401, errors.New("unauthorized"))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxAgent, id)))
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, errors.New("POST only"))
		return
	}
	var req protocol.EnrollRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	t0 := now()
	s.store.mu.Lock()
	var tok *EnrollToken
	for _, t := range s.store.st.EnrollTokens {
		if secretMatches(t.Hash, req.Token) {
			tok = t
			break
		}
	}
	if tok == nil || tok.Revoked || (tok.ExpiresAt > 0 && t0 > tok.ExpiresAt) || (tok.MaxUses > 0 && tok.Uses >= tok.MaxUses) {
		s.store.mu.Unlock()
		s.Audit("ip:"+clientIP(r), "agent.enroll_refused", map[string]string{"hostname": req.Facts.Hostname})
		writeErr(w, 403, errors.New("invalid, expired or exhausted enrollment token"))
		return
	}
	tok.Uses++
	secret := randomHex(32)
	a := &Agent{
		ID: newID("a"), Hostname: strings.ToUpper(req.Facts.Hostname), SecretHash: hashSecret(secret),
		Groups: append([]string(nil), tok.Groups...), Facts: req.Facts, Version: req.AgentVersion,
		Variant: req.Variant, EnrolledAt: t0, LastSeen: t0, LastIP: clientIP(r),
	}
	if a.Facts.ProductType == "domain_controller" {
		a.Groups = appendUnique(a.Groups, "domain-controllers")
	} else if a.Facts.ProductType == "server" {
		a.Groups = appendUnique(a.Groups, "servers")
	}
	s.store.st.Agents[a.ID] = a
	s.store.markDirty()
	s.store.mu.Unlock()
	s.Audit("token:"+tok.Name, "agent.enroll", map[string]interface{}{"agent": a.ID, "hostname": a.Hostname, "ip": a.LastIP, "groups": a.Groups})
	writeJSON(w, 200, protocol.EnrollResponse{AgentID: a.ID, Secret: secret})
}

var groupRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func normGroups(in []string) ([]string, error) {
	var out []string
	for _, g := range in {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		if !groupRe.MatchString(g) {
			return nil, fmt.Errorf("invalid group name %q (use a-z, 0-9, . _ -)", g)
		}
		out = appendUnique(out, g)
	}
	return out, nil
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(ctxAgent).(string)
	var req protocol.PollRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	s.store.mu.Lock()
	a := s.store.st.Agents[id]
	a.LastSeen = now()
	a.LastIP = clientIP(r)
	a.Version = req.AgentVersion
	a.Variant = req.Variant
	if req.Facts != nil {
		a.Facts = *req.Facts
		if req.Facts.Hostname != "" {
			a.Hostname = strings.ToUpper(req.Facts.Hostname)
		}
	}
	upd := s.updateForLocked(a)
	s.store.markDirty()
	s.store.mu.Unlock()

	resp := protocol.PollResponse{Update: upd}
	ch := s.agentChan(id)
	// Drain any stale wake-up so we only block if there is nothing queued.
	select {
	case <-ch:
	default:
	}
	resp.Jobs = s.takeJobs(id, 8)
	if len(resp.Jobs) == 0 && upd == nil {
		select {
		case <-ch:
			resp.Jobs = s.takeJobs(id, 8)
		case <-time.After(25 * time.Second):
		case <-r.Context().Done():
			// The agent hung up; any job we might take now would be lost.
			return
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(ctxAgent).(string)
	var res protocol.JobResult
	if err := readJSON(r, &res); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.completeJob(id, &res); err != nil {
		writeErr(w, 404, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// updateForLocked returns the release assigned to this agent, if it differs
// from what the agent runs.
func (s *Server) updateForLocked(a *Agent) *protocol.UpdateInfo {
	osName, arch := "windows", a.Facts.Arch
	var best *Release
	for _, rel := range s.store.st.Releases {
		if rel.OS != osName || rel.Arch != arch || rel.Variant != a.Variant {
			continue
		}
		if len(rel.Groups) > 0 && !intersects(rel.Groups, a.Groups) {
			continue
		}
		if best == nil || rel.CreatedAt > best.CreatedAt {
			best = rel
		}
	}
	if best == nil || best.Version == a.Version {
		return nil
	}
	return &protocol.UpdateInfo{Version: best.Version, URL: "/api/v1/agent/release/" + best.File, SHA256: best.SHA256, Signature: best.Signature}
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(strings.TrimPrefix(r.URL.Path, "/api/v1/agent/release/"))
	if name == "." || name == "/" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(s.Dir, "releases", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}

// ---- operator / AI REST API ----

func (s *Server) apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		var c *Caller
		if tok != "" {
			s.store.mu.Lock()
			for _, k := range s.store.st.APIKeys {
				if !k.Disabled && secretMatches(k.Hash, tok) {
					c = &Caller{Name: k.Name, Role: k.Role}
					break
				}
			}
			s.store.mu.Unlock()
		}
		if c == nil {
			writeErr(w, 401, errors.New("unauthorized: send Authorization: Bearer <api key>"))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxCaller, *c)))
	}
}

func callerOf(r *http.Request) Caller { return r.Context().Value(ctxCaller).(Caller) }

// AgentView is the API representation of an agent (no secrets).
type AgentView struct {
	ID         string         `json:"id"`
	Hostname   string         `json:"hostname"`
	Online     bool           `json:"online"`
	LastSeen   string         `json:"last_seen"`
	LastIP     string         `json:"last_ip"`
	Groups     []string       `json:"groups"`
	Version    string         `json:"version"`
	Variant    string         `json:"variant,omitempty"`
	Disabled   bool           `json:"disabled,omitempty"`
	Notes      string         `json:"notes,omitempty"`
	Policy     Policy         `json:"effective_policy"`
	Facts      protocol.Facts `json:"facts"`
	EnrolledAt string         `json:"enrolled_at"`
}

func (s *Server) viewLocked(a *Agent) AgentView {
	p, _ := s.Cfg.EffectivePolicy(a.Groups)
	return AgentView{
		ID: a.ID, Hostname: a.Hostname, Online: now()-a.LastSeen < int64(s.Cfg.OfflineAfterSec),
		LastSeen: time.Unix(a.LastSeen, 0).UTC().Format(time.RFC3339), LastIP: a.LastIP,
		Groups: a.Groups, Version: a.Version, Variant: a.Variant, Disabled: a.Disabled, Notes: a.Notes,
		Policy: p, Facts: a.Facts, EnrolledAt: time.Unix(a.EnrolledAt, 0).UTC().Format(time.RFC3339),
	}
}

func (s *Server) ListAgents(search, group string, onlineOnly bool) []AgentView {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	var out []AgentView
	search = strings.ToLower(search)
	for _, a := range s.store.st.Agents {
		v := s.viewLocked(a)
		if onlineOnly && !v.Online {
			continue
		}
		if group != "" && !intersects([]string{group}, a.Groups) {
			continue
		}
		if search != "" {
			hay := strings.ToLower(strings.Join([]string{a.ID, a.Hostname, a.Facts.OSName, a.Facts.Domain, strings.Join(a.Facts.IPs, " "), strings.Join(a.Groups, " "), a.Notes}, " "))
			if !strings.Contains(hay, search) {
				continue
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

func (s *Server) GetAgent(idOrHost string) (*AgentView, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	agents, err := s.resolveTargetsLocked([]string{idOrHost})
	if err != nil {
		return nil, err
	}
	v := s.viewLocked(agents[0])
	return &v, nil
}

type AgentPatch struct {
	Groups   *[]string `json:"groups"`
	Notes    *string   `json:"notes"`
	Disabled *bool     `json:"disabled"`
}

func (s *Server) PatchAgent(c Caller, id string, p AgentPatch) (*AgentView, error) {
	if p.Disabled != nil && c.Role != RoleAdmin {
		return nil, errors.New("only an admin can disable or enable agents")
	}
	if p.Groups != nil && c.Role != RoleAdmin {
		// Groups drive policy; letting the AI move a machine out of "ot"
		// would let it loosen its own guardrails.
		return nil, errors.New("only an admin can change agent groups (groups determine approval policy)")
	}
	s.store.mu.Lock()
	a, ok := s.store.st.Agents[id]
	if !ok {
		s.store.mu.Unlock()
		return nil, errors.New("no such agent")
	}
	if p.Groups != nil {
		gs, err := normGroups(*p.Groups)
		if err != nil {
			s.store.mu.Unlock()
			return nil, err
		}
		a.Groups = gs
	}
	if p.Notes != nil {
		a.Notes = *p.Notes
	}
	if p.Disabled != nil {
		a.Disabled = *p.Disabled
	}
	s.store.markDirty()
	v := s.viewLocked(a)
	s.store.mu.Unlock()
	s.Audit(c.String(), "agent.update", map[string]interface{}{"agent": id, "patch": p})
	return &v, nil
}

func (s *Server) CreateEnrollToken(c Caller, name string, groups []string, ttl time.Duration, maxUses int) (string, *EnrollToken, error) {
	if c.Role != RoleAdmin {
		return "", nil, errors.New("admin only")
	}
	secret := "et_" + randomHex(20)
	gs, err := normGroups(groups)
	if err != nil {
		return "", nil, err
	}
	t := &EnrollToken{ID: newID("t"), Name: name, Hash: hashSecret(secret), Groups: gs, MaxUses: maxUses, CreatedAt: now()}
	if ttl > 0 {
		t.ExpiresAt = now() + int64(ttl.Seconds())
	}
	s.store.mu.Lock()
	s.store.st.EnrollTokens[t.ID] = t
	s.store.markDirty()
	s.store.mu.Unlock()
	s.Audit(c.String(), "enroll_token.create", map[string]interface{}{"id": t.ID, "name": name, "groups": t.Groups, "max_uses": maxUses})
	return secret, t, nil
}

func (s *Server) CreateAPIKey(c Caller, name, role string) (string, error) {
	if role != RoleAdmin && role != RoleAI {
		return "", errors.New("role must be admin or ai")
	}
	secret := "rk_" + randomHex(24)
	k := &APIKey{ID: newID("k"), Name: name, Role: role, Hash: hashSecret(secret), CreatedAt: now()}
	s.store.mu.Lock()
	s.store.st.APIKeys[k.ID] = k
	s.store.markDirty()
	s.store.mu.Unlock()
	s.Audit(c.String(), "api_key.create", map[string]string{"id": k.ID, "name": name, "role": role})
	return secret, nil
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/"), "/")
	q := r.URL.Query()
	m := r.Method
	route := parts[0]
	arg := ""
	if len(parts) > 1 {
		arg = parts[1]
	}
	sub := ""
	if len(parts) > 2 {
		sub = parts[2]
	}
	adminOnly := func() bool {
		if c.Role != RoleAdmin {
			writeErr(w, 403, errors.New("admin only"))
			return false
		}
		return true
	}

	switch {
	case route == "whoami":
		writeJSON(w, 200, map[string]string{"name": c.Name, "role": c.Role, "server_version": s.Version})

	case route == "agents" && arg == "" && m == "GET":
		writeJSON(w, 200, s.ListAgents(q.Get("search"), q.Get("group"), q.Get("online") == "true"))
	case route == "agents" && arg != "" && m == "GET":
		v, err := s.GetAgent(arg)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, 200, v)
	case route == "agents" && arg != "" && m == "PATCH":
		var p AgentPatch
		if err := readJSON(r, &p); err != nil {
			writeErr(w, 400, err)
			return
		}
		v, err := s.PatchAgent(c, arg, p)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, v)

	case route == "tools" && arg == "" && m == "GET":
		writeJSON(w, 200, s.ListTools())
	case route == "tools" && arg != "" && sub == "" && m == "GET":
		t, ok := s.LookupTool(arg)
		if !ok {
			writeErr(w, 404, errors.New("no such tool"))
			return
		}
		writeJSON(w, 200, t)
	case route == "tools" && arg != "" && sub == "" && m == "PUT":
		var t Tool
		if err := readJSON(r, &t); err != nil {
			writeErr(w, 400, err)
			return
		}
		t.Name = arg
		saved, err := s.SaveTool(c, &t)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		s.Audit(c.String(), "tool.save", map[string]interface{}{"tool": t.Name, "version": saved.Version, "status": saved.Status, "risk": saved.Risk})
		writeJSON(w, 200, saved)
	case route == "tools" && arg != "" && (sub == "publish" || sub == "unpublish") && m == "POST":
		if !adminOnly() {
			return
		}
		st := ToolPublished
		if sub == "unpublish" {
			st = ToolDraft
		}
		if err := s.SetToolStatus(arg, st); err != nil {
			writeErr(w, 400, err)
			return
		}
		s.Audit(c.String(), "tool."+sub, map[string]string{"tool": arg})
		writeJSON(w, 200, map[string]string{"status": st})
	case route == "tools" && arg != "" && m == "DELETE":
		if !adminOnly() {
			return
		}
		if err := s.DeleteTool(arg); err != nil {
			writeErr(w, 400, err)
			return
		}
		s.Audit(c.String(), "tool.delete", map[string]string{"tool": arg})
		writeJSON(w, 200, map[string]bool{"ok": true})

	case route == "jobs" && arg == "" && m == "POST":
		var req SubmitRequest
		if err := readJSON(r, &req); err != nil {
			writeErr(w, 400, err)
			return
		}
		res, err := s.Submit(c, req)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if ws, _ := strconv.Atoi(q.Get("wait")); ws > 0 {
			if ws > 300 {
				ws = 300
			}
			res.Jobs = s.WaitJobs(r.Context(), jobIDs(res.Jobs), time.Duration(ws)*time.Second)
		}
		writeJSON(w, 200, res)
	case route == "jobs" && arg == "" && m == "GET":
		lim, _ := strconv.Atoi(q.Get("limit"))
		writeJSON(w, 200, s.ListJobs(JobFilter{AgentID: q.Get("agent"), BatchID: q.Get("batch"), Status: q.Get("status"), Tool: q.Get("tool"), Limit: lim}))
	case route == "jobs" && arg != "" && sub == "" && m == "GET":
		js := s.GetJobs([]string{arg})
		if len(js) == 0 {
			writeErr(w, 404, errors.New("no such job"))
			return
		}
		writeJSON(w, 200, js[0])
	case route == "jobs" && arg != "" && sub == "cancel" && m == "POST":
		if err := s.Cancel(c, arg); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	case route == "approvals" && m == "GET":
		writeJSON(w, 200, s.ListJobs(JobFilter{Status: protocol.StatusPendingApproval, Limit: 500}))
	case route == "approvals" && m == "POST":
		var body struct {
			BatchID string   `json:"batch_id"`
			JobIDs  []string `json:"job_ids"`
			Approve bool     `json:"approve"`
			Note    string   `json:"note"`
		}
		if err := readJSON(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		n, err := s.Decide(c, body.BatchID, body.JobIDs, body.Approve, body.Note)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]int{"decided": n})

	case route == "audit" && m == "GET":
		n, _ := strconv.Atoi(q.Get("n"))
		if n <= 0 || n > 5000 {
			n = 200
		}
		lines, err := s.ReadAudit(n)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, lines)

	case route == "enroll-tokens" && m == "POST":
		if !adminOnly() {
			return
		}
		var body struct {
			Name     string   `json:"name"`
			Groups   []string `json:"groups"`
			TTLHours int      `json:"ttl_hours"`
			MaxUses  int      `json:"max_uses"`
		}
		if err := readJSON(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		secret, t, err := s.CreateEnrollToken(c, body.Name, body.Groups, time.Duration(body.TTLHours)*time.Hour, body.MaxUses)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"token": secret, "info": t})

	default:
		writeErr(w, 404, errors.New("no such endpoint"))
	}
}

func jobIDs(js []*JobRecord) []string {
	out := make([]string, 0, len(js))
	for _, j := range js {
		out = append(out, j.ID)
	}
	return out
}
