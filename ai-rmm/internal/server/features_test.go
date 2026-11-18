package server

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

var (
	adminC = Caller{Name: "jane", Role: RoleAdmin}
	aiC    = Caller{Name: "claude", Role: RoleAI}
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.TLSCert, cfg.TLSKey = "", ""
	if err := SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSigningKey(dir); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func addAgent(s *Server, host string, f protocol.Facts, groups ...string) *Agent {
	a := &Agent{ID: newID("a"), Hostname: host, Groups: groups, Facts: f, LastSeen: now(), EnrolledAt: now()}
	s.store.mu.Lock()
	s.store.st.Agents[a.ID] = a
	s.store.mu.Unlock()
	return a
}

func TestVaultNeverExposesSecrets(t *testing.T) {
	s := newTestServer(t)
	if err := s.PutCredential(aiC, "x", CredWindows, "", map[string]string{"username": "u", "password": "p"}); err == nil {
		t.Fatal("AI must not store credentials")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.PutCredential(adminC, "domain-deploy", CredWindows, "rollout", map[string]string{"username": `CORP\svc-rmm`, "password": "Sup3r-S3cret!"}))
	must(s.Flush())
	b, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if strings.Contains(string(b), "Sup3r-S3cret!") {
		t.Fatal("plaintext password in state.json")
	}
	lb, _ := json.Marshal(s.ListCredentials())
	if strings.Contains(string(lb), "Sup3r") || !strings.Contains(string(lb), `svc-rmm`) {
		t.Fatalf("listing wrong: %s", lb)
	}
	// Tampering with ciphertext (or swapping between entries) must fail.
	s.store.mu.Lock()
	c := *s.store.st.Credentials["domain-deploy"]
	c.Name = "other"
	_, err := s.open(&c)
	s.store.mu.Unlock()
	if err == nil {
		t.Fatal("ciphertext bound to another name decrypted")
	}
}

func TestDeployInjectsSecretsAndSingleUseTokens(t *testing.T) {
	s := newTestServer(t)
	src := addAgent(s, "DC01", protocol.Facts{OSVersion: "10.0.20348", ProductType: "domain_controller"})
	_ = s.PutCredential(adminC, "domain-deploy", CredWindows, "", map[string]string{"username": `CORP\svc`, "password": "Pw-123456"})
	params := json.RawMessage(`{"computers":["PC-01","pc-02.corp.local"],"credential":"domain-deploy","groups":["Office"]}`)

	if _, err := s.Submit(aiC, SubmitRequest{Tool: "deploy_agent", Targets: []string{"DC01"}, Params: json.RawMessage(`{"computers":["x"],"credential":"nope"}`), Reason: "r"}); err == nil {
		t.Fatal("unknown credential should be refused at submit")
	}
	if _, err := s.Submit(aiC, SubmitRequest{Tool: "deploy_agent", Targets: []string{"DC01"}, Params: json.RawMessage(`{"computers":["bad name;rm"],"credential":"domain-deploy"}`), Reason: "r"}); err == nil {
		t.Fatal("bad hostname should be refused")
	}
	res, err := s.Submit(aiC, SubmitRequest{Tool: "deploy_agent", Targets: []string{"DC01"}, Params: params, Reason: "roll out"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Jobs[0].Status != protocol.StatusPendingApproval {
		t.Fatalf("deploy is high risk, expected approval: %s", res.Jobs[0].Status)
	}
	if _, err := s.Decide(adminC, res.BatchID, nil, true, ""); err != nil {
		t.Fatal(err)
	}
	jobs := s.takeJobs(src.ID, 8)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 dispatched job, got %d", len(jobs))
	}
	j := jobs[0]
	if j.Kind != "native" || j.Secrets["password"] != "Pw-123456" || j.Secrets["token:PC-01"] == "" || j.Secrets["token:PC-02.CORP.LOCAL"] == "" {
		t.Fatalf("secrets not injected: kind=%s keys=%v", j.Kind, keys(j.Secrets))
	}
	// Secrets are covered by the signature.
	pub := s.signKey.Public().(ed25519.PublicKey)
	j2 := j
	j2.Secrets = map[string]string{"password": "x"}
	if j2.Verify(pub, src.ID, time.Now()) == nil {
		t.Fatal("modified secrets verified")
	}
	if err := j.Verify(pub, src.ID, time.Now()); err != nil {
		t.Fatalf("genuine job: %v", err)
	}
	// Nothing secret is persisted with the job.
	_ = s.Flush()
	b, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if strings.Contains(string(b), "Pw-123456") || strings.Contains(string(b), j.Secrets["token:PC-01"]) {
		t.Fatal("secret persisted in state.json")
	}
	// Tokens are single use and carry the requested groups.
	tok := j.Secrets["token:PC-01"]
	s.store.mu.Lock()
	var et *EnrollToken
	for _, t := range s.store.st.EnrollTokens {
		if secretMatches(t.Hash, tok) {
			et = t
		}
	}
	s.store.mu.Unlock()
	if et == nil || et.MaxUses != 1 || len(et.Groups) != 1 || et.Groups[0] != "office" {
		t.Fatalf("token wrong: %+v", et)
	}
}

func TestCredentialParamsForCustomTools(t *testing.T) {
	s := newTestServer(t)
	a := addAgent(s, "PC1", protocol.Facts{})
	_ = s.PutCredential(adminC, "erp-api", CredGeneric, "", map[string]string{"token": "tok-abcdef"})
	_, err := s.SaveTool(adminC, &Tool{Name: "erp_check", Description: "d", Risk: protocol.RiskRead, Status: ToolPublished,
		Params: json.RawMessage(`{"type":"object","properties":{"cred":{"type":"string"}}}`), CredentialParams: []string{"cred"}, Script: "Get-RmmSecret 'cred.token'"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(aiC, SubmitRequest{Tool: "erp_check", Targets: []string{"PC1"}, Params: json.RawMessage(`{"cred":"missing"}`), Reason: "r"}); err == nil {
		t.Fatal("missing credential should fail")
	}
	if _, err := s.Submit(aiC, SubmitRequest{Tool: "erp_check", Targets: []string{"PC1"}, Params: json.RawMessage(`{"cred":"erp-api"}`), Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	jobs := s.takeJobs(a.ID, 8)
	if len(jobs) != 1 || jobs[0].Secrets["cred.token"] != "tok-abcdef" {
		t.Fatalf("credential param not delivered: %+v", jobs)
	}
}

func TestSchedulesApprovalAndRun(t *testing.T) {
	s := newTestServer(t)
	a := addAgent(s, "PC1", protocol.Facts{}, "office")
	sc, err := s.SaveSchedule(aiC, &Schedule{Name: "Patch office", Tool: "install_windows_updates", Targets: []string{"group:office"},
		Params: json.RawMessage(`{"reboot_if_required":true}`), Reason: "monthly patching", Days: []string{"wed"}, Time: "02:00", WindowMinutes: 180, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if sc.Approved {
		t.Fatal("AI schedule must start unapproved")
	}
	next := time.Unix(sc.NextRun, 0).In(s.location())
	if next.Weekday() != time.Wednesday || next.Hour() != 2 || !next.After(time.Now()) {
		t.Fatalf("bad next run %v", next)
	}
	force := func() {
		s.store.mu.Lock()
		s.store.st.Schedules[sc.ID].NextRun = now() - 60
		s.store.mu.Unlock()
	}
	force()
	s.runDueSchedules()
	if len(s.ListJobs(JobFilter{AgentID: a.ID})) != 0 {
		t.Fatal("unapproved schedule ran")
	}
	if err := s.ApproveSchedule(aiC, sc.ID); err == nil {
		t.Fatal("AI approved a schedule")
	}
	_ = s.ApproveSchedule(adminC, sc.ID)
	force()
	s.runDueSchedules()
	js := s.ListJobs(JobFilter{AgentID: a.ID})
	if len(js) != 1 || js[0].Status != protocol.StatusQueued || !strings.HasPrefix(js[0].RequestedBy, "schedule:") {
		t.Fatalf("approved schedule should queue a pre-approved high-risk job: %+v", js)
	}
	// Missed window (server down) is skipped, not run late.
	s.store.mu.Lock()
	s.store.st.Schedules[sc.ID].NextRun = now() - 4*3600
	s.store.mu.Unlock()
	s.runDueSchedules()
	if len(s.ListJobs(JobFilter{AgentID: a.ID})) != 1 {
		t.Fatal("missed window should not run")
	}
}

func TestScheduleWithChangedToolNeedsApproval(t *testing.T) {
	s := newTestServer(t)
	a := addAgent(s, "PC1", protocol.Facts{})
	tl := &Tool{Name: "my_fix", Description: "d", Risk: protocol.RiskRead, Status: ToolPublished, Script: "1"}
	if _, err := s.SaveTool(adminC, tl); err != nil {
		t.Fatal(err)
	}
	sc, _ := s.SaveSchedule(adminC, &Schedule{Name: "n", Tool: "my_fix", Targets: []string{"PC1"}, Reason: "r", Time: "03:00", Enabled: true})
	_, _ = s.SaveTool(aiC, &Tool{Name: "my_fix", Description: "d", Risk: protocol.RiskRead, Script: "Restart-Computer"})
	s.store.mu.Lock()
	s.store.st.Schedules[sc.ID].NextRun = now() - 60
	s.store.mu.Unlock()
	s.runDueSchedules()
	js := s.ListJobs(JobFilter{AgentID: a.ID})
	if len(js) != 1 || js[0].Status != protocol.StatusPendingApproval {
		t.Fatalf("changed tool must not run on the old approval: %+v", js)
	}
}

func TestMonitorIngestAndEvents(t *testing.T) {
	s := newTestServer(t)
	col := addAgent(s, "FS01", protocol.Facts{})
	_ = s.PutCredential(adminC, "snmp-ro", CredSNMP, "", map[string]string{"community": "s3cr3t-community"})
	d, err := s.SaveDevice(aiC, &NetDevice{Name: "core-sw1", Address: "10.0.0.2", Kind: "switch", CollectorAgentID: "FS01", SNMPCredential: "snmp-ro"})
	if err != nil {
		t.Fatal(err)
	}
	s.store.mu.Lock()
	mc := s.monitorConfigLocked(col.ID)
	s.store.mu.Unlock()
	if len(mc.Devices) != 1 || mc.Devices[0].SNMP == nil || mc.Devices[0].SNMP.Community != "s3cr3t-community" || mc.Version == "" {
		t.Fatalf("monitor config: %+v", mc)
	}
	rep := func(up bool, ifaces []protocol.Interface) {
		r := protocol.MonitorReport{DeviceID: d.ID, Time: now(), Up: up}
		if ifaces != nil {
			r.SNMP = &protocol.SNMPSnapshot{OK: true, SysName: "core-sw1", Interfaces: ifaces}
		}
		s.ingestMonitor(col.ID, []protocol.MonitorReport{r})
	}
	uplink := func(up bool) []protocol.Interface {
		return []protocol.Interface{{Index: 1, Name: "Gi1/0/48", Alias: "Uplink to FW", AdminUp: true, OperUp: up}, {Index: 2, Name: "Gi1/0/1", AdminUp: true, OperUp: up}}
	}
	rep(true, uplink(true))
	rep(false, nil) // one lost check: no alert yet
	if dv, _ := s.GetDevice("core-sw1"); dv.Status.State != "up" {
		t.Fatalf("single failure should not mark down: %s", dv.Status.State)
	}
	rep(false, nil)
	rep(true, uplink(false))
	types := map[string]int{}
	for _, e := range s.ListEvents(0, "", 100) {
		types[e.Type]++
	}
	if types["device_down"] != 1 || types["device_up"] != 1 || types["interface_down"] != 1 {
		t.Fatalf("events: %v", types)
	}
	// Reports from a non-collector agent are ignored.
	other := addAgent(s, "PC9", protocol.Facts{})
	s.ingestMonitor(other.ID, []protocol.MonitorReport{{DeviceID: d.ID, Time: now(), Up: false}})
	if dv, _ := s.GetDevice(d.ID); dv.Status.ConsecutiveFails != 0 {
		t.Fatal("foreign report accepted")
	}
}

func TestCrossGradeUpdate(t *testing.T) {
	cases := []struct {
		f             protocol.Facts
		arch, variant string
	}{
		{protocol.Facts{OSVersion: "10.0.19045", OSArch: "amd64", Arch: "386"}, "amd64", ""},
		{protocol.Facts{OSVersion: "6.1.7601", OSArch: "amd64", Arch: "386"}, "amd64", "legacy"},
		{protocol.Facts{OSVersion: "6.3.9600", OSArch: "386", Arch: "386"}, "386", "legacy"},
		{protocol.Facts{OSVersion: "10.0.22631", OSArch: "arm64", Arch: "386"}, "arm64", ""},
	}
	for _, c := range cases {
		if a, v := idealBuild(c.f); a != c.arch || v != c.variant {
			t.Errorf("%+v -> %s/%s, want %s/%s", c.f, a, v, c.arch, c.variant)
		}
	}
	s := newTestServer(t)
	ag := addAgent(s, "PC1", protocol.Facts{OSVersion: "10.0.19045", OSArch: "amd64", Arch: "386"})
	ag.Version, ag.Variant = "1.0.0", "legacy"
	s.AddRelease(adminC, &Release{OS: "windows", Arch: "386", Variant: "legacy", Version: "1.0.0", File: "a", CreatedAt: 1})
	s.store.mu.Lock()
	if u := s.updateForLocked(ag); u != nil {
		t.Fatalf("no ideal build published yet, nothing to do: %+v", u)
	}
	s.store.mu.Unlock()
	s.AddRelease(adminC, &Release{OS: "windows", Arch: "amd64", Variant: "", Version: "1.0.0", File: "b", CreatedAt: 2})
	s.store.mu.Lock()
	u := s.updateForLocked(ag)
	s.store.mu.Unlock()
	if u == nil || u.Arch != "amd64" || u.Variant != "" {
		t.Fatalf("expected cross-grade to amd64 modern, got %+v", u)
	}
}

func TestAgentOfflineEvents(t *testing.T) {
	s := newTestServer(t)
	serverStarted = time.Now().Add(-time.Hour)
	a := addAgent(s, "PC1", protocol.Facts{})
	s.store.mu.Lock()
	a.LastSeen = now() - 3600
	s.store.mu.Unlock()
	s.checkAgentsOffline()
	s.checkAgentsOffline() // only once per transition
	s.store.mu.Lock()
	a.LastSeen = now()
	s.store.mu.Unlock()
	s.checkAgentsOffline()
	if n := len(s.ListEvents(0, "agent_offline", 10)); n != 1 {
		t.Fatalf("offline events: %d", n)
	}
	if n := len(s.ListEvents(0, "agent_online", 10)); n != 1 {
		t.Fatalf("online events: %d", n)
	}
}

func TestPatchReport(t *testing.T) {
	s := newTestServer(t)
	a := addAgent(s, "PC1", protocol.Facts{OSName: "Windows 11"})
	b := addAgent(s, "PC2", protocol.Facts{})
	s.store.mu.Lock()
	s.store.st.Jobs["j1"] = &JobRecord{ID: "j1", AgentID: a.ID, Tool: "windows_update_status", Status: protocol.StatusSucceeded, FinishedAt: now(),
		Result: &protocol.JobResult{Data: json.RawMessage(`{"most_recent":[{"installed":"2026-11-12"}],"pending_reboot":true,"searched_missing":true,"missing_updates":[{"title":"2026-11 CU","severity":"Critical"}]}`)}}
	s.store.mu.Unlock()
	r := s.patchReport("", false)
	sum := r["summary"].(map[string]int)
	if sum["machines"] != 2 || sum["missing_updates"] != 1 || sum["pending_reboot"] != 1 || sum["no_recent_scan"] != 1 || sum["compliant"] != 0 {
		t.Fatalf("summary %v", sum)
	}
	_ = b
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
