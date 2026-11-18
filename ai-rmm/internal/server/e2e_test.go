package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/airmm/airmm/internal/agent"
	"github.com/airmm/airmm/internal/protocol"
	"github.com/airmm/airmm/internal/server"
)

// fakePS stands in for powershell.exe: it echoes the tool name and params
// back as the structured result, after some host noise, so the full
// server -> signed job -> agent -> result path is exercised without Windows.
const fakePS = `#!/bin/sh
echo "host noise before result"
if grep -q '"fail":true' "$RMM_PARAMS_FILE"; then echo "boom" >&2; exit 1; fi
if grep -q '"sleep":true' "$RMM_PARAMS_FILE"; then sleep 30; fi
if grep -q '"echo_secret":true' "$RMM_PARAMS_FILE"; then echo "stdout leak: $(cat "$RMM_SECRETS_FILE")"; echo '<<<RMM-DATA>>>'; printf '{"leak":%s}\n' "$(cat "$RMM_SECRETS_FILE")"; exit 0; fi
grep -q 'Get-RmmParam' "$RMM_SCRIPT_FILE" || { echo "prelude missing" >&2; exit 9; }
echo '<<<RMM-DATA>>>'
printf '{"tool":"%s","params":%s}\n' "$RMM_TOOL" "$(cat "$RMM_PARAMS_FILE")"
`

type env struct {
	t        *testing.T
	srv      *server.Server
	http     *httptest.Server
	adminKey string
	aiKey    string
	agentCfg string
	cancel   context.CancelFunc
	agent    *agent.Agent
}

func setup(t *testing.T, mutateCfg func(*server.Config)) *env {
	return setupFull(t, mutateCfg, nil)
}

func setupFull(t *testing.T, mutateCfg func(*server.Config), mutateAgent func(c *agent.Config, serverURL string)) *env {
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh fake interpreter")
	}
	dir := t.TempDir()
	cfg := server.DefaultConfig()
	cfg.TLSCert, cfg.TLSKey = "", ""
	if mutateCfg != nil {
		mutateCfg(cfg)
	}
	must(t, os.MkdirAll(filepath.Join(dir, "releases"), 0o700))
	must(t, server.SaveConfig(dir, cfg))
	pub, err := server.GenerateSigningKey(dir)
	must(t, err)
	s, err := server.New(dir, "test")
	must(t, err)
	admin := server.Caller{Name: "test", Role: server.RoleAdmin}
	adminKey, _ := s.CreateAPIKey(admin, "admin", server.RoleAdmin)
	aiKey, _ := s.CreateAPIKey(admin, "claude", server.RoleAI)
	tok, _, err := s.CreateEnrollToken(admin, "t", []string{"plant1"}, time.Hour, 0)
	must(t, err)
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(func() { hs.Close(); s.Close() })

	adir := t.TempDir()
	ps := filepath.Join(adir, "fakeps.sh")
	must(t, os.WriteFile(ps, []byte(fakePS), 0o755))
	acfg := &agent.Config{ServerURL: hs.URL, EnrollToken: tok, PowerShellPath: ps}
	acfg.ServerPubKey = b64(pub)
	if mutateAgent != nil {
		mutateAgent(acfg, hs.URL)
	}
	cfgPath := filepath.Join(adir, "agent.json")
	must(t, acfg.Validate())
	must(t, acfg.Save(cfgPath))
	loaded, err := agent.LoadConfig(cfgPath)
	must(t, err)
	a, err := agent.New(loaded, "1.0.0", "")
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = a.Run(ctx) }()
	t.Cleanup(cancel)
	e := &env{t: t, srv: s, http: hs, adminKey: adminKey, aiKey: aiKey, agentCfg: cfgPath, cancel: cancel, agent: a}
	e.waitFor(func() bool { return len(s.ListAgents("", "", true)) == 1 }, "agent enrollment")
	return e
}

func (e *env) waitFor(cond func() bool, what string) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatalf("timed out waiting for %s", what)
}

func (e *env) api(key, method, path string, body interface{}, out interface{}) int {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.http.URL+path, r)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: decode %q: %v", method, path, b, err)
		}
	}
	return resp.StatusCode
}

func (e *env) mcp(key, method string, params interface{}) map[string]interface{} {
	var out map[string]interface{}
	code := e.api(key, "POST", "/mcp", map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, &out)
	if code != 200 {
		e.t.Fatalf("mcp %s: HTTP %d %v", method, code, out)
	}
	return out
}

func mcpText(t *testing.T, resp map[string]interface{}) (string, bool) {
	res, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	content := res["content"].([]interface{})
	isErr, _ := res["isError"].(bool)
	return content[0].(map[string]interface{})["text"].(string), isErr
}

func TestReadToolAutoRunsAndReturnsData(t *testing.T) {
	e := setup(t, nil)
	var res server.SubmitResult
	code := e.api(e.aiKey, "POST", "/api/v1/jobs?wait=10", map[string]interface{}{
		"tool": "list_services", "targets": []string{"all"}, "params": map[string]interface{}{"stopped_auto_only": true}, "reason": "triage",
	}, &res)
	if code != 200 || len(res.Jobs) != 1 {
		t.Fatalf("submit: %d %+v", code, res)
	}
	j := res.Jobs[0]
	if j.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s, result %+v", j.Status, j.Result)
	}
	var data struct {
		Tool   string                 `json:"tool"`
		Params map[string]interface{} `json:"params"`
	}
	must(t, json.Unmarshal(j.Result.Data, &data))
	if data.Tool != "list_services" || data.Params["stopped_auto_only"] != true {
		t.Fatalf("unexpected data %s", j.Result.Data)
	}
	if !strings.Contains(j.Result.Stdout, "host noise") || strings.Contains(j.Result.Stdout, "RMM-DATA") {
		t.Fatalf("stdout not split correctly: %q", j.Result.Stdout)
	}
}

func TestParamValidationAndReasonRequired(t *testing.T) {
	e := setup(t, nil)
	var errOut map[string]string
	if c := e.api(e.aiKey, "POST", "/api/v1/jobs", map[string]interface{}{"tool": "list_services", "targets": []string{"all"}}, &errOut); c != 400 || !strings.Contains(errOut["error"], "reason") {
		t.Fatalf("expected reason error, got %d %v", c, errOut)
	}
	if c := e.api(e.aiKey, "POST", "/api/v1/jobs", map[string]interface{}{"tool": "list_services", "targets": []string{"all"}, "reason": "x", "params": map[string]interface{}{"bogus": 1}}, &errOut); c != 400 || !strings.Contains(errOut["error"], "unknown param") {
		t.Fatalf("expected unknown param error, got %d %v", c, errOut)
	}
	if c := e.api(e.aiKey, "POST", "/api/v1/jobs", map[string]interface{}{"tool": "service_control", "targets": []string{"all"}, "reason": "x", "params": map[string]interface{}{"name": "Spooler", "action": "explode"}}, &errOut); c != 400 || !strings.Contains(errOut["error"], "must be one of") {
		t.Fatalf("expected enum error, got %d %v", c, errOut)
	}
}

func TestHighRiskNeedsHumanApproval(t *testing.T) {
	e := setup(t, nil)
	var res server.SubmitResult
	e.api(e.aiKey, "POST", "/api/v1/jobs?wait=2", map[string]interface{}{
		"tool": "reboot", "targets": []string{"group:plant1"}, "reason": "apply updates",
	}, &res)
	if res.Jobs[0].Status != protocol.StatusPendingApproval {
		t.Fatalf("expected pending approval, got %s", res.Jobs[0].Status)
	}
	// The AI key cannot approve its own request.
	var out map[string]interface{}
	if c := e.api(e.aiKey, "POST", "/api/v1/approvals", map[string]interface{}{"batch_id": res.BatchID, "approve": true}, &out); c != 400 {
		t.Fatalf("ai approval should fail, got %d", c)
	}
	if c := e.api(e.adminKey, "POST", "/api/v1/approvals", map[string]interface{}{"batch_id": res.BatchID, "approve": true}, &out); c != 200 {
		t.Fatalf("admin approval failed: %d %v", c, out)
	}
	jobs := e.srv.WaitJobs(context.Background(), []string{res.Jobs[0].ID}, 10*time.Second)
	if jobs[0].Status != protocol.StatusSucceeded || jobs[0].DecidedBy != "admin:admin" {
		t.Fatalf("after approval: %s by %s", jobs[0].Status, jobs[0].DecidedBy)
	}
}

func TestGroupPolicyTightens(t *testing.T) {
	e := setup(t, func(c *server.Config) {
		c.GroupPolicies["plant1"] = server.Policy{AutoApproveMaxRisk: protocol.RiskRead, AllowAdHocScripts: false}
	})
	var res server.SubmitResult
	e.api(e.aiKey, "POST", "/api/v1/jobs", map[string]interface{}{
		"tool": "flush_dns", "targets": []string{"all"}, "reason": "dns stale",
	}, &res)
	if res.Jobs[0].Status != protocol.StatusPendingApproval || !strings.Contains(res.Jobs[0].ApprovalReason, "group:plant1") {
		t.Fatalf("change on plant1 should need approval: %+v", res.Jobs[0])
	}
	var out map[string]string
	if c := e.api(e.aiKey, "POST", "/api/v1/jobs", map[string]interface{}{"script": "Get-Date", "targets": []string{"all"}, "reason": "x"}, &out); c != 400 || !strings.Contains(out["error"], "disabled by policy") {
		t.Fatalf("ad-hoc should be refused: %d %v", c, out)
	}
	// The AI cannot move the machine out of the restrictive group.
	agents := e.srv.ListAgents("", "", false)
	if c := e.api(e.aiKey, "PATCH", "/api/v1/agents/"+agents[0].ID, map[string]interface{}{"groups": []string{}}, &out); c != 400 {
		t.Fatalf("ai should not change groups: %d", c)
	}
}

func TestDraftToolLifecycleViaMCP(t *testing.T) {
	e := setup(t, nil)
	init := e.mcp(e.aiKey, "initialize", map[string]interface{}{"protocolVersion": "2025-06-18"})
	if init["result"].(map[string]interface{})["instructions"] == "" {
		t.Fatal("missing instructions")
	}
	tl := e.mcp(e.aiKey, "tools/list", nil)
	if n := len(tl["result"].(map[string]interface{})["tools"].([]interface{})); n < 10 {
		t.Fatalf("expected MCP tools, got %d", n)
	}
	txt, isErr := mcpText(t, e.mcp(e.aiKey, "tools/call", map[string]interface{}{"name": "save_tool", "arguments": map[string]interface{}{
		"name": "check_label_printer", "description": "Check the Zebra printer", "risk": "read",
		"params_schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"printer": map[string]string{"type": "string"}}},
		"script":        "Get-RmmParam 'printer'",
	}}))
	if isErr || !strings.Contains(txt, `"draft"`) {
		t.Fatalf("save_tool: %s", txt)
	}
	// Even though the draft says "read", running it needs approval.
	txt, _ = mcpText(t, e.mcp(e.aiKey, "tools/call", map[string]interface{}{"name": "run_tool", "arguments": map[string]interface{}{
		"tool": "check_label_printer", "targets": []string{"all"}, "params": map[string]string{"printer": "ZT410"}, "reason": "labels not printing", "wait_seconds": 1,
	}}))
	if !strings.Contains(txt, "pending_approval") || !strings.Contains(txt, "unpublished draft") {
		t.Fatalf("draft run should need approval: %s", txt)
	}
	// Admin publishes; now it runs automatically.
	if c := e.api(e.adminKey, "POST", "/api/v1/tools/check_label_printer/publish", nil, nil); c != 200 {
		t.Fatalf("publish: %d", c)
	}
	txt, _ = mcpText(t, e.mcp(e.aiKey, "tools/call", map[string]interface{}{"name": "run_tool", "arguments": map[string]interface{}{
		"tool": "check_label_printer", "targets": []string{"all"}, "params": map[string]string{"printer": "ZT410"}, "reason": "labels not printing", "wait_seconds": 10,
	}}))
	if !strings.Contains(txt, `"succeeded"`) || !strings.Contains(txt, "ZT410") {
		t.Fatalf("published tool should run: %s", txt)
	}
	// An AI edit sends it back to draft.
	mcpText(t, e.mcp(e.aiKey, "tools/call", map[string]interface{}{"name": "save_tool", "arguments": map[string]interface{}{
		"name": "check_label_printer", "description": "v2", "risk": "read", "script": "Restart-Computer",
	}}))
	tool, _ := e.srv.LookupTool("check_label_printer")
	if tool.Status != server.ToolDraft || tool.Version != 2 {
		t.Fatalf("AI edit must reset to draft: %+v", tool)
	}
	// Built-ins can't be shadowed.
	txt, isErr = mcpText(t, e.mcp(e.aiKey, "tools/call", map[string]interface{}{"name": "save_tool", "arguments": map[string]interface{}{
		"name": "system_info", "description": "x", "risk": "read", "script": "x",
	}}))
	if !isErr {
		t.Fatalf("shadowing a builtin should fail: %s", txt)
	}
}

func TestFailureAndTimeoutReported(t *testing.T) {
	e := setup(t, nil)
	e.srv.Cfg.DefaultPolicy.AutoApproveMaxRisk = protocol.RiskHigh
	var res server.SubmitResult
	e.api(e.aiKey, "POST", "/api/v1/jobs?wait=10", map[string]interface{}{
		"script": "throw 'x'", "targets": []string{"all"}, "reason": "test", "params": map[string]bool{"fail": true},
	}, &res)
	j := res.Jobs[0]
	if j.Status != protocol.StatusFailed || j.Result.ExitCode != 1 || !strings.Contains(j.Result.Stderr, "boom") {
		t.Fatalf("expected failure: %s %+v", j.Status, j.Result)
	}
	e.api(e.aiKey, "POST", "/api/v1/jobs?wait=15", map[string]interface{}{
		"script": "Start-Sleep 99", "targets": []string{"all"}, "reason": "test", "timeout_sec": 2, "params": map[string]bool{"sleep": true},
	}, &res)
	if res.Jobs[0].Status != protocol.StatusTimeout {
		t.Fatalf("expected timeout, got %s", res.Jobs[0].Status)
	}
}

func TestAgentRejectsForgedJob(t *testing.T) {
	e := setup(t, nil)
	// A job signed by a different key must be refused by the agent even if
	// it arrives over the authenticated channel.
	other := t.TempDir()
	_, err := server.GenerateSigningKey(other)
	must(t, err)
	key, _ := server.LoadSigningKey(other)
	cfg, _ := agent.LoadConfig(e.agentCfg)
	j := protocol.Job{ID: "j_forged", AgentID: cfg.AgentID, Tool: "x", Script: "Restart-Computer", Params: json.RawMessage(`{}`), TimeoutSec: 10, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	j.Sign(key)
	pub, _ := cfg.PublicKey()
	if err := j.Verify(pub, cfg.AgentID, time.Now()); err == nil {
		t.Fatal("forged job verified")
	}
	j2 := j
	realKey, _ := server.LoadSigningKey(e.srv.Dir)
	j2.Sign(realKey)
	if err := j2.Verify(pub, cfg.AgentID, time.Now()); err != nil {
		t.Fatalf("genuine job failed: %v", err)
	}
	j2.Script = "tampered"
	if err := j2.Verify(pub, cfg.AgentID, time.Now()); err == nil {
		t.Fatal("tampered job verified")
	}
	if err := j2.Verify(pub, "a_someoneelse", time.Now()); err == nil {
		t.Fatal("job for another agent verified")
	}
}

func TestBadCredentials(t *testing.T) {
	e := setup(t, nil)
	if c := e.api("nope", "GET", "/api/v1/agents", nil, nil); c != 401 {
		t.Fatalf("expected 401, got %d", c)
	}
	req, _ := http.NewRequest("POST", e.http.URL+"/api/v1/agent/poll", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer a_x.y")
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for bad agent creds, got %d", resp.StatusCode)
	}
	var out map[string]string
	if c := e.api("", "POST", "/api/v1/agent/enroll", map[string]string{"token": "et_wrong"}, &out); c != 403 {
		t.Fatalf("expected 403 for bad enroll token, got %d", c)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestAgentFailsOverToSecondServerAddress(t *testing.T) {
	// Primary address is dead; the agent must still enroll via the fallback.
	e := setupFull(t, nil, func(c *agent.Config, url string) {
		c.ServerURL = "http://127.0.0.1:1"
		c.ServerURLs = []string{url}
		c.InstallURL = "http://127.0.0.1:1"
	})
	if len(e.srv.ListAgents("", "", true)) != 1 {
		t.Fatal("agent did not enroll through the fallback address")
	}
}

func TestServerPushesAddressList(t *testing.T) {
	var url string
	e := setupFull(t, nil, func(c *agent.Config, u string) { url = u })
	e.srv.Cfg.AgentServerURLs = []string{url, "https://rmm-backup.corp.local:8443"}
	// Wake the long poll so the agent gets a fresh response.
	var res server.SubmitResult
	e.api(e.aiKey, "POST", "/api/v1/jobs?wait=10", map[string]interface{}{"tool": "system_info", "targets": []string{"all"}, "reason": "x"}, &res)
	e.waitFor(func() bool {
		c, err := agent.LoadConfig(e.agentCfg)
		return err == nil && len(c.ServerURLs) == 1 && c.ServerURLs[0] == "https://rmm-backup.corp.local:8443" && c.InstallURL != ""
	}, "pushed server URL list to be saved")
}

func TestSecretsReachScriptButAreRedacted(t *testing.T) {
	e := setup(t, nil)
	admin := server.Caller{Name: "test", Role: server.RoleAdmin}
	must(t, e.srv.PutCredential(admin, "erp", server.CredGeneric, "", map[string]string{"apikey": "VERY-SECRET-KEY-42"}))
	_, err := e.srv.SaveTool(admin, &server.Tool{Name: "leaky", Description: "tries to leak", Risk: protocol.RiskRead, Status: server.ToolPublished,
		Params: json.RawMessage(`{"type":"object","properties":{"cred":{"type":"string"},"echo_secret":{"type":"boolean"}}}`), CredentialParams: []string{"cred"}, Script: "Get-RmmSecret 'cred.apikey'"})
	must(t, err)
	var res server.SubmitResult
	e.api(e.aiKey, "POST", "/api/v1/jobs?wait=10", map[string]interface{}{"tool": "leaky", "targets": []string{"all"}, "reason": "x", "params": map[string]interface{}{"cred": "erp", "echo_secret": true}}, &res)
	j := res.Jobs[0]
	if j.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s %+v", j.Status, j.Result)
	}
	all := j.Result.Stdout + j.Result.Stderr + string(j.Result.Data)
	if strings.Contains(all, "VERY-SECRET-KEY-42") {
		t.Fatalf("secret leaked: %s", all)
	}
	if !strings.Contains(all, "[REDACTED]") || !strings.Contains(string(j.Result.Data), "cred.apikey") {
		t.Fatalf("expected the script to have received (redacted) secrets: %s", all)
	}
}

func TestNativeNetworkScan(t *testing.T) {
	e := setup(t, nil)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(e.http.URL, "http://"))
	p, _ := strconv.Atoi(port)
	var res server.SubmitResult
	e.api(e.aiKey, "POST", "/api/v1/jobs?wait=20", map[string]interface{}{"tool": "network_scan", "targets": []string{"all"}, "reason": "discover",
		"params": map[string]interface{}{"cidr": "127.0.0.1/32", "ports": []int{p}, "ping": false}}, &res)
	j := res.Jobs[0]
	if j.Status != protocol.StatusSucceeded {
		t.Fatalf("scan: %s %+v", j.Status, j.Result)
	}
	var d struct {
		Alive int `json:"alive"`
		Hosts []struct {
			IP        string `json:"ip"`
			OpenPorts []int  `json:"open_ports"`
		} `json:"hosts"`
	}
	must(t, json.Unmarshal(j.Result.Data, &d))
	if d.Alive != 1 || d.Hosts[0].IP != "127.0.0.1" || len(d.Hosts[0].OpenPorts) != 1 || d.Hosts[0].OpenPorts[0] != p {
		t.Fatalf("scan result %s", j.Result.Data)
	}
	var out map[string]string
	if c := e.api(e.aiKey, "POST", "/api/v1/jobs", map[string]interface{}{"tool": "network_scan", "targets": []string{"all"}, "reason": "x", "params": map[string]interface{}{"cidr": "10.0.0.0/16"}}, &out); c != 400 {
		t.Fatalf("oversized scan should be refused: %d %v", c, out)
	}
}

func TestDeployFromNonWindowsSourceFailsCleanly(t *testing.T) {
	e := setup(t, nil)
	admin := server.Caller{Name: "test", Role: server.RoleAdmin}
	must(t, e.srv.PutCredential(admin, "deploy", server.CredWindows, "", map[string]string{"username": "CORP\\svc", "password": "pw-secret-1"}))
	var res server.SubmitResult
	e.api(e.adminKey, "POST", "/api/v1/jobs?wait=10", map[string]interface{}{"tool": "deploy_agent", "targets": []string{"all"}, "reason": "x",
		"params": map[string]interface{}{"computers": []string{"PC-01"}, "credential": "deploy"}}, &res)
	j := res.Jobs[0]
	if j.Status != protocol.StatusFailed || !strings.Contains(j.Result.Stderr, "Windows") {
		t.Fatalf("expected clean failure: %s %+v", j.Status, j.Result)
	}
}
