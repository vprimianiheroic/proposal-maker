//go:build windows

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/airmm/airmm/internal/protocol"
)

// Push-install, PsExec style:
//   1. authenticate an SMB session to \\target\ADMIN$ with the vault credential
//   2. copy rmm-agent.exe + a bootstrap config (single-use enrollment token)
//      to %SystemRoot%\Temp\AIRMM-Setup on the target
//   3. over the same session, create and start a one-shot "AIRMMSetup"
//      service that runs `rmm-agent.exe bootstrap`, which performs a normal
//      install (Program Files, AIRMMAgent service, watchdog) and exits
//   4. remove the setup service and files; verify AIRMMAgent is running
// The password and token never appear on a command line.

const setupService = "AIRMMSetup"

var (
	mpr                      = windows.NewLazySystemDLL("mpr.dll")
	procWNetAddConnection2W  = mpr.NewProc("WNetAddConnection2W")
	procWNetCancelConnection = mpr.NewProc("WNetCancelConnection2W")
)

type netResource struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

func wnetConnect(remote, user, pass string) error {
	r16, _ := windows.UTF16PtrFromString(remote)
	u16, _ := windows.UTF16PtrFromString(user)
	p16, _ := windows.UTF16PtrFromString(pass)
	nr := netResource{Type: 1 /* RESOURCETYPE_DISK */, RemoteName: r16}
	rc, _, _ := procWNetAddConnection2W.Call(uintptr(unsafe.Pointer(&nr)), uintptr(unsafe.Pointer(p16)), uintptr(unsafe.Pointer(u16)), 4 /* CONNECT_TEMPORARY */)
	if rc == 1219 { // ERROR_SESSION_CREDENTIAL_CONFLICT: drop the old session and retry
		wnetDisconnect(remote)
		rc, _, _ = procWNetAddConnection2W.Call(uintptr(unsafe.Pointer(&nr)), uintptr(unsafe.Pointer(p16)), uintptr(unsafe.Pointer(u16)), 4)
	}
	if rc != 0 {
		return syscallErr(rc)
	}
	return nil
}

func wnetDisconnect(remote string) {
	r16, _ := windows.UTF16PtrFromString(remote)
	procWNetCancelConnection.Call(uintptr(unsafe.Pointer(r16)), 0, 1)
}

func syscallErr(rc uintptr) error {
	switch rc {
	case 5:
		return errors.New("access denied (credential is not a local administrator on the target, or UAC remote restrictions apply)")
	case 53, 67:
		return errors.New("network path not found (name doesn't resolve, or File and Printer Sharing is blocked)")
	case 1326:
		return errors.New("logon failure: wrong username or password")
	case 1909:
		return errors.New("the deployment account is locked out")
	case 1331:
		return errors.New("the deployment account is disabled")
	}
	return fmt.Errorf("%v (code %d)", windows.Errno(rc), rc)
}

type deployResult struct {
	Computer string  `json:"computer"`
	Status   string  `json:"status"` // installed | already_installed | ok_dry_run | failed
	Stage    string  `json:"stage,omitempty"`
	Detail   string  `json:"detail,omitempty"`
	Seconds  float64 `json:"seconds"`
}

func nativeDeployAgent(ctx context.Context, a *Agent, job *protocol.Job) (interface{}, error) {
	var p struct {
		Computers []string `json:"computers"`
		DryRun    bool     `json:"dry_run"`
		Force     bool     `json:"force"`
		Bootstrap *struct {
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		} `json:"_bootstrap"`
	}
	if err := json.Unmarshal(job.Params, &p); err != nil {
		return nil, err
	}
	user, pass := job.Secrets["username"], job.Secrets["password"]
	if user == "" || pass == "" {
		return nil, errors.New("no deployment credential delivered with the job")
	}

	installer := ""
	if !p.DryRun {
		work := filepath.Join(a.DataDir, "work", job.ID)
		if err := os.MkdirAll(work, 0o700); err != nil {
			return nil, err
		}
		defer os.RemoveAll(work)
		if p.Bootstrap != nil && p.Bootstrap.URL != "" {
			path := filepath.Join(work, "rmm-agent.exe")
			if err := a.download(ctx, p.Bootstrap.URL, p.Bootstrap.SHA256, path); err != nil {
				return nil, fmt.Errorf("fetch installer build: %w", err)
			}
			installer = path
		} else {
			// No release published on the server: push our own binary.
			exe, err := os.Executable()
			if err != nil {
				return nil, err
			}
			installer = exe
		}
	}

	results := make([]deployResult, len(p.Computers))
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for i, c := range p.Computers {
		wg.Add(1)
		go func(i int, c string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			r := a.deployOne(ctx, c, user, pass, job.Secrets["token:"+strings.ToUpper(c)], installer, p.DryRun, p.Force)
			r.Computer, r.Seconds = c, time.Since(start).Round(100*time.Millisecond).Seconds()
			results[i] = r
		}(i, c)
	}
	wg.Wait()
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	out := map[string]interface{}{"summary": counts, "results": results}
	if counts["failed"] == len(results) {
		return out, errors.New("deployment failed on every computer; see results")
	}
	return out, nil
}

func (a *Agent) deployOne(ctx context.Context, host, user, pass, token, installer string, dryRun, force bool) deployResult {
	fail := func(stage string, err error) deployResult {
		return deployResult{Status: "failed", Stage: stage, Detail: err.Error()}
	}
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, "445"))
	if err != nil {
		return fail("connect", fmt.Errorf("TCP 445 unreachable: %v (offline, or firewall blocks File and Printer Sharing)", err))
	}
	c.Close()

	share := `\\` + host + `\ADMIN$`
	if err := wnetConnect(share, user, pass); err != nil {
		return fail("authenticate", err)
	}
	defer wnetDisconnect(share)

	m, err := mgr.ConnectRemote(host)
	if err != nil {
		return fail("service_manager", fmt.Errorf("open remote service manager: %v", err))
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		st, _ := s.Query()
		s.Close()
		if !force {
			return deployResult{Status: "already_installed", Detail: fmt.Sprintf("AIRMMAgent service exists (state %d); use force to reinstall", st.State)}
		}
	}
	if dryRun {
		return deployResult{Status: "ok_dry_run", Detail: "SMB, ADMIN$ and remote service control all work with this credential"}
	}
	if token == "" {
		return fail("token", errors.New("server did not issue an enrollment token for this computer"))
	}

	// Stage files.
	dir := share + `\Temp\AIRMM-Setup`
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("copy", err)
	}
	defer func() {
		for i := 0; i < 5; i++ { // the bootstrap process may still be exiting
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
	if err := copyPlain(installer, dir+`\rmm-agent.exe`); err != nil {
		return fail("copy", err)
	}
	boot := &Config{ServerURL: a.Cfg.ServerURL, ServerURLs: a.Cfg.ServerURLs, InstallURL: a.Cfg.InstallURL,
		ServerPubKey: a.Cfg.ServerPubKey, TLSPinSHA256: a.Cfg.TLSPinSHA256, EnrollToken: token}
	b, _ := json.MarshalIndent(boot, "", "  ")
	if err := os.WriteFile(dir+`\agent.json`, b, 0o600); err != nil {
		return fail("copy", err)
	}

	// Run the one-shot setup service.
	if old, err := m.OpenService(setupService); err == nil {
		_, _ = old.Control(svc.Stop)
		_ = old.Delete()
		old.Close()
		time.Sleep(2 * time.Second)
	}
	s, err := m.CreateService(setupService, `%SystemRoot%\Temp\AIRMM-Setup\rmm-agent.exe`, mgr.Config{
		DisplayName: "AI-RMM Agent Setup", StartType: mgr.StartManual, ErrorControl: mgr.ErrorIgnore,
	}, "bootstrap")
	if err != nil {
		return fail("create_setup_service", err)
	}
	defer func() {
		_ = s.Delete()
		s.Close()
	}()
	if err := s.Start(); err != nil {
		return fail("start_setup_service", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	var st svc.Status
	for time.Now().Before(deadline) {
		if !sleepCtx(ctx, 2*time.Second) {
			return fail("install", ctx.Err())
		}
		if st, err = s.Query(); err != nil || st.State == svc.Stopped {
			break
		}
	}
	detail, _ := os.ReadFile(dir + `\bootstrap-result.txt`)
	if st.State != svc.Stopped {
		return fail("install", errors.New("setup did not finish within 3 minutes"))
	}
	if st.ServiceSpecificExitCode != 0 || st.Win32ExitCode != 0 && st.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
		return fail("install", fmt.Errorf("setup exited with %d/%d: %s", st.Win32ExitCode, st.ServiceSpecificExitCode, strings.TrimSpace(string(detail))))
	}

	// Verify.
	ag, err := m.OpenService(ServiceName)
	if err != nil {
		return fail("verify", fmt.Errorf("AIRMMAgent service not found after setup: %s", strings.TrimSpace(string(detail))))
	}
	defer ag.Close()
	for i := 0; i < 10; i++ {
		if st, err = ag.Query(); err == nil && st.State == svc.Running {
			return deployResult{Status: "installed", Detail: "agent running; it will enroll and appear in list_agents shortly"}
		}
		time.Sleep(time.Second)
	}
	return fail("verify", fmt.Errorf("AIRMMAgent installed but not running (state %d)", st.State))
}

// download fetches a server-hosted build and checks the hash from the signed job.
func (a *Agent) download(ctx context.Context, url, sha, dst string) error {
	if !strings.HasPrefix(url, "/api/v1/agent/release/") {
		return errors.New("unexpected download URL")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", a.endpoint()+url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Cfg.AgentID+"."+a.Cfg.AgentSecret)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	f.Close()
	if err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sha) {
		return errors.New("sha256 mismatch")
	}
	return nil
}

func copyPlain(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
