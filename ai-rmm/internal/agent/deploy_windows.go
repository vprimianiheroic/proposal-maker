//go:build windows

package agent

import (
	"context"
	"crypto/rand"
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
	"runtime"
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
//   1. impersonate the vault credential (LogonUser NEW_CREDENTIALS) on a
//      locked OS thread, so SMB and remote SCM calls use it
//   2. copy rmm-agent.exe + a bootstrap config (single-use enrollment token)
//      to a random, SYSTEM/Administrators-only folder in %SystemRoot%\Temp
//   3. over the same session, create and start a one-shot "AIRMMSetup"
//      service that runs `rmm-agent.exe bootstrap`, which performs a normal
//      install (Program Files, AIRMMAgent service, watchdog) and exits
//   4. remove the setup service and files; verify AIRMMAgent is running
// The password and token never appear on a command line.

const setupService = "AIRMMSetup"

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW              = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
)

const (
	logon32LogonNewCredentials = 9 // outbound-only: network access uses these creds
	logon32ProviderWinNT50     = 3
)

// splitUser accepts DOMAIN\user or user@domain (UPN, domain left empty).
func splitUser(u string) (user, domain string) {
	if i := strings.IndexByte(u, '\\'); i > 0 {
		return u[i+1:], u[:i]
	}
	return u, ""
}

// impersonate gives the calling OS thread a private outbound credential
// context. Unlike WNetAddConnection2 this never conflicts with SYSTEM's
// existing SMB sessions (e.g. the machine account's SYSVOL connection to a
// DC), and it also covers RPC-over-TCP to the remote service manager.
// The caller must hold runtime.LockOSThread and call windows.RevertToSelf.
func impersonate(username, password string) (windows.Token, error) {
	user, domain := splitUser(username)
	u16, _ := windows.UTF16PtrFromString(user)
	p16, _ := windows.UTF16PtrFromString(password)
	var d16 *uint16
	if domain != "" {
		d16, _ = windows.UTF16PtrFromString(domain)
	}
	var tok windows.Token
	r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(u16)), uintptr(unsafe.Pointer(d16)), uintptr(unsafe.Pointer(p16)),
		logon32LogonNewCredentials, logon32ProviderWinNT50, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return 0, fmt.Errorf("LogonUser: %v", e)
	}
	if r, _, e := procImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
		tok.Close()
		return 0, fmt.Errorf("ImpersonateLoggedOnUser: %v", e)
	}
	return tok, nil
}

// explain maps common Win32 errors from remote operations to plain advice.
func explain(err error) error {
	var en windows.Errno
	if !errors.As(err, &en) {
		return err
	}
	switch en {
	case 5:
		return errors.New("access denied (credential is not a local administrator on the target, or UAC remote restrictions apply)")
	case 53, 67:
		return errors.New("network path not found (File and Printer Sharing blocked, or name doesn't resolve)")
	case 1326:
		return errors.New("logon failure: wrong username or password")
	case 1909:
		return errors.New("the deployment account is locked out")
	case 1331:
		return errors.New("the deployment account is disabled")
	case 1722:
		return errors.New("RPC server unavailable (remote service control blocked by firewall)")
	case 193:
		return errors.New("installer build is incompatible with the target (publish a 386 legacy release so the server pushes a build that runs everywhere)")
	}
	return err
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
		return deployResult{Status: "failed", Stage: stage, Detail: explain(err).Error()}
	}
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, "445"))
	if err != nil {
		return fail("connect", fmt.Errorf("TCP 445 unreachable: %v (offline, or firewall blocks File and Printer Sharing)", err))
	}
	c.Close()

	// Everything below runs on one OS thread holding the deployment
	// credential; file I/O and SCM calls are synchronous on that thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tok, err := impersonate(user, pass)
	if err != nil {
		return fail("authenticate", err)
	}
	defer tok.Close()
	defer windows.RevertToSelf()

	share := `\\` + host + `\ADMIN$`
	if _, err := os.Stat(share + `\Temp`); err != nil {
		return fail("authenticate", fmt.Errorf("cannot open %s: %w", share, unwrapPathErr(err)))
	}
	m, err := mgr.ConnectRemote(host)
	if err != nil {
		return fail("service_manager", err)
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
		return deployResult{Status: "ok_dry_run", Detail: "ADMIN$ and remote service control both work with this credential"}
	}
	if token == "" {
		return fail("token", errors.New("server did not issue an enrollment token for this computer"))
	}

	// Stage files in a fresh, unguessable folder locked to SYSTEM and
	// Administrators. %SystemRoot%\Temp lets ordinary users create files,
	// so a predictable path would let a local user plant or swap the binary
	// that the setup service runs as SYSTEM.
	name := "AIRMM-Setup-" + randHex(8)
	dir := share + `\Temp\` + name
	if err := os.Mkdir(dir, 0o700); err != nil {
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
	if err := protectDir(dir); err != nil {
		return fail("copy", fmt.Errorf("secure staging folder: %w", err))
	}
	if err := copyExcl(installer, dir+`\rmm-agent.exe`); err != nil {
		return fail("copy", err)
	}
	boot := &Config{ServerURL: a.Cfg.ServerURL, ServerURLs: a.Cfg.ServerURLs, InstallURL: a.Cfg.InstallURL,
		ServerPubKey: a.Cfg.ServerPubKey, TLSPinSHA256: a.Cfg.TLSPinSHA256, EnrollToken: token}
	b, _ := json.MarshalIndent(boot, "", "  ")
	if err := writeExcl(dir+`\agent.json`, b); err != nil {
		return fail("copy", err)
	}

	// Run the one-shot setup service.
	if old, err := m.OpenService(setupService); err == nil {
		_, _ = old.Control(svc.Stop)
		_ = old.Delete()
		old.Close()
	}
	var s *mgr.Service
	for i := 0; i < 10; i++ {
		s, err = m.CreateService(setupService, `%SystemRoot%\Temp\`+name+`\rmm-agent.exe`, mgr.Config{
			DisplayName: "AI-RMM Agent Setup", StartType: mgr.StartManual, ErrorControl: mgr.ErrorIgnore,
		}, "bootstrap")
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) && !errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
			break
		}
		time.Sleep(2 * time.Second)
	}
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
	for {
		time.Sleep(2 * time.Second) // plain sleep: stay on this impersonating thread
		if st, err = s.Query(); err != nil {
			return fail("install", fmt.Errorf("query setup service: %w", err))
		}
		if st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fail("install", errors.New("setup did not finish within 3 minutes"))
		}
	}
	detail, _ := os.ReadFile(dir + `\bootstrap-result.txt`)
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

func unwrapPathErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return explain(pe.Err)
	}
	return err
}

// protectDir replaces the folder's DACL with SYSTEM + Administrators only,
// with inheritance from the parent blocked.
func protectDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeExcl(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func copyExcl(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
