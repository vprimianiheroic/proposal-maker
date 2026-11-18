//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	ServiceName    = "AIRMMAgent"
	ServiceDisplay = "AI-RMM Agent"
	ServiceDesc    = "AI-managed remote monitoring and management agent. Executes server-signed maintenance jobs."
)

func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

func InstallDir() string {
	pf := os.Getenv("ProgramW6432") // real Program Files even from the 32-bit build
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	return filepath.Join(pf, "AIRMM")
}

type handler struct {
	run func(ctx context.Context) (restart bool)
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- h.run(ctx) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case restart := <-done:
			cancel()
			if restart {
				// Non-zero service-specific exit code => SCM recovery action
				// restarts us (installed with "actions on non-crash failures").
				return true, 3
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// RunService hands control to the Service Control Manager.
func RunService(run func(ctx context.Context) bool) error {
	return svc.Run(ServiceName, &handler{run: run})
}

// SecureDir restricts a directory to SYSTEM and Administrators (it holds the
// agent secret and job scripts).
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out, err := exec.Command("icacls.exe", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", // BUILTIN\Administrators
		"/T", "/C", "/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	return nil
}

// InstallService copies the running binary into Program Files, registers the
// service with restart-on-failure recovery, and starts it.
func InstallService(cfg *Config, inPlace bool) error {
	if err := SecureDir(DefaultDataDir()); err != nil {
		return err
	}
	if err := cfg.Save(DefaultConfigPath()); err != nil {
		return err
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dst := filepath.Join(InstallDir(), "rmm-agent.exe")
	if inPlace {
		dst = src
	} else if !sameFile(src, dst) {
		if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("copy binary: %w", err)
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err == nil {
		// Upgrade/reconfigure in place.
		_ = stopService(s)
		cfgS, _ := s.Config()
		cfgS.BinaryPathName = `"` + dst + `" run`
		cfgS.StartType = mgr.StartAutomatic
		cfgS.DelayedAutoStart = false
		if err := s.UpdateConfig(cfgS); err != nil {
			s.Close()
			return err
		}
	} else {
		s, err = m.CreateService(ServiceName, dst, mgr.Config{
			DisplayName: ServiceDisplay, Description: ServiceDesc, StartType: mgr.StartAutomatic,
		}, "run")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}
	defer s.Close()
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, 24*3600)
	if err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	if err := installWatchdog(dst); err != nil {
		fmt.Fprintln(os.Stderr, "warning: watchdog task not installed:", err)
	}
	return nil
}

const watchdogTask = "AIRMM Watchdog"

// installWatchdog keeps a separate copy of a known-good build and a SYSTEM
// scheduled task that runs it every 10 minutes. The copy is only refreshed
// after a new build has proven it can reach the server, so a bad update
// can't take the watchdog down with it.
func installWatchdog(agentExe string) error {
	wd := filepath.Join(filepath.Dir(agentExe), "rmm-watchdog.exe")
	if err := copyPlain(agentExe, wd); err != nil && !fileExists(wd) {
		return err
	}
	// XML rather than /sc flags: schtasks' defaults would stop the task on
	// battery (laptops on the shop floor) and allow overlapping runs.
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keeps the AI-RMM agent installed, running and reachable.</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT5M</Delay></BootTrigger>
    <TimeTrigger><StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>
      <Repetition><Interval>PT10M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEscape(wd) + `</Command><Arguments>watchdog</Arguments></Exec></Actions>
</Task>`
	f := filepath.Join(DefaultDataDir(), "watchdog-task.xml")
	if err := os.WriteFile(f, utf16File(xml), 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	out, err := exec.Command("schtasks.exe", "/create", "/tn", watchdogTask, "/xml", f, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// utf16File encodes as UTF-16LE with BOM, which schtasks /xml requires.
func utf16File(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		b[2+2*i], b[3+2*i] = byte(c), byte(c>>8)
	}
	return b
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var (
	lastPromote  time.Time
	processStart = time.Now()
)

// promoteWatchdog refreshes the watchdog copy from the running build, but
// only after this build has run and kept server contact for 24 hours. Until
// then the previous build stays as both the watchdog and rmm-agent.exe.old,
// so a build that is subtly broken (crashes later, breaks updates) can
// still be rolled back.
func promoteWatchdog() {
	if time.Since(processStart) < 24*time.Hour || time.Since(lastPromote) < 10*time.Minute || !IsService() {
		return
	}
	lastPromote = time.Now()
	self, err := os.Executable()
	if err != nil {
		return
	}
	wd := filepath.Join(filepath.Dir(self), "rmm-watchdog.exe")
	si, err1 := os.Stat(self)
	wi, err2 := os.Stat(wd)
	if err1 != nil || (err2 == nil && !wi.ModTime().Before(si.ModTime())) {
		_ = os.Remove(self + ".old")
		return
	}
	tmp := wd + ".tmp"
	if copyPlain(self, tmp) == nil && os.Rename(tmp, wd) == nil { // Rename replaces atomically
		_ = os.Remove(self + ".old")
	}
}

// Watchdog is run by the scheduled task. It never needs the server: it
// only makes sure the agent service exists, is enabled and running, and
// rolls back a self-update that never managed to reach the server.
func Watchdog() error {
	dataDir := DefaultDataDir()
	logf := func(format string, args ...interface{}) {
		f, err := os.OpenFile(filepath.Join(dataDir, "watchdog.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			if st, _ := f.Stat(); st != nil && st.Size() > 1<<20 {
				f.Truncate(0)
			}
			fmt.Fprintf(f, "%s %s\r\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
			f.Close()
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	agentExe := filepath.Join(filepath.Dir(self), "rmm-agent.exe")
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		if !fileExists(DefaultConfigPath()) {
			return nil // never configured / deliberately purged: nothing to restore
		}
		logf("agent service missing; re-registering")
		if !fileExists(agentExe) {
			if err := copyPlain(self, agentExe); err != nil {
				logf("restore binary: %v", err)
				return err
			}
		}
		out, err := exec.Command(agentExe, "install", "--in-place").CombinedOutput()
		logf("reinstall: %v %s", err, strings.TrimSpace(string(out)))
		return err
	}
	defer s.Close()

	if c, err := s.Config(); err != nil {
		logf("read service config: %v", err)
	} else if c.StartType == mgr.StartDisabled {
		c.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(c); err == nil {
			logf("agent service was disabled; re-enabled")
		}
	}

	// restore puts a known-good build back: the previous build if kept,
	// otherwise this watchdog's own copy.
	restore := func(why string) error {
		logf("%s; restoring a known-good agent binary", why)
		_ = stopService(s)
		src := agentExe + ".old"
		if !fileExists(src) {
			src = self
		}
		_ = os.Remove(agentExe + ".bad")
		if fileExists(agentExe) {
			if err := os.Rename(agentExe, agentExe+".bad"); err != nil {
				logf("move bad binary aside: %v", err)
				return err
			}
		}
		var err error
		if src == self {
			err = copyPlain(self, agentExe)
		} else {
			err = os.Rename(src, agentExe)
		}
		if err != nil {
			logf("restore failed: %v", err)
			if fileExists(agentExe + ".bad") {
				_ = os.Rename(agentExe+".bad", agentExe)
			}
			return err
		}
		_ = os.Remove(filepath.Join(dataDir, updateMarker))
		return s.Start()
	}

	// The new build stamps its first start into the marker, so this measures
	// "15 minutes since it first ran without ever reaching the server".
	marker := filepath.Join(dataDir, updateMarker)
	if age, ok := markerAge(marker); ok && age > 15*time.Minute {
		return restore("self-update never reached the server within 15 minutes")
	}
	// AV quarantine or deletion of the agent binary.
	if !fileExists(agentExe) {
		return restore("agent binary is missing")
	}

	st, err := s.Query()
	if err != nil {
		return err
	}
	switch st.State {
	case svc.Stopped:
		logf("agent service was stopped; starting")
		err := s.Start()
		var en windows.Errno
		if errors.As(err, &en) && (en == windows.ERROR_FILE_NOT_FOUND || en == windows.ERROR_PATH_NOT_FOUND || en == windows.ERROR_BAD_EXE_FORMAT) {
			return restore(fmt.Sprintf("agent binary will not start (%v)", err))
		}
		return err
	case svc.Running:
		// Running but silent for an hour: hung process or wedged network
		// stack. A restart is cheap and often fixes it.
		if lc, err := os.Stat(filepath.Join(dataDir, "last_contact")); err == nil && time.Since(lc.ModTime()) > time.Hour {
			if fi, err := os.Stat(filepath.Join(dataDir, "watchdog.restart")); err != nil || time.Since(fi.ModTime()) > time.Hour {
				_ = os.WriteFile(filepath.Join(dataDir, "watchdog.restart"), nil, 0o600)
				logf("no server contact for %s; restarting agent service", time.Since(lc.ModTime()).Round(time.Minute))
				_ = stopService(s)
				return s.Start()
			}
		}
	}
	return nil
}

// RunBootstrap is the entry point of the one-shot AIRMMSetup service that
// deploy_agent creates on a target: install from the config next to the
// binary, record the outcome for the deployer, exit.
func RunBootstrap() error {
	return svc.Run(setupServiceName, &bootstrapHandler{})
}

const setupServiceName = "AIRMMSetup"

type bootstrapHandler struct{}

func (bootstrapHandler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.Running}
	self, _ := os.Executable()
	dir := filepath.Dir(self)
	err := func() error {
		cfg, err := LoadConfig(filepath.Join(dir, "agent.json"))
		if err != nil {
			return err
		}
		// Forced reinstall over an enrolled agent: keep its identity
		// rather than enrolling a duplicate.
		if old, err := LoadConfig(DefaultConfigPath()); err == nil && old.AgentID != "" &&
			strings.TrimRight(old.ServerURL, "/") == strings.TrimRight(cfg.ServerURL, "/") {
			cfg.AgentID, cfg.AgentSecret, cfg.EnrollToken = old.AgentID, old.AgentSecret, ""
		}
		return InstallService(cfg, false)
	}()
	msg := "ok"
	if err != nil {
		msg = "error: " + err.Error()
	}
	_ = os.WriteFile(filepath.Join(dir, "bootstrap-result.txt"), []byte(msg), 0o600)
	// Don't leave the single-use token lying around on the target.
	_ = os.Remove(filepath.Join(dir, "agent.json"))
	if err != nil {
		return true, 1
	}
	return false, 0
}

func UninstallService(purge bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	_ = exec.Command("schtasks.exe", "/delete", "/tn", watchdogTask, "/f").Run()
	s, err := m.OpenService(ServiceName)
	if err == nil {
		_ = stopService(s)
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	// Remove files the MSI doesn't know about (watchdog copy, rollback
	// builds); never the running executable itself.
	if self, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(self))
		for _, n := range []string{"rmm-watchdog.exe", "rmm-watchdog.exe.tmp", "rmm-agent.exe.old", "rmm-agent.exe.bad", "rmm-agent.exe.prev", "rmm-agent.exe.new"} {
			if p := filepath.Join(dir, n); !strings.EqualFold(p, self) {
				_ = os.Remove(p)
			}
		}
	}
	if purge {
		_ = os.RemoveAll(DefaultDataDir())
		// The binary may be the one running this command; schedule removal.
		_ = exec.Command("cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul & rmdir /s /q \""+InstallDir()+"\"").Start()
	}
	return nil
}

func stopService(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return errors.New("service did not stop within 30 seconds")
		}
		time.Sleep(500 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

func sameFile(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// If a previous version is running, rename it out of the way first.
	if _, err := os.Stat(dst); err == nil {
		if fileExists(filepath.Join(DefaultDataDir(), updateMarker)) && fileExists(dst+".old") {
			// keep the rollback target; park the current file elsewhere
			_ = os.Remove(dst + ".prev")
			if err := os.Rename(dst, dst+".prev"); err != nil {
				return err
			}
		} else {
			_ = os.Remove(dst + ".old")
			if err := os.Rename(dst, dst+".old"); err != nil {
				return err
			}
		}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
