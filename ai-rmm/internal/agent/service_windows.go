//go:build windows

package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

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
	return s.Start()
}

func UninstallService(purge bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err == nil {
		_ = stopService(s)
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
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
	for st.State != svc.Stopped && time.Now().Before(deadline) {
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
		_ = os.Remove(dst + ".old")
		if err := os.Rename(dst, dst+".old"); err != nil {
			return err
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
