// rmm-agent is the endpoint agent. On Windows it runs as the AIRMMAgent
// service (LocalSystem). See docs/DEPLOYMENT.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/airmm/airmm/internal/agent"
)

// Set with -ldflags "-X main.version=1.2.3 -X main.variant=legacy".
var (
	version = "dev"
	variant = "" // "" = modern (Win10/2016+), "legacy" = Go 1.20 build for Win7/2008R2/2012R2
)

func main() {
	if agent.IsService() && len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		// One-shot setup service created by deploy_agent on a new machine.
		if err := agent.RunBootstrap(); err != nil {
			os.Exit(1)
		}
		return
	}
	if agent.IsService() {
		setupFileLog()
		err := agent.RunService(func(ctx context.Context) bool { return runAgent(ctx, agent.DefaultConfigPath()) })
		if err != nil {
			log.Printf("service: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfgPath := fs.String("config", agent.DefaultConfigPath(), "config file")
		_ = fs.Parse(args)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if runAgent(ctx, *cfgPath) {
			os.Exit(3)
		}
	case "install", "configure":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		server := fs.String("server", "", "server URL, e.g. https://rmm.corp.local:8443 (omit to reuse the existing config)")
		token := fs.String("token", "", "enrollment token")
		pub := fs.String("pubkey", "", "server job-signing public key (base64)")
		pin := fs.String("tls-pin", "", "optional SHA-256 pin of the server TLS public key (hex), for self-signed certs")
		inPlace := fs.Bool("in-place", false, "register the service at this binary's current path instead of copying to Program Files (used by the MSI)")
		cfgPath := fs.String("config", agent.DefaultConfigPath(), "config file (configure only)")
		_ = fs.Parse(args)
		old, oldErr := agent.LoadConfig(*cfgPath)
		var cfg *agent.Config
		switch {
		case *server == "" && oldErr == nil:
			cfg = old // upgrade / repair: keep everything
		case *server == "":
			fatal(fmt.Errorf("--server is required (no usable existing config: %v)", oldErr))
		default:
			cfg = &agent.Config{ServerURL: *server, EnrollToken: *token, ServerPubKey: *pub, TLSPinSHA256: *pin}
			// Re-running install on an enrolled machine keeps its identity.
			if oldErr == nil && old.AgentID != "" && strings.TrimRight(old.ServerURL, "/") == strings.TrimRight(*server, "/") {
				cfg.AgentID, cfg.AgentSecret, cfg.EnrollToken = old.AgentID, old.AgentSecret, ""
				cfg.MaxConcurrent, cfg.PowerShellPath = old.MaxConcurrent, old.PowerShellPath
			}
		}
		if err := cfg.Validate(); err != nil {
			fatal(err)
		}
		if cmd == "configure" {
			if err := agent.SecureDir(filepath.Dir(*cfgPath)); err != nil {
				fatal(err)
			}
			if err := cfg.Save(*cfgPath); err != nil {
				fatal(err)
			}
			fmt.Println("configuration written to", *cfgPath)
			return
		}
		if err := agent.InstallService(cfg, *inPlace); err != nil {
			fatal(err)
		}
		fmt.Println("AI-RMM agent installed and started.")
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "also delete configuration, logs and program files")
		_ = fs.Parse(args)
		if err := agent.UninstallService(*purge); err != nil {
			fatal(err)
		}
		fmt.Println("AI-RMM agent removed.")
	case "watchdog":
		// Run every 10 minutes by the "AIRMM Watchdog" scheduled task.
		if err := agent.Watchdog(); err != nil {
			fatal(err)
		}
	case "facts":
		f := agent.CollectFacts()
		fmt.Printf("%+v\n", f)
	case "version", "--version", "-v":
		v := variant
		if v == "" {
			v = "modern"
		}
		fmt.Printf("rmm-agent %s (%s)\n", version, v)
	default:
		usage()
		os.Exit(2)
	}
}

func runAgent(ctx context.Context, cfgPath string) (restart bool) {
	cfg, err := agent.LoadConfig(cfgPath)
	if err != nil {
		log.Printf("load config %s: %v", cfgPath, err)
		return false
	}
	a, err := agent.New(cfg, version, variant)
	if err != nil {
		log.Printf("init: %v", err)
		return false
	}
	if err := a.Run(ctx); err != nil {
		log.Printf("agent stopped: %v", err)
	}
	return a.RestartRequested
}

func usage() {
	fmt.Fprint(os.Stderr, `rmm-agent - AI-RMM endpoint agent

  rmm-agent install   --server URL --token TOKEN --pubkey KEY [--tls-pin HEX] [--in-place]
                      copy to Program Files, write config, register + start the service
                      (with no --server: re-register using the existing config, e.g. after upgrade)
  rmm-agent configure --server URL --token TOKEN --pubkey KEY [--tls-pin HEX] [--config FILE]
                      write config only (used by the MSI)
  rmm-agent uninstall [--purge]
  rmm-agent run       [--config FILE]   run in the foreground (debugging)
  rmm-agent watchdog                   ensure the service exists/runs; roll back a bad update (scheduled task)
  rmm-agent facts                      print the inventory facts this machine reports
  rmm-agent version
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// ---- size-capped log file for service mode ----

type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.size > 5<<20 {
		if r.f != nil {
			r.f.Close()
			_ = os.Remove(r.path + ".1")
			_ = os.Rename(r.path, r.path+".1")
		}
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		st, _ := f.Stat()
		r.f, r.size = f, st.Size()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func setupFileLog() {
	dir := agent.DefaultDataDir()
	_ = os.MkdirAll(dir, 0o700)
	log.SetOutput(io.Writer(&rotatingFile{path: filepath.Join(dir, "agent.log")}))
	log.SetFlags(log.LstdFlags | log.LUTC)
}
