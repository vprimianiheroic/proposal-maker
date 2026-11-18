// rmm-server is the AI-RMM control plane: agent API, operator API, MCP
// endpoint for AI agents, and the approval dashboard.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/airmm/airmm/internal/server"

	// Embedded timezone database so schedule timezones work on Windows hosts.
	_ "time/tzdata"
)

var version = "dev"

var cli = server.Caller{Name: "cli", Role: server.RoleAdmin}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("data", "./rmm-data", "data directory")
	switch cmd {
	case "init":
		url := fs.String("url", "", "public URL agents will use, e.g. https://rmm.corp.local:8443 (required)")
		hosts := fs.String("hosts", "", "comma-separated DNS names / IPs for the self-signed TLS cert (default: host from --url)")
		listen := fs.String("listen", ":8443", "listen address")
		noTLS := fs.Bool("no-tls", false, "plain HTTP (lab only)")
		_ = fs.Parse(args)
		if *url == "" {
			fatal(fmt.Errorf("--url is required"))
		}
		doInit(*dir, *url, *hosts, *listen, *noTLS)
	case "serve":
		_ = fs.Parse(args)
		s := mustServer(*dir)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		log.Printf("ai-rmm server %s, data %s, %d built-in tools", version, *dir, len(s.ListTools()))
		if err := s.Run(ctx); err != nil {
			fatal(err)
		}
	case "apikey":
		name := fs.String("name", "", "key name, e.g. claude-ops or jane.doe")
		role := fs.String("role", "ai", "ai | admin")
		_ = fs.Parse(args)
		if *name == "" {
			fatal(fmt.Errorf("--name is required"))
		}
		s := mustServer(*dir)
		k, err := s.CreateAPIKey(cli, *name, *role)
		check(err)
		check(s.Flush())
		fmt.Printf("%s key for %q (shown once):\n%s\n", *role, *name, k)
	case "enroll-token":
		name := fs.String("name", "default", "token name")
		groups := fs.String("groups", "", "comma-separated groups applied to machines enrolling with this token (e.g. ot,plant1)")
		ttl := fs.Duration("ttl", 7*24*time.Hour, "validity, 0 = never expires")
		maxUses := fs.Int("max-uses", 0, "0 = unlimited")
		_ = fs.Parse(args)
		s := mustServer(*dir)
		tok, _, err := s.CreateEnrollToken(cli, *name, splitCSV(*groups), *ttl, *maxUses)
		check(err)
		check(s.Flush())
		fmt.Printf("enrollment token %q (shown once):\n%s\n", *name, tok)
	case "release":
		file := fs.String("file", "", "agent binary to publish")
		ver := fs.String("version", "", "version string the binary reports")
		arch := fs.String("arch", "amd64", "amd64 | 386 | arm64")
		variant := fs.String("variant", "", `"" (modern) or "legacy"`)
		groups := fs.String("groups", "", "limit rollout to these agent groups (canary); empty = all")
		_ = fs.Parse(args)
		s := mustServer(*dir)
		check(addRelease(s, *file, *ver, *arch, *variant, splitCSV(*groups)))
		check(s.Flush())
	case "credential":
		// rmm-server credential set|list|delete ...
		if len(args) == 0 {
			fatal(fmt.Errorf("usage: rmm-server credential set|list|delete [flags]"))
		}
		sub := args[0]
		fs2 := flag.NewFlagSet("credential "+sub, flag.ExitOnError)
		dir2 := fs2.String("data", "./rmm-data", "data directory")
		name := fs2.String("name", "", "credential name, e.g. domain-deploy")
		kind := fs2.String("kind", "windows", "windows | snmp | generic")
		user := fs2.String("username", "", "username (windows: DOMAIN\\user)")
		desc := fs2.String("description", "", "what it is for")
		_ = fs2.Parse(args[1:])
		s := mustServer(*dir2)
		switch sub {
		case "list":
			for _, c := range s.ListCredentials() {
				fmt.Printf("%-24s %-8s %-30s %s\n", c.Name, c.Kind, c.Username, c.Description)
			}
		case "delete":
			check(s.DeleteCredential(cli, *name))
			check(s.Flush())
		case "set":
			fmt.Fprintln(os.Stderr, "Enter secrets as key=value lines, then Ctrl-D (Ctrl-Z Enter on Windows).")
			fmt.Fprintln(os.Stderr, "  windows: password=...   snmp v2c: community=...   snmp v3: version=3 username=... auth_proto=SHA auth_pass=... priv_proto=AES priv_pass=...")
			sec := map[string]string{}
			if *user != "" {
				sec["username"] = *user
			}
			b, _ := io.ReadAll(os.Stdin)
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimRight(line, "\r")
				if i := strings.IndexByte(line, '='); i > 0 {
					sec[strings.TrimSpace(line[:i])] = line[i+1:]
				}
			}
			check(s.PutCredential(cli, *name, *kind, *desc, sec))
			check(s.Flush())
			fmt.Println("stored", *name)
		default:
			fatal(fmt.Errorf("unknown credential subcommand %q", sub))
		}
	case "version":
		fmt.Println("rmm-server", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `rmm-server - AI-RMM control plane

  rmm-server init         --url https://rmm.corp.local:8443 [--hosts a,b] [--data DIR]
  rmm-server serve        [--data DIR]
  rmm-server apikey       --name NAME --role ai|admin
  rmm-server enroll-token --name NAME [--groups ot,plant1] [--ttl 168h] [--max-uses N]
  rmm-server release      --file rmm-agent.exe --version 1.2.0 --arch amd64 [--variant legacy] [--groups canary]
  rmm-server credential   set --name domain-deploy --kind windows --username 'CORP\svc-rmm' < secrets.txt
  rmm-server credential   list | delete --name NAME

Stop the server before running apikey / enroll-token / release / credential
against the same data dir, or use the console / REST API while it runs
(e.g. POST /api/v1/releases?version=1.2.0&arch=amd64 with the .exe as body).
`)
}

func mustServer(dir string) *server.Server {
	s, err := server.New(dir, version)
	check(err)
	return s
}

func doInit(dir, url, hosts, listen string, noTLS bool) {
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		fatal(fmt.Errorf("%s already initialised", dir))
	}
	check(os.MkdirAll(filepath.Join(dir, "releases"), 0o700))
	cfg := server.DefaultConfig()
	cfg.PublicURL = strings.TrimRight(url, "/")
	cfg.Listen = listen
	pin := ""
	if noTLS {
		cfg.TLSCert, cfg.TLSKey = "", ""
	} else {
		if hosts == "" {
			h := strings.TrimPrefix(strings.TrimPrefix(cfg.PublicURL, "https://"), "http://")
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			hosts = h
		}
		var err error
		pin, err = selfSignedCert(dir, splitCSV(hosts))
		check(err)
	}
	check(server.SaveConfig(dir, cfg))
	pub, err := server.GenerateSigningKey(dir)
	check(err)

	s := mustServer(dir)
	admin, err := s.CreateAPIKey(cli, "initial-admin", server.RoleAdmin)
	check(err)
	ai, err := s.CreateAPIKey(cli, "ai-agent", server.RoleAI)
	check(err)
	tok, _, err := s.CreateEnrollToken(cli, "initial", nil, 30*24*time.Hour, 0)
	check(err)
	check(s.Flush())
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	fmt.Printf(`
AI-RMM server initialised in %s
================================================================
Store these now; secrets are shown only once.

Admin API key (humans; dashboard + approvals):  %s
AI API key (MCP / automation):                  %s
Enrollment token (30 days, no groups):          %s
Job-signing public key (agents pin this):       %s
TLS public-key pin (self-signed cert):          %s

Start:     rmm-server serve --data %s
Dashboard: %s/

Install an agent (elevated PowerShell on the endpoint):
  .\rmm-agent.exe install --server %s --token %s --pubkey %s%s

Or MSI:
  msiexec /i airmm-agent-x64.msi /qn SERVER_URL=%s ENROLL_TOKEN=%s SERVER_PUBKEY=%s%s

Connect Claude Code (MCP over HTTP):
  claude mcp add --transport http ai-rmm %s/mcp --header "Authorization: Bearer %s"
`, dir, admin, ai, tok, pubB64, orNone(pin), dir, cfg.PublicURL,
		cfg.PublicURL, tok, pubB64, flagIf(" --tls-pin ", pin),
		cfg.PublicURL, tok, pubB64, flagIf(" TLS_PIN=", pin),
		cfg.PublicURL, ai)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func flagIf(prefix, v string) string {
	if v == "" {
		return ""
	}
	return prefix + v
}

// selfSignedCert writes tls.crt/tls.key (ECDSA P-256, 5 years) and returns
// the SHA-256 of its SubjectPublicKeyInfo for agents to pin.
func selfSignedCert(dir string, hosts []string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ai-rmm", Organization: []string{"AI-RMM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return "", err
	}
	cert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

func addRelease(s *server.Server, file, ver, arch, variant string, groups []string) error {
	if file == "" || ver == "" {
		return fmt.Errorf("--file and --version are required")
	}
	in, err := os.Open(file)
	if err != nil {
		return err
	}
	defer in.Close()
	r, err := s.PublishRelease(cli, in, ver, arch, variant, groups)
	if err != nil {
		return err
	}
	fmt.Printf("release %s (windows/%s %s) published as %s, sha256 %s\n", r.Version, r.Arch, r.Variant, r.File, r.SHA256)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func check(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
