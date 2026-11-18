package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Server is the control plane: agent API, operator REST API, MCP endpoint
// for AI agents, and a small approval dashboard.
type Server struct {
	Dir     string
	Cfg     *Config
	Version string

	signKey  ed25519.PrivateKey
	vaultKey []byte
	store    *store
	builtin  map[string]*Tool

	notifyMu sync.Mutex
	notify   map[string]chan struct{} // agentID -> wake long-poll
	doneCh   map[string]chan struct{} // jobID -> closed when terminal

	auditMu sync.Mutex
	audit   *os.File
}

func New(dir, version string) (*Server, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("load config (did you run `rmm-server init`?): %w", err)
	}
	key, err := LoadSigningKey(dir)
	if err != nil {
		return nil, err
	}
	vk, err := loadOrCreateVaultKey(dir)
	if err != nil {
		return nil, err
	}
	st, err := loadStore(dir, cfg.JobRetention)
	if err != nil {
		return nil, err
	}
	bt, err := BuiltinTools()
	if err != nil {
		return nil, fmt.Errorf("builtin tools: %w", err)
	}
	af, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	for name, t := range nativeTools() {
		bt[name] = t
	}
	s := &Server{
		Dir: dir, Cfg: cfg, Version: version, signKey: key, vaultKey: vk, store: st, builtin: bt,
		notify: map[string]chan struct{}{}, doneCh: map[string]chan struct{}{}, audit: af,
	}
	// Jobs that were mid-flight when the server stopped can't be trusted to
	// report back to a waiter; leave them for the reaper's normal deadlines.
	return s, nil
}

// ---- keys ----

const signingKeyFile = "signing.key"

func GenerateSigningKey(dir string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := os.WriteFile(filepath.Join(dir, signingKeyFile), []byte(enc+"\n"), 0o600); err != nil {
		return nil, err
	}
	return pub, nil
}

func LoadSigningKey(dir string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, signingKeyFile))
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(string(trimSpace(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing.key is corrupt")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s *Server) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(s.signKey.Public().(ed25519.PublicKey))
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// ---- audit ----

type auditEntry struct {
	Time   string      `json:"time"`
	Actor  string      `json:"actor"`
	Action string      `json:"action"`
	Detail interface{} `json:"detail,omitempty"`
}

func (s *Server) Audit(actor, action string, detail interface{}) {
	e := auditEntry{Time: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Detail: detail}
	b, _ := json.Marshal(e)
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	_, _ = s.audit.Write(append(b, '\n'))
}

// ReadAudit returns the last n audit entries (newest last).
func (s *Server) ReadAudit(n int) ([]json.RawMessage, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	var lines []json.RawMessage
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			if i > start {
				lines = append(lines, json.RawMessage(b[start:i]))
			}
			start = i + 1
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// ---- lifecycle ----

func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go s.background(ctx)
	errc := make(chan error, 1)
	go func() {
		if s.Cfg.TLSCert != "" {
			log.Printf("listening on %s (TLS)", s.Cfg.Listen)
			errc <- srv.ListenAndServeTLS(s.path(s.Cfg.TLSCert), s.path(s.Cfg.TLSKey))
		} else {
			log.Printf("WARNING: listening on %s WITHOUT TLS (lab use only)", s.Cfg.Listen)
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return s.store.flush()
	case err := <-errc:
		_ = s.store.flush()
		return err
	}
}

func (s *Server) path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.Dir, p)
}

func (s *Server) background(ctx context.Context) {
	save := time.NewTicker(2 * time.Second)
	reap := time.NewTicker(15 * time.Second)
	defer save.Stop()
	defer reap.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-save.C:
			if err := s.store.flush(); err != nil {
				log.Printf("persist state: %v", err)
			}
		case <-reap.C:
			s.reap()
			s.checkAgentsOffline()
			s.checkDevicesStale()
			s.runDueSchedules()
		}
	}
}

// Flush persists state immediately (used by tests and CLI commands).
func (s *Server) Flush() error { return s.store.flush() }
