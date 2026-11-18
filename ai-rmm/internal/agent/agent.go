// Package agent is the endpoint side: enroll once, long-poll the server for
// signed jobs, run them in PowerShell, report results, self-update.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

type Agent struct {
	Cfg     *Config
	Version string
	Variant string
	DataDir string

	pub    ed25519.PublicKey
	client *http.Client

	mu       sync.Mutex
	running  map[string]bool
	executed map[string]int64 // job ID -> unix time, replay guard
	sem      chan struct{}
	wg       sync.WaitGroup

	// RestartRequested is set when a self-update has been staged; the caller
	// should exit with a non-zero code so the service manager restarts it.
	RestartRequested bool
}

func New(cfg *Config, version, variant string) (*Agent, error) {
	pub, err := cfg.PublicKey()
	if err != nil {
		return nil, err
	}
	a := &Agent{
		Cfg: cfg, Version: version, Variant: variant, DataDir: filepath.Dir(cfg.Path()),
		pub: pub, running: map[string]bool{}, executed: map[string]int64{},
		sem: make(chan struct{}, cfg.MaxConcurrent),
	}
	a.client = &http.Client{Timeout: 90 * time.Second, Transport: a.transport()}
	return a, nil
}

func (a *Agent) transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin := strings.ToLower(strings.TrimSpace(a.Cfg.TLSPinSHA256)); pin != "" {
		// Self-signed server cert: skip chain validation but require the
		// exact public key we were installed with.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("server certificate does not match pinned key")
			}
			return nil
		}
	}
	t.TLSClientConfig = tc
	return t
}

func (a *Agent) do(ctx context.Context, method, path string, body, out interface{}, auth bool) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Cfg.ServerURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "airmm-agent/"+a.Version)
	if auth {
		req.Header.Set("Authorization", "Bearer "+a.Cfg.AgentID+"."+a.Cfg.AgentSecret)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &httpError{resp.StatusCode, strings.TrimSpace(string(msg))}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

type httpError struct {
	Code int
	Msg  string
}

func (e *httpError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Code, e.Msg) }

func (a *Agent) enroll(ctx context.Context) error {
	req := protocol.EnrollRequest{Token: a.Cfg.EnrollToken, AgentVersion: a.Version, Variant: a.Variant, Facts: CollectFacts()}
	var resp protocol.EnrollResponse
	if err := a.do(ctx, "POST", "/api/v1/agent/enroll", req, &resp, false); err != nil {
		return err
	}
	a.Cfg.AgentID, a.Cfg.AgentSecret, a.Cfg.EnrollToken = resp.AgentID, resp.Secret, ""
	if err := a.Cfg.Save(""); err != nil {
		return fmt.Errorf("enrolled as %s but could not save config: %w", resp.AgentID, err)
	}
	log.Printf("enrolled as %s", resp.AgentID)
	return nil
}

// Run blocks until ctx is cancelled or a self-update needs a restart.
func (a *Agent) Run(ctx context.Context) error {
	log.Printf("ai-rmm agent %s (%s) starting; server %s", a.Version, variantName(a.Variant), a.Cfg.ServerURL)
	cleanupOldBinary()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	backoff := time.Second
	for a.Cfg.AgentID == "" {
		if err := a.enroll(ctx); err != nil {
			log.Printf("enroll failed: %v (retrying in %s)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
	}

	var lastFacts time.Time
	backoff = time.Second
	for ctx.Err() == nil {
		a.flushSpool(ctx)
		req := protocol.PollRequest{AgentVersion: a.Version, Variant: a.Variant, Running: a.runningIDs()}
		if time.Since(lastFacts) > 15*time.Minute {
			f := CollectFacts()
			req.Facts = &f
		}
		var resp protocol.PollResponse
		if err := a.do(ctx, "POST", "/api/v1/agent/poll", req, &resp, true); err != nil {
			if ctx.Err() != nil {
				break
			}
			var he *httpError
			if errors.As(err, &he) && he.Code == 401 {
				log.Printf("server rejected agent credentials (agent disabled or deleted?)")
			} else {
				log.Printf("poll: %v (retry in %s)", err, backoff)
			}
			sleepCtx(ctx, backoff)
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = time.Second
		if req.Facts != nil {
			lastFacts = time.Now()
		}
		for i := range resp.Jobs {
			a.start(ctx, resp.Jobs[i])
		}
		if resp.Update != nil && len(a.runningIDs()) == 0 {
			if err := a.applyUpdate(ctx, resp.Update); err != nil {
				log.Printf("self-update to %s failed: %v", resp.Update.Version, err)
				sleepCtx(ctx, 5*time.Minute) // don't hammer the server with retries
			} else {
				log.Printf("update to %s staged; restarting", resp.Update.Version)
				a.RestartRequested = true
				break
			}
		}
	}
	cancel()
	a.wg.Wait()
	return nil
}

func variantName(v string) string {
	if v == "" {
		return "modern"
	}
	return v
}

func (a *Agent) runningIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.running))
	for id := range a.running {
		out = append(out, id)
	}
	return out
}

func (a *Agent) start(ctx context.Context, job protocol.Job) {
	a.mu.Lock()
	if a.running[job.ID] || a.executed[job.ID] != 0 {
		a.mu.Unlock()
		return
	}
	a.running[job.ID] = true
	a.executed[job.ID] = time.Now().Unix()
	for id, t := range a.executed { // prune replay guard; signatures expire long before this
		if time.Now().Unix()-t > 48*3600 {
			delete(a.executed, id)
		}
	}
	a.mu.Unlock()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			a.mu.Lock()
			delete(a.running, job.ID)
			a.mu.Unlock()
		}()
		select {
		case a.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		res := a.execute(ctx, &job)
		<-a.sem
		log.Printf("job %s (%s) -> %s exit=%d", job.ID, job.Tool, res.Status, res.ExitCode)
		a.report(res)
	}()
}

// report delivers a result, retrying, and spools it to disk if the server is
// unreachable so it is delivered after the next successful poll.
func (a *Agent) report(res *protocol.JobResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	backoff := time.Second
	for i := 0; i < 5; i++ {
		err := a.do(ctx, "POST", "/api/v1/agent/result", res, nil, true)
		if err == nil {
			return
		}
		var he *httpError
		if errors.As(err, &he) && he.Code == 404 {
			return // server no longer knows the job
		}
		if !sleepCtx(ctx, backoff) {
			break
		}
		backoff = nextBackoff(backoff)
	}
	dir := filepath.Join(a.DataDir, "spool")
	_ = os.MkdirAll(dir, 0o700)
	b, _ := json.Marshal(res)
	_ = os.WriteFile(filepath.Join(dir, res.JobID+".json"), b, 0o600)
	log.Printf("job %s result spooled for later delivery", res.JobID)
}

func (a *Agent) flushSpool(ctx context.Context) {
	dir := filepath.Join(a.DataDir, "spool")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var res protocol.JobResult
		if json.Unmarshal(b, &res) != nil {
			_ = os.Remove(p)
			continue
		}
		err = a.do(ctx, "POST", "/api/v1/agent/result", &res, nil, true)
		var he *httpError
		if err == nil || (errors.As(err, &he) && he.Code == 404) {
			_ = os.Remove(p)
		} else {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d = d*2 + time.Duration(rand.Int63n(int64(time.Second)))
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}
