package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

type Agent struct {
	ID         string         `json:"id"`
	Hostname   string         `json:"hostname"`
	SecretHash string         `json:"secret_hash"`
	Groups     []string       `json:"groups"`
	Facts      protocol.Facts `json:"facts"`
	Version    string         `json:"version"`
	Variant    string         `json:"variant"`
	EnrolledAt int64          `json:"enrolled_at"`
	LastSeen   int64          `json:"last_seen"`
	LastIP     string         `json:"last_ip"`
	Notes      string         `json:"notes,omitempty"`
	Disabled   bool           `json:"disabled,omitempty"`
}

type JobRecord struct {
	ID             string              `json:"id"`
	BatchID        string              `json:"batch_id"`
	AgentID        string              `json:"agent_id"`
	Hostname       string              `json:"hostname"`
	Tool           string              `json:"tool"`
	ToolVersion    int                 `json:"tool_version"`
	Risk           protocol.Risk       `json:"risk"`
	Params         json.RawMessage     `json:"params"`
	Script         string              `json:"script"`
	TimeoutSec     int                 `json:"timeout_sec"`
	Reason         string              `json:"reason"`
	RequestedBy    string              `json:"requested_by"`
	ApprovalReason string              `json:"approval_reason,omitempty"` // why a human must approve
	DecidedBy      string              `json:"decided_by,omitempty"`
	Status         string              `json:"status"`
	CreatedAt      int64               `json:"created_at"`
	QueueDeadline  int64               `json:"queue_deadline"`
	DispatchedAt   int64               `json:"dispatched_at,omitempty"`
	ExpiresAt      int64               `json:"expires_at,omitempty"`
	FinishedAt     int64               `json:"finished_at,omitempty"`
	Result         *protocol.JobResult `json:"result,omitempty"`
}

type APIKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"` // admin | ai
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"created_at"`
	Disabled  bool   `json:"disabled,omitempty"`
}

const (
	RoleAdmin = "admin"
	RoleAI    = "ai"
)

type EnrollToken struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Hash      string   `json:"hash"`
	Groups    []string `json:"groups"`
	ExpiresAt int64    `json:"expires_at"`
	MaxUses   int      `json:"max_uses"` // 0 = unlimited
	Uses      int      `json:"uses"`
	CreatedAt int64    `json:"created_at"`
	Revoked   bool     `json:"revoked,omitempty"`
}

type Release struct {
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Variant   string   `json:"variant"` // "" (modern) | legacy
	Version   string   `json:"version"`
	File      string   `json:"file"` // under <data>/releases
	SHA256    string   `json:"sha256"`
	Signature string   `json:"signature"`
	Groups    []string `json:"groups,omitempty"` // empty = every agent of that os/arch/variant
	CreatedAt int64    `json:"created_at"`
}

// State is everything persisted in state.json.
type State struct {
	Agents       map[string]*Agent       `json:"agents"`
	Jobs         map[string]*JobRecord   `json:"jobs"`
	Tools        map[string]*Tool        `json:"tools"` // custom tools only; builtins come from the binary
	APIKeys      map[string]*APIKey      `json:"api_keys"`
	EnrollTokens map[string]*EnrollToken `json:"enroll_tokens"`
	Releases     []*Release              `json:"releases"`
}

func newState() *State {
	return &State{
		Agents:       map[string]*Agent{},
		Jobs:         map[string]*JobRecord{},
		Tools:        map[string]*Tool{},
		APIKeys:      map[string]*APIKey{},
		EnrollTokens: map[string]*EnrollToken{},
	}
}

// store wraps State with a mutex and debounced atomic persistence.
type store struct {
	mu        sync.Mutex
	st        *State
	path      string
	dirty     bool
	retention int
}

func loadStore(dir string, retention int) (*store, error) {
	s := &store{st: newState(), path: filepath.Join(dir, "state.json"), retention: retention}
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, s.st); err != nil {
			return nil, fmt.Errorf("parse %s: %w", s.path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Maps may be nil when loading an older/partial file.
	n := newState()
	if s.st.Agents == nil {
		s.st.Agents = n.Agents
	}
	if s.st.Jobs == nil {
		s.st.Jobs = n.Jobs
	}
	if s.st.Tools == nil {
		s.st.Tools = n.Tools
	}
	if s.st.APIKeys == nil {
		s.st.APIKeys = n.APIKeys
	}
	if s.st.EnrollTokens == nil {
		s.st.EnrollTokens = n.EnrollTokens
	}
	return s, nil
}

// markDirty must be called with mu held.
func (s *store) markDirty() { s.dirty = true }

// flush writes state.json atomically if anything changed.
func (s *store) flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	s.pruneLocked()
	b, err := json.MarshalIndent(s.st, "", " ")
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// pruneLocked drops the oldest finished jobs beyond the retention limit.
func (s *store) pruneLocked() {
	if s.retention <= 0 || len(s.st.Jobs) <= s.retention {
		return
	}
	var done []*JobRecord
	for _, j := range s.st.Jobs {
		if protocol.IsTerminal(j.Status) {
			done = append(done, j)
		}
	}
	sort.Slice(done, func(a, b int) bool { return done[a].CreatedAt < done[b].CreatedAt })
	excess := len(s.st.Jobs) - s.retention
	for i := 0; i < excess && i < len(done); i++ {
		delete(s.st.Jobs, done[i].ID)
	}
}

// ---- small crypto helpers ----

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func newID(prefix string) string { return prefix + "_" + randomHex(8) }

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func secretMatches(hash, secret string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(hashSecret(secret))) == 1
}

func now() int64 { return time.Now().Unix() }
