package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/airmm/airmm/internal/protocol"
)

// Policy governs what an AI caller may run without a human approving.
type Policy struct {
	// Highest tool risk that runs without approval: none | read | change | high.
	AutoApproveMaxRisk protocol.Risk `json:"auto_approve_max_risk"`
	// Whether run_powershell (ad-hoc, always "high" risk) may be requested at all.
	AllowAdHocScripts bool `json:"allow_adhoc_scripts"`
}

type Config struct {
	Listen    string `json:"listen"`
	PublicURL string `json:"public_url"` // what agents use; informational
	TLSCert   string `json:"tls_cert"`   // relative to data dir; empty = plain HTTP (lab only)
	TLSKey    string `json:"tls_key"`

	// DefaultPolicy applies to every agent. GroupPolicies can only tighten it:
	// an agent's effective policy is the strictest of the default and every
	// group policy matching one of its groups.
	DefaultPolicy Policy            `json:"default_policy"`
	GroupPolicies map[string]Policy `json:"group_policies"`

	JobRetention    int `json:"job_retention"`     // finished jobs kept in state.json
	OfflineAfterSec int `json:"offline_after_sec"` // agent considered offline after this
	DefaultQueueMin int `json:"default_queue_min"` // how long a job waits for an offline agent
}

func DefaultConfig() *Config {
	return &Config{
		Listen:    ":8443",
		PublicURL: "https://rmm.example.local:8443",
		TLSCert:   "tls.crt",
		TLSKey:    "tls.key",
		DefaultPolicy: Policy{
			AutoApproveMaxRisk: protocol.RiskChange,
			AllowAdHocScripts:  true,
		},
		GroupPolicies: map[string]Policy{
			// Production floor / OT-adjacent machines: look, don't touch.
			"ot":                 {AutoApproveMaxRisk: protocol.RiskRead, AllowAdHocScripts: true},
			"domain-controllers": {AutoApproveMaxRisk: protocol.RiskRead, AllowAdHocScripts: true},
			"servers":            {AutoApproveMaxRisk: protocol.RiskRead, AllowAdHocScripts: true},
		},
		JobRetention:    20000,
		OfflineAfterSec: 120,
		DefaultQueueMin: 60,
	}
}

func LoadConfig(dir string) (*Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	return c, nil
}

func SaveConfig(dir string, c *Config) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

// EffectivePolicy returns the strictest applicable policy and the names of
// the policies that contributed, for explaining approval decisions.
func (c *Config) EffectivePolicy(groups []string) (Policy, []string) {
	p := c.DefaultPolicy
	sources := []string{"default"}
	gs := append([]string(nil), groups...)
	sort.Strings(gs)
	for _, g := range gs {
		gp, ok := c.GroupPolicies[g]
		if !ok {
			continue
		}
		sources = append(sources, "group:"+g)
		if gp.AutoApproveMaxRisk.Level() < p.AutoApproveMaxRisk.Level() {
			p.AutoApproveMaxRisk = gp.AutoApproveMaxRisk
		}
		if !gp.AllowAdHocScripts {
			p.AllowAdHocScripts = false
		}
	}
	return p, sources
}
