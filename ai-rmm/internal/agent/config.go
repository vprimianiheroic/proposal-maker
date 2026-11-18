package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config lives in <DataDir>/agent.json. On Windows the installer restricts
// the directory to SYSTEM and Administrators because it holds the agent secret.
type Config struct {
	ServerURL string `json:"server_url"`
	// ServerURLs is the ordered failover list pushed by the server
	// (primary first). InstallURL is the address given at install time and
	// is always kept as a last resort so a bad push can't strand the agent.
	ServerURLs     []string `json:"server_urls,omitempty"`
	InstallURL     string   `json:"install_url,omitempty"`
	ServerPubKey   string   `json:"server_public_key"`        // base64 Ed25519; jobs must be signed by it
	TLSPinSHA256   string   `json:"tls_pin_sha256,omitempty"` // hex SHA-256 of server cert SPKI (for self-signed certs)
	EnrollToken    string   `json:"enroll_token,omitempty"`   // removed after successful enrollment
	AgentID        string   `json:"agent_id,omitempty"`
	AgentSecret    string   `json:"agent_secret,omitempty"`
	MaxConcurrent  int      `json:"max_concurrent,omitempty"`
	PowerShellPath string   `json:"powershell_path,omitempty"` // override interpreter (testing / pwsh)
	LogLevel       string   `json:"log_level,omitempty"`

	path string
}

func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "AIRMM")
	}
	return "/var/lib/airmm"
}

func DefaultConfigPath() string { return filepath.Join(DefaultDataDir(), "agent.json") }

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	c.path = path
	return c, c.Validate()
}

func (c *Config) Validate() error {
	c.ServerURL = strings.TrimRight(strings.TrimSpace(c.ServerURL), "/")
	if !strings.HasPrefix(c.ServerURL, "https://") && !strings.HasPrefix(c.ServerURL, "http://") {
		return errors.New("server_url must start with https://")
	}
	if _, err := c.PublicKey(); err != nil {
		return err
	}
	if c.AgentID == "" && c.EnrollToken == "" {
		return errors.New("not enrolled and no enroll_token configured")
	}
	if c.InstallURL == "" {
		c.InstallURL = c.ServerURL
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 4
	}
	return nil
}

func (c *Config) PublicKey() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.ServerPubKey))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("server_public_key must be a base64 Ed25519 public key (from `rmm-server init`)")
	}
	return ed25519.PublicKey(b), nil
}

func (c *Config) Path() string { return c.path }

func (c *Config) Save(path string) error {
	if path == "" {
		path = c.path
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	c.path = path
	return nil
}

// Endpoints returns the de-duplicated failover order.
func (c *Config) Endpoints() []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range append(append([]string{c.ServerURL}, c.ServerURLs...), c.InstallURL) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u != "" && !seen[u] && (strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}
