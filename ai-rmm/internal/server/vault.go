package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/airmm/airmm/internal/protocol"
)

// The credential vault holds secrets the AI may *use* but never *see*:
// a domain account for pushing the agent to new machines, SNMP credentials
// for network devices, and anything a custom tool needs. Secrets are
// encrypted at rest with AES-256-GCM using vault.key (kept separate from
// state.json so a leaked state file alone reveals nothing), and are only
// ever decrypted into a signed job or a collector's monitoring config.

const vaultKeyFile = "vault.key"

const (
	CredWindows = "windows" // username + password (e.g. CORP\svc-rmm-deploy)
	CredSNMP    = "snmp"    // community, or v3 user/auth/priv
	CredGeneric = "generic" // arbitrary key/value secrets for custom tools
)

type StoredCredential struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Username    string `json:"username,omitempty"` // shown in listings; not secret
	Description string `json:"description,omitempty"`
	Ciphertext  string `json:"ciphertext"`
	CreatedAt   int64  `json:"created_at"`
	CreatedBy   string `json:"created_by"`
}

// CredentialInfo is what listings return.
type CredentialInfo struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Username    string `json:"username,omitempty"`
	Description string `json:"description,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

var credNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func loadOrCreateVaultKey(dir string) ([]byte, error) {
	p := filepath.Join(dir, vaultKeyFile)
	b, err := os.ReadFile(p)
	if err == nil {
		k, err := base64.StdEncoding.DecodeString(string(trimSpace(b)))
		if err != nil || len(k) != 32 {
			return nil, errors.New("vault.key is corrupt")
		}
		return k, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Server) seal(name string, secrets map[string]string) (string, error) {
	block, err := aes.NewCipher(s.vaultKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	pt, _ := json.Marshal(secrets)
	// The credential name is bound as associated data so ciphertexts can't be
	// swapped between entries in state.json.
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, pt, []byte(name))), nil
}

func (s *Server) open(c *StoredCredential) (map[string]string, error) {
	raw, err := base64.StdEncoding.DecodeString(c.Ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.vaultKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(c.Name))
	if err != nil {
		return nil, fmt.Errorf("decrypt credential %s: %w", c.Name, err)
	}
	var out map[string]string
	return out, json.Unmarshal(pt, &out)
}

// PutCredential stores (or replaces) a credential. Admin only.
func (s *Server) PutCredential(c Caller, name, kind, description string, secrets map[string]string) error {
	if c.Role != RoleAdmin {
		return errors.New("only an admin can store credentials")
	}
	if !credNameRe.MatchString(name) {
		return errors.New("credential name must match ^[a-z0-9][a-z0-9._-]{0,62}$")
	}
	switch kind {
	case CredWindows:
		if secrets["username"] == "" || secrets["password"] == "" {
			return errors.New("windows credential needs username and password")
		}
	case CredSNMP:
		v := secrets["version"]
		if v == "" {
			v = "2c"
			secrets["version"] = v
		}
		if v == "2c" && secrets["community"] == "" {
			return errors.New("snmp v2c credential needs community")
		}
		if v == "3" && secrets["username"] == "" {
			return errors.New("snmp v3 credential needs username")
		}
		if v != "2c" && v != "3" {
			return errors.New("snmp version must be 2c or 3")
		}
	case CredGeneric:
		if len(secrets) == 0 {
			return errors.New("generic credential needs at least one key")
		}
	default:
		return errors.New("kind must be windows, snmp or generic")
	}
	ct, err := s.seal(name, secrets)
	if err != nil {
		return err
	}
	sc := &StoredCredential{Name: name, Kind: kind, Username: secrets["username"], Description: description, Ciphertext: ct, CreatedAt: now(), CreatedBy: c.String()}
	s.store.mu.Lock()
	s.store.st.Credentials[name] = sc
	s.store.markDirty()
	s.store.mu.Unlock()
	s.Audit(c.String(), "credential.put", map[string]string{"name": name, "kind": kind, "username": sc.Username})
	return nil
}

func (s *Server) DeleteCredential(c Caller, name string) error {
	if c.Role != RoleAdmin {
		return errors.New("only an admin can delete credentials")
	}
	s.store.mu.Lock()
	_, ok := s.store.st.Credentials[name]
	delete(s.store.st.Credentials, name)
	s.store.markDirty()
	s.store.mu.Unlock()
	if !ok {
		return errors.New("no such credential")
	}
	s.Audit(c.String(), "credential.delete", map[string]string{"name": name})
	return nil
}

func (s *Server) ListCredentials() []CredentialInfo {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	out := []CredentialInfo{}
	for _, c := range s.store.st.Credentials {
		out = append(out, CredentialInfo{Name: c.Name, Kind: c.Kind, Username: c.Username, Description: c.Description, CreatedAt: c.CreatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// credentialLocked decrypts a credential and checks its kind. mu must be held.
func (s *Server) credentialLocked(name, kind string) (map[string]string, error) {
	c, ok := s.store.st.Credentials[name]
	if !ok {
		return nil, fmt.Errorf("no credential named %q (an admin stores credentials in the console or with `rmm-server credential`)", name)
	}
	if kind != "" && c.Kind != kind {
		return nil, fmt.Errorf("credential %q is %s, need %s", name, c.Kind, kind)
	}
	return s.open(c)
}

func snmpAuthFrom(sec map[string]string) *protocol.SNMPAuth {
	return &protocol.SNMPAuth{
		Version: sec["version"], Community: sec["community"], Username: sec["username"],
		AuthProto: sec["auth_proto"], AuthPass: sec["auth_pass"], PrivProto: sec["priv_proto"], PrivPass: sec["priv_pass"],
	}
}
