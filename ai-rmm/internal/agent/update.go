package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// applyUpdate downloads the assigned build, checks the server's signature and
// the SHA-256, then swaps binaries. Windows lets a running .exe be renamed
// (not overwritten), so: current -> .old, new -> current, then exit and let
// the service manager's recovery action start the new binary.
func (a *Agent) applyUpdate(ctx context.Context, u *protocol.UpdateInfo) error {
	sig, err := base64.StdEncoding.DecodeString(u.Signature)
	if err != nil {
		return err
	}
	arch, variant := u.Arch, u.Variant
	if arch == "" { // older servers
		arch, variant = runtime.GOARCH, a.Variant
	}
	msg := protocol.UpdateSigningBytes("windows", arch, variant, u.Version, u.SHA256)
	if !ed25519.Verify(a.pub, msg, sig) {
		return errors.New("update signature invalid; refusing")
	}
	if !strings.HasPrefix(u.URL, "/api/v1/agent/release/") {
		return errors.New("unexpected update URL")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	newPath, oldPath := exe+".new", exe+".old"

	req, err := http.NewRequestWithContext(ctx, "GET", a.endpoint()+u.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Cfg.AgentID+"."+a.Cfg.AgentSecret)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(newPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	f.Close()
	if err != nil {
		os.Remove(newPath)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, u.SHA256) {
		os.Remove(newPath)
		return fmt.Errorf("sha256 mismatch: got %s", got)
	}
	// The marker makes the watchdog roll back if the new build never
	// manages to reach the server.
	marker, _ := json.Marshal(map[string]interface{}{"from": a.Version, "to": u.Version, "time": time.Now().Unix()})
	if err := os.WriteFile(filepath.Join(a.DataDir, updateMarker), marker, 0o600); err != nil {
		os.Remove(newPath)
		return err
	}
	_ = os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("rename current binary: %w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(oldPath, exe) // roll back
		_ = os.Remove(filepath.Join(a.DataDir, updateMarker))
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

const updateMarker = "update-pending.json"

// cleanupOldBinary runs at startup. If this build was just installed by a
// self-update it re-stamps the marker so the watchdog's 15-minute rollback
// clock starts now (not when the update was staged, possibly before a
// sleep or reboot). The previous build (.old) is kept until the new one
// has proven itself for 24h (see promoteWatchdog).
func cleanupOldBinary(dataDir string) {
	marker := filepath.Join(dataDir, updateMarker)
	b, err := os.ReadFile(marker)
	if err != nil {
		return
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		m = map[string]interface{}{}
	}
	// Stamp the first start only: a crash-looping build must not keep
	// resetting the watchdog's rollback clock.
	if _, ok := m["started_at"]; !ok {
		m["started_at"] = time.Now().Unix()
		nb, _ := json.Marshal(m)
		_ = os.WriteFile(marker, nb, 0o600)
	}
}

// markerAge is how long the updated build has been trying to reach the
// server (falls back to the file time for markers without started_at).
func markerAge(path string) (time.Duration, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	var m struct {
		StartedAt int64 `json:"started_at"`
	}
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &m) == nil && m.StartedAt > 0 {
		return time.Since(time.Unix(m.StartedAt, 0)), true
	}
	return time.Since(fi.ModTime()), true
}
