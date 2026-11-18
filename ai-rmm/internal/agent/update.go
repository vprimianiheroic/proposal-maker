package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

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
	msg := protocol.UpdateSigningBytes("windows", runtime.GOARCH, a.Variant, u.Version, u.SHA256)
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

	req, err := http.NewRequestWithContext(ctx, "GET", a.Cfg.ServerURL+u.URL, nil)
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
	_ = os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("rename current binary: %w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(oldPath, exe) // roll back
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

func cleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
