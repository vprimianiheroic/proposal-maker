package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/airmm/airmm/internal/protocol"
)

// SignUpdate signs an agent build so agents only install binaries this
// server's key approved.
func (s *Server) SignUpdate(osName, arch, variant, version, sha string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.signKey, protocol.UpdateSigningBytes(osName, arch, variant, version, sha)))
}

func (s *Server) AddRelease(c Caller, r *Release) {
	s.store.mu.Lock()
	s.store.st.Releases = append(s.store.st.Releases, r)
	s.store.markDirty()
	s.store.mu.Unlock()
	s.Audit(c.String(), "release.add", r)
}

var versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)

// PublishRelease stores an agent binary, signs it and makes it the current
// build for its arch/variant (optionally only for some groups). Safe to call
// while the server is running (REST: POST /api/v1/releases).
func (s *Server) PublishRelease(c Caller, body io.Reader, version, arch, variant string, groups []string) (*Release, error) {
	if c.Role != RoleAdmin {
		return nil, errors.New("only an admin can publish agent releases")
	}
	if !versionRe.MatchString(version) {
		return nil, errors.New("invalid version")
	}
	if arch != "amd64" && arch != "386" && arch != "arm64" {
		return nil, errors.New("arch must be amd64, 386 or arm64")
	}
	if variant != "" && variant != "legacy" {
		return nil, errors.New(`variant must be "" or "legacy"`)
	}
	gs, err := normGroups(groups)
	if err != nil {
		return nil, err
	}
	suffix := ""
	if variant != "" {
		suffix = "-" + variant
	}
	name := fmt.Sprintf("rmm-agent-%s-windows-%s%s.exe", version, arch, suffix)
	dir := filepath.Join(s.Dir, "releases")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "upload-*")
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, 200<<20))
	tmp.Close()
	if err == nil && n < 1024 {
		err = errors.New("file too small to be an agent build")
	}
	var head [2]byte
	if f, ferr := os.Open(tmp.Name()); ferr == nil {
		_, _ = io.ReadFull(f, head[:])
		f.Close()
	}
	if err == nil && string(head[:]) != "MZ" {
		err = errors.New("not a Windows executable")
	}
	if err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	r := &Release{OS: "windows", Arch: arch, Variant: variant, Version: version, File: name, SHA256: sha,
		Signature: s.SignUpdate("windows", arch, variant, version, sha), Groups: gs, CreatedAt: now()}
	s.AddRelease(c, r)
	return r, nil
}

// ListReleases returns published builds, newest first.
func (s *Server) ListReleases() []*Release {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	out := make([]*Release, 0, len(s.store.st.Releases))
	for i := len(s.store.st.Releases) - 1; i >= 0; i-- {
		c := *s.store.st.Releases[i]
		out = append(out, &c)
	}
	return out
}
