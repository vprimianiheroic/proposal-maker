package server

import (
	"crypto/ed25519"
	"encoding/base64"

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
