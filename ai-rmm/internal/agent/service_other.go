//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
)

// Non-Windows builds are for development and CI; run the agent in the
// foreground (or under systemd) instead of installing a service.

func IsService() bool    { return false }
func InstallDir() string { return "/opt/airmm" }
func RunService(run func(ctx context.Context) bool) error {
	return errors.New("not supported on this OS")
}
func SecureDir(dir string) error { return os.MkdirAll(dir, 0o700) }
func InstallService(cfg *Config, inPlace bool) error {
	return errors.New("service install is only supported on Windows; use `rmm-agent run --config <file>`")
}
func UninstallService(purge bool) error { return errors.New("only supported on Windows") }
