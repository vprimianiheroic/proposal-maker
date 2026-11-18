//go:build !windows

package agent

import (
	"os"
	"runtime"
	"strings"

	"github.com/airmm/airmm/internal/protocol"
)

// Non-Windows builds exist for development and CI only.
func platformFacts(f *protocol.Facts) {
	f.OSName = runtime.GOOS
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				f.OSName = strings.Trim(l[len("PRETTY_NAME="):], `"`)
			}
		}
	}
	f.ProductType = "workstation"
}
