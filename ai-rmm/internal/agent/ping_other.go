//go:build !windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

var pingTimeRe = regexp.MustCompile(`time[=<]([0-9.]+)`)

// Non-Windows (dev/CI) builds shell out to ping(8).
func pingOnce(ctx context.Context, host string, timeout time.Duration) (float64, bool) {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprint(secs), host).Output()
	if err != nil {
		return 0, false
	}
	if m := pingTimeRe.FindSubmatch(out); m != nil {
		ms, _ := strconv.ParseFloat(string(m[1]), 64)
		return ms, true
	}
	return 0, true
}
