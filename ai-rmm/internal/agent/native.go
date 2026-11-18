package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// Native tools run in-process. Each returns structured data (sent as the
// job's data) or an error.
type nativeFunc func(ctx context.Context, a *Agent, job *protocol.Job) (interface{}, error)

var nativeTools = map[string]nativeFunc{
	"network_scan": nativeNetworkScan,
	"deploy_agent": nativeDeployAgent, // Windows implementation in deploy_windows.go
}

func (a *Agent) runNative(ctx context.Context, job *protocol.Job, res *protocol.JobResult) *protocol.JobResult {
	fn, ok := nativeTools[job.Tool]
	if !ok {
		res.Status, res.ExitCode, res.Stderr = protocol.StatusRejected, -1, "this agent version has no native tool "+job.Tool+"; update the agent"
		res.FinishedAt = time.Now().Unix()
		return res
	}
	tctx, cancel := context.WithTimeout(ctx, time.Duration(job.TimeoutSec)*time.Second)
	defer cancel()
	data, err := func() (d interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("native tool panic: %v", r)
			}
		}()
		return fn(tctx, a, job)
	}()
	res.FinishedAt = time.Now().Unix()
	if data != nil {
		if b, mErr := json.Marshal(data); mErr == nil {
			res.Data = b
		}
	}
	switch {
	case tctx.Err() == context.DeadlineExceeded:
		res.Status, res.ExitCode, res.Stderr = protocol.StatusTimeout, -1, fmt.Sprintf("native tool exceeded %ds", job.TimeoutSec)
	case err != nil:
		res.Status, res.ExitCode, res.Stderr = protocol.StatusFailed, 1, err.Error()
	default:
		res.Status, res.ExitCode = protocol.StatusSucceeded, 0
	}
	return res
}
