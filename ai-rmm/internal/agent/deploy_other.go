//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/airmm/airmm/internal/protocol"
)

func nativeDeployAgent(ctx context.Context, a *Agent, job *protocol.Job) (interface{}, error) {
	return nil, errors.New("deploy_agent needs a Windows source machine")
}

func promoteWatchdog() {}
