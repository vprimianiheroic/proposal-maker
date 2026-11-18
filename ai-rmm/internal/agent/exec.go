package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// prelude wraps every tool body. It gives tools Get-RmmParam and
// Invoke-RmmNative, captures whatever objects the body emits, and prints them
// as JSON after a marker so host noise on stdout cannot corrupt the result.
const prelude = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
$RmmParams = New-Object PSObject
$__raw = [System.IO.File]::ReadAllText($env:RMM_PARAMS_FILE)
if ($__raw.Trim()) { $RmmParams = ConvertFrom-Json $__raw }
function Get-RmmParam {
  param([string]$Name, $Default = $null)
  $p = $RmmParams.PSObject.Properties[$Name]
  if ($null -eq $p -or $null -eq $p.Value) { return $Default }
  return $p.Value
}
function Get-RmmSecret {
  param([string]$Name)
  if (-not $global:__rmmSecrets) {
    $global:__rmmSecrets = New-Object PSObject
    if ($env:RMM_SECRETS_FILE -and (Test-Path -LiteralPath $env:RMM_SECRETS_FILE)) {
      $global:__rmmSecrets = ConvertFrom-Json ([System.IO.File]::ReadAllText($env:RMM_SECRETS_FILE))
      Remove-Item -LiteralPath $env:RMM_SECRETS_FILE -Force -ErrorAction SilentlyContinue
    }
  }
  $p = $global:__rmmSecrets.PSObject.Properties[$Name]
  if ($null -eq $p) { throw "secret '$Name' was not provided to this job" }
  return $p.Value
}
function Invoke-RmmNative {
  param([string]$FilePath, [string[]]$ArgumentList = @())
  $ErrorActionPreference = 'Continue'
  $lines = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
  [pscustomobject]@{ exit_code = $LASTEXITCODE; lines = $lines; output = ($lines -join "` + "`" + `n") }
}
try {
  $__result = & {
%BODY%
  }
  $__json = ConvertTo-Json -InputObject $__result -Depth 8 -Compress
  [Console]::Out.WriteLine('` + protocol.DataMarker + `')
  [Console]::Out.WriteLine($__json)
  exit 0
} catch {
  [Console]::Error.WriteLine(($_ | Out-String))
  if ($_.ScriptStackTrace) { [Console]::Error.WriteLine($_.ScriptStackTrace) }
  exit 1
}
`

// bootstrap is passed with -Command so that a machine-wide AllSigned
// execution policy (common in hardened domains) does not block the
// (signature-verified) job script.
const bootstrap = `& ([scriptblock]::Create([System.IO.File]::ReadAllText($env:RMM_SCRIPT_FILE)))`

const maxOutput = 1 << 20

func (a *Agent) execute(ctx context.Context, job *protocol.Job) *protocol.JobResult {
	res := a.executeRaw(ctx, job)
	redactResult(res, job.Secrets)
	return res
}

// redactResult scrubs every delivered secret value from the result, so a
// careless (or malicious) tool cannot echo a password back to the server
// and the AI.
func redactResult(res *protocol.JobResult, secrets map[string]string) {
	for _, v := range secrets {
		if len(v) < 4 {
			continue
		}
		res.Stdout = strings.Replace(res.Stdout, v, "[REDACTED]", -1)
		res.Stderr = strings.Replace(res.Stderr, v, "[REDACTED]", -1)
		if len(res.Data) > 0 {
			enc, _ := json.Marshal(v) // match the JSON-escaped form too
			d := strings.Replace(string(res.Data), v, "[REDACTED]", -1)
			d = strings.Replace(d, string(enc[1:len(enc)-1]), "[REDACTED]", -1)
			if json.Valid([]byte(d)) {
				res.Data = json.RawMessage(d)
			} else {
				res.Data = nil
				res.Stderr += "\n[agent: structured output dropped: it contained a secret]"
			}
		}
	}
}

func (a *Agent) executeRaw(ctx context.Context, job *protocol.Job) *protocol.JobResult {
	res := &protocol.JobResult{JobID: job.ID, StartedAt: time.Now().Unix()}
	finish := func(status string, code int, stderr string) *protocol.JobResult {
		res.Status, res.ExitCode, res.FinishedAt = status, code, time.Now().Unix()
		if stderr != "" {
			res.Stderr = stderr
		}
		return res
	}
	if err := job.Verify(a.pub, a.Cfg.AgentID, time.Now()); err != nil {
		return finish(protocol.StatusRejected, -1, "agent refused job: "+err.Error())
	}

	if job.Kind == "native" {
		return a.runNative(ctx, job, res)
	}
	if job.Kind != "" {
		return finish(protocol.StatusRejected, -1, "unknown job kind "+job.Kind)
	}

	work := filepath.Join(a.DataDir, "work", job.ID)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return finish(protocol.StatusFailed, -1, err.Error())
	}
	defer os.RemoveAll(work)
	paramsFile := filepath.Join(work, "params.json")
	scriptFile := filepath.Join(work, "script.ps1")
	params := job.Params
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	script := strings.Replace(prelude, "%BODY%", job.Script, 1)
	if err := os.WriteFile(paramsFile, params, 0o600); err != nil {
		return finish(protocol.StatusFailed, -1, err.Error())
	}
	if err := os.WriteFile(scriptFile, []byte(script), 0o600); err != nil {
		return finish(protocol.StatusFailed, -1, err.Error())
	}
	secretsFile := ""
	if len(job.Secrets) > 0 {
		// Read once (and deleted) by Get-RmmSecret; never put in env vars or
		// command lines, which other local processes can inspect.
		secretsFile = filepath.Join(work, "secrets.json")
		b, _ := json.Marshal(job.Secrets)
		if err := os.WriteFile(secretsFile, b, 0o600); err != nil {
			return finish(protocol.StatusFailed, -1, err.Error())
		}
	}

	ps := a.powershell()
	tctx, cancel := context.WithTimeout(ctx, time.Duration(job.TimeoutSec)*time.Second)
	defer cancel()
	cmd := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-InputFormat", "None", "-ExecutionPolicy", "Bypass", "-Command", bootstrap)
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"RMM_PARAMS_FILE="+paramsFile, "RMM_SCRIPT_FILE="+scriptFile,
		"RMM_JOB_ID="+job.ID, "RMM_TOOL="+job.Tool, "RMM_SECRETS_FILE="+secretsFile)
	var stdout, stderr capBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	setProcAttrs(cmd)
	if err := cmd.Start(); err != nil {
		return finish(protocol.StatusFailed, -1, fmt.Sprintf("start %s: %v", ps, err))
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	timedOut := false
	select {
	case waitErr = <-done:
	case <-tctx.Done():
		timedOut = true
		killTree(cmd)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}

	out := stdout.String()
	if i := strings.LastIndex(out, protocol.DataMarker); i >= 0 {
		data := strings.TrimSpace(out[i+len(protocol.DataMarker):])
		if json.Valid([]byte(data)) {
			res.Data = json.RawMessage(data)
		}
		out = out[:i]
	}
	res.Stdout = strings.TrimSpace(out)
	res.Stderr = strings.TrimSpace(stderr.String())
	if stdout.truncated || stderr.truncated {
		res.Stderr += "\n[agent: output truncated at 1MB]"
	}
	switch {
	case timedOut:
		return finish(protocol.StatusTimeout, -1, res.Stderr+fmt.Sprintf("\n[agent: killed after %ds timeout]", job.TimeoutSec))
	case waitErr != nil:
		code := -1
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return finish(protocol.StatusFailed, code, "")
	}
	return finish(protocol.StatusSucceeded, 0, "")
}

// powershell picks Windows PowerShell 5.1 from the native System32, even when
// this is the 32-bit agent on 64-bit Windows (where System32 would redirect
// to the 32-bit SysWOW64 copy with a different registry view).
func (a *Agent) powershell() string {
	if a.Cfg.PowerShellPath != "" {
		return a.Cfg.PowerShellPath
	}
	if runtime.GOOS != "windows" {
		return "pwsh"
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	native := filepath.Join(root, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(native); err == nil {
		return native
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// capBuffer is a goroutine-safe buffer that stops growing at maxOutput.
type capBuffer struct {
	mu        sync.Mutex
	b         bytes.Buffer
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := maxOutput - c.b.Len(); room < len(p) {
		if room > 0 {
			c.b.Write(p[:room])
		}
		c.truncated = true
		return len(p), nil
	}
	return c.b.Write(p)
}

func (c *capBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}
