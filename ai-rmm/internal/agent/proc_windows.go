//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"syscall"
)

const createNoWindow = 0x08000000

func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// killTree terminates PowerShell and anything it spawned (msiexec, etc.).
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	k := exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
	setProcAttrs(k)
	if k.Run() != nil {
		_ = cmd.Process.Kill()
	}
}
