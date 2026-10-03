//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// killProcessGroupOnCancel runs cmd in its own process group and kills the whole group when its
// context ends, so children the probe started die with it.
func killProcessGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
