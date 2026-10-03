//go:build !unix

package main

import "os/exec"

// killProcessGroupOnCancel: no process groups here (the tool runs in Linux images; this keeps it
// building on other hosts, e.g. scanning an extracted rootfs on Windows). exec.CommandContext's
// default Cancel kills the probe process itself; runProbe's WaitDelay bounds the wait for any
// child that keeps the output open.
func killProcessGroupOnCancel(cmd *exec.Cmd) {}
