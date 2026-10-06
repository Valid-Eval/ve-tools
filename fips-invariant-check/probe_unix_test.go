//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A probe whose child outlives it, holding the output pipe, must be cut off at the timeout AND
// its child killed. (WaitDelay alone bounds the wait but leaves the child running; this test
// checks the process-group kill, not just the bound.)
func TestRunProbeTimeoutKillsChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	var out bytes.Buffer
	start := time.Now()
	err := runProbe([]string{"sh", "-c", "sleep 600 & echo $! > " + pidFile + "; wait"}, &out, time.Second)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout, got %v", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("the run outlived the timeout by %s: the pipe was held, the group was not killed", d-time.Second)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the probe's child %d survived the timeout", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
