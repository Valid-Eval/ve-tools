package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// An allow entry exempts paths from the embedded-crypto rule. Every entry must state why: the
// reason is printed whenever the entry is used, so an exemption is always visible in build logs.
//
// File format, one entry per line:
//
//	<glob> <reason...>
//
// <glob> matches the absolute in-image path with filepath.Match semantics, plus a trailing "/**"
// meaning "anything under this directory". '#' starts a comment line. Blank lines are ignored.
type allowEntry struct {
	Pattern string
	Reason  string
	Source  string // file:line, for the report
	Used    bool
}

func loadAllowFile(name string) ([]*allowEntry, error) {
	fh, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []*allowEntry
	sc := bufio.NewScanner(fh)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s:%d: entry %q has no reason; every exemption must say why", name, n, line)
		}
		pat := fields[0]
		if !strings.HasPrefix(pat, "/") {
			return nil, fmt.Errorf("%s:%d: pattern %q must be an absolute in-image path", name, n, pat)
		}
		if _, err := filepath.Match(strings.TrimSuffix(pat, "/**"), "/"); err != nil {
			return nil, fmt.Errorf("%s:%d: bad pattern %q: %v", name, n, pat, err)
		}
		out = append(out, &allowEntry{
			Pattern: pat,
			Reason:  strings.TrimSpace(strings.TrimPrefix(line, pat)),
			Source:  fmt.Sprintf("%s:%d", name, n),
		})
	}
	return out, sc.Err()
}

func (e *allowEntry) matches(p string) bool {
	if dir, ok := strings.CutSuffix(e.Pattern, "/**"); ok {
		return p == dir || strings.HasPrefix(p, dir+"/")
	}
	ok, _ := filepath.Match(e.Pattern, p)
	return ok
}

func findAllow(entries []*allowEntry, p string) *allowEntry {
	for _, e := range entries {
		if e.matches(p) {
			e.Used = true
			return e
		}
	}
	return nil
}
