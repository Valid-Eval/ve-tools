package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
)

// An allow entry exempts paths from both rules: it removes a file from the OpenSSL-core count
// (rule 1) and turns a crypto-outside-a-module finding (rule 2) into an ALLOWED line. Every entry
// must state why; the reason is printed whenever the entry is used, so an exemption is always
// visible in build logs. Strict mode (production images) applies none of them.
//
// File format, one entry per line:
//
//	<glob> <reason...>
//
// <glob> matches the absolute in-image path with path.Match semantics (in-image paths always use
// "/"), plus a trailing "/**" meaning "anything under the matching directory"; the directory part
// may itself contain globs. A pattern whose first path component is a glob would exempt the
// whole image and is rejected. '#' starts a comment line. Blank lines are ignored.
type allowEntry struct {
	pattern string
	reason  string
	source  string // file:line, for the report
	used    bool
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
		if err := validatePattern(pat); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", name, n, err)
		}
		out = append(out, &allowEntry{
			pattern: pat,
			reason:  strings.TrimSpace(strings.TrimPrefix(line, pat)),
			source:  fmt.Sprintf("%s:%d", name, n),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %v", name, err)
	}
	return out, nil
}

func validatePattern(pat string) error {
	if !strings.HasPrefix(pat, "/") {
		return fmt.Errorf("pattern %q must be an absolute in-image path", pat)
	}
	base := strings.TrimSuffix(pat, "/**")
	first := strings.SplitN(strings.TrimPrefix(base, "/"), "/", 2)[0]
	if first == "" || strings.ContainsAny(first, `*?[\`) {
		return fmt.Errorf("pattern %q would exempt the whole image; name a directory or file", pat)
	}
	if _, err := path.Match(base, "/"); err != nil {
		return fmt.Errorf("bad pattern %q: %v", pat, err)
	}
	return nil
}

func (e *allowEntry) matches(p string) bool {
	if dir, ok := strings.CutSuffix(e.pattern, "/**"); ok {
		// Match the directory part component by component, so globs in it work and a sibling with
		// the same prefix (/opt/a vs /opt/ab) does not.
		want := strings.Split(dir, "/")
		got := strings.Split(p, "/")
		if len(got) < len(want) {
			return false
		}
		for i, w := range want {
			if ok, _ := path.Match(w, got[i]); !ok {
				return false
			}
		}
		return true
	}
	ok, _ := path.Match(e.pattern, p)
	return ok
}

func findAllow(entries []*allowEntry, p string) *allowEntry {
	for _, e := range entries {
		if e.matches(p) {
			e.used = true
			return e
		}
	}
	return nil
}
