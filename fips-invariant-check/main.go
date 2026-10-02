// fips-invariant-check enforces the VE fleet's FIPS crypto invariant on a container image's
// filesystem, from inside the image (it is a static binary, so it runs in distroless images).
//
// The invariant:
//
//  1. ONE OpenSSL core. Every binary and library that links OpenSSL links the same major
//     (libcrypto.so.N). Two cores in one process cannot both initialise the single FIPS provider
//     module: whichever loads second fails ("could not generate nonce" from libpq, 2026-10-02).
//  2. NO unvalidated crypto. No binary carries its own crypto library (a precompiled gem or wheel
//     that statically links OpenSSL/BoringSSL/AWS-LC, a vendored libcrypto, Mozilla NSS). Those
//     never touch the FIPS provider and do not fail: they silently run non-validated crypto.
//     Go binaries are the one sanctioned second module: they pass only when built on the
//     validated Go Cryptographic Module (GOFIPS140=v1.0.0, fips140=on by default; CMVP #5247) or
//     with -tags requirefips (golang-fips/openssl, i.e. the system FIPS provider).
//
// Structural checks cannot prove behaviour, so the image can also register a behavioural probe
// (--probe ... or the FIPS_INVARIANT_PROBE env var) that this tool runs after the scan: a
// language-specific script that loads the runtime's own crypto, then the native libraries, and
// asserts FIPS behaviour (MD5 refused, SHA-256 and RAND working).
//
// Exit status: 0 = invariant holds, 1 = violation, 2 = usage or internal error.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const defaultAllowDir = "/etc/fips-invariant-check/allow.d"

var skipDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() { os.Exit(run()) }

func run() int {
	root := flag.String("root", "/", "filesystem root to scan (an extracted image rootfs, or / inside the image)")
	verbose := flag.Bool("v", false, "list every file that links or carries crypto, not just violations")
	strict := flag.Bool("strict", os.Getenv("FIPS_INVARIANT_STRICT") == "1",
		"production mode: honour NO exemptions, and fail if any allowlist file is present (default from FIPS_INVARIANT_STRICT=1)")
	var allowFiles multiFlag
	flag.Var(&allowFiles, "allow", "allowlist file (repeatable); files in "+defaultAllowDir+"/*.allow are always loaded")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: fips-invariant-check [-root DIR] [-allow FILE]... [-v] [-- PROBE CMD ARGS...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	rootAbs, err := filepath.Abs(*root)
	if err != nil {
		return fatal("bad -root: %v", err)
	}

	// Allowlists live inside the scanned image, so a downstream image inherits its base's
	// exemptions only if it keeps the base's files.
	defaults, _ := filepath.Glob(filepath.Join(rootAbs, defaultAllowDir, "*.allow"))
	var allow []*allowEntry
	var strictPresent []string
	failed := false
	if *strict {
		// Runtime images set FIPS_INVARIANT_STRICT=1 and every image built FROM them inherits it.
		// Exemptions exist for builder-only tooling; one that reached a production image (copied
		// from a builder stage, say) would be a silent hole, so its mere presence fails.
		if present := append(defaults, allowFiles...); len(present) > 0 {
			failed = true
			shown := make([]string, len(present))
			for i, p := range present {
				shown[i] = "/" + strings.TrimPrefix(strings.TrimPrefix(p, rootAbs), "/")
			}
			strictPresent = shown
		}
	} else {
		for _, name := range append(defaults, allowFiles...) {
			entries, err := loadAllowFile(name)
			if err != nil {
				return fatal("%v", err)
			}
			allow = append(allow, entries...)
		}
	}

	self, _ := os.Executable()
	selfReal, _ := filepath.EvalSymlinks(self)

	var reports []*fileReport
	walkErr := filepath.WalkDir(rootAbs, func(real string, d fs.DirEntry, err error) error {
		imagePath := "/" + strings.TrimPrefix(strings.TrimPrefix(real, rootAbs), "/")
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDirs[imagePath] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks are reported through their targets
		}
		if selfReal != "" && real == selfReal {
			return nil
		}
		info, err := d.Info()
		if err != nil || !isELFCandidate(d.Name(), info.Size()) {
			return nil
		}
		r, err := analyze(real, imagePath)
		if err == nil && r != nil {
			reports = append(reports, r)
		}
		return nil
	})
	if walkErr != nil {
		return fatal("walking %s: %v", rootAbs, walkErr)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Path < reports[j].Path })

	if *strict {
		fmt.Println("=== fips-invariant-check (strict: no exemptions) ===")
		if len(strictPresent) > 0 {
			fmt.Printf("FAIL  strict mode: exemption files are present, and production images may carry none: %s\n", strings.Join(strictPresent, ", "))
		}
	} else {
		fmt.Println("=== fips-invariant-check ===")
	}

	// Rule 1: one OpenSSL core.
	present := map[string][]string{} // major -> system core files present
	linkers := map[string][]string{} // major -> files that link it
	var coreAllowed []string
	for _, r := range reports {
		if major, ok := systemCoreMajor(r); ok {
			present[major] = append(present[major], r.Path)
			continue
		}
		if len(r.NeededCores) > 0 {
			// An exemption also takes a file out of the core count. The rule is deliberately
			// image-wide (stricter than the per-process hazard), so a build tool that runs as its
			// own process and never loads the application's libraries (e.g. a toolchain linking
			// another core) is exempted by name, with its reason printed.
			if e := findAllow(allow, r.Path); e != nil {
				coreAllowed = append(coreAllowed, fmt.Sprintf("ALLOWED %s links %s\n        exemption (%s): %s", r.Path, strings.Join(r.NeededCores, ", "), e.Source, e.Reason))
				continue
			}
		}
		for _, n := range r.NeededCores {
			major := coreSoname.FindStringSubmatch(n)[2]
			linkers[major] = appendUnique(linkers[major], r.Path)
		}
	}
	majors := sortedKeys(linkers)
	switch {
	case len(majors) > 1:
		failed = true
		fmt.Printf("FAIL  more than one OpenSSL core is linked: %s\n", strings.Join(prefixAll(majors, "libcrypto.so."), ", "))
		fmt.Println("      Two cores in one process cannot both initialise the FIPS provider; whichever loads second fails.")
		for _, m := range majors {
			fmt.Printf("      linked against .so.%s (%d files):\n", m, len(linkers[m]))
			for _, p := range head(linkers[m], 15) {
				fmt.Printf("        %s\n", p)
			}
		}
	case len(majors) == 1:
		fmt.Printf("ok    one OpenSSL core linked: libcrypto.so.%s (%d files)\n", majors[0], len(linkers[majors[0]]))
	default:
		fmt.Println("ok    no file links a system OpenSSL")
	}
	for _, a := range coreAllowed {
		fmt.Printf("      %s\n", a)
	}
	for _, m := range sortedKeys(present) {
		if len(linkers[m]) == 0 {
			fmt.Printf("note  OpenSSL core .so.%s is present but nothing links it (%s)\n", m, strings.Join(present[m], ", "))
		}
	}

	// Rule 2: no embedded crypto.
	var violations, allowed []string
	for _, r := range reports {
		reason := embeddedReason(r)
		if reason == "" {
			if *verbose && (len(r.NeededCores) > 0 || len(r.Markers) > 0) {
				fmt.Printf("info  %s links %v\n", r.Path, r.NeededCores)
			}
			continue
		}
		if e := findAllow(allow, r.Path); e != nil {
			allowed = append(allowed, fmt.Sprintf("ALLOWED %s: %s\n        exemption (%s): %s", r.Path, reason, e.Source, e.Reason))
			continue
		}
		violations = append(violations, fmt.Sprintf("%s: %s", r.Path, reason))
	}
	if len(violations) > 0 {
		failed = true
		fmt.Printf("FAIL  %d file(s) do crypto outside a validated FIPS module:\n", len(violations))
		for _, v := range violations {
			fmt.Printf("        %s\n", v)
		}
	} else {
		fmt.Println("ok    no embedded crypto outside the allowlist")
	}
	for _, a := range allowed {
		fmt.Printf("      %s\n", a)
	}
	for _, e := range allow {
		if !e.Used {
			fmt.Printf("warn  allowlist entry matched nothing, remove it if stale: %s (%s)\n", e.Pattern, e.Source)
		}
	}

	// Behavioural probe.
	probe := flag.Args()
	if len(probe) == 0 {
		if env := strings.Fields(os.Getenv("FIPS_INVARIANT_PROBE")); len(env) > 0 {
			probe = env
		}
	}
	if len(probe) > 0 {
		if rootAbs != "/" {
			fmt.Println("note  behavioural probe skipped: it can only run inside the image (-root is not /)")
		} else {
			fmt.Printf("=== behavioural probe: %s ===\n", strings.Join(probe, " "))
			cmd := exec.Command(probe[0], probe[1:]...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				failed = true
				fmt.Printf("FAIL  behavioural probe failed: %v\n", err)
			} else {
				fmt.Println("ok    behavioural probe passed")
			}
		}
	}

	if failed {
		fmt.Println("=== FIPS INVARIANT VIOLATED ===")
		return 1
	}
	fmt.Println("=== FIPS invariant holds ===")
	return 0
}

func fatal(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "fips-invariant-check: "+format+"\n", a...)
	return 2
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func prefixAll(s []string, p string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = p + v
	}
	return out
}

func head(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("... and %d more", len(s)-n))
}
