// fips-invariant-check enforces the VE fleet's FIPS crypto invariant on a container image's
// filesystem, from inside the image (it is a static binary, so it runs in distroless images).
//
// The invariant:
//
//  1. ONE OpenSSL core. Every binary and library that links OpenSSL links the same major
//     (libcrypto.so.N). Two cores in one process cannot both initialise the single FIPS provider
//     module: whichever loads second fails ("could not generate nonce" from libpq, 2026-10-02).
//  2. NO unvalidated crypto. No binary carries its own crypto library (a precompiled gem or wheel
//     that statically links OpenSSL/BoringSSL/AWS-LC, a vendored libcrypto, Mozilla NSS, Heimdal
//     and other independent stacks). Those never touch the FIPS provider and do not fail: they
//     silently run non-validated crypto. Go binaries are the one sanctioned second module, on the
//     two routes ruled valid on 2026-10-02 (INF-377); see goFIPSMode in scan.go.
//
// A gate that passes what it never looked at is worse than no gate, so anything the scan cannot
// inspect (an unreadable directory or file, a Go binary whose build info cannot be parsed, a root
// that does not exist or contains no ELF files) fails the run instead of being skipped.
//
// Structural checks cannot prove behaviour, so the image can also register a behavioural probe
// (trailing `-- CMD ARGS`, or the FIPS_INVARIANT_PROBE env var; time limit
// FIPS_INVARIANT_PROBE_TIMEOUT, default 10m) that this tool runs after the scan: a language-specific script that loads the runtime's own crypto, then the native
// libraries, and asserts FIPS behaviour (MD5 refused, SHA-256 and RAND working).
//
// Exit status: 0 = invariant holds, 1 = violation, 2 = usage or internal error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const defaultAllowDir = "/etc/fips-invariant-check/allow.d"

// inImageRoot is the -root that means "this tool is running inside the image being checked", the
// only place a behavioural probe can run. A variable only so tests can exercise run()'s probe path.
var inImageRoot = "/"

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, getenv func(string) string, out, errOut io.Writer) int {
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(errOut, "fips-invariant-check: "+format+"\n", a...)
		return 2
	}

	strictDefault, err := parseStrictEnv(getenv("FIPS_INVARIANT_STRICT"))
	if err != nil {
		return fatal("%v", err)
	}
	fl := flag.NewFlagSet("fips-invariant-check", flag.ContinueOnError)
	fl.SetOutput(errOut)
	root := fl.String("root", "/", "filesystem root to scan (an extracted image rootfs, or / inside the image)")
	verbose := fl.Bool("v", false, "also list every file that passes while linking or naming crypto")
	strict := fl.Bool("strict", strictDefault,
		"production mode: honour NO exemptions, and fail if any allowlist file is present (default from FIPS_INVARIANT_STRICT)")
	var allowFiles multiFlag
	fl.Var(&allowFiles, "allow", "extra allowlist file (repeatable); "+defaultAllowDir+"/*.allow inside -root is always looked for (applied normally; its mere presence fails -strict)")
	fl.Usage = func() {
		fmt.Fprintf(errOut, "usage: fips-invariant-check [-root DIR] [-allow FILE]... [-strict] [-v] [-- PROBE CMD ARGS...]\n")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}

	rootAbs, err := resolveRoot(*root)
	if err != nil {
		return fatal("%v", err)
	}
	// An explicitly requested probe that cannot run is an error, not a skipped check. One
	// inherited through FIPS_INVARIANT_PROBE is only noted when scanning from outside the image.
	probe := probeCommand(fl.Args(), getenv)
	if len(fl.Args()) > 0 && rootAbs != inImageRoot {
		return fatal("a probe given as -- CMD can only run inside the image (-root /); -root is %s", rootAbs)
	}
	probeTimeout, err := parseProbeTimeout(getenv("FIPS_INVARIANT_PROBE_TIMEOUT"))
	if err != nil {
		return fatal("%v", err)
	}

	// Allowlists live inside the scanned image, so a downstream image inherits its base's
	// exemptions only if it keeps the base's files. Glob only fails on a malformed pattern, and a
	// -root containing glob metacharacters would make it silently match nothing, so read the
	// directory instead.
	allowPaths, err := allowFilesIn(rootAbs, defaultAllowDir)
	if err != nil {
		return fatal("%v", err)
	}
	allowPaths = append(allowPaths, allowFiles...)

	in := evalInput{strict: *strict, verbose: *verbose}
	if *strict {
		// Runtime images set FIPS_INVARIANT_STRICT and every image built FROM them inherits it.
		// Exemptions exist for builder-only tooling; one that reached a production image (copied
		// from a builder stage, say) would be a silent hole, so its mere presence fails.
		for _, p := range allowPaths {
			in.strictAllowFiles = append(in.strictAllowFiles, imagePath(rootAbs, p))
		}
	} else {
		for _, name := range allowPaths {
			entries, err := loadAllowFile(name)
			if err != nil {
				return fatal("%v", err)
			}
			in.allow = append(in.allow, entries...)
		}
	}

	self, _ := os.Executable()
	selfReal, _ := filepath.EvalSymlinks(self)
	in.reports, in.unscanned, err = scan(rootAbs, selfReal)
	if err != nil {
		return fatal("%v", err)
	}

	failed := evaluate(out, in)

	if probeFailed := applyProbe(out, rootAbs, probe, probeTimeout); probeFailed {
		failed = true
	}

	if failed {
		fmt.Fprintln(out, "=== FIPS INVARIANT VIOLATED ===")
		return 1
	}
	fmt.Fprintln(out, "=== FIPS invariant holds ===")
	return 0
}

// parseStrictEnv reads FIPS_INVARIANT_STRICT. Anything it does not recognise ("enabled", "2") is
// an error, not "off": silently selecting non-strict mode would apply exemptions in exactly the
// production images strict mode protects.
func parseStrictEnv(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "", "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("FIPS_INVARIANT_STRICT=%q is not a recognised value (use 1/true/yes/on or 0/false/no/off)", v)
}

// resolveRoot returns the absolute, symlink-resolved scan root, which must be an existing
// directory: WalkDir on a missing root reports nothing, which would read as a clean image.
func resolveRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("bad -root %q: %v", root, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("-root %q: %v", root, err)
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("-root %q: %v", root, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("-root %q is not a directory", root)
	}
	return real, nil
}

// allowFilesIn lists the *.allow files in the in-image directory dir under root. A symlink is
// resolved INSIDE the image (an absolute target is relative to root, not to the host), and a
// dangling link is an error: from outside the image, following it on the host would read the
// wrong directory, or silently find none.
func allowFilesIn(root, dir string) ([]string, error) {
	real, err := resolveInRoot(root, dir)
	if err != nil {
		return nil, err
	}
	if real == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return nil, fmt.Errorf("reading allowlist directory %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".allow") {
			out = append(out, filepath.Join(real, e.Name()))
		}
	}
	return out, nil
}

// resolveInRoot returns the host path of in-image path p under root, following symlinks with
// root as "/". It returns "" when p does not exist.
func resolveInRoot(root, p string) (string, error) {
	cur := path.Clean(p)
	for hops := 0; hops < 16; hops++ {
		host := filepath.Join(root, filepath.FromSlash(cur))
		st, err := os.Lstat(host)
		if errors.Is(err, os.ErrNotExist) {
			if hops == 0 {
				return "", nil
			}
			return "", fmt.Errorf("allowlist directory %s is a dangling symlink (-> %s)", p, cur)
		}
		if err != nil {
			return "", fmt.Errorf("allowlist directory %s: %v", p, err)
		}
		if st.Mode()&os.ModeSymlink == 0 {
			return host, nil
		}
		target, err := os.Readlink(host)
		if err != nil {
			return "", fmt.Errorf("allowlist directory %s: %v", p, err)
		}
		if path.IsAbs(target) {
			cur = path.Clean(target)
		} else {
			cur = path.Clean(path.Join(path.Dir(cur), target))
		}
	}
	return "", fmt.Errorf("allowlist directory %s: too many symlinks", p)
}

type evalInput struct {
	reports          []*fileReport
	unscanned        []string // "<path>: <why>", each one a failure
	allow            []*allowEntry
	strict           bool
	strictAllowFiles []string // in strict mode: allowlist files present in the image (each a failure)
	verbose          bool
}

// evaluate applies both rules to the scan results, writes the report, and returns whether the
// invariant is violated. It does no I/O beyond writing to out, so it is unit-tested directly.
func evaluate(out io.Writer, in evalInput) (failed bool) {
	// Strict mode applies no exemptions whatever the input carries (run() also never loads them).
	allow := in.allow
	if in.strict {
		allow = nil
	}
	if in.strict {
		fmt.Fprintln(out, "=== fips-invariant-check (strict: no exemptions) ===")
		if len(in.strictAllowFiles) > 0 {
			failed = true
			fmt.Fprintf(out, "FAIL  strict mode: exemption files are present, and production images may carry none: %s\n", strings.Join(in.strictAllowFiles, ", "))
		}
	} else {
		fmt.Fprintln(out, "=== fips-invariant-check ===")
	}

	if len(in.unscanned) > 0 {
		failed = true
		fmt.Fprintf(out, "FAIL  %d path(s) could not be inspected, so the invariant cannot be shown to hold:\n", len(in.unscanned))
		for _, u := range head(in.unscanned, 25) {
			fmt.Fprintf(out, "        %s\n", u)
		}
	}

	// Rule 1: one OpenSSL core.
	present := map[string][]string{} // major -> system core files present
	linkers := map[string][]string{} // major -> files that link it
	var coreAllowed []string
	for _, r := range in.reports {
		if major, ok := systemCoreMajor(r); ok {
			present[major] = append(present[major], r.Path)
			continue
		}
		if len(r.NeededCores) == 0 {
			continue
		}
		// An exemption also takes a file out of the core count. The rule is deliberately image-wide
		// (stricter than the per-process hazard), so a build tool that runs as its own process and
		// never loads the application's libraries (e.g. a toolchain linking another core) is
		// exempted by name, with its reason printed.
		if e := findAllow(allow, r.Path); e != nil {
			coreAllowed = append(coreAllowed, fmt.Sprintf("ALLOWED %s links %s\n        exemption (%s): %s", r.Path, strings.Join(r.NeededCores, ", "), e.source, e.reason))
			continue
		}
		for _, n := range r.NeededCores {
			major := coreSoname.FindStringSubmatch(n)[2]
			if !slices.Contains(linkers[major], r.Path) {
				linkers[major] = append(linkers[major], r.Path)
			}
		}
	}
	majors := slices.Sorted(maps.Keys(linkers))
	switch {
	case len(majors) > 1:
		failed = true
		names := make([]string, len(majors))
		for i, m := range majors {
			names[i] = "libcrypto.so." + m
		}
		fmt.Fprintf(out, "FAIL  more than one OpenSSL core is linked: %s\n", strings.Join(names, ", "))
		fmt.Fprintln(out, "      Two cores in one process cannot both initialise the FIPS provider; whichever loads second fails.")
		for _, m := range majors {
			fmt.Fprintf(out, "      linked against .so.%s (%d files):\n", m, len(linkers[m]))
			for _, p := range head(linkers[m], 15) {
				fmt.Fprintf(out, "        %s\n", p)
			}
		}
	case len(majors) == 1:
		fmt.Fprintf(out, "ok    one OpenSSL core linked: libcrypto.so.%s (%d files)\n", majors[0], len(linkers[majors[0]]))
	default:
		fmt.Fprintln(out, "ok    no file links a system OpenSSL")
	}
	for _, a := range coreAllowed {
		fmt.Fprintf(out, "      %s\n", a)
	}
	for _, m := range slices.Sorted(maps.Keys(present)) {
		if len(linkers[m]) == 0 {
			fmt.Fprintf(out, "note  OpenSSL core .so.%s is present but nothing links it (%s)\n", m, strings.Join(present[m], ", "))
		}
	}

	// Rule 2: no crypto outside a validated module.
	var violations, allowed []string
	for _, r := range in.reports {
		reason := embeddedReason(r)
		if reason == "" {
			if in.verbose && (len(r.NeededCores) > 0 || len(r.Markers) > 0 || r.IsGo) {
				fmt.Fprintf(out, "info  %s passes (links %v, markers %v, go=%v)\n", r.Path, r.NeededCores, r.Markers, r.IsGo)
			}
			continue
		}
		if e := findAllow(allow, r.Path); e != nil {
			allowed = append(allowed, fmt.Sprintf("ALLOWED %s: %s\n        exemption (%s): %s", r.Path, reason, e.source, e.reason))
			continue
		}
		violations = append(violations, fmt.Sprintf("%s: %s", r.Path, reason))
	}
	if len(violations) > 0 {
		failed = true
		fmt.Fprintf(out, "FAIL  %d file(s) do crypto outside a validated FIPS module:\n", len(violations))
		for _, v := range violations {
			fmt.Fprintf(out, "        %s\n", v)
		}
	} else {
		fmt.Fprintln(out, "ok    no crypto outside a validated FIPS module, other than listed exemptions")
	}
	for _, a := range allowed {
		fmt.Fprintf(out, "      %s\n", a)
	}
	for _, e := range allow {
		if !e.used {
			fmt.Fprintf(out, "warn  allowlist entry matched nothing, remove it if stale: %s (%s)\n", e.pattern, e.source)
		}
	}
	return failed
}

// probeCommand is the probe to run: trailing `-- CMD ARGS` win over FIPS_INVARIANT_PROBE.
func probeCommand(args []string, getenv func(string) string) []string {
	if len(args) > 0 {
		return args
	}
	return strings.Fields(getenv("FIPS_INVARIANT_PROBE"))
}

// applyProbe runs the probe when the scan is of this image (-root /) and reports whether it
// failed. From outside the image an (inherited) probe can only be noted as not run.
func applyProbe(out io.Writer, rootAbs string, probe []string, timeout time.Duration) (failed bool) {
	if len(probe) == 0 {
		return false
	}
	if rootAbs != inImageRoot {
		fmt.Fprintln(out, "note  behavioural probe not run: it can only run inside the image (-root is not /)")
		return false
	}
	fmt.Fprintf(out, "=== behavioural probe: %s ===\n", strings.Join(probe, " "))
	if err := runProbe(probe, out, timeout); err != nil {
		fmt.Fprintf(out, "FAIL  behavioural probe failed: %v\n", err)
		return true
	}
	fmt.Fprintln(out, "ok    behavioural probe passed")
	return false
}

const defaultProbeTimeout = 10 * time.Minute

func parseProbeTimeout(v string) (time.Duration, error) {
	if strings.TrimSpace(v) == "" {
		return defaultProbeTimeout, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("FIPS_INVARIANT_PROBE_TIMEOUT=%q is not a positive duration (e.g. 10m)", v)
	}
	return d, nil
}

// runProbe runs the image's behavioural probe. Failure to start, a non-zero exit, or running past
// the timeout all fail: a hung probe must not hang the image build.
func runProbe(probe []string, out io.Writer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, probe[0], probe[1:]...)
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("timed out after %s", timeout)
	}
	return err
}

// imagePath maps a host path under root to the path it has inside the image.
func imagePath(root, real string) string {
	rel := strings.TrimPrefix(real, root)
	return "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
}

func head(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("... and %d more", len(s)-n))
}
