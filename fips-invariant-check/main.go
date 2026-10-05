// fips-invariant-check enforces the VE fleet's FIPS crypto invariant on a container image's
// filesystem, from inside the image (it is a static binary, so it runs in distroless images).
//
// The invariant:
//
//  1. ONE OpenSSL core. Every binary and library that links OpenSSL links the same soname version
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
// that does not exist or has nothing to inspect) fails the run instead of being skipped.
//
// Structural checks cannot prove behaviour, so the image can also register a behavioural probe
// (trailing `-- CMD ARGS`, or the FIPS_INVARIANT_PROBE env var; time limit
// FIPS_INVARIANT_PROBE_TIMEOUT, default 10m) that this tool runs after the scan: a
// language-specific script that loads the runtime's own crypto, then the native libraries, and
// asserts FIPS behaviour (MD5 refused, SHA-256 and RAND working).
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
		"production mode: honour NO exemptions, and fail if any allowlist file is present (on whenever FIPS_INVARIANT_STRICT is; cannot be turned off by the flag)")
	baselineFile := fl.String("baseline", "", "fleet baseline file (KEY=VALUE); default: the baseline.env compiled into this binary")
	var allowFiles multiFlag
	fl.Var(&allowFiles, "allow", "extra allowlist file (repeatable); "+defaultAllowDir+"/*.allow inside -root is always looked for (applied normally; its mere presence fails -strict)")
	fl.Usage = func() {
		fmt.Fprintf(errOut, "usage: fips-invariant-check [-root DIR] [-allow FILE]... [-strict] [-baseline FILE] [-v] [-- PROBE CMD ARGS...]\n")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	// An inherited FIPS_INVARIANT_STRICT is a floor: a downstream RUN cannot opt out with
	// -strict=false, or an exemption copied into a production image would apply again.
	if strictDefault && !*strict {
		return fatal("-strict=false cannot override FIPS_INVARIANT_STRICT=%s: production images stay strict", getenv("FIPS_INVARIANT_STRICT"))
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
	allowPaths, oddAllow, err := allowFilesIn(rootAbs, defaultAllowDir)
	if err != nil {
		return fatal("%v", err)
	}
	if len(oddAllow) > 0 && !*strict {
		return fatal("allowlist entry is not a regular file: %s", strings.Join(oddAllow, ", "))
	}
	allowPaths = append(allowPaths, allowFiles...)

	baselineText := embeddedBaseline
	if *baselineFile != "" && *strict {
		// A production image is held to the fleet baseline compiled into the checker; letting it
		// name its own would let one image drift while staying strict-green.
		return fatal("-baseline cannot be used with -strict: production images are checked against the compiled-in fleet baseline")
	}
	if *baselineFile != "" {
		b, err := os.ReadFile(*baselineFile)
		if err != nil {
			return fatal("%v", err)
		}
		baselineText = string(b)
	}
	bl, err := parseBaseline(baselineText)
	if err != nil {
		return fatal("%v", err)
	}

	in := evalInput{strict: *strict, verbose: *verbose}
	in.baseline = bl
	if *strict {
		// Runtime images set FIPS_INVARIANT_STRICT and every image built FROM them inherits it.
		// Exemptions exist for builder-only tooling; one that reached a production image (copied
		// from a builder stage, say) would be a silent hole, so its mere presence fails.
		for _, p := range allowPaths {
			in.strictAllowFiles = append(in.strictAllowFiles, imagePath(rootAbs, p))
		}
		// A non-regular *.allow (directory, FIFO) grants nothing, but under fail-closed it is
		// still an exemption file present in a production image.
		in.strictAllowFiles = append(in.strictAllowFiles, oddAllow...)
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

	if applyProbe(out, rootAbs, probe, probeTimeout) {
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

// allowFilesIn lists the *.allow files in the in-image directory dir under root, and separately the
// in-image paths of *.allow entries that are not regular files (never opened: a FIFO would block). The directory and
// each file are resolved INSIDE the image (an absolute symlink target is relative to root, not to
// the host), and a dangling link is an error: following it on the host would read the wrong
// file, or silently find none.
func allowFilesIn(root, dir string) (out, odd []string, err error) {
	real, err := resolveInRoot(root, dir)
	if err != nil {
		return nil, nil, fmt.Errorf("allowlist directory: %v", err)
	}
	if real == "" {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return nil, nil, fmt.Errorf("reading allowlist directory %s: %v", dir, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".allow") {
			continue
		}
		// Each entry is resolved in the image too: a packaged drop-in is often a symlink
		// (x.allow -> /opt/vendor/x.allow), which the host would otherwise follow.
		host, err := resolveInRoot(root, path.Join(dir, e.Name()))
		if err != nil {
			return nil, nil, fmt.Errorf("allowlist file: %v", err)
		}
		st, err := os.Stat(host)
		if err != nil {
			return nil, nil, fmt.Errorf("allowlist file %s: %v", path.Join(dir, e.Name()), err)
		}
		if st.Mode().IsRegular() {
			out = append(out, host)
		} else {
			odd = append(odd, path.Join(dir, e.Name()))
		}
	}
	return out, odd, nil
}

// resolveInRoot returns the host path of in-image path p under root, following symlinks with
// root as "/". Every component is resolved here, not by the host kernel: an absolute symlink in a
// parent directory (/etc -> /usr/etc) must also stay inside the image. It returns "" when p does
// not exist, and an error when p itself is a symlink that leads nowhere.
func resolveInRoot(root, p string) (string, error) {
	pending := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	resolved := "/"
	viaFinalLink := false // p's last component was a symlink: a missing target is dangling
	for hops := 0; len(pending) > 0; {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, c)
		host := filepath.Join(root, filepath.FromSlash(next))
		st, err := os.Lstat(host)
		if errors.Is(err, os.ErrNotExist) {
			if viaFinalLink {
				return "", fmt.Errorf("%s is a dangling symlink (%s does not exist)", p, next)
			}
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("%s: %v", p, err)
		}
		if st.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if hops++; hops > 40 {
			return "", fmt.Errorf("%s: too many levels of symlinks", p)
		}
		target, err := os.Readlink(host)
		if err != nil {
			return "", fmt.Errorf("%s: %v", p, err)
		}
		if len(pending) == 0 {
			viaFinalLink = true
		}
		if path.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), pending...)
	}
	return filepath.Join(root, filepath.FromSlash(resolved)), nil
}

type evalInput struct {
	reports          []*fileReport
	unscanned        []string // "<path>: <why>", each one a failure
	allow            []*allowEntry
	strict           bool
	strictAllowFiles []string // in strict mode: allowlist files present in the image (each a failure)
	verbose          bool
	baseline         *baseline // fleet OpenSSL majors and FIPS provider (nil: not checked)
}

// evaluate applies both rules to the scan results, writes the report, and returns whether the
// invariant is violated. It does no I/O beyond writing to out, so it is unit-tested directly.
func evaluate(out io.Writer, in evalInput) (failed bool) {
	// Strict mode applies no exemptions whatever the input carries (run() also never loads them).
	allow := in.allow
	if in.strict {
		allow = nil
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
	present := map[string][]string{} // soname version -> system core files present
	linkers := map[string][]string{} // soname version -> files that link it
	var coreAllowed []string
	for _, r := range in.reports {
		if ver, ok := systemCoreVersion(r); ok {
			present[ver] = append(present[ver], r.Path)
			continue
		}
		if len(r.NeededCores) == 0 {
			continue
		}
		// An exemption also takes a file out of the core count. The rule is deliberately image-wide
		// (stricter than the per-process hazard), so a build tool that runs as its own process and
		// never loads the application's libraries (e.g. a toolchain linking another core) is
		// exempted by name, with its reason printed.
		if e := matchAllow(allow, r.Path); e != nil {
			coreAllowed = append(coreAllowed, fmt.Sprintf("ALLOWED %s links %s\n        exemption (%s): %s", r.Path, strings.Join(r.NeededCores, ", "), e.source, e.reason))
			continue
		}
		for _, n := range r.NeededCores {
			ver := coreSoname.FindStringSubmatch(n)[2]
			if !slices.Contains(linkers[ver], r.Path) {
				linkers[ver] = append(linkers[ver], r.Path)
			}
		}
	}
	versions := slices.Sorted(maps.Keys(linkers))
	switch {
	case len(versions) > 1:
		failed = true
		names := make([]string, len(versions))
		for i, v := range versions {
			names[i] = "libcrypto.so." + v
		}
		fmt.Fprintf(out, "FAIL  more than one OpenSSL core is linked: %s\n", strings.Join(names, ", "))
		fmt.Fprintln(out, "      Two cores in one process cannot both initialise the FIPS provider; whichever loads second fails.")
		for _, v := range versions {
			fmt.Fprintf(out, "      linked against .so.%s (%d files):\n", v, len(linkers[v]))
			for _, p := range head(linkers[v], 15) {
				fmt.Fprintf(out, "        %s\n", p)
			}
		}
	case len(versions) == 1:
		fmt.Fprintf(out, "ok    one OpenSSL core linked: libcrypto.so.%s (%d files)\n", versions[0], len(linkers[versions[0]]))
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

	// Rule 1, against the baseline. The image's own major is the one core it links or, if nothing
	// links one, the one core present. That major must be one the fleet accepts, and a core of
	// any other major fails even unlinked: the next package or dlopen that links it makes a second
	// core in the process (the 2026-10-02 outage). Only a non-strict (builder) image may exempt
	// such a file by path. With two linked cores the check above has already failed.
	if in.baseline != nil && len(versions) <= 1 {
		allowed := strings.Join(in.baseline.OpenSSLMajors, " ")
		own := ""
		if len(versions) == 1 {
			own = versions[0]
		} else {
			var kept []string // majors present with at least one file not exempted
			for _, m := range slices.Sorted(maps.Keys(present)) {
				if slices.ContainsFunc(present[m], func(p string) bool { return matchAllow(allow, p) == nil }) {
					kept = append(kept, m)
				}
			}
			switch {
			case len(kept) == 1:
				own = kept[0]
			case len(kept) > 1:
				failed = true
				fmt.Fprintf(out, "FAIL  OpenSSL cores of more than one major are present (.so.%s) and nothing links any of them, so the image has no single core; keep one\n", strings.Join(kept, ", .so."))
			}
			if own == "" { // no single own major: still show every exemption used on a present core
				for _, m := range slices.Sorted(maps.Keys(present)) {
					for _, p := range present[m] {
						if e := matchAllow(allow, p); e != nil {
							fmt.Fprintf(out, "      ALLOWED %s is OpenSSL core .so.%s\n        exemption (%s): %s\n", p, m, e.source, e.reason)
						}
					}
				}
			}
		}
		if own != "" && !slices.Contains(in.baseline.OpenSSLMajors, own) {
			failed = true
			fmt.Fprintf(out, "FAIL  the image's OpenSSL core libcrypto.so.%s is not a major the fleet accepts (%s; baseline.env FIPS_OPENSSL_MAJORS)\n", own, allowed)
		}
		if own != "" {
			for _, m := range slices.Sorted(maps.Keys(present)) {
				if m == own {
					continue
				}
				for _, p := range present[m] {
					if e := matchAllow(allow, p); e != nil {
						fmt.Fprintf(out, "      ALLOWED %s is OpenSSL core .so.%s, not this image's .so.%s\n        exemption (%s): %s\n", p, m, own, e.source, e.reason)
						continue
					}
					failed = true
					fmt.Fprintf(out, "FAIL  %s is OpenSSL core .so.%s, but this image's core is .so.%s; remove it from the image\n", p, m, own)
				}
			}
		}
	}

	// Rule 3: every FIPS provider module is an allowed build. Checked whenever the image carries
	// a system OpenSSL or any provider module. This automates the comparison the Security Policy's
	// Crypto Officer check makes (module name and build info), against the fleet baseline.
	var modules []*fileReport
	verified := map[string]bool{} // provider modules whose identity is an allowed build (rule 2 skips them)
	for _, r := range in.reports {
		if isProviderModule(r.Path) {
			modules = append(modules, r)
		}
	}
	// Any other module in a provider dir (legacy.so, an engine, a provider under another name)
	// is crypto outside a validated module that the core can load on request; rule 2 skips the
	// provider dirs, so it is judged here. Only a non-strict (builder) image may exempt it.
	if in.baseline != nil {
		for _, r := range in.reports {
			if isProviderModule(r.Path) || !inDir(r.Path, providerDirs) {
				continue
			}
			if e := matchAllow(allow, r.Path); e != nil {
				fmt.Fprintf(out, "      ALLOWED %s is a loadable OpenSSL module other than a FIPS provider\n        exemption (%s): %s\n", r.Path, e.source, e.reason)
				continue
			}
			failed = true
			fmt.Fprintf(out, "FAIL  %s is a loadable OpenSSL module other than a FIPS provider (crypto outside a validated module); remove it from the image\n", r.Path)
		}
	}
	if in.baseline != nil && (len(present) > 0 || len(versions) > 0 || len(modules) > 0) {
		want := in.baseline.providersString()
		if len(modules) == 0 {
			failed = true
			fmt.Fprintf(out, "FAIL  no FIPS provider module (fips.so or fips-<version>.so) anywhere in the image; the fleet baseline allows %s\n", want)
		}
		seen := map[string]string{} // allowed build -> first module path carrying it
		for _, m := range modules {
			p, ok := in.baseline.providerFor(m)
			switch {
			case !ok:
				failed = true
				fmt.Fprintf(out, "FAIL  FIPS provider %s reports name %q and build %q; the fleet baseline allows %s\n",
					m.Path, strings.Join(m.ProviderNames, ","), strings.Join(m.ProviderBuilds, ","), want)
			case seen[p.Buildinfo] != "":
				failed = true
				fmt.Fprintf(out, "FAIL  FIPS provider build %s is present twice (%s, %s); keep one\n", p.Buildinfo, seen[p.Buildinfo], m.Path)
			default:
				seen[p.Buildinfo] = m.Path
				verified[m.Path] = true
				fmt.Fprintf(out, "ok    FIPS provider %s is an allowed build: %q build %s (CMVP #%s)\n", m.Path, in.baseline.ProviderName, p.Buildinfo, p.CMVP)
			}
		}
		if len(seen) > 1 {
			fmt.Fprintln(out, "note  more than one FIPS provider build is present; which one is active depends on the runtime OpenSSL config, which this check does not evaluate")
		}
	}

	// Rule 2: no crypto outside a validated module.
	var violations, allowed []string
	for _, r := range in.reports {
		reason := embeddedReason(r)
		if verified[r.Path] {
			reason = "" // an allowed FIPS provider build (rule 3), wherever OPENSSL_MODULES points
		}
		if reason == "" {
			if in.verbose && (len(r.NeededCores) > 0 || len(r.Markers) > 0 || r.IsGo) {
				fmt.Fprintf(out, "info  %s passes (links %v, markers %v, go=%v)\n", r.Path, r.NeededCores, r.Markers, r.IsGo)
			}
			continue
		}
		if e := matchAllow(allow, r.Path); e != nil {
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
		fmt.Fprintln(out, "ok    no native crypto outside a validated FIPS module, other than listed exemptions")
	}
	for _, a := range allowed {
		fmt.Fprintf(out, "      %s\n", a)
	}
	var noCode []string
	for _, r := range in.reports {
		if r.NoCode {
			noCode = append(noCode, r.Path)
		}
	}
	if len(noCode) > 0 {
		fmt.Fprintf(out, "note  %d file(s) hold no runnable code (separate debug info); their linked libraries count, their own symbols are not judged: %s\n", len(noCode), strings.Join(head(noCode, 5), ", "))
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
	t := strings.TrimSpace(v)
	if t == "" {
		return defaultProbeTimeout, nil
	}
	d, err := time.ParseDuration(t)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("FIPS_INVARIANT_PROBE_TIMEOUT=%q is not a positive duration (e.g. 10m)", v)
	}
	return d, nil
}

// runProbe runs the image's behavioural probe. Failure to start, a non-zero exit, or running past
// the timeout all fail: a hung probe must not hang the image build. On Unix the probe runs in its
// own process group and the whole group is killed at the deadline, so a child it started (a shell
// probe's subprocess) cannot keep the output pipe open; WaitDelay bounds the wait regardless.
func runProbe(probe []string, out io.Writer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, probe[0], probe[1:]...)
	cmd.Stdout, cmd.Stderr = out, out
	killProcessGroupOnCancel(cmd)
	cmd.WaitDelay = 5 * time.Second
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
