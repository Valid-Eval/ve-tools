package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func evalOut(t *testing.T, in evalInput) (bool, string) {
	t.Helper()
	var b bytes.Buffer
	failed := evaluate(&b, in)
	return failed, b.String()
}

// Rule 1 is the check behind the 2026-10-02 outage (libpq on OpenSSL 4 next to CPython on 3).
func TestEvaluateOneCore(t *testing.T) {
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3", Defines: []string{"RAND_bytes"}}
	sys4 := &fileReport{Path: "/usr/lib/libcrypto.so.4", Soname: "libcrypto.so.4", Defines: []string{"RAND_bytes"}}
	ssl := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libssl.so.3", "libcrypto.so.3"}}
	pq4 := &fileReport{Path: "/usr/lib/libpq.so.5.17", NeededCores: []string{"libssl.so.4", "libcrypto.so.4"}}
	pq3 := &fileReport{Path: "/usr/lib/libpq.so.5.17", NeededCores: []string{"libssl.so.3", "libcrypto.so.3"}}

	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl, pq4}}); !failed || !strings.Contains(out, "more than one OpenSSL core is linked: libcrypto.so.3, libcrypto.so.4") || !strings.Contains(out, "/usr/lib/libpq.so.5.17") {
		t.Fatalf("mixed cores must fail and name the files:\n%s", out)
	}
	failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl, pq3}})
	if failed || !strings.Contains(out, "one OpenSSL core linked: libcrypto.so.3") || !strings.Contains(out, "note  OpenSSL core .so.4 is present but nothing links it") {
		t.Fatalf("a single linked core must pass, with the unused core noted:\n%s", out)
	}

	// An exemption takes a separate-process build tool out of the count; nothing else.
	cargo := &fileReport{Path: "/usr/bin/cargo.real", NeededCores: []string{"libssl.so.4", "libcrypto.so.4"}}
	allow := []*allowEntry{{pattern: "/usr/bin/cargo.real", reason: "separate process", source: "t:1"}}
	failed, out = evalOut(t, evalInput{reports: []*fileReport{ssl, pq3, cargo}, allow: allow})
	if failed || !strings.Contains(out, "ALLOWED /usr/bin/cargo.real links libssl.so.4, libcrypto.so.4") {
		t.Fatalf("an exempted tool must leave the core count, with its reason printed:\n%s", out)
	}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{ssl, pq3, cargo}}); !failed {
		t.Fatal("without the exemption the same tool must fail rule 1")
	}
	unrelated := []*allowEntry{{pattern: "/usr/bin/other", reason: "r", source: "t:1"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{ssl, pq4}, allow: unrelated}); !failed || !strings.Contains(out, "matched nothing") {
		t.Fatalf("an exemption for another path must not hide a mixed core, and must be reported stale:\n%s", out)
	}
}

func TestEvaluateEmbeddedAndExemptions(t *testing.T) {
	wheel := &fileReport{Path: "/opt/appenv/cryptography/_rust.abi3.so", Defines: []string{"EVP_DigestInit_ex"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{wheel}}); !failed || !strings.Contains(out, "do crypto outside a validated FIPS module") {
		t.Fatalf("embedded crypto must fail:\n%s", out)
	}
	allow := []*allowEntry{{pattern: "/opt/appenv/**", reason: "builder-only", source: "t:1"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{wheel}, allow: allow}); failed || !strings.Contains(out, "ALLOWED /opt/appenv/cryptography/_rust.abi3.so") {
		t.Fatalf("an exempted finding must pass and be printed as ALLOWED:\n%s", out)
	}
}

func TestEvaluateStrictAndUnscanned(t *testing.T) {
	clean := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libcrypto.so.3"}}
	failed, out := evalOut(t, evalInput{reports: []*fileReport{clean}, strict: true, strictAllowFiles: []string{"/etc/fips-invariant-check/allow.d/builder.allow"}})
	if !failed || !strings.Contains(out, "strict mode: exemption files are present") || strings.Count(out, "=== fips-invariant-check") != 1 {
		t.Fatalf("strict mode must fail on an allowlist file's presence, under a single header:\n%s", out)
	}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{clean}, strict: true}); failed {
		t.Fatal("strict mode with no allowlist files and a clean image must pass")
	}
	failed, out = evalOut(t, evalInput{reports: []*fileReport{clean}, unscanned: []string{"/opt/secret: permission denied"}})
	if !failed || !strings.Contains(out, "could not be inspected") || !strings.Contains(out, "/opt/secret") {
		t.Fatalf("a path that could not be inspected must fail the run:\n%s", out)
	}
}

func TestParseStrictEnv(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on", " 1 "} {
		if got, err := parseStrictEnv(v); err != nil || !got {
			t.Errorf("%q should select strict mode (got %v, %v)", v, got, err)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off"} {
		if got, err := parseStrictEnv(v); err != nil || got {
			t.Errorf("%q should select non-strict mode (got %v, %v)", v, got, err)
		}
	}
	for _, v := range []string{"enabled", "2", "strict"} {
		if _, err := parseStrictEnv(v); err == nil {
			t.Errorf("%q is unrecognised and must be an error, not silently non-strict", v)
		}
	}
}

func TestProbe(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if got := probeCommand(nil, env("python3 /probe.py")); strings.Join(got, " ") != "python3 /probe.py" {
		t.Errorf("FIPS_INVARIANT_PROBE should be used when no args are given, got %v", got)
	}
	if got := probeCommand([]string{"x"}, env("python3 /probe.py")); strings.Join(got, " ") != "x" {
		t.Errorf("trailing args should win over FIPS_INVARIANT_PROBE, got %v", got)
	}
	if runtime.GOOS == "windows" {
		t.Skip("true/false commands")
	}
	var b bytes.Buffer
	if err := runProbe([]string{"true"}, &b); err != nil {
		t.Errorf("a passing probe must not error: %v", err)
	}
	if err := runProbe([]string{"false"}, &b); err == nil {
		t.Error("a probe that exits non-zero must fail the run")
	}
	if err := runProbe([]string{"/nonexistent/probe"}, &b); err == nil {
		t.Error("a probe that cannot start must fail the run")
	}
}

// End-to-end through run(): these need a real ELF file to scan, so they run on Linux, where the
// test binary itself is one.
func linuxRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs an ELF test binary (Linux)")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/tool"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func runWith(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, func(k string) string { return env[k] }, &out, &errOut)
	return code, out.String() + errOut.String()
}

func TestRunRootErrors(t *testing.T) {
	if code, out := runWith(t, nil, "-root", filepath.Join(t.TempDir(), "missing")); code != 2 {
		t.Errorf("a missing root must be an error (exit 2), got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-root", t.TempDir()); code != 2 || !strings.Contains(out, "no ELF files") {
		t.Errorf("a root with no ELF files must be an error (exit 2), got %d:\n%s", code, out)
	}
	if code, _ := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "maybe"}, "-root", t.TempDir()); code != 2 {
		t.Errorf("an unrecognised FIPS_INVARIANT_STRICT must be an error (exit 2), got %d", code)
	}
}

func TestRunStrictAndAllowFiles(t *testing.T) {
	root := linuxRoot(t)
	dir := filepath.Join(root, "etc/fips-invariant-check/allow.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.allow"), []byte("/usr/bin/tool builder-only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The test binary may or may not link std crypto (testing's fuzz support uses sha256); either
	// way, non-strict mode reads the allow file: the binary is ALLOWED, or the entry is unused.
	if code, out := runWith(t, nil, "-root", root); code != 0 || !(strings.Contains(out, "ALLOWED /usr/bin/tool") || strings.Contains(out, "matched nothing")) {
		t.Fatalf("non-strict: the allow file must be read and applied, got %d:\n%s", code, out)
	}
	code, out := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "true"}, "-root", root)
	if code != 1 || !strings.Contains(out, "/etc/fips-invariant-check/allow.d/b.allow") {
		t.Fatalf("strict (via env): an allow file in the image must fail the run and be named by its in-image path, got %d:\n%s", code, out)
	}
	if code, _ := runWith(t, nil, "-strict", "-root", root); code != 1 {
		t.Fatalf("strict (via flag) must also fail, got %d", code)
	}
}

func TestRunUnreadableDirFails(t *testing.T) {
	root := linuxRoot(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	locked := filepath.Join(root, "opt/locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	code, out := runWith(t, nil, "-root", root)
	if code != 1 || !strings.Contains(out, "could not be inspected") || !strings.Contains(out, "/opt/locked") {
		t.Fatalf("an unreadable directory must fail the run and be named, got %d:\n%s", code, out)
	}
}

// analyze on the runner's real OpenSSL: the system libcrypto DEFINES RAND_bytes; libssl only
// IMPORTS it (undefined), links libcrypto, and must therefore not count as defining crypto.
func TestAnalyzeRealLibraries(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux ELF libraries")
	}
	find := func(name string) string {
		for _, d := range []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib", "/lib"} {
			if _, err := os.Stat(filepath.Join(d, name)); err == nil {
				return filepath.Join(d, name)
			}
		}
		t.Skipf("%s not found on this runner", name)
		return ""
	}
	crypto, ssl := find("libcrypto.so.3"), find("libssl.so.3")
	rc, err := analyze(crypto, crypto)
	if err != nil || rc == nil {
		t.Fatalf("analyze libcrypto: %v", err)
	}
	if rc.Soname != "libcrypto.so.3" || !strings.Contains(strings.Join(rc.Defines, ","), "RAND_bytes") {
		t.Errorf("libcrypto: want soname libcrypto.so.3 defining RAND_bytes, got %+v", rc)
	}
	rs, err := analyze(ssl, ssl)
	if err != nil || rs == nil {
		t.Fatalf("analyze libssl: %v", err)
	}
	if strings.Join(rs.NeededCores, ",") != "libcrypto.so.3" {
		t.Errorf("libssl should link exactly libcrypto.so.3, got %v", rs.NeededCores)
	}
	if len(rs.Defines) != 0 {
		t.Errorf("libssl only imports the crypto entry points; got defines %v", rs.Defines)
	}
	self, _ := os.Executable()
	rg, err := analyze(self, "/usr/bin/tool")
	if err != nil || rg == nil || !rg.IsGo {
		t.Fatalf("the test binary should be recognised as Go: %+v %v", rg, err)
	}
}
