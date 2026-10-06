package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the 2026-10-05 22:29Z review of #22.

// New item 1: a non-FIPS provider or engine is judged wherever it sits, not only in the system
// provider dirs. A real legacy.so defines no crypto entry points and links the system core, so
// rule 2 does not catch it.
func TestEvaluateLoadableModuleAnywhere(t *testing.T) {
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	fips := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{"3.4.0-r5"}}
	for _, m := range []*fileReport{
		{Path: "/usr/local/lib/ossl-modules/legacy.so", NeededCores: []string{"libcrypto.so.3"}},
		{Path: "/opt/openssl/lib/ossl-modules/legacy.so", NeededCores: []string{"libcrypto.so.3"}},
		{Path: "/usr/local/lib/engines-3/padlock.so", NeededCores: []string{"libcrypto.so.3"}},
		{Path: "/opt/vendor/libmyprov.so", NeededCores: []string{"libcrypto.so.3"}, LoadableModule: true},
	} {
		if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, fips, m}, baseline: b, strict: true}); !failed || !strings.Contains(out, m.Path+" is a loadable OpenSSL module other than a FIPS provider") {
			t.Errorf("%s must fail as a loadable module:\n%s", m.Path, out)
		}
	}
	plain := &fileReport{Path: "/opt/vendor/libfoo.so", NeededCores: []string{"libcrypto.so.3"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, fips, plain}, baseline: b, strict: true}); failed {
		t.Fatalf("control: an ordinary library linking the core is not a module:\n%s", out)
	}
	moved := &fileReport{Path: "/opt/openssl/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{"3.4.0-r5"}, LoadableModule: true}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, moved}, baseline: b, strict: true}); failed {
		t.Fatalf("control: an allowed fips.so outside the system dirs is the provider, not another module:\n%s", out)
	}
}

// New item 3: analyze reports a read failure on the magic as an error (a directory fails the
// read with "is a directory"), not as "not ELF".
func TestAnalyzeMagicReadErrorIsAnError(t *testing.T) {
	r, err := analyze(t.TempDir(), "/usr/lib/x")
	if err == nil || r != nil || !strings.Contains(err.Error(), "reading ELF magic") {
		t.Fatalf("a failed magic read must be an error, got %+v %v", r, err)
	}
	short := filepath.Join(t.TempDir(), "s")
	os.WriteFile(short, []byte("\x7fE"), 0o644)
	if r, err := analyze(short, "/usr/lib/s"); r != nil || err != nil {
		t.Fatalf("control: a file shorter than the magic is simply not ELF, got %+v %v", r, err)
	}
}

// Non-blocking item 4: a builder stage on a non-FIPS base can exempt its core, and then needs no
// provider. Strict mode ignores the exemption.
func TestEvaluateBuilderExemptCoreNeedsNoProvider(t *testing.T) {
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	allow := []*allowEntry{{pattern: "/usr/lib/libcrypto.so.3", reason: "builder on a non-FIPS base", source: "t:1"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3}, baseline: b, allow: allow}); failed {
		t.Fatalf("non-strict: an exempted core alone must not require a provider:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3}, baseline: b}); !failed || !strings.Contains(out, "no FIPS provider module") {
		t.Fatalf("control: without the exemption it still fails:\n%s", out)
	}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{sys3}, baseline: b, allow: allow, strict: true}); !failed {
		t.Fatal("strict must ignore the exemption")
	}
}

// Non-blocking item 7: unbalanced quotes in baseline.env are rejected.
func TestParseBaselineUnbalancedQuotes(t *testing.T) {
	ok := "FIPS_OPENSSL_MAJORS=\"3 4\"\nFIPS_PROVIDER_NAME=n\nFIPS_PROVIDER_BUILDS=1.2.3-r4:1\n"
	if _, err := parseBaseline(ok); err != nil {
		t.Fatalf("control: balanced quotes parse, got %v", err)
	}
	for _, bad := range []string{
		strings.Replace(ok, `"3 4"`, `"3 4`, 1),
		strings.Replace(ok, `"3 4"`, `3 4"`, 1),
		strings.Replace(ok, `1.2.3-r4:1`, `1.2.3-r4:1"`, 1),
		strings.Replace(ok, `"3 4"`, `"`, 1),
	} {
		if _, err := parseBaseline(bad); err == nil || !strings.Contains(err.Error(), "unbalanced quotes") {
			t.Errorf("must reject unbalanced quotes, got %v for:\n%s", err, bad)
		}
	}
}

// New item 2: run() itself applies the compiled-in baseline (rule 3 on a real image layout), and
// -baseline overrides it in non-strict mode. Real ELF files built with gcc; Linux only.
func TestRunEnforcesBaseline(t *testing.T) {
	gcc, _ := gccAndObjcopy(t)
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "core.c"), []byte("int core_marker(void){return 3;}\n"), 0o644)
	mkRoot := func(ver string) string {
		root := fixtureRoot(t)
		os.MkdirAll(filepath.Join(root, "usr/lib/ossl-modules"), 0o755)
		provSrc := filepath.Join(src, "prov-"+ver+".c")
		os.WriteFile(provSrc, []byte("__attribute__((used)) const char provname[] = \"Chainguard FIPS Provider for OpenSSL\";\n__attribute__((used)) const char provbuild[] = \""+ver+"\";\nint OSSL_provider_init(void){return 1;}\n"), 0o644)
		build(t, gcc, "-shared", "-fPIC", "-Wl,-soname,libcrypto.so.3", "-o", filepath.Join(root, "usr/lib/libcrypto.so.3"), filepath.Join(src, "core.c"))
		build(t, gcc, "-shared", "-fPIC", "-o", filepath.Join(root, "usr/lib/ossl-modules/fips.so"), provSrc)
		return root
	}
	bad := mkRoot("3.4.0-r4")
	if code, out := runWith(t, nil, "-strict", "-root", bad); code != 1 || !strings.Contains(out, `build "3.4.0-r4"`) {
		t.Fatalf("run() must apply the compiled-in baseline: a disallowed provider build fails, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-strict", "-root", mkRoot("3.4.0-r5")); code != 0 || !strings.Contains(out, "is an allowed build") {
		t.Fatalf("control: an allowed provider build passes, got %d:\n%s", code, out)
	}
	override := filepath.Join(t.TempDir(), "b.env")
	os.WriteFile(override, []byte("FIPS_OPENSSL_MAJORS=3\nFIPS_PROVIDER_NAME=\"Chainguard FIPS Provider for OpenSSL\"\nFIPS_PROVIDER_BUILDS=3.4.0-r4:5132\n"), 0o644)
	if code, out := runWith(t, nil, "-baseline", override, "-root", bad); code != 0 {
		t.Fatalf("-baseline overrides the compiled-in baseline in non-strict mode, got %d:\n%s", code, out)
	}
}
