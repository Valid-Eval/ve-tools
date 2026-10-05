package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testBaseline() *baseline {
	return &baseline{OpenSSLMajors: []string{"3", "4"}, ProviderName: "Chainguard FIPS Provider for OpenSSL", ProviderBuildinfo: "3.4.0-r5", CMVP: "5132"}
}

func TestEmbeddedBaselineParses(t *testing.T) {
	b, err := parseBaseline(embeddedBaseline)
	if err != nil {
		t.Fatalf("the compiled-in baseline.env must parse: %v", err)
	}
	if len(b.OpenSSLMajors) == 0 || b.ProviderName == "" || b.ProviderBuildinfo == "" || b.CMVP == "" {
		t.Fatalf("incomplete embedded baseline: %+v", b)
	}
}

func TestParseBaseline(t *testing.T) {
	b, err := parseBaseline("# c\nFIPS_OPENSSL_MAJORS=\"3 4\"\nFIPS_PROVIDER_NAME=\"X FIPS Provider for OpenSSL\"\nFIPS_PROVIDER_BUILDINFO=3.6.0-r4\nFIPS_PROVIDER_CMVP=5523\n")
	if err != nil || !slices.Equal(b.OpenSSLMajors, []string{"3", "4"}) || b.ProviderName != "X FIPS Provider for OpenSSL" || b.ProviderBuildinfo != "3.6.0-r4" || b.CMVP != "5523" {
		t.Fatalf("got %+v, %v", b, err)
	}
	if _, err := parseBaseline("FIPS_OPENSSL_MAJORS=3\n"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("a baseline missing keys must be an error, got %v", err)
	}
	if _, err := parseBaseline("not a pair\n"); err == nil {
		t.Fatal("a line without = must be an error")
	}
}

func TestProviderIdentityReadsCompiledStrings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fips.so")
	body := "\x7fELF junk\x00Chainguard FIPS Provider for OpenSSL\x00more\x003.4.0-r5\x00 3.4.0 \x00not-3.4.0-r5x\x00"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	names, builds, err := providerIdentity(p)
	if err != nil || !slices.Equal(names, []string{"Chainguard FIPS Provider for OpenSSL"}) || !slices.Equal(builds, []string{"3.4.0-r5"}) {
		t.Fatalf("names %v builds %v err %v", names, builds, err)
	}
	if !isProviderModule("/usr/lib/ossl-modules/fips.so") || isProviderModule("/usr/lib/ossl-modules/legacy.so") {
		t.Fatal("isProviderModule must accept fips.so and nothing else")
	}
}

// Rule 1 against the baseline, and rule 3.
func TestEvaluateFleetBaseline(t *testing.T) {
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3", Defines: []string{"RAND_bytes"}}
	ssl3 := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libssl.so.3", "libcrypto.so.3"}}
	ssl4 := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libssl.so.4", "libcrypto.so.4"}}
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{"Chainguard FIPS Provider for OpenSSL"}, ProviderBuilds: []string{"3.4.0-r5"}}
	r4 := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{"Chainguard FIPS Provider for OpenSSL"}, ProviderBuilds: []string{"3.4.0-r4"}}
	second := &fileReport{Path: "/usr/lib64/ossl-modules/fips.so", ProviderNames: good.ProviderNames, ProviderBuilds: good.ProviderBuilds}
	b := testBaseline()

	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, good}, baseline: b}); failed || !strings.Contains(out, "ok    FIPS provider matches the fleet baseline") {
		t.Fatalf("baseline core and provider must pass:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{ssl4, good}, baseline: b}); failed {
		t.Fatalf("one core on another accepted major (4) must pass:\n%s", out)
	}
	only3 := testBaseline()
	only3.OpenSSLMajors = []string{"3"}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{ssl4, good}, baseline: only3}); !failed || !strings.Contains(out, "libcrypto.so.4 is not a major the fleet accepts (3;") {
		t.Fatalf("one core on a major outside the set must fail:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3}, baseline: b}); !failed || !strings.Contains(out, "no FIPS provider module") {
		t.Fatalf("OpenSSL without a provider must fail:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, good, second}, baseline: b}); !failed || !strings.Contains(out, "more than one FIPS provider module") {
		t.Fatalf("two providers must fail:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, r4}, baseline: b}); !failed || !strings.Contains(out, `build "3.4.0-r4"`) {
		t.Fatalf("a provider build other than the baseline's must fail:\n%s", out)
	}
	goOnly := &fileReport{Path: "/usr/local/bin/s3-upload", IsGo: true}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{goOnly}, baseline: b}); failed || strings.Contains(out, "FIPS provider") {
		t.Fatalf("an image with no OpenSSL at all needs no provider:\n%s", out)
	}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{ssl4}}); failed {
		t.Fatal("without a baseline (nil) rule 1 stays self-consistency only")
	}
}

func TestParseBaselineRejectsAmbiguity(t *testing.T) {
	ok := "FIPS_OPENSSL_MAJORS=3\nFIPS_PROVIDER_NAME=n\nFIPS_PROVIDER_BUILDINFO=b\nFIPS_PROVIDER_CMVP=1\n"
	for name, s := range map[string]string{
		"unknown key":     ok + "FIPS_OTHER=1\n",
		"duplicate key":   ok + "FIPS_OPENSSL_MAJORS=4\n",
		"non-numeric":     strings.Replace(ok, "=3", "=3 x", 1),
		"duplicate major": strings.Replace(ok, "=3", "=\"3 3\"", 1),
		"empty majors":    strings.Replace(ok, "=3", "=\"\"", 1),
		"old key name":    strings.Replace(ok, "FIPS_OPENSSL_MAJORS", "FIPS_OPENSSL_MAJOR", 1),
	} {
		if _, err := parseBaseline(s); err == nil {
			t.Errorf("%s must be an error", name)
		}
	}
}

// Review findings: unlinked other-major cores, providers outside the usual dirs, name mismatch,
// and rule 3 triggered by a present core or a lone fips.so.
func TestEvaluateBaselineHardening(t *testing.T) {
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	sys4 := &fileReport{Path: "/usr/lib/libcrypto.so.4", Soname: "libcrypto.so.4"}
	ssl3 := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libcrypto.so.3"}}
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{b.ProviderBuildinfo}}

	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl3, good}, baseline: b}); !failed || !strings.Contains(out, "/usr/lib/libcrypto.so.4 is OpenSSL core .so.4, but this image's core is .so.3") {
		t.Fatalf("an unlinked core of another major must fail:\n%s", out)
	}
	allow := []*allowEntry{{pattern: "/usr/lib/libcrypto.so.4", reason: "builder only", source: "t:1"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl3, good}, baseline: b, allow: allow}); failed || !strings.Contains(out, "ALLOWED /usr/lib/libcrypto.so.4 is OpenSSL core .so.4, not this image's .so.3") {
		t.Fatalf("a non-strict image may exempt it by path:\n%s", out)
	}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl3, good}, baseline: b, allow: allow, strict: true}); !failed {
		t.Fatal("strict must ignore that exemption")
	}
	multi := &fileReport{Path: "/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so", ProviderNames: good.ProviderNames, ProviderBuilds: good.ProviderBuilds}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, good, multi}, baseline: b}); !failed || !strings.Contains(out, "more than one FIPS provider module") {
		t.Fatalf("a second fips.so anywhere must count:\n%s", out)
	}
	wrongName := &fileReport{Path: good.Path, ProviderNames: []string{"Other FIPS Provider for OpenSSL"}, ProviderBuilds: good.ProviderBuilds}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, wrongName}, baseline: b}); !failed {
		t.Fatal("a provider name other than the baseline's must fail")
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3}, baseline: b}); !failed || !strings.Contains(out, "no FIPS provider module") {
		t.Fatalf("a present but unlinked core still needs the provider:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{wrongName}, baseline: b}); !failed || !strings.Contains(out, "reports name") {
		t.Fatalf("a lone fips.so with no OpenSSL is still checked:\n%s", out)
	}
}

func TestRunBaselineFlag(t *testing.T) {
	var out, errOut strings.Builder
	env := func(string) string { return "" }
	if code := run([]string{"-strict", "-baseline", "/nonexistent", "-root", t.TempDir()}, env, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "cannot be used with -strict") {
		t.Fatalf("strict must refuse -baseline: code %d, %s", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"-baseline", "/nonexistent", "-root", t.TempDir()}, env, &out, &errOut); code != 2 {
		t.Fatalf("an unreadable -baseline must be fatal: code %d, %s", code, errOut.String())
	}
	bad := filepath.Join(t.TempDir(), "b.env")
	os.WriteFile(bad, []byte("FIPS_OPENSSL_MAJORS=3\n"), 0o644)
	errOut.Reset()
	if code := run([]string{"-baseline", bad, "-root", t.TempDir()}, env, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "missing") {
		t.Fatalf("an incomplete -baseline must be fatal: code %d, %s", code, errOut.String())
	}
}

func TestOtherProviderModulesAndAdjacentStrings(t *testing.T) {
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{b.ProviderBuildinfo}}
	legacy := &fileReport{Path: "/usr/lib/ossl-modules/legacy.so"}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, good, legacy}, baseline: b}); !failed || !strings.Contains(out, "legacy.so is a loadable OpenSSL module other than the FIPS provider") {
		t.Fatalf("legacy.so must fail:\n%s", out)
	}
	allow := []*allowEntry{{pattern: "/usr/lib/ossl-modules/legacy.so", reason: "builder only", source: "t:1"}}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{sys3, good, legacy}, baseline: b, allow: allow}); failed {
		t.Fatal("a non-strict image may exempt it")
	}
	if !isProviderModule("/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so") || !inDir("/usr/lib/aarch64-linux-gnu/ossl-modules/fips.so", providerDirs) {
		t.Fatal("multiarch provider dirs must count")
	}
	p := filepath.Join(t.TempDir(), "fips.so")
	os.WriteFile(p, []byte("\x003.4.0-r5\x003.4.0-r4\x00Chainguard FIPS Provider for OpenSSL\x00"), 0o644)
	if _, builds, _ := providerIdentity(p); !slices.Equal(builds, []string{"3.4.0-r4", "3.4.0-r5"}) {
		t.Fatalf("adjacent build strings must both be read, got %v", builds)
	}
}

// The other-major rule is judged against the image's own core, not a fleet-wide one.
func TestEvaluateOwnMajor(t *testing.T) {
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	sys4 := &fileReport{Path: "/usr/lib/libcrypto.so.4", Soname: "libcrypto.so.4"}
	sys5 := &fileReport{Path: "/usr/lib/libcrypto.so.5", Soname: "libcrypto.so.5"}
	ssl4 := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libcrypto.so.4"}}
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{b.ProviderBuildinfo}}

	// An OpenSSL-4-only image (DU python-fips v3.14.8) passes; the same image carrying an unused
	// .so.3 fails, now that 3 is the other major.
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, ssl4, good}, baseline: b}); failed {
		t.Fatalf("a 4-only image must pass:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl4, good}, baseline: b}); !failed || !strings.Contains(out, "/usr/lib/libcrypto.so.3 is OpenSSL core .so.3, but this image's core is .so.4") {
		t.Fatalf("an unlinked .so.3 beside a linked .so.4 must fail:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, ssl4, good}, baseline: b}); strings.Contains(out, "/usr/lib/libcrypto.so.4 is OpenSSL core") {
		t.Fatalf("the linked core itself must not be reported (failed=%v):\n%s", failed, out)
	}

	// Nothing links a core: one present core is the image's own; two present majors fail.
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, good}, baseline: b}); failed {
		t.Fatalf("one unlinked accepted core must pass:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, good}, baseline: b}); !failed || !strings.Contains(out, "more than one major are present (.so.3, .so.4) and nothing links any of them") {
		t.Fatalf("two unlinked majors must fail:\n%s", out)
	}
	allow := []*allowEntry{{pattern: "/usr/lib/libcrypto.so.3", reason: "builder only", source: "t:1"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, good}, baseline: b, allow: allow}); failed || !strings.Contains(out, "ALLOWED /usr/lib/libcrypto.so.3 is OpenSSL core .so.3, not this image's .so.4") {
		t.Fatalf("a non-strict image may exempt one of them, leaving the other as its core:\n%s", out)
	}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{sys3, sys4, good}, baseline: b, allow: allow, strict: true}); !failed {
		t.Fatal("strict must ignore that exemption")
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys5, good}, baseline: b}); !failed || !strings.Contains(out, "libcrypto.so.5 is not a major the fleet accepts") {
		t.Fatalf("a lone unlinked core outside the set must fail:\n%s", out)
	}
}

// Rules 2 and 3 agree on what the provider module is: a fips.so outside the usual provider dirs
// is not "embedded crypto" (rule 3 holds it to the baseline identity), while any other file with
// the same content still is.
func TestProviderModuleExemptFromRule2Anywhere(t *testing.T) {
	stripped := func(p string) *fileReport {
		return &fileReport{Path: p, Markers: []string{"OpenSSL 3.4.0"}, HasSource: true}
	}
	if r := embeddedReason(stripped("/opt/openssl/lib/ossl-modules/fips.so")); r != "" {
		t.Fatalf("a fips.so outside providerDirs must not fail rule 2, got %q", r)
	}
	if r := embeddedReason(stripped("/opt/openssl/lib/ossl-modules/libfoo.so")); r == "" {
		t.Fatal("the same content under another name must still fail rule 2")
	}
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	moved := stripped("/opt/openssl/lib/ossl-modules/fips.so")
	moved.ProviderNames, moved.ProviderBuilds = []string{b.ProviderName}, []string{b.ProviderBuildinfo}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, moved}, baseline: b}); failed {
		t.Fatalf("a baseline provider at a non-standard path must pass:\n%s", out)
	}
	moved.ProviderBuilds = []string{"3.4.0-r4"}
	if failed, _ := evalOut(t, evalInput{reports: []*fileReport{sys3, moved}, baseline: b}); !failed {
		t.Fatal("and must still fail rule 3 when its build is not the baseline's")
	}
}
