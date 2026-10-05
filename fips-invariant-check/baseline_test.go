package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testBaseline() *baseline {
	return &baseline{OpenSSLMajors: []string{"3", "4"}, ProviderName: "Chainguard FIPS Provider for OpenSSL",
		Providers: []providerBuild{{"3.4.0-r5", "5132"}, {"3.6.0-r4", "5523"}}}
}

func TestEmbeddedBaselineParses(t *testing.T) {
	b, err := parseBaseline(embeddedBaseline)
	if err != nil {
		t.Fatalf("the compiled-in baseline.env must parse: %v", err)
	}
	if len(b.OpenSSLMajors) == 0 || b.ProviderName == "" || len(b.Providers) == 0 {
		t.Fatalf("incomplete embedded baseline: %+v", b)
	}
}

func TestParseBaseline(t *testing.T) {
	b, err := parseBaseline("# c\nFIPS_OPENSSL_MAJORS=\"3 4\"\nFIPS_PROVIDER_NAME=\"X FIPS Provider for OpenSSL\"\nFIPS_PROVIDER_BUILDS=\"3.4.0-r5:5132 3.6.0-r4:5523\"\n")
	if err != nil || !slices.Equal(b.OpenSSLMajors, []string{"3", "4"}) || b.ProviderName != "X FIPS Provider for OpenSSL" || !slices.Equal(b.Providers, []providerBuild{{"3.4.0-r5", "5132"}, {"3.6.0-r4", "5523"}}) {
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
	for p, want := range map[string]bool{"/usr/lib/ossl-modules/fips.so": true, "/usr/lib/ossl-modules/fips-3.6.0.so": true,
		"/usr/lib/ossl-modules/legacy.so": false, "/usr/lib/ossl-modules/fips-x.so": false, "/usr/lib/ossl-modules/myfips.so": false} {
		if isProviderModule(p) != want {
			t.Errorf("isProviderModule(%s) = %v, want %v", p, !want, want)
		}
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

	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, good}, baseline: b}); failed || !strings.Contains(out, "ok    FIPS provider /usr/lib/ossl-modules/fips.so is an allowed build") {
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
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, good, second}, baseline: b}); !failed || !strings.Contains(out, "build 3.4.0-r5 is present twice") {
		t.Fatalf("two copies of one provider build must fail:\n%s", out)
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
	ok := "FIPS_OPENSSL_MAJORS=3\nFIPS_PROVIDER_NAME=n\nFIPS_PROVIDER_BUILDS=1.2.3-r4:1\n"
	for name, s := range map[string]string{
		"unknown key":      ok + "FIPS_OTHER=1\n",
		"duplicate key":    ok + "FIPS_OPENSSL_MAJORS=4\n",
		"non-numeric":      strings.Replace(ok, "=3", "=3 x", 1),
		"duplicate major":  strings.Replace(ok, "=3", "=\"3 3\"", 1),
		"empty majors":     strings.Replace(ok, "=3", "=\"\"", 1),
		"old key name":     strings.Replace(ok, "FIPS_OPENSSL_MAJORS", "FIPS_OPENSSL_MAJOR", 1),
		"old provider key": ok + "FIPS_PROVIDER_BUILDINFO=1.2.3-r4\n",
		"build no cmvp":    strings.Replace(ok, "1.2.3-r4:1", "1.2.3-r4", 1),
		"bad build":        strings.Replace(ok, "1.2.3-r4:1", "1.2.3:1", 1),
		"dup build":        strings.Replace(ok, "1.2.3-r4:1", "\"1.2.3-r4:1 1.2.3-r4:2\"", 1),
		"no builds":        strings.Replace(ok, "1.2.3-r4:1", "\"\"", 1),
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
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{"3.4.0-r5"}}

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
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, ssl3, good, multi}, baseline: b}); !failed || !strings.Contains(out, "build 3.4.0-r5 is present twice") {
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
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{"3.4.0-r5"}}
	legacy := &fileReport{Path: "/usr/lib/ossl-modules/legacy.so"}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, good, legacy}, baseline: b}); !failed || !strings.Contains(out, "legacy.so is a loadable OpenSSL module other than a FIPS provider") {
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
	good := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{"3.4.0-r5"}}

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

// Rules 2 and 3 agree on what the provider module is: a provider module outside the usual
// provider dirs is exempt from rule 2 only once rule 3 has matched it to an allowed build.
func TestProviderModuleRule2ExemptionNeedsAllowedIdentity(t *testing.T) {
	b := testBaseline()
	sys3 := &fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}
	moved := func(build string) *fileReport {
		return &fileReport{Path: "/opt/openssl/lib/ossl-modules/fips.so", Markers: []string{"OpenSSL 3.4.0"}, HasSource: true,
			ProviderNames: []string{b.ProviderName}, ProviderBuilds: []string{build}}
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, moved("3.4.0-r5")}, baseline: b}); failed {
		t.Fatalf("an allowed provider build at a non-standard path must pass:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys3, moved("3.4.0-r4")}, baseline: b}); !failed ||
		!strings.Contains(out, `build "3.4.0-r4"`) || !strings.Contains(out, "fips.so: carries a compiled-in crypto library") {
		t.Fatalf("an unrecognised one must fail rule 3 AND rule 2:\n%s", out)
	}
	if r := embeddedReason(moved("3.4.0-r5")); r == "" {
		t.Fatal("embeddedReason alone must not exempt a provider module outside providerDirs")
	}
}

// Allowed-provider list: DU's newest bases carry fips.so (#5132) and fips-3.6.0.so (#5523).
func TestAllowedProviderList(t *testing.T) {
	b := testBaseline()
	sys4 := &fileReport{Path: "/usr/lib/libcrypto.so.4", Soname: "libcrypto.so.4"}
	ssl4 := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libcrypto.so.4"}}
	mod := func(name string, builds ...string) *fileReport {
		return &fileReport{Path: "/usr/lib/ossl-modules/" + name, ProviderNames: []string{b.ProviderName}, ProviderBuilds: builds}
	}
	f34, f36 := mod("fips.so", "3.4.0-r5"), mod("fips-3.6.0.so", "3.6.0-r4")

	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, ssl4, f34, f36}, baseline: b, strict: true}); failed ||
		!strings.Contains(out, "fips-3.6.0.so is an allowed build") || !strings.Contains(out, "note  more than one FIPS provider build is present") {
		t.Fatalf("both allowed providers present must pass, with a note:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, ssl4, f36}, baseline: b}); failed {
		t.Fatalf("the #5523 provider alone must pass:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, ssl4, f34, mod("fips-3.6.0.so", "3.6.0-r3")}, baseline: b}); !failed || !strings.Contains(out, `build "3.6.0-r3"`) {
		t.Fatalf("a provider build not on the list must fail:\n%s", out)
	}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, ssl4, mod("fips.so", "3.4.0-r5", "3.6.0-r4")}, baseline: b}); !failed || !strings.Contains(out, "reports name") {
		t.Fatalf("a module carrying two builds is ambiguous and must fail:\n%s", out)
	}
	unknown := &fileReport{Path: "/usr/lib/ossl-modules/other.so"}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{sys4, ssl4, f34, f36, unknown}, baseline: b}); !failed || !strings.Contains(out, "other.so is a loadable OpenSSL module other than a FIPS provider") {
		t.Fatalf("an unknown module in a provider dir must fail:\n%s", out)
	}
}
