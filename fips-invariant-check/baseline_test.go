package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testBaseline() *baseline {
	return &baseline{OpenSSLMajor: "3", ProviderName: "Chainguard FIPS Provider for OpenSSL", ProviderBuildinfo: "3.4.0-r5", CMVP: "5132"}
}

func TestEmbeddedBaselineParses(t *testing.T) {
	b, err := parseBaseline(embeddedBaseline)
	if err != nil {
		t.Fatalf("the compiled-in baseline.env must parse: %v", err)
	}
	if b.OpenSSLMajor == "" || b.ProviderName == "" || b.ProviderBuildinfo == "" || b.CMVP == "" {
		t.Fatalf("incomplete embedded baseline: %+v", b)
	}
}

func TestParseBaseline(t *testing.T) {
	b, err := parseBaseline("# c\nFIPS_OPENSSL_MAJOR=4\nFIPS_PROVIDER_NAME=\"X FIPS Provider for OpenSSL\"\nFIPS_PROVIDER_BUILDINFO=3.6.0-r4\nFIPS_PROVIDER_CMVP=5523\n")
	if err != nil || b.OpenSSLMajor != "4" || b.ProviderName != "X FIPS Provider for OpenSSL" || b.ProviderBuildinfo != "3.6.0-r4" || b.CMVP != "5523" {
		t.Fatalf("got %+v, %v", b, err)
	}
	if _, err := parseBaseline("FIPS_OPENSSL_MAJOR=3\n"); err == nil || !strings.Contains(err.Error(), "missing") {
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
	if !isProviderModule("/usr/lib/ossl-modules/fips.so") || isProviderModule("/opt/x/fips.so") || isProviderModule("/usr/lib/ossl-modules/legacy.so") {
		t.Fatal("isProviderModule must accept only fips.so in a provider dir")
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
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{ssl4, good}, baseline: b}); !failed || !strings.Contains(out, "is not the fleet baseline's libcrypto.so.3") {
		t.Fatalf("one core on the wrong major must fail:\n%s", out)
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
