package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// Tests for the 2026-10-05 review of #22 (fail-open paths and minor items).

// Finding 1: a file is judged by its ELF magic, never skipped by its name.
func TestRunPyNamedELFIsScanned(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	data, _ := os.ReadFile(withCrypto)
	root := fixtureRoot(t)
	os.WriteFile(filepath.Join(root, "usr/bin/evil.py"), data, 0o755)
	if code, out := runWith(t, nil, "-root", root); code != 1 || !strings.Contains(out, "/usr/bin/evil.py") {
		t.Fatalf("a crypto ELF named *.py must be judged, got %d:\n%s", code, out)
	}
	clean := fixtureRoot(t)
	os.WriteFile(filepath.Join(clean, "usr/bin/tool.py"), []byte(strings.Repeat("print('a perfectly ordinary script')\n", 5)), 0o644)
	if code, out := runWith(t, nil, "-root", clean); code != 0 {
		t.Fatalf("a real Python script must still pass, got %d:\n%s", code, out)
	}
	if isELFCandidate(51) || !isELFCandidate(52) {
		t.Fatal("the size floor must admit a 52-byte ELF32 header")
	}
}

// Finding 3: a short file is not ELF, but any other read error surfaces (the file is then
// reported as uninspected, not silently dropped).
func TestHasELFMagic(t *testing.T) {
	for name, c := range map[string]struct {
		r      func() *bytes.Reader
		wantOK bool
	}{
		"elf":   {func() *bytes.Reader { return bytes.NewReader([]byte("\x7fELF\x02")) }, true},
		"text":  {func() *bytes.Reader { return bytes.NewReader([]byte("#!/bin/sh")) }, false},
		"short": {func() *bytes.Reader { return bytes.NewReader([]byte("\x7fE")) }, false},
		"empty": {func() *bytes.Reader { return bytes.NewReader(nil) }, false},
	} {
		if ok, err := hasELFMagic(c.r()); err != nil || ok != c.wantOK {
			t.Errorf("%s: got %v %v, want %v nil", name, ok, err, c.wantOK)
		}
	}
	eio := errors.New("input/output error")
	if ok, err := hasELFMagic(iotest.ErrReader(eio)); ok || !errors.Is(err, eio) {
		t.Fatalf("a read error must be returned, got %v %v", ok, err)
	}
}

// Finding 2: a Go binary carrying a stripped static C crypto library (version text plus its own
// source paths, no system core linked) fails like any other binary. Control: the same Go binary
// without that payload passes.
func TestRunGoBinaryWithStrippedCCryptoFails(t *testing.T) {
	_, nocrypto := goFixtures(t)
	payload := []byte("\x00OpenSSL 3.5.1  1 Jul 2026\x00crypto/evp/digest.c\x00ssl/ssl_lib.c\x00")
	bad := copyWith(t, nocrypto, func(b []byte) []byte { return append(b, payload...) })
	root := fixtureRoot(t)
	data, _ := os.ReadFile(bad)
	os.WriteFile(filepath.Join(root, "usr/bin/kafka-client"), data, 0o755)
	if code, out := runWith(t, nil, "-root", root); code != 1 || !strings.Contains(out, "/usr/bin/kafka-client: carries a compiled-in crypto library") {
		t.Fatalf("a Go binary with a stripped C crypto copy must fail, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-root", fixtureRoot(t)); code != 0 {
		t.Fatalf("control: the same Go binary without the payload must pass, got %d:\n%s", code, out)
	}
}

// Finding 4: an inherited FIPS_INVARIANT_STRICT is a floor.
func TestRunStrictEnvIsAFloor(t *testing.T) {
	root := fixtureRoot(t)
	dir := filepath.Join(root, "etc/fips-invariant-check/allow.d")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "b.allow"), []byte("/usr/bin/tool builder only\n"), 0o644)
	env := map[string]string{"FIPS_INVARIANT_STRICT": "1"}
	if code, out := runWith(t, env, "-strict=false", "-root", root); code != 2 || !strings.Contains(out, "cannot override FIPS_INVARIANT_STRICT") {
		t.Fatalf("-strict=false must not override the env, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, env, "-root", root); code != 1 || !strings.Contains(out, "exemption files are present") {
		t.Fatalf("the env alone must select strict mode, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-strict", "-root", root); code != 1 || !strings.Contains(out, "exemption files are present") {
		t.Fatalf("the flag alone must select strict mode, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-root", root); code != 0 {
		t.Fatalf("control: with neither, the allow file applies, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "0"}, "-strict=false", "-root", root); code != 0 {
		t.Fatalf("control: -strict=false with a non-strict env is fine, got %d:\n%s", code, out)
	}
}

// Minor 7b: a non-regular *.allow counts as present in strict mode and is an error otherwise.
func TestRunNonRegularAllowEntry(t *testing.T) {
	root := fixtureRoot(t)
	os.MkdirAll(filepath.Join(root, "etc/fips-invariant-check/allow.d/x.allow"), 0o755)
	if code, out := runWith(t, nil, "-strict", "-root", root); code != 1 || !strings.Contains(out, "/etc/fips-invariant-check/allow.d/x.allow") {
		t.Fatalf("strict: a directory named *.allow must count as present, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-root", root); code != 2 || !strings.Contains(out, "not a regular file") {
		t.Fatalf("non-strict: it must be an error, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-strict", "-root", fixtureRoot(t)); code != 0 {
		t.Fatalf("control: strict with no allow entries passes, got %d:\n%s", code, out)
	}
}

// Minor 7c: provider/engine dirs follow systemLibDirs, so lib64 and multiarch layouts count.
func TestProviderDirsCoverSystemLibDirs(t *testing.T) {
	defines := []string{"RAND_bytes"}
	for _, p := range []string{"/usr/lib64/engines-3/afalg.so", "/usr/lib/x86_64-linux-gnu/engines-3/x.so", "/usr/lib/aarch64-linux-gnu/ossl-modules/legacy.so", "/lib/ossl-modules/legacy.so"} {
		if r := embeddedReason(&fileReport{Path: p, Defines: defines}); r != "" {
			t.Errorf("%s is a provider/engine dir and must be exempt from rule 2, got %q", p, r)
		}
	}
	for _, p := range []string{"/opt/lib/engines-3/x.so", "/usr/lib/engines-3x/x.so", "/usr/local/lib/ossl-modules/x.so"} {
		if r := embeddedReason(&fileReport{Path: p, Defines: defines}); r == "" {
			t.Errorf("%s is not a system provider dir and must fail", p)
		}
	}
}

// Finding 9: a statically linked independent stack is caught by the entry points it DEFINES;
// a file that only imports (calls) them is not. Real ELF files, Linux only.
func TestAnalyzeStaticIndependentStackSymbols(t *testing.T) {
	gcc, _ := gccAndObjcopy(t)
	dir := t.TempDir()
	def := filepath.Join(dir, "def.c")
	use := filepath.Join(dir, "use.c")
	os.WriteFile(def, []byte("int mbedtls_ctr_drbg_seed(void*a,void*b,void*c,const unsigned char*d,unsigned long e){return 0;}\nint sodium_init(void){return 0;}\n"), 0o644)
	os.WriteFile(use, []byte("int sodium_init(void);\nint go(void){return sodium_init();}\n"), 0o644)
	libDef := filepath.Join(dir, "libapp.so")
	libUse := filepath.Join(dir, "libuse.so")
	build(t, gcc, "-shared", "-fPIC", "-o", libDef, def)
	build(t, gcc, "-shared", "-fPIC", "-o", libUse, use)
	r, err := analyze(libDef, "/opt/app/lib/libapp.so")
	if err != nil || !strings.Contains(embeddedReason(r), "mbedtls_ctr_drbg_seed (Mbed TLS)") || !strings.Contains(embeddedReason(r), "sodium_init (libsodium)") {
		t.Fatalf("defining independent-stack entry points must fail, got %v %q", err, embeddedReason(r))
	}
	r, err = analyze(libUse, "/opt/app/lib/libuse.so")
	if err != nil || embeddedReason(r) != "" {
		t.Fatalf("only importing one must pass, got %v %q", err, embeddedReason(r))
	}
}
