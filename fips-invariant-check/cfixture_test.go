package main

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A real program linked statically against the system's libcrypto.a and stripped: OpenSSL compiled
// in, no symbol table, no DT_NEEDED. Only the byte scan (version text plus OpenSSL's own source
// paths) can see it. The same program linked dynamically is the control and must pass.
//
// It needs a Linux C compiler, pkg-config and OpenSSL's static library with its own static
// dependencies (Debian/Ubuntu: libssl-dev pkg-config zlib1g-dev libzstd-dev). Without them the test
// skips, unless FIC_REQUIRE_C_FIXTURES is set (CI sets it; any value but "0"), where a skip would
// hide that this case never ran. A missing strip or a failed dynamic link always fails.
const opensslProgram = `#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
int main(void) {
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;
	if (!EVP_Digest("x", 1, md, &n, EVP_sha256(), NULL)) return 1;
	printf("%s %02x\n", OpenSSL_version(OPENSSL_VERSION), md[0]);
	return 0;
}
`

func cFixtures(t *testing.T) (static, dynamic string) {
	t.Helper()
	unavailable := func(why string) {
		if v := os.Getenv("FIC_REQUIRE_C_FIXTURES"); v != "" && v != "0" {
			t.Fatalf("FIC_REQUIRE_C_FIXTURES=%s but the C fixture cannot be built: %s", v, why)
		}
		t.Skip(why)
	}
	if runtime.GOOS != "linux" {
		unavailable("needs a Linux C toolchain (host is " + runtime.GOOS + ")")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		unavailable("no cc")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.c")
	if err := os.WriteFile(src, []byte(opensslProgram), 0o644); err != nil {
		t.Fatal(err)
	}
	static, dynamic = filepath.Join(dir, "static"), filepath.Join(dir, "dynamic")
	// libcrypto.a's own dependencies (zlib, zstd, ...) differ by distro build; pkg-config knows them.
	libs, err := exec.Command("pkg-config", "--static", "--libs", "libcrypto").Output()
	if err != nil {
		unavailable("pkg-config --static --libs libcrypto: " + err.Error())
	}
	args := append([]string{"-static", "-o", static, src}, strings.Fields(string(libs))...)
	if out, err := exec.Command(cc, append(args, "-pthread")...).CombinedOutput(); err != nil {
		unavailable("static link against libcrypto.a failed: " + strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("strip", static).CombinedOutput(); err != nil {
		t.Fatalf("strip: %v %s", err, out)
	}
	if out, err := exec.Command(cc, "-o", dynamic, src, "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("dynamic link against libcrypto failed: %v %s", err, out)
	}
	// Preconditions: the static fixture really is stripped and links nothing, and the control
	// really links the system core. Otherwise a pass or a fail below would prove nothing.
	f, err := elf.Open(static)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Section(".symtab") != nil || f.Section(".dynamic") != nil {
		t.Fatal("precondition: the static fixture must have no symbol table and no dynamic section")
	}
	if out, err := exec.Command(dynamic).CombinedOutput(); err != nil || !strings.HasPrefix(string(out), "OpenSSL ") {
		t.Fatalf("precondition: the control must run against the system libcrypto: %v %s", err, out)
	}
	return static, dynamic
}

func TestRealStrippedStaticOpenSSLFails(t *testing.T) {
	static, dynamic := cFixtures(t)
	r, err := analyze(static, "/usr/bin/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Defines) != 0 || len(r.NeededCores) != 0 {
		t.Fatalf("precondition: the byte scan must be the only evidence, got defines %v, needed %v", r.Defines, r.NeededCores)
	}
	if got := embeddedReason(r); !strings.Contains(got, "stripped embedded copy") {
		t.Fatalf("a stripped binary with OpenSSL compiled in must fail as an embedded copy, got %q (markers %v, source %v)", got, r.Markers, r.HasSource)
	}

	ctrl, err := analyze(dynamic, "/usr/bin/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrl.NeededCores) == 0 {
		t.Fatalf("precondition: the control must link the system libcrypto, got %+v", ctrl)
	}
	if got := embeddedReason(ctrl); got != "" {
		t.Fatalf("control: the same program linking the system libcrypto must pass, got %q", got)
	}
}
