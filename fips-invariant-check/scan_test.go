package main

import (
	"debug/buildinfo"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// Each case is a real file the fleet scan met on 2026-10-02, reduced to what the classifier sees.
func TestEmbeddedReason(t *testing.T) {
	cases := []struct {
		name string
		r    fileReport
		want string // substring of the reason; "" means the file must pass
	}{
		{"system libcrypto 3", fileReport{Path: "/usr/lib/libcrypto.so.3", Soname: "libcrypto.so.3", Defines: []string{"RAND_bytes"}}, ""},
		{"system libssl 4", fileReport{Path: "/usr/lib/libssl.so.4", Soname: "libssl.so.4", NeededCores: []string{"libcrypto.so.4"}}, ""},
		{"FIPS provider module", fileReport{Path: "/usr/lib/ossl-modules/fips.so", Defines: []string{"EVP_DigestInit_ex"}}, ""},
		{"python _ssl links the system core", fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libssl.so.3", "libcrypto.so.3"}, Markers: []string{"OpenSSL 3.6.4"}}, ""},
		{"ruby openssl.so: header text only", fileReport{Path: "/usr/lib/ruby/3.4.0/x86_64-linux-gnu/openssl.so", NeededCores: []string{"libssl.so.3"}, Markers: []string{"OpenSSL 3.6.4"}}, ""},
		{"git build-options text, no source paths", fileReport{Path: "/usr/bin/git", Markers: []string{"OpenSSL 3.6.4"}}, ""},
		{"pg gem bundled libpq", fileReport{Path: "/app/vendor/pg-1.6.3-x86_64-linux/ports/x86_64-linux/lib/libpq-ruby-pg.so.1", Defines: []string{"RAND_bytes"}, Markers: []string{"OpenSSL 3.6.0"}}, "defines its own RAND_bytes"},
		{"cryptography wheel", fileReport{Path: "/usr/lib/python3.14/site-packages/cryptography/hazmat/bindings/_rust.abi3.so", Defines: []string{"EVP_DigestInit_ex"}}, "defines its own"},
		{"stripped chrome with BoringSSL sources", fileReport{Path: "/usr/lib/chromium/chrome", Markers: []string{"BoringSSL"}, HasSource: true}, "compiled-in crypto library"},
		// Boundaries of the stripped-copy branch: source paths in a file that links the system
		// core are its headers/asserts, not a second copy; a Go binary is judged by the Go rule.
		{"source paths but links the system core", fileReport{Path: "/usr/lib/ruby/openssl.so", NeededCores: []string{"libcrypto.so.3"}, Markers: []string{"OpenSSL 3.6.4"}, HasSource: true}, ""},
		{"Go binary with source paths is judged by the Go rule", fileReport{Path: "/usr/bin/svc", IsGo: true, GoFIPS: true, GoCrypto: true, Markers: []string{"BoringSSL"}, HasSource: true}, ""},
		{"independent stack by soname, even in a system dir", fileReport{Path: "/usr/lib/libwolfssl.so.42", Soname: "libwolfssl.so.42"}, "wolfSSL"},
		{"Mbed TLS crypto soname", fileReport{Path: "/usr/lib/libmbedcrypto.so.16", Soname: "libmbedcrypto.so.16"}, "Mbed TLS"},
		{"vendored libcrypto in a wheel", fileReport{Path: "/opt/appenv/lib/foo.libs/libcrypto-1a2b3c4d.so.3", Soname: "libcrypto-1a2b3c4d.so.3"}, "vendored OpenSSL"},
		{"libcrypto outside system dirs", fileReport{Path: "/opt/app/lib/libcrypto.so.3", Soname: "libcrypto.so.3"}, "vendored OpenSSL"},
		{"NSS", fileReport{Path: "/usr/lib/libssl3.so", Soname: "libssl3.so"}, "Mozilla NSS"},
		{"Heimdal hcrypto by soname", fileReport{Path: "/usr/lib/libhcrypto.so.4.1.0", Soname: "libhcrypto.so.4"}, "Heimdal hcrypto"},
		{"Heimdal symbols without its soname", fileReport{Path: "/opt/x/libfoo.so", Defines: []string{"hc_RAND_bytes"}}, "defines its own hc_RAND_bytes"},
		{"libgcrypt", fileReport{Path: "/usr/lib/libgcrypt.so.20", Soname: "libgcrypt.so.20"}, "libgcrypt"},
		{"GnuTLS", fileReport{Path: "/usr/lib/libgnutls.so.30", Soname: "libgnutls.so.30"}, "GnuTLS"},
		{"Go with std crypto, no FIPS", fileReport{Path: "/usr/bin/credbridge", IsGo: true, GoCrypto: true, GoBuildNote: "CGO_ENABLED=0"}, "Go binary whose crypto is not a validated FIPS module"},
		{"Go with FIPS mode", fileReport{Path: "/usr/bin/svc", IsGo: true, GoCrypto: true, GoFIPS: true}, ""},
		{"Go without crypto", fileReport{Path: "/usr/bin/tool", IsGo: true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := embeddedReason(&c.r)
			if c.want == "" && got != "" {
				t.Fatalf("expected pass, got violation: %s", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("expected violation containing %q, got %q", c.want, got)
			}
		})
	}
}

func TestSourceMarker(t *testing.T) {
	for _, s := range []string{"third_party/boringssl/src/crypto/x.c", "crypto/evp/digest.c", "ssl/ssl_lib.c"} {
		if !cryptoSourceMarker.MatchString(s) {
			t.Errorf("should match %q", s)
		}
	}
	for _, s := range []string{"OpenSSL: %s", "libcurl: %s", "SHA256_BLK"} { // git's strings
		if cryptoSourceMarker.MatchString(s) {
			t.Errorf("must not match %q", s)
		}
	}
}

func TestGoFIPSMode(t *testing.T) {
	mk := func(kv ...string) *buildinfo.BuildInfo {
		bi := &buildinfo.BuildInfo{}
		for i := 0; i < len(kv); i += 2 {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return bi
	}
	// Real `go version -m` settings, 2026-10-02 (jacob-82's probes and a local go1.27.1 build).
	cg127 := []string{"chainguard_go_package", "go-geomys-1.27-1.27.0-r1", "chainguard_cryptographic_module", "geomys",
		"chainguard_entropy_source", "geomys", "-tags", "fips140v1.0",
		"DefaultGODEBUG", "fips140=on,tracebacklabels=0,x509sslcertoverrideplatform=0", "CGO_ENABLED", "0", "GOFIPS140", "v1.0.0-c2097c7c"}
	upV100 := []string{"-tags", "fips140v1.0", "DefaultGODEBUG", "fips140=on", "CGO_ENABLED", "0", "GOFIPS140", "v1.0.0-c2097c7c"}
	cg126 := []string{"microsoft_systemcrypto", "1", "microsoft_toolset_version", "go1.26.8-microsoft", "-tags", "requirefips",
		"DefaultGODEBUG", "fips140=on", "CGO_ENABLED", "1", "GOEXPERIMENT", "systemcrypto", "GOFIPS140", "latest"}
	with := func(base []string, kv ...string) []string {
		out := append([]string{}, base...)
		for i := 0; i < len(kv); i += 2 {
			replaced := false
			for j := 0; j < len(out); j += 2 {
				if out[j] == kv[i] {
					out[j+1], replaced = kv[i+1], true
				}
			}
			if !replaced {
				out = append(out, kv[i], kv[i+1])
			}
		}
		return out
	}
	cases := []struct {
		name string
		kv   []string
		fips bool
	}{
		{"DU go-fips 1.27 native (#5247)", cg127, true},
		{"DU go-fips 1.27 with fips140=only", with(cg127, "DefaultGODEBUG", "fips140=only"), true},
		{"upstream GOFIPS140=v1.0.0 (kernel entropy; Jacob: reject)", upV100, false},
		{"DU 1.27 but fips140 off", with(cg127, "DefaultGODEBUG", "fips140=off"), false},
		{"DU 1.27 but GOFIPS140=latest", with(cg127, "GOFIPS140", "latest"), false},
		{"DU 1.27 but entropy not geomys", with(cg127, "chainguard_entropy_source", "kernel"), false},
		{"DU 1.27 but module not geomys", with(cg127, "chainguard_cryptographic_module", "boringcrypto"), false},
		{"DU go-fips 1.26.8.1 systemcrypto (#5132 via OpenSSL)", cg126, true},
		{"systemcrypto without CGO", with(cg126, "CGO_ENABLED", "0"), false},
		{"requirefips without systemcrypto", with(cg126, "GOEXPERIMENT", ""), false},
		{"plain golang (comment-dedup today)", []string{"CGO_ENABLED", "0"}, false},
		{"boringcrypto", []string{"GOEXPERIMENT", "boringcrypto", "CGO_ENABLED", "1"}, false},
	}
	for _, c := range cases {
		if got, note := goFIPSMode(mk(c.kv...)); got != c.fips {
			t.Errorf("%s: got fips=%v want %v (%s)", c.name, got, c.fips, note)
		}
	}
}

func TestSystemCoreMajor(t *testing.T) {
	if m, ok := systemCoreMajor(&fileReport{Path: "/usr/lib/libcrypto.so.4", Soname: "libcrypto.so.4"}); !ok || m != "4" {
		t.Fatalf("got %q %v", m, ok)
	}
	if _, ok := systemCoreMajor(&fileReport{Path: "/opt/x/libcrypto.so.3", Soname: "libcrypto.so.3"}); ok {
		t.Fatal("a libcrypto outside the system dirs is not the system core")
	}
}

func TestAllowFile(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "x.allow")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, err := loadAllowFile(write("/usr/bin/credbridge\n")); err == nil {
		t.Fatal("an entry without a reason must be rejected")
	}
	if _, err := loadAllowFile(write("usr/bin/x reason\n")); err == nil {
		t.Fatal("a relative pattern must be rejected")
	}

	entries, err := loadAllowFile(write("# comment\n\n/usr/bin/credbridge dev-only credential helper; builder never ships\n/usr/lib/python3.14/site-packages/** poetry's own closure\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].reason != "dev-only credential helper; builder never ships" {
		t.Fatalf("parsed %+v", entries)
	}
	if findAllow(entries, "/usr/bin/credbridge") == nil {
		t.Error("exact path should match")
	}
	if findAllow(entries, "/usr/lib/python3.14/site-packages/cryptography/x.so") == nil {
		t.Error("/** should match anything below")
	}
	if findAllow(entries, "/usr/lib/python3.14/site-packages-other/x.so") != nil {
		t.Error("/** must not match a sibling with the same prefix")
	}
	if findAllow(entries, "/usr/bin/credbridge2") != nil {
		t.Error("exact path must not prefix-match")
	}

	for _, bad := range []string{"/** everything", "/* everything", "/*/bin/** too wide", "/ root"} {
		if _, err := loadAllowFile(write(bad + "\n")); err == nil {
			t.Errorf("pattern %q exempts the whole image and must be rejected", strings.Fields(bad)[0])
		}
	}

	globDir, err := loadAllowFile(write("/usr/lib/python3.*/site-packages/** builder-only closure\n"))
	if err != nil {
		t.Fatal(err)
	}
	if findAllow(globDir, "/usr/lib/python3.14/site-packages/x/y.so") == nil {
		t.Error("a glob in the directory part of a /** pattern should match")
	}
	if findAllow(globDir, "/usr/lib/python3.14/other/y.so") != nil {
		t.Error("a /** pattern must not match outside its directory")
	}
}

// CPython's _ssl defines a local _ssl_RAND_bytes wrapper around the system OpenSSL; only exact
// OpenSSL/Heimdal entry-point names may count as "defines its own crypto".
func TestCryptoSymbolsAreExactNames(t *testing.T) {
	for _, s := range []string{"_ssl_RAND_bytes", "my_RAND_bytes", "RAND_bytes_ex"} {
		if cryptoSymbols[s] {
			t.Errorf("%q must not count as a crypto entry point", s)
		}
	}
	for _, s := range []string{"RAND_bytes", "EVP_DigestInit_ex", "OPENSSL_init_crypto", "hc_RAND_bytes", "hc_EVP_DigestInit_ex"} {
		if !cryptoSymbols[s] {
			t.Errorf("%q must count as a crypto entry point", s)
		}
	}
}

func TestIsCryptoFunc(t *testing.T) {
	for _, s := range []string{"crypto/internal/fips140/sha256.(*Digest).Write", "crypto/sha512.Sum512", "crypto/hmac.New", "crypto/rand.Read", "crypto/ecdsa.Sign", "crypto/x509.ParseCertificate", "crypto/tls.(*Conn).Handshake", "golang.org/x/crypto/chacha20.(*Cipher).XORKeyStream"} {
		if !isCryptoFunc(s) {
			t.Errorf("should detect std crypto use in %q", s)
		}
	}
	for _, s := range []string{"debug/elf.NewFile", "hash/crc32.Update", "math/rand.Int", "internal/chacha8rand.(*State).Next", "main.cryptoHelper", "github.com/x/crypto/y.F"} {
		if isCryptoFunc(s) {
			t.Errorf("must not treat %q as std crypto", s)
		}
	}
}
