package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GoCrypto on real binaries: a crypto-using Go program must be seen as using crypto, a
// crypto-free one must not (this is what decides whether a non-FIPS Go binary fails).
func TestAnalyzeGoCrypto(t *testing.T) {
	withCrypto, withoutCrypto := goFixtures(t)
	r, err := analyze(withCrypto, "/usr/bin/svc")
	if err != nil || r == nil || !r.IsGo || !r.GoCrypto || r.GoFIPS {
		t.Fatalf("crypto fixture: want IsGo, GoCrypto, !GoFIPS; got %+v %v", r, err)
	}
	if reason := embeddedReason(r); !strings.Contains(reason, "not a validated FIPS module") {
		t.Fatalf("a non-FIPS crypto Go binary must fail, got %q", reason)
	}
	r, err = analyze(withoutCrypto, "/usr/bin/tool")
	if err != nil || r == nil || !r.IsGo || r.GoCrypto {
		t.Fatalf("crypto-free fixture: want IsGo and !GoCrypto; got %+v %v", r, err)
	}
	if reason := embeddedReason(r); reason != "" {
		t.Fatalf("a crypto-free Go binary must pass, got %q", reason)
	}
}

// A Go binary whose function table cannot be found, or whose build info is damaged (debug/buildinfo
// then reports "not a Go executable"), must be uninspectable, not "non-Go".
func TestAnalyzeGoBinaryThatCannotBeRead(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	noTable := copyWith(t, withCrypto, func(d []byte) []byte { return renameSection(t, d, ".gopclntab", ".gopclnXXX") })
	if _, err := analyze(noTable, "/usr/bin/svc"); err == nil || !strings.Contains(err.Error(), "function table") {
		t.Errorf("a Go binary without a readable function table must be an error, got %v", err)
	}
	damaged := copyWith(t, withCrypto, func(d []byte) []byte {
		i := bytes.Index(d, goBuildInfoMagic)
		if i < 0 {
			t.Fatal("fixture has no build-info magic")
		}
		d[i+len(goBuildInfoMagic)+1] = 0 // flags byte (magic, pointer size, flags)
		return d
	})
	// debug/buildinfo reports this damage as "not a Go executable"; only the Go-section check
	// keeps it from being classified as non-Go.
	if _, err := buildinfoErr(damaged); err == nil || !strings.Contains(err.Error(), "not a Go executable") {
		t.Fatalf("fixture damage should make debug/buildinfo say 'not a Go executable', got %v", err)
	}
	if _, err := analyze(damaged, "/usr/bin/svc"); err == nil || !strings.Contains(err.Error(), "Go binary whose build info cannot be read") {
		t.Errorf("a Go binary with damaged build info must be an error, not non-Go; got %v", err)
	}
}

func TestAnalyzePackedAndTruncated(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	// Simulate UPX's layout: the "UPX!" header in the padding after the program headers, and no
	// section headers. Merely containing the text elsewhere (as this test binary does) is not packing.
	packed := copyWith(t, withCrypto, func(d []byte) []byte {
		copy(d[0x800:], "UPX!")
		binary.LittleEndian.PutUint64(d[0x28:], 0) // e_shoff
		binary.LittleEndian.PutUint16(d[0x3c:], 0) // e_shnum
		binary.LittleEndian.PutUint16(d[0x3e:], 0) // e_shstrndx
		return d
	})
	textOnly := copyWith(t, withCrypto, func(d []byte) []byte { return append(d, []byte("UPX! packed with the UPX executable packer")...) })
	if r, err := analyze(textOnly, "/usr/bin/svc"); err != nil || r == nil {
		t.Errorf("a binary that merely contains UPX text is not packed: %v", err)
	}
	if _, err := analyze(packed, "/usr/bin/svc"); err == nil || !strings.Contains(err.Error(), "packed") {
		t.Errorf("a UPX-packed executable must be uninspectable, got %v", err)
	}
	truncated := copyWith(t, withCrypto, func(d []byte) []byte { return d[:4096] })
	if _, err := analyze(truncated, "/usr/bin/svc"); err == nil {
		t.Error("an ELF that cannot be parsed must be an error")
	}
}

// scanBytes must find a marker that straddles a chunk boundary.
func TestScanBytesChunkBoundary(t *testing.T) {
	data := append(bytes.Repeat([]byte{'x'}, 60), []byte("BoringSSL crypto/evp/digest.c \xff Go buildinf:")...)
	data = append(data, bytes.Repeat([]byte{'y'}, 100)...)
	facts, err := scanBytes(bytes.NewReader(data), 64, 48)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.markers["BoringSSL"] || !facts.source || !facts.goMagic {
		t.Fatalf("markers split across chunks were missed: %+v", facts)
	}
	none, _ := scanBytes(bytes.NewReader(bytes.Repeat([]byte{'z'}, 300)), 64, 48)
	if len(none.markers) != 0 || none.source || none.goMagic {
		t.Fatalf("plain bytes must yield no evidence: %+v", none)
	}
}

// End to end: a file the scan cannot inspect fails the run and is named.
func TestRunUninspectableFileFails(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	root := fixtureRoot(t)
	data, _ := os.ReadFile(withCrypto)
	if err := os.WriteFile(filepath.Join(root, "usr/bin/broken"), data[:4096], 0o755); err != nil {
		t.Fatal(err)
	}
	code, out := runWith(t, nil, "-root", root)
	if code != 1 || !strings.Contains(out, "could not be inspected") || !strings.Contains(out, "/usr/bin/broken") {
		t.Fatalf("an uninspectable ELF must fail the run and be named, got %d:\n%s", code, out)
	}
}

func TestRunGoCryptoBinaryFails(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	root := fixtureRoot(t)
	data, _ := os.ReadFile(withCrypto)
	os.WriteFile(filepath.Join(root, "usr/bin/svc"), data, 0o755)
	code, out := runWith(t, nil, "-root", root)
	if code != 1 || !strings.Contains(out, "/usr/bin/svc: Go binary whose crypto is not a validated FIPS module") {
		t.Fatalf("a non-FIPS crypto Go binary must fail the run, got %d:\n%s", code, out)
	}
	if strings.Contains(out, "/usr/bin/tool:") {
		t.Fatalf("the crypto-free Go binary must not be flagged:\n%s", out)
	}
}

func TestRunSkipsVirtualFilesystems(t *testing.T) {
	root := fixtureRoot(t)
	os.MkdirAll(filepath.Join(root, "proc/1"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/1/exe"), append([]byte("\x7fELF"), make([]byte, 100)...), 0o644)
	code, out := runWith(t, nil, "-root", root)
	if code != 0 || strings.Contains(out, "/proc") {
		t.Fatalf("/proc must not be scanned, got %d:\n%s", code, out)
	}
}

func TestRunRootResolution(t *testing.T) {
	root := fixtureRoot(t)
	link := filepath.Join(t.TempDir(), "rootlink")
	if err := os.Symlink(root, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if code, out := runWith(t, nil, "-root", link); code != 0 {
		t.Errorf("a symlinked -root must be followed and scanned, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-root", filepath.Join(root, "usr/bin/tool")); code != 2 || !strings.Contains(out, "is not a directory") {
		t.Errorf("-root pointing at a file must be an error, got %d:\n%s", code, out)
	}
}

func TestRunExplicitProbeOutsideImageIsAnError(t *testing.T) {
	root := fixtureRoot(t)
	if code, out := runWith(t, nil, "-root", root, "--", "/bin/false"); code != 2 || !strings.Contains(out, "can only run inside the image") {
		t.Fatalf("an explicit -- probe that cannot run must be an error, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, map[string]string{"FIPS_INVARIANT_PROBE": "/bin/false"}, "-root", root); code != 0 || !strings.Contains(out, "not run") {
		t.Fatalf("an inherited probe is only noted from outside the image, got %d:\n%s", code, out)
	}
}

// allow.d reached through a symlink is resolved inside the image, never on the host.
func TestRunAllowDirSymlinkResolvedInImage(t *testing.T) {
	root := fixtureRoot(t)
	os.MkdirAll(filepath.Join(root, "opt/allow"), 0o755)
	os.WriteFile(filepath.Join(root, "opt/allow/x.allow"), []byte("/usr/bin/tool builder-only\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "etc/fips-invariant-check"), 0o755)
	if err := os.Symlink("/opt/allow", filepath.Join(root, "etc/fips-invariant-check/allow.d")); err != nil {
		t.Skip("symlinks unavailable")
	}
	code, out := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "1"}, "-root", root)
	if code != 1 || !strings.Contains(out, "x.allow") {
		t.Fatalf("strict: an allow file behind an absolute in-image symlink must be found, got %d:\n%s", code, out)
	}
	dangling := fixtureRoot(t)
	os.MkdirAll(filepath.Join(dangling, "etc/fips-invariant-check"), 0o755)
	os.Symlink("/nowhere", filepath.Join(dangling, "etc/fips-invariant-check/allow.d"))
	if code, out := runWith(t, nil, "-root", dangling); code != 2 || !strings.Contains(out, "dangling") {
		t.Fatalf("a dangling allow.d symlink must be an error, got %d:\n%s", code, out)
	}
}

// OpenSSL 1.x's dotted sonames are cores too: 1.1 next to 3 is two cores.
func TestEvaluateOpenSSL1Soname(t *testing.T) {
	if !coreSoname.MatchString("libcrypto.so.1.1") || !coreSoname.MatchString("libssl.so.1.0.0") {
		t.Fatal("OpenSSL 1.x sonames must be recognised")
	}
	old := &fileReport{Path: "/opt/legacy/bin/tool", NeededCores: []string{"libcrypto.so.1.1"}}
	cur := &fileReport{Path: "/usr/lib/python3.14/lib-dynload/_ssl.so", NeededCores: []string{"libcrypto.so.3"}}
	if failed, out := evalOut(t, evalInput{reports: []*fileReport{old, cur}}); !failed || !strings.Contains(out, "libcrypto.so.1.1, libcrypto.so.3") {
		t.Fatalf("1.1 next to 3 must fail rule 1:\n%s", out)
	}
	sys11 := &fileReport{Path: "/usr/lib/libcrypto.so.1.1", Soname: "libcrypto.so.1.1"}
	if m, ok := systemCoreMajor(sys11); !ok || m != "1.1" {
		t.Fatalf("a system libcrypto.so.1.1 is a core (major 1.1), got %q %v", m, ok)
	}
}

func TestXCryptoPrimitives(t *testing.T) {
	cases := map[string]string{
		"golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305).Seal": "golang.org/x/crypto/chacha20poly1305",
		"golang.org/x/crypto/ssh/agent.(*client).Sign":                  "golang.org/x/crypto/ssh/agent",
		"golang.org/x/crypto/internal/poly1305.Sum":                     "golang.org/x/crypto/internal/poly1305",
		"golang.org/x/crypto/argon2.IDKey":                              "golang.org/x/crypto/argon2",
		// Own implementations inside packages that are wrappers in newer x/crypto versions:
		"golang.org/x/crypto/sha3.keccakF1600":                "golang.org/x/crypto/sha3", // < v0.44.0, and legacy Keccak today
		"golang.org/x/crypto/sha3.(*state).padAndPermute":     "golang.org/x/crypto/sha3",
		"golang.org/x/crypto/pbkdf2.Key.func1":                "golang.org/x/crypto/pbkdf2", // < v0.51.0 inlines its HMAC loop
		"golang.org/x/crypto/hkdf.(*hkdfReader).Read":         "golang.org/x/crypto/hkdf",   // own Expand on crypto/hmac
		"golang.org/x/crypto/curve25519/internal/field.feMul": "golang.org/x/crypto/curve25519/internal/field",
		"golang.org/x/crypto/newpkg.Thing":                    "golang.org/x/crypto/newpkg", // unknown: fails closed
		"filippo.io/edwards25519.(*Point).Add":                "filippo.io/edwards25519",
		"github.com/cloudflare/circl/sign/ed448.Sign":         "github.com/cloudflare/circl",
		"gitlab.com/yawning/x448.git.ScalarMult":              "gitlab.com/yawning",
	}
	for fn, want := range cases {
		if got, ok := xcryptoPrimitive(fn, "v0.50.0"); !ok || got != want {
			t.Errorf("%s: want %s, got %q %v", fn, want, got, ok)
		}
	}
	for _, fn := range []string{
		"vendor/golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305).Seal", // stdlib's vendored copy behind crypto/tls
		"golang.org/x/crypto/sha3.New256",                                      // forwards to crypto/sha3 (>= v0.44.0)
		"golang.org/x/crypto/sha3.(*shakeWrapper).Read",
		"golang.org/x/crypto/pbkdf2.Key",              // forwards to crypto/pbkdf2 (>= v0.51.0)
		"golang.org/x/crypto/curve25519.X25519.func1", // closure of a forwarding function
		"golang.org/x/crypto/ed25519.Sign",
		"golang.org/x/crypto/sha3.init",
		"golang.org/x/crypto/cryptobyte.(*String).ReadASN1", // parsing, no crypto
		"golang.org/x/crypto/cryptobyte.(*Builder).AddASN1[go.shape.*a/b.T]",
		"golang.org/x/crypto/internal/alias.AnyOverlap",
		"crypto/sha256.Sum256",
	} {
		if p, ok := xcryptoPrimitive(fn, "v0.57.0"); ok {
			t.Errorf("%s must not count as crypto outside the standard library (got %s)", fn, p)
		}
	}
	// The same forwarding names are own implementations in older versions, or when the version
	// is unknown (replaced module).
	for fn, v := range map[string]string{
		"golang.org/x/crypto/pbkdf2.Key":        "v0.50.0",
		"golang.org/x/crypto/sha3.New256":       "v0.43.0",
		"golang.org/x/crypto/curve25519.X25519": "v0.7.0",
		"golang.org/x/crypto/sha3.Sum256":       "",
	} {
		if _, ok := xcryptoPrimitive(fn, v); !ok {
			t.Errorf("%s at x/crypto %q must count as its own implementation", fn, v)
		}
	}
	for _, c := range []struct {
		v, min string
		want   bool
	}{{"v0.51.0", "v0.51.0", true}, {"v0.57.0", "v0.51.0", true}, {"v0.50.9", "v0.51.0", false},
		{"v1.0.0", "v0.51.0", true}, {"v0.51.1-0.20260101000000-abcdef123456", "v0.51.0", true},
		{"", "v0.1.0", false}, {"(devel)", "v0.1.0", false}} {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q, %q) = %v", c.v, c.min, got)
		}
	}
	fipsWithX := &fileReport{Path: "/usr/bin/svc", IsGo: true, GoCrypto: true, GoFIPS: true, GoUnvalidated: []string{"golang.org/x/crypto/chacha20poly1305"}}
	if r := embeddedReason(fipsWithX); !strings.Contains(r, "golang.org/x/crypto/chacha20poly1305") {
		t.Errorf("a FIPS-built Go binary linking an x/crypto primitive must fail, got %q", r)
	}
}

func TestAllowEntryUsedHasNoStaleWarningAndBadGlob(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.allow")
	os.WriteFile(p, []byte("/usr/[ broken glob\n"), 0o644)
	if _, err := loadAllowFile(p); err == nil {
		t.Error("a malformed glob must be rejected")
	}
	wheel := &fileReport{Path: "/opt/x/_rust.so", Defines: []string{"RAND_bytes"}}
	allow := []*allowEntry{{pattern: "/opt/x/**", reason: "r", source: "t:1"}}
	if _, out := evalOut(t, evalInput{reports: []*fileReport{wheel}, allow: allow}); strings.Contains(out, "matched nothing") {
		t.Errorf("a used exemption must not be reported stale:\n%s", out)
	}
}

// A shared library stripped of its section headers still declares its libraries in PT_DYNAMIC,
// which the loader uses; they must still be seen.
func TestAnalyzeSectionHeadersStripped(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs the runner's libssl.so.3")
	}
	var src string
	for _, d := range []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib", "/lib"} {
		if _, err := os.Stat(filepath.Join(d, "libssl.so.3")); err == nil {
			src = filepath.Join(d, "libssl.so.3")
			break
		}
	}
	if src == "" {
		t.Skip("libssl.so.3 not found")
	}
	stripped := copyWith(t, src, func(d []byte) []byte {
		if d[4] != 2 { // ELFCLASS64 only
			t.Skip("not a 64-bit ELF")
		}
		bo := binary.ByteOrder(binary.LittleEndian)
		if d[5] == 2 {
			bo = binary.BigEndian
		}
		bo.PutUint64(d[0x28:], 0) // e_shoff
		bo.PutUint16(d[0x3c:], 0) // e_shnum
		bo.PutUint16(d[0x3e:], 0) // e_shstrndx
		return d
	})
	r, err := analyze(stripped, "/opt/x/libssl.so.3")
	if err != nil || r == nil {
		t.Fatalf("analyze: %v", err)
	}
	if strings.Join(r.NeededCores, ",") != "libcrypto.so.3" || r.Soname != "libssl.so.3" {
		t.Fatalf("PT_DYNAMIC must still yield DT_NEEDED libcrypto.so.3 and DT_SONAME libssl.so.3, got %+v", r)
	}
}

// analyze records crypto-library markers and source paths from a real file's bytes.
func TestAnalyzeRecordsMarkers(t *testing.T) {
	_, withoutCrypto := goFixtures(t)
	marked := copyWith(t, withoutCrypto, func(d []byte) []byte {
		return append(d, []byte("\x00BoringSSL\x00third_party/boringssl/src/crypto/x.c\x00")...)
	})
	r, err := analyze(marked, "/usr/bin/tool")
	if err != nil || r == nil {
		t.Fatal(err)
	}
	if strings.Join(r.Markers, ",") != "BoringSSL" || !r.HasSource {
		t.Fatalf("want markers [BoringSSL] with source paths, got %v source=%v", r.Markers, r.HasSource)
	}
}

// run() itself must turn a failing probe into a failing run (exit 1) and a passing one into 0.
func TestRunProbeWiring(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("true/false commands")
	}
	root := fixtureRoot(t)
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	saved := inImageRoot
	inImageRoot = real
	t.Cleanup(func() { inImageRoot = saved })
	if code, out := runWith(t, map[string]string{"FIPS_INVARIANT_PROBE": "false"}, "-root", root); code != 1 || !strings.Contains(out, "behavioural probe failed") {
		t.Fatalf("a failing probe must fail the run, got %d:\n%s", code, out)
	}
	if code, out := runWith(t, nil, "-root", root, "--", "true"); code != 0 || !strings.Contains(out, "behavioural probe passed") {
		t.Fatalf("a passing probe on a clean image must pass, got %d:\n%s", code, out)
	}
}

func buildinfoErr(p string) (any, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return buildinfo.Read(f)
}

// A separate debug-info file has section headers but no in-file dynamic table (.dynamic is
// NOBITS); its program headers point at data that is not there. It must analyze cleanly, not as
// uninspectable (the JDK ships dozens of these).
func TestAnalyzeDebugInfoFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs objcopy and the runner's libssl.so.3")
	}
	objcopy, err := exec.LookPath("objcopy")
	if err != nil {
		t.Skip("objcopy not available")
	}
	var src string
	for _, d := range []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib", "/lib"} {
		if _, err := os.Stat(filepath.Join(d, "libssl.so.3")); err == nil {
			src = filepath.Join(d, "libssl.so.3")
			break
		}
	}
	if src == "" {
		t.Skip("libssl.so.3 not found")
	}
	dbg := filepath.Join(t.TempDir(), "libssl.so.3.debug")
	if out, err := exec.Command(objcopy, "--only-keep-debug", src, dbg).CombinedOutput(); err != nil {
		t.Fatalf("objcopy: %v %s", err, out)
	}
	r, err := analyze(dbg, "/usr/lib/debug/libssl.so.3.debug")
	if err != nil {
		t.Fatalf("a debug-info file must analyze cleanly, got %v", err)
	}
	if r == nil || len(r.NeededCores) != 0 {
		t.Fatalf("a debug-info file links nothing, got %+v", r)
	}
}
