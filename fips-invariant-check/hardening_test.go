package main

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

// The x/crypto rule on real binaries: an own implementation is reported, a forwarding function
// is not. Without this, the analysis could stop collecting packages and every unit test still pass.
func TestAnalyzeXCryptoOnRealBinaries(t *testing.T) {
	r, err := analyze(goFixture(t, "xown"), "/usr/bin/svc")
	if err != nil || r == nil || !r.IsGo {
		t.Fatalf("xown: %v %+v", err, r)
	}
	if !slices.Equal(r.GoUnvalidated, []string{"golang.org/x/crypto/sha3"}) {
		t.Errorf("an own Keccak in x/crypto/sha3 must be reported, got %v", r.GoUnvalidated)
	}
	r.GoFIPS = true // stand in for a route-A/B build, which this toolchain cannot produce
	if embeddedReason(r) == "" {
		t.Error("a FIPS-built binary carrying an own x/crypto implementation must fail")
	}
	w, err := analyze(goFixture(t, "xwrap"), "/usr/bin/svc")
	if err != nil || w == nil || !w.GoCrypto {
		t.Fatalf("xwrap: %v %+v", err, w)
	}
	// The fixture's x/crypto is a replace directive, so its version is unknown and even the
	// forwarding function is reported: no exemption without a known upstream version. (The
	// version-gated exemption itself is unit-tested in TestXCryptoPrimitives.)
	if !slices.Equal(w.GoUnvalidated, []string{"golang.org/x/crypto/sha3"}) {
		t.Errorf("a replaced x/crypto must fail closed, got %v", w.GoUnvalidated)
	}
}

// With both Go sections renamed and build info damaged, only the build-info magic in the bytes
// still says "Go"; such a binary must be an error, never pass as a non-Go file.
func TestAnalyzeGoMagicAloneMarksGo(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	d := copyWith(t, withCrypto, func(d []byte) []byte {
		d = renameSection(t, d, ".gopclntab", ".gopclnXXX")
		d = renameSection(t, d, ".go.buildinfo", ".go.buildinfX")
		i := bytes.Index(d, goBuildInfoMagic)
		if i < 0 {
			t.Fatal("fixture has no build-info magic")
		}
		d[i+len(goBuildInfoMagic)+1] = 0
		return d
	})
	if _, err := analyze(d, "/usr/bin/svc"); err == nil {
		t.Fatal("a binary recognisable as Go only by its build-info magic must be an error")
	}
}

// A Go separate debug-info file (objcopy --only-keep-debug) carries .gopclntab as NOBITS: no code,
// nothing to judge. It must not fail as unreadable Go.
func TestAnalyzeGoDebugInfoFile(t *testing.T) {
	objcopy, err := exec.LookPath("objcopy")
	if err != nil {
		t.Skip("objcopy not available")
	}
	withCrypto, _ := goFixtures(t)
	dbg := filepath.Join(t.TempDir(), "svc.debug")
	if out, err := exec.Command(objcopy, "--only-keep-debug", withCrypto, dbg).CombinedOutput(); err != nil {
		t.Skipf("objcopy cannot handle a linux/amd64 ELF here: %v %s", err, out)
	}
	r, err := analyze(dbg, "/usr/lib/debug/svc.debug")
	// Its first segment keeps file bytes, so it is not NoCode; its Go sections are NOBITS, so it is
	// not judged as Go.
	if err != nil || r == nil || r.IsGo {
		t.Fatalf("a Go debug-info file must analyze cleanly and not as Go, got %v %+v", err, r)
	}
	if r != nil && embeddedReason(r) != "" {
		t.Fatalf("a Go debug-info file must not fail, got %q", embeddedReason(r))
	}
}

func TestDynamicTableBounds(t *testing.T) {
	huge := &elf.File{FileHeader: elf.FileHeader{Class: elf.ELFCLASS64}, Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_DYNAMIC, Filesz: 1 << 40}}}}
	if _, _, err := dynamicFromProgs(huge, bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "implausible") {
		t.Fatalf("a header-supplied PT_DYNAMIC size must be bounded before allocating, got %v", err)
	}
	f := &elf.File{Progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0x1000, Vaddr: 0x401000, Filesz: 0x200}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0x2000, Vaddr: ^uint64(0) - 0x10, Filesz: 0x100}},
	}}
	if off, ok := vaddrToOffset(f, 0x401010); !ok || off != 0x1010 {
		t.Errorf("non-PIE layout: want 0x1010, got %#x %v", off, ok)
	}
	if _, ok := vaddrToOffset(f, 0x401200); ok {
		t.Error("an address past the segment's file bytes must not translate")
	}
	if off, ok := vaddrToOffset(f, ^uint64(0)-1); !ok || off != 0x200f {
		t.Errorf("a segment ending past 2^64 must still translate without overflow, got %#x %v", off, ok)
	}
}

// Every component of the allowlist path is resolved inside the image: an absolute symlink in a
// PARENT directory, a relative link, and a link cycle.
func TestRunAllowDirParentSymlinks(t *testing.T) {
	strict := map[string]string{"FIPS_INVARIANT_STRICT": "1"}
	abs := fixtureRoot(t)
	os.MkdirAll(filepath.Join(abs, "usr/etc/fips-invariant-check/allow.d"), 0o755)
	os.WriteFile(filepath.Join(abs, "usr/etc/fips-invariant-check/allow.d/b.allow"), []byte("/usr/bin/tool x\n"), 0o644)
	if err := os.Symlink("/usr/etc", filepath.Join(abs, "etc")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if code, out := runWith(t, strict, "-root", abs); code != 1 || !strings.Contains(out, "b.allow") {
		t.Fatalf("an allow file behind an absolute symlinked parent must be found, got %d:\n%s", code, out)
	}

	rel := fixtureRoot(t)
	os.MkdirAll(filepath.Join(rel, "opt/allow"), 0o755)
	os.WriteFile(filepath.Join(rel, "opt/allow/x.allow"), []byte("/usr/bin/tool x\n"), 0o644)
	os.MkdirAll(filepath.Join(rel, "etc/fips-invariant-check"), 0o755)
	os.Symlink("../../opt/allow", filepath.Join(rel, "etc/fips-invariant-check/allow.d"))
	if code, out := runWith(t, strict, "-root", rel); code != 1 || !strings.Contains(out, "x.allow") {
		t.Fatalf("an allow file behind a relative symlink must be found, got %d:\n%s", code, out)
	}

	cycle := fixtureRoot(t)
	os.MkdirAll(filepath.Join(cycle, "etc/fips-invariant-check"), 0o755)
	os.Symlink("/etc/fips-invariant-check/loop", filepath.Join(cycle, "etc/fips-invariant-check/allow.d"))
	os.Symlink("/etc/fips-invariant-check/allow.d", filepath.Join(cycle, "etc/fips-invariant-check/loop"))
	if code, out := runWith(t, nil, "-root", cycle); code != 2 || !strings.Contains(out, "too many levels of symlinks") {
		t.Fatalf("a symlink cycle must be an error, not a hang, got %d:\n%s", code, out)
	}

	// A symlinked parent whose target lacks allow.d means "no allowlist", not a dangling link.
	none := fixtureRoot(t)
	os.MkdirAll(filepath.Join(none, "usr/etc"), 0o755)
	os.Symlink("/usr/etc", filepath.Join(none, "etc"))
	if code, out := runWith(t, strict, "-root", none); code != 0 {
		t.Fatalf("no allow.d behind a symlinked parent is a clean image, got %d:\n%s", code, out)
	}
}

func TestEvaluateStrictIgnoresAllow(t *testing.T) {
	bad := &fileReport{Path: "/opt/x/lib.so", Defines: []string{"RAND_bytes"}}
	allow := []*allowEntry{{pattern: "/opt/x/**", reason: "r", source: "a:1"}}
	failed, out := evalOut(t, evalInput{reports: []*fileReport{bad}, allow: allow, strict: true})
	if !failed || strings.Contains(out, "ALLOWED") {
		t.Fatalf("strict mode must apply no exemption even when given one:\n%s", out)
	}
}

// Overlapping entries that match the same file are all in use; none is reported stale.
func TestFindAllowMarksEveryMatch(t *testing.T) {
	bad := &fileReport{Path: "/opt/x/_rust.so", Defines: []string{"RAND_bytes"}}
	allow := []*allowEntry{
		{pattern: "/opt/x/**", reason: "r", source: "a:1"},
		{pattern: "/opt/x/_rust.so", reason: "r", source: "a:2"},
	}
	failed, out := evalOut(t, evalInput{reports: []*fileReport{bad}, allow: allow})
	if failed || strings.Contains(out, "matched nothing") {
		t.Fatalf("both overlapping entries are in use, got failed=%v:\n%s", failed, out)
	}
}

func TestRunAllowFlag(t *testing.T) {
	root := fixtureRoot(t)
	f := filepath.Join(t.TempDir(), "extra.allow")
	os.WriteFile(f, []byte("/usr/bin/tool not needed\n"), 0o644)
	if code, out := runWith(t, nil, "-root", root, "-allow", f); code != 0 || !strings.Contains(out, "matched nothing") {
		t.Fatalf("-allow FILE must be loaded (its unused entry reported), got %d:\n%s", code, out)
	}
	if code, out := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "1"}, "-root", root, "-allow", f); code != 1 {
		t.Fatalf("strict mode must fail when given -allow FILE, got %d:\n%s", code, out)
	}
}

// /run is ordinary image content at build time (not a mount under docker build), so it is scanned.
func TestRunScansRun(t *testing.T) {
	root := fixtureRoot(t)
	os.MkdirAll(filepath.Join(root, "run/x"), 0o755)
	os.WriteFile(filepath.Join(root, "run/x/lib.so"), append([]byte("\x7fELF"), make([]byte, 100)...), 0o644)
	if code, out := runWith(t, nil, "-root", root); code != 1 || !strings.Contains(out, "/run/x/lib.so") {
		t.Fatalf("a file under /run must be scanned, got %d:\n%s", code, out)
	}
}

// A probe whose child outlives it, holding the output pipe, must be cut off at the timeout AND
// its child killed. (WaitDelay alone bounds the wait but leaves the child running; this test
// checks the process-group kill, not just the bound.)
func TestRunProbeTimeoutKillsChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	var out bytes.Buffer
	start := time.Now()
	err := runProbe([]string{"sh", "-c", "sleep 600 & echo $! > " + pidFile + "; wait"}, &out, time.Second)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout, got %v", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("the run outlived the timeout by %s: the pipe was held, the group was not killed", d-time.Second)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the probe's child %d survived the timeout", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A symbol table that is present but unreadable is not "stripped": the file must be reported as
// uninspectable, or a defined RAND_bytes in it would go unseen.
func TestAnalyzeBrokenSymbolTableIsAnError(t *testing.T) {
	src := goFixture(t, "symtab")
	if r, err := analyze(src, "/usr/bin/tool"); err != nil || r == nil {
		t.Fatalf("intact fixture: %v", err)
	}
	broken := copyWith(t, src, func(d []byte) []byte {
		f, err := elf.NewFile(bytes.NewReader(d))
		if err != nil {
			t.Fatal(err)
		}
		for i, sec := range f.Sections {
			if sec.Type == elf.SHT_SYMTAB {
				// ELF64 section header: sh_link is at byte 40. 0 is not a valid string table.
				shoff := binary.LittleEndian.Uint64(d[0x28:]) // e_shoff
				binary.LittleEndian.PutUint32(d[shoff+uint64(i)*64+40:], 0)
				return d
			}
		}
		t.Fatal("fixture has no .symtab")
		return nil
	})
	if _, err := analyze(broken, "/usr/bin/tool"); err == nil || !strings.Contains(err.Error(), "symbol table") {
		t.Fatalf("a broken symbol table must be an error, got %v", err)
	}
}

// A non-FIPS Go binary whose only crypto comes from a listed third-party module links no
// crypto/... package; it must still count as using crypto, and fail.
func TestRunThirdPartyOnlyCryptoFails(t *testing.T) {
	r, err := analyze(goFixture(t, "tponly"), "/usr/bin/app")
	if err != nil || r == nil || !r.GoCrypto || !slices.Equal(r.GoUnvalidated, []string{"github.com/aead/chacha20"}) {
		t.Fatalf("want GoCrypto with github.com/aead/chacha20, got %v %+v", err, r)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	data, _ := os.ReadFile(goFixture(t, "tponly"))
	os.WriteFile(filepath.Join(root, "usr/bin/app"), data, 0o755)
	if code, out := runWith(t, nil, "-root", root); code != 1 || !strings.Contains(out, "/usr/bin/app") {
		t.Fatalf("a non-FIPS binary using only third-party crypto must fail, got %d:\n%s", code, out)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, floor string
		want     bool
	}{
		{"v0.51.0", "v0.51.0", true}, {"v0.57.0", "v0.51.0", true}, {"v1.0.0", "v0.51.0", true},
		{"v0.50.9", "v0.51.0", false},
		// Pre-release and pseudo-versions precede their base version.
		{"v0.51.0-rc.1", "v0.51.0", false},
		{"v0.51.0-0.20250101000000-abcdef123456", "v0.51.0", false},
		{"v0.51.1-0.20260101000000-abcdef123456", "v0.51.0", true},
		{"", "v0.1.0", false}, {"(devel)", "v0.1.0", false}, {"v0.51", "v0.51.0", false},
	} {
		if got := versionAtLeast(c.v, c.floor); got != c.want {
			t.Errorf("versionAtLeast(%q, %q) = %v, want %v", c.v, c.floor, got, c.want)
		}
	}
}

// Every wrapper entry must carry a parseable version and at least one function; a typo would
// otherwise withhold the exemption forever without saying why.
func TestXCryptoWrappersTable(t *testing.T) {
	for pkg, w := range xcryptoWrappers {
		if !versionAtLeast(w.since, w.since) || len(w.funcs) == 0 {
			t.Errorf("xcryptoWrappers[%q] = %+v is malformed", pkg, w)
		}
	}
}

func TestXCryptoVersion(t *testing.T) {
	dep := func(v string, repl bool) *buildinfo.BuildInfo {
		m := &debug.Module{Path: "golang.org/x/crypto", Version: v}
		if repl {
			m.Replace = &debug.Module{Path: "./xc"}
		}
		return &buildinfo.BuildInfo{Deps: []*debug.Module{{Path: "other", Version: "v1.0.0"}, m}}
	}
	if v := xcryptoVersion(dep("v0.57.0", false)); v != "v0.57.0" {
		t.Errorf("want v0.57.0, got %q", v)
	}
	if v := xcryptoVersion(dep("v0.57.0", true)); v != "" {
		t.Errorf("a replaced x/crypto has no trustworthy version, got %q", v)
	}
	if v := xcryptoVersion(&buildinfo.BuildInfo{}); v != "" {
		t.Errorf("no x/crypto dependency: want \"\", got %q", v)
	}
}

func TestXCryptoGeneratedNames(t *testing.T) {
	for _, fn := range []string{
		"golang.org/x/crypto/sha3.init.0",
		"golang.org/x/crypto/curve25519.X25519.gowrap1",
		"golang.org/x/crypto/curve25519.X25519.deferwrap2",
	} {
		if p, ok := xcryptoPrimitive(fn, "v0.57.0"); ok {
			t.Errorf("%s is generated code of an exempt function, got %s", fn, p)
		}
	}
}

// An unreadable component of the allow.d path (here a regular file where a directory belongs) is
// an error, never "no allowlist".
func TestRunAllowDirComponentNotADirectory(t *testing.T) {
	root := fixtureRoot(t)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/fips-invariant-check"), []byte("not a dir"), 0o644)
	if code, out := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "1"}, "-root", root); code != 2 || !strings.Contains(out, "allowlist directory") {
		t.Fatalf("want exit 2 naming the allowlist directory, got %d:\n%s", code, out)
	}
}

// A *.allow entry that is a symlink resolves inside the image too.
func TestRunAllowFileSymlinkResolvedInImage(t *testing.T) {
	root := fixtureRoot(t)
	os.MkdirAll(filepath.Join(root, "opt/vendor"), 0o755)
	os.WriteFile(filepath.Join(root, "opt/vendor/in-image.allow"), []byte("/usr/bin/tool in-image-entry\n"), 0o644)
	dir := filepath.Join(root, "etc/fips-invariant-check/allow.d")
	os.MkdirAll(dir, 0o755)
	if err := os.Symlink("/opt/vendor/in-image.allow", filepath.Join(dir, "x.allow")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if code, out := runWith(t, nil, "-root", root); code != 0 || !strings.Contains(out, "in-image") {
		t.Fatalf("the in-image target must be loaded (its entry reported unused), got %d:\n%s", code, out)
	}
	if code, out := runWith(t, map[string]string{"FIPS_INVARIANT_STRICT": "1"}, "-root", root); code != 1 || !strings.Contains(out, "in-image.allow") {
		t.Fatalf("strict: a symlinked allow file is still an allow file, got %d:\n%s", code, out)
	}
	os.Symlink("/opt/vendor/missing.allow", filepath.Join(dir, "y.allow"))
	if code, out := runWith(t, nil, "-root", root); code != 2 || !strings.Contains(out, "dangling") {
		t.Fatalf("a dangling allow-file symlink must be an error, got %d:\n%s", code, out)
	}
}

// runnerLibssl returns the runner's libssl.so.3, a real dynamically linked library.
func runnerLibssl(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs the runner's libssl.so.3")
	}
	for _, d := range []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib", "/lib"} {
		if _, err := os.Stat(filepath.Join(d, "libssl.so.3")); err == nil {
			return filepath.Join(d, "libssl.so.3")
		}
	}
	t.Skip("libssl.so.3 not found")
	return ""
}

// retypeSection rewrites the sh_type of the first section of type from (ELF64 little-endian).
func retypeSection(t *testing.T, d []byte, from elf.SectionType, edit func(hdr []byte)) []byte {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(d))
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.ELFCLASS64 || f.ByteOrder != binary.LittleEndian {
		t.Skip("needs a 64-bit little-endian ELF")
	}
	shoff := binary.LittleEndian.Uint64(d[0x28:])
	for i, sec := range f.Sections {
		if sec.Type == from {
			edit(d[shoff+uint64(i)*64:][:64])
			return d
		}
	}
	t.Fatalf("no %v section", from)
	return nil
}

// A .dynamic whose section header is mislabelled still has its libraries read from PT_DYNAMIC, as
// the loader does; it must not read as statically linked. Section flags are not trusted to say
// "debug info" either: with SHF_EXECINSTR cleared everywhere it must still be read.
func TestAnalyzeMislabelledDynamicSection(t *testing.T) {
	src := runnerLibssl(t)
	patched := copyWith(t, src, func(d []byte) []byte {
		d = retypeSection(t, d, elf.SHT_DYNAMIC, func(h []byte) { binary.LittleEndian.PutUint32(h[4:], uint32(elf.SHT_PROGBITS)) })
		forEachSectionHeader(t, d, func(h []byte) {
			binary.LittleEndian.PutUint64(h[8:], binary.LittleEndian.Uint64(h[8:])&^uint64(elf.SHF_EXECINSTR))
		})
		return d
	})
	r, err := analyze(patched, "/usr/lib/libssl.so.3")
	if err != nil || r == nil || !slices.Contains(r.NeededCores, "libcrypto.so.3") {
		t.Fatalf("PT_DYNAMIC must still yield DT_NEEDED libcrypto.so.3, got %v %+v", err, r)
	}
}

// A broken dynamic symbol table is an error, not "stripped".
func TestAnalyzeBrokenDynamicSymbolTableIsAnError(t *testing.T) {
	src := runnerLibssl(t)
	patched := copyWith(t, src, func(d []byte) []byte {
		return retypeSection(t, d, elf.SHT_DYNSYM, func(h []byte) { binary.LittleEndian.PutUint32(h[40:], 0) })
	})
	if _, err := analyze(patched, "/usr/lib/libssl.so.3"); err == nil || !strings.Contains(err.Error(), "symbol table") {
		t.Fatalf("a broken .dynsym must be an error, got %v", err)
	}
}

// gccAndObjcopy returns gcc and objcopy, or skips.
func gccAndObjcopy(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs gcc and objcopy")
	}
	gcc, err1 := exec.LookPath("gcc")
	objcopy, err2 := exec.LookPath("objcopy")
	if err1 != nil || err2 != nil {
		t.Skip("gcc/objcopy not available")
	}
	return gcc, objcopy
}

func build(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, out)
	}
}

// The separate debug file of a library that defines RAND_bytes keeps the symbol (pointing at a
// NOBITS .text) but no runnable code; it must not fail as "defines its own RAND_bytes", in both
// segment layouts. The library itself must fail.
func TestAnalyzeDebugFileOfCryptoLibraryPasses(t *testing.T) {
	gcc, objcopy := gccAndObjcopy(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.c"), []byte("int RAND_bytes(unsigned char*b,int n){for(int i=0;i<n;i++)b[i]=i;return 1;}\n"), 0o644)
	for i, layout := range []string{"-Wl,-z,separate-code", "-Wl,-z,noseparate-code"} {
		lib := filepath.Join(dir, fmt.Sprintf("libfoo%d.so.1", i))
		build(t, gcc, "-shared", "-fPIC", "-g", layout, "-o", lib, filepath.Join(dir, "c.c"))
		dbg := lib + ".debug"
		build(t, objcopy, "--only-keep-debug", lib, dbg)
		if r, err := analyze(lib, "/opt/x/libfoo.so.1"); err != nil || embeddedReason(r) == "" {
			t.Fatalf("%s control: the library itself must fail, got %v %+v", layout, err, r)
		}
		r, err := analyze(dbg, "/usr/lib/debug/.build-id/ab/cdef.debug")
		if err != nil || r == nil || !r.NoCode || embeddedReason(r) != "" {
			t.Fatalf("%s: its debug file must hold no runnable code and pass, got %v %+v", layout, err, r)
		}
		// Weaken the program headers that make "no code" true: the file is then judged and fails.
		for name, edit := range map[string]func(ph []byte){
			"no PT_GNU_STACK": func(ph []byte) {
				if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_GNU_STACK {
					binary.LittleEndian.PutUint32(ph, uint32(elf.PT_NULL))
				}
			},
			"executable stack": func(ph []byte) {
				if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_GNU_STACK {
					binary.LittleEndian.PutUint32(ph[4:], binary.LittleEndian.Uint32(ph[4:])|uint32(elf.PF_X))
				}
			},
			"executable bytes beyond the headers": func(ph []byte) {
				if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_LOAD && binary.LittleEndian.Uint32(ph[4:])&uint32(elf.PF_X) != 0 {
					binary.LittleEndian.PutUint64(ph[32:], 0x400) // p_filesz
				}
			},
			"PT_DYNAMIC with bytes": func(ph []byte) {
				if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_DYNAMIC {
					binary.LittleEndian.PutUint64(ph[32:], 16) // p_filesz
				}
			},
		} {
			weak := copyWith(t, dbg, func(d []byte) []byte {
				phoff := binary.LittleEndian.Uint64(d[0x20:])
				phnum := binary.LittleEndian.Uint16(d[0x38:])
				for i := uint64(0); i < uint64(phnum); i++ {
					edit(d[phoff+i*56:][:56])
				}
				return d
			})
			r, err := analyze(weak, "/usr/lib/debug/.build-id/ab/cdef.debug")
			if err == nil && (r == nil || r.NoCode || embeddedReason(r) == "") {
				t.Errorf("%s, %s: must be judged and fail, got %+v", layout, name, r)
			}
		}
		// With noseparate-code the executable segment keeps the header bytes; an entry point inside
		// them would make them code, so it is judged. (With separate-code that segment has no file
		// bytes at all, and an entry point in the headers points at non-executable memory.)
		if layout != "-Wl,-z,noseparate-code" {
			continue
		}
		entry := copyWith(t, dbg, func(d []byte) []byte {
			binary.LittleEndian.PutUint64(d[0x18:], binary.LittleEndian.Uint64(d[0x20:])+8) // e_entry into the program headers
			return d
		})
		if r, err := analyze(entry, "/usr/lib/debug/x.debug"); err == nil && (r == nil || r.NoCode) {
			t.Errorf("%s: an entry point in the kept bytes must not count as no code, got %+v", layout, r)
		}
	}
}

// A data-only shared library (stock gcc, no executable segment) can still pull in an OpenSSL core
// when loaded: its DT_NEEDED must be recorded, whatever its code status.
func TestAnalyzeDataOnlyLibraryLinksRecorded(t *testing.T) {
	gcc, _ := gccAndObjcopy(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.c"), []byte("int RAND_bytes(unsigned char*b,int n){return 1;}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "data.c"), []byte("const int x = 1;\n"), 0o644)
	build(t, gcc, "-shared", "-fPIC", "-o", filepath.Join(dir, "libcrypto.so.1.1"), "-Wl,-soname,libcrypto.so.1.1", filepath.Join(dir, "c.c"))
	meta := filepath.Join(dir, "libmeta.so")
	build(t, gcc, "-shared", "-fPIC", "-nostdlib", "-o", meta, filepath.Join(dir, "data.c"), "-Wl,--no-as-needed", filepath.Join(dir, "libcrypto.so.1.1"))
	r, err := analyze(meta, "/usr/lib/libmeta.so")
	if err != nil || r == nil || !slices.Contains(r.NeededCores, "libcrypto.so.1.1") {
		t.Fatalf("a data-only library's DT_NEEDED core must be recorded, got %v %+v", err, r)
	}
}

// forEachSectionHeader calls fn with each 64-byte section header of a 64-bit little-endian ELF.
func forEachSectionHeader(t *testing.T, d []byte, fn func(h []byte)) {
	t.Helper()
	if d[4] != byte(elf.ELFCLASS64) || d[5] != byte(elf.ELFDATA2LSB) {
		t.Skip("needs a 64-bit little-endian ELF")
	}
	shoff := binary.LittleEndian.Uint64(d[0x28:])
	shnum := binary.LittleEndian.Uint16(d[0x3c:])
	for i := uint64(0); i < uint64(shnum); i++ {
		fn(d[shoff+i*64:][:64])
	}
}

// A runnable library whose section headers say "no code" (SHF_EXECINSTR cleared, .text retyped
// NOBITS) still has a loadable executable segment; it must be judged.
func TestAnalyzeForgedSectionsStillJudged(t *testing.T) {
	src := runnerLibssl(t)
	patched := copyWith(t, src, func(d []byte) []byte {
		forEachSectionHeader(t, d, func(h []byte) {
			if binary.LittleEndian.Uint64(h[8:])&uint64(elf.SHF_EXECINSTR) != 0 {
				binary.LittleEndian.PutUint32(h[4:], uint32(elf.SHT_NOBITS))
				binary.LittleEndian.PutUint64(h[8:], binary.LittleEndian.Uint64(h[8:])&^uint64(elf.SHF_EXECINSTR))
			}
		})
		return d
	})
	r, err := analyze(patched, "/usr/lib/libssl.so.3")
	if err != nil || r == nil || r.NoCode || !slices.Contains(r.NeededCores, "libcrypto.so.3") {
		t.Fatalf("forged section headers must not make a runnable library 'no code', got %v %+v", err, r)
	}
}

// An ELF the scanning user cannot read (a root-owned 0700 binary, with the check running as the
// image's USER) is uninspectable and fails the run; it is never skipped.
func TestRunUnreadableFileFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	root := fixtureRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "usr/bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "usr/bin/locked")
	os.WriteFile(locked, data, 0o755)
	os.Chmod(locked, 0o000)
	t.Cleanup(func() { os.Chmod(locked, 0o644) })
	if code, out := runWith(t, nil, "-root", root); code != 1 || !strings.Contains(out, "/usr/bin/locked") {
		t.Fatalf("an unreadable file must fail the run and be named, got %d:\n%s", code, out)
	}
}

func TestParseProbeTimeoutValues(t *testing.T) {
	for in, want := range map[string]time.Duration{"30s": 30 * time.Second, " 2m ": 2 * time.Minute} {
		if d, err := parseProbeTimeout(in); err != nil || d != want {
			t.Errorf("parseProbeTimeout(%q) = %v %v, want %v", in, d, err, want)
		}
	}
	for _, in := range []string{"0s", "-1m"} {
		if _, err := parseProbeTimeout(in); err == nil {
			t.Errorf("parseProbeTimeout(%q) must be an error", in)
		}
	}
}

// Only *.allow files in allow.d are exemptions: a parked x.allow.disabled must not apply.
func TestRunAllowDirIgnoresNonAllowFiles(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	data, _ := os.ReadFile(goFixture(t, "tponly"))
	os.WriteFile(filepath.Join(root, "usr/bin/app"), data, 0o755)
	dir := filepath.Join(root, "etc/fips-invariant-check/allow.d")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "x.allow.disabled"), []byte("/usr/bin/app parked-exemption\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "README"), []byte("not an allowlist\n"), 0o644)
	if code, out := runWith(t, nil, "-root", root); code != 1 || strings.Contains(out, "parked-exemption") {
		t.Fatalf("a non-.allow file must be ignored, got %d:\n%s", code, out)
	}
}

// The reject-everything side of the gate: ordinary non-ELF files (scripts, text named like a
// library) are not uninspectable, and a clean image with them passes.
func TestRunNonELFFilesPass(t *testing.T) {
	root := fixtureRoot(t)
	script := "#!/bin/sh\n" + strings.Repeat("echo hello world from a perfectly ordinary script\n", 10)
	os.WriteFile(filepath.Join(root, "usr/bin/run.sh"), []byte(script), 0o755)
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/lib/libfake.so"), []byte(strings.Repeat("INPUT(-lc)\n", 20)), 0o644)
	if code, out := runWith(t, nil, "-root", root); code != 0 || strings.Contains(out, "could not be inspected") {
		t.Fatalf("non-ELF files must not fail a clean image, got %d:\n%s", code, out)
	}
}

// UPX also leaves its own section names (UPX0/UPX1) when section headers are kept.
func TestAnalyzeUPXWithSections(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	packed := copyWith(t, withCrypto, func(d []byte) []byte {
		copy(d[0x800:], "UPX!")
		return renameSection(t, d, ".text", "UPX0.")
	})
	if _, err := analyze(packed, "/usr/bin/svc"); err == nil || !strings.Contains(err.Error(), "packed") {
		t.Fatalf("a UPX-packed executable with UPX sections must be uninspectable, got %v", err)
	}
}

// With section headers stripped, a DT_STRTAB that points outside every loadable segment makes the
// file uninspectable; it must not read as "links nothing".
func TestAnalyzeStrtabOutsideSegments(t *testing.T) {
	src := runnerLibssl(t)
	bad := copyWith(t, src, func(d []byte) []byte {
		f, err := elf.NewFile(bytes.NewReader(d))
		if err != nil {
			t.Fatal(err)
		}
		if f.Class != elf.ELFCLASS64 || f.ByteOrder != binary.LittleEndian {
			t.Skip("needs a 64-bit little-endian ELF")
		}
		found := false
		for _, p := range f.Progs {
			if p.Type != elf.PT_DYNAMIC {
				continue
			}
			for o := p.Off; o+16 <= p.Off+p.Filesz; o += 16 {
				if elf.DynTag(binary.LittleEndian.Uint64(d[o:])) == elf.DT_STRTAB {
					binary.LittleEndian.PutUint64(d[o+8:], 0x7fff_0000_0000)
					found = true
				}
			}
		}
		if !found {
			t.Fatal("no DT_STRTAB")
		}
		binary.LittleEndian.PutUint64(d[0x28:], 0) // e_shoff
		binary.LittleEndian.PutUint16(d[0x3c:], 0) // e_shnum
		binary.LittleEndian.PutUint16(d[0x3e:], 0) // e_shstrndx
		return d
	})
	if _, err := analyze(bad, "/usr/lib/libssl.so.3"); err == nil || !strings.Contains(err.Error(), "string table") {
		t.Fatalf("an unlocatable dynamic string table must be an error, got %v", err)
	}
}

// A NoCode report is never a violation of its own, whatever else it carries.
func TestEmbeddedReasonNoCode(t *testing.T) {
	r := &fileReport{Path: "/usr/lib/debug/x.debug", NoCode: true, Defines: []string{"RAND_bytes"}}
	if reason := embeddedReason(r); reason != "" {
		t.Fatalf("a file with no runnable code must not be judged, got %q", reason)
	}
}

// A read error part-way through is an error, never a partial (and so "clean") scan.
func TestScanBytesReadErrorIsAnError(t *testing.T) {
	r := io.MultiReader(bytes.NewReader(make([]byte, 100)), iotest.ErrReader(errors.New("EIO")))
	if _, err := scanBytes(r, 64, 16); err == nil {
		t.Fatal("a read error must be returned")
	}
}

// A version string without the library's own source paths is not an embedded copy (git carries
// "OpenSSL x.y.z" text and links the system libcrypto dynamically, or not at all).
func TestAnalyzeVersionTextWithoutSourceIsNotEmbedded(t *testing.T) {
	_, withoutCrypto := goFixtures(t)
	marked := copyWith(t, withoutCrypto, func(d []byte) []byte { return append(d, []byte("\x00OpenSSL 3.6.4 1 Jul 2026\x00")...) })
	r, err := analyze(marked, "/usr/bin/tool")
	if err != nil || r == nil || len(r.Markers) == 0 || r.HasSource {
		t.Fatalf("want markers without HasSource, got %v %+v", err, r)
	}
}

// A .dynamic section whose string-table link is broken is an error: its DT_NEEDED cannot be read.
func TestAnalyzeUnreadableDynamicSectionIsAnError(t *testing.T) {
	src := runnerLibssl(t)
	bad := copyWith(t, src, func(d []byte) []byte {
		return retypeSection(t, d, elf.SHT_DYNAMIC, func(h []byte) { binary.LittleEndian.PutUint32(h[40:], 0) })
	})
	if _, err := analyze(bad, "/usr/lib/libssl.so.3"); err == nil {
		t.Fatal("an unreadable .dynamic must make the file uninspectable")
	}
}

// A .gopclntab read from the wrong place (here its section header points at the ELF header) parses
// as an empty table without error; it must make the file uninspectable, not "no crypto".
func TestAnalyzeUnrecognisedGoFunctionTable(t *testing.T) {
	withCrypto, _ := goFixtures(t)
	forged := copyWith(t, withCrypto, func(d []byte) []byte {
		f, err := elf.NewFile(bytes.NewReader(d))
		if err != nil {
			t.Fatal(err)
		}
		shoff := binary.LittleEndian.Uint64(d[0x28:])
		for i, sec := range f.Sections {
			if sec.Name == ".gopclntab" {
				binary.LittleEndian.PutUint64(d[shoff+uint64(i)*64+24:], 0) // sh_offset
				return d
			}
		}
		t.Fatal("fixture has no .gopclntab")
		return nil
	})
	if _, err := analyze(forged, "/usr/bin/svc"); err == nil || !strings.Contains(err.Error(), "unrecognised") {
		t.Fatalf("an unrecognisable Go function table must be an error, got %v", err)
	}
}

func TestBuildInfoErr(t *testing.T) {
	notGo := errors.New("not a Go executable")
	if err := buildInfoErr(false, notGo); err != nil {
		t.Errorf("no Go evidence + 'not a Go executable' is not Go, got %v", err)
	}
	if err := buildInfoErr(true, notGo); err == nil {
		t.Error("Go evidence with unreadable build info must be an error")
	}
	if err := buildInfoErr(false, errors.New("read /x: input/output error")); err == nil {
		t.Error("any other build-info error must be an error")
	}
}

func TestEvaluateNotesNoCodeFiles(t *testing.T) {
	r := &fileReport{Path: "/usr/lib/debug/.build-id/ab/cdef.debug", NoCode: true}
	failed, out := evalOut(t, evalInput{reports: []*fileReport{r}})
	if failed || !strings.Contains(out, "hold no runnable code") || !strings.Contains(out, r.Path) {
		t.Fatalf("a NoCode file must be noted by path and not fail, got failed=%v:\n%s", failed, out)
	}
}

func TestRunMalformedAllowFileIsUsageError(t *testing.T) {
	root := fixtureRoot(t)
	dir := filepath.Join(root, "etc/fips-invariant-check/allow.d")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "bad.allow"), []byte("/usr/bin/tool\n"), 0o644) // no reason
	if code, out := runWith(t, nil, "-root", root); code != 2 || !strings.Contains(out, "bad.allow:1") {
		t.Fatalf("a malformed allow file must be exit 2 naming the line, got %d:\n%s", code, out)
	}
}

// Provider and engine directories are exempt by exact directory, not by name prefix.
func TestProviderDirBoundary(t *testing.T) {
	ok := &fileReport{Path: "/usr/lib/ossl-modules/fips.so", Defines: []string{"RAND_bytes"}}
	if r := embeddedReason(ok); r != "" {
		t.Errorf("the provider dir is exempt, got %q", r)
	}
	for _, p := range []string{"/usr/lib/ossl-modules-vendor/evil.so", "/usr/lib/engines-3x/evil.so"} {
		if embeddedReason(&fileReport{Path: p, Defines: []string{"RAND_bytes"}}) == "" {
			t.Errorf("%s is not a provider dir and must fail", p)
		}
	}
}

// The 32-bit paths: a hand-built ELFCLASS32 file with only program headers and a PT_DYNAMIC that
// needs libcrypto.so.3.
func TestDynamicFromProgs32Bit(t *testing.T) {
	const ehsize, phsize = 52, 32
	strtab := "\x00libcrypto.so.3\x00"
	dynOff := uint32(ehsize + 2*phsize)
	dyn := []uint32{uint32(elf.DT_NEEDED), 1, uint32(elf.DT_STRTAB), dynOff + 32, uint32(elf.DT_STRSZ), uint32(len(strtab)), uint32(elf.DT_NULL), 0}
	size := dynOff + 32 + uint32(len(strtab))
	b := make([]byte, size)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = byte(elf.ELFCLASS32), byte(elf.ELFDATA2LSB), 1
	le := binary.LittleEndian
	le.PutUint16(b[16:], uint16(elf.ET_DYN))
	le.PutUint16(b[18:], uint16(elf.EM_386))
	le.PutUint32(b[20:], 1)
	le.PutUint32(b[28:], ehsize) // e_phoff
	le.PutUint16(b[40:], ehsize)
	le.PutUint16(b[42:], phsize)
	le.PutUint16(b[44:], 2)
	ph := func(i int, typ elf.ProgType, off, filesz uint32, flags elf.ProgFlag) {
		p := b[ehsize+i*phsize:]
		le.PutUint32(p[0:], uint32(typ))
		le.PutUint32(p[4:], off)
		le.PutUint32(p[8:], off) // vaddr == offset
		le.PutUint32(p[16:], filesz)
		le.PutUint32(p[20:], filesz)
		le.PutUint32(p[24:], uint32(flags))
	}
	ph(0, elf.PT_LOAD, 0, size, elf.PF_R)
	ph(1, elf.PT_DYNAMIC, dynOff, 32, elf.PF_R)
	for i, v := range dyn {
		le.PutUint32(b[dynOff+uint32(i)*4:], v)
	}
	copy(b[dynOff+32:], strtab)
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if end := headerEnd(f, b); end != ehsize+2*phsize {
		t.Errorf("headerEnd = %d, want %d", end, ehsize+2*phsize)
	}
	needed, _, err := dynamicFromProgs(f, bytes.NewReader(b))
	if err != nil || !slices.Equal(needed, []string{"libcrypto.so.3"}) {
		t.Fatalf("want DT_NEEDED [libcrypto.so.3], got %v %v", needed, err)
	}
}
