package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatalf("a Go debug-info file must analyze cleanly, got %v", err)
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

// A probe whose child outlives it, holding the output pipe, must still be cut off at the timeout.
func TestRunProbeTimeoutKillsChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	var out bytes.Buffer
	start := time.Now()
	err := runProbe([]string{"sh", "-c", "sleep 600 & sleep 600"}, &out, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout, got %v", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("the probe's children kept the run alive for %s", d)
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
