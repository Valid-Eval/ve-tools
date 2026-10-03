package main

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Real linux/amd64 Go binaries, built once per test run, so the analysis is exercised on actual
// ELF files on any host OS.
var (
	fixtureOnce sync.Once
	fixtureDir  string
	fixtureErr  error
)

// xcModule is a stand-in golang.org/x/crypto (wired in with a replace directive, so no network):
// sha3.New256 is a forwarding function the tool exempts, keccakF1600 an own implementation.
var xcModule = map[string]string{
	"xc/go.mod": "module golang.org/x/crypto\ngo 1.24\n",
	"xc/sha3/sha3.go": "package sha3\nimport std \"crypto/sha3\"\n" +
		"//go:noinline\nfunc New256(b []byte) []byte { s := std.Sum256(b); return s[:] }\n" +
		"//go:noinline\nfunc keccakF1600(a *[25]uint64) { for i := range a { a[i] ^= uint64(i) * 0x9e3779b9 } }\n" +
		"//go:noinline\nfunc Legacy(b []byte) uint64 { var a [25]uint64; a[0] = uint64(len(b)); keccakF1600(&a); return a[1] }\n",
}

// The required version is one at which sha3.New256 would be exempt, so only the replace directive
// (version unknown) keeps the forwarding function reported.
const xcGoMod = "module fixture\ngo 1.24\nrequire golang.org/x/crypto v0.57.0\nreplace golang.org/x/crypto => ./xc\n"

func goFixtures(t *testing.T) (withCrypto, withoutCrypto string) {
	t.Helper()
	return goFixture(t, "crypto"), goFixture(t, "nocrypto")
}

// goFixture returns the path of a built fixture: crypto, nocrypto, symtab (nocrypto with its
// symbol table kept), xwrap (std crypto plus only
// x/crypto forwarding functions) or xown (an x/crypto function with its own implementation).
func goFixture(t *testing.T, name string) string {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fic-fixtures-")
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureDir = dir
		plain := "module fixture\ngo 1.24\n"
		progs := map[string]map[string]string{
			"crypto":   {"go.mod": plain, "main.go": "package main\nimport (\"crypto/sha256\";\"fmt\")\nfunc main(){fmt.Println(sha256.Sum256([]byte(\"x\")))}\n"},
			"nocrypto": {"go.mod": plain, "main.go": "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello\")}\n"},
			"xwrap":    {"go.mod": xcGoMod, "main.go": "package main\nimport (\"fmt\";\"golang.org/x/crypto/sha3\")\nfunc main(){fmt.Println(sha3.New256([]byte(\"x\")))}\n"},
			"symtab":   {"go.mod": plain, "main.go": "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello\")}\n"},
			"xown":     {"go.mod": xcGoMod, "main.go": "package main\nimport (\"fmt\";\"golang.org/x/crypto/sha3\")\nfunc main(){fmt.Println(sha3.Legacy([]byte(\"x\")))}\n"},
		}
		for name, files := range progs {
			pd := filepath.Join(dir, "src-"+name)
			if strings.Contains(files["go.mod"], "replace") {
				for f, c := range xcModule {
					files[f] = c
				}
			}
			for f, c := range files {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(pd, f)), 0o755); err != nil {
					fixtureErr = err
					return
				}
				if err := os.WriteFile(filepath.Join(pd, f), []byte(c), 0o644); err != nil {
					fixtureErr = err
					return
				}
			}
			ldflags := "-ldflags=-s -w"
			if name == "symtab" {
				ldflags = "-ldflags=-w" // keeps .symtab
			}
			cmd := exec.Command("go", "build", "-trimpath", ldflags, "-o", filepath.Join(dir, name), ".")
			cmd.Dir = pd
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				fixtureErr = &buildErr{name + ": " + string(out), err}
				return
			}
		}
	})
	if fixtureErr != nil {
		t.Fatalf("building Go fixtures: %v", fixtureErr)
	}
	return filepath.Join(fixtureDir, name)
}

type buildErr struct {
	out string
	err error
}

func (e *buildErr) Error() string { return e.err.Error() + ": " + e.out }

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureDir != "" {
		os.RemoveAll(fixtureDir)
	}
	os.Exit(code)
}

// copyWith copies src to a new file in t.TempDir(), applying edit to its bytes.
func copyWith(t *testing.T, src string, edit func([]byte) []byte) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		data = edit(data)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// renameSection renames a section in the section-name string table only, so the section is no
// longer found by name while everything else in the file stays intact.
func renameSection(t *testing.T, data []byte, from, to string) []byte {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	shstr := f.Section(".shstrtab")
	if shstr == nil {
		t.Fatal("fixture has no .shstrtab")
	}
	region := data[shstr.Offset : shstr.Offset+shstr.Size]
	i := bytes.Index(region, []byte(from+"\x00"))
	if i < 0 || len(from) != len(to) {
		t.Fatalf("cannot rename %s", from)
	}
	copy(region[i:], to)
	return data
}

// fixtureRoot builds an image root holding the non-crypto Go fixture at /usr/bin/tool.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	_, nocrypto := goFixtures(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(nocrypto)
	if err := os.WriteFile(filepath.Join(root, "usr/bin/tool"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}
