package main

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
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

func goFixtures(t *testing.T) (withCrypto, withoutCrypto string) {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fic-fixtures-")
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureDir = dir
		progs := map[string]string{
			"crypto":   "package main\nimport (\"crypto/sha256\";\"fmt\")\nfunc main(){fmt.Println(sha256.Sum256([]byte(\"x\")))}\n",
			"nocrypto": "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello\")}\n",
		}
		for name, src := range progs {
			pd := filepath.Join(dir, "src-"+name)
			if err := os.MkdirAll(pd, 0o755); err != nil {
				fixtureErr = err
				return
			}
			os.WriteFile(filepath.Join(pd, "go.mod"), []byte("module fixture\ngo 1.24\n"), 0o644)
			os.WriteFile(filepath.Join(pd, "main.go"), []byte(src), 0o644)
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", filepath.Join(dir, name), ".")
			cmd.Dir = pd
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=")
			if out, err := cmd.CombinedOutput(); err != nil {
				fixtureErr = &buildErr{string(out), err}
				return
			}
		}
	})
	if fixtureErr != nil {
		t.Fatalf("building Go fixtures: %v", fixtureErr)
	}
	return filepath.Join(fixtureDir, "crypto"), filepath.Join(fixtureDir, "nocrypto")
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
