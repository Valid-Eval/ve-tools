package main

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// cryptoSymbols are core entry points every OpenSSL-family library (OpenSSL, BoringSSL, AWS-LC,
// LibreSSL) DEFINES; Heimdal's hcrypto defines them under an hc_ prefix. A file that defines one
// carries its own crypto implementation. Version strings alone are not evidence: anything
// compiled against the system OpenSSL headers carries "OpenSSL x.y.z" text (Ruby's openssl.so,
// puma), while linking the system library. A generic "any prefix" match is deliberately not
// used: CPython's _ssl defines a local _ssl_RAND_bytes wrapper around the system OpenSSL.
var cryptoSymbols = map[string]bool{
	"RAND_bytes":           true,
	"EVP_DigestInit_ex":    true,
	"OPENSSL_init_crypto":  true,
	"hc_RAND_bytes":        true,
	"hc_EVP_DigestInit_ex": true,
}

// prefixedCryptoSymbol matches the version-prefixed symbols Rust's crypto crates give their
// bundled C/assembly, so two versions can link into one binary: aws-lc-rs (the rustls default
// provider) builds AWS-LC as aws_lc_<maj>_<min>_<patch>_RAND_bytes and so on, and ring prefixes
// every primitive ring_core_<maj>_<min>_<patch>_ (sometimes with a pre-release tag). Exact
// version-prefix forms only, so a local wrapper such as CPython's _ssl_RAND_bytes still passes.
var prefixedCryptoSymbol = regexp.MustCompile(`^aws_lc_[0-9]+_[0-9]+_[0-9]+_(RAND_bytes|EVP_DigestInit_ex|OPENSSL_init_crypto)$|^ring_core_[0-9]+_[0-9]+_[0-9]+(_[a-z0-9]+)?_`)

// cryptoLibMarker names a crypto library. On its own it proves nothing: git carries
// "OpenSSL 3.6.4" only as text for `git version --build-options` and links no crypto at all.
// aws-lc-sys builds carry no "AWS-LC" text, only the library's own source paths.
var cryptoLibMarker = regexp.MustCompile(`OpenSSL [0-9]+\.[0-9]+\.[0-9]+|BoringSSL|AWS-LC|LibreSSL [0-9]|aws-lc/crypto/fipsmodule`)

// cryptoSourceMarker is what a compiled-in copy of the library leaves behind even when stripped:
// its own source paths in assert/error strings. Together with cryptoLibMarker it identifies an
// embedded copy in a binary whose symbols are gone.
var cryptoSourceMarker = regexp.MustCompile(`crypto/(evp|rand|fipsmodule|sha|bn|ec)/[a-z0-9_]+\.(c|cc)|ssl/(ssl_lib|s3_lib|t1_lib|ssl_cert)\.(c|cc)|third_party/boringssl/`)

// otherCryptoLibs are independent crypto implementations, recognised by soname because they do
// not export the OpenSSL entry-point names.
var otherCryptoLibs = []struct {
	soname *regexp.Regexp
	name   string
}{
	{regexp.MustCompile(`^lib(nss3|ssl3|smime3|freebl3|freeblpriv3|softokn3|nssckbi)\.so$`), "Mozilla NSS"},
	{regexp.MustCompile(`^libhcrypto\.so(\.|$)`), "Heimdal hcrypto"},
	{regexp.MustCompile(`^libgcrypt\.so(\.|$)`), "libgcrypt"},
	{regexp.MustCompile(`^lib(nettle|hogweed)\.so(\.|$)`), "Nettle"},
	{regexp.MustCompile(`^libgnutls\.so(\.|$)`), "GnuTLS"},
	{regexp.MustCompile(`^libmbed(crypto|tls|x509)\.so(\.|$)`), "Mbed TLS"},
	{regexp.MustCompile(`^libwolfssl\.so(\.|$)`), "wolfSSL"},
}

// goCrypto reads a Go binary's function table (.gopclntab, which the runtime needs and stripping
// does not remove) and reports (a) whether it has any crypto compiled in, and (b) which
// golang.org/x/crypto packages and known third-party crypto modules that implement crypto
// THEMSELVES it links (counted in (a) too). It reads compiled functions, not bytes: a byte search for "crypto/..." matches binaries
// that merely contain such text (this tool's own patterns, an error message).
//
// (b) matters even for a FIPS-built binary: those packages run outside both validated modules,
// and neither fips140=on nor fips140=only governs them. Only module-path symbols count. The
// standard library vendors x/crypto (vendor/golang.org/x/crypto/chacha20poly1305 backs crypto/tls's
// ChaCha20 suites), so every Go TLS binary carries vendor/ copies; FIPS mode refuses those suites.
func goCrypto(f *elf.File, xcVersion string) (uses bool, unvalidated []string, err error) {
	tab, err := goFuncTable(f)
	if err != nil {
		return false, nil, err
	}
	pkgs := map[string]bool{}
	for _, fn := range tab.Funcs {
		if isCryptoFunc(fn.Name) {
			uses = true
		}
		if p, ok := xcryptoPrimitive(fn.Name, xcVersion); ok {
			pkgs[p] = true
		}
	}
	// Crypto from a listed third-party module is crypto use too: a binary whose only crypto is
	// BLAKE3 or circl links no crypto/... package, yet must not pass as crypto-free.
	return uses || len(pkgs) > 0, slices.Sorted(maps.Keys(pkgs)), nil
}

// pclntabMagics are the function-table header magics of the Go 1.2, 1.16, 1.18 and 1.20+ formats.
var pclntabMagics = []uint32{0xfffffffb, 0xfffffffa, 0xfffffff0, 0xfffffff1}

// goFuncTable finds and parses the Go function table. Executables keep it in its own .gopclntab
// section, but a PIE, c-shared or plugin build linked externally (the default with cgo, and for
// those build modes before Go 1.26) folds it into .data.rel.ro with no section of its own. There it
// is found by its header: the format magic, two zero bytes, the instruction quantum (1, 2 or 4)
// and the pointer size (4 or 8). A candidate counts only if it parses to a table holding runtime
// functions. gosym does not reject a table it cannot recognise (one read from the wrong place, say
// via a forged section header): it returns no functions, which would read as "no crypto". Every Go
// build mode links runtime functions, so a table without any was not really read.
func goFuncTable(f *elf.File) (*gosym.Table, error) {
	text := f.Section(".text")
	if text == nil {
		return nil, errors.New("Go binary without a .text section")
	}
	parse := func(data []byte) *gosym.Table {
		tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
		if err != nil || !slices.ContainsFunc(tab.Funcs, func(fn gosym.Func) bool { return strings.HasPrefix(fn.Name, "runtime.") }) {
			return nil
		}
		return tab
	}
	for _, name := range []string{".gopclntab", ".data.rel.ro.gopclntab"} {
		if sec := f.Section(name); sec != nil {
			data, err := sec.Data()
			if err != nil {
				return nil, fmt.Errorf("reading %s: %v", name, err)
			}
			if tab := parse(data); tab != nil {
				return tab, nil
			}
			return nil, fmt.Errorf("Go function table (%s) unrecognised: no runtime functions", name)
		}
	}
	sec := f.Section(".data.rel.ro")
	if sec == nil || sec.Type == elf.SHT_NOBITS || sec.Size > maxPclnSearch {
		return nil, errors.New("Go binary without a readable function table (.gopclntab)")
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("reading .data.rel.ro: %v", err)
	}
	for off := 0; off+8 <= len(data); off += 4 {
		h := data[off:]
		if !slices.Contains(pclntabMagics, f.ByteOrder.Uint32(h)) || h[4] != 0 || h[5] != 0 ||
			(h[6] != 1 && h[6] != 2 && h[6] != 4) || (h[7] != 4 && h[7] != 8) {
			continue
		}
		if tab := parse(h); tab != nil {
			return tab, nil
		}
	}
	return nil, errors.New("Go binary without a readable function table (no .gopclntab, none found in .data.rel.ro)")
}

// maxPclnSearch bounds the section read when searching for the function table.
const maxPclnSearch = 512 << 20

// isCryptoFunc: a function in a standard-library crypto package, such as "crypto/sha256.Sum256"
// or "crypto/internal/fips140/aes.(*Block).Encrypt", or in the golang.org/x/crypto module.
func isCryptoFunc(name string) bool {
	return strings.HasPrefix(name, "crypto/") || strings.HasPrefix(name, "golang.org/x/crypto/")
}

// xcryptoNoCrypto are golang.org/x/crypto packages that implement no cryptographic algorithm
// (encoding, protocol plumbing over the standard library). Every other x/crypto package counts as
// its own implementation unless xcryptoWrappers says otherwise, so a package added to x/crypto, or
// an old version of one, fails closed.
var xcryptoNoCrypto = map[string]bool{
	"cryptobyte": true, "cryptobyte/asn1": true, "internal/alias": true, "acme": true,
	"acme/autocert": true, "ocsp": true, "ssh/terminal": true,
}

// wrapperSpec: from which x/crypto version a package only forwards, and the functions that may.
type wrapperSpec struct {
	since string          // first x/crypto version in which these functions only forward
	funcs map[string]bool // the forwarding functions (package-relative names)
}

// xcryptoWrappers are x/crypto packages that only forward to the standard library from a given
// x/crypto version on, with the functions each may then contain. Before that version they carry
// their own implementation, often in the very same exported function (pbkdf2.Key ran its own
// HMAC loop until v0.51.0), so the exemption needs both the version and the function name. Any
// other function in the package, such as the legacy-Keccak sha3.(*state) methods, is its own
// implementation. hkdf is absent on purpose: it still runs its own Expand on crypto/hmac.
var xcryptoWrappers = map[string]wrapperSpec{
	"sha3": {since: "v0.44.0", funcs: set("New224", "New256", "New384", "New512", "Sum224", "Sum256", "Sum384", "Sum512",
		"NewShake128", "NewShake256", "NewCShake128", "NewCShake256", "ShakeSum128", "ShakeSum256",
		"(*shakeWrapper).Read", "(*shakeWrapper).Clone", "(*shakeWrapper).Size", "(*shakeWrapper).Sum",
		"(*shakeWrapper).Write", "(*shakeWrapper).Reset", "(*shakeWrapper).BlockSize")},
	"pbkdf2":     {since: "v0.51.0", funcs: set("Key")},
	"ed25519":    {since: "v0.1.0", funcs: set("GenerateKey", "NewKeyFromSeed", "Sign", "Verify")},
	"curve25519": {since: "v0.8.0", funcs: set("ScalarMult", "ScalarBaseMult", "X25519", "x25519")},
}

// xcryptoVersion is the golang.org/x/crypto version the binary was built with, or "" when it is
// unknown or replaced (a replacement is not the upstream code that version names).
func xcryptoVersion(bi *buildinfo.BuildInfo) string {
	for _, d := range bi.Deps {
		if d.Path == "golang.org/x/crypto" {
			if d.Replace != nil {
				return ""
			}
			return d.Version
		}
	}
	return ""
}

// versionAtLeast reports whether module version v is at least floor (both vMAJOR.MINOR.PATCH).
// A pre-release or pseudo-version (v0.51.0-rc.1, v0.51.0-0.2025...-abc) is a commit BEFORE its
// base version, so it counts only when its base is strictly greater than floor. Anything
// unparseable is not "at least": the exemption it would grant is withheld.
func versionAtLeast(v, floor string) bool {
	parse := func(s string) (n [3]int, pre bool, ok bool) {
		s, ok = strings.CutPrefix(s, "v")
		if !ok {
			return n, false, false
		}
		s, _, pre = strings.Cut(s, "-")
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			return n, false, false
		}
		for i, p := range parts {
			x, err := strconv.Atoi(p)
			if err != nil {
				return n, false, false
			}
			n[i] = x
		}
		return n, pre, true
	}
	a, pre, ok1 := parse(v)
	b, _, ok2 := parse(floor)
	if !ok1 || !ok2 {
		return false
	}
	c := slices.Compare(a[:], b[:])
	return c > 0 || (c == 0 && !pre)
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// goClosureSuffix: compiler-generated closures and init functions, which belong to the function
// they are named after.
var goClosureSuffix = regexp.MustCompile(`(\.func[0-9]+|\.gowrap[0-9]+|\.deferwrap[0-9]+)+$`)

// thirdPartyGoCrypto are module paths outside golang.org/x/crypto that implement cryptography
// themselves. Like x/crypto primitives, they run outside the validated module.
var thirdPartyGoCrypto = []string{
	"filippo.io/edwards25519", "filippo.io/age", "github.com/cloudflare/circl",
	"github.com/ProtonMail/go-crypto", "lukechampine.com/blake3", "github.com/zeebo/blake3",
	"github.com/aead/chacha20", "gitlab.com/yawning/",
}

// xcryptoPrimitive returns the package of a function that implements crypto outside the standard
// library: an x/crypto function that is neither crypto-free nor a forwarding function at this
// x/crypto version, or a known third-party crypto module. vendor/golang.org/x/crypto/... (the standard library's own
// copy) never matches.
func xcryptoPrimitive(name, xcVersion string) (string, bool) {
	for _, m := range thirdPartyGoCrypto {
		if strings.HasPrefix(name, m) {
			return strings.TrimSuffix(m, "/"), true
		}
	}
	rest, ok := strings.CutPrefix(name, "golang.org/x/crypto/")
	if !ok {
		return "", false
	}
	// x/crypto package paths contain no ".", so the first one ends the package path. (Searching
	// for the last "/" instead would be misled by generic shape types such as [go.shape.*a/b.T].)
	pkg, fn, ok := strings.Cut(rest, ".")
	if !ok {
		return "", false
	}
	if xcryptoNoCrypto[pkg] {
		return "", false
	}
	fn = goClosureSuffix.ReplaceAllString(fn, "")
	if fn == "init" || strings.HasPrefix(fn, "init.") {
		return "", false // package initialisation: tables, not an algorithm being run
	}
	if w, ok := xcryptoWrappers[pkg]; ok && w.funcs[fn] && versionAtLeast(xcVersion, w.since) {
		return "", false
	}
	return "golang.org/x/crypto/" + pkg, true
}

var coreSoname = regexp.MustCompile(`^lib(crypto|ssl)\.so\.([0-9]+(?:\.[0-9]+)*)$`)

// vendoredCoreSoname: wheel/gem-vendored copies renamed by auditwheel-style tools
// (libcrypto-1a2b3c4d.so.3, libssl-5e6f.so.3).
var vendoredCoreSoname = regexp.MustCompile(`^lib(crypto|ssl)-[0-9a-f]+\.so(\.[0-9]+)*$`)

// systemLibDirs are where the distro's own OpenSSL lives. A libcrypto/libssl anywhere else (a
// wheel's .libs/, a gem's ports/) is a vendored copy, i.e. embedded crypto.
var systemLibDirs = map[string]bool{
	"/lib": true, "/lib64": true, "/usr/lib": true, "/usr/lib64": true,
	"/usr/lib/x86_64-linux-gnu": true, "/usr/lib/aarch64-linux-gnu": true,
}

// providerDirs hold OpenSSL provider modules (fips.so, legacy.so) and OpenSSL 3 engines. They
// define crypto by design and are loaded by the system core.
var providerDirs = []string{"/usr/lib/ossl-modules", "/usr/lib64/ossl-modules", "/usr/lib/engines-3",
	"/usr/lib/x86_64-linux-gnu/ossl-modules", "/usr/lib/aarch64-linux-gnu/ossl-modules"}

// skipDirs are virtual filesystems, never image content. /run is not one of them: it is not a
// mount during docker build, and what an image puts there ships with it.
var skipDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true}

type fileReport struct {
	Path          string   // absolute path inside the image
	Soname        string   // DT_SONAME, if any
	NeededCores   []string // libcrypto.so.N / libssl.so.N this file links
	Defines       []string // crypto entry points this file defines (any binding)
	Markers       []string // crypto-library version markers found in the bytes
	HasSource     bool     // the bytes also carry the library's own source paths (compiled-in copy)
	IsGo          bool
	GoFIPS        bool     // built on one of the two accepted routes (see goFIPSMode)
	GoCrypto      bool     // Go binary with any crypto compiled in (standard library, x/crypto, or GoUnvalidated)
	GoUnvalidated []string // non-standard-library packages whose own crypto it links (outside both modules); implies GoCrypto
	GoBuildNote   string   // the settings that decided GoFIPS, for the report
	NoCode        bool     // nothing in the file can run (separate debug info): its own code is not judged; its linked libraries still count
	// For an OpenSSL FIPS provider module (fips.so or fips-<version>.so, anywhere): the name and build-info
	// strings compiled into it, which rule 3 compares with the fleet baseline.
	ProviderNames, ProviderBuilds []string
}

// scan walks root and analyzes every ELF file. Anything it cannot inspect is returned in
// unscanned ("<image path>: <why>"); the caller fails on it. It returns an error when the scan
// cannot mean anything: the root itself is unreadable, or it holds nothing to inspect (no ELF file
// and no uninspectable path; a wrong -root, or an empty mount, would otherwise read as clean).
func scan(root, self string) (reports []*fileReport, unscanned []string, err error) {
	walkErr := filepath.WalkDir(root, func(real string, d fs.DirEntry, err error) error {
		ip := imagePath(root, real)
		if err != nil {
			if real == root {
				return err
			}
			unscanned = append(unscanned, fmt.Sprintf("%s: %v", ip, err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDirs[ip] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || (self != "" && real == self) {
			return nil // symlinks are reported through their targets
		}
		info, err := d.Info()
		if err != nil {
			unscanned = append(unscanned, fmt.Sprintf("%s: %v", ip, err))
			return nil
		}
		if !isELFCandidate(d.Name(), info.Size()) {
			return nil
		}
		r, err := analyze(real, ip)
		if err != nil {
			unscanned = append(unscanned, fmt.Sprintf("%s: %v", ip, err))
			return nil
		}
		if r != nil {
			reports = append(reports, r)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("scanning %s: %v", root, walkErr)
	}
	if len(reports) == 0 && len(unscanned) == 0 {
		return nil, nil, fmt.Errorf("no ELF files under %s: wrong -root?", root)
	}
	slices.SortFunc(reports, func(a, b *fileReport) int { return strings.Compare(a.Path, b.Path) })
	return reports, unscanned, nil
}

// analyze returns (nil, nil) for a file that is not ELF, and an error for one it cannot inspect.
func analyze(realPath, imagePath string) (*fileReport, error) {
	fh, err := os.Open(realPath)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var magic [4]byte
	if _, err := io.ReadFull(fh, magic[:]); err != nil || string(magic[:]) != "\x7fELF" {
		return nil, nil
	}
	f, err := elf.NewFile(fh)
	if err != nil {
		return nil, fmt.Errorf("ELF magic but unparseable: %v", err)
	}
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	facts, err := scanBytes(io.NewSectionReader(fh, 0, st.Size()), scanChunk, scanOverlap)
	if err != nil {
		return nil, fmt.Errorf("reading contents: %v", err)
	}
	// UPX, decided structurally: its "UPX!" header sits right after the program headers, and the
	// packed file has no section headers (or UPX-named ones). Text matching is not enough: any
	// binary can contain the string (this tool's own tests do).
	head := make([]byte, min(st.Size(), upxHeaderWindow))
	if _, err := fh.ReadAt(head, 0); err != nil {
		return nil, fmt.Errorf("reading header: %v", err)
	}
	if bytes.Contains(head, upxMagic) && (len(f.Sections) == 0 || hasSectionPrefix(f, "UPX")) {
		return nil, errors.New("packed executable (UPX): its real contents cannot be inspected")
	}
	// PyInstaller --onefile: the bundled libraries (often a wheel's own OpenSSL) are compressed
	// into a "pydata" section (objcopy --add-section, PyInstaller/building/api.py) or, in older
	// versions, appended to the file, and extracted only at run time. The archive ends with its
	// cookie, so an appended one puts the cookie in the file's last bytes; the magic elsewhere
	// is just text (this tool's own binary carries it).
	tail := make([]byte, min(st.Size(), pyiTailWindow))
	if _, err := fh.ReadAt(tail, st.Size()-int64(len(tail))); err != nil {
		return nil, fmt.Errorf("reading trailer: %v", err)
	}
	if f.Section("pydata") != nil || bytes.Contains(tail, pyiCookieMagic) {
		return nil, errors.New("PyInstaller one-file bundle: its packed libraries cannot be inspected")
	}

	r := &fileReport{Path: imagePath}
	needed, soname, err := dynamicInfo(f, fh)
	if err != nil {
		return nil, err
	}
	for _, l := range needed {
		if coreSoname.MatchString(l) {
			r.NeededCores = append(r.NeededCores, l)
		}
	}
	r.Soname = soname
	// Linked libraries are always recorded (above). What follows judges the file's own code, so it
	// is skipped when nothing in the file can run: separate debug info (objcopy --only-keep-debug,
	// -dbgsym/.debug packages) keeps the symbol table and DWARF, and judging its symbols would
	// fail every image that installs debug symbols for the system libcrypto.
	if noLoadableCode(f, headerEnd(f, head)) {
		r.NoCode = true
		return r, nil
	}

	seen := map[string]bool{}
	for _, get := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := get()
		if errors.Is(err, elf.ErrNoSymbols) {
			continue // no table of this kind; the byte-scan markers cover stripped embedded copies
		}
		if err != nil {
			return nil, fmt.Errorf("reading symbol table: %v", err)
		}
		for _, s := range syms {
			if s.Section == elf.SHN_UNDEF {
				continue
			}
			switch {
			case cryptoSymbols[s.Name]:
				seen[s.Name] = true
			case strings.HasPrefix(s.Name, "ring_core_") && prefixedCryptoSymbol.MatchString(s.Name):
				seen["ring_core_* (ring)"] = true // one label for ring's hundreds of primitives
			case prefixedCryptoSymbol.MatchString(s.Name):
				seen[s.Name] = true
			}
		}
	}
	r.Defines = slices.Sorted(maps.Keys(seen))
	r.Markers = slices.Sorted(maps.Keys(facts.markers))
	r.HasSource = len(r.Markers) > 0 && facts.source
	if isProviderModule(imagePath) {
		if r.ProviderNames, r.ProviderBuilds, err = providerIdentity(realPath); err != nil {
			return nil, fmt.Errorf("reading FIPS provider identity: %v", err)
		}
	}

	// Is it Go? Decided independently of debug/buildinfo, which reports a damaged or relocated
	// build-info blob as "not a Go executable": that would let a crypto-using Go binary skip the
	// Go rule. A Go section or the build-info magic makes it Go; then its build info must parse.
	// A section counts only when its bytes are in the file: in a separate debug-info file
	// (objcopy --only-keep-debug) they are SHT_NOBITS and there is no code to judge.
	goLike := inFile(f.Section(".gopclntab")) || inFile(f.Section(".go.buildinfo")) || facts.goMagic
	bi, biErr := buildinfo.Read(fh)
	if biErr != nil {
		if err := buildInfoErr(goLike, biErr); err != nil {
			return nil, err
		}
		return r, nil // not Go
	}
	r.IsGo = true
	r.GoFIPS, r.GoBuildNote = goFIPSMode(bi)
	if r.GoCrypto, r.GoUnvalidated, err = goCrypto(f, xcryptoVersion(bi)); err != nil {
		return nil, err
	}
	return r, nil
}

// buildInfoErr decides what a build-info read failure means. Only debug/buildinfo's "not a Go
// executable", on a file with no other Go evidence, means "not Go"; anything else (damaged build
// info in a Go-looking file, an I/O error) makes the file uninspectable.
func buildInfoErr(goLike bool, biErr error) error {
	switch {
	case goLike:
		return fmt.Errorf("Go binary whose build info cannot be read: %v", biErr)
	case !strings.Contains(biErr.Error(), "not a Go executable"):
		return fmt.Errorf("Go build info unreadable: %v", biErr)
	}
	return nil
}

// noLoadableCode: nothing in the file can run, decided from the program headers the loader uses
// (section headers and flags can be carried falsely). All must hold:
//   - it has loadable segments, and no executable one (PF_X) has file bytes beyond its metadata
//     prefix: the ELF and program headers plus any notes right after them (objcopy
//     --only-keep-debug keeps those bytes of a segment that starts at offset 0, the usual layout
//     without -z separate-code), and the entry point does not lie in those bytes;
//   - it declares a non-executable stack (PT_GNU_STACK without PF_X); without one, or with an
//     executable one, a kernel may map every readable segment executable (READ_IMPLIES_EXEC);
//   - its dynamic table, if any, has no bytes in the file, so it cannot work as a loaded library.
//
// Separate debug info satisfies all three. Relocatable objects (no PT_LOAD) are not covered: their
// code is in sections and is judged.
func noLoadableCode(f *elf.File, hdrEnd uint64) bool {
	meta := metadataEnd(f, hdrEnd)
	loads, nxStack := 0, false
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			loads++
			if p.Flags&elf.PF_X == 0 || p.Filesz == 0 {
				continue
			}
			if p.Off != 0 || p.Filesz > meta {
				return false
			}
			if f.Entry != 0 && f.Entry >= p.Vaddr && f.Entry-p.Vaddr < p.Filesz {
				return false
			}
		case elf.PT_GNU_STACK:
			nxStack = p.Flags&elf.PF_X == 0
		case elf.PT_DYNAMIC:
			if p.Filesz > 0 {
				return false
			}
		}
	}
	return loads > 0 && nxStack
}

// metadataEnd extends the header end over PT_NOTE ranges that follow it without a gap.
func metadataEnd(f *elf.File, end uint64) uint64 {
	for grew := true; grew; {
		grew = false
		for _, p := range f.Progs {
			if p.Type == elf.PT_NOTE && p.Off <= end && p.Off+p.Filesz > end {
				end, grew = p.Off+p.Filesz, true
			}
		}
	}
	return end
}

// headerEnd is the file offset where the ELF header and program header table end (0 if unknown).
func headerEnd(f *elf.File, head []byte) uint64 {
	var phoff, entsize, num uint64
	switch {
	case f.Class == elf.ELFCLASS64 && len(head) >= 0x3a:
		phoff = f.ByteOrder.Uint64(head[0x20:])
		entsize, num = uint64(f.ByteOrder.Uint16(head[0x36:])), uint64(f.ByteOrder.Uint16(head[0x38:]))
	case f.Class == elf.ELFCLASS32 && len(head) >= 0x2e:
		phoff = uint64(f.ByteOrder.Uint32(head[0x1c:]))
		entsize, num = uint64(f.ByteOrder.Uint16(head[0x2a:])), uint64(f.ByteOrder.Uint16(head[0x2c:]))
	default:
		return 0
	}
	return phoff + entsize*num
}

func inFile(s *elf.Section) bool { return s != nil && s.Type != elf.SHT_NOBITS }

func hasSectionPrefix(f *elf.File, prefix string) bool {
	return slices.ContainsFunc(f.Sections, func(s *elf.Section) bool { return strings.HasPrefix(s.Name, prefix) })
}

// dynamicInfo returns the DT_NEEDED entries and DT_SONAME. debug/elf finds the dynamic table only
// through section headers; the loader uses the program headers (PT_DYNAMIC). Whenever there is
// no in-file dynamic section, it falls back to PT_DYNAMIC, so headers that are stripped, missing
// or mislabelled cannot hide the libraries a file links.
func dynamicInfo(f *elf.File, r io.ReaderAt) ([]string, string, error) {
	if f.SectionByType(elf.SHT_DYNAMIC) != nil {
		needed, err := f.ImportedLibraries()
		if err != nil {
			return nil, "", fmt.Errorf("reading DT_NEEDED: %v", err)
		}
		so, err := f.DynString(elf.DT_SONAME)
		if err != nil {
			return nil, "", fmt.Errorf("reading DT_SONAME: %v", err)
		}
		soname := ""
		if len(so) > 0 {
			soname = so[0]
		}
		return needed, soname, nil
	}
	// No in-file dynamic section, but the loader ignores sections and uses PT_DYNAMIC: a file
	// stripped with --strip-section-headers, or one whose .dynamic header is missing or
	// mislabelled. Read the libraries from there (a static binary has no PT_DYNAMIC).
	return dynamicFromProgs(f, r)
}

// maxDynamic bounds what is read from header-supplied sizes, so a corrupt header fails the file
// instead of exhausting memory. Real dynamic tables and string tables are far smaller.
const maxDynamic = 64 << 20

func dynamicFromProgs(f *elf.File, r io.ReaderAt) ([]string, string, error) {
	var dyn *elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			dyn = p
		}
	}
	if dyn == nil {
		return nil, "", nil // statically linked
	}
	if dyn.Filesz == 0 {
		// The table is not in this file: a separate debug-info file (objcopy --only-keep-debug
		// keeps PT_DYNAMIC with a zero file size). Decided from the program header the loader
		// uses, not from section flags, which a file can carry falsely.
		return nil, "", nil
	}
	if dyn.Filesz > maxDynamic {
		return nil, "", fmt.Errorf("PT_DYNAMIC of %d bytes is implausible", dyn.Filesz)
	}
	data := make([]byte, dyn.Filesz)
	if _, err := dyn.ReadAt(data, 0); err != nil {
		return nil, "", fmt.Errorf("reading PT_DYNAMIC: %v", err)
	}
	ent := 8
	if f.Class == elf.ELFCLASS64 {
		ent = 16
	}
	var strtab, strsz, sonameOff uint64
	var neededOffs []uint64
	hasSoname := false
loop:
	for i := 0; i+ent <= len(data); i += ent {
		var tag, val uint64
		if f.Class == elf.ELFCLASS64 {
			tag, val = f.ByteOrder.Uint64(data[i:]), f.ByteOrder.Uint64(data[i+8:])
		} else {
			tag, val = uint64(f.ByteOrder.Uint32(data[i:])), uint64(f.ByteOrder.Uint32(data[i+4:]))
		}
		switch elf.DynTag(tag) {
		case elf.DT_NULL:
			break loop
		case elf.DT_STRTAB:
			strtab = val
		case elf.DT_STRSZ:
			strsz = val
		case elf.DT_NEEDED:
			neededOffs = append(neededOffs, val)
		case elf.DT_SONAME:
			sonameOff, hasSoname = val, true
		}
	}
	if len(neededOffs) == 0 && !hasSoname {
		return nil, "", nil
	}
	off, ok := vaddrToOffset(f, strtab)
	if !ok || strsz == 0 || strsz > maxDynamic {
		return nil, "", errors.New("PT_DYNAMIC string table cannot be located")
	}
	str := make([]byte, strsz)
	if _, err := r.ReadAt(str, int64(off)); err != nil {
		return nil, "", fmt.Errorf("reading dynamic string table: %v", err)
	}
	cstr := func(o uint64) (string, error) {
		if o >= uint64(len(str)) {
			return "", errors.New("dynamic string offset out of range")
		}
		end := bytes.IndexByte(str[o:], 0)
		if end < 0 {
			return "", errors.New("unterminated dynamic string")
		}
		return string(str[o : o+uint64(end)]), nil
	}
	var needed []string
	for _, o := range neededOffs {
		s, err := cstr(o)
		if err != nil {
			return nil, "", err
		}
		needed = append(needed, s)
	}
	soname := ""
	if hasSoname {
		var err error
		if soname, err = cstr(sonameOff); err != nil {
			return nil, "", err
		}
	}
	return needed, soname, nil
}

func vaddrToOffset(f *elf.File, vaddr uint64) (uint64, bool) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && vaddr >= p.Vaddr && vaddr-p.Vaddr < p.Filesz {
			return p.Off + (vaddr - p.Vaddr), true
		}
	}
	return 0, false
}

const (
	scanChunk   = 16 << 20 // bytes per read: memory stays bounded however large the file
	scanOverlap = 4 << 10  // carried between chunks; far longer than any realistic match, so none is split
)

var (
	goBuildInfoMagic = []byte("\xff Go buildinf:")
	// PyInstaller's archive cookie (PyInstaller/archive/writers.py _COOKIE_MAGIC_PATTERN).
	pyiCookieMagic = []byte("MEI\x0c\x0b\x0a\x0b\x0e")
)

// pyiTailWindow: how far from the end of the file an appended PyInstaller cookie can sit (the
// cookie is 88 bytes; the rest allows for trailing padding).
const pyiTailWindow = 4096

var (
	upxMagic = []byte("UPX!")
)

// upxHeaderWindow: how far into the file the UPX header can sit (it follows the program headers).
const upxHeaderWindow = 4096

type byteFacts struct {
	markers         map[string]bool
	source, goMagic bool
}

// scanBytes reads r once, in fixed chunks with an overlap, and records the byte-level evidence
// analyze needs. Nothing is skipped for size: an unread file would read as "no crypto".
func scanBytes(r io.Reader, chunk, overlap int) (byteFacts, error) {
	facts := byteFacts{markers: map[string]bool{}}
	buf := make([]byte, 0, chunk+overlap)
	tmp := make([]byte, chunk)
	for {
		n, err := io.ReadFull(r, tmp)
		buf = append(buf, tmp[:n]...)
		for _, m := range cryptoLibMarker.FindAll(buf, -1) {
			facts.markers[string(m)] = true
		}
		facts.source = facts.source || cryptoSourceMarker.Match(buf)
		facts.goMagic = facts.goMagic || bytes.Contains(buf, goBuildInfoMagic)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return facts, nil
		}
		if err != nil {
			return facts, err
		}
		if len(buf) > overlap {
			buf = append(buf[:0], buf[len(buf)-overlap:]...)
		}
	}
}

// validatedGoFIPS140: a frozen, certified Go Cryptographic Module snapshot, which buildinfo
// records with its hash (GOFIPS140=v1.0.0 -> "v1.0.0-c2097c7c"). GOFIPS140=latest/inprocess
// build the UNVALIDATED in-tree module.
var validatedGoFIPS140 = regexp.MustCompile(`^v1\.0\.[0-9]+-`)

// goFIPSMode accepts exactly the two routes ruled valid on 2026-10-02 (INF-377), matched against
// real `go version -m` output from DU and upstream toolchains:
//
//	(A) Native Go Cryptographic Module (CMVP #5247), Chainguard build (DU go-fips >= 1.27):
//	    GOFIPS140 is a certified snapshot, fips140 is on by default, AND
//	    chainguard_cryptographic_module=geomys AND chainguard_entropy_source=geomys.
//	    Upstream Go with GOFIPS140=v1.0.0 has identical settings minus the chainguard_* lines and
//	    is REJECTED: its entropy comes from the kernel, outside the module boundary, and the
//	    certificate's caveat gives "no assurance of the minimum strength of generated SSPs".
//	(B) System OpenSSL (DU go-fips <= 1.26, Microsoft systemcrypto toolset):
//	    -tags requirefips AND GOEXPERIMENT systemcrypto AND CGO_ENABLED=1. Crypto goes through
//	    libcrypto -> the Chainguard FIPS provider (#5132); the binary refuses to start without
//	    it. It reports GOFIPS140=latest, so (B) must not be judged by GOFIPS140.
//
// The chainguard_* lines are the toolchain's self-declared build settings, not proof, and a
// runtime GODEBUG=fips140=off would switch FIPS mode off in a route (A) binary; neither is
// visible to a build-time scan.
func goFIPSMode(bi *buildinfo.BuildInfo) (bool, string) {
	settings := map[string]string{}
	var notes []string
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
		switch s.Key {
		case "GOFIPS140", "DefaultGODEBUG", "-tags", "GOEXPERIMENT", "CGO_ENABLED",
			"chainguard_cryptographic_module", "chainguard_entropy_source":
			notes = append(notes, s.Key+"="+s.Value)
		}
	}
	has := func(key, item string) bool { return slices.Contains(strings.Split(settings[key], ","), item) }
	native := validatedGoFIPS140.MatchString(settings["GOFIPS140"]) &&
		(has("DefaultGODEBUG", "fips140=on") || has("DefaultGODEBUG", "fips140=only")) &&
		settings["chainguard_cryptographic_module"] == "geomys" &&
		settings["chainguard_entropy_source"] == "geomys"
	viaOpenSSL := has("-tags", "requirefips") && has("GOEXPERIMENT", "systemcrypto") && settings["CGO_ENABLED"] == "1"
	return native || viaOpenSSL, strings.Join(notes, " ")
}

func inDir(p string, dirs []string) bool {
	return slices.ContainsFunc(dirs, func(d string) bool { return strings.HasPrefix(p, d+"/") })
}

// systemCoreVersion returns the core's soname version ("3", "4", or OpenSSL 1.x's dotted "1.1") if
// r IS a system libcrypto/libssl. That version is the core's identity.
func systemCoreVersion(r *fileReport) (string, bool) {
	m := coreSoname.FindStringSubmatch(r.Soname)
	if m == nil || !systemLibDirs[path.Dir(r.Path)] {
		return "", false
	}
	return m[2], true
}

// embeddedReason explains why r does crypto outside a validated FIPS module, or returns "".
func embeddedReason(r *fileReport) string {
	if r.NoCode {
		return "" // nothing in the file can run; only its linked libraries count (rule 1)
	}
	// A provider module outside providerDirs is exempted by evaluate() only once rule 3 has
	// matched its identity to an allowed build.
	if _, ok := systemCoreVersion(r); ok || inDir(r.Path, providerDirs) {
		return ""
	}
	for _, l := range otherCryptoLibs {
		if l.soname.MatchString(r.Soname) {
			return l.name + " crypto library (" + r.Soname + "), a separate crypto stack outside a validated FIPS module"
		}
	}
	if coreSoname.MatchString(r.Soname) || vendoredCoreSoname.MatchString(r.Soname) {
		return "vendored OpenSSL library outside the system lib dirs (soname " + r.Soname + ")"
	}
	if len(r.Defines) > 0 {
		return "defines its own " + strings.Join(r.Defines, ", ") + markerSuffix(r)
	}
	if r.HasSource && len(r.NeededCores) == 0 && !r.IsGo {
		return "carries a compiled-in crypto library (" + strings.Join(r.Markers, ", ") + ", with its source paths) and links no system libcrypto/libssl (stripped embedded copy)"
	}
	if r.IsGo && r.GoFIPS && len(r.GoUnvalidated) > 0 {
		return "Go binary built on a validated module but also running crypto code from outside the standard library (" + strings.Join(r.GoUnvalidated, ", ") + "); FIPS mode does not govern it"
	}
	if r.IsGo && (r.GoCrypto || len(r.GoUnvalidated) > 0) && !r.GoFIPS {
		return "Go binary whose crypto is not a validated FIPS module: needs the Chainguard native Go module build (certified GOFIPS140 snapshot + fips140=on + chainguard geomys module/entropy; CMVP #5247) or the system-OpenSSL route (requirefips + systemcrypto + CGO); has " + r.GoBuildNote
	}
	return ""
}

func markerSuffix(r *fileReport) string {
	if len(r.Markers) == 0 {
		return ""
	}
	return " (" + strings.Join(r.Markers, ", ") + ")"
}

// isELFCandidate cheaply skips files that cannot be ELF objects.
func isELFCandidate(name string, size int64) bool {
	return size >= 64 && !strings.HasSuffix(name, ".py") // .py: trivially common, never ELF
}
