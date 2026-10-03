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

// cryptoLibMarker names a crypto library. On its own it proves nothing: git carries
// "OpenSSL 3.6.4" only as text for `git version --build-options` and links no crypto at all.
var cryptoLibMarker = regexp.MustCompile(`OpenSSL [0-9]+\.[0-9]+\.[0-9]+|BoringSSL|AWS-LC|LibreSSL [0-9]`)

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
// does not remove) and reports (a) whether it has any standard-library or x/crypto crypto
// compiled in, and (b) which golang.org/x/crypto packages that implement crypto THEMSELVES it
// links. It reads compiled functions, not bytes: a byte search for "crypto/..." matches binaries
// that merely contain such text (this tool's own patterns, an error message).
//
// (b) matters even for a FIPS-built binary: those packages run outside both validated modules,
// and neither fips140=on nor fips140=only governs them. Only module-path symbols count. The
// standard library vendors x/crypto (vendor/golang.org/x/crypto/chacha20poly1305 backs crypto/tls's
// ChaCha20 suites), so every Go TLS binary carries vendor/ copies; FIPS mode refuses those suites.
func goCrypto(f *elf.File) (uses bool, unvalidated []string, err error) {
	pcln := f.Section(".gopclntab")
	if pcln == nil {
		pcln = f.Section(".data.rel.ro.gopclntab") // some PIE layouts
	}
	text := f.Section(".text")
	if pcln == nil || text == nil {
		return false, nil, errors.New("Go binary without a readable function table (.gopclntab)")
	}
	data, err := pcln.Data()
	if err != nil {
		return false, nil, fmt.Errorf("reading .gopclntab: %v", err)
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return false, nil, fmt.Errorf("parsing .gopclntab: %v", err)
	}
	pkgs := map[string]bool{}
	for _, fn := range tab.Funcs {
		if isCryptoFunc(fn.Name) {
			uses = true
		}
		if p, ok := xcryptoPrimitive(fn.Name); ok {
			pkgs[p] = true
		}
	}
	return uses, slices.Sorted(maps.Keys(pkgs)), nil
}

// isCryptoFunc: a function in a standard-library crypto package, such as "crypto/sha256.Sum256"
// or "crypto/internal/fips140/aes.(*Block).Encrypt", or in the golang.org/x/crypto module.
func isCryptoFunc(name string) bool {
	return strings.HasPrefix(name, "crypto/") || strings.HasPrefix(name, "golang.org/x/crypto/")
}

// xcryptoPrimitives are the golang.org/x/crypto packages that implement cryptography themselves.
// Packages that only wrap the standard library (sha3, ed25519, curve25519, hkdf) or do no crypto
// (cryptobyte) are deliberately absent. ssh and openpgp carry their own cipher implementations.
var xcryptoPrimitives = map[string]bool{
	"argon2": true, "bcrypt": true, "blake2b": true, "blake2s": true, "blowfish": true,
	"bn256": true, "cast5": true, "chacha20": true, "chacha20poly1305": true, "md4": true,
	"nacl": true, "openpgp": true, "otr": true, "pbkdf2": true, "pkcs12": true, "poly1305": true,
	"ripemd160": true, "salsa20": true, "scrypt": true, "ssh": true, "tea": true, "twofish": true,
	"xtea": true, "xts": true,
}

// xcryptoPrimitive returns the x/crypto package of a module-path function in xcryptoPrimitives.
// vendor/golang.org/x/crypto/... (the standard library's own copy) never matches.
func xcryptoPrimitive(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "golang.org/x/crypto/")
	if !ok {
		return "", false
	}
	top := rest
	if i := strings.IndexAny(rest, "/."); i >= 0 {
		top = rest[:i]
	}
	if !xcryptoPrimitives[top] && !strings.HasPrefix(rest, "internal/poly1305") {
		return "", false
	}
	pkg := rest
	if i := strings.Index(rest, "."); i >= 0 {
		pkg = rest[:i]
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
var providerDirs = []string{"/usr/lib/ossl-modules", "/usr/lib64/ossl-modules", "/usr/lib/engines-3"}

// skipDirs are virtual filesystems, never image content.
var skipDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true}

type fileReport struct {
	Path          string   // absolute path inside the image
	Soname        string   // DT_SONAME, if any
	NeededCores   []string // libcrypto.so.N / libssl.so.N this file links
	Defines       []string // crypto entry points this file defines (any binding)
	Markers       []string // crypto-library version markers found in the bytes
	HasSource     bool     // the bytes also carry the library's own source paths (compiled-in copy)
	IsGo          bool
	GoFIPS        bool     // built on one of the two accepted routes (see goFIPSMode)
	GoCrypto      bool     // Go binary that uses standard-library or x/crypto crypto
	GoUnvalidated []string // x/crypto packages that implement crypto themselves (outside both modules)
	GoBuildNote   string   // the settings that decided GoFIPS, for the report
}

// scan walks root and analyzes every ELF file. Anything it cannot inspect is returned in
// unscanned ("<image path>: <why>"); the caller fails on it. It returns an error when the scan
// cannot mean anything: the root itself is unreadable, or it holds no ELF file at all (a wrong
// -root, or an empty mount, would otherwise read as a clean image).
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

	seen := map[string]bool{}
	for _, get := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := get()
		if err != nil {
			continue // stripped: no .symtab; the byte scan's markers cover this case
		}
		for _, s := range syms {
			if cryptoSymbols[s.Name] && s.Section != elf.SHN_UNDEF {
				seen[s.Name] = true
			}
		}
	}
	r.Defines = slices.Sorted(maps.Keys(seen))
	r.Markers = slices.Sorted(maps.Keys(facts.markers))
	r.HasSource = len(r.Markers) > 0 && facts.source

	// Is it Go? Decided independently of debug/buildinfo, which reports a damaged or relocated
	// build-info blob as "not a Go executable": that would let a crypto-using Go binary skip the
	// Go rule. A Go section or the build-info magic makes it Go; then its build info must parse.
	goLike := f.Section(".gopclntab") != nil || f.Section(".go.buildinfo") != nil || facts.goMagic
	bi, biErr := buildinfo.Read(fh)
	switch {
	case biErr == nil:
		r.IsGo = true
		r.GoFIPS, r.GoBuildNote = goFIPSMode(bi)
		if r.GoCrypto, r.GoUnvalidated, err = goCrypto(f); err != nil {
			return nil, err
		}
	case goLike:
		return nil, fmt.Errorf("Go binary whose build info cannot be read: %v", biErr)
	case !strings.Contains(biErr.Error(), "not a Go executable"):
		return nil, fmt.Errorf("Go build info unreadable: %v", biErr)
	}
	return r, nil
}

func hasSectionPrefix(f *elf.File, prefix string) bool {
	return slices.ContainsFunc(f.Sections, func(s *elf.Section) bool { return strings.HasPrefix(s.Name, prefix) })
}

// dynamicInfo returns the DT_NEEDED entries and DT_SONAME. debug/elf finds the dynamic table only
// through section headers; the loader uses the program headers (PT_DYNAMIC). A binary stripped of
// ALL its section headers would otherwise hide every library it links, so it falls back to
// PT_DYNAMIC, but only then.
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
	if len(f.Sections) > 0 {
		// Section headers are present but none is an in-file dynamic table: a separate debug-info
		// file (.debug/.debuginfo, where .dynamic is NOBITS), or a static binary. Its program
		// headers describe data that is not in this file, so there is nothing to read.
		return nil, "", nil
	}
	// No section headers at all: stripped with --strip-section-headers. The loader still uses
	// PT_DYNAMIC, so read the libraries from there.
	return dynamicFromProgs(f, r)
}

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
	if !ok || strsz == 0 || strsz > 64<<20 {
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
		if p.Type == elf.PT_LOAD && vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
			return p.Off + (vaddr - p.Vaddr), true
		}
	}
	return 0, false
}

const (
	scanChunk   = 16 << 20 // bytes per read: memory stays bounded however large the file
	scanOverlap = 4 << 10  // carried between chunks; longer than any pattern, so none is split
)

var (
	goBuildInfoMagic = []byte("\xff Go buildinf:")
	upxMagic         = []byte("UPX!")
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
	set := map[string]string{}
	var notes []string
	for _, s := range bi.Settings {
		set[s.Key] = s.Value
		switch s.Key {
		case "GOFIPS140", "DefaultGODEBUG", "-tags", "GOEXPERIMENT", "CGO_ENABLED",
			"chainguard_cryptographic_module", "chainguard_entropy_source":
			notes = append(notes, s.Key+"="+s.Value)
		}
	}
	has := func(key, item string) bool { return slices.Contains(strings.Split(set[key], ","), item) }
	native := validatedGoFIPS140.MatchString(set["GOFIPS140"]) &&
		(has("DefaultGODEBUG", "fips140=on") || has("DefaultGODEBUG", "fips140=only")) &&
		set["chainguard_cryptographic_module"] == "geomys" &&
		set["chainguard_entropy_source"] == "geomys"
	viaOpenSSL := has("-tags", "requirefips") && has("GOEXPERIMENT", "systemcrypto") && set["CGO_ENABLED"] == "1"
	return native || viaOpenSSL, strings.Join(notes, " ")
}

func inDir(p string, dirs []string) bool {
	return slices.ContainsFunc(dirs, func(d string) bool { return strings.HasPrefix(p, d+"/") })
}

// systemCoreMajor returns the OpenSSL major ("3", "4") if r IS a system libcrypto/libssl.
func systemCoreMajor(r *fileReport) (string, bool) {
	m := coreSoname.FindStringSubmatch(r.Soname)
	if m == nil || !systemLibDirs[path.Dir(r.Path)] {
		return "", false
	}
	return m[2], true
}

// embeddedReason explains why r does crypto outside a validated FIPS module, or returns "".
func embeddedReason(r *fileReport) string {
	if _, ok := systemCoreMajor(r); ok || inDir(r.Path, providerDirs) {
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
		return "Go binary built on a validated module but also linking golang.org/x/crypto code that implements crypto outside it (" + strings.Join(r.GoUnvalidated, ", ") + "); FIPS mode does not govern it"
	}
	if r.IsGo && r.GoCrypto && !r.GoFIPS {
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
