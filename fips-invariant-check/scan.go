package main

import (
	"debug/buildinfo"
	"debug/elf"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// cryptoSymbols are core entry points every OpenSSL-family library (OpenSSL, BoringSSL, AWS-LC,
// LibreSSL) DEFINES. A file that defines one carries its own crypto implementation. Version
// strings alone are not evidence: anything compiled against the system OpenSSL headers carries
// "OpenSSL x.y.z" text (Ruby's openssl.so, puma), while linking the system library.
var cryptoSymbols = map[string]bool{
	"RAND_bytes":          true,
	"EVP_DigestInit_ex":   true,
	"OPENSSL_init_crypto": true,
}

// cryptoLibMarker names a crypto library. On its own it proves nothing: git carries
// "OpenSSL 3.6.4" only as text for `git version --build-options` and links no crypto at all.
var cryptoLibMarker = regexp.MustCompile(`OpenSSL [0-9]+\.[0-9]+\.[0-9]+|BoringSSL|AWS-LC|LibreSSL [0-9]`)

// cryptoSourceMarker is what a compiled-in copy of the library leaves behind even when stripped:
// its own source paths in assert/error strings. Together with cryptoLibMarker it identifies an
// embedded copy in a binary whose symbols are gone.
var cryptoSourceMarker = regexp.MustCompile(`crypto/(evp|rand|fipsmodule|sha|bn|ec)/[a-z0-9_]+\.(c|cc)|ssl/(ssl_lib|s3_lib|t1_lib|ssl_cert)\.(c|cc)|third_party/boringssl/`)

// nssSonames are Mozilla NSS, a separate crypto stack (Chromium uses it), never the FIPS provider.
var nssSonames = map[string]bool{
	"libnss3.so": true, "libssl3.so": true, "libsmime3.so": true, "libfreebl3.so": true,
	"libfreeblpriv3.so": true, "libsoftokn3.so": true, "libnssckbi.so": true,
}

// otherCryptoLibs are independent crypto implementations, recognised by soname. They name their
// entry points differently (Heimdal's hcrypto exports hc_RAND_bytes / hc_EVP_DigestInit_ex), so
// the exact-name symbol check cannot see them. A generic "any prefix" match would false-positive
// on CPython's _ssl, which defines a local _ssl_RAND_bytes wrapper around the system OpenSSL.
var otherCryptoLibs = []struct {
	soname *regexp.Regexp
	name   string
}{
	{regexp.MustCompile(`^libhcrypto\.so(\.|$)`), "Heimdal hcrypto"},
	{regexp.MustCompile(`^libgcrypt\.so(\.|$)`), "libgcrypt"},
	{regexp.MustCompile(`^lib(nettle|hogweed)\.so(\.|$)`), "Nettle"},
	{regexp.MustCompile(`^libgnutls\.so(\.|$)`), "GnuTLS"},
	{regexp.MustCompile(`^libmbed(crypto|tls|x509)\.so(\.|$)`), "Mbed TLS"},
	{regexp.MustCompile(`^libwolfssl\.so(\.|$)`), "wolfSSL"},
}

// heimdalSymbols catch a Heimdal hcrypto copy that is not shipped under its own soname.
var heimdalSymbols = map[string]bool{"hc_RAND_bytes": true, "hc_EVP_DigestInit_ex": true}

// goCryptoMarker: function names a Go binary carries (in its pclntab, which stripping does not
// remove) when it does TLS or symmetric/hash crypto through the standard library.
var goCryptoMarker = regexp.MustCompile(`crypto/tls\.\(\*Conn\)\.Handshake|crypto/aes\.NewCipher|crypto/sha256\.Sum256`)

var coreSoname = regexp.MustCompile(`^lib(crypto|ssl)\.so\.([0-9]+)$`)

// vendoredCoreSoname: wheel/gem-vendored copies renamed by auditwheel-style tools
// (libcrypto-1a2b3c4d.so.3, libssl-5e6f.so.3).
var vendoredCoreSoname = regexp.MustCompile(`^lib(crypto|ssl)-[0-9a-f]+\.so(\.[0-9]+)*$`)

// systemLibDirs are where the distro's own OpenSSL lives. A libcrypto/libssl anywhere else (a
// wheel's .libs/, a gem's ports/) is a vendored copy, i.e. embedded crypto.
var systemLibDirs = map[string]bool{
	"/lib": true, "/lib64": true, "/usr/lib": true, "/usr/lib64": true,
	"/usr/lib/x86_64-linux-gnu": true, "/usr/lib/aarch64-linux-gnu": true,
}

// providerDirs hold OpenSSL provider modules (fips.so, legacy.so). They define crypto by design.
var providerDirs = []string{"/usr/lib/ossl-modules", "/usr/lib64/ossl-modules", "/usr/lib/engines-3"}

const maxMarkerScanBytes = 768 << 20

type fileReport struct {
	Path        string   // absolute path inside the image
	Soname      string   // DT_SONAME, if any
	NeededCores []string // libcrypto.so.N / libssl.so.N this file links
	Defines     []string // crypto entry points this file defines (any binding)
	Markers     []string // crypto-library version markers found in the bytes
	HasSource   bool     // the bytes also carry the library's own source paths (compiled-in copy)
	IsGo        bool
	GoFIPS      bool   // built with a FIPS crypto mode (GOFIPS140, boringcrypto, requirefips)
	GoCrypto    bool   // Go binary that uses standard-library crypto
	GoBuildNote string // the settings that decided GoFIPS, for the report
}

// analyze returns nil for non-ELF files.
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
		return nil, nil // corrupt or exotic ELF: not something a loader would map either
	}
	defer f.Close()

	r := &fileReport{Path: imagePath}
	if libs, err := f.ImportedLibraries(); err == nil {
		for _, l := range libs {
			if coreSoname.MatchString(l) {
				r.NeededCores = append(r.NeededCores, l)
			}
		}
	}
	if s, err := f.DynString(elf.DT_SONAME); err == nil && len(s) > 0 {
		r.Soname = s[0]
	}
	seen := map[string]bool{}
	for _, get := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := get()
		if err != nil {
			continue // stripped: no .symtab; the marker scan below covers this case
		}
		for _, s := range syms {
			if (cryptoSymbols[s.Name] || heimdalSymbols[s.Name]) && s.Section != elf.SHN_UNDEF && !seen[s.Name] {
				seen[s.Name] = true
				r.Defines = append(r.Defines, s.Name)
			}
		}
	}
	sort.Strings(r.Defines)

	if bi, err := buildinfo.ReadFile(realPath); err == nil {
		r.IsGo = true
		r.GoFIPS, r.GoBuildNote = goFIPSMode(bi)
	}

	if st, err := fh.Stat(); err == nil && st.Size() <= maxMarkerScanBytes {
		data, err := os.ReadFile(realPath)
		if err == nil {
			m := map[string]bool{}
			for _, b := range cryptoLibMarker.FindAll(data, -1) {
				m[string(b)] = true
			}
			for k := range m {
				r.Markers = append(r.Markers, k)
			}
			sort.Strings(r.Markers)
			r.HasSource = len(r.Markers) > 0 && cryptoSourceMarker.Match(data)
			if r.IsGo {
				r.GoCrypto = goCryptoMarker.Match(data)
			}
		}
	}
	return r, nil
}

// validatedGoFIPS140: a frozen, certified Go Cryptographic Module snapshot, which buildinfo
// records with its hash (GOFIPS140=v1.0.0 -> "v1.0.0-c2097c7c"). GOFIPS140=latest/inprocess
// build the UNVALIDATED in-tree module.
var validatedGoFIPS140 = regexp.MustCompile(`^v1\.0\.[0-9]+-`)

// goFIPSMode accepts exactly the two routes Jacob ruled valid on 2026-10-02 (INF-377). The values
// are real `go version -m` output from DU and upstream toolchains, collected by the Go-FIPS work:
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
// The chainguard_* lines are the toolchain's self-declared build settings, not proof. Whether
// entropy actually routes through the module is behavioural (the Go probe's job).
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
	has := func(key, item string) bool {
		for _, v := range strings.Split(set[key], ",") {
			if v == item {
				return true
			}
		}
		return false
	}
	native := validatedGoFIPS140.MatchString(set["GOFIPS140"]) &&
		(has("DefaultGODEBUG", "fips140=on") || has("DefaultGODEBUG", "fips140=only")) &&
		set["chainguard_cryptographic_module"] == "geomys" &&
		set["chainguard_entropy_source"] == "geomys"
	viaOpenSSL := has("-tags", "requirefips") && has("GOEXPERIMENT", "systemcrypto") && set["CGO_ENABLED"] == "1"
	return native || viaOpenSSL, strings.Join(notes, " ")
}

func inDir(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// systemCoreMajor returns the OpenSSL major ("3", "4") if r IS a system libcrypto/libssl.
func systemCoreMajor(r *fileReport) (string, bool) {
	m := coreSoname.FindStringSubmatch(r.Soname)
	if m == nil || !systemLibDirs[path.Dir(r.Path)] {
		return "", false
	}
	return m[2], true
}

// embeddedReason explains why r carries its own crypto implementation, or returns "".
func embeddedReason(r *fileReport) string {
	if _, ok := systemCoreMajor(r); ok || inDir(r.Path, providerDirs) {
		return ""
	}
	for _, l := range otherCryptoLibs {
		if l.soname.MatchString(r.Soname) {
			return l.name + " crypto library (" + r.Soname + "), a separate crypto stack outside a validated FIPS module"
		}
	}
	if nssSonames[r.Soname] {
		return "Mozilla NSS crypto library (" + r.Soname + "), a separate crypto stack outside the FIPS provider"
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
	if size < 64 {
		return false
	}
	return !strings.HasSuffix(name, ".py") // trivially common, never ELF
}
