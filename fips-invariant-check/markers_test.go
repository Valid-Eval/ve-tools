package main

import (
	"bytes"
	"io"
	"maps"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The marker patterns as of v0.5.1, when scanBytes ran each as one alternation. Copied here as
// literals, not read from the package vars, so a change to those vars cannot also change the
// reference they are checked against.
var (
	oracleLibMarker    = regexp.MustCompile(`OpenSSL [0-9]+\.[0-9]+\.[0-9]+|BoringSSL|AWS-LC|LibreSSL [0-9]|aws-lc/crypto/fipsmodule`)
	oracleSourceMarker = regexp.MustCompile(`crypto/(evp|rand|fipsmodule|sha|bn|ec)/[a-z0-9_]+\.(c|cc)|ssl/(ssl_lib|s3_lib|t1_lib|ssl_cert)\.(c|cc)|third_party/boringssl/`)
)

// oracleScanBytes is scanBytes as of v0.5.1.
func oracleScanBytes(r io.Reader, chunk, overlap int) (byteFacts, error) {
	facts := byteFacts{markers: map[string]bool{}}
	buf := make([]byte, 0, chunk+overlap)
	tmp := make([]byte, chunk)
	for {
		n, err := io.ReadFull(r, tmp)
		buf = append(buf, tmp[:n]...)
		for _, m := range oracleLibMarker.FindAll(buf, -1) {
			facts.markers[string(m)] = true
		}
		facts.source = facts.source || oracleSourceMarker.Match(buf)
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

// checkAgainstOracle fails unless scanBytes finds everything the oracle finds. It may find more:
// run per branch, a match overlapping another branch's match is also recorded ("BoringSSLibreSSL 3"
// gives LibreSSL 3 as well), which only makes a file fail. Each extra must still be a whole match
// of the original pattern.
func checkAgainstOracle(t *testing.T, data []byte, chunk, overlap int) {
	t.Helper()
	got, err := scanBytes(bytes.NewReader(data), chunk, overlap)
	want, werr := oracleScanBytes(bytes.NewReader(data), chunk, overlap)
	if (err == nil) != (werr == nil) {
		t.Fatalf("error mismatch: %v vs oracle %v", err, werr)
	}
	for m := range want.markers {
		if !got.markers[m] {
			t.Fatalf("marker %q missed (chunk %d, overlap %d): got %v, oracle %v", m, chunk, overlap,
				slices.Sorted(maps.Keys(got.markers)), slices.Sorted(maps.Keys(want.markers)))
		}
	}
	for m := range got.markers {
		if loc := oracleLibMarker.FindStringIndex(m); !want.markers[m] && (loc == nil || loc[0] != 0 || loc[1] != len(m)) {
			t.Fatalf("extra marker %q is not a match of the original pattern", m)
		}
	}
	if got.source != want.source || got.goMagic != want.goMagic {
		t.Fatalf("source/goMagic %v/%v, oracle %v/%v (chunk %d, overlap %d)", got.source, got.goMagic, want.source, want.goMagic, chunk, overlap)
	}
}

var oracleSeeds = []string{
	// each branch alone
	"OpenSSL 3.6.4", "BoringSSL", "AWS-LC", "LibreSSL 3", "aws-lc/crypto/fipsmodule",
	"crypto/evp/digest.c", "crypto/sha/sha256.cc", "ssl/ssl_lib.c", "ssl/s3_lib.cc", "ssl/t1_lib.c", "ssl/ssl_cert.c",
	"third_party/boringssl/src/crypto/x.c",
	// overlaps and repeats
	"BoringSSLibreSSL 3", "OpenSSL 1.2.3OpenSSL 4.5.6", "AWS-LCaws-lc/crypto/fipsmodule", "aws-lc/crypto/fipsmodule/bcm.c",
	"crypto/sha/sha256.ccrypto/bn/x.c", "LibreSSL LibreSSL 9", "OpenSSL 123.456.7890123",
	// invalid UTF-8 and split runes around a marker
	"\xffBoringSSL\xe2\x82", "\xe2BoringSSL", "Open\xffSSL 1.2.3", "OpenSSL 1.2.\xff3", "\xf0\x9f\x98OpenSSL 1.2.3",
	// near misses (git's own strings)
	"OpenSSL: %s", "libcurl: %s", "SHA256_BLK", "OpenSSL 3.", "crypto/evp/.c", "ssl/ssl_libc",
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBoringSSLyyyyyy",
}

// Small chunks put markers across chunk boundaries. The seeds run in every `go test`; run
// `go test -fuzz FuzzScanBytesMatchesOracle` to search further.
func FuzzScanBytesMatchesOracle(f *testing.F) {
	for _, s := range oracleSeeds {
		for _, c := range []uint8{1, 3, 7, 16, 64} {
			f.Add([]byte(s), c, c/2)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, c, o uint8) {
		if len(data) > 1<<14 {
			return
		}
		chunk := int(c%96) + 1
		checkAgainstOracle(t, data, chunk, int(o)%(chunk+40))
	})
}

// Buffers of a few KiB run on regexp's backtracker; production's 16 MiB chunks run its NFA. This
// puts the seeds in large buffers of mixed text and invalid UTF-8, at real overlap, so CI also
// compares the engine production uses.
func TestScanBytesMatchesOracleLargeBuffers(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	filler := make([]byte, 96<<10)
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./_-\xff\xe2\x82\xf0")
	for i := range filler {
		filler[i] = alphabet[rng.IntN(len(alphabet))]
	}
	for _, s := range oracleSeeds {
		for _, at := range []int{0, 4095, 32<<10 - 3, len(filler) - 1} {
			data := slices.Concat(filler[:at], []byte(s), filler[at:])
			for _, chunk := range []int{32 << 10, 64<<10 + 7, 112 << 10} {
				checkAgainstOracle(t, data, chunk, scanOverlap)
			}
		}
	}
}

// One row per branch of each marker pattern, so dropping or mistyping any branch fails a test.
func TestMarkerBranches(t *testing.T) {
	lib := map[string]string{ // text -> the marker it must record
		"x OpenSSL 3.6.4 x":            "OpenSSL 3.6.4",
		"x BoringSSL x":                "BoringSSL",
		"x AWS-LC x":                   "AWS-LC",
		"x LibreSSL 3.9 x":             "LibreSSL 3",
		"x aws-lc/crypto/fipsmodule x": "aws-lc/crypto/fipsmodule",
	}
	for text, want := range lib {
		got := map[string]bool{}
		addLibMarkers([]byte(text), got)
		if !got[want] || len(got) != 1 {
			t.Errorf("%q: markers %v, want exactly %q", text, slices.Sorted(maps.Keys(got)), want)
		}
	}
	for _, text := range []string{"x crypto/evp/digest.c x", "x ssl/t1_lib.cc x", "x third_party/boringssl/ x"} {
		if !hasSourceMarker([]byte(text)) {
			t.Errorf("%q must be a source marker", text)
		}
	}
	if len(lib) != len(cryptoLibMarkerParts) || len(cryptoSourceMarkerParts) != 3 {
		t.Errorf("branches: %d lib, %d source; this table covers %d lib, 3 source: add a row for the new branch",
			len(cryptoLibMarkerParts), len(cryptoSourceMarkerParts), len(lib))
	}
	for _, text := range []string{"OpenSSL: %s", "OpenSSL 3.", "LibreSSL x", "aws-lc/crypto/", "crypto/evp/.c", "ssl/ssl_libc", "SHA256_BLK"} {
		got := map[string]bool{}
		addLibMarkers([]byte(text), got)
		if len(got) > 0 || hasSourceMarker([]byte(text)) {
			t.Errorf("%q must match nothing: markers %v, source %v", text, slices.Sorted(maps.Keys(got)), hasSourceMarker([]byte(text)))
		}
	}
}

// Every branch must start with a literal (or the per-byte cost is back), and literalLedParts must
// refuse a pattern it cannot split that way rather than run it.
func TestLiteralLedParts(t *testing.T) {
	for _, p := range slices.Concat(cryptoLibMarkerParts, cryptoSourceMarkerParts) {
		if prefix, _ := p.LiteralPrefix(); prefix == "" {
			t.Errorf("branch %q has no literal prefix", p)
		}
	}
	parts := literalLedParts(regexp.MustCompile(`ab[0-9]|cd`))
	if len(parts) != 2 || parts[0].String() != `ab[0-9]` || parts[1].String() != `cd` {
		t.Errorf("split of ab[0-9]|cd: %v", parts)
	}
	for _, bad := range []string{`OpenSSL [0-9]+`, `abc|[0-9]+x`, `abc|(?i)def`} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(r.(string), "marker pattern") {
					t.Errorf("%q: want a marker-pattern panic, got %v", bad, r)
				}
			}()
			literalLedParts(regexp.MustCompile(bad))
		}()
	}
}
