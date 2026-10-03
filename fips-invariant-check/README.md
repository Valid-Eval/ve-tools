# fips-invariant-check

Enforces the VE fleet's FIPS crypto invariant on a container image, from inside the image. It's a static Go binary, so it also runs in distroless images with no shell.

## The invariant

1. **One OpenSSL core.** Everything that links OpenSSL links the same major (`libcrypto.so.N`).
   - Two cores in one process cannot both initialise the single Chainguard FIPS provider (`fips.so`), and whichever loads second fails.
   - On 2026-10-02 this broke every Python service: libpq-17 `17.11-r4` moved to OpenSSL 4 while CPython uses OpenSSL 3, and libpq failed with `could not generate nonce`.
2. **No unvalidated crypto.** No binary carries its own crypto library. Those never touch the FIPS provider and do not fail; they silently run non-validated crypto. Seen in the fleet:
   - a precompiled `pg` gem with OpenSSL statically linked;
   - the `cryptography` wheel with its own OpenSSL;
   - Chromium/chromedriver with BoringSSL, and Mozilla NSS;
   - Heimdal `libhcrypto`, pulled in by libldap's SASL/GSSAPI plugins;
   - the AWS CLI's `_awscrt` with AWS-LC;
   - Go binaries using standard-library crypto with no FIPS mode.

   Go is the one sanctioned second module (decision 2026-10-02, INF-377), on exactly two routes (see the Go row below). A build-time check cannot see a runtime `GODEBUG=fips140=off` override, which switches FIPS mode off in a native-module binary, so deployment configuration must not set one.
3. **Nothing skipped.** A gate that passes what it never inspected is worse than no gate. Any path the scan cannot inspect fails the run:
   - an unreadable directory or file, or an ELF it cannot parse;
   - an unreadable dynamic table, or one whose header-supplied size is implausible (over 64 MiB);
   - a symbol table that is present but unreadable (only a missing one counts as stripped);
   - a UPX-packed executable;
   - a Go binary whose build info or function table cannot be read. Go is recognised by its sections or build-info magic, not only by `debug/buildinfo`, which reports damaged build info as "not a Go executable".

   Only `/proc`, `/sys` and `/dev` are skipped, as virtual filesystems. `/run` is scanned: it is not a mount during `docker build`, and what an image puts there ships with it. A separate debug-info file (`objcopy --only-keep-debug`, `-dbgsym`/`.debug` packages) is not judged when its program headers show no executable segment with bytes in the file: nothing in it can run. Section headers alone never make a file "debug info". A Go debug file keeps bytes in its first segment, so it is inspected, but not judged as Go, because its Go sections hold no bytes. A missing `-root`, or one with nothing to inspect (no ELF file and no uninspectable path), is an error (exit 2). Linked libraries are read from the program headers (`PT_DYNAMIC`, as the loader does) whenever there is no in-file dynamic section: section headers stripped, or `.dynamic` missing or mislabelled. A separate debug-info file, whose `PT_DYNAMIC` has no bytes in the file, has nothing to read. Files of any size are scanned in bounded chunks.

## How it decides

| Finding | Evidence |
|---|---|
| A process can mix cores | Each ELF's `DT_NEEDED` `libcrypto.so.N` / `libssl.so.N`, including OpenSSL 1.x's dotted `libcrypto.so.1.1`. The image fails if more than one soname version (core) is linked. Cores that are present but unused are reported as notes. |
| Embedded copy | The file **defines** `RAND_bytes`, `EVP_DigestInit_ex` or `OPENSSL_init_crypto`, or Heimdal's `hc_RAND_bytes` / `hc_EVP_DigestInit_ex` (any binding, `.symtab` or `.dynsym`). The system `libcrypto`/`libssl`, OpenSSL provider modules (`ossl-modules/`) and OpenSSL 3 engines (`engines-3/`) are exempt. Exact names only: CPython's `_ssl` defines a local `_ssl_RAND_bytes` wrapper and must pass. |
| Embedded copy, stripped | A crypto-library version string **plus** that library's own source paths (`crypto/evp/…`, `third_party/boringssl/`), with no system OpenSSL linked, in a non-Go binary (Go binaries are judged by the Go row). A version string alone is not evidence: git carries `OpenSSL 3.6.4` only as `--build-options` text. |
| Vendored library | A `libcrypto.so.N`/`libssl.so.N` outside the system lib dirs (`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, and the multiarch `x86_64-linux-gnu` / `aarch64-linux-gnu` dirs), or an auditwheel-renamed `libcrypto-<hash>.so.N`. |
| Independent crypto stack | Recognised by soname: Mozilla NSS (`libnss3`, `libssl3`, `libfreebl3` and the rest), Heimdal `libhcrypto`, libgcrypt, Nettle/hogweed, GnuTLS, Mbed TLS, wolfSSL. |
| Go | The binary has crypto compiled in, and `debug/buildinfo` shows **neither** accepted route below. "Has crypto" means any function from a `crypto/...` package (including Go 1.24+'s `crypto/internal/fips140/`) or from `golang.org/x/crypto`. This is read from the binary's function table (`.gopclntab`, which stripping does not remove), not by searching its bytes, so text that merely mentions `crypto/` does not count. The routes: **(A) Chainguard native Go Cryptographic Module (CMVP #5247), DU go-fips ≥ 1.27:** `GOFIPS140` is a certified snapshot (`v1.0.0-<hash>`) **and** `DefaultGODEBUG` has `fips140=on` or `=only` **and** `chainguard_cryptographic_module=geomys` **and** `chainguard_entropy_source=geomys`. Upstream Go with `GOFIPS140=v1.0.0` fails: its entropy comes from outside the module boundary. `GOFIPS140=latest`/`inprocess` fail too: they build the unvalidated in-tree module. **(B) System OpenSSL, DU go-fips ≤ 1.26:** `-tags requirefips` **and** `GOEXPERIMENT=systemcrypto` **and** `CGO_ENABLED=1` (crypto via the system FIPS provider). It reports `GOFIPS140=latest`, so it is not judged by that. **Also:** a binary on either route still fails if it links crypto code from outside the standard library, because that code runs outside both validated modules and FIPS mode does not govern it. That means any `golang.org/x/crypto` package function (chacha20poly1305, argon2, hkdf, ssh and the like), and the third-party crypto modules listed in `scan.go` (`thirdPartyGoCrypto`: filippo.io/edwards25519, cloudflare/circl, ProtonMail/go-crypto, blake3 modules). It is decided per function, because a package's status depends on its x/crypto version: sha3 forwards to the standard library from v0.44.0 and pbkdf2 from v0.51.0, while older versions carry their own Keccak/PBKDF2. Only the forwarding functions of sha3, pbkdf2, ed25519 and curve25519 (`xcryptoWrappers`), the crypto-free packages (cryptobyte, acme, ocsp) and package initialisation are exempt. An unknown x/crypto package fails closed. The standard library's own vendored copy (`vendor/golang.org/x/crypto/...`, behind `crypto/tls`) does not count. Other third-party Go modules that implement crypto and are not on the list are not detected. |

Structural checks cannot prove behaviour, so an image can also register a **behavioural probe**. The probe is a language-specific script that loads the runtime's own crypto first, then each native library, and asserts that MD5 is refused while SHA-256 and RAND work.
- **Registering it:** use `-- CMD ARGS` or `FIPS_INVARIANT_PROBE`.
- **Where it runs:** only inside the image (`-root /`). An explicit `-- CMD` with any other `-root` is an error (exit 2). An inherited `FIPS_INVARIANT_PROBE` is only noted as not run.
- **Time limit:** `FIPS_INVARIANT_PROBE_TIMEOUT`, default `10m`. A probe that fails to start, exits non-zero or times out fails the run. At the deadline the probe's whole process group is killed, so a child it started cannot keep the build waiting.

## Use

```dockerfile
# In the image's gobuilder stage (credbridge pattern):
RUN CGO_ENABLED=0 go install github.com/Valid-Eval/ve-tools/fips-invariant-check@v0.1.0
# ...and as the LAST step of every image build, base or downstream:
COPY --from=gobuilder /usr/bin/fips-invariant-check /usr/local/bin/fips-invariant-check
RUN ["/usr/local/bin/fips-invariant-check"]
```

To scan an extracted rootfs instead, run `fips-invariant-check -root /path/to/rootfs`. The behavioural probe is skipped in that mode.

- **Exit status:** `0` means the invariant holds, `1` a violation, `2` a usage or internal error.
- **`-v`** additionally lists every file that passes while linking a system OpenSSL, naming a crypto library, or being a Go binary.
- **`FIPS_INVARIANT_STRICT`** accepts `1`/`true`/`yes`/`on` (strict) and `0`/`false`/`no`/`off` or unset (not strict). Anything else is an error, so a mistyped value can't silently select non-strict mode.
- **credbridge** is a Go binary that uses standard-library crypto, so an image carrying it passes only once it's built on route (A) or (B) (INF-377, `ve-base/go-fips`). Until then, builder images exempt it by name; production (strict) images can't.

## Exemptions

Exemptions go in `/etc/fips-invariant-check/allow.d/*.allow` inside the image, or in a file passed with `-allow FILE`. When scanning an extracted rootfs, every component of the `allow.d` path is resolved inside the image, never on the host, including symlinked parent directories such as `/etc -> /usr/etc`. A dangling `allow.d` link, or a symlink loop, is an error.

- **Format:** one `<absolute-glob> <reason>` per line, matched with `path.Match`. A trailing `/**` means "anything under the matching directory", and that directory part may itself use globs. A pattern whose first path component is a glob (for example `/**` or `/*/bin/**`) would exempt the whole image and is rejected.
- **An entry exempts a file from both rules.** It also takes the file out of the OpenSSL-core count. The core rule is deliberately image-wide, stricter than the per-process hazard, so a build tool that runs as its own process and links another core (e.g. a Rust toolchain built against OpenSSL 4) can be exempted by name.
- **Every entry needs a reason.** It's printed every time the entry is used, so an exemption is always visible in the build log.
- **Stale entries are flagged:** an entry that matches nothing produces a warning. Overlapping entries that match the same file both count as used.
- **Production images run in strict mode.** Runtime bases set `FIPS_INVARIANT_STRICT=1` (or pass `-strict`), and every image built FROM them inherits it. In strict mode no exemption applies, and the presence of any allowlist file is itself a failure. An exemption copied out of a builder stage can therefore never open a hole in production.
- **Use them only for things that never ship to production**, such as a builder-only toolchain. Exemptions live in the image, so a downstream image that discards the builder stage also discards its exemptions.

## Releases

Tags are `fips-invariant-check/vX.Y.Z` (Go's subdirectory-module convention), so `go install …@vX.Y.Z` resolves them.
