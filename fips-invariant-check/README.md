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
   - the AWS CLI's `_awscrt` with AWS-LC;
   - Go binaries using standard-library crypto with no FIPS mode.

   Go is the one sanctioned second module (decision 2026-10-02, INF-377). A Go binary passes when built on the validated Go Cryptographic Module, or through golang-fips/openssl to the system FIPS provider. A build-time check cannot see a runtime `GODEBUG=fips140=off` override, so deployment configuration must not set one.

## How it decides

| Finding | Evidence |
|---|---|
| A process can mix cores | Each ELF's `DT_NEEDED` `libcrypto.so.N` / `libssl.so.N`. The image fails if more than one major is linked. Cores that are present but unused are reported as notes. |
| Embedded copy | The file **defines** `RAND_bytes`, `EVP_DigestInit_ex` or `OPENSSL_init_crypto` (any binding, `.symtab` or `.dynsym`) and is not a system `libcrypto`/`libssl` or an OpenSSL provider module. |
| Embedded copy, stripped | A crypto-library version string **plus** that library's own source paths (`crypto/evp/…`, `third_party/boringssl/`), with no system OpenSSL linked. A version string alone is not evidence: git carries `OpenSSL 3.6.4` only as `--build-options` text. |
| Vendored library | A `libcrypto`/`libssl` outside `/usr/lib` and `/lib`, or an auditwheel-renamed `libcrypto-<hash>.so.N`. |
| Mozilla NSS | `libnss3.so`, `libssl3.so`, `libfreebl3.so` and the rest of NSS. |
| Go | The binary contains standard-library crypto functions, and `debug/buildinfo` shows **neither** route to a validated module. **Native Go Cryptographic Module (CMVP #5247):** `GOFIPS140` is the frozen `v1.0.0` snapshot (recorded as `v1.0.0-<hash>`) **and** `DefaultGODEBUG` has `fips140=on` or `=only`. `GOFIPS140=latest`/`inprocess` also enable FIPS mode, but on the unvalidated in-tree module, so they fail. **golang-fips/openssl:** `-tags requirefips` (crypto via the system OpenSSL FIPS provider). |

Structural checks cannot prove behaviour, so an image can also register a **behavioural probe**. The probe is a language-specific script that loads the runtime's own crypto first, then each native library, and asserts that MD5 is refused while SHA-256 and RAND work. Register it with `-- CMD ARGS` or `FIPS_INVARIANT_PROBE`; it runs only inside the image (`-root /`).

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
- **`-v`** additionally lists every file that links crypto.

## Exemptions

Exemptions go in `/etc/fips-invariant-check/allow.d/*.allow` inside the image, or in a file passed with `-allow FILE`.

- **Format:** one `<absolute-glob> <reason>` per line. A trailing `/**` means "anything under this directory".
- **An entry exempts a file from both rules.** It also takes the file out of the OpenSSL-core count. The core rule is deliberately image-wide, stricter than the per-process hazard, so a build tool that runs as its own process and links another core (e.g. a Rust toolchain built against OpenSSL 4) can be exempted by name.
- **Every entry needs a reason.** It's printed every time the entry is used, so an exemption is always visible in the build log.
- **Stale entries are flagged:** an entry that matches nothing produces a warning.
- **Use them only for things that never ship to production**, such as a builder-only toolchain. Exemptions live in the image, so a downstream image that discards the builder stage also discards its exemptions.

## Releases

Tags are `fips-invariant-check/vX.Y.Z` (Go's subdirectory-module convention), so `go install …@vX.Y.Z` resolves them.
