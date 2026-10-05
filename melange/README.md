# melange recipes

Source-built packages shared across the VE image fleet, built with [melange](https://github.com/chainguard-dev/melange). Each one exists because the Wolfi package doesn't fit our FIPS invariant: one OpenSSL core per image, and only the Chainguard FIPS provider for crypto (see `fips-invariant-check/`).

| Recipe | Why |
|---|---|
| `libpq-17.yaml` | Wolfi `libpq-17` moved to OpenSSL 4 (`17.11-r4`), while CPython and Ruby use OpenSSL 3. Two cores in one process cannot both initialise the FIPS provider. This build links the same OpenSSL line as the consuming runtimes (see [OpenSSL line](#openssl-line)) and drops GSSAPI/LDAP (unused in the fleet). |
| `libpq-17.yaml` → subpackage `ve-postgresql-17-client` | `pg_dump`, `pg_restore`, `psql` and `pg_isready` from the same source build, linked against `ve-libpq-17`. Wolfi's `postgresql-17-client` loads two OpenSSL cores in one process: `.so.4` via its libpq, and `.so.3` via krb5's `libk5crypto`. Same source build and configure as libpq (no GSSAPI/LDAP, so no krb5 closure). zlib is enabled for the tools because `pg_restore` must read gzip-compressed `pg_dump -Fc` archives; libpq itself does not link it. |

## How images consume a recipe

Nothing is published. Each image-\* CI:

1. Checks out ve-tools at a pinned tag and verifies the commit, e.g. `melange-libpq-17/v1` (Renovate tracks it).
2. Runs `melange/build.sh <recipe> <amd64|arm64> <build-context>/melange-packages`, which signs with a key generated for that run. An image whose base is on a different OpenSSL line from the recipe's default vars sets `OPENSSL_LINE=<major>.<minor>` (see **OpenSSL line**), derived from its own base.
3. In its Dockerfile, trusts that key for one `apk add --repository …` and then deletes it. Install the key as `/etc/apk/keys/melange.rsa.pub`, the exact name recorded in the index signature: under any other name apk silently skips the repository and reports the packages as missing.

The packages are real apks:
- **Scanners see them.** Each carries an apk DB record and an SPDX SBOM at `/var/lib/db/sbom/`.
- **Collisions fail loudly.** apk refuses to install the Wolfi package they replace alongside them, because both own the same files. A downstream `apk add libpq-17` therefore errors instead of quietly bringing back OpenSSL 4.

## Package tests

`build.sh` runs these checks. The header check is a build pipeline step; the rest are the recipe's `test:` pipelines, which only `melange test` runs (`melange build` never does), so `build.sh` runs it after building and fails unless its log shows every test block ran (`check-tests-ran.sh`). For `libpq-17.yaml`, with `N.M` the OpenSSL line from the recipe's vars:

- **The build env's OpenSSL headers are `N.M`.** Checked before compiling. Wolfi's `openssl-N.M-dev` is what selects them today, but that pin is Wolfi's packaging, not ours.
- **`libpq.so.5` links only libc, libm, `libssl.so.N` and `libcrypto.so.N`.** This catches a configure or toolchain change that drags in zlib, krb5 or a second OpenSSL major.
- **`libpq.so.5` and the client tools need no OpenSSL symbol version newer than `N.M`.** The soname is the same across minors, so this is the check meant to catch a libpq built against newer headers than the runtime's library.
- **Each client tool's resolved library closure contains only the `.so.N` OpenSSL core.** This is checked with glibc's `LD_TRACE_LOADED_OBJECTS`, not the tool's own NEEDED entries. A second core usually arrives one level down, so a NEEDED-only check passes Wolfi's client even though that client loads both cores.
- **`pg_dump` and `pg_restore` link zlib, and `pg_dump` accepts gzip compression.** A build without zlib rejects `-Z gzip` before connecting.
- **`ve-libpq-17-dev` installs its headers, `libpq.pc` and `pg_config`, and brings `N.M` OpenSSL headers.** Both OpenSSL lines' `-dev` packages satisfy `libpq.pc`'s `pc:libcrypto`, so the subpackage depends on `openssl-N.M-dev` explicitly. Without it, a fresh `apk add ve-libpq-17-dev` chose `openssl-4.0-dev` next to a 3.x libpq.

These checks have been seen failing on a known-bad input and passing on the real build. The libz NEEDED check, the per-tool symbol-version loop, the `-dev` file checks and the "does not run" guards have not.

| Check | Known-bad input | Result |
|---|---|---|
| Header version | build env given `openssl-4.0-dev` with vars at 3.6 | `build.sh` fails before compiling |
| libpq NEEDED set | a `--with-gssapi` build (`libgssapi_krb5.so.2` appears) | `build.sh` fails in `melange test` |
| Symbol-version ceiling | proxy input: the same loop pointed at `libssl.so.3` (needs `OPENSSL_3.2.0`+) with ceiling 3.0 (minor branch) or 4.0 (major branch); no libpq built against newer headers has been run | fails; passes at 3.6 |
| `-dev` headers | the `ve-libpq-17-dev` built before the explicit dependency (fresh install pulled `openssl-4.0-dev`) | `melange test` fails |
| Client closure | Wolfi's `postgresql-17-client` (loads `.so.3` and `.so.4`) | fails |
| zlib probe | a `--without-zlib` build | fails |
| Unresolved-library guard | Wolfi's client with `libzstd` removed | fails |
| Version parse guard | a non-numeric minor (`3.x`) fed to the loop | fails |

CI builds and tests the recipe both at its default vars and with `OPENSSL_LINE=4.0`.

## OpenSSL line

The recipe's `openssl-major`/`openssl-minor` vars set the line. The build env's `-dev` package, the `-dev` subpackage's dependency and every check above derive from them. 3.x and 4.x are both acceptable. The line must match what the **consuming** image's runtimes link (CPython `_ssl`, Ruby `openssl.so`, or the base's own OpenSSL), and a different major in one process is the failure this recipe exists to prevent.

Each image follows its own base, so consumers can need different lines at once (for example a base on 3.6 next to an OpenSSL-4-only base). The vars in the file are the default. A consumer on another line sets `OPENSSL_LINE=<major>.<minor>`, and `build.sh` builds and tests a rendered copy of the recipe with just those two vars replaced. It refuses a value that isn't `<major>.<minor>`, or a recipe where either var line is missing or duplicated, rather than silently building the default line.

- Renovate cannot see that coupling. The controls are the consuming images' own checks and `fips-invariant-check`.
- A consumer should derive `OPENSSL_LINE` from its base, not hard-code it, so a base move changes the build line or fails loudly.
- Move the default vars only when the default consumer set moves, and bump `epoch` if the PostgreSQL version doesn't change with them.

## Updates

Renovate, configured in `renovate.json`, tracks two things:

- **The upstream source.** For `libpq-17.yaml` it watches the `postgres/postgres` `REL_17_*` tags. The tag, the commit (which melange checks as `expected-commit`) and the package version move in one PR.
  - Keep the `pg-tag`, `pg-commit`, `package:` and `version:` lines contiguous and in that order. Renovate's regex matches them as one block, and if anything is inserted between them it stops proposing updates without any error. CI checks that the regex still matches (see below).
  - PostgreSQL patch releases are mostly security fixes, so this dependency skips the repo-wide 7-day age gate and weekly schedule.
- **The digest-pinned melange image** in `build.sh`.

CI (`.github/workflows/melange.yml`) runs on every PR touching `melange/`, `renovate.json`, `.github/scripts/` or the workflow itself. It tests and runs `.github/scripts/check-renovate-regex.js`, which requires every recipe to be covered by a regex customManager whose matchStrings each match exactly once. It then checks, without docker, that `build.sh`'s argument, out-dir and `OPENSSL_LINE` guards and `check-tests-ran.sh` reject bad input with the expected message, that `build.sh` exits 1 and cleans up after a mid-run failure, and (through a stub docker) that `melange build` receives the recipe at the requested line. Finally it runs `build.sh` (build and package tests) on amd64, at the default vars and at `OPENSSL_LINE=4.0`, in separate jobs.

Merging a recipe change and tagging `melange-<recipe>/vN+1` lets each image-\* Renovate pick up the new tag.

## Known limitation: CVE matching

Scanners match apk packages to advisories by package name against Wolfi's security database. A package named `ve-libpq-17` won't be matched to PostgreSQL CVEs that way. Its SBOM records the upstream source (`pkg:github/postgres/postgres@REL_17_x`), but whether a given scanner uses that has not been verified. The primary control is staying on the latest PostgreSQL 17 patch release through the Renovate rule above.

## Running locally

```bash
melange/build.sh melange/libpq-17.yaml amd64 "$(mktemp -d)"   # needs docker; a fresh out-dir each run
OPENSSL_LINE=4.0 melange/build.sh melange/libpq-17.yaml amd64 "$(mktemp -d)"   # for an OpenSSL 4.0 consumer
```
