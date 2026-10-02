# melange recipes

Source-built packages shared across the VE image fleet, built with [melange](https://github.com/chainguard-dev/melange). Each one exists because the Wolfi package doesn't fit our FIPS invariant: one OpenSSL core per image, and only the Chainguard FIPS provider for crypto (see `fips-invariant-check/`).

| Recipe | Why |
|---|---|
| `libpq-17.yaml` | Wolfi `libpq-17` moved to OpenSSL 4 (`17.11-r4`), while CPython and Ruby use OpenSSL 3. Two cores in one process cannot both initialise the FIPS provider. This build links the runtimes' OpenSSL 3 and drops GSSAPI/LDAP (unused in the fleet). |
| `libpq-17.yaml` → subpackage `ve-postgresql-17-client` | `pg_dump`, `pg_restore`, `psql` and `pg_isready` from the same source build, linked against `ve-libpq-17`. Wolfi's `postgresql-17-client` loads two OpenSSL cores in one process: `.so.4` via its libpq, and `.so.3` via krb5's `libk5crypto`. Built with zlib, because `pg_restore` must read gzip-compressed `pg_dump -Fc` archives. |

## How images consume a recipe

Nothing is published. Each image-\* CI:

1. Checks out ve-tools at a pinned tag and verifies the commit, e.g. `melange-libpq-17/v1` (Renovate tracks it).
2. Runs `melange/build.sh <recipe> <amd64|arm64> <build-context>/melange-packages`, which signs with a key generated for that run.
3. In its Dockerfile, trusts that key for one `apk add --repository …` and then deletes it.

The packages are real apks:
- **Scanners see them.** Each carries an apk DB record and an SPDX SBOM at `/var/lib/db/sbom/`.
- **Collisions fail loudly.** apk refuses to install the Wolfi package they replace alongside them, because both own the same files. A downstream `apk add libpq-17` therefore errors instead of quietly bringing back OpenSSL 4.

## Package tests

Each recipe's `test:` pipelines are the build's own checks, and `build.sh` runs them with `melange test` after building (`melange build` never runs them). For `libpq-17.yaml`:

- **`libpq.so.5` links only libc, libm, `libssl.so.3` and `libcrypto.so.3`.** This catches a configure or toolchain change that drags in zlib, krb5 or a second OpenSSL major.
- **Each client tool's resolved library closure contains only the `.so.3` OpenSSL core.** This is checked with the dynamic loader's `--list`, not the tool's own NEEDED entries. A second core usually arrives one level down, so a NEEDED-only check passes Wolfi's client even though that client loads both cores.
- **`pg_dump` accepts gzip compression.** A build without zlib rejects `-Z gzip` before connecting.

Each check has been seen failing on a known-bad input: a `--without-zlib` build, and Wolfi's `postgresql-17-client`.

## Updates

Renovate, configured in `renovate.json`, tracks two things:

- **The upstream source.** For `libpq-17.yaml` it watches the `postgres/postgres` `REL_17_*` tags. The tag, the commit (which melange checks as `expected-commit`) and the package version move in one PR.
  - Keep those three lines adjacent and in order: the replacement template rewrites them as one block.
  - PostgreSQL patch releases are mostly security fixes, so this dependency skips the repo-wide 7-day age gate and weekly schedule.
- **The digest-pinned melange image** in `build.sh`.

Merging a recipe change and tagging `melange-<recipe>/vN+1` lets each image-\* Renovate pick up the new tag.

## Known limitation: CVE matching

Scanners match apk packages to advisories by package name against Wolfi's security database. A package named `ve-libpq-17` won't be matched to PostgreSQL CVEs that way. Its SBOM records the upstream source (`pkg:github/postgres/postgres@REL_17_x`), but whether a given scanner uses that has not been verified. The primary control is staying on the latest PostgreSQL 17 patch release through the Renovate rule above.

## Running locally

```bash
melange/build.sh melange/libpq-17.yaml amd64 /tmp/melange-out   # needs docker
```
