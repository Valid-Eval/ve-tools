# melange recipes

Source-built packages shared across the VE image fleet, built with [melange](https://github.com/chainguard-dev/melange). Each one exists because the Wolfi package doesn't fit our FIPS invariant: one OpenSSL core per image, and only the Chainguard FIPS provider for crypto (see `fips-invariant-check/`).

| Recipe | Why |
|---|---|
| `libpq-17.yaml` | Wolfi `libpq-17` moved to OpenSSL 4 (`17.11-r4`), while CPython and Ruby use OpenSSL 3. Two cores in one process cannot both initialise the FIPS provider. This build links the runtimes' OpenSSL 3 and drops GSSAPI/LDAP (unused in the fleet). |

## How images consume a recipe

Nothing is published. Each image-\* CI:

1. Checks out ve-tools at a pinned tag and verifies the commit, e.g. `melange-libpq-17/v1` (Renovate tracks it).
2. Runs `melange/build.sh <recipe> <amd64|arm64> <build-context>/melange-packages`, which signs with a key generated for that run.
3. In its Dockerfile, trusts that key for one `apk add --repository …` and then deletes it.

The packages are real apks:
- **Scanners see them.** Each carries an apk DB record and an SPDX SBOM at `/var/lib/db/sbom/`.
- **Collisions fail loudly.** apk refuses to install the Wolfi package they replace alongside them, because both own the same files. A downstream `apk add libpq-17` therefore errors instead of quietly bringing back OpenSSL 4.

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
