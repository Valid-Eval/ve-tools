#!/bin/bash
# Build a melange recipe into a local, signed apk repository for a Docker build context.
#
# The signing key is generated per run and returned beside the packages; consuming Dockerfiles
# trust it only for the one `apk add` and delete it afterwards. Nothing is published.
#
# melange runs in a container and drives the HOST docker daemon (--runner docker), so its
# workspace is mounted at the same path inside and outside the container.
#
# Usage: [OPENSSL_LINE=<major>.<minor>] build.sh <recipe.yaml> <amd64|arm64> <out-dir>
# OPENSSL_LINE builds for a consumer's OpenSSL line (for example 4.0) instead of the recipe's
# default `openssl-major`/`openssl-minor` vars. Each image follows its own base's line, so the
# consumer derives it from its base and passes it here; the recipe file itself is not edited.
# Output: <out-dir>/<apk-arch>/{APKINDEX.tar.gz,*.apk} and <out-dir>/melange.rsa.pub
# <out-dir>/<apk-arch> must be absent or empty: use a fresh out-dir per run.
set -euo pipefail

RECIPE="${1:?usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>}"
ARCH="${2:?usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>}"
OUT="${3:?usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>}"
case "$ARCH" in
  amd64) APK_ARCH=x86_64 ;;
  arm64) APK_ARCH=aarch64 ;;
  *) echo "::error::unknown arch '$ARCH'"; exit 1 ;;
esac
# Set-but-empty is an error, not "use the default": a consumer passing OPENSSL_LINE from a detection
# step that came back empty would otherwise silently build the recipe's default line.
if [ -n "${OPENSSL_LINE+set}" ] && [ -z "$OPENSSL_LINE" ]; then
  echo "::error::OPENSSL_LINE is set but empty; unset it to build the recipe's default line"; exit 1
fi
OPENSSL_LINE="${OPENSSL_LINE:-}"
if [ -n "$OPENSSL_LINE" ]; then
  # Only the OpenSSL majors the fleet runs (3 and 4), and a minor without leading zeros, so a typo
  # (04.0, 3.06, 99999.0) fails here with this message instead of later inside apk as an
  # unresolvable openssl-<line>-dev.
  case "$OPENSSL_LINE" in
    [34].0|[34].[1-9]|[34].[1-9][0-9]) ;;
    *) echo "::error::OPENSSL_LINE must be <major>.<minor> with major 3 or 4 and no leading zeros (e.g. 4.0, 3.6), got '$OPENSSL_LINE'"; exit 1 ;;
  esac
fi

# Digest-pinned; Renovate tracks it through the customManagers entry in renovate.json.
MELANGE_IMAGE="cgr.dev/chainguard/melange:latest@sha256:15dd85c0e35c099e4142c463d8479da769f319f01ab0f9e6ff427f79d63091f9"

RECIPE_DIR="$(cd "$(dirname "$RECIPE")" && pwd)"
RECIPE="$RECIPE_DIR/$(basename "$RECIPE")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# A reused out-dir would let a previous run's apks satisfy the checks below and reach the consumer.
if [ -n "$(ls -A "$OUT/$APK_ARCH" 2>/dev/null)" ]; then
  echo "::error::$OUT/$APK_ARCH is not empty; remove it or use a fresh out-dir"; exit 1
fi
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/melange-ws.XXXXXX")"
# Exit non-zero unless the script reached its end. Under `set -eu`, macOS /bin/bash 3.2 exits 0 when
# an unbound variable aborts the script with an EXIT trap set (and gives the trap $? = 0), so the
# trap can't just preserve $?.
DONE=0
trap 'rm -rf "$WORK"; [ "$DONE" = 1 ] || exit 1' EXIT

# With OPENSSL_LINE, build and test a rendered copy of the recipe whose two vars are replaced, so
# `melange build`, `melange test` and check-tests-ran.sh all see the same line. (`melange build
# --vars-file` exists, but `melange test` has no equivalent and the test pipelines read the vars.)
# Each var line must occur exactly once, or the build stops: a missing line would silently build
# the default, and a duplicate would leave the second copy unrendered. sed then replaces those two
# lines with the same patterns the count used, so the copy differs from the recipe in at most those
# two lines (none when OPENSSL_LINE equals the defaults). CI's stub check asserts the vars that
# `melange build` and `melange test` actually receive.
if [ -n "$OPENSSL_LINE" ]; then
  maj="${OPENSSL_LINE%%.*}"; min="${OPENSSL_LINE#*.}"
  for v in openssl-major openssl-minor; do
    n="$(grep -c "^  $v: \"[0-9]*\"\$" "$RECIPE" || true)"
    [ "$n" = 1 ] || { echo "::error::$(basename "$RECIPE") must define '  $v: \"N\"' exactly once (found $n)"; exit 1; }
  done
  mkdir "$WORK/recipe"
  RENDERED="$WORK/recipe/$(basename "$RECIPE")"
  sed -e "s/^  openssl-major: \"[0-9]*\"\$/  openssl-major: \"$maj\"/" \
      -e "s/^  openssl-minor: \"[0-9]*\"\$/  openssl-minor: \"$min\"/" "$RECIPE" > "$RENDERED"
  RECIPE="$RENDERED"
  echo "=== building at OpenSSL $OPENSSL_LINE (OPENSSL_LINE) instead of the recipe's default vars ==="
fi

run_melange() {
  docker run --rm --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$RECIPE_DIR":"$RECIPE_DIR":ro -v "$OUT":"$OUT" -v "$WORK":"$WORK" -w "$WORK" \
    "$MELANGE_IMAGE" "$@"
}

run_melange keygen "$WORK/melange.rsa"
echo "=== melange build $(basename "$RECIPE") ($APK_ARCH) ==="
run_melange build "$RECIPE" \
  --arch "$APK_ARCH" \
  --runner docker \
  --workspace-dir "$WORK/ws" \
  --signing-key "$WORK/melange.rsa" \
  --out-dir "$OUT"
cp "$WORK/melange.rsa.pub" "$OUT/melange.rsa.pub"

# Fail here with a clear message, before `melange test` and the consumer's `apk add`, if nothing
# was produced for this arch.
ls "$OUT/$APK_ARCH"/*.apk >/dev/null 2>&1 || { echo "::error::melange produced no apks for $APK_ARCH"; exit 1; }
[ -s "$OUT/$APK_ARCH/APKINDEX.tar.gz" ] || { echo "::error::melange produced no signed APKINDEX for $APK_ARCH"; exit 1; }

# `melange build` does not run a recipe's `test:` pipelines; only `melange test` does. Run them
# against the packages just built (installed from the output repo, trusted via this run's key), so
# a failing assertion fails this script instead of never executing.
echo "=== melange test $(basename "$RECIPE") ($APK_ARCH) ==="
# melange test bind-mounts <workspace>/<arch> into the test pod but does not create it first.
mkdir -p "$WORK/test-ws/$APK_ARCH"
run_melange test "$RECIPE" \
  --arch "$APK_ARCH" \
  --runner docker \
  --workspace-dir "$WORK/test-ws" \
  --repository-append "$OUT" \
  --keyring-append "$OUT/melange.rsa.pub" 2>&1 | tee "$WORK/test.log"

# melange's exit code alone doesn't show that the tests ran; its log must show every test block.
"$(dirname "$0")/check-tests-ran.sh" "$RECIPE" "$WORK/test.log"

echo "melange packages for $APK_ARCH:"
ls -1 "$OUT/$APK_ARCH"
DONE=1
