#!/usr/bin/env bash
# Build a melange recipe into a local, signed apk repository for a Docker build context.
#
# The signing key is generated per run and returned beside the packages; consuming Dockerfiles
# trust it only for the one `apk add` and delete it afterwards. Nothing is published.
#
# melange runs in a container and drives the HOST docker daemon (--runner docker), so its
# workspace is mounted at the same path inside and outside the container.
#
# Usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>
# Output: <out-dir>/<apk-arch>/{APKINDEX.tar.gz,*.apk} and <out-dir>/melange.rsa.pub
set -euo pipefail

RECIPE="${1:?usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>}"
ARCH="${2:?usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>}"
OUT="${3:?usage: build.sh <recipe.yaml> <amd64|arm64> <out-dir>}"
case "$ARCH" in
  amd64) APK_ARCH=x86_64 ;;
  arm64) APK_ARCH=aarch64 ;;
  *) echo "::error::unknown arch '$ARCH'"; exit 1 ;;
esac

# Digest-pinned; Renovate tracks it through the customManagers entry in renovate.json.
MELANGE_IMAGE="cgr.dev/chainguard/melange:latest@sha256:15dd85c0e35c099e4142c463d8479da769f319f01ab0f9e6ff427f79d63091f9"

RECIPE="$(cd "$(dirname "$RECIPE")" && pwd)/$(basename "$RECIPE")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/melange-ws.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
RECIPE_DIR="$(dirname "$RECIPE")"

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
  --keyring-append "$OUT/melange.rsa.pub"

# Fail here, not at the consumer's `apk add`, if nothing was produced for this arch.
ls "$OUT/$APK_ARCH"/*.apk >/dev/null 2>&1 || { echo "::error::melange produced no apks for $APK_ARCH"; exit 1; }
[ -s "$OUT/$APK_ARCH/APKINDEX.tar.gz" ] || { echo "::error::melange produced no signed APKINDEX for $APK_ARCH"; exit 1; }
echo "melange packages for $APK_ARCH:"
ls -1 "$OUT/$APK_ARCH"
