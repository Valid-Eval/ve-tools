#!/bin/bash
# Fail unless a `melange test` log shows every test block in its recipe ran.
#
# melange's exit code alone doesn't show that the tests ran, so build.sh calls this with the
# recipe and the tee'd `melange test` log. A recipe must have at least one test block. Blocks are
# counted at column 0 (the package) and 4 spaces (subpackages); a recipe laid out differently fails
# here loudly rather than passing unobserved.
#
# Usage: check-tests-ran.sh <recipe.yaml> <melange-test.log>
set -euo pipefail

RECIPE="${1:?usage: check-tests-ran.sh <recipe.yaml> <melange-test.log>}"
LOG="${2:?usage: check-tests-ran.sh <recipe.yaml> <melange-test.log>}"
[ -r "$RECIPE" ] && [ -r "$LOG" ] || { echo "::error::cannot read $RECIPE or $LOG"; exit 1; }

want="$(grep -cE '^(    )?test:' "$RECIPE" || true)"
got="$(grep -cE 'running (the main test pipeline|test pipeline for subpackage )' "$LOG" || true)"
echo "melange test ran $got of $want test blocks"
[ "$want" -ge 1 ] || { echo "::error::$RECIPE has no test blocks"; exit 1; }
[ "$got" = "$want" ] || { echo "::error::melange test ran $got test blocks, recipe has $want"; exit 1; }
