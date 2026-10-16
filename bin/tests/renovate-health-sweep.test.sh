#!/bin/bash
# Offline tests for bin/renovate-health-sweep. Runs the real script against a
# fixture `gh` (bin/tests/gh-shim) with the clock pinned, and checks exit codes
# and output. No network, no tokens.
#
#   bin/tests/renovate-health-sweep.test.sh
#
# Targets bash 3.2 (macOS): no associative arrays, mapfile, or ${x,,}.
# Cases are  t NAME WANT_RC PATTERN... -- ARGS...   where a PATTERN is an
# extended regex that must match the output, or !REGEX that must not.

HERE=$(cd "$(dirname "$0")" && pwd)
SWEEP="$HERE/../renovate-health-sweep"
WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT
FIX="$WORK/fix"; BIN="$WORK/bin"
mkdir -p "$FIX" "$BIN"
cp "$HERE/gh-shim" "$BIN/gh"; chmod +x "$BIN/gh"

NOW=1791331200                       # 2026-10-07T00:00:00Z
FRESH='2026-10-05T00:00:00Z'         # 2 days before NOW
OLD='2026-09-20T00:00:00Z'           # 17 days before NOW

DASH='<!-- manual job -->
This issue lists Renovate updates and detected dependencies. Read the [Dependency Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/) docs to learn more.'

# mk REPO BODY [ISSUES_JSON]: a repo with one Renovate issue (#1) unless given JSON.
mk() {
  mkdir -p "$FIX/$1"
  if [ -n "${3:-}" ]; then printf '%s' "$3" > "$FIX/$1/issues.json"
  else printf '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"%s"}]' "$FRESH" > "$FIX/$1/issues.json"; fi
  [ -n "${2:-}" ] && printf '%s\n' "$2" > "$FIX/$1/issue-1.md"
  return 0
}
two() {  # two Renovate issues, #1 and #2, both fresh
  printf '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"%s"},{"number":2,"author":{"login":"renovate[bot]"},"updatedAt":"%s"}]' "$FRESH" "$FRESH"
}

mk clean "$DASH

## Detected dependencies"
mk failures "$DASH

> [!WARNING]
> Renovate failed to look up the following dependencies: \`Failed to look up docker package 123.dkr.ecr.us-gov-west-1.amazonaws.com/base\`, \`Can't find version matching 1.2 for github-tags package foo/bar\`."
mk digest "$DASH

 - Could not determine new digest for update (docker package registry.example/x)"
mk problems "$DASH

## Repository Problems

 - WARN: No docker auth found - returning
 - ERROR: ECR getAuthorizationToken error

## Detected dependencies"
mk errored "$DASH

## Errored

 - [ ] <!-- retry-branch=renovate/foo -->Update foo to v2

## Detected dependencies"
mk halted "There is an error with this repository's Renovate configuration. As a result, Renovate will pause PRs until it is resolved.

Message: \`Add missing credentials\`"
mk haltnomsg "Action Required: Renovate will stop PRs until it is resolved."
mk unrec "Some other renovate issue body"
# realdash: the Dependency Dashboard of Valid-Eval/ve-tools (issue #5), captured 2026-10-07 by
# `gh issue view 5 --json body --jq .body`; Renovate version not recorded. Refresh by re-capturing.
mkdir -p "$FIX/realdash"; cp "$HERE/fixtures/real-dashboard.md" "$FIX/realdash/issue-1.md"
printf '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"%s"}]' "$FRESH" > "$FIX/realdash/issues.json"
mk future "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2027-10-05T00:00:00Z"}]'
mk skew_ok "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2026-10-07T00:30:00Z"}]'     # 30 min ahead
mk skew_edge "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2026-10-07T01:00:00Z"}]'   # exactly 1 h ahead
mk skew_bad "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2026-10-07T01:00:01Z"}]'    # 1 h 1 s ahead
mk marker_manual "<!-- manual job -->
## Detected dependencies"
mk marker_header "This issue lists Renovate updates and detected dependencies.
## Detected dependencies"
mk nine "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2026-09-28T00:00:00Z"}]'   # 9 days old
mk prob_unread "" "$(two)"; cp "$FIX/problems/issue-1.md" "$FIX/prob_unread/issue-1.md"; echo 'HTTP 502' > "$FIX/prob_unread/issue-2.err"
mk unrec_unread "" "$(two)"; cp "$FIX/unrec/issue-1.md" "$FIX/unrec_unread/issue-1.md"; echo 'HTTP 502' > "$FIX/unrec_unread/issue-2.err"
mk onlyunread ""; echo 'HTTP 502: Bad Gateway' > "$FIX/onlyunread/issue-1.err"
mk stale_fresh "" "$(printf '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"%s"},{"number":2,"author":{"login":"app/renovate"},"updatedAt":"%s"}]' "$OLD" "$FRESH")"; cp "$FIX/clean/issue-1.md" "$FIX/stale_fresh/issue-1.md"; cp "$FIX/clean/issue-1.md" "$FIX/stale_fresh/issue-2.md"
mk cfg_emptyerr "" '[]'; : > "$FIX/cfg_emptyerr/c__root.err"
mk cfg_scopeerr "" '[]'; echo 'gh: API rate limit exceeded (HTTP 403)' > "$FIX/cfg_scopeerr/c__root.err"
mk stale "$DASH" "[{\"number\":1,\"author\":{\"login\":\"app/renovate\"},\"updatedAt\":\"$OLD\"}]"
mk edge7 "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2026-09-30T00:00:00Z"}]'   # exactly 7 days
mk edge7p "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"2026-09-29T23:59:59Z"}]'  # 7 days + 1s
mk nostamp "$DASH" '[{"number":1,"author":{"login":"app/renovate"}}]'
mk badstamp "$DASH" '[{"number":1,"author":{"login":"app/renovate"},"updatedAt":"yesterday"}]'
mk fail_then_halt "" "$(two)"; printf '%s\n' "$(cat "$FIX/failures/issue-1.md")" > "$FIX/fail_then_halt/issue-1.md"; cp "$FIX/halted/issue-1.md" "$FIX/fail_then_halt/issue-2.md"
mk halt_then_fail "" "$(two)"; cp "$FIX/halted/issue-1.md" "$FIX/halt_then_fail/issue-1.md"; cp "$FIX/failures/issue-1.md" "$FIX/halt_then_fail/issue-2.md"
mk clean_unread "" "$(two)"; cp "$FIX/clean/issue-1.md" "$FIX/clean_unread/issue-1.md"; echo 'HTTP 502: Bad Gateway' > "$FIX/clean_unread/issue-2.err"
mk fail_unread "" "$(two)"; cp "$FIX/failures/issue-1.md" "$FIX/fail_unread/issue-1.md"; echo 'HTTP 502: Bad Gateway' > "$FIX/fail_unread/issue-2.err"
mk clean_unrec "" "$(two)"; cp "$FIX/clean/issue-1.md" "$FIX/clean_unrec/issue-1.md"; cp "$FIX/unrec/issue-1.md" "$FIX/clean_unrec/issue-2.md"
mk human "" '[{"number":5,"author":{"login":"jacob"},"updatedAt":"2026-10-05T00:00:00Z"}]'
mk noissues "" '[]'
mk disabled ""; echo 'the repo Valid-Eval/disabled has disabled issues' > "$FIX/disabled/issues.err"
mk ratelimit ""; echo 'GraphQL: API rate limit exceeded for user' > "$FIX/ratelimit/issues.err"
mk badjson "" 'not json'
mk badauthor "" '[1,"x"]'
mk toomany "" "$(jq -nc '[range(500)|{number:.,author:{login:"x"}}]')"
# configured-but-no-dashboard repos (for --all)
mk cfg_nodash "" '[]';   printf 'renovate.json\n' > "$FIX/cfg_nodash/c__root"
mk cfg_human "" '[{"number":5,"author":{"login":"ve-automation-bot"},"updatedAt":"2026-10-05T00:00:00Z"}]'; printf '.github\n' > "$FIX/cfg_human/c__root"; printf 'renovate.json5\n' > "$FIX/cfg_human/c_.github"
mk cfg_disabled ""; echo 'has disabled issues' > "$FIX/cfg_disabled/issues.err"; printf 'renovate.json\n' > "$FIX/cfg_disabled/c__root"
mk plain_nodash "" '[]'; printf 'README.md\n' > "$FIX/plain_nodash/c__root"
mk plain_disabled ""; echo 'has disabled issues' > "$FIX/plain_disabled/issues.err"; printf 'README.md\n' > "$FIX/plain_disabled/c__root"
# discovery matrix
for r in d_root d_dotgh d_pkg d_pkgno d_empty d_err d_none d_arch d_badpkg d_dotgherr; do cp -R "$FIX/clean" "$FIX/$r"; done
printf 'renovate.json\nREADME.md\n' > "$FIX/d_root/c__root"; printf 'renovate.json\n' > "$FIX/d_arch/c__root"
printf '.github\n' > "$FIX/d_dotgh/c__root"; printf 'workflows\nrenovate.json5\n' > "$FIX/d_dotgh/c_.github"
printf 'package.json\n' > "$FIX/d_pkg/c__root"; echo '{"name":"x","renovate":{"extends":["config:base"]}}' > "$FIX/d_pkg/c_package.json"
printf 'package.json\n' > "$FIX/d_pkgno/c__root"; echo '{"name":"x"}' > "$FIX/d_pkgno/c_package.json"
printf 'package.json\n' > "$FIX/d_badpkg/c__root"; echo '{not json' > "$FIX/d_badpkg/c_package.json"
echo 'gh: This repository is empty. (HTTP 404)' > "$FIX/d_empty/c__root.err"
echo 'HTTP 500: server error' > "$FIX/d_err/c__root.err"
printf 'README.md\n.github\n' > "$FIX/d_none/c__root"; printf 'workflows\n' > "$FIX/d_none/c_.github"
printf '.github\n' > "$FIX/d_dotgherr/c__root"; echo 'HTTP 403 forbidden' > "$FIX/d_dotgherr/c_.github.err"
cp -R "$FIX/clean" "$FIX/d_pkgerr"; printf 'package.json\n' > "$FIX/d_pkgerr/c__root"; echo 'HTTP 502 bad gateway' > "$FIX/d_pkgerr/c_package.json.err"
cp -R "$FIX/clean" "$FIX/d_gh404pkg"; printf '.github\npackage.json\n' > "$FIX/d_gh404pkg/c__root"; echo '{"renovate":{}}' > "$FIX/d_gh404pkg/c_package.json"   # .github listed but 404
cp -R "$FIX/clean" "$FIX/d_gh404none"; printf '.github\nREADME.md\n' > "$FIX/d_gh404none/c__root"   # .github listed, but 404; nothing else
cp -R "$FIX/clean" "$FIX/d_gitlab"; printf '.gitlab\n' > "$FIX/d_gitlab/c__root"; printf 'renovate.json\n' > "$FIX/d_gitlab/c_.gitlab"
n=0; for cfg in renovate.json renovate.jsonc renovate.json5 .renovaterc .renovaterc.json .renovaterc.jsonc .renovaterc.json5; do
  n=$((n + 1)); cp -R "$FIX/clean" "$FIX/d_cfg$n"; printf '%s\n' "$cfg" > "$FIX/d_cfg$n/c__root"
done
for cfg in renovate.json renovate.jsonc renovate.json5; do
  n=$((n + 1)); cp -R "$FIX/clean" "$FIX/d_cfg$n"; printf '.github\n' > "$FIX/d_cfg$n/c__root"; printf '%s\n' "$cfg" > "$FIX/d_cfg$n/c_.github"
done

lists() {  # lists NAME... : write a repo list (non-archived) for GH_REPOLIST
  local out='[' sep=''
  for n in "$@"; do out="$out$sep{\"name\":\"$n\",\"isArchived\":false}"; sep=','; done
  printf '%s]' "$out" > "$WORK/list.json"; GH_REPOLIST="$WORK/list.json"; export GH_REPOLIST
}
lists_default() {
  unset GH_REPOLIST
  jq -nc '[{name:"d_root",isArchived:false},{name:"d_dotgh",isArchived:false},{name:"d_pkg",isArchived:false},{name:"d_pkgno",isArchived:false},{name:"d_empty",isArchived:false},{name:"d_err",isArchived:false},{name:"d_none",isArchived:false},{name:"d_arch",isArchived:true},{name:"d_badpkg",isArchived:false},{name:"d_dotgherr",isArchived:false}]' > "$FIX/repolist.json"
}
lists_default

PASS=0; FAIL=0
CASE_TIMEOUT=20   # seconds; a hung script fails its case instead of stalling the suite

# run_limited SECONDS CMD...: run CMD, print its combined output, and return its exit code, or
# 124 if it was still running after SECONDS and had to be killed. macOS has no `timeout`, so this
# is a watchdog in plain bash 3.2.
run_limited() {
  local secs="$1" pid wd rc outf="$WORK/limited.out"; shift
  "$@" > "$outf" 2>&1 &
  pid=$!
  ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  wd=$!
  wait "$pid" 2>/dev/null; rc=$?
  kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null
  cat "$outf"
  [ "$rc" -eq 137 ] && rc=124
  return "$rc"
}
t() {
  local name="$1" want="$2" out rc pat ok=1; shift 2
  local pats=""
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do pats="${pats}$1
"; shift; done
  [ "${1:-}" = "--" ] && shift
  out=$(GH_FIX="$FIX" PATH="$BIN:$PATH" RENOVATE_SWEEP_NOW="$NOW" run_limited "$CASE_TIMEOUT" /bin/bash "$SWEEP" "$@"); rc=$?
  [ "$rc" -eq 124 ] && out="TIMED OUT after ${CASE_TIMEOUT}s: $out"
  if [ "$rc" -ne "$want" ]; then ok=0; fi
  while IFS= read -r pat; do
    [ -n "$pat" ] || continue
    case "$pat" in
      '!'*) printf '%s\n' "$out" | grep -qE -- "${pat#!}" && ok=0 ;;
      *)    printf '%s\n' "$out" | grep -qE -- "$pat" || ok=0 ;;
    esac
  done <<PATS
$pats
PATS
  if [ "$ok" -eq 1 ]; then PASS=$((PASS + 1)); printf 'PASS  %s\n' "$name"
  else FAIL=$((FAIL + 1)); printf 'FAIL  %s (want rc %s, got %s)\n%s\n' "$name" "$want" "$rc" "$out" | sed 's/^/        /'; fi
}

# The watchdog itself: a command that hangs must be killed and reported as 124.
wd_out=$(run_limited 1 /bin/bash -c 'sleep 30'); wd_rc=$?
if [ "$wd_rc" -eq 124 ]; then PASS=$((PASS + 1)); echo 'PASS  a hung command is killed and reported as timed out'
else FAIL=$((FAIL + 1)); echo "FAIL  a hung command should return 124, got $wd_rc"; fi

# --- one repo, each state -------------------------------------------------
t 'clean dashboard: CLEAN, exit 0'                 0 'CLEAN +: 1' 'UNREADABLE +: 0' -- --repo clean
t 'lookup failures: FAILURES, exit 1'              1 'FAILURES +: 1' 'Failed|docker package' -- --repo failures
t 'digest-only failure still FAILURES'             1 'FAILURES +: 1' 'Could not determine new digest' -- --repo digest
t 'repository problems: PROBLEMS, exit 1'          1 'PROBLEMS +: 1' 'ECR getAuthorizationToken' -- --repo problems
t 'errored updates: PROBLEMS, exit 1'              1 'PROBLEMS +: 1' '1 errored update' -- --repo errored
t 'halt with a message: HALTED, exit 1'            1 'HALTED +: 1' 'Add missing credentials' -- --repo halted
t 'halt without a message: HALTED, exit 1'         1 'HALTED +: 1' -- --repo haltnomsg
t 'unrecognised Renovate issue is never clean'     1 'UNRECOGNIZED +: 1' 'CLEAN +: 0' -- --repo unrec
# --- staleness ------------------------------------------------------------
t 'dashboard older than 7 days: STALE, exit 1'     1 'STALE +: 1' 'CLEAN +: 0' '17 days ago' -- --repo stale
t 'exactly 7 days is not stale'                    0 'CLEAN +: 1' 'STALE +: 0' -- --repo edge7
t '7 days and 1 second is stale'                   1 'STALE +: 1' -- --repo edge7p
t '--stale-days widens the limit'                  0 'CLEAN +: 1' -- --repo stale --stale-days 30
t '--stale-days narrows the limit'                 1 'STALE +: 1' -- --repo clean --stale-days 1
t 'missing updatedAt: UNREADABLE, exit 2'          2 'UNREADABLE +: 1' 'no usable updatedAt' 'CLEAN +: 0' -- --repo nostamp
t 'unparseable updatedAt: UNREADABLE, exit 2'      2 'UNREADABLE +: 1' 'no usable updatedAt \(yesterday\)' -- --repo badstamp
# --- repos with several Renovate issues ----------------------------------
t 'FAILURES then HALTED: worst wins (HALTED)'      1 'HALTED +: 1' 'FAILURES +: 0' -- --repo fail_then_halt
t 'HALTED then FAILURES: worst wins (HALTED)'      1 'HALTED +: 1' 'FAILURES +: 0' -- --repo halt_then_fail
t 'clean + unreadable issue is UNREADABLE, exit 2' 2 'UNREADABLE +: 1' 'CLEAN +: 0' -- --repo clean_unread
t 'finding + unreadable issue: exit 1, partially read' 1 'FAILURES +: 1' 'partially read +: 1' 'UNREADABLE +: 0' '\(\+1 Renovate issue\(s\) unreadable\)' -- --repo fail_unread
t 'clean + unrecognised issue is UNRECOGNIZED'     1 'UNRECOGNIZED +: 1' 'CLEAN +: 0' -- --repo clean_unrec
# --- no dashboard ---------------------------------------------------------
t 'no Renovate issue: NO_DASHBOARD, exit 1 (default scope)' 1 'NO_DASHBOARD +: 1' -- --repo human
t 'no issues at all: NO_DASHBOARD, exit 1'         1 'NO_DASHBOARD +: 1' -- --repo noissues
t 'issues disabled: NO_DASHBOARD, exit 1'          1 'NO_DASHBOARD +: 1' 'issues are disabled' -- --repo disabled
# --- could not read -------------------------------------------------------
t 'rate limit: UNREADABLE with gh error, exit 2'   2 'UNREADABLE +: 1' 'rate limit exceeded' 'COVERAGE INCOMPLETE' -- --repo ratelimit
t 'unparseable issue list: UNREADABLE, exit 2'     2 'UNREADABLE +: 1' 'could not parse gh issue list' -- --repo badjson
t 'unparseable authors: UNREADABLE, exit 2'        2 'UNREADABLE +: 1' 'could not parse issue authors' -- --repo badauthor
t 'issue list at the limit: UNREADABLE, exit 2'    2 'UNREADABLE +: 1' 'hit the 500 limit' -- --repo toomany
t 'one unreadable repo among clean ones: exit 2'   2 'attempted +: 2' 'UNREADABLE +: 1' 'CLEAN +: 1' -- --repo clean --repo ratelimit
# --- --all ----------------------------------------------------------------
lists plain_nodash plain_disabled clean
t '--all: NO_DASHBOARD with no config is allowed'  0 'NO_DASHBOARD +: 2' 'NO_DASHBOARD_CONFIGURED: 0' -- --all
lists cfg_nodash
t '--all: config at the root, no dashboard: finding'      1 'NO_DASHBOARD_CONFIGURED: 1' 'has a Renovate config' -- --all
lists cfg_human
t '--all: config in .github, dashboard by another author: finding' 1 'NO_DASHBOARD_CONFIGURED: 1' -- --all
lists cfg_disabled
t '--all: config but issues disabled: finding'     1 'NO_DASHBOARD_CONFIGURED: 1' 'issues are disabled' -- --all
t '--all with --repo is a usage error'             64 'cannot be combined' -- --all --repo clean
# --- discovery ------------------------------------------------------------
lists_default
t 'default scope: config repos in; no-config, empty, archived out' 0 'attempted +: 6' 'd_root' 'd_dotgh' 'd_pkg ' '!d_pkgno' '!d_empty' '!d_none' '!d_arch' -- 
t 'default scope keeps repos whose scope lookup failed or was unparseable' 0 'd_err' 'd_badpkg' 'd_dotgherr' -- 
lists_default
jq -nc '[range(1000)|{name:("r\(.)"),isArchived:false}]' > "$FIX/repolist.json"
t 'repo list at the limit is fatal'                2 'hit the 1000 limit' -- --quiet
echo '[]' > "$FIX/repolist.json"
t 'empty org: fatal, exit 2'                       2 'no non-archived repos' -- --quiet
echo '[{"name":"a","isArchived":true}]' > "$FIX/repolist.json"
t 'all repos archived: fatal, exit 2'              2 'no non-archived repos' -- --quiet
echo 'not json' > "$FIX/repolist.json"
t 'unparseable repo list: fatal, exit 2'           2 'could not parse the repo list' -- --quiet
echo 'HTTP 502' > "$FIX/repolist.json.err"
t 'repo list error: fatal, exit 2'                 2 'could not list repos' -- --quiet
rm -f "$FIX/repolist.json.err"; lists_default
t 'a real dashboard body (sections, checkboxes) reads CLEAN, not PROBLEMS' 0 'CLEAN +: 1' 'PROBLEMS +: 0' '!errored' -- --repo realdash
t 'dashboard updatedAt in the future: UNREADABLE, exit 2' 2 'UNREADABLE +: 1' 'in the future' 'CLEAN +: 0' -- --repo future
t 'PROBLEMS + unreadable issue: UNREADABLE, exit 2' 2 'UNREADABLE +: 1' 'PROBLEMS +: 0' -- --repo prob_unread
t 'UNRECOGNIZED + unreadable issue: UNREADABLE, exit 2' 2 'UNREADABLE +: 1' 'UNRECOGNIZED +: 0' -- --repo unrec_unread
t 'a stale dashboard and a fresh one: STALE outranks CLEAN' 1 'STALE +: 1' 'CLEAN +: 0' -- --repo stale_fresh
t 'a clean repo has no partial-read note' 0 'partially read +: 0' '!issue\(s\) unreadable' -- --repo clean
t 'a wholly unreadable repo is not "partially read"' 2 'partially read +: 0' 'UNREADABLE +: 1' -- --repo ratelimit
t 'a repo whose only Renovate issue is unreadable is not "partially read"' 2 'partially read +: 0' 'UNREADABLE +: 1' '!issue\(s\) unreadable' -- --repo onlyunread
t '--quiet prints the summary only' 0 'attempted +: 1' '!dashboard last updated' -- --quiet --repo clean
t 'halt without a message shows the first line as the reason' 1 'Action Required: Renovate will stop PRs' -- --repo haltnomsg
t '--stale-days 010 means ten days, not octal 8' 0 'CLEAN +: 1' 'STALE +: 0' -- --repo nine --stale-days 010
t '--stale-days 000 means zero days (everything not brand-new is stale)' 1 'STALE +: 1' 'limit 0' -- --repo clean --stale-days 000
t '--stale-days over 6 digits is a usage error, not a silent wrap' 64 'too large' -- --repo clean --stale-days 213503982334601
t '--stale-days 0000000000000000000000008 is eight days' 1 'STALE +: 1' 'limit 8' -- --repo nine --stale-days 0000000000000000000000008
t '--stale-days 08 is accepted (eight days)' 1 'STALE +: 1' 'limit 8' -- --repo nine --stale-days 08
t 'RENOVATE_SWEEP_NOW is announced on stderr' 0 'RENOVATE_SWEEP_NOW is set' -- --repo clean
out=$(GH_FIX="$FIX" PATH="$BIN:$PATH" RENOVATE_SWEEP_NOW=1e20 run_limited "$CASE_TIMEOUT" /bin/bash "$SWEEP" --repo clean); rc=$?
if [ "$rc" -eq 64 ] && printf '%s' "$out" | grep -q 'whole epoch seconds'; then PASS=$((PASS + 1)); echo 'PASS  a non-integer RENOVATE_SWEEP_NOW is a usage error'
else FAIL=$((FAIL + 1)); echo "FAIL  non-integer RENOVATE_SWEEP_NOW should exit 64 (got $rc)"; fi
# --all, scope lookup failure
lists cfg_scopeerr
t '--all: no dashboard and a failed config lookup is UNREADABLE, exit 2' 2 'UNREADABLE +: 1' 'config lookup failed' 'NO_DASHBOARD_CONFIGURED: 0' -- --all
lists cfg_emptyerr
t '--all: a failed config lookup with no stderr still says why' 2 'UNREADABLE +: 1' 'config lookup failed: gh exited non-zero with no message' -- --all
lists_default
# --- more discovery -------------------------------------------------------
lists d_pkgno d_none
t 'default scope with no config repos is fatal, not healthy' 2 'no repos in scope' -- 
lists d_gh404none d_root
t 'a .github that 404s and no other config: out of default scope' 0 'attempted +: 1' '!d_gh404none' -- 
lists d_gh404none
mk d_gh404none "" '[]'
t '--all: a .github that 404s with no config is NO_DASHBOARD, not UNREADABLE' 0 'NO_DASHBOARD +: 1' 'UNREADABLE +: 0' -- --all
lists_default
mk d_gh404none "$DASH"
lists d_pkgerr d_gh404pkg d_gitlab d_cfg1 d_cfg2 d_cfg3 d_cfg4 d_cfg5 d_cfg6 d_cfg7 d_cfg8 d_cfg9 d_cfg10
t 'every config name Renovate reads, .gitlab/, .github with a 404, and a failed package.json fetch all keep the repo in scope' 0 'attempted +: 13' -- 
lists_default
out=$(GH_FIX="$FIX" PATH="$BIN:$PATH" RENOVATE_SWEEP_NOW=99999999999999999999 run_limited "$CASE_TIMEOUT" /bin/bash "$SWEEP" --repo clean); rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q 'no usable updatedAt' && ! printf '%s' "$out" | grep -qE 'CLEAN +: 1'; then PASS=$((PASS + 1)); echo 'PASS  an age too large to compare is UNREADABLE, not CLEAN'
else FAIL=$((FAIL + 1)); echo "FAIL  an absurd clock should be UNREADABLE exit 2 (got $rc)"; printf '%s\n' "$out" | sed 's/^/        /'; fi
out=$(GH_FIX="$FIX" PATH="$BIN:$PATH" RENOVATE_SWEEP_NOW=100000000000000000000000000000 run_limited "$CASE_TIMEOUT" /bin/bash "$SWEEP" --repo clean); rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q 'no usable updatedAt'; then PASS=$((PASS + 1)); echo 'PASS  an age that jq prints in exponent form is UNREADABLE, not CLEAN'
else FAIL=$((FAIL + 1)); echo "FAIL  an exponent-form age should be UNREADABLE exit 2 (got $rc)"; printf '%s\n' "$out" | sed 's/^/        /'; fi
t 'updatedAt 30 minutes ahead is within the skew tolerance: CLEAN' 0 'CLEAN +: 1' -- --repo skew_ok
t 'updatedAt exactly 1 hour ahead is still within tolerance: CLEAN' 0 'CLEAN +: 1' -- --repo skew_edge
t 'updatedAt 1 hour 1 second ahead is UNREADABLE' 2 'UNREADABLE +: 1' 'in the future' -- --repo skew_bad
t 'a dashboard with only the manual-job marker is recognised' 0 'CLEAN +: 1' -- --repo marker_manual
t 'a dashboard with only the header sentence is recognised' 0 'CLEAN +: 1' -- --repo marker_header
t '--stale-days with an empty value is a usage error' 64 'whole number' -- --repo clean --stale-days ''
t 'default scope: a failed config lookup on a repo with no dashboard is UNREADABLE, not a finding' 2 'UNREADABLE +: 1' 'config lookup failed' 'NO_DASHBOARD +: 0' -- --repo cfg_scopeerr
# --- usage ----------------------------------------------------------------
t 'repeated --repo is swept once'                  0 'attempted +: 1' -- --repo clean --repo clean
t '--repo with no value: exit 64'                  64 'needs a value' -- --repo
t '--org with no value: exit 64'                   64 'needs a value' -- --org
t '--stale-days with no value: exit 64'            64 'needs a value' -- --stale-days
t '--stale-days not a number: exit 64'             64 'whole number' -- --stale-days abc --repo clean
t 'unknown flag: exit 64'                          64 'unknown argument' -- --nope
t '--help prints the contract, exit 0'             0 'EXIT CODES' 'REQUIREMENTS' -- --help

# gh missing: a PATH holding the other tools but no gh.
NOGH="$WORK/nogh"; mkdir -p "$NOGH"
for tool in jq sed grep awk head tr cut sort date mktemp rm cat; do ln -s "$(command -v $tool)" "$NOGH/$tool" 2>/dev/null; done
out=$(run_limited "$CASE_TIMEOUT" env PATH="$NOGH" /bin/bash "$SWEEP" --repo clean); rc=$?
if [ "$rc" -eq 64 ] && printf '%s' "$out" | grep -q 'gh not found'; then PASS=$((PASS + 1)); echo 'PASS  gh missing: exit 64'
else FAIL=$((FAIL + 1)); echo "FAIL  gh missing: exit 64 (got $rc)"; fi

NOJQ="$WORK/nojq"; mkdir -p "$NOJQ"
for tool in gh sed grep awk head tr cut sort date mktemp rm cat; do ln -s "$(command -v $tool 2>/dev/null || echo "$BIN/gh")" "$NOJQ/$tool" 2>/dev/null; done
ln -sf "$BIN/gh" "$NOJQ/gh"
out=$(run_limited "$CASE_TIMEOUT" env PATH="$NOJQ" /bin/bash "$SWEEP" --repo clean); rc=$?
if [ "$rc" -eq 64 ] && printf '%s' "$out" | grep -q 'jq not found'; then PASS=$((PASS + 1)); echo 'PASS  jq missing: exit 64'
else FAIL=$((FAIL + 1)); echo "FAIL  jq missing: exit 64 (got $rc)"; fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$PASS" -gt 0 ] && [ "$FAIL" -eq 0 ]
