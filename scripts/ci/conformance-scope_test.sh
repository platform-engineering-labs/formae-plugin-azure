#!/usr/bin/env bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
# Self-check for conformance-scope.sh. Builds a throwaway git repo per case, so
# it exercises the real diff and the real name mapping. No network, no Azure.
#
#   ./scripts/ci/conformance-scope_test.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/conformance-scope.sh"
PASS=0 FAIL=0

# run_case <name> <expected-count> <expected-json> <setup-commands...>
run_case() {
  local name="$1" want_count="$2" want_json="$3"; shift 3
  local dir; dir=$(mktemp -d)
  (
    set -e
    cd "$dir"
    git init -q .
    git config user.email t@t; git config user.name t
    mkdir -p testdata .github scripts/ci
    cp "$SCRIPT" scripts/ci/conformance-scope.sh
    # A curated matrix that is deliberately different from any fixture set below,
    # so a case that wrongly falls back to it is obvious.
    printf '# comment\n\ncurated-only\n' > .github/conformance-matrix.txt
    printf 'x\n' > testdata/pre-existing.pkl
    git add -A; git commit -q -m base
    BASE=$(git rev-parse HEAD)
    eval "$@"
    git add -A; git commit -q -m change --allow-empty
    out=$(EVENT_NAME=pull_request BASE_SHA="$BASE" FULL_LABEL=false \
          bash scripts/ci/conformance-scope.sh 2>&1)
    got_count=$(printf '%s' "$out" | sed -n 's/^count=//p')
    got_json=$(printf '%s' "$out" | tail -1)
    if [ "$got_count" = "$want_count" ] && [ "$got_json" = "$want_json" ]; then
      exit 0
    fi
    echo "    want count=$want_count json=$want_json"
    echo "    got  count=$got_count json=$got_json"
    exit 1
  )
  if [ $? -eq 0 ]; then
    echo "ok   $name"; PASS=$((PASS+1))
  else
    echo "FAIL $name"; FAIL=$((FAIL+1))
  fi
  rm -rf "$dir"
}

run_case "added fixture is in scope" 1 "web-app" \
  'printf "x\n" > testdata/web-app.pkl'

run_case "companion maps back to its fixture" 1 "web-app" \
  'printf "x\n" > testdata/web-app.pkl; printf "y\n" > testdata/web-app-update.pkl'

run_case "-replace companion maps back too" 1 "cosmos-table" \
  'printf "x\n" > testdata/cosmos-table.pkl; printf "y\n" > testdata/cosmos-table-replace.pkl'

run_case "editing only the companion still runs the fixture" 1 "pre-existing" \
  'printf "y\n" > testdata/pre-existing-update.pkl'

run_case "suffix look-alike is its own fixture, not a companion" 2 "subnet, subnet-delegated" \
  'printf "x\n" > testdata/subnet.pkl; printf "y\n" > testdata/subnet-delegated.pkl'

run_case "deletion alone is out of scope" 0 "(none)" \
  'git rm -q testdata/pre-existing.pkl'

run_case "non-fixture change is out of scope" 0 "(none)" \
  'printf "x\n" > README.md'

run_case "several fixtures are deduped and sorted" 2 "a-thing, b-thing" \
  'printf "x\n" > testdata/b-thing.pkl; printf "x\n" > testdata/b-thing-update.pkl;
   printf "x\n" > testdata/a-thing.pkl'

run_case "skip-listed fixture is subtracted" 1 "web-app" \
  'printf "x\n" > testdata/web-app.pkl; printf "x\n" > testdata/vpn-gateway.pkl;
   printf "# r\nvpn-gateway\n" > .github/conformance-pr-skip.txt'

run_case "every touched fixture skip-listed leaves an empty scope" 0 "(none)" \
  'printf "x\n" > testdata/vpn-gateway.pkl;
   printf "vpn-gateway\n" > .github/conformance-pr-skip.txt'

# A name in both files is a contradiction and must fail, not silently resolve.
dir=$(mktemp -d)
(
  cd "$dir"; git init -q .; git config user.email t@t; git config user.name t
  mkdir -p testdata .github scripts/ci
  cp "$SCRIPT" scripts/ci/conformance-scope.sh
  printf 'both-ways\n' > .github/conformance-matrix.txt
  printf 'both-ways\n' > .github/conformance-pr-skip.txt
  printf 'x\n' > testdata/both-ways.pkl
  git add -A; git commit -q -m base
  EVENT_NAME=push bash scripts/ci/conformance-scope.sh >/dev/null 2>&1
)
if [ $? -ne 0 ]; then echo "ok   matrix/skip overlap fails loudly"; PASS=$((PASS+1))
else echo "FAIL matrix/skip overlap fails loudly"; FAIL=$((FAIL+1)); fi
rm -rf "$dir"

# A companion whose base fixture does not exist must fail loudly rather than
# filter to nothing and pass green.
dir=$(mktemp -d)
(
  cd "$dir"; git init -q .; git config user.email t@t; git config user.name t
  mkdir -p testdata .github scripts/ci
  cp "$SCRIPT" scripts/ci/conformance-scope.sh
  printf 'curated-only\n' > .github/conformance-matrix.txt
  git add -A; git commit -q -m base
  BASE=$(git rev-parse HEAD)
  printf 'y\n' > testdata/orphan-update.pkl
  git add -A; git commit -q -m change
  EVENT_NAME=pull_request BASE_SHA="$BASE" bash scripts/ci/conformance-scope.sh >/dev/null 2>&1
)
if [ $? -ne 0 ]; then echo "ok   orphan companion fails loudly"; PASS=$((PASS+1))
else echo "FAIL orphan companion fails loudly"; FAIL=$((FAIL+1)); fi
rm -rf "$dir"

# push and the full-conformance label both take the curated matrix.
dir=$(mktemp -d)
(
  cd "$dir"; git init -q .; git config user.email t@t; git config user.name t
  mkdir -p testdata .github scripts/ci
  cp "$SCRIPT" scripts/ci/conformance-scope.sh
  printf '# c\n\ncurated-only\n' > .github/conformance-matrix.txt
  git add -A; git commit -q -m base
  push_out=$(EVENT_NAME=push bash scripts/ci/conformance-scope.sh 2>&1 | tail -1)
  label_out=$(EVENT_NAME=pull_request FULL_LABEL=true BASE_SHA=$(git rev-parse HEAD) \
              bash scripts/ci/conformance-scope.sh 2>&1 | tail -1)
  [ "$push_out" = "curated-only" ] && [ "$label_out" = "curated-only" ]
)
if [ $? -eq 0 ]; then echo "ok   push and full-conformance label use curated matrix"; PASS=$((PASS+1))
else echo "FAIL push and full-conformance label use curated matrix"; FAIL=$((FAIL+1)); fi
rm -rf "$dir"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
