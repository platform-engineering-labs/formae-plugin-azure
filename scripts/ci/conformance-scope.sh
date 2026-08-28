#!/usr/bin/env bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
# Decide which conformance fixtures a run should exercise.
#
#   push / workflow_dispatch / a PR labelled `full-conformance`
#     -> the whole curated matrix in .github/conformance-matrix.txt
#   any other pull request
#     -> only the fixtures the PR actually touched
#
# A pull request previously ran no conformance at all, so a new or edited fixture
# was unverified until it reached main, and the only way to check one early was to
# dispatch debug-conformance.yml by hand. Scoping the matrix to the touched
# fixtures gives a PR the same evidence the curated matrix asks for - CRUD *and*
# discovery green - without paying for the other ~130 resources.
#
# Deletions are ignored on purpose: a removed fixture has nothing left to run.
# A fixture's `-update` / `-replace` companion maps back to the fixture itself,
# since one matrix entry drives the whole lifecycle. Only those two suffixes are
# stripped - `subnet-delegated`, `ip-group` and friends are independent fixtures
# with their own matrix lines, not companions.
#
# Writes `resources` (a JSON array) and `count` to $GITHUB_OUTPUT.
#
# Inputs (environment):
#   EVENT_NAME  github.event_name
#   BASE_SHA    github.event.pull_request.base.sha  (pull_request only)
#   FULL_LABEL  "true" when the PR carries the full-conformance label
#   GITHUB_OUTPUT / GITHUB_STEP_SUMMARY  optional; stdout-only when unset
set -euo pipefail

EVENT_NAME="${EVENT_NAME:-push}"
BASE_SHA="${BASE_SHA:-}"
FULL_LABEL="${FULL_LABEL:-false}"

MATRIX_FILE=".github/conformance-matrix.txt"
SKIP_FILE=".github/conformance-pr-skip.txt"

emit() {
  local resources="$1" count="$2" reason="$3" skipped="${4:-}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'resources=%s\n' "$resources" >> "$GITHUB_OUTPUT"
    printf 'count=%s\n' "$count" >> "$GITHUB_OUTPUT"
  fi
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### Conformance scope\n\n%s\n\n' "$reason"
      if [ -n "$skipped" ]; then
        printf 'Skipped per `%s`:\n\n' "$SKIP_FILE"
        printf '%s\n' "$skipped" | sed 's/^/- `/;s/$/`/'
        printf '\n'
      fi
      if [ "$count" -eq 0 ]; then
        printf 'No fixtures to run.\n'
      else
        printf '%s fixture(s):\n\n' "$count"
        echo "$resources" | jq -r '.[] | "- `\(.)`"'
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  printf '%s\n' "$reason"
  if [ -n "$skipped" ]; then
    printf 'skipped per %s: %s\n' "$SKIP_FILE" "$(printf '%s' "$skipped" | tr '\n' ' ')"
  fi
  printf 'count=%s\n' "$count"
  echo "$resources" | jq -r 'if length == 0 then "(none)" else join(", ") end'
}

entries() {
  # One name per line, '#' comments and blank lines dropped.
  [ -f "$1" ] || return 0
  grep -vE '^[[:space:]]*(#|$)' "$1" | sed 's/[[:space:]]*$//' | sed '/^$/d'
}

curated_matrix() {
  entries "$MATRIX_FILE" | jq -R . | jq -sc .
}

# A name in both files is a contradiction: the matrix says run it everywhere, the
# skip list says never run it on a PR. Fail rather than silently pick one.
assert_no_overlap() {
  local both
  both=$(comm -12 <(entries "$MATRIX_FILE" | sort -u) <(entries "$SKIP_FILE" | sort -u))
  if [ -n "$both" ]; then
    echo "::error::listed in both $MATRIX_FILE and $SKIP_FILE: $(printf '%s' "$both" | tr '\n' ' ')" >&2
    exit 1
  fi
}

assert_no_overlap

# --- full matrix ------------------------------------------------------------
if [ "$EVENT_NAME" != "pull_request" ] || [ "$FULL_LABEL" = "true" ]; then
  RESOURCES=$(curated_matrix)
  COUNT=$(echo "$RESOURCES" | jq 'length')
  if [ "$COUNT" -eq 0 ]; then
    echo "::error::$MATRIX_FILE yielded no resources" >&2
    exit 1
  fi
  if [ "$FULL_LABEL" = "true" ]; then
    REASON="Full curated matrix (\`full-conformance\` label)."
  else
    REASON="Full curated matrix (\`$EVENT_NAME\`)."
  fi
  emit "$RESOURCES" "$COUNT" "$REASON"
  exit 0
fi

# --- pull request: only what changed ---------------------------------------
if [ -z "$BASE_SHA" ]; then
  echo "::error::BASE_SHA is required on a pull_request" >&2
  exit 1
fi

# Three-dot: changes on this branch since it diverged from the base, so an
# unrelated commit landing on the base does not pull extra fixtures into scope.
# Needs the full history that actions/checkout fetch-depth: 0 provides.
if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
  echo "::error::base commit $BASE_SHA is not in this checkout - is fetch-depth: 0 set?" >&2
  exit 1
fi

CHANGED=$(git diff --name-only --diff-filter=ACMR "${BASE_SHA}...HEAD" -- 'testdata/*.pkl' || true)

NAMES=$(printf '%s\n' "$CHANGED" \
  | sed -n 's|^testdata/||p' \
  | sed 's|\.pkl$||' \
  | sed -E 's/-(update|replace)$//' \
  | sort -u \
  | sed '/^$/d')

if [ -z "$NAMES" ]; then
  emit '[]' 0 'No `testdata/*.pkl` fixtures added or modified - conformance skipped.'
  exit 0
fi

# A name whose fixture does not exist would set FORMAE_TEST_FILTER to something
# that matches nothing, and the job would pass green having tested nothing. Same
# guard debug-conformance.yml applies to its hand-typed input.
MISSING=""
while IFS= read -r n; do
  [ -f "testdata/${n}.pkl" ] || MISSING="${MISSING} ${n}"
done <<< "$NAMES"
if [ -n "$MISSING" ]; then
  echo "::error::changed companion fixture with no base fixture:${MISSING} - expected testdata/<name>.pkl" >&2
  exit 1
fi

# Subtract the never-auto-run list. Done after the existence check, so a typo in
# the skip file cannot mask a genuinely broken fixture name.
SKIPPED=$(comm -12 <(printf '%s\n' "$NAMES" | sort -u) <(entries "$SKIP_FILE" | sort -u))
KEPT=$(comm -23 <(printf '%s\n' "$NAMES" | sort -u) <(entries "$SKIP_FILE" | sort -u))

if [ -z "$KEPT" ]; then
  emit '[]' 0 'Every fixture this pull request touched is on the never-auto-run list.' "$SKIPPED"
  exit 0
fi

RESOURCES=$(printf '%s\n' "$KEPT" | jq -R . | jq -sc .)
COUNT=$(echo "$RESOURCES" | jq 'length')
emit "$RESOURCES" "$COUNT" 'Fixtures added or modified by this pull request.' "$SKIPPED"
