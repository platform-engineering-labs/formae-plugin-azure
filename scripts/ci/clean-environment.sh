#!/bin/bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Clean Environment Hook for Azure
# =================================
# Deletes every resource group matching the test prefix, then VERIFIES they are
# gone. Called before and after conformance tests, and by the scheduled reaper.
#
# Deletes, waits, verifies, and FAILS if anything survives. There is no lenient
# mode: a leftover group means the previous run leaked, and starting a conformance
# run against a dirty subscription invites name collisions and phantom drift. The
# scheduled reaper retries every 6 hours, so a transient slow delete resolves
# itself; a group that survives repeatedly is a real problem and should block.
#
# Environment:
#   TEST_PREFIX        resource-group prefix to sweep (default formae-plugin-sdk-test-)
#   CLEAN_WAIT_MINUTES how long to wait for deletions to finish (default 25)
#
# Why this verifies instead of firing and forgetting
# --------------------------------------------------
# The previous version ran `az group delete --yes --no-wait || true` per group and
# printed "Cleanup complete" unconditionally. Two ways that leaked silently:
#
#   1. A REFUSED delete - a delete lock, a child resource that blocks its parent,
#      an ARM conflict - was swallowed by `|| true`, and the script still exited 0.
#      A leak could therefore never turn CI red.
#   2. The group list was taken ONCE. When a run is cancelled, its matrix jobs are
#      still mid-create; groups that appeared after the snapshot were never
#      revisited. A cancelled full-matrix run on 2026-08-28 left 28 groups behind
#      this way - including an Application Gateway and three Virtual WAN hubs,
#      billing for three days - while its cleanup job reported success.
#
# So: delete, wait for ARM to actually finish, then re-list and sweep again to
# catch anything created during the first pass. A survivor is a non-zero exit,
# which is the only way a leak becomes visible.
#
# Deletion is asynchronous and slow for some types (an Application Gateway or a
# Cosmos account is ~10 min), hence the wait budget rather than a fixed sleep.

set -eEuo pipefail

# Report where an unexpected failure happened.
#
# This script has failed three times in CI (pre-cleanup on #145, the nightly
# cleanup job, and the scheduled reaper) with NO output beyond the banner: it
# prints "Using subscription: ..." and exits 1 about a second later, before
# either "Pass 1 - found:" or "No resource groups found" can be reached. Under
# `set -e` the failing command is silent, and the failure does not reproduce
# outside CI, so there is nothing to read.
#
# $LINENO and $BASH_COMMAND in an ERR trap name the exact command that failed,
# which turns the next occurrence into a one-line diagnosis instead of a guess.
# Set CLEAN_DEBUG=1 for a full `set -x` trace on top of it.
#
# `set -E` (errtrace) above is what makes that work. Without it an ERR trap is
# NOT inherited by shell functions, so a failure inside list_groups was reported
# against the CALLER - `clean-environment.sh failed at line 189 (exit 1):
# GROUPS=$(list_groups)` - which names the command substitution rather than the
# command that actually failed. Three fixes (#146, #147, #149) were aimed at
# line 189 on the strength of that message; the real failure was always further
# in. With -E the trap fires at the inner line and names it.
trap 'rc=$?; echo "clean-environment.sh: command failed at line ${LINENO} (exit ${rc}): ${BASH_COMMAND}" >&2' ERR

# An if-block, not `[[ ... ]] && set -x`, for the reason this file already
# documents further down: under `set -e` that construct takes the exit status of
# the failed test, which is the class of silent failure being chased here.
if [[ "${CLEAN_DEBUG:-0}" == "1" ]]; then
    set -x
fi

TEST_PREFIX="${TEST_PREFIX:-formae-plugin-sdk-test-}"
CLEAN_WAIT_MINUTES="${CLEAN_WAIT_MINUTES:-25}"

echo "clean-environment.sh: sweeping resource groups with prefix '${TEST_PREFIX}'"

if ! command -v az &> /dev/null; then
    echo "Azure CLI (az) not found. Skipping cleanup."
    exit 0
fi
if ! az account show &> /dev/null; then
    echo "Not logged in to Azure CLI. Skipping cleanup."
    exit 0
fi

echo "Using subscription: $(az account show --query name -o tsv)"

# Needed to build the ARM URL for the APIM purge below. Empty would silently
# produce an unroutable URL, so fail loudly here instead.
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
if [[ -z "${SUBSCRIPTION_ID}" ]]; then
    echo "Could not determine the subscription id. Skipping cleanup."
    exit 0
fi
echo ""

# list_groups - names of every resource group matching TEST_PREFIX, one per line.
#
# Parses JSON and re-checks the prefix LOCALLY rather than trusting the server-side
# projection. That guard matters: anything that is not a real prefixed group name -
# a truncation marker from an output-filtering wrapper, a CLI warning, a malformed
# projection - is dropped instead of being passed to `az group delete`. Deleting is
# destructive, so it only ever acts on a name it has re-verified itself.
list_groups() {
    local raw err names reported parsed=0 matched=0 name
    err=$(mktemp)
    # `|| true` goes INSIDE the substitution.
    #
    # A CLEAN_DEBUG=1 trace showed `az group list` exiting 1 in CI while writing a
    # complete, valid JSON body for all 117 groups, with `2>/dev/null` discarding
    # whatever it complained about. That status escaped the command substitution
    # and killed the script before a single group was swept - the silent failure
    # seen in pre-cleanup, the nightly cleanup job and the reaper. Neither `set +e`
    # around the call nor an explicit `return 0` below stopped it, so the status
    # must not be allowed to leave the subshell in the first place: with `true` as
    # the last command inside it, the substitution cannot report failure at all.
    # That holds without needing errexit or ERR-trap semantics to be exactly right.
    raw=$(az group list -o json 2>"${err}" || true)
    # Judge success by the output, not an exit status: a non-empty stderr from az
    # is worth surfacing even when the JSON that came with it is perfectly usable.
    if [[ -s "${err}" ]]; then
        echo "  note: 'az group list' wrote to stderr; continuing with the output it produced" >&2
        sed 's/^/    az: /' "${err}" >&2 || true
    fi
    rm -f "${err}"
    if [[ -z "${raw}" ]]; then
        echo "  note: 'az group list' produced no output" >&2
        return 0
    fi

    # How many groups did ARM actually report? Used below to prove the parse
    # succeeded rather than assuming it.
    reported=$(printf '%s' "${raw}" | jq -r 'length' 2>/dev/null || true)

    # jq's stderr is deliberately NOT discarded any more. The previous version
    # had `2>/dev/null` here and `|| true` on a `grep` prefix filter, so every
    # possible failure in this pipeline was swallowed - and one duly was: a CI
    # run parsed 204 groups down to the single token `1001`, which then passed a
    # `grep -E "^${TEST_PREFIX}..."` filter it cannot possibly match. The script
    # went on to "delete" a resource group named 1001, got ResourceGroupNotFound,
    # counted it as "already gone", and then sat in wait_gone for two full
    # 25-minute budgets while all 204 real groups survived untouched.
    names=$(printf '%s' "${raw}" | jq -r '.[]? | select(.name != null) | .name')

    # Prefix filtering is done in bash, NOT with grep.
    #
    # `grep` is the one link in the old pipeline that provably misbehaved: no
    # regex anchored on TEST_PREFIX can return `1001`. A bash prefix test needs no
    # external binary, cannot be shadowed by a wrapper on PATH, and is exact.
    while IFS= read -r name; do
        [[ -z "${name}" ]] && continue
        parsed=$((parsed + 1))
        if [[ "${name}" == "${TEST_PREFIX}"* ]]; then
            matched=$((matched + 1))
            printf '%s\n' "${name}"
        fi
    done <<< "${names}"

    # Prove the parse rather than trusting it. If ARM reported N groups and we
    # extracted a different number of names, the JSON was not parsed - and
    # "extracted no test groups" would otherwise be indistinguishable from
    # "there are no test groups", which is how a sweep silently does nothing and
    # a leak goes unnoticed. PARSE_FAILED makes the run fail loudly at the
    # verdict instead of exiting 0 on a subscription full of leaked groups.
    if [[ "${reported}" =~ ^[0-9]+$ ]] && [[ ${parsed} -ne ${reported} ]]; then
        echo "::error::clean-environment.sh: parsed ${parsed} group name(s) from an 'az group list' body that reports ${reported} group(s) - refusing to treat this as an empty subscription" >&2
        echo "    first 200 bytes of the body: ${raw:0:200}" >&2
        echo "    names extracted: ${names:0:200}" >&2
        echo failed > "${PARSE_FAIL_FLAG}"
        return 0
    fi

    if [[ "${CLEAN_DEBUG:-0}" == "1" ]]; then
        echo "  debug: az reported ${reported:-?} group(s), parsed ${parsed}, matched prefix ${matched}" >&2
    fi
    # Explicit: "no matching groups" is a normal result, not a failure. Every
    # caller assigns this through a command substitution, so any non-zero status
    # leaking out of here aborts the script before a single group is swept.
    return 0
}

# summarise_kinds <file> <indent> - print a count per resource kind, not a list
# of every group name.
#
# A full sweep touches ~200 groups, and naming each one twice (once on discovery,
# once on delete) buries the only thing a reader actually wants: WHAT was cleaned
# up. The fixture kind is already encoded in the group name, so
#   formae-plugin-sdk-test-cdn-profile-rg-6d137340
# reduces to `cdn-profile` by dropping the prefix, the trailing run id and a
# trailing `-rg`. Individual names are still available in the trace under
# CLEAN_DEBUG=1 if a specific group ever needs chasing.
#
# Deliberately no associative arrays: this has to run under the bash 3.2 used for
# local testing as well as the runner's bash 5.
summarise_kinds() {
    local file="$1" indent="${2:-  }" name kind tmp
    tmp=$(mktemp)
    while IFS= read -r name; do
        [[ -z "${name}" ]] && continue
        kind=${name#"${TEST_PREFIX}"}
        kind=${kind%-*}
        kind=${kind%-rg}
        [[ -z "${kind}" ]] && kind="(unnamed)"
        printf '%s\n' "${kind}" >> "${tmp}"
    done < "${file}"
    if [[ -s "${tmp}" ]]; then
        sort "${tmp}" | uniq -c | sort -rn | while read -r n k; do
            printf '%s%s x%s\n' "${indent}" "${k}" "${n}"
        done
    fi
    rm -f "${tmp}"
}

# remove_locks <groups...> - drop any management lock inside these groups.
#
# A CanNotDelete or ReadOnly lock makes `az group delete` fail permanently, so a
# leaked lock does not just leave one resource behind - it wedges the whole group
# and every resource in it, forever, until a human removes the lock by hand. The
# AZURE::Authorization::ManagementLock fixture creates real locks, and a run that
# is killed mid-lifecycle leaves one behind, so the reaper has to clear locks
# before it can be trusted to clear groups.
#
# Scoped to the prefixed test groups the caller already verified - this never
# touches a lock outside them.
remove_locks() {
    # Takes a FILE of group names, one per line - not positional arguments. See
    # the note above `GROUPS_FILE` for why nothing here passes the group list
    # through a variable.
    local RG
    while IFS= read -r RG; do
        [[ -z "${RG}" ]] && continue
        local ids
        ids=$(az lock list --resource-group "${RG}" --query "[].id" -o tsv 2>/dev/null) || continue
        [[ -z "${ids}" ]] && continue
        while IFS= read -r id; do
            [[ -z "${id}" ]] && continue
            echo "  removing lock ${id}"
            az lock delete --ids "${id}" 2>/dev/null || echo "    could not remove lock"
        done <<< "${ids}"
    done < "$1"
    # Explicit: this script runs under `set -e`, and issue_deletes calls this
    # first. A lock sweep that could not clean up must not abort the whole
    # cleanup - deleting groups is the important part, and a lock that survives
    # shows up as a REFUSED delete below, which is already reported.
    return 0
}

# issue_deletes <groups...> - returns non-zero if ARM refused any delete outright.
# A refusal is reported rather than swallowed; "already gone" is not a refusal.
issue_deletes() {
    local failed=0 RG
    remove_locks "$1"
    while IFS= read -r RG; do
        [[ -z "${RG}" ]] && continue
        # No per-group line: see summarise_kinds. The caller prints one summary.
        if ! err=$(az group delete --name "${RG}" --yes --no-wait 2>&1); then
            if echo "${err}" | grep -qi 'could not be found\|ResourceGroupNotFound'; then
                echo "    already gone"
            else
                echo "    REFUSED: ${err}" | head -3
                failed=1
            fi
        fi
    done < "$1"
    return $failed
}

# wait_gone - poll until no matching group remains, or the budget expires.
wait_gone() {
    local deadline=$(( SECONDS + CLEAN_WAIT_MINUTES * 60 ))
    while [[ ${SECONDS} -lt ${deadline} ]]; do
        set +e
        list_groups > "${GROUPS_FILE}"
        set -e
        [[ ! -s "${GROUPS_FILE}" ]] && return 0
        local n
        n=$(wc -l < "${GROUPS_FILE}" | tr -d ' ')
        echo "  ${n} group(s) still deleting, waiting..."
        sleep 30
    done
    return 1
}

REFUSED=0

# Raised by list_groups when it cannot trust its own parse of `az group list`.
#
# This is a FILE, not a variable, and deliberately so: every caller invokes
# list_groups through a `GROUPS=$(list_groups)` command substitution, which runs
# it in a subshell, so a variable assignment inside the function is discarded the
# moment it returns. A flag file is the only channel that survives.
PARSE_FAIL_FLAG=$(mktemp)

# The group list travels through FILES, never through a variable.
#
# `GROUPS=$(list_groups)` looked obviously correct and was the actual bug. A
# CLEAN_DEBUG=1 trace from CI shows the function working perfectly - "az reported
# 205 group(s), parsed 205, matched prefix 204", `return 0`, and even the correct
# 204 names being assigned - and then, on the very next traced line, `GROUPS` is
# the string `1001` and the substitution has reported exit 1:
#
#     + GROUPS='formae-plugin-sdk-test-vnet-rg-13770d81
#     formae-plugin-sdk-test-pip-rg-9042acb1
#     ...'
#     ++ echo 'clean-environment.sh: command failed at line 267 (exit 1): GROUPS=$(list_groups)'
#     + [[ -z 1001 ]]
#     + issue_deletes 1001
#     ++ az group delete --name 1001 --yes --no-wait
#     + err='ERROR: (ResourceGroupNotFound) Resource group '1001' could not be found.'
#
# So the sweep asked ARM to delete a group named `1001`, was told it does not
# exist, counted that as "already gone", and then sat in wait_gone for two full
# 25-minute budgets while all 204 real groups survived. Every fix before this one
# targeted the function; the function was never wrong. The corruption is in
# capturing its ~8KB multi-line output through a command substitution, and no
# amount of care inside the function can survive that - which is also why
# wait_gone appeared to work: it re-lists and counts, so it saw the real 204.
#
# Short substitutions are unaffected (`err=$(mktemp)` traces correctly), so
# mktemp here is safe. Only the large group list moves to a file.
GROUPS_FILE=$(mktemp)
SURVIVORS_FILE=$(mktemp)
trap 'rm -f "${PARSE_FAIL_FLAG}" "${GROUPS_FILE}" "${SURVIVORS_FILE}"' EXIT

# Pass 1 - whatever is there now.
#
# `set +e` around the substitution, not just inside list_groups.
#
# list_groups already runs its body with `set -e` off and ends in `return 0`, and
# that was still not enough: pre-cleanup failed again, identically, on the CI
# runner. The function survives this locally under bash 3.2 and dies under the
# runner's bash 5, so something in there is fatal in a way `set +e` inside the
# function does not cover - a `set -u` unbound-variable error and a failed
# `local` are both fatal regardless of errexit, and both are bash-version
# sensitive.
#
# Rather than keep guessing at which, the call sites stop caring: a non-zero
# status here is not allowed to kill a sweep.
set +e
list_groups > "${GROUPS_FILE}"
set -e
if [[ ! -s "${GROUPS_FILE}" ]]; then
    echo "No resource groups found with prefix '${TEST_PREFIX}'"
else
    echo "Pass 1 - deleting $(wc -l < "${GROUPS_FILE}" | tr -d ' ') group(s):"
    summarise_kinds "${GROUPS_FILE}"
    issue_deletes "${GROUPS_FILE}" || REFUSED=1
    echo ""
    echo "Waiting up to ${CLEAN_WAIT_MINUTES}m for deletion to complete..."
    wait_gone || true
fi

# Pass 2 - catch anything created while pass 1 was running. This is the case a
# cancelled run hits: jobs still finishing create groups after the first list.
set +e
list_groups > "${GROUPS_FILE}"
set -e
if [[ -s "${GROUPS_FILE}" ]]; then
    echo ""
    echo "Pass 2 - $(wc -l < "${GROUPS_FILE}" | tr -d ' ') group(s) appeared during or survived pass 1:"
    summarise_kinds "${GROUPS_FILE}"
    issue_deletes "${GROUPS_FILE}" || REFUSED=1
    echo ""
    echo "Waiting up to ${CLEAN_WAIT_MINUTES}m for deletion to complete..."
    wait_gone || true
fi

# Soft-deleted Key Vaults survive their resource group and hold the name, so they
# need a separate purge.
echo ""
echo "Purging soft-deleted Key Vaults with prefix 'fpsdt-kv-'..."
DELETED_VAULTS=$(az keyvault list-deleted --query "[?starts_with(name, 'fpsdt-kv-')].name" -o tsv 2>/dev/null || true)
if [[ -z "${DELETED_VAULTS}" ]]; then
    echo "  none"
else
    for VAULT in ${DELETED_VAULTS}; do
        echo "  purging ${VAULT}"
        az keyvault purge --name "${VAULT}" --no-wait || true
    done
fi

# Soft-deleted API Management services do the same, and worse: they keep counting
# against the Consumption per-subscription service quota until purged, so they do
# not merely hold a name - they eventually stop new services being created at all.
#
# That is not hypothetical. On 2026-09-03 the subscription had accumulated 31
# soft-deleted APIM services, and conformance fixtures began failing with
#
#   RESPONSE 400: MaxConsumptionServicesPerSubscriptionExceeded
#
# on create. Every APIM fixture provisions its own Consumption service, so the
# quota is reached quickly once deleted ones stop being reclaimed. Key Vaults have
# been purged here since the beginning; APIM was simply missed.
#
# Purged with `az rest`, after getting this wrong twice.
#
# The first version purged synchronously with `az apim deletedservice purge`.
# Measured: ~1.3 min each, so clearing a 16-service backlog held pre-cleanup for
# over 17 minutes, and at steady state every run leaves ~28 behind - ~36 min of
# purging in EVERY sweep.
#
# The second version added `--no-wait` to that command. THAT FLAG DOES NOT EXIST:
#
#     ERROR: unrecognized arguments: --no-wait
#
# so every purge failed, the loop reported "queued purge for 0", and soft-deleted
# services accumulated unchecked until they exhausted the 20-service Consumption
# cap. The failure was invisible because a purge that cannot proceed is tolerated
# here by design, and because the count it prints was the count of successes.
#
# `az rest` sends the DELETE and returns on ARM's 202 without the CLI's polling
# loop: ~20s per service rather than ~1.3 min, with no dependency on which flags
# this month's `az apim` happens to accept. Failures stay tolerated - a purge that
# cannot proceed shows up as the quota error on a later create, and must not abort
# the sweep - but the count below now distinguishes them.
echo ""
echo "Purging soft-deleted API Management services with prefix 'fpsdt-'..."
DELETED_APIMS=$(az apim deletedservice list --query "[?starts_with(name, 'fpsdt-')].{n:name,l:location}" -o tsv 2>/dev/null || true)
if [[ -z "${DELETED_APIMS}" ]]; then
    echo "  none"
else
    apim_purged=0
    apim_failed=0
    while IFS=$'\t' read -r APIM_NAME APIM_LOC; do
        [[ -z "${APIM_NAME}" ]] && continue
        # Re-check the prefix LOCALLY, exactly as list_groups does and for the same
        # reason: a purge is irreversible, so it only ever acts on a name this
        # script has verified itself rather than trusting the server-side
        # projection in the --query above. A stub that ignored that query was
        # enough to make this loop purge a service it had no business touching.
        if [[ "${APIM_NAME}" != fpsdt-* ]]; then
            echo "    skipping ${APIM_NAME} - does not match the test prefix"
            continue
        fi
        APIM_LOC_SLUG=$(printf '%s' "${APIM_LOC}" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        if az rest --method delete --url \
            "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.ApiManagement/locations/${APIM_LOC_SLUG}/deletedservices/${APIM_NAME}?api-version=2022-08-01" \
            > /dev/null 2>&1; then
            apim_purged=$((apim_purged + 1))
        else
            apim_failed=$((apim_failed + 1))
            echo "    could not purge ${APIM_NAME} (${APIM_LOC_SLUG})"
        fi
    done <<< "${DELETED_APIMS}"
    echo "  purged ${apim_purged} soft-deleted APIM service(s), ${apim_failed} failed"
fi

# Verdict. Same `set +e` guard as the other call sites - a non-zero list here
# must not pre-empt the verdict it exists to compute.
set +e
list_groups > "${SURVIVORS_FILE}"
set -e
echo ""
if [[ -s "${PARSE_FAIL_FLAG}" ]]; then
    echo "clean-environment.sh: could not parse the resource-group list; nothing was swept."
    echo "Treat this as a failed sweep, not a clean subscription."
    exit 1
fi

if [[ ! -s "${SURVIVORS_FILE}" ]] && [[ ${REFUSED} -eq 0 ]]; then
    echo "clean-environment.sh: clean - no test resource groups remain"
    exit 0
fi

if [[ -s "${SURVIVORS_FILE}" ]]; then
    echo "SURVIVING: $(wc -l < "${SURVIVORS_FILE}" | tr -d ' ') group(s) still billing, by kind:"
    summarise_kinds "${SURVIVORS_FILE}"
    # Survivors DO get named, capped: this is the failure path and someone has to
    # go and delete them by hand, so the names matter - but a wholesale failure
    # leaves ~200 of them, and 200 lines is the noise this summary exists to
    # avoid. First 20, then a count. All of them are in the trace under
    # CLEAN_DEBUG=1.
    n_surv=$(wc -l < "${SURVIVORS_FILE}" | tr -d ' ')
    echo "  names:"
    head -20 "${SURVIVORS_FILE}" | sed 's/^/    /'
    if [[ ${n_surv} -gt 20 ]]; then
        echo "    ... and $((n_surv - 20)) more"
    fi
fi
# An if-block, not `[[ ... ]] && echo`: with `set -e` that construct exits the
# script when the test is false, skipping the ::error:: annotation below.
if [[ ${REFUSED} -ne 0 ]]; then
    echo "One or more deletes were refused by ARM (see above)."
fi

echo ""
echo "::error::test resource groups survived cleanup and are still billing"
exit 1
