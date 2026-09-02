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

set -euo pipefail

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
trap 'rc=$?; echo "::error::clean-environment.sh failed at line ${LINENO} (exit ${rc}): ${BASH_COMMAND}" >&2' ERR

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
echo ""

# list_groups - names of every resource group matching TEST_PREFIX, one per line.
#
# Parses JSON and re-checks the prefix LOCALLY rather than trusting the server-side
# projection. That guard matters: anything that is not a real prefixed group name -
# a truncation marker from an output-filtering wrapper, a CLI warning, a malformed
# projection - is dropped instead of being passed to `az group delete`. Deleting is
# destructive, so it only ever acts on a name it has re-verified itself.
list_groups() {
    local raw err
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
    # An if-block, not `[[ ... ]] && return 0`: when raw is non-empty that
    # construct evaluates to the failed test's status, and this function's status
    # is consumed by a `GROUPS=$(list_groups)` command substitution, where a
    # non-zero exit kills the whole script under `set -e`.
    if [[ -z "${raw}" ]]; then
        return 0
    fi
    printf '%s' "${raw}" \
        | jq -r --arg p "${TEST_PREFIX}" '.[]? | select(.name != null) | select(.name | startswith($p)) | .name' 2>/dev/null \
        | grep -E "^${TEST_PREFIX}[A-Za-z0-9._-]*$" || true
    # Explicit: "no matching groups" is a normal result, not a failure. Every
    # caller assigns this through a command substitution, so any non-zero status
    # leaking out of here aborts the script before a single group is swept.
    return 0
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
    for RG in $@; do
        local ids
        ids=$(az lock list --resource-group "${RG}" --query "[].id" -o tsv 2>/dev/null) || continue
        [[ -z "${ids}" ]] && continue
        while IFS= read -r id; do
            [[ -z "${id}" ]] && continue
            echo "  removing lock ${id}"
            az lock delete --ids "${id}" 2>/dev/null || echo "    could not remove lock"
        done <<< "${ids}"
    done
    # Explicit: this script runs under `set -e`, and issue_deletes calls this
    # first. A lock sweep that could not clean up must not abort the whole
    # cleanup - deleting groups is the important part, and a lock that survives
    # shows up as a REFUSED delete below, which is already reported.
    return 0
}

# issue_deletes <groups...> - returns non-zero if ARM refused any delete outright.
# A refusal is reported rather than swallowed; "already gone" is not a refusal.
issue_deletes() {
    local failed=0
    remove_locks $@
    for RG in $@; do
        echo "  deleting ${RG}"
        if ! err=$(az group delete --name "${RG}" --yes --no-wait 2>&1); then
            if echo "${err}" | grep -qi 'could not be found\|ResourceGroupNotFound'; then
                echo "    already gone"
            else
                echo "    REFUSED: ${err}" | head -3
                failed=1
            fi
        fi
    done
    return $failed
}

# wait_gone - poll until no matching group remains, or the budget expires.
wait_gone() {
    local deadline=$(( SECONDS + CLEAN_WAIT_MINUTES * 60 ))
    while [[ ${SECONDS} -lt ${deadline} ]]; do
        local remaining
        remaining=$(list_groups)
        [[ -z "${remaining}" ]] && return 0
        local n
        n=$(echo "${remaining}" | grep -c . || true)
        echo "  ${n} group(s) still deleting, waiting..."
        sleep 30
    done
    return 1
}

REFUSED=0

# Pass 1 - whatever is there now.
GROUPS=$(list_groups)
if [[ -z "${GROUPS}" ]]; then
    echo "No resource groups found with prefix '${TEST_PREFIX}'"
else
    echo "Pass 1 - found:"
    echo "${GROUPS}" | sed 's/^/  /'
    issue_deletes ${GROUPS} || REFUSED=1
    echo ""
    echo "Waiting up to ${CLEAN_WAIT_MINUTES}m for deletion to complete..."
    wait_gone || true
fi

# Pass 2 - catch anything created while pass 1 was running. This is the case a
# cancelled run hits: jobs still finishing create groups after the first list.
GROUPS=$(list_groups)
if [[ -n "${GROUPS}" ]]; then
    echo ""
    echo "Pass 2 - these appeared during or survived pass 1:"
    echo "${GROUPS}" | sed 's/^/  /'
    issue_deletes ${GROUPS} || REFUSED=1
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

# Verdict.
SURVIVORS=$(list_groups)
echo ""
if [[ -z "${SURVIVORS}" ]] && [[ ${REFUSED} -eq 0 ]]; then
    echo "clean-environment.sh: clean - no test resource groups remain"
    exit 0
fi

if [[ -n "${SURVIVORS}" ]]; then
    echo "SURVIVING resource groups (still billing):"
    echo "${SURVIVORS}" | sed 's/^/  /'
fi
# An if-block, not `[[ ... ]] && echo`: with `set -e` that construct exits the
# script when the test is false, skipping the ::error:: annotation below.
if [[ ${REFUSED} -ne 0 ]]; then
    echo "One or more deletes were refused by ARM (see above)."
fi

echo ""
echo "::error::test resource groups survived cleanup and are still billing"
exit 1
