#!/usr/bin/env bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
# Run one conformance phase for one resource, with the timeouts it needs.
#
# Usage: run-conformance-phase.sh <resource> <crud|discovery>
#
# The two phases are separate steps in the workflows because the Azure login
# has to be refreshed between them, so each calls this once. ci.yml carried the
# same timeout table twice and debug-conformance.yml would have made it four
# copies; this is the single one.
#
# FORMAE_TEST_TIMEOUT is the per-command poll (the 5 minute default is too short
# for slow ARM provisioning); TIMEOUT is the overall go-test timeout.
set -euo pipefail

RESOURCE="${1:?usage: run-conformance-phase.sh <resource> <crud|discovery>}"
PHASE="${2:?usage: run-conformance-phase.sh <resource> <crud|discovery>}"

TIMEOUT_ARG=""

# set_timeouts <per-command-minutes> <go-test-minutes>
set_timeouts() {
  export FORMAE_TEST_TIMEOUT="$1" FORMAE_TEST_OOB_TIMEOUT="$1" FORMAE_TEST_OOB_DELETE_TIMEOUT="$1"
  # Discovery reads back through inventory, so it needs the same headroom as the
  # create it is discovering. The crud phase leaves the workflow default alone.
  if [ "$PHASE" = "discovery" ]; then
    export FORMAE_TEST_DISCOVERY_TIMEOUT="$1"
  fi
  TIMEOUT_ARG="TIMEOUT=$2"
}

case "$RESOURCE" in
  application-gateway)
    # App Gateway v2 is slow to provision.
    set_timeouts 20 50
    ;;
  cdn-*)
    # Front Door's full CRUD lifecycle (create+update+destroy+recreate+
    # OOB-delete) measures ~36 min clean, so cdn-* needs a wide margin.
    set_timeouts 25 75
    ;;
  flux-configuration|maintenance-configuration|trusted-access-role-binding|grafana|grafana-managed-private-endpoint)
    # An AKS cluster or a managed Grafana workspace takes ~5-10 min before the
    # resource under test can even be created.
    set_timeouts 20 50
    ;;
  virtual-machine-extension|sql-*)
    set_timeouts 15 40
    ;;
esac

# shellcheck disable=SC2086 # TIMEOUT_ARG is a deliberate word-split make arg.
case "$PHASE" in
  crud)      make conformance-test-crud-run $TIMEOUT_ARG ;;
  discovery) make conformance-test-discovery-run $TIMEOUT_ARG ;;
  *)         echo "unknown phase: $PHASE" >&2; exit 2 ;;
esac
