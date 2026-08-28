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
  virtual-machine-extension)
    set_timeouts 15 40
    ;;
  sql-*)
    # 20 not 15: sql-firewall-rule timed out on the OOB-delete re-apply at 17 min
    # and sql-virtual-network-rule on the out-of-band server create at 15 min.
    # Both spend most of that waiting on the parent SQL server.
    set_timeouts 20 50
    ;;
  cosmos-database-account|configuration|database|firewall-rule|flexible-server|web-pubsub|signalr-service)
    # Managed data services: the control plane accepts the create in seconds but
    # the instance is not Succeeded for 10-20 min, and Destroy is just as slow.
    # cosmos-database-account blew the 5 min default on Destroy and web-pubsub on
    # the OOB-delete re-apply, while every other phase passed. configuration,
    # database, firewall-rule and flexible-server are out of the matrix but stay
    # in this table so debug-conformance.yml gives them the same headroom.
    set_timeouts 20 50
    ;;
  app-service-plan|static-site)
    # A plan and a Static Web App create in a couple of minutes, but the
    # lifecycle does several of them.
    set_timeouts 10 30
    ;;
  web-app|web-app-slot|function-app)
    # The site itself is quick; these fixtures build a plan first (and a storage
    # account for function-app), and Destroy is slower than Create.
    set_timeouts 15 40
    ;;
  virtual-wan|vpn-site)
    # Virtual WAN control plane only - nothing is provisioned behind it.
    set_timeouts 10 30
    ;;
  virtual-hub|bastion-host)
    # A hub programs routing and a Bastion deploys real instances: ~20-25 min
    # per lifecycle, measured.
    set_timeouts 30 90
    ;;
  vpn-gateway|virtual-network-gateway|virtual-network-gateway-connection)
    # 60-90 min per lifecycle. That exceeds the conformance-tests job's
    # timeout-minutes: 120 in both ci.yml and debug-conformance.yml, so these
    # are not dispatchable there yet. The budget lives here so a local run gets
    # a usable one, and so raising the job cap is the only change needed later.
    set_timeouts 60 150
    ;;
  cosmos-*)
    # Every Cosmos child fixture stands up its own account first (10-20 min
    # before the child can be created at all), and a container or graph create
    # is minutes on top. Deliberately after the cosmos-database-account arm, so
    # that keeps its own budget.
    set_timeouts 30 90
    ;;
  redis-cache)
    # Out of the matrix because a Basic C0 create is ~20 min and the lifecycle
    # does several; at 30 min the job still ran 60 min before failing on the
    # OOB-delete re-apply. Kept here so a debug run gets a usable budget.
    set_timeouts 30 90
    ;;
esac

# shellcheck disable=SC2086 # TIMEOUT_ARG is a deliberate word-split make arg.
case "$PHASE" in
  crud)      make conformance-test-crud-run $TIMEOUT_ARG ;;
  discovery) make conformance-test-discovery-run $TIMEOUT_ARG ;;
  *)         echo "unknown phase: $PHASE" >&2; exit 2 ;;
esac
