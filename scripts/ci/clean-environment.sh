#!/bin/bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Clean Environment Hook for Azure
# =================================
# This script is called before AND after conformance tests to clean up
# test resources in your Azure environment.
#
# Purpose:
# - Before tests: Remove orphaned resources from previous failed runs
# - After tests: Clean up resources created during the test run
#
# The script should be idempotent - safe to run multiple times.
# It deletes all resource groups matching the test resource prefix.
#
# Test resources typically use a naming convention like:
#   formae-plugin-sdk-test-{run-id}-*
#
# Exit with non-zero status only for unexpected errors.
# Missing resources (already cleaned) should not cause failures.

set -euo pipefail

# Prefix used for test resources - should match what conformance tests create
TEST_PREFIX="${TEST_PREFIX:-formae-plugin-sdk-test-}"

echo "clean-environment.sh: Cleaning Azure resources with prefix '${TEST_PREFIX}'"
echo ""

# Check if Azure CLI is available and logged in
if ! command -v az &> /dev/null; then
    echo "Azure CLI (az) not found. Skipping cleanup."
    exit 0
fi

if ! az account show &> /dev/null; then
    echo "Not logged in to Azure CLI. Skipping cleanup."
    exit 0
fi

# Get current subscription for logging
SUBSCRIPTION=$(az account show --query name -o tsv)
echo "Using subscription: ${SUBSCRIPTION}"
echo ""

# List and delete resource groups with test prefix
echo "Finding resource groups with prefix '${TEST_PREFIX}'..."
RESOURCE_GROUPS=$(az group list --query "[?starts_with(name, '${TEST_PREFIX}')].name" -o tsv || true)

if [[ -z "${RESOURCE_GROUPS}" ]]; then
    echo "No resource groups found with prefix '${TEST_PREFIX}'"
else
    echo "Found resource groups to delete:"
    echo "${RESOURCE_GROUPS}"
    echo ""

    for RG in ${RESOURCE_GROUPS}; do
        echo "Deleting resource group: ${RG}..."
        # Use --yes to skip confirmation, --no-wait to not block
        # We use --no-wait because deletion can take a while
        az group delete --name "${RG}" --yes --no-wait || true
    done

    echo ""
    echo "Deletion initiated for all matching resource groups."
    echo "Note: Resource group deletion happens asynchronously in Azure."
fi

echo ""
echo "clean-environment.sh: Cleanup complete"
