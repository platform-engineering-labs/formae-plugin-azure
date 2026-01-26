#!/bin/bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Setup Azure Credentials Hook
# ============================
# This script verifies that Azure credentials are properly configured
# before running conformance tests.
#
# For local development:
#   - Run `az login` to authenticate
#   - Credentials are stored in ~/.azure/azureProfile.json
#
# For CI (GitHub Actions):
#   - Use OIDC with azure/login action
#   - Or set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID

set -euo pipefail

AZURE_PROFILE="$HOME/.azure/azureProfile.json"

echo "Verifying Azure credentials..."
echo ""

# Check for Azure CLI profile (indicates az login was run at some point)
if [[ ! -f "$AZURE_PROFILE" ]]; then
    echo "ERROR: Azure CLI profile not found at $AZURE_PROFILE"
    echo ""
    echo "Run 'az login' to authenticate, or set environment variables:"
    echo "  - AZURE_CLIENT_ID"
    echo "  - AZURE_CLIENT_SECRET"
    echo "  - AZURE_TENANT_ID"
    exit 1
fi

# Check for service principal env vars (CI scenario)
if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
    echo "Using service principal authentication (env vars)"
    echo "  Client ID: ${AZURE_CLIENT_ID:0:8}..."
    echo "  Tenant ID: ${AZURE_TENANT_ID:0:8}..."

    # Subscription ID must be set explicitly for service principal
    if [[ -z "${AZURE_SUBSCRIPTION_ID:-}" ]]; then
        echo ""
        echo "ERROR: AZURE_SUBSCRIPTION_ID must be set when using service principal"
        exit 1
    fi
    echo "  Subscription ID: ${AZURE_SUBSCRIPTION_ID:0:8}..."
    echo ""
    echo "Azure credentials configured (service principal)"
    exit 0
fi

# Parse subscription info from Azure CLI profile
echo "Using Azure CLI authentication"

if ! command -v jq &> /dev/null; then
    echo "ERROR: jq is required to parse Azure profile"
    echo "Install with: brew install jq"
    exit 1
fi

# Get default subscription info
DEFAULT_SUB=$(jq -r '.subscriptions[] | select(.isDefault)' "$AZURE_PROFILE")

if [[ -z "$DEFAULT_SUB" || "$DEFAULT_SUB" == "null" ]]; then
    echo "ERROR: No default subscription found in Azure profile"
    echo "Run 'az account set --subscription <id>' to set a default"
    exit 1
fi

SUB_ID=$(echo "$DEFAULT_SUB" | jq -r '.id')
SUB_NAME=$(echo "$DEFAULT_SUB" | jq -r '.name')
TENANT_ID=$(echo "$DEFAULT_SUB" | jq -r '.tenantId')
USER_NAME=$(echo "$DEFAULT_SUB" | jq -r '.user.name')

echo "  Subscription: $SUB_NAME"
echo "  Subscription ID: ${SUB_ID:0:8}..."
echo "  Tenant ID: ${TENANT_ID:0:8}..."
echo "  User: $USER_NAME"

# Verify credentials are still valid
echo ""
echo "Verifying credentials with Azure CLI..."
if ! az account show > /dev/null 2>&1; then
    echo "ERROR: Azure credentials are invalid or expired"
    echo "Run 'az login' to re-authenticate"
    exit 1
fi

echo ""
echo "Azure credentials verified successfully!"
