#!/bin/bash
# © 2025 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Script to run conformance tests against a specific version of formae.
#
# Usage:
#   ./scripts/run-conformance-tests.sh [VERSION]
#
# Arguments:
#   VERSION - Optional formae version (e.g., 0.76.0). Defaults to "latest".
#
# Environment variables:
#   FORMAE_BINARY      - Path to formae binary (skips download if set)
#   FORMAE_INSTALL_PREFIX - Installation directory (default: temp directory)
#   FORMAE_TEST_FILTER - Filter tests by name pattern (e.g., "s3-bucket")
#   FORMAE_TEST_TYPE   - Select test type: "all" (default), "crud", or "discovery"

set -euo pipefail

# Cross-platform sed in-place edit (macOS vs Linux)
sed_inplace() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Sends a telemetry event to PostHog for tracking CI/dev binary downloads.
# Gated on POSTHOG_API_KEY — silently no-ops when unset.
formae_track_event() {
  local api_key="${POSTHOG_API_KEY:-}"
  if [[ -z "$api_key" ]]; then return; fi

  local event="$1"; shift
  local repo
  repo=$(basename "$(git remote get-url origin 2>/dev/null)" .git 2>/dev/null || echo "unknown")

  local payload
  payload=$(jq -n \
    --arg api_key "$api_key" \
    --arg event "$event" \
    --arg repo "$repo" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg run_id "${GITHUB_RUN_ID:-}" \
    '{
      api_key: $api_key,
      distinct_id: "formae-ci",
      event: $event,
      timestamp: $ts,
      properties: {
        "$process_person_profile": false,
        repo: $repo,
        ci_run_id: $run_id
      }
    }')

  for kv in "$@"; do
    local key="${kv%%=*}" val="${kv#*=}"
    payload=$(echo "$payload" | jq --arg k "$key" --arg v "$val" '.properties[$k] = $v')
  done

  curl -sf -o /dev/null https://k.platform.engineering/capture/ \
    -H "Content-Type: application/json" \
    -d "$payload" || echo "[telemetry] event send failed (non-critical)" >&2 &
}

VERSION="${1:-latest}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# =============================================================================
# Setup Formae Binary
# =============================================================================

# Check if FORMAE_BINARY is already set and valid
if [[ -n "${FORMAE_BINARY:-}" ]] && [[ -x "${FORMAE_BINARY}" ]]; then
    echo "Using FORMAE_BINARY from environment: ${FORMAE_BINARY}"
    # Extract version from binary if not explicitly provided
    if [[ "${VERSION}" == "latest" ]]; then
        VERSION=$("${FORMAE_BINARY}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
        if [[ -z "${VERSION}" ]]; then
            echo "Warning: Could not extract version from FORMAE_BINARY, using 'latest'"
            VERSION="latest"
        else
            echo "Detected formae version: ${VERSION}"
        fi
    fi
else
    # Always download formae to temp directory for conformance tests
    # Don't use system-installed formae to ensure version consistency

    INSTALL_DIR=$(mktemp -d -t formae-conformance-XXXXXX)
    echo "Using temp directory: ${INSTALL_DIR}"
    trap "rm -rf ${INSTALL_DIR}" EXIT

    # Determine OS and architecture for pelmgr download
    DETECTED_OS=$(uname | tr '[:upper:]' '[:lower:]')
    DETECTED_ARCH=$(uname -m | tr -d '_' | sed s/aarch64/arm64/)

    # Download pelmgr (the PEL package manager)
    PELMGR="${INSTALL_DIR}/pelmgr"
    echo "Downloading pelmgr..."
    if ! curl -fsSL "https://hub.platform.engineering/get/binaries/${DETECTED_OS}-${DETECTED_ARCH}/pelmgr" -o "${PELMGR}"; then
        echo "Error: Failed to download pelmgr"
        exit 1
    fi
    chmod +x "${PELMGR}"

    # Install formae via pelmgr
    if [[ "${VERSION}" == "latest" ]]; then
        echo "Installing latest formae..."
        "${PELMGR}" --install-path "${INSTALL_DIR}" --yes install formae
    else
        echo "Installing formae version ${VERSION}..."
        "${PELMGR}" --install-path "${INSTALL_DIR}" --yes install "formae@${VERSION}"
    fi

    FORMAE_BINARY="${INSTALL_DIR}/bin/formae"
    if [[ ! -x "${FORMAE_BINARY}" ]]; then
        echo "Error: formae binary not found at ${FORMAE_BINARY}"
        find "${INSTALL_DIR}" -name "formae" -type f 2>/dev/null || ls -laR "${INSTALL_DIR}"
        exit 1
    fi

    # Resolve VERSION from the installed binary (needed for PKL dependency updates)
    if [[ "${VERSION}" == "latest" ]]; then
        VERSION=$("${FORMAE_BINARY}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ -z "${VERSION}" ]]; then
            echo "Error: Could not extract version from installed formae binary"
            exit 1
        fi
        echo "Resolved latest to version: ${VERSION}"
    fi
fi

formae_track_event "ci_binary_download" "version=${VERSION}" "os=${DETECTED_OS:-$(uname | tr '[:upper:]' '[:lower:]')}" "arch=${DETECTED_ARCH:-$(uname -m | tr -d '_')}"

echo ""
echo "Using formae binary: ${FORMAE_BINARY}"
"${FORMAE_BINARY}" --version

# Export environment variables for the tests
# FORMAE_VERSION is required by the plugin SDK to resolve PKL schema paths
export FORMAE_BINARY
export FORMAE_VERSION="${VERSION}"

# Pass through test filter and type if set
if [[ -n "${FORMAE_TEST_FILTER:-}" ]]; then
    export FORMAE_TEST_FILTER
    echo "Test filter: ${FORMAE_TEST_FILTER}"
fi
if [[ -n "${FORMAE_TEST_TYPE:-}" ]]; then
    export FORMAE_TEST_TYPE
    echo "Test type: ${FORMAE_TEST_TYPE}"
fi

# =============================================================================
# Update and Resolve PKL Dependencies
# =============================================================================
# Update testdata/PklProject with the resolved formae version, then resolve
# dependencies from the public package registry.
# =============================================================================

echo ""
echo "Updating PKL dependencies for formae version ${VERSION}..."

# Update PklProject files with the resolved formae version, but only if the
# binary version is newer than or equal to what's already declared. This
# prevents downgrading a PklProject that intentionally targets a pre-release
# schema version for testing (e.g. 0.84.0 when the latest stable is 0.83.2).
update_pkl_project_version() {
    local file="$1"
    local new_version="$2"
    local current
    current=$(grep -oP 'formae/formae@\K[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null | head -1)
    if [[ -z "$current" ]]; then
        echo "  No formae version found in $file, setting to ${new_version}"
        sed_inplace "s|formae/formae@[0-9a-zA-Z.\-]*\"|formae/formae@${new_version}\"|g" "$file"
    elif printf '%s\n%s\n' "$new_version" "$current" | sort -V | tail -1 | grep -q "^${current}$" && [[ "$current" != "$new_version" ]]; then
        echo "  Keeping $file at formae@${current} (newer than binary version ${new_version})"
    else
        echo "  Updating $file to formae@${new_version} (was ${current})"
        sed_inplace "s|formae/formae@[0-9a-zA-Z.\-]*\"|formae/formae@${new_version}\"|g" "$file"
    fi
}

if [[ "${VERSION}" != "latest" ]]; then
    # Update schema/pkl/PklProject (plugin schema depends on formae)
    if [[ -f "${PROJECT_ROOT}/schema/pkl/PklProject" ]]; then
        update_pkl_project_version "${PROJECT_ROOT}/schema/pkl/PklProject" "${VERSION}"
    fi

    # Update testdata/PklProject (test files depend on formae)
    if [[ -f "${PROJECT_ROOT}/testdata/PklProject" ]]; then
        update_pkl_project_version "${PROJECT_ROOT}/testdata/PklProject" "${VERSION}"
    fi
fi

# Resolve schema dependencies (if any)
if [[ -f "${PROJECT_ROOT}/schema/pkl/PklProject" ]]; then
    echo "Resolving schema/pkl dependencies..."
    if ! pkl project resolve "${PROJECT_ROOT}/schema/pkl" 2>&1; then
        echo "Error: Failed to resolve schema/pkl dependencies"
        echo "Make sure the formae PKL package is accessible at the configured URL"
        exit 1
    fi
fi

# Resolve testdata dependencies
if [[ -f "${PROJECT_ROOT}/testdata/PklProject" ]]; then
    echo "Resolving testdata dependencies..."
    if ! pkl project resolve "${PROJECT_ROOT}/testdata" 2>&1; then
        echo "Error: Failed to resolve testdata dependencies"
        exit 1
    fi
fi

echo "PKL dependencies resolved successfully"

# =============================================================================
# Run Conformance Tests
# =============================================================================
echo ""
echo "Running conformance tests..."

# Azure resources like PostgreSQL Flexible Server can take 6-8 minutes to provision.
# The default per-command timeout in the conformance harness is 5 minutes, which is
# too short. Set to 10 minutes to provide sufficient headroom.
export FORMAE_TEST_TIMEOUT="${FORMAE_TEST_TIMEOUT:-10}"

cd "${PROJECT_ROOT}"
go test -tags=conformance -v -timeout 60m ./...
