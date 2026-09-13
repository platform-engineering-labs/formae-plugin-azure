#!/usr/bin/env bash
# © 2026 Platform Engineering Labs Inc.
# SPDX-License-Identifier: FSL-1.1-ALv2
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
cat > "$test_dir/make" <<'MAKE'
#!/usr/bin/env bash
printf '%s:%s\n' "${FORMAE_TEST_UPDATE_MODE:-patch}" "$1"
MAKE
chmod +x "$test_dir/make"
for resource in blob-container-metadata-clear file-share-metadata-clear storage-queue-metadata-clear api-management-named-value-tags-clear; do
  actual="$(env -u FORMAE_TEST_UPDATE_MODE PATH="$test_dir:$PATH" bash "$script_dir/run-conformance-phase.sh" "$resource" crud)"
  test "$actual" = 'reconcile:conformance-test-crud-run' || { echo "$resource unexpectedly selected $actual" >&2; exit 1; }
done
for resource in blob-container file-share storage-queue api-management-named-value; do
  actual="$(env -u FORMAE_TEST_UPDATE_MODE PATH="$test_dir:$PATH" bash "$script_dir/run-conformance-phase.sh" "$resource" crud)"
  test "$actual" = 'patch:conformance-test-crud-run' || { echo "$resource unexpectedly selected $actual" >&2; exit 1; }
done
actual="$(env -u FORMAE_TEST_UPDATE_MODE PATH="$test_dir:$PATH" bash "$script_dir/run-conformance-phase.sh" blob-container-metadata-clear discovery)"
test "$actual" = 'patch:conformance-test-discovery-run' || { echo "discovery unexpectedly selected $actual" >&2; exit 1; }
for resource in blob-container-metadata-clear file-share-metadata-clear storage-queue-metadata-clear api-management-named-value-tags-clear; do
  actual="$(env -u FORMAE_TEST_UPDATE_MODE PATH="$test_dir:$PATH" bash "$script_dir/run-conformance-phase.sh" "$resource" all)"
  test "$actual" = 'reconcile:conformance-test' || { echo "$resource nightly unexpectedly selected $actual" >&2; exit 1; }
done
actual="$(env -u FORMAE_TEST_UPDATE_MODE PATH="$test_dir:$PATH" bash "$script_dir/run-conformance-phase.sh" blob-container all)"
test "$actual" = 'patch:conformance-test' || { echo "ordinary nightly unexpectedly selected $actual" >&2; exit 1; }
echo 'Conformance update mode checks passed' 
