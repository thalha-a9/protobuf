#!/usr/bin/env bash
# Proves protobuf-ci bazel-setup does NOT disable remote cache uploads on
# pull_request_target, contradicting documented policy ("forks are read-only").
#
# Bazel default: --remote_upload_local_results=true
# Source: https://github.com/bazelbuild/bazel/blob/master/src/main/java/com/google/devtools/build/lib/remote/options/RemoteOptions.java
#
# Usage: ./prove_remote_upload_gate.sh

set -euo pipefail

simulate_bazel_setup_flags() {
  local event_name="$1"
  local bazel_cache="${2:-cpp_linux/Bazel8}"
  local BAZEL_FLAGS="--keep_going --test_output=errors --test_timeout=600"

  # Mirrors: protocolbuffers/protobuf-ci internal/bazel-setup/action.yml
  # "Configure Bazel caching" (runs for all events when bazel-cache set)
  BAZEL_FLAGS="$BAZEL_FLAGS --google_credentials=/tmp/gar.json --remote_cache=https://storage.googleapis.com/protobuf-bazel-cache/protobuf/gha/${bazel_cache}"

  # "Configure Bazel cache writing"
  # ONLY adds --remote_upload_local_results when NOT pull_request_target.
  # It never adds --remote_upload_local_results=false for forks.
  if [[ "$event_name" != "pull_request_target" ]]; then
    BAZEL_FLAGS="$BAZEL_FLAGS --remote_upload_local_results"
  fi

  echo "$BAZEL_FLAGS"
}

echo "=== protobuf-ci remote upload gate simulation ==="
echo
echo "[1] Documented Bazel default: remote_upload_local_results = true"
echo "    (unless explicitly set to false)"
echo

for ev in pull_request_target pull_request push schedule; do
  flags="$(simulate_bazel_setup_flags "$ev")"
  echo "event=$ev"
  echo "  flags=$flags"
  if echo "$flags" | grep -q 'remote_upload_local_results=false\|noremote_upload_local_results'; then
    upload="DISABLED"
  elif echo "$flags" | grep -q 'remote_upload_local_results'; then
    upload="EXPLICITLY ENABLED (same as default true)"
  else
    upload="NOT SET → Bazel DEFAULT TRUE → UPLOADS ENABLED"
  fi
  echo "  effective_upload_policy=$upload"
  echo
done

echo "=== VERDICT ==="
echo "pull_request_target does NOT disable uploads."
echo "Policy (protobuf .github/workflows/README.md) claims forks cannot write."
echo "Implementation allows writes whenever GAR credentials authorize GCS."
echo
echo "Affected composite action:"
echo "  protocolbuffers/protobuf-ci@v5 (commit e6f43bbf992213fb28a21fab10368dfd9dd3cb13)"
echo "  internal/bazel-setup/action.yml"
