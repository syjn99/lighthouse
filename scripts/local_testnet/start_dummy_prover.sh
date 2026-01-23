#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( cd -- "$SCRIPT_DIR/../.." &> /dev/null && pwd )"

ENCLAVE_NAME="${ENCLAVE_NAME:-local-testnet}"
TARGET_SERVICE="${TARGET_SERVICE:-}"
SOURCE_SERVICE="${SOURCE_SERVICE:-}"
BEACON_NODE_URL="${BEACON_NODE_URL:-}"
SOURCE_BEACON_NODE_URL="${SOURCE_BEACON_NODE_URL:-}"
PROOFS_PER_BLOCK="${PROOFS_PER_BLOCK:-1}"
PROOF_DELAY_MS="${PROOF_DELAY_MS:-1000}"
BACKFILL_THRESHOLD_SLOTS="${BACKFILL_THRESHOLD_SLOTS:-32}"
BACKFILL_INTERVAL_SECS="${BACKFILL_INTERVAL_SECS:-10}"

while getopts "e:t:s:T:S:p:d:B:I:h" flag; do
  case "${flag}" in
    e) ENCLAVE_NAME=${OPTARG};;
    t) TARGET_SERVICE=${OPTARG};;
    s) SOURCE_SERVICE=${OPTARG};;
    T) BEACON_NODE_URL=${OPTARG};;
    S) SOURCE_BEACON_NODE_URL=${OPTARG};;
    p) PROOFS_PER_BLOCK=${OPTARG};;
    d) PROOF_DELAY_MS=${OPTARG};;
    B) BACKFILL_THRESHOLD_SLOTS=${OPTARG};;
    I) BACKFILL_INTERVAL_SECS=${OPTARG};;
    h)
      echo "Start the dummy prover against a local testnet."
      echo "Note: Run this after the testnet is up so the beacon node endpoint exists."
      echo
      echo "Usage: $0 [options]"
      echo
      echo "Options:"
      echo "  -e ENCLAVE_NAME           Kurtosis enclave name (default: $ENCLAVE_NAME)"
      echo "  -t TARGET_SERVICE         Kurtosis service name for target (proof submission)"
      echo "  -s SOURCE_SERVICE         Kurtosis service name for source (block events)"
      echo "  -T BEACON_NODE_URL        Target beacon node URL (overrides -t)"
      echo "  -S SOURCE_BEACON_NODE_URL Source beacon node URL (overrides -s)"
      echo "  -p PROOFS_PER_BLOCK       Proof IDs to submit per block (default: $PROOFS_PER_BLOCK)"
      echo "  -d PROOF_DELAY_MS         Proof generation delay in ms (default: $PROOF_DELAY_MS)"
      echo "  -B BACKFILL_THRESHOLD     Backfill threshold in slots (default: $BACKFILL_THRESHOLD_SLOTS)"
      echo "  -I BACKFILL_INTERVAL      Backfill interval in seconds (default: $BACKFILL_INTERVAL_SECS)"
      echo "  -h                        Show this help"
      echo
      echo "Example:"
      echo "  $0 -s cl-1-prysm-geth -t cl-4-prysm-dummy"
      echo "  $0 -T http://localhost:5052 -S http://localhost:5053"
      exit
      ;;
  esac
done

# Resolve target URL
if [ -z "$BEACON_NODE_URL" ]; then
  if [ -n "$TARGET_SERVICE" ] && command -v kurtosis &> /dev/null; then
    if BEACON_NODE_URL=$(kurtosis port print "$ENCLAVE_NAME" "$TARGET_SERVICE" http 2>/dev/null); then
      echo "Target from kurtosis ($TARGET_SERVICE): $BEACON_NODE_URL"
    else
      echo "Failed to get URL for target service '$TARGET_SERVICE'" >&2
      exit 1
    fi
  else
    BEACON_NODE_URL="http://localhost:5052"
    echo "No target specified, defaulting to $BEACON_NODE_URL"
  fi
fi

# Resolve source URL
if [ -z "$SOURCE_BEACON_NODE_URL" ]; then
  if [ -n "$SOURCE_SERVICE" ] && command -v kurtosis &> /dev/null; then
    if SOURCE_BEACON_NODE_URL=$(kurtosis port print "$ENCLAVE_NAME" "$SOURCE_SERVICE" http 2>/dev/null); then
      echo "Source from kurtosis ($SOURCE_SERVICE): $SOURCE_BEACON_NODE_URL"
    else
      echo "Failed to get URL for source service '$SOURCE_SERVICE'" >&2
      exit 1
    fi
  else
    SOURCE_BEACON_NODE_URL="$BEACON_NODE_URL"
  fi
fi

echo "Starting dummy prover..."
echo "  target:  $BEACON_NODE_URL"
echo "  source:  $SOURCE_BEACON_NODE_URL"
echo "  proofs:  $PROOFS_PER_BLOCK"
echo "  delay:   ${PROOF_DELAY_MS}ms"
echo "  backfill threshold: ${BACKFILL_THRESHOLD_SLOTS} slots"
echo "  backfill interval:  ${BACKFILL_INTERVAL_SECS}s"

exec cargo run --manifest-path "$ROOT_DIR/Cargo.toml" -p zkvm_execution_layer --bin dummy-prover -- \
  --beacon-node "$BEACON_NODE_URL" \
  --source-beacon-node "$SOURCE_BEACON_NODE_URL" \
  --proofs-per-block "$PROOFS_PER_BLOCK" \
  --proof-delay-ms "$PROOF_DELAY_MS" \
  --backfill-threshold-slots "$BACKFILL_THRESHOLD_SLOTS" \
  --backfill-interval-secs "$BACKFILL_INTERVAL_SECS"
