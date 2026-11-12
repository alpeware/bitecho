#!/usr/bin/env bash
# ==============================================================================
# scripts/smoke_light_node_live.sh
# End-to-end smoke check for Bitecho Light Node against devnet / live cluster.
# When --require-testnet or REQUIRE_TESTNET=1 is specified, fails closed (exit 1)
# loudly if the bootstrap peer or network is unreachable (AGENTS.md Rule 5/6).
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BOOTSTRAP_URL="${BOOTSTRAP_URL:-https://bitecho.org/devnet/bootstrap.txt}"
REQUIRE_TESTNET="${REQUIRE_TESTNET:-0}"

for arg in "$@"; do
  if [[ "$arg" == "--require-testnet" ]]; then
    REQUIRE_TESTNET=1
  elif [[ "$arg" == --bootstrap=* ]]; then
    BOOTSTRAP_URL="${arg#*=}"
  fi
done

echo "=== Bitecho Light-Node Live Smoke Check ==="
echo "Bootstrap URL: ${BOOTSTRAP_URL}"
echo "Require Testnet: ${REQUIRE_TESTNET}"

TMP_STATE_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_STATE_DIR}"' EXIT

# 1. Check bootstrap availability
BOOTSTRAP_REACHABLE=0
if curl -fsSL -m 5 "${BOOTSTRAP_URL}" > "${TMP_STATE_DIR}/bootstrap.txt" 2>/dev/null; then
  BOOTSTRAP_REACHABLE=1
  echo "[OK] Downloaded bootstrap descriptor (${BOOTSTRAP_URL})"
else
  echo "[WARN] Could not reach bootstrap descriptor (${BOOTSTRAP_URL})"
fi

if [[ "${BOOTSTRAP_REACHABLE}" -eq 0 ]]; then
  if [[ "${REQUIRE_TESTNET}" == "1" ]]; then
    echo "ERROR: Testnet connection is required (--require-testnet or REQUIRE_TESTNET=1) but bootstrap is unreachable!" >&2
    exit 1
  else
    echo "Skipping live testnet smoke check (bootstrap unreachable and REQUIRE_TESTNET!=1)."
    exit 0
  fi
fi

# 2. Test Node.js bundle status command
echo "Testing Node.js light-node status..."
NODE_BIN="${NODE_BIN:-node}"
STATUS_OUT=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" status --state-dir "${TMP_STATE_DIR}" --bootstrap "${TMP_STATE_DIR}/bootstrap.txt")
echo "Status output: ${STATUS_OUT}"
if [[ "${STATUS_OUT}" != *'"ok":true'* ]]; then
  echo "ERROR: Light node status failed against live bootstrap!" >&2
  exit 1
fi

echo "=== Bitecho Light-Node Live Smoke Passed ==="
