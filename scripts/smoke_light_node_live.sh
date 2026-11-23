#!/usr/bin/env bash
# ==============================================================================
# scripts/smoke_light_node_live.sh
# End-to-end smoke check for Bitecho Light Node against devnet / live cluster,
# plus populated string-keyed sorted-map fixture checks (BIP-020 Catch 5).
# When --require-testnet or REQUIRE_TESTNET=1 is specified, fails closed (exit 1)
# loudly if the bootstrap peer or network is unreachable (AGENTS.md Rule 5/6).
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BOOTSTRAP_URL="${BOOTSTRAP_URL:-https://bitecho.org/devnet/bootstrap.txt}"
REQUIRE_TESTNET="${REQUIRE_TESTNET:-0}"
NODE_BIN="${NODE_BIN:-node}"

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

# 0. Populated string-keyed sorted-map :petnames / :sessions fixture & cursor/events-out smoke (BIP-020 Catch 5)
if [[ -f "dist/bitecho-light-node.cjs" ]]; then
  echo "Testing populated petnames/sessions fixture, ctl wait cursor, and --events-out mismatch..."
  POP_DIR="${TMP_STATE_DIR}/populated"
  mkdir -p "${POP_DIR}"
  INIT_STATUS=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" status --state-dir "${POP_DIR}")
  if [[ "${INIT_STATUS}" != *'"ok":true'* || "${INIT_STATUS}" != *'"delivery_telemetry"'* ]]; then
    echo "ERROR: Light node initial status missing ok:true or delivery_telemetry!" >&2
    exit 1
  fi
  PET_OUT=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" petname-set --state-dir "${POP_DIR}" --petname "alice" --pubkey "302a300506032b6570032100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  if [[ "${PET_OUT}" != *'"ok":true'* ]]; then
    echo "ERROR: petname-set failed on populated fixture!" >&2
    exit 1
  fi
  POP_STATUS=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" status --state-dir "${POP_DIR}")
  if [[ "${POP_STATUS}" != *'"alice"'* || "${POP_STATUS}" != *'"ok":true'* ]]; then
    echo "ERROR: Populated sorted-map :petnames status check failed!" >&2
    exit 1
  fi
  # Verify wait-event warns loudly on --events-out mismatch against control.json
  printf '{"port":59999,"token":"smoke","pid":1,"events_out":"%s/daemon-events.jsonl"}\n' "${POP_DIR}" > "${POP_DIR}/control.json"
  MISMATCH_ERR=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" wait-event --state-dir "${POP_DIR}" --events-out "${POP_DIR}/wrong-events.jsonl" --timeout-ms 100 2>&1 >/dev/null || true)
  if [[ "${MISMATCH_ERR}" != *'events-out-mismatch'* ]]; then
    echo "ERROR: Expected loud events-out-mismatch warning on stderr, got: ${MISMATCH_ERR}" >&2
    exit 1
  fi
  echo "[OK] Populated petnames sorted-map, delivery_telemetry, and events-out-mismatch checks passed."
fi

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

# 2. Test Node.js bundle status command against live bootstrap
echo "Testing Node.js light-node status..."
STATUS_OUT=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" status --state-dir "${TMP_STATE_DIR}" --bootstrap "${TMP_STATE_DIR}/bootstrap.txt")
echo "Status output: ${STATUS_OUT}"
if [[ "${STATUS_OUT}" != *'"ok":true'* ]]; then
  echo "ERROR: Light node status failed against live bootstrap!" >&2
  exit 1
fi

echo "=== Bitecho Light-Node Live Smoke Passed ==="
