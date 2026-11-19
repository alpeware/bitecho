#!/usr/bin/env bash
# ==============================================================================
# scripts/light-node.sh - One-line Bitecho Light Node runner
# Defaults bootstrap peer to https://bitecho.org/devnet/bootstrap.txt
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ $# -eq 0 ]]; then
  set -- "status"
fi

has_bootstrap=false
for arg in "$@"; do
  if [[ "$arg" == "--bootstrap" || "$arg" == --bootstrap=* ]]; then
    has_bootstrap=true
    break
  fi
done

ARGS=("$@")
if [[ "$has_bootstrap" == "false" ]]; then
  ARGS+=("--bootstrap" "https://bitecho.org/devnet/bootstrap.txt")
fi

# P-OPS-3 (BIP-010): Atomic single-instance guard for serve mode on --state-dir
is_serve=false
state_dir="${HOME}/.bitecho/light-node"
for ((i=0; i<${#ARGS[@]}; i++)); do
  if [[ "${ARGS[$i]}" == "serve" ]]; then
    is_serve=true
  elif [[ "${ARGS[$i]}" == "--state-dir" && $((i+1)) -lt ${#ARGS[@]} ]]; then
    state_dir="${ARGS[$((i+1))]}"
  elif [[ "${ARGS[$i]}" == --state-dir=* ]]; then
    state_dir="${ARGS[$i]#--state-dir=}"
  fi
done

if [[ "$is_serve" == "true" ]]; then
  mkdir -p "${state_dir}"
  lock_file="${state_dir}/serve.lock"
  ctrl_file="${state_dir}/control.json"
  locked_pid=""
  if [[ -f "${lock_file}" ]]; then
    locked_pid=$(grep -oE ':pid[[:space:]]+[0-9]+' "${lock_file}" | awk '{print $2}' || true)
  fi
  if [[ -z "${locked_pid}" && -f "${ctrl_file}" ]]; then
    locked_pid=$(grep -oE '"pid"[[:space:]]*:[[:space:]]*[0-9]+' "${ctrl_file}" | grep -oE '[0-9]+' || true)
  fi
  if [[ -n "${locked_pid}" && "${locked_pid}" != "$$" ]] && kill -0 "${locked_pid}" 2>/dev/null; then
    echo "{\"event\":\"duplicate-serve-rejected\",\"ok\":false,\"error\":\"already-running\",\"locked_pid\":${locked_pid},\"diagnose\":\"duplicate-serve-instance-rejected\"}"
    exit 1
  fi
fi

exec clojure -J--enable-native-access=ALL-UNNAMED \
     -J--add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
     -J--add-exports=java.base/sun.security.x509=ALL-UNNAMED \
     -M -m bitecho.main light-node "${ARGS[@]}"
