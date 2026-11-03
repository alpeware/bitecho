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

exec clojure -J--enable-native-access=ALL-UNNAMED \
     -J--add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
     -J--add-exports=java.base/sun.security.x509=ALL-UNNAMED \
     -M -m bitecho.main light-node "${ARGS[@]}"
