#!/usr/bin/env bash
# scripts/run-validator-node.sh (installed to /opt/bitecho/run-node.sh)
# Runtime supervisor for bitecho.service (`BIP-010 / BIP-011: P-NODE-1`).
# Reads /opt/bitecho/active-runtime.env and enforces a fail-closed
# runtime-binary preflight gate (Node.js >= v22) before exec'ing
# `node /opt/bitecho/bitecho-full-node.cjs run /etc/bitecho/config.edn`,
# reverting cleanly to JVM if Node.js >= 22 or the bundle is missing/incompatible.

set -euo pipefail

RUNTIME_ENV="${BITECHO_RUNTIME_ENV:-/opt/bitecho/active-runtime.env}"
CONFIG_FILE="${1:-${BITECHO_CONFIG:-/etc/bitecho/config.edn}}"
NODE_BUNDLE="${BITECHO_NODE_BUNDLE:-/opt/bitecho/bitecho-full-node.cjs}"
JVM_JAR="${BITECHO_JVM_JAR:-/opt/bitecho/bitecho.jar}"
JAVA_BIN="${BITECHO_JAVA_BIN:-/opt/jdk-25/bin/java}"
NETWORK="${BITECHO_NETWORK:-devnet}"
POINTER_PATH="${BITECHO_POINTER_PATH:-/var/lib/bitecho/config/${NETWORK}/active.edn}"
LKG_BUNDLE="${NODE_BUNDLE}.lkg"
RUNTIME="jvm"

if [[ -f "${RUNTIME_ENV}" ]]; then
  # shellcheck disable=SC1090
  source "${RUNTIME_ENV}"
fi

check_unified_pointer() {
  local nbin="$1"
  if [[ -f "${POINTER_PATH}" && -n "${nbin}" && -x "${nbin}" && -s "${NODE_BUNDLE}" ]]; then
    if ! "${nbin}" "${NODE_BUNDLE}" --check-pointer "${POINTER_PATH}" >/dev/null 2>&1; then
      echo "{\"event\":\"unified-pointer-verification-failed\",\"pointer\":\"${POINTER_PATH}\",\"action\":\"retain-lkg\"}" >&2
      if [[ -s "${LKG_BUNDLE}" ]]; then
        cp -f "${LKG_BUNDLE}" "${NODE_BUNDLE}"
      fi
      return 1
    fi
  fi
  return 0
}

resolve_node_bin() {
  if [[ -n "${NODE_BIN:-}" && -x "${NODE_BIN}" ]]; then
    echo "${NODE_BIN}"
    return 0
  fi
  for cand in /usr/bin/node /usr/local/bin/node "${HOME:-/home/bitecho}/.local/bin/node"; do
    if [[ -x "${cand}" ]]; then
      echo "${cand}"
      return 0
    fi
  done
  command -v node 2>/dev/null || true
}

check_node_preflight() {
  local nbin="$1"
  if [[ -z "${nbin}" || ! -x "${nbin}" ]]; then
    echo '{"event":"runtime-preflight-failed","reason":"node-binary-missing","fallback":"jvm"}' >&2
    return 1
  fi
  local ver major
  ver="$("${nbin}" --version 2>/dev/null || true)"
  major="$(echo "${ver}" | sed -n -E 's/^v([0-9]+)\..*/\1/p')"
  if [[ -z "${major}" || "${major}" -lt 22 ]]; then
    echo "{\"event\":\"runtime-preflight-failed\",\"reason\":\"node-version-incompatible\",\"version\":\"${ver}\",\"required\":\">=22\",\"fallback\":\"jvm\"}" >&2
    return 1
  fi
  if [[ ! -s "${NODE_BUNDLE}" ]]; then
    echo "{\"event\":\"runtime-preflight-failed\",\"reason\":\"node-bundle-missing\",\"bundle\":\"${NODE_BUNDLE}\",\"fallback\":\"jvm\"}" >&2
    return 1
  fi
  return 0
}

if [[ "${RUNTIME}" == "nodejs" ]]; then
  RESOLVED_NODE="$(resolve_node_bin)"
  if check_node_preflight "${RESOLVED_NODE}"; then
    check_unified_pointer "${RESOLVED_NODE}" || true
    # Exit 75 triggers OpenRC supervise-daemon respawn after unified pointer advance (P-HOST-6)
    exec "${RESOLVED_NODE}" "${NODE_BUNDLE}" run "${CONFIG_FILE}"
  else
    echo '{"event":"runtime-fallback","from":"nodejs","to":"jvm"}' >&2
    RUNTIME="jvm"
  fi
fi

if [[ ! -x "${JAVA_BIN}" ]]; then
  JAVA_BIN="$(command -v java 2>/dev/null || true)"
fi
if [[ -z "${JAVA_BIN}" || ! -x "${JAVA_BIN}" || ! -s "${JVM_JAR}" ]]; then
  echo '{"event":"runtime-fatal","reason":"no-valid-runtime-available"}' >&2
  exit 1
fi

exec "${JAVA_BIN}" \
  -Xms128m -Xmx448m -XX:MaxMetaspaceSize=112m -XX:MaxDirectMemorySize=64m \
  -XX:+UseCompactObjectHeaders -XX:+UseG1GC \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar "${JVM_JAR}" run "${CONFIG_FILE}"
