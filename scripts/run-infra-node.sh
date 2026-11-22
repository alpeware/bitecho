#!/usr/bin/env bash
# scripts/run-infra-node.sh (installed to /opt/bitecho-infra/run-node.sh)
# Runtime supervisor for bitecho-infra.service (`BIP-010 / BIP-011: P-NODE-1`).
# Reads /opt/bitecho-infra/active-runtime.env and enforces a fail-closed
# runtime-binary preflight gate (Node.js >= v22) before exec'ing
# `node /opt/bitecho-infra/bitecho-full-node.cjs infra-node /etc/bitecho-infra/config.edn`,
# reverting cleanly to JVM if Node.js >= 22 or the bundle is missing/incompatible.

set -euo pipefail

RUNTIME_ENV="${BITECHO_RUNTIME_ENV:-/opt/bitecho-infra/active-runtime.env}"
CONFIG_FILE="${BITECHO_INFRA_CONFIG:-/etc/bitecho-infra/config.edn}"
NODE_BUNDLE="${BITECHO_NODE_BUNDLE:-/opt/bitecho-infra/bitecho-full-node.cjs}"
JVM_JAR="${BITECHO_JVM_JAR:-/opt/bitecho-infra/bitecho.jar}"
JAVA_BIN="${BITECHO_JAVA_BIN:-/opt/jdk-25/bin/java}"
NETWORK="${BITECHO_NETWORK:-devnet}"
POINTER_PATH="${BITECHO_POINTER_PATH:-/var/lib/clj-web/config/${NETWORK}/active.edn}"
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
  for cand in /usr/bin/node /usr/local/bin/node "${HOME:-/home/cljweb}/.local/bin/node"; do
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
    # P-OBS-5 / BIP-018-SOAK-F1: bound glibc arena/mmap retention so >=16 KiB Node.js TLS records,
    # 64 KiB HTTP socket chunks, and 512 KiB chunk buffers return directly to Linux via munmap()
    # instead of fragmenting glibc brk() [heap], and tighten V8 old-space heap cap to 192 MiB on e2-micro.
    export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"
    export MALLOC_MMAP_THRESHOLD_="${MALLOC_MMAP_THRESHOLD_:-16384}"
    export MALLOC_TRIM_THRESHOLD_="${MALLOC_TRIM_THRESHOLD_:-16384}"
    NODE_MAX_OLD_SPACE_MB="${BITECHO_NODE_MAX_OLD_SPACE_MB:-192}"
    # Exit 75 triggers OpenRC supervise-daemon respawn after unified pointer advance (P-HOST-6)
    exec "${RESOLVED_NODE}" "--max-old-space-size=${NODE_MAX_OLD_SPACE_MB}" "${NODE_BUNDLE}" infra-node "${CONFIG_FILE}"
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
  -Xms128m -Xmx448m -XX:MaxMetaspaceSize=112m -XX:MaxDirectMemorySize=64m -XX:+UseCompactObjectHeaders \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar "${JVM_JAR}" infra-node "${CONFIG_FILE}"
