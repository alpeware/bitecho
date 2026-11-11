#!/usr/bin/env bash
# scripts/build-node-light-node.sh
# Compiles the Bitecho Node.js Light Node (bitecho.node-main) into a standalone,
# deterministic single-file CommonJS bundle (`dist/bitecho-light-node.cjs`),
# computes SHA-256 integrity hash (`dist/bitecho-light-node.cjs.sha256`),
# verifies reproducible determinism across consecutive builds, and runs a CLI smoke check.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=== Bitecho Node.js Light-Node Bundle Build (M2b) ==="
echo "Working directory: ${ROOT_DIR}"

mkdir -p dist
rm -rf target/cljs-node target/cljs-node-verify

echo "Compiling bitecho.node-main via ClojureScript (:target :nodejs, :optimizations :simple)..."
clojure -M:build-browser -e '
(require (quote [cljs.build.api :as b]))
(b/build (b/inputs "src")
         {:main (quote bitecho.node-main)
          :output-to "dist/bitecho-light-node.cjs"
          :output-dir "target/cljs-node/out"
          :target :nodejs
          :parallel-build false
          :optimizations :simple})'

if [ ! -f "dist/bitecho-light-node.cjs" ]; then
  echo "ERROR: dist/bitecho-light-node.cjs was not generated!" >&2
  exit 1
fi

normalize_bundle() {
  local bundle_file="$1"
  python3 - "$bundle_file" <<'PY'
import re, sys, zlib
path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

dyn_map = {}
def repl_dyn(m):
    orig = m.group(0)
    if orig not in dyn_map:
        dyn_map[orig] = f'$dyn_{len(dyn_map) + 1}'
    return dyn_map[orig]
content = re.sub(r'\$dyn_[0-9]+', repl_dyn, content)

gen_map = {}
def repl_gen(m):
    prefix = m.group(1)
    orig = m.group(0)
    if orig not in gen_map:
        gen_map[orig] = f'{prefix}{len(gen_map) + 1}'
    return gen_map[orig]
content = re.sub(r'(map__|p__|vec__|seq__|first__|G__|t_(?:[A-Za-z0-9_]+\$)+(?!dyn_)[A-Za-z_]+|meta)[0-9]+', repl_gen, content)

def repl_sym_hash(m):
    ws = m.group(1)
    sym = m.group(2)
    h = zlib.crc32(sym.encode('utf-8'))
    if h >= 0x80000000:
        h -= 0x100000000
    return f'new cljs.core.Symbol(null,{ws}"{sym}","{sym}",{h},null)'

content = re.sub(
    r'new cljs\.core\.Symbol\(null,(\s*)"((?:map__|p__|vec__|seq__|first__|G__|t_(?:[A-Za-z0-9_]+\$)+(?!dyn_)[A-Za-z_]+|meta)[0-9]+)","\2",-?[0-9]+,null\)',
    repl_sym_hash,
    content
)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
PY
}

normalize_bundle "dist/bitecho-light-node.cjs"

echo "Verifying deterministic reproducibility via second build..."
clojure -M:build-browser -e '
(require (quote [cljs.build.api :as b]))
(b/build (b/inputs "src")
         {:main (quote bitecho.node-main)
          :output-to "target/cljs-node-verify/bitecho-light-node.cjs"
          :output-dir "target/cljs-node-verify/out"
          :target :nodejs
          :parallel-build false
          :optimizations :simple})'

normalize_bundle "target/cljs-node-verify/bitecho-light-node.cjs"

SHA1=$(sha256sum "dist/bitecho-light-node.cjs" | awk '{print $1}')
SHA2=$(sha256sum "target/cljs-node-verify/bitecho-light-node.cjs" | awk '{print $1}')

if [ "${SHA1}" != "${SHA2}" ]; then
  echo "ERROR: Non-deterministic build detected! (${SHA1} != ${SHA2})" >&2
  exit 1
fi

printf "%s  bitecho-light-node.cjs\n" "${SHA1}" > "dist/bitecho-light-node.cjs.sha256"
BUNDLE_SIZE=$(wc -c < "dist/bitecho-light-node.cjs")
echo "Generated deterministic dist/bitecho-light-node.cjs (${BUNDLE_SIZE} bytes, sha256=${SHA1})"

# Smoke test with Node.js
NODE_BIN="${NODE_BIN:-node}"
if [ -x "${HOME}/.local/bin/node" ]; then
  NODE_BIN="${HOME}/.local/bin/node"
fi

TMP_STATE_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_STATE_DIR}"' EXIT

SMOKE_OUT=$("${NODE_BIN}" "dist/bitecho-light-node.cjs" identity --state-dir "${TMP_STATE_DIR}")
echo "Smoke check output: ${SMOKE_OUT}"
if [[ "${SMOKE_OUT}" != *'"ok":true'* || "${SMOKE_OUT}" != *'"pubkey":'* ]]; then
  echo "ERROR: Smoke check failed for dist/bitecho-light-node.cjs!" >&2
  exit 1
fi

# Serve startup smoke check (F-G3 / F-G4: verifies serve starts without crashing on IWithMeta or failing offline bootstrap)
cat << 'EOF' > "${TMP_STATE_DIR}/bootstrap.txt"
Network: devnet
Treasury Public Key: 302a300506032b65700321007c2b695b77904a19a630b75ce53889a53963c0f85aa69e5276bb988a183b91b8
Custody Public Key:  302a300506032b6570032100e476d77ef34962d09baee0062b4c03be832a1ccc2d691623a8cb39e356793f2b
Directory Authority Public Key: 302a300506032b657003210056b505baa32c3b99663d163d6ee00b5018a26e182405f5ec4d5062f12f633ce9

Node: node1 (local-smoke)
  Cluster Address:   127.0.0.1:19999 (UDP DataChannel)
  Agent Ingress:     127.0.0.1:19999 (UDP DataChannel)
  Agent TCP Ingress: 127.0.0.1:19999 (TCP DataChannel)
  Ed25519 Pubkey:    302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086
  DTLS Fingerprint:  95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B
  ICE Credentials:   ufrag=1ec0ae74 pwd=d928f1aac56a0d6e6fdda551
EOF

SERVE_OUT=$( (sleep 0.5; echo '{"cmd":"status"}'; sleep 0.5) | timeout 5 "${NODE_BIN}" "dist/bitecho-light-node.cjs" serve --state-dir "${TMP_STATE_DIR}" --bootstrap "${TMP_STATE_DIR}/bootstrap.txt" --transport tcp --ingress-tcp-port 0 2>&1 || true)
echo "Serve smoke check output: ${SERVE_OUT}"
if [[ "${SERVE_OUT}" == *"descriptor-file-not-found"* || "${SERVE_OUT}" == *"IWithMeta"* || "${SERVE_OUT}" == *"alter-meta!"* || "${SERVE_OUT}" == *"TypeError"* ]]; then
  echo "ERROR: Serve smoke check failed for dist/bitecho-light-node.cjs!" >&2
  exit 1
fi
if [[ "${SERVE_OUT}" != *'"mdns_hostname":'* ]]; then
  echo "ERROR: Serve smoke check did not produce expected mdns_hostname status output!" >&2
  exit 1
fi

echo "=== Bitecho Node.js Light-Node Bundle Verified Successfully ==="
