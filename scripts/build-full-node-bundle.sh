#!/usr/bin/env bash
# scripts/build-full-node-bundle.sh
# Compiles the Bitecho Node.js Full / Infra Node (bitecho.full-node-main) into a standalone,
# deterministic single-file CommonJS bundle (`dist/bitecho-full-node.cjs`),
# computes SHA-256 integrity hash (`dist/bitecho-full-node.cjs.sha256`),
# verifies reproducible determinism across consecutive builds, and runs `--self-test`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=== Bitecho Node.js Full-Node Bundle Build (BIP-010 / P-NODE-1) ==="
echo "Working directory: ${ROOT_DIR}"

mkdir -p dist
rm -rf target/cljs-full-node target/cljs-full-nod2

echo "Compiling bitecho.full-node-main via ClojureScript (:target :nodejs, :optimizations :advanced)..."
clojure -M:build-browser -e '
(require (quote [cljs.build.api :as b]))
(b/build (b/inputs "src")
         {:main (quote bitecho.full-node-main)
          :output-to "dist/bitecho-full-node.cjs"
          :output-dir "target/cljs-full-node/out"
          :target :nodejs
          :externs ["resources/closure-externs.js"]
          :infer-externs true
          :parallel-build false
          :optimizations :advanced})'

if [ ! -f "dist/bitecho-full-node.cjs" ]; then
  echo "ERROR: dist/bitecho-full-node.cjs was not generated!" >&2
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

content = content.replace("target/cljs-full-nod2/out", "target/cljs-full-node/out")

if not content.startswith("#!/usr/bin/env node\n"):
    content = "#!/usr/bin/env node\n" + content

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
PY
chmod +x "$bundle_file"
}

normalize_bundle "dist/bitecho-full-node.cjs"

echo "Verifying deterministic reproducibility via second build..."
clojure -M:build-browser -e '
(require (quote [cljs.build.api :as b]))
(b/build (b/inputs "src")
         {:main (quote bitecho.full-node-main)
          :output-to "target/cljs-full-nod2/bitecho-full-node.cjs"
          :output-dir "target/cljs-full-nod2/out"
          :target :nodejs
          :externs ["resources/closure-externs.js"]
          :infer-externs true
          :parallel-build false
          :optimizations :advanced})'

normalize_bundle "target/cljs-full-nod2/bitecho-full-node.cjs"

SHA1=$(sha256sum "dist/bitecho-full-node.cjs" | awk '{print $1}')
SHA2=$(sha256sum "target/cljs-full-nod2/bitecho-full-node.cjs" | awk '{print $1}')

if [ "${SHA1}" != "${SHA2}" ]; then
  echo "ERROR: Non-deterministic build detected! (${SHA1} != ${SHA2})" >&2
  exit 1
fi

printf "%s  bitecho-full-node.cjs\n" "${SHA1}" > "dist/bitecho-full-node.cjs.sha256"
BUNDLE_SIZE=$(wc -c < "dist/bitecho-full-node.cjs")
echo "Generated deterministic dist/bitecho-full-node.cjs (${BUNDLE_SIZE} bytes, sha256=${SHA1})"

NODE_BIN="${NODE_BIN:-node}"
if [ -x "${HOME}/.local/bin/node" ]; then
  NODE_BIN="${HOME}/.local/bin/node"
fi

SELF_TEST_OUT=$("${NODE_BIN}" "dist/bitecho-full-node.cjs" --self-test)
echo "Full-node self-test output: ${SELF_TEST_OUT}"
if [[ "${SELF_TEST_OUT}" != *'"ok":true'* || "${SELF_TEST_OUT}" != *'"runtime":"nodejs"'* ]]; then
  echo "ERROR: Full-node self-test failed for dist/bitecho-full-node.cjs!" >&2
  exit 1
fi

echo "=== Bitecho Node.js Full-Node Bundle Verified Successfully ==="
