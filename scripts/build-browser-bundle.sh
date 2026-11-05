#!/usr/bin/env bash
# scripts/build-browser-bundle.sh
# Compiles the Bitecho CLJS browser client into a deterministic static bundle,
# computes Subresource Integrity (SRI) hashes (SHA-384 and SHA-256),
# generates dist/index.html with SRI script tags, verifies reproducible determinism
# across consecutive builds, and syncs the distribution into clj-web/public/app.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=== Bitecho Browser Bundle Build ==="
echo "Working directory: ${ROOT_DIR}"

# 1. Clean and prepare dist directory
mkdir -p dist
rm -rf target/cljs-browser target/cljs-browser-verify target/bundle-verify
mkdir -p target/bundle-verify

# 2. Compile bitecho.browser-main into dist/bitecho-browser.js
echo "Compiling bitecho.browser-main via ClojureScript (:optimizations :simple)..."
clojure -M:build-browser -e '
(require (quote [cljs.build.api :as b]))
(b/build (b/inputs "src")
         {:main (quote bitecho.browser-main)
          :output-to "dist/bitecho-browser.js"
          :output-dir "target/cljs-browser/out"
          :optimizations :simple})'

if [ ! -f "dist/bitecho-browser.js" ]; then
  echo "ERROR: dist/bitecho-browser.js was not generated!" >&2
  exit 1
fi

BUNDLE_SIZE=$(wc -c < "dist/bitecho-browser.js")
echo "Generated dist/bitecho-browser.js (${BUNDLE_SIZE} bytes)"

# 3. Compute Subresource Integrity (SRI) hashes
echo "Computing Subresource Integrity (SRI) hashes..."
SHA384_BASE64=$(openssl dgst -sha384 -binary dist/bitecho-browser.js | openssl base64 -A)
SHA256_BASE64=$(openssl dgst -sha256 -binary dist/bitecho-browser.js | openssl base64 -A)

SRI_384="sha384-${SHA384_BASE64}"
SRI_256="sha256-${SHA256_BASE64}"

printf "%s\n%s\n" "${SRI_384}" "${SRI_256}" > dist/bitecho-browser.js.sri
echo "Written dist/bitecho-browser.js.sri:"
cat dist/bitecho-browser.js.sri

# 4. Generate dist/index.html loading the bundle with SRI attributes
echo "Generating dist/index.html..."
cat <<EOF > dist/index.html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bitecho Browser Node</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; text-align: center; background: #fdfdfd; color: #1e1e1e; }
    h1 { color: #111; }
    .card { background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-top: 24px; }
    button { background: #1a73e8; color: white; border: none; padding: 10px 20px; font-size: 15px; border-radius: 4px; cursor: pointer; transition: background 0.2s; }
    button:hover { background: #1557b0; }
    pre { background: #1e1e1e; color: #00ff66; padding: 16px; border-radius: 6px; overflow-x: auto; text-align: left; font-size: 13px; min-height: 200px; }
  </style>
</head>
<body>
  <h1>Bitecho Browser Node</h1>
  <p>Decentralized Autonomous Mesh Client &amp; Light Node</p>
  <div class="card">
    <button id="runDemoBtn">Run Browser Subnet Demo</button>
    <pre id="outputLog">Loading BitechoBrowser bundle...</pre>
  </div>
  <script src="bitecho-browser.js" integrity="${SRI_384}" crossorigin="anonymous"></script>
  <script>
    const log = document.getElementById("outputLog");
    const btn = document.getElementById("runDemoBtn");
    if (globalThis.BitechoBrowser) {
      log.textContent = "BitechoBrowser v" + globalThis.BitechoBrowser.version + " initialized.\nReady to run browser subnet demo.";
    } else {
      log.textContent = "Error: BitechoBrowser global not found.";
    }
    btn.onclick = () => {
      if (globalThis.BitechoBrowser) {
        log.textContent = "Running browser subnet demo...";
        const res = globalThis.BitechoBrowser.runSubnetDemo();
        log.textContent = JSON.stringify(res, null, 2);
      }
    };
  </script>
</body>
</html>
EOF

# 5. Verify build reproducibility across consecutive runs
echo "Verifying build reproducibility (consecutive build comparison)..."
clojure -M:build-browser -e '
(require (quote [cljs.build.api :as b]))
(b/build (b/inputs "src")
         {:main (quote bitecho.browser-main)
          :output-to "target/bundle-verify/bitecho-browser.js"
          :output-dir "target/cljs-browser-verify/out"
          :optimizations :simple})'

if cmp -s "dist/bitecho-browser.js" "target/bundle-verify/bitecho-browser.js"; then
  echo "SUCCESS: Build is 100% byte-for-byte reproducible!"
else
  echo "WARNING: Differences detected between consecutive builds."
  diff -u "dist/bitecho-browser.js" "target/bundle-verify/bitecho-browser.js" | head -n 30 || true
fi

# 6. Sync to ../clj-web/public/app if clj-web exists
CLJ_WEB_PUBLIC="${ROOT_DIR}/../clj-web/public"
if [ -d "${CLJ_WEB_PUBLIC}" ]; then
  mkdir -p "${CLJ_WEB_PUBLIC}/app"
  cp dist/bitecho-browser.js "${CLJ_WEB_PUBLIC}/app/"
  cp dist/bitecho-browser.js.sri "${CLJ_WEB_PUBLIC}/app/"
  cp dist/index.html "${CLJ_WEB_PUBLIC}/app/"
  echo "Synced bundle and SRI hash to ${CLJ_WEB_PUBLIC}/app/"
fi

echo "=== Browser bundle build complete ==="
