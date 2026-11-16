#!/usr/bin/env bash
# ==============================================================================
# scripts/build-sea.sh - Node.js Single Executable Application (SEA) Builder
# Builds standalone Node.js light-node executable (Milestone D26 / Direction 3)
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "=== Building Bitecho Node.js Single Executable Application (SEA) ==="

# 1. Assert preconditions loudly (Rule 6)
if ! command -v node >/dev/null 2>&1; then
  echo "FATAL: node binary not found in PATH." >&2
  exit 1
fi

NODE_VER=$(node -v | sed 's/^v//')
NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
if [[ "$NODE_MAJOR" -lt 20 ]]; then
  echo "FATAL: Node.js version 20+ required for SEA (found v${NODE_VER})." >&2
  exit 1
fi

# Ensure light-node bundle exists or build it
if [[ ! -f "dist/bitecho-light-node.cjs" ]]; then
  echo "--> dist/bitecho-light-node.cjs not found. Building Node light-node bundle..."
  ./scripts/build-node-light-node.sh
fi

mkdir -p dist

# 2. Generate sea-config.json
SEA_CONFIG="sea-config.json"
cat > "${SEA_CONFIG}" << 'EOF'
{
  "main": "dist/bitecho-light-node.cjs",
  "output": "dist/sea-prep.blob",
  "disableExperimentalSEAWarning": true,
  "useCodeCache": true
}
EOF

echo "--> Generated ${SEA_CONFIG} with disableExperimentalSEAWarning & useCodeCache"

# 3. Generate the SEA preparation blob
echo "--> Generating dist/sea-prep.blob via node --experimental-sea-config..."
node --experimental-sea-config "${SEA_CONFIG}"

# 4. Copy node binary and inject blob
OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_NAME=$(uname -m)
case "$ARCH_NAME" in
  x86_64) ARCH_NAME="x64" ;;
  aarch64|arm64) ARCH_NAME="arm64" ;;
esac

TARGET_BIN="dist/bitecho-light-node-${OS_NAME}-${ARCH_NAME}"
cp "$(command -v node)" "${TARGET_BIN}"
chmod u+w "${TARGET_BIN}"

# Remove signature on macOS if required
if [[ "$OS_NAME" == "darwin" ]] && command -v codesign >/dev/null 2>&1; then
  codesign --remove-signature "${TARGET_BIN}" || true
fi

# Inject blob using postject or npx postject
if command -v npx >/dev/null 2>&1; then
  echo "--> Injecting blob into ${TARGET_BIN}..."
  SENTINEL_FUSE="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"
  if [[ "$OS_NAME" == "darwin" ]]; then
    npx --yes postject "${TARGET_BIN}" NODE_SEA_BLOB dist/sea-prep.blob \
      --sentinel-fuse "${SENTINEL_FUSE}" \
      --macho-segment-name NODE_SEA || true
    if command -v codesign >/dev/null 2>&1; then
      codesign --sign - "${TARGET_BIN}" || true
    fi
  else
    npx --yes postject "${TARGET_BIN}" NODE_SEA_BLOB dist/sea-prep.blob \
      --sentinel-fuse "${SENTINEL_FUSE}" || true
  fi
fi

chmod +x "${TARGET_BIN}"
echo "=== SEA Build Complete: ${TARGET_BIN} ==="
