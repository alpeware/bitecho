# BIP-017b: Atomic `web/app/release` Pointer Resolver, Strict `/app/*` CSP + COOP/COEP Headers, & `legacy.js` Extraction

**Status:** Stage-2 Implementation (Isolated Branch — Pending 5/5 Real Stage 2 Consent)
**Scope:** Pure Sans-IO `.cljc` atomic `web/app/release` resolver & lifecycle reducer, JVM & Node.js infra `/app/*` atomic serving with pointer-versioned strict CSP + COOP/COEP headers, `legacy.js` extraction with SHA-384 SRI, and Rule 6 CLI/flag inventory.

---

## 1. Domain-Separated Release CID & Detached 2-of-3 Quorum Signatures (`bitecho.storage.app-release`)

- **Canonicalization:** Reuses RFC 8785 JCS (`bitecho.storage.chunk-constants/jcs-canonical-bytes`, integers only, sorted keys).
- **Release CID:** `release-cid = SHA-256("bitecho/web-app-release/v1" || canonical-release-bytes(release))` (64-char lowercase hex, byte-identical across JVM and CLJS).
- **Detached Quorum Envelope:**
  ```edn
  {:release-cid "<64-hex>"
   :sigs [{:owner-pubkey "<hex>" :sig "<hex>"} ...]}
  ```
- **2-of-3 Threshold Verification (`verify-release-quorum-envelope`):**
  - Rejects `< threshold` signatures, duplicate `:owner-pubkey` entries, unknown signers outside `:trusted-signers`, or tampered release bytes fail-closed with counted `:diagnose` `:release-sig-invalid`.

---

## 2. Zero-TOFU Genesis Pin, Monotonic Floor & Single-Authority Reducer (Rules 4 & 5)

- **CID-Pinned Genesis Anchor:** `:genesis-anchor-cid` MUST match the node's pinned genesis policy CID (zero TOFU). Missing or mismatched genesis anchor fails closed with `:release-genesis-missing`.
- **Single-Authority Reducer:** `(transition state event) -> [new-state effects]` maintains:
  - Monotonic persisted `:current-seq` floor (`seq <= current-seq` -> `:release-seq-non-monotonic`, zero mutation).
  - Generation isolation (`ev-gen < current-gen` -> `:ignored-stale-release`, zero mutation).
  - Asset completeness & integrity (`:release-asset-missing`, `:release-asset-corrupt`) while keeping the previous active generation untouched.
  - Strict storage accounting (`:bytes-at-rest == sum(assets[].size)` -> `:storage-accounting-mismatch`).
  - Generalized SHA-384 SRI verification across ALL executable JS/WASM assets + HTML `<script src=... integrity=sha384-...>` and `.sri` file cross-check -> `:release-sri-mismatch`.
  - Atomic `:lkg-release-cid` retention pin (`:max-bytes >= 2 * active-release-bytes` -> `:retention-bound-exceeded`; LKG eviction attempts -> `:release-lkg-evicted`).
  - Diagnostic conservation invariant: `(:dropped (:diagnostics st)) == sum(vals(:causes (:diagnostics st)))`.

---

## 3. Strict `/app/*` `headers-config` Validation (`validate-headers-config`)

Every release references a content-addressed `:headers-config-cid` blob. Serving `/app/*` applies headers strictly from the validated `:headers-config`:
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: credentialless`
- `Cache-Control: no-cache`
- `Content-Security-Policy`:
  - `script-src` MUST include `'self'` and `'wasm-unsafe-eval'`
  - `script-src` MUST NOT include `'unsafe-inline'`
  - NO directive may include `'unsafe-eval'`
  - `connect-src` MUST include `blob:`

---

## 4. `legacy.js` Extraction & Zero Inline `<script>` (`scripts/build-browser-bundle.sh`)

- Extracts the legacy dashboard inline `<script>` from `dist/index.html` into `dist/legacy.js` (and `resources/public/legacy.js`) with computed SHA-384 SRI (`dist/legacy.js.sri`).
- `dist/index.html` and `dist/legacy.html` enforce strict CSP (no `'unsafe-inline'` in `script-src`) and load both `/app/bitecho-browser.js` and `/app/legacy.js` with `integrity="sha384-..." crossorigin="anonymous"`.

---

## 5. Infra Shell `/app/*` Routing & Backwards-Compatible Fallback

- Wired in `bitecho.shell.infra`, `bitecho.shell.http`, and `bitecho.full-node-main`.
- Serves `/app/`, `/app/index.html`, `/app/trace-viz.html`, `/app/legacy.html`, `/app/chat.js`, `/app/trace-viz.js`, `/app/legacy.js`, `/app/bitecho-browser.js`, `/app/bitecho-browser.js.sri`, and any self-hosted asset key in `:assets` atomically from `web/app/release` with headers strictly from `:headers-config-cid`.
- When no `web/app/release` pointer exists yet, falls back seamlessly to individual `web/app/*` pointers (zero regression before live cutover).

---

## 6. Monotonic Rollback Protocol (`seq N -> N+1 -> N+2`)

- Rollback NEVER rewinds `seq` (which is rejected fail-closed with `:release-seq-non-monotonic`).
- Pre-signed monotonic rollback publishes `seq N+2` referencing the exact `.lkg` asset CIDs and legacy `:headers-config-cid`, restoring byte-identical `.sri`, `index.html`, `legacy.js`, `bitecho-browser.js`, and legacy headers atomically.

---

## 7. CLI Verbs & Flags (Rule 6 Inventory)

- **Verbs:** `web-release-publish`, `web-release-rollback`, `web-release-verify`
- **Flags:** `--release-cid`, `--genesis-anchor-cid`, `--lkg-release-cid`, `--headers-config-cid`
