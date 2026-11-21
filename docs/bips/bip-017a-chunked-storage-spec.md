# BIP-017a: Chunked Large-Artifact Storage, Safe Blob Headers & `BitechoLightNode` v1.1.0 Additive Facade

**Status:** Consented (5/5 Real Stage 2 Consent — Landed on `main`)
**Scope:** Pure Sans-IO `.cljc` chunk manifest & resumable fetch state machine, JVM & Node.js infra blob headers/quota enforcement, `window.BitechoLightNode` v1.1.0 additive facade, and Rule 6 CLI/flag inventory.

---

## 1. Normative Constants (`bitecho.storage.chunk-constants`)

| Constant | Value | Description |
| :--- | :--- | :--- |
| `manifest-domain-tag` | `"bitecho/chunk-manifest/v1"` | Domain separation prefix for manifest CID SHA-256 |
| `min-chunk-bytes` | `65536` (64 KiB) | Minimum allowed chunk size |
| `default-chunk-bytes` | `1048576` (1 MiB) | Default chunk size |
| `max-chunk-bytes` | `4194304` (4 MiB) | Hard ceiling per chunk blob |
| `max-chunks-per-manifest` | `8192` | Maximum chunks per manifest |
| `default-fetch-concurrency` | `2` | Default parallel chunk fetches |
| `max-fetch-concurrency-940mb` | `3` | Hard concurrency cap on 940 MiB RAM nodes/browsers |
| `min-grace-epochs` | `4` | Minimum finalized-epoch grace window before refcounted GC |
| `default-infra-chunk-quota-bytes` | `2147483648` (2 GiB) | Default infra chunk store quota |

All configurable caps apply a pure `(min constant config)` clamp (`clamp-cap`) and emit a counted `:diagnose` effect (`:cap-ceiling-clamped`) whenever clamped.

---

## 2. Manifest v1 Canonicalization & Detached Owner Envelopes

- **RFC 8785 JCS Canonicalization (`jcs-canonicalize`):**
  - Object keys sorted lexicographically (UTF-16 code-unit order), compact JSON without insignificant whitespace, lowercase hex strings, and **integers only** (non-integer floats rejected fail-closed).
  - `manifest-cid = SHA-256("bitecho/chunk-manifest/v1" || jcs-canonical-bytes(manifest))` (byte-identical across JVM and CLJS).
- **Fail-Closed Validation (`validate-manifest` & `verify-detached-owner-envelope`):**
  - `:missing-state-owner` — missing or invalid `state_owner` / `:owner-pubkey`.
  - `:owner-signature-invalid` — Ed25519 signature verification failure or signer mismatch.
  - `:owner-signature-ambiguous` — `> 1` verifying owner signatures on the same manifest.
  - `:missing-retention-policy` — missing `retention_policy` or `grace_epochs < 4`.
  - `:storage-accounting-mismatch` — chunk index non-contiguous, chunk size invalid, or `sum(chunk.size) != total_bytes`.
  - `:max-bytes-exceeded` — `total_bytes > configured max-bytes`.

---

## 3. Pure Sans-IO Chunk Fetch State Machine (`bitecho.storage.chunk-fetch`)

- Single-authority generation-tagged state map `(init-fetch-state opts)` updated exclusively via `(transition state event) -> [new-state effects]` (Rules 2 & 4).
- **Zero Mutable Digest in Reducer:** Incremental SHA-256 runs strictly via shell effects (`:digest-chunk` -> `:digest-result` -> `:digest-final`) in strict chunk index order `0..N-1`.
- **Resumability:** Pausing and resuming in a new generation (`gen + 1`) with cached chunk indices issues **0 redundant network fetches** for cached chunks.
- **Fault Handling & Zero Silent Failures (Rule 5):**
  - Corrupt chunks (`:chunk-cid-mismatch`, `:chunk-size-mismatch`) blacklist the offending mirror for the current generation only and retry on healthy mirrors up to `:max-retries`, failing loudly on exhaustion.
  - HTTP `410 Gone` emits counted `:chunk-gone` and `:grace-expired` diagnostics, **never** blacklists the mirror, and **never** counts as `:chunk-fetch-failed`.
  - OPFS/disk cache eviction emits `:cache-evicted` and re-queues the chunk for fetch and verification.
  - Stale-generation callbacks (`ev-gen < current`) emit counted `:ignored-stale-chunk` with zero operational state mutation.
  - Staged-but-unhashed bytes are counted toward `:bytes-at-rest` and HTTP `507` quota checks (`:chunk-store-quota-exceeded`).
  - `:dropped == sum(vals(:causes))` holds as an invariant across every transition.

---

## 4. Safe Blob HTTP Headers & Quota (`bitecho.shell.{http,infra}` & `bitecho.full-node-main`)

Scoped **strictly** to `GET/HEAD /artifact/v1/blob/<cid>`:
- `Cache-Control: public, max-age=31536000, immutable`
- `Access-Control-Allow-Origin: *` (NEVER emitted on non-blob endpoints)
- `X-Content-Type-Options: nosniff`
- `Content-Type` allowlist: `application/octet-stream`, `application/wasm`, `application/json`, `text/plain; charset=utf-8`, `text/markdown; charset=utf-8` (unknown MIME types fall back to `application/octet-stream`).
- `text/html` blobs MUST include `Content-Security-Policy: sandbox` (without `allow-same-origin`).
- `POST /artifact/v1/blob` enforces `max-chunk-bytes` (4 MiB) and `:max-chunk-store-bytes` quota (returning HTTP `507` with `:chunk-store-quota-exceeded`).

---

## 5. `BitechoLightNode` v1.1.0 Additive Facade (`bitecho.browser-main`)

- `BitechoLightNode.apiVersion === "1.1.0"` (100% backwards-compatible with all `v1.0.0` methods).
- `getStatus()` includes `pendingOffers`.
- Top-level camelCase methods added: `openChannel`, `openSession`, `acceptOffer`, `approveOffer`, `denyOffer`, `listPendingOffers`, `registerYubiKey`, `recoverYubiKey`, `saveIdentity`, and `getChunkedArtifact(manifestCid, opts)`.

---

## 6. CLI Verbs & Flags (Rule 6 Inventory)

- **Verbs:** `artifact-put-chunked`, `artifact-get-chunked`, `artifact-manifest-verify`
- **Flags:** `--chunk-size`, `--concurrency`, `--resume-dir`, `--grace-epochs`, `--max-bytes`
