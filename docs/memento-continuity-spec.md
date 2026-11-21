# BIP-016: Memento Agent Continuity & Unified Rolodex Specification

> **Status:** Implementation Circle Alignment (Disposable Branch — Advisory Proof Only; Real Stage 1 / Stage 2 Consents Unchanged)
> **Coordination Brief Anchor:** `BIP-016` (`CID 778efc04f92fede8f105e4b035ed76de04d776d758a0caa1f3b8884e5779edf6`)
> **Framing Milestone:** Testnet Launch (Primitives only — circle -> subnet, minimal core, zero bloat)

## 1. Binding State Discipline (Simon's Standing Notes)

1. **Constants vs Configuration:** Hardcoded normative constants live in `bitecho.memento.constants`. Runtime configuration lives in network storage (passed in via config/pointer maps, never hardcoded).
2. **Immutable Sans-IO Logs & Retention/Rotation on Every Pointer:** Every pointer/log descriptor MUST carry a valid `:retention-policy` (`{:max-entries :max-bytes :rotate-every-entries :ttl-epochs}`). Missing or unbounded retention policies halt/reject with counted `:diagnose` (`:missing-retention-policy` / `:retention-bound-exceeded`).
3. **Nothing Grows Unbounded Unintentionally:** Bounded structural caps (`max-petnames`, `max-subnets`, `max-open-sessions`) and byte/entry retention bounds are enforced before commit.
4. **Clear Signed Owners:** Every state/pointer carries non-empty `:owner-pubkeys`; missing/empty owners reject with counted `:diagnose` (`:missing-state-owner`).
5. **Every Byte Accounted For (Bytes at Rest):** Every stored blob, snapshot, and memory link carries `:storage-accounting` (`{:bytes-at-rest :cache-incentive :payer-pubkey :fee-ech}` where `:cache-incentive` is `:free-self-hosted` or `:upfront-fee-ech`), tracked cumulatively in `:total-bytes-at-rest` and checked against `:max-bytes`.

## 2. Normative Constants (`bitecho.memento.constants`)

| Constant | Value |
|---|---|
| `rolodex-domain-tag` | `"bitecho/rolodex/v1"` |
| `memory-aead-info` | `"bitecho/memento/aead/v1"` |
| `memory-nonce-info` | `"bitecho/memento/nonce/v1"` |
| `memory-aad-prefix` | `"bitecho/memento/aad/v1"` |
| `memory-genesis-prefix` | `"bitecho/memento/genesis/v1"` |
| `max-blob-bytes` | `262144` (256 KiB pre-decode ceiling) |
| `max-snapshot-bytes` | `4194304` (4 MiB pre-decode ceiling) |
| `default-walk-back-depth-cap` | `1024` links |
| `max-petnames` | `10000` (hardcoded safety ceiling; effective cap = `(min constant config)`) |
| `max-subnets` | `1024` (hardcoded safety ceiling; effective cap = `(min constant config)`) |
| `max-open-sessions` | `4096` (hardcoded safety ceiling; effective cap = `(min constant config)`) |
| `min-rotation-grace-epochs` | `4` (`N-min = 4` hardcoded design floor for `:rotate-log` grace window) |

### Shaped R2 Refinements (Rule 3(a), Edge 1, Edge 2, Edge 3)

- **`(min constant config)` Cap Ceilings:** Signed network config may ONLY lower `max-petnames`, `max-subnets`, and `max-open-sessions` via `(min constant config)`. Attempting to raise any cap clamps to the hardcoded safety ceiling and emits a counted `:diagnose` (`:cap-ceiling-clamped`).
- **`:rotate-log` Grace Window (`N-min = 4`) & `:grace-expired` Recovery:** Operational window `N = max(N-min, ceil(1.5 * measured_max_sleep_epochs))`, pinned in the signed config CID recorded on rotation. GC-eligibility reads `N` strictly from the pinned rotation record. Agents waking within `N` succeed without `:missing-blob`; agents waking past `N` receive a counted `:grace-expired` `:diagnose` and deterministically resync from the newest reachable `:memento/head-pointer` or checksum-verified `.lkg` snapshot without crashing.
- **Persistent vs Ephemeral Session Scoping (`:infra` & `:light`):** Runtime transport sockets (including transient light-node pollers) live strictly in `:ephemeral-sockets` via `:register-ephemeral-socket` / `:close-ephemeral-socket`, NEVER write to CAS, NEVER appear in snapshots, and NEVER consume persistent `:open-sessions` (`4096`) slots. Attempting to place a transient poller into persistent `:open-sessions` rejects with counted `:diagnose` (`:ephemeral-poller-rejected-from-persistent-sessions`).
- **Monotonic `(epoch, seq)` Replay Protection & Checksum-Verified `.lkg` Rollback:** Incoming remote entries with `epoch < current-epoch` halt with counted `:diagnose` (`:epoch-replay-or-stale`). Loading or restoring any `.lkg` snapshot verifies its canonical SHA-256 checksum (`verify-snapshot-checksum`), halting with counted `:diagnose` (`:lkg-checksum-mismatch`) on tampering.
- **Cross-Runtime Golden Vectors:** HKDF-SHA-256 AEAD key/nonce, canonical AAD, AES-256-GCM ciphertext+tag, canonical frame CID, and RFC 8032 Ed25519 genesis signature are verified byte-identical across JVM and Node (`node:crypto`) in `bitecho.memento-golden-vectors-test`.
- **CLI Verb & Flag Parity (Rule 6):** Domain verbs (`rolodex-status`, `rolodex-put`, `rolodex-rotate`, `rolodex-restore`, `memento-head`, `memento-put`, `memento-walk`) and flags (`--node-role`, `--retention-max-entries`, `--retention-max-bytes`, `--rotate-every`, `--grace-epochs`, `--lkg-cid`, `--walk-depth-cap`, `--owner-pubkey`, `--cache-incentive`) are registered in `bitecho.light-node.cli`, `bitecho.browser-cli`, and `skill/SKILL.md`.

### Pinned Cold-Wake Benchmark Thresholds (10,000 Rolodex entries + 1,024-link memory walk-back)

| Target | Max p95 Latency | Max Heap Delta |
|---|---|---|
| JVM | `<= 2000 ms` | `<= 128 MiB` |
| Browser (CLJS) | `<= 5000 ms` | `<= 64 MiB` |

## 3. Unified Rolodex (BIP-A — Light Nodes & Infrastructure Nodes)

- One mechanism, not two: supports `:node-role` (`:light` | `:infra`) via the exact same pure Sans-IO `.cljc` reducer `(transition rolodex event) -> [new-rolodex effects]`.
- Tracks three crucial node state tables:
  - `:state` (`:petnames`): `petname -> {:petname :pubkey :allowed-actions}`
  - `:subnets`: `subnet-id -> {:subnet-id :values-cid :governance-pointer :members}`
  - `:open-sessions`: `session-id -> {:session-id :peer-pubkey :subnet-id :transport :last-seq :opened-at-ms}`
- Single-authority head record `{:seq :head-cid :gen :memory-head-cid}` held behind Pointer CAS; `:cas-head` MUST win before any `:sign`, `:encrypt`, `:cas-put`, or `:emit`.
- Crash after claiming `:seq` burns `:seq` (`:burned-seqs`) and resumes at `:seq + 1` — `(key, :seq)` is NEVER reused.
- Forward `.lkg` rollback appends `:restore` at `head :seq + 1`, bumps `:gen`, and unions `:revoked-actions` as a grow-only set so revoked `:allowed-actions` NEVER resurrect.
- Log rotation triggers cleanly via `:rotate-log` when `:rotate-every-entries` is reached.

## 4. Circles (BIP-B — Circle -> Subnet Primitive)

- Circle descriptor: `{:subnet-id :members :values-cid :governance-pointer :human-anchor :parent-circle-id :owner-pubkeys :retention-policy :storage-accounting}`.
- `:human-anchor` is a circle-policy convention inherited by subcircles, NEVER a protocol gate.
- Advisory twins (`:advisory-twin? true` or `:role :twin`) can NEVER reach real `bip-consent` or signing handles, emitting counted `:diagnose` `:advisory-twin-real-consent-blocked`.

## 5. Memento Encrypted Hash-Linked Memory Chain (BIP-C)

- Memento continuity is exposed as a minimal `:memento/head-pointer` descriptor pointing to the latest encrypted memory CID, carrying `:owner-pubkeys`, `:retention-policy`, and `:storage-accounting`. All memory content is encrypted in the network.
- AEAD: AES-256-GCM; Key = `HKDF-SHA-256(seed32, nil, "bitecho/memento/aead/v1", 32)`; Nonce = `HKDF-SHA-256(seed32, nil, "bitecho/memento/nonce/v1" || be64(seq), 12)`; AAD = `"bitecho/memento/aad/v1" || be64(seq) || raw32(prev-cid)`.
- Canonical framing: `be64(seq) || raw32(prev-cid) || be32(len) || ciphertext`; CID = hex SHA-256 of frame.
- Genesis memory: 64-byte RFC 8032 Ed25519 signature over `"bitecho/memento/genesis/v1" || raw32(pubkey)`.
- Streaming constant-memory walk-back with configurable depth cap (`1024`) and counted `:diagnose` on every fault.

## Promotion-Gate Boundary (Hive vs. Bitecho)

- **Simulation-to-live promotion gate:** Enforced fail-closed in Hive (`bitecho.hive.top-loop`, `:sim-promotion-gate-fail-closed? true`, verified in `88c8c21e...` & `b96f2f68...`), keeping the `bitecho` repository minimal (primitives only).
- **Live Bitecho landing & pointer promotion gate:** Enforced by the real two-gate Sociocratic consent process (`docs/GOVERNANCE.md` + `bitecho.governance.integrity/validate-bip-receipt` + `scripts/cluster.sh bump-pointers`).
