# Bitecho Light-Node Protocol & Gateway Specification (`docs/SPEC.md`)

## 1. HTTP Relay Gateway (`/relay/v1/*`) Contract

The Bitecho HTTP Relay Gateway provides an asymmetric, zero-burn, air-gappable transport bridge for light nodes and web clients unable to maintain direct DataChannel UDP/TCP mesh connections.

### 1.1 Bridge Modes: `:relay-validator-bridge?`

Relay server instances operate in one of two distinct modes:

- **Standalone Zero-Burn Gateway (`:relay-validator-bridge? false`):**
  - Serves as an ephemeral message and broadcast broker between peers without touching consensus or validator state.
  - Zero token burn requirements; all messages and offers route via internal inboxes.
- **Validator Bridge (`:relay-validator-bridge? true`):**
  - Acts as a full bridge connected to the validator cluster mesh.
  - Bridges incoming gossip envelopes to cluster validators and forwards validator-signed responses (such as `:chain-state-snapshot`) back into target account inboxes.

### 1.2 Endpoints

All relay endpoints enforce UTF-8 JSON payloads and canonical Ed25519 signature checks.

#### `POST /relay/v1/poll`
Polls for queued messages addressed to `pubkey` and public broadcast envelopes.
- **Request:**
  ```json
  {
    "pubkey": "<64-or-88-char-hex-pubkey>",
    "since_seq": 0,
    "since_broadcast_seq": 0,
    "timestamp_ms": 1794510041000,
    "nonce": "poll-0-<hex>-1794510041000",
    "signature": "<128-char-hex-signature>"
  }
  ```
  *Canonical string for signature:* `(str "bitecho-relay-poll-v1|" pubkey "|" since-seq "|" timestamp-ms "|" nonce)`
- **Response:**
  ```json
  {
    "ok": true,
    "messages": [
      {
        "relay_seq": 1,
        "envelope_hex": "<hex>",
        "timestamp_ms": 1794510042000
      }
    ],
    "broadcasts": [
      {
        "broadcast_seq": 1,
        "envelope_hex": "<hex>",
        "timestamp_ms": 1794510042000
      }
    ]
  }
  ```

#### `POST /relay/v1/send`
Submits an envelope for forwarding to target inboxes or network broadcast.
- **Request:**
  ```json
  {
    "envelope_hex": "<hex>"
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "relay_seq": 1
  }
  ```
  *Note:* Submissions carrying valid validator-signed `:chain-state-snapshot` envelopes (`:validator-pubkey` and `:signature`) are verified via canonical snapshot signing payloads and routed directly into the queried account's inbox.
  *Intra-Ring Replication (F-P0-1):* Intra-cluster peer forwarding includes headers `X-Bitecho-Relay-Replicated: true` and `X-Bitecho-Relay-Auth: <hmac-sha256(secret, path + ":" + body)>`. Requests claiming replication without valid HMAC are rejected with 403 Forbidden.

#### `POST /relay/v1/ack`
Acknowledges receipt of polled envelopes, allowing the gateway to garbage collect delivered items.
- **Request:**
  ```json
  {
    "pubkey": "<hex>",
    "ack_seq": 1,
    "ack_broadcast_seq": 1,
    "timestamp_ms": 1794510043000,
    "nonce": "ack-1-<hex>-1794510043000",
    "signature": "<hex>"
  }
  ```
  *Canonical string for signature:* `(str "bitecho-relay-poll-v1|" pubkey "|" ack-seq "|" timestamp-ms "|" nonce)`
- **Response:**
  ```json
  {
    "ok": true
  }
  ```

#### `POST /relay/v1/chain-state`
Queries validator quorum for an account's authenticated chain state snapshot.
- **Request:**
  ```json
  {
    "pubkey": "<hex>"
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "pubkey": "<hex>",
    "snapshots": [
      {
        "type": "chain-state-snapshot",
        "validator_pubkey": "<hex>",
        "pubkey": "<hex>",
        "finalized_epoch": 42,
        "balance": 1000000,
        "spendable": 1000000,
        "seq": 5,
        "deps": [],
        "escrows": [],
        "nonce": "<string>",
        "signature": "<128-hex-signature>"
      }
    ],
    "min_signaling_burn": 100,
    "bootstrap": "bitecho.org"
  }
  ```
  *Canonical string for snapshot signature:* `(str "bitecho-chain-state-snapshot-v1|" validator-pubkey "|" pubkey "|" finalized-epoch "|" balance "|" spendable "|" seq "|" comma-joined-deps "|" canonical-escrows-str "|" nonce)`

#### `GET /healthz`
Liveness probe returning HTTP 200 `{"ok": true}`.

---

## 2. Chunked Envelope Transport Format

For ultra-reliable manual cut-and-paste or air-gapped terminal transfer, envelope hex payloads are formatted in numbered, fixed-width chunks with cryptographic integrity tags:

```text
L01 [200c sha=89abcdef]: <200 hex chars>
L02 [200c sha=12345678]: <200 hex chars>
L03 [48c sha=abcdef01]: <remaining 48 hex chars>
```

### Parsing Rules:
1. **Line Normalization:** Pure parser `strip-chunk-prefixes` strips line prefix labels (`L01`, `L02`), length tags (`[200c sha=...]`), whitespace, and trailing newlines.
2. **Integrity Prefix:** The 8-character `sha=` parameter represents the first 8 hex characters of the SHA-256 digest of the chunk's payload, enabling visual confirmation of line integrity.
3. **Payload Extraction:** `parse-poll-payloads` handles raw JSON envelopes, individual hex lines, chunked hex strings, and signed `:chain-state-snapshot` maps interchangeably.

---

## 3. Light-Node Control Daemon Interface (`ctl`)

When running in daemon mode (`serve`), light nodes expose a local loopback-only control interface for IPC and operator automation.

### 3.1 Control Metadata & Security
- **File Location:** `<state-dir>/control.json`
- **File Permissions:** `0600` (`-rw-------`, POSIX compliant)
- **Contents:**
  ```json
  {
    "port": 5020,
    "token": "32-byte-hex-random-token",
    "pid": 12345
  }
  ```
- **Binding:** Strictly loopback `127.0.0.1`.
- **Authentication:** All requests must include `Authorization: Bearer <token>`.
- **Lifecycle:** On graceful shutdown or signal termination (SIGINT, SIGTERM), the socket is closed and `<state-dir>/control.json` is atomically unlinked.

### 3.2 Command Dispatch (`POST /ctl`)
Any valid light-node command map or raw CLI `argv` array may be sent to `/ctl`:
```json
{
  "cmd": "send",
  "to": "alice",
  "text": "Hello, world!"
}
```
or:
```json
{
  "argv": ["broadcast", "--subnet-id", "homebrew-cafe", "--text", "Hello subnet!", "--burn", "100"]
}
```
When `<state-dir>/control.json` exists and is reachable, one-shot `clojure -M:light-node <verb> ...` invocations automatically delegate execution to the running `serve` daemon over `POST /ctl` to preserve Single-Authority Shell Lifecycle State (`Rule 4`). Gossip-emitting commands (`broadcast`, `storage-put`, `capability-publish`) accept `--burn <ech>` to attach anti-spam burn fees and route across all validators via outer `:subnet-id "*"`, while `inbox` accepts `--subnet-id <id>` to filter and drain both direct messages and subnet broadcasts.

### 3.3 Event Notification Long-Polling (`cmd: "wait"`)
The `wait` command provides zero-latency notification of asynchronous network events:
```json
{
  "cmd": "wait",
  "timeout_ms": 10000
}
```
If actionable events (`message-received`, `offer-received`, `channel-opened`, `p2p-connected`, `p2p-disconnected`, `diagnostic`, `storage-replicated`, `capability-published`) are buffered in `:event-queue`, they are drained and returned immediately. If the queue is empty, the daemon holds the HTTP connection open until an event is enqueued or `timeout_ms` expires.

---

## 4. Content-Addressed `sci` Smart Contracts, Fractal E2EE Storage, & Capability Descriptors

For detailed specifications and cross-runtime CLI/JSONL/Browser usage of Bitecho's programmable settlement, encrypted storage, and capability economy primitives, see:

- **[`docs/SMART_CONTRACTS.md`](SMART_CONTRACTS.md)**: ChiaLisp-style content-addressed `sci` smart contracts (`bitecho.economy.puzzle`), sandbox determinism & fuel metering, condition outputs (`:release`, `:refund`, `:refund-remainder`, `:assert-epoch-gte`, `:assert-epoch-lte`, `:assert-sig`, `:assert-sha256`), and `puzzle-hash` / `puzzle-eval` / `lock-intent` / `release-intent`.
- **[`docs/STORAGE.md`](STORAGE.md)**: Built-in Fractal E2EE Storage (`bitecho.core.storage`) over `Blob` + `Pointer` + `Subnet`, domain-separated XSalsa20-Poly1305 encryption (`derive-storage-key`), anti-rollback sequence guards, and `storage-put` / `storage-get` / `storage-list`.
- **[`docs/CAPABILITIES.md`](CAPABILITIES.md)**: Generic Fractal Capability Descriptors (`bitecho.core.storage`) for `:storage/blob-pinning`, `:compute/uop-kernel`, `:compute/gpu-access`, `:model/weights`, `:network/turn-relay`, and `:network/gateway`, plus `capability-publish` / `capability-resolve` / `capability-list`.

---

## 5. Autonomous Development & Tri-Circle Sociocratic Governance Protocol (`bitecho.governance.core`)

Bitecho implements a pure Sans-IO 4-layer autonomous protocol evolution and governance state machine in [`src/bitecho/governance/core.cljc`](../src/bitecho/governance/core.cljc):

1. **Layer 1 — Permissionless Fractal Lab Subnets & RFC 6962 Binary Merkle Anchoring (`register-lab-subnet`, `compute-rfc6962-merkle-root`, `anchor-subnet-merkle-root`):**
   - Registers child lab subnets with custom `:min-signaling-burn`, `:admission-gate` (`:permissionless`, `:dac-attested`, `:stake-gated`), `:capability-schemas`, and `:settlement-take-bps`.
   - Computes domain-separated RFC 6962 binary Merkle roots (`SHA-256(0x00 || leaf)` for leaves and `SHA-256(0x01 || left || right)` for internal nodes) to anchor child subnet state into `"global"`.
2. **Layer 2 — Fractal Subnet Executable BIPs (`verify-bip-admission-gates`, `submit-bip`, `get-bip`):**
   - Enforces `"No Proposal Without a Property & Seed"` (`INV-D20-1`): a BIP is rejected with counted `:bip-admission-rejected` diagnostics unless it provides all 4 `:invariant-diff` fields (`:defspec-vars`, `:sans-io-pure?`, `:diagnose-coverage?`, `:co-committed-spec-and-flags?`) and all 4 `:oracle-receipts` (`:four-way-golden-oracle`, `:vopr-jepsen-non-vacuity`, `:deterministic-bundle-sha256`, `:bwrap-civilization-regression`).
   - Admitted BIPs are scoped per fractal subnet under `[:bips [subnet-id bip-id]]`, stored as content-addressed Fressian `Blob`s, and referenced by authority-signed `Pointer`s (`bip/<bip-id>`) in `subnet-id` (`INV-D22-1`).
3. **Layer 3 — Capability-Backed Bilateral Builder/Auditor Bounties (`calculate-bounty-split`, `create-bounty-escrow`, `settle-bounty-escrow`, `get-bounty`):**
   - Enforces exact zero-dust integer conservation (`builder-net + auditor-net + protocol-take == gross-amount`) for all $A \ge 1$.
   - Automatically packs and publishes a signed `:governance/bounty` marketplace capability descriptor (`bounty/<bounty-id>`) in `[:capabilities [subnet-id "bounty/<bounty-id>"]]` (`INV-D22-2`).
   - Requires pairwise-distinct Ed25519 signatures from a **Builder**, a **Cross-Model AI Auditor** (attesting `:tests-passed? true`, `:lint-clean? true`, and matching `:reproducible-sha256`), and a **Human Anchor Maintainer**; any signer collision fails closed with `:sybil-bounty-claim-rejected`.
4. **Layer 4 — Fractal Tri-Circle Sociocratic Consent, Reproducible Counterexample Gate, & Deterministic Epoch Activation (`register-circle-member`, `submit-circle-response`, `evaluate-tri-circle-consent`, `activate-epoch-upgrades`):**
   - Evaluates consent per subnet (`[subnet-id circle-id]`) across `:builders-stewards` (`:verified-commits`), `:mesh-validators` (`attestation/calculate-node-weight`), and `:anchor-agent-users` (`:trailing-burned-ech`).
   - Unsubstantiated objections (missing or invalid `:counterexample`) emit counted `:unsubstantiated-objection-ignored` diagnostics and never block ratification.
   - Valid reproducible counterexamples (`:vopr-seed`, `:monte-carlo-insolvency`, `:security-regression`) transition the BIP to `:blocked-by-paramount-objection` and append a deterministic regression test vector to `[:subnet-regression-vectors subnet-id]` and `:regression-vectors`.
   - Ratified BIPs specifying `:policy-theta` and `:activate-at-epoch` are queued in `[:scheduled-upgrades [subnet-id activate-at-epoch]]` and deterministically activated at epoch boundary $E_{\text{act}}$ via `activate-epoch-upgrades` (`INV-D22-4`).
5. **First-Class Light-Node CLI & Wire Verbs (`INV-D22-3`):**
   - All 63 light-node CLI verbs (including `bip-submit`, `bip-consent`, `bip-object`, `bip-status`, `bounty-create`, `bounty-settle`, `subscribe-subnets`, `help`, and `offer --wait-open-ms`) and 51 canonical flags execute across JVM, Node.js, and Browser runtimes and replicate governance state over signed `:governance-replicate` Fressian gossip envelopes.

---

## 6. Network URI Separation, Cross-Network Replay Protection, & Canary Release Process (`RELEASE.md`)

1. **Canonical Network URIs & Root Subnet Equivalence (`bitecho.config`):**
   - Bitecho defines three canonical root network URIs: `:devnet` -> `"devnet.bitecho.org"`, `:testnet` -> `"testnet.bitecho.org"`, and `:mainnet` -> `"mainnet.bitecho.org"`.
   - Each network URI is a valid root `:subnet/id` (`root-subnet-id?`) that validates in `bitecho.core.subnet/validate-subnet-policy` without requiring `:subnet/parent-id`.
   - During rolling `N` / `N+1` upgrades, `equivalent-subnet-id?` treats legacy `"global"` as equivalent to the active network's root URI while strictly isolating `"devnet.bitecho.org"`, `"testnet.bitecho.org"`, and `"mainnet.bitecho.org"` from one another.
2. **Cryptographic Cross-Network Replay Protection (`bitecho.economy.account`, `bitecho.economy.escrow`, `bitecho.state-machine`, `bitecho.light-node.core`):**
   - `Transfer` signatures bind `:network-uri`, and `escrow/compute-escrow-id` (8-arity) binds `network-uri` into `bitecho-escrow-id-v1`.
   - Validators and light nodes reject foreign-network transfers and escrow intents fail-closed, incrementing `[:diagnostics :network-replay-rejected]` and emitting a `:diagnose` effect (`Rule 5`).
   - Mainnet (`config/mainnet-config`) enforces `:strict-network-uri? true` (rejecting unscoped transfers) and `mesh/validate-node-config` rejects hot `:custody-privkey` on Mainnet (`A-D23-4`).
3. **Formal Release Runbook & Canary Rolling Deploy ([`RELEASE.md`](../RELEASE.md)):**
   - Defines the 6-gate pre-release verification pipeline, deterministic artifact SHA-256 attestation, canary rolling order (`ns3` -> `node3` -> E2E gate -> `ns2` -> `ns1` -> `node2` -> `node1`), and `./scripts/cluster.sh rollback`.

---

## 7. P2P Single-Responder Contract & Hook Newline Discipline

### 7.1 Single-Responder Contract (`bitecho.light-node.core`)
To avoid dual-dial race conditions, ICE candidate collisions, and asymmetric state splits when establishing direct P2P connections:
1. **Deterministic Single-Responder Rule:** When two peers exchange WebRTC signaling offers and answers, only the designated responder (the peer with deterministic lower pubkey or callee) establishes the active connection; stale or concurrent cross-offers are ignored with counted diagnostics (`:p2p-offer-answered-while-open`).
2. **Candidate Fallback (`INV-D24-1`):** In symmetric NAT environments or local proxy scenarios where filtered remote candidates match local candidate addresses, the node automatically falls back to raw remote candidates and increments `[:diagnostics :p2p-answer-candidate-self-filter-fallback]`.
3. **Signaling Metadata Persistence (`Rule 4`):** Derived runtime connection liveness (`:p2p` containing `:phase`, `:connected?`, `:error`) is stripped prior to disk or browser storage persistence. Immutable remote signaling credentials (`:p2p-meta` containing `:remote-candidates`, `:remote-ice-ufrag`, `:remote-fingerprint`, `:remote-transport`, `:preferred-transport`, `:preferred-candidates`) are persisted and restored across node restarts.

### 7.2 Hook Newline Discipline & Control Concurrency
1. **Streaming JSONL Discipline:** Streaming CLI commands, subagent inputs, or stdin pipelines (`--cmd-file` or stdin pipe) must strictly maintain single-line JSON (`\n`) formatting. If adjacent, un-delimited JSON commands arrive (e.g. `}{`), `cli/split-jsonl-commands` parses and splits valid JSON objects without dropping envelopes or throwing syntax errors.
2. **Control Socket Concurrency:** All `/ctl` command executions are serialized through a single reentrant mutex (`serve-cmd-lock` / sequential dispatch) to prevent concurrent command races and state corruption across multiple subagents.

---

## 8. Milestone D25: Stateless One-Shot Continuity, Peek Semantics, Subnet Filtering, & UPnP

### 8.1 Stateless One-Shot Offer Handshake Continuity (`A-D25-1`, `A-D25-2`, `A-CARB-D25-1`, `F-D25-4`)
1. **Deterministic X25519 Seed Keypair Derivation:** `sealed/x25519-keypair-from-seed` derives SPKI/PKCS#8 keypairs cross-runtime (JVM, Node.js, Browser) identically from RFC 7748 scalar multiplication.
2. **Domain-Separated HKDF Nonce Recovery:** `exec-offer` generates 32-byte `:offer-nonce` and derives the ephemeral keypair using HKDF with info string `"bitecho-offer-x25519-v1|<caller>|<callee>"`.
3. **Restricted Nonce Lifetime (`A-CARB-D25-1`):** `:offer-nonce` is preserved across persistence while session state is `"offered"`, allowing one-shot nodes to resume and complete handshakes across process boundaries. Once the handshake transitions to `"open"` or `"closed"`, `:offer-nonce` is strictly stripped alongside `:ephemeral-priv`.

### 8.2 Non-Destructive Peek Reads & Subnet Filtering (`F-D25-5`, `F-D25-6`, `F-D25-7`, `F-D25-9`)
1. **`inbox --peek` Semantics:** When `--peek` is passed, `inbox` returns messages non-destructively without draining `:inbox` or `:broadcast-inbox`, without writing state to disk, and without acknowledging relay envelopes.
2. **Subnet-Filtered Relay Polling:** Gateway relay `/relay/v1/poll` filters broadcasts by `:subnets` while advancing `:last_broadcast_seq` monotonically.
3. **Subnet Subscriptions:** Default subscribed subnets include `"chat/simon-nexus-axiom"`. `subscribe-subnets` CLI verb dynamically registers additional subnet filters.
4. **Dual Key Broadcast Normalization:** Incoming broadcasts normalize dual snake/kebab keys (`:msg-id`, `:msg_id`, `"msg_id"`, `:subnet-id`, `:subnet_id`, `"subnet_id"`).

### 8.3 UPnP IGD Port-Mapping Renewal Loop (`F-D25-10`)
1. **Background Lease Renewal:** `upnp/start-upnp-renewal-loop!` starts a daemon thread periodically renewing router port mappings for `:ingress-tcp-port` and `:agent-port`.
2. **SSDP Gateway Re-Discovery & Fail-Closed Diagnostics:** If gateway mapping fails or times out, the renewal loop attempts re-discovery and emits counted `:diagnose` effects per Rule 5. Clean termination via `upnp/stop-upnp-renewal-loop!` is wired into node shutdown.

---

## 9. Milestone D26: BIP-000 Charter, Parallel Track Foundation, & Remediation (`v0.23.4`)

### 9.1 Network-Bound Offer Hashes & Rolling Upgrade Interop (`F-D26-3`, `F-D26-7`, `A-D26-1`, `A-CARB-D26-3`)
1. **5-Field Network Binding:** `compute-offer-hash` binds canonical `:network-uri` into the SHA-256 preimage format:
   `sha256(session-id|caller|callee|epoch|burn|net:<network-uri>)`.
2. **Rolling Upgrade Sunset (`config/legacy-unbound-offer-hash-sunset`):** `matching-offer-hash?` accepts legacy 4-field unbound hashes on non-Mainnet networks through `2026-12-31`. Mainnet rejects unbound hashes unconditionally.

### 9.2 BIP-000 Charter Ratification & Strict Admission Guard (`F-D26-6`, `F-D26-10`, `A-D26-3`, `A-CARB-D26-4`)
1. **BIP-000 Charter:** Ratified in `docs/bips/bip-000-charter.edn` with complete `:invariant-diff`, `:oracle-receipts`, `:jurisdiction-map`, `:decision-records`, and `:human-anchor-sunset "2027-06-30"`.
2. **Strict Admission Guard:** `exec-bip-submit` rejects proposals with fabricated/empty admission defaults when `strict_admission` is true or proposal is `"BIP-000"`, incrementing `[:diagnostics :bip-admission-rejected]`.

### 9.3 Budget Floor Pre-Transition Guard & Monotonic Broadcast Filtering (`F-D26-8`, `F-D26-13`, `A-D26-4`, `A-D26-5`)
1. **Pre-Transition Budget Floor Guard (`--min-balance`):** Pure core reducer rejects burn-bearing commands (`"send"`, `"broadcast"`, `"offer"`, `"rendezvous-offer"`, `"transfer"`) before mutating state if `spendable - required-burn < min-balance`, incrementing `[:diagnostics :below-min-balance-rejected]` and emitting `{"event" "budget-floor-reached"}`.
2. **Monotonic Broadcast Filtering (`--min-broadcast-seq`):** `wait-event` and `poll` filter incoming broadcasts to return only items strictly `>= min-broadcast-seq`.

### 9.4 Multi-Cluster Network Profiles & Standalone SEA Packaging (`F-D26-11`, `F-D26-12`, `A-CARB-D26-5`, `A-CARB-D26-6`)
1. **Multi-Cluster Profiles:** Formalized in `ops/networks/{devnet,testnet,mainnet}.env` containing `NETWORK_URI`, `GCP_PROJECT`, `BOOTSTRAP_FILE`, and `TREASURY_PUBKEY`.
2. **Release Proof Deploy Gate:** `verify_release_proof_gate` in `cluster.sh` and `infra_cluster.sh` asserts verified `docs/releases/v${VERSION}-proof.edn` before remote deployment.
3. **Single Executable Application (SEA):** `scripts/build-sea.sh` injects code cache and deterministic blobs into standalone node binary without experimental warnings.

### 9.5 Treasury Faucet & Network Directory Service (`F-D26-2`, `F-D26-9`)
1. **Pure Faucet Reducer (`bitecho.core.protocol.faucet`):** Cryptographic challenge-response faucet with 60-second TTL, network-uri scoping, and single-use claim tracking.
2. **Multi-Network Directory Endpoints:** Ingress HTTP shells support `/directory/v1/<network-uri>/<nickname>` alongside legacy fallbacks.

---

## 10. Milestone D30: BIP-004 On-Network Artifact Publishing, First-Match Path-ACL, & P2P Relay Remediation (`v0.23.8`)

### 10.1 First-Match `:subnet/path-acl` Stream Isolation & Hard-`404` Revocation (`BIP-004 §§B.2-B.4`)
1. **First-Match Path-ACL Ordering:** In `infra/default-infra-policy`, specific stream patterns (`"subnet/policy"`, `"dist/*"`, `"releases/*"`, `"pkg/*"`, `"web/SKILL.md"`, `"web/ONBOARDING.md"`, `"web/llms.txt"`, `"web/references/*"`, `"web/agents/*"`, `"web/blog/*"`, `"blog/*"`) strictly precede the catch-all `"web/*"` rule so Tier-1 stream maintainers (`K_nexus`, `K_axiom`, `K_lumen`) can publish to their delegated paths without granting authority over `"web/index.html"` or `"dist/*"`.
2. **Hard-`404` Tombstones & `:subnet/denied-cids`:** `infra/resolve-path-blob!` checks whether a path is tombstoned (`:pointer/target nil`) or whether its target CID is listed in `:subnet/denied-cids`, returning `{:ok? false :denied? true}` and blocking fallback to disk `dist/` or `content-root`.

### 10.2 Pointer-First `serve-dist-request`, Dynamic `.sha256` Synthesis, & `/artifact/v1/*` Bridge (`BIP-004 §§C-D`)
1. **Pointer-First `/dist/*` Resolution:** `http/serve-dist-request` resolves `"dist/<rel-path>"` via `infra/resolve-path-blob!` before any disk fallback, serving `X-Bitecho-Blob-Cid`, `X-Bitecho-Pointer-Pubkey`, `X-Bitecho-Pointer-Seq`, `X-Bitecho-Pointer-Signature`, `ETag`, and `Range` (`206 Partial Content`) headers.
2. **Dynamic `.sha256` Synthesis:** Requests for `/dist/<name>.sha256` resolve `"dist/<name>"` in `rt` and dynamically synthesize `<cid>  <name>\n` when an active pointer exists (or return `404` if tombstoned/denied).
3. **HTTP Artifact Bridge (`/artifact/v1/{blob,pointer,list}`):** Ingress HTTP shells expose `POST /artifact/v1/blob`, `POST /artifact/v1/pointer`, and `GET /artifact/v1/list`, and ingest `:artifact-replicate` / `:replicate-pointer` envelopes arriving via `/relay/v1/send` or the validator bridge.
4. **Light-Node Artifact Verbs:** `artifact-put`, `artifact-get`, `artifact-list`, and `artifact-revoke` are supported across CLI, `serve`, `ctl`, and one-shot modes (`--subnet-id`, `--path`, `--file`, `--text`, `--hex`, `--seq`, `--burn`, `--relay-url`, `--authority`, `--prefix`).

### 10.3 Shared Relay Candidate Preservation & Shuttle Broadcast Forwarding (`BIP-004 §E`)
1. **Shared Relay Candidate Preservation:** `filter-p2p-remote-candidates` in `exec-p2p-answer`, `handle-wire-p2p-offer`, and `handle-wire-p2p-answer` never strips shared `https://` or `http://` relay URLs during self-filtering, and falls back to raw remote candidates with counted `:p2p-answer-candidate-self-filter-fallback` / `:p2p-offer-candidate-self-filter-fallback` diagnostics when non-relay candidates self-filter to empty.
2. **Shuttle Import Live Forwarding:** In `handle-serve-line!`, import shuttle verbs (`import-poll`, `import`, `import-envelope`) forward generated hub-relay/gossip envelopes immediately when validator or P2P links are live, or increment `[:diagnostics :shuttle-import-forward-deferred]` and return `"pending_forward_count"` when offline.

---

## 11. Milestone D31: BIP-005 Unification III (`v0.23.9`)

### 11.1 Live-Test Bugfixes (`F-D31-BUG-1..3`) & Dead-Code Purge
1. **Closure `:advanced` Pure Ed25519 Direct Calls (`F-D31-BUG-1`):** `bitecho.crypto` calls `(ed-sha512 ...)`, `(ed-public-key ...)`, `(ed-sign ...)`, and `(ed-verify ...)` directly without JS dot-property access, and `exec-artifact-put`, `exec-artifact-revoke`, `exec-bip-submit`, and `exec-bounty-settle` lazily evaluate `fallback-kp` only `(when-not privkey-bytes ...)`.
2. **Strict `:p2p-broadcast` Subnet Filtering (`F-D31-BUG-2` / `F-D29-21`):** Default `"global"` and `"devnet.bitecho.org"` light nodes drop unsubscribed `:p2p-broadcast` envelopes with counted `:subnet-mismatch-dropped` diagnostics.
3. **Persisted Snapshot Policy Upgrade Merge (`F-D31-BUG-3`):** `infra/merge-upgraded-policy` merges newly added `:subnet/path-acl` patterns and upgraded `:signers` sets from `default-infra-policy` into persisted `subnet-pointers.fressian` snapshots on runtime startup.

### 11.2 Pure Foundations, `68 -> 12` Canonical CLI Desugaring, `:sync-pointer`, & 3-of-3 Bounty Puzzle (`F-U1..F-U7`)
1. **Pure Foundations (`bitecho.core.window`, `bitecho.core.lifecycle`, Unified RFC 6962 Merkle):** Shared bounded FIFO, byte-LRU, and 64-bit replay bitmask windows in `bitecho.core.window`; shared Rule 4/5 generation-fenced lifecycle reducer in `bitecho.core.lifecycle`; single RFC 6962 Merkle tree implementation in `bitecho.core.data`.
2. **`68 -> 12` Canonical CLI Verb Desugaring (`F-U1`, `F-U2`):** `bitecho.light-node.cli` defines the 12 canonical verbs (`put`, `get`, `list`, `transfer`, `lock`, `spend`, `connect`, `send`, `inbox`, `wait`, `serve`, `ctl`) and desugars all 68 legacy verbs and 8 runner aliases while preserving `--burn` anti-Sybil burn deduction and `outer-subnet = "*"` global propagation.
3. **Unified `:sync-pointer` & `.v0238.bak` State Migration (`F-U4`, `F-U5`):** Light nodes ingest `:sync-pointer` alongside N-1 legacy `*-replicate` frames, project all domain pointers/blobs into `:pointers` and `:blobs`, and automatically create `<state-dir>/state.fressian.v0238.bak` before migrating `v0.23.8` snapshots.
4. **Canonical 3-of-3 Bounty SCI Puzzle:** `bitecho.economy.puzzle/canonical-bounty-puzzle-source` enforces pairwise-distinct 3-of-3 (`maintainer`, `builder`, `auditor`) Ed25519 signatures, exact zero-dust `85/15` net-pool split + protocol take, and post-timeout maintainer refund.

---

## 12. Milestone D32: BIP-006 Core Network Reliability, `bitecho-mcp`, Browser App Refresh & Hardware-Key Faucet (`v0.23.10`)

### 12.1 Core Network & Artifact Reliability (`Part 0`: `D-LEG-1..3`, `F-SYNC-1`, `F-RELAY-1`, `F-ART-1..2`)
1. **Shared HTTP Relay Candidate Preservation & Import-Poll P2P Dialing (`D-LEG-1a`, `D-LEG-1c`):** `handle-wire-p2p-offer` and `exec-p2p-answer` filter out unconfigured `connect://` candidates and preserve shared `https://.../relay/v1` candidates whenever local fallback candidates are private RFC1918/mDNS addresses (`private-or-mdns-candidate?`). Burned `:p2p-offer` and `:p2p-answer` envelopes use wildcard outer gossip `:subnet-id "*"` so signaling routes across all validators. `exec-import-poll` and `exec-import` preserve `:p2p-dial` and `:p2p-dials` so HTTP-relay-polled signaling triggers `dial-p2p-peer!`.
2. **Authenticated HTTPS Proxy CONNECT Tunnel (`D-LEG-1b`):** `open-https-proxy-tls-socket!` in `bitecho.node-main` sends `Proxy-Authorization: Basic ...` when proxy credentials are present and attaches `"error"` and `"secureConnect"` listeners on the upgraded TLS socket.
3. **Half-Open Outbox Eviction Auto-Down & Wildcard `:session-ack` (`D-LEG-2`):** When `retransmit-unacked-outbox` evicts an unacked message (`retries >= 5`) while `[:p2p :connected?]` is `true`, it transitions the P2P leg to `:closed` (`:connected? false`, `:error "ack-timeout"`, `[:p2p-meta :reconnect-needed?] true`) and emits an actionable `"p2p-disconnected"` event. Burned `:session-ack` envelopes use outer gossip `:subnet-id "*"`.
4. **Expanded Actionable Wait Event Queue (`D-LEG-3`):** `actionable-event-types` includes `"p2p-offer-received"`, `"p2p-answer-received"`, `"p2p-offer-answered-while-open"`, `"artifact-replicated"`, `"artifact-revoked"`, `"governance-replicated"`, `"broadcast-received"`, and `"transfer-received"`.
5. **Co-Located Validator Quorum Snapshot & Dual UDP + HTTP Relay Bridge (`F-SYNC-1`, `F-RELAY-1`):** `infra/fetch-validator-chain-state-snapshots!` builds the co-located `:validator-node` snapshot in-memory (`< 5ms`) and queries remote validators with a `1500ms` timeout. `http/start-http-server!` `default-forwarder` injects relay envelopes directly into the co-located validator's `:network-in` channel and forwards to connected agents via `mesh/forward-gossip-to-agents!`. `parse-bootstrap-descriptor-pure` defaults `:relay-url` to `"https://ns1.bitecho.org"` when `Domain: bitecho.org`, and `run-serve!` runs background HTTP relay polling alongside UDP.
6. **Idempotent Duplicate Replication, Default Burn, & `get --cid` (`F-ART-1`, `F-ART-2`):** Duplicate `:artifact-replicate`, `:storage-replicate`, `:capability-replicate`, and `:sync-pointer` envelopes with identical `(authority, seq, target)` are idempotent no-ops. `artifact-put` and `artifact-revoke` default `burn` to `(max 100 (effective-signaling-burn-floor state))` when economy is enabled. `get --cid <cid>` resolves blobs directly by content-addressed SHA-256 CID.

### 12.2 Zero-Install `bitecho-mcp` Stdio JSON-RPC 2.0 Server (`Part 1`, `bitecho.light-node.mcp`)
1. **Pure Sans-IO MCP Reducer:** `bitecho.light-node.mcp/handle-jsonrpc-request` implements JSON-RPC 2.0 (`"initialize"`, `"ping"`, `"notifications/initialized"`, `"tools/list"`, `"tools/call"`) in pure `.cljc`.
2. **Curated 8 + 1 Tool Surface:** Exposes `bitecho_identity`, `bitecho_discover`, `bitecho_connect`, `bitecho_send`, `bitecho_inbox`, `bitecho_wait`, `bitecho_storage`, `bitecho_escrow`, and `bitecho_ctl`, invoked via `--mcp` or `mcp` CLI mode on both JVM and Node.js shells.

### 12.3 Browser Light-Node App Refresh & Hardware-Key Sponsored Faucet (`Part 2` & `Part 3`)
1. **Browser Sociocratic Governance & Broadcast (`bitecho.browser-main`, `resources/public/index.html`):** Exposes `submitBip`, `consentBip`, `objectBip`, `getBipStatus`, `broadcastMessage`, and `claimHardwareKeyFaucet` on `globalThis.BitechoBrowser` with corresponding dashboard UI controls.
2. **Hardware-Key Sponsored Faucet Receipts (`bitecho.core.protocol.faucet`, `bitecho.shell.http`):** `faucet/reduce-faucet-claim` issues a single `1,000,000 ECH` drip per attested hardware credential ID, producing a signed transfer and signed fractal `Blob`/`Pointer` receipt at `faucet/<network-uri>/claims/<credential-id-hash>`.

---

## 13. Milestone D33: BIP-007 Low-Latency Quorum Sync, Zero-Burn HTTPS Relay Legs & Cluster Operations Hardening (`v0.23.11`)

### 13.1 Sub-25ms Zero-UDP `/relay/v1/chain-state` & Light-Node Quorum Sync (`P-NET-1`)
1. **Fast Local-Only Snapshot Endpoint (`/relay/v1/chain-state?local_only=true`):** `http/handle-relay-chain-state` supports `local_only=true`, returning the co-located validator's signed snapshot in `< 5ms` without dialing remote UDP `:5010`.
2. **Parallel HTTP Peer Snapshot Aggregation (`infra/fetch-validator-chain-state-snapshots!`):** Infra nodes query peer `http://<peer-ip>/relay/v1/chain-state?pubkey=<pk>&nonce=<n>&local_only=true` endpoints in parallel (`1200ms` timeout) and verify each validator's Ed25519 signature before falling back to UDP `:5010` for any remaining validators.
3. **Signed Snapshot in `/accountz` (`mesh/make-http-handler`):** When `pubkey` and `nonce` query parameters are provided to `/accountz`, the validator includes `:snapshot` signed with its Ed25519 identity.
4. **HTTPS Relay-First Light-Node Sync (`maybe-sync-account-state!`):** When a relay URL is configured or present on `bootstrap`, light nodes attempt `/relay/v1/chain-state` `2f+1` quorum verification first (`3000ms` timeout) before spawning ephemeral UDP `:5010` WebRTC PeerConnections.

### 13.2 Zero-Burn HTTPS Relay P2P Legs, `--autonomous` Auto-Answer, & Session Resolution (`P-NET-2`)
1. **Zero-Burn P2P Mailbox Admission (`relay/reduce-relay`):** P2P envelopes (`:sealed-message`, `:session-ack`, `:p2p-broadcast`, `:p2p-hub-relay`, `:p2p-offer`, `:p2p-answer`, `:p2p-link-bind`, `:p2p-ping`, `:p2p-pong`) are admitted into recipient `:mailboxes` / `:broadcasts` at `0` ECH burn, while `:forward-to-validators` is emitted only when `burn-amt >= min-signaling-burn`.
2. **Autonomous `:p2p-offer` Auto-Answer (`handle-wire-p2p-offer`):** When `(:autonomous? state)` is `true`, incoming `:p2p-offer` envelopes on open sessions automatically generate a signed `:p2p-answer`, emit both `"p2p-offer-received"` and `"p2p-offer-answered-while-open"`, and populate `:p2p-dial`.
3. **Most-Active Open Session Resolution (`resolve-session-id`, `cli/build-cmd-map`):** `resolve-session-id` selects the open session with highest `(tx-seq + rx-high-seq)` (tie-breaking by `:epoch` and `:session-id`), and `p2p-offer` / `p2p-answer` support `--to` and `--endpoint`.

### 13.3 Canonical `put` Relay Publishing, Idempotent `/artifact/v1/pointer`, & Ops Hardening (`P-ART-1`, `P-OPS-1`, `P-OPS-2`)
1. **Canonical `put` Relay Upload & Idempotent Pointer Acceptance:** Both `"put"` and `"artifact-put"` trigger `post-artifact-to-relay!` (`30000ms` blob timeout, `15000ms` pointer timeout, awaited before process exit in one-shot mode), and `/artifact/v1/pointer` returns `200 OK` (`"idempotent": true`) when an already-applied pointer is re-submitted.
2. **Non-Interactive SSH & Infra Rollback Hardening (`scripts/cluster.sh`, `scripts/infra_cluster.sh`):** All `ssh`, `scp`, and `rsync` invocations enforce `-o BatchMode=yes -o StrictHostKeyChecking=accept-new`; `rollback_node` restores previous bundle/config backups and restarts the service; and `publish-git --deploy` verifies live `/dist/bitecho-light-node.cjs.sha256`.

---

## 14. Milestones D34–D41: Hardened Gentoo + OpenRC, `P-OBS-*` Telemetry, `P-ASYNC-*` Zero-Sync-IO, `P-UPD-1` Auto-Update, `BitechoLightNode`, & `BIP-015` (`v0.23.12`–`v0.23.18`)

### 14.1 Hardened Gentoo Linux + OpenRC & Node.js Full-Node Fleet (`BIP-010`, `BIP-011`, `BIP-012`)
1. **Unified 6-Node (`4-of-6`) Node.js Fleet:** All 6 validators (`node1..node3` and `ns1..ns3`) run `dist/bitecho-full-node.cjs` (`--max-old-space-size=384`) supervised by OpenRC `supervise-daemon` on Hardened Gentoo Linux (`docs/runbooks/gentoo-stage3-live-migration.md`).
2. **Merkle Root-Hash Attestation & Fail-Closed Admission (`BIP-011`, `BIP-013`):** Host and artifact manifests verify layered SHA-256 trees and fail closed on missing layers or empty subtrees.

### 14.2 Core Observability (`P-OBS-*`), Six-Nines SLA & Request Defense (`BIP-013` / `D38`, `D39.5`–`D39.6.1`)
1. **Pure Step Instrumentation (`bitecho.observability.core`):** Zero-allocation-bounded step instrumentation and sequenced sinks (disk, network, IndexedDB) with sink failure isolation.
2. **Network Telemetry & Rolling Six-Nines Cluster SLA (`P-OBS-4`):** Nodes publish signed telemetry digests to `bitecho.org/observability` (`/telemetry/<node>/digest.edn`), aggregated into `https://bitecho.org/sla/latest.edn` using an interval-sweepline rollup (`:finalization-stall` breach triggers at quorum level `>= 3` simultaneous nodes per `D39.6.1`).
3. **Built-In Request Defense (`bitecho.defense.core`):** Fail-open consensus protection with escalating throttle/drop/ban windows and automatic expiry.

### 14.3 Zero-Sync-IO Boundary Shells & Immutable Epoch-Addressed Snapshots (`P-ASYNC-*` / `BIP-014` / `D39`)
1. **Pure Snapshot Core (`bitecho.snapshot.core`):** Deterministic immutable snapshot naming (`snapshot-<node>-epoch-<012d>.fressian`), highest-epoch recovery with seamless legacy `snapshot-<node>.edn` fallback, tunable retention (`keep-epochs` default `360`, `min-keep >= 2`), and single-authority generation-tagged coalescing writer reducer (Rule 4 & Rule 5).
2. **Zero-Sync-IO Across All 3 Runtimes:** Node.js (`full_node_main.cljs`, `node_main.cljs`), JVM (`shell/persistence.clj`, `shell/mesh.clj`, `shell/infra.clj`, `shell/light_node.clj`), and Browser (`shell/browser.cljc`, `browser_main.cljs`) eliminate synchronous disk/gzip I/O on runtime hot paths.
3. **Browser WebRTC ICE Diagnostics (`P-ASYNC-4`):** `pc.oniceconnectionstatechange` and `pc.onconnectionstatechange` dispatch generation-tagged events into `transition-conn`, surfacing counted `:ice-disconnects`, `:ice-reconnects`, `:last-ice-state`, and `:last-connection-state` in `getStatus().diagnostics`.

### 14.4 `P-UPD-1` Opt-In Auto-Update & `BitechoLightNode` Browser Console CLI (`D40.1`–`D40.3`)
1. **Live Pointer Auto-Update (`D40.1` `e91214c`, `D40.2` `9ecf885`, `D40.2.1` `3d86ce2`):** Shipped across Node.js light/full nodes, JVM light/full nodes (`shell/updater.clj`), and Browser (`browser_main.cljs`). Verifies `SHA-256 == pointer.target-cid`, runs a pre-swap health gate, supports same-version hotfixes with distinct verified CIDs (`D40.2.1`), and restores `.lkg` on failure. Controlled via `--auto-update-pointer`, `--auto-update-interval-ms`, and `--pin-version`.
2. **Browser Console CLI Parity (`D40.3` `b7dc6d4`, `bitecho.browser-cli`):** `window.BitechoLightNode` derives its verb inventory directly from `bitecho.light-node.cli/all-recognized-cli-verbs-set` and exposes camelCase methods + `.cli(...)`, `.exec(...)`, `.help(...)`, `.peers()`, and `.verbs()`, explicitly failing closed with `:unsupported-in-browser` on OS-only verbs (`serve`, `daemon`, `mcp`).

### 14.5 Sociocratic Governance Formalization, Canonical Channels & Rule 6 Integrity (`BIP-015` / `D41`)
1. **Two-Gate Sociocratic Consent & BIP Integrity (`docs/GOVERNANCE.md`, `bitecho.governance.integrity`):** Enforces full 64-char SHA-256 CIDs, zero `:pending` consent records, non-nil Stage 2 `:patch-cid`/`:patch-size-bytes`, and explicit resolution of `CONSENT-WITH-ADDENDUM` / `CONSENT-WITH-FLAGS` items (`S-D41-1`).
2. **Canonical Broadcast Channels (`docs/CHANNELS.md`):** Establishes `bitecho.org/team` (primary circle), `bitecho.org/dev`, `bitecho.org/ops`, `bitecho.org/observability`, and `bitecho.org/infra`, with a gated migration/deprecation checklist for `chat/simon-nexus-axiom` (`S-D41-4`).
3. **Automated Rule 6 Freshness & Pointer-Bump Gate (`S-D41-2`, `S-D41-3`, `S-D41-5`):** Automated JVM `test.check` tests verify live `cli` / `browser-cli` parity with `skill/SKILL.md`, reject hardcoded local `file://` doc links, verify `docs/bips/INDEX.md` covers all committed BIPs, and `./scripts/cluster.sh bump-pointers` automates signed `dist/*` and `web/app/*` pointer bumps.

### 14.6 Shared-Core Delivery Telemetry, Dual-Fanout Reliability & Browser Self-Healing (`BIP-020` Draft 2)
1. **Four-Pillar Shared-Core Telemetry (`bitecho.light-node.core`):** Pure Sans-IO `.cljc` reducers maintain a bounded `256`-entry (`<= 1 KiB`/entry) sender lifecycle ring buffer (Pillar 1), monotonic `sent` / `acked` / 6-reason `evicted_by_reason` / wall-clock `unacked_aged` / per-leg `fanout` counters (Pillar 2), a closed-enum receiver/watcher `received_but_not_emitted` counter including `:foreign-unicast` (Pillar 3), and counted Rule 5 `:diagnose` events (Pillar 4), surfaced in `ctl status` and Browser `getStatus()`.
2. **Two-Phase Delivery Confirmation & Wall-Clock Retry Honesty:** `prepare-send` / `prepare-broadcast` + shell-confirmed `commit-delivery-outcome` ensure `ok: true` / `mesh_submitted: true` are never returned prior to transport confirmation. Outbox timestamps use explicit wall-clock `now_ms` (never `:epoch`) and pause retry burns while disconnected.
3. **N-1 Wire Compatibility, Unconditional Dual-Fanout & `e2-micro` Bounds:** Route metadata remains strictly local (never inside signed wire bytes); browser `route-browser-envelope!` fans out broadcasts unconditionally to both open P2P channels and validator mesh/relay with zero silent catches; relay polls filter on inner `:subnet-id` even when `burn > 0`; `:broadcast-seen` is FIFO-capped at `1024` entries.
4. **Browser Liveness Honesty & Bounded Auto-Redial:** `transition-conn` transitions out of `:open` on ICE `disconnected`/`failed` prior to `DataChannel.onclose`; `transition-redial` drives bounded auto-redial (`2s -> 30s`, max `5` attempts, `<= 2` concurrent dials, hidden-tab throttle) alongside HTTPS relay fallback; `resolve-peer-target` uses `safe-map-get` to avoid CLJS `sorted-map` `CompareError`.
5. **Relay Catchup Gaps & Watcher Cursor Continuity:** `/relay/v1/poll` (including parked wakeups in `shell/http.clj` and `full_node_main.cljs`) returns `min_available_broadcast_seq` and `relay_id` respecting `sub-filter-set`; `detect-relay-broadcast-gap` emits counted `:broadcast-gap-detected`; `exec-wait` separates global `event_id` cursors from per-stream `seq`/`broadcast_seq` with non-destructive `--cursor` / `--non-destructive` reads; `control.json` persists canonical `events_out` for startup mismatch warnings.

### 14.7 Light-Node Authority, Session Recovery, Browser Parity, `:443` Passthrough Resilience & Node.js Off-Heap Slab Compaction (`BIP-021` Draft 2)
1. **Startup `subnet_id` Authority & Cross-Network Fencing (§2.1):** Pure `reconcile-startup-subnet-id` overrides stale persisted `:subnet-id` on explicit startup override (emitting counted `:subnet-id-reconciled`), while failing closed across canonical `:network-uri` boundaries (`devnet` ↔ `testnet` ↔ `mainnet`) with `:cross-network-subnet-switch-blocked` unless `--reset-network-state` is explicitly passed.
2. **Subscribed-Subnet Direct Admission & Anti-Spoofing (§2.2):** `handle-wire-payload` admits direct non-broadcast envelopes matching `:subnet-id` or `(effective-subscribed-subnets state)` via `config/equivalent-subnet-id?`, rejects untagged (`nil`) and wildcard (`"*"`) direct-envelope spoofing, exempts `:chain-state-snapshot` on non-root subnets, and stamps session replies (`send`, `session-ack`, `p2p-answer`) with `(:subnet-id session)`.
3. **Distinct Broadcast/DAC Diagnostics & Event-Queue Flood Protection (§2.3):** Mutually exclusive counted counters (`:broadcast-malformed`, `:broadcast-sig-invalid`, `:broadcast-dac-missing` / `"dac-required-missing"`, `:broadcast-dac-invalid` including non-map `wire-dac`) plus queue throttling isolating unauthenticated `broadcast-sig-invalid` floods from the 256-entry `:event-queue`.
4. **Session `tx-seq` Rollback Hardening & Real X25519 Rekey (§2.4):** Receivers store 64-slot `ciphertext-sha256` digests and return Ed25519-signed rollback ACKs (`:replay-rejected?`, `:rejected-seq`, `:peer-high-seq`, `:accepted-ciphertext-sha256` bound inside `ack-sign-bytes` with zero legacy fallback) on both `:replayed-seq` and `>= 64` `:stale-seq`. Senders evict colliding outbox entries (`:rollback-collision`) before `(acked? s)` purge, quarantine tainted `:tx-key` (`session-key-tainted-rollback`), and initiate real X25519 rekey (`channel-offer`, never `p2p-offer`), paired with a non-blocking `fs.promises` async write-barrier (`save-light-state-barrier!`).
5. **Browser Parity (§2.5.1–§2.5.2; §2.5.3 Deferred to BIP-022):** `project-light-state-liveness` projects live mesh/relay status honestly (`transport_healthy: false` when `mesh_open_peers == 0` even on relay fallback) without persisting liveness (Rule 4), paired with generation-tagged 30s (`visible`) / 180s (`hidden`) `auto-sync` and updated `allowed-persistence-keys`. Encrypted on-network Rolodex (§2.5.3) is deferred to `BIP-022`.
6. **`:443` Passthrough Graceful Drain & Mesh-First Auto-Updater (§2.6.1–§2.6.2):** Clean `:socket-close` with `peer-fin? true` routes through `:draining` (`5,000 ms` idle-progress timer up to `30,000 ms` ceiling, explicit `:cancel-drain-timeout`, global `max-draining-pairs = 64` cap, `/statusz` `TCPSocketWrap`/FD/draining counters). `deploy/core.cljc` enforces `:phase == :watching` livelock guard, BIP-017a chunked mesh fetch (`192 KiB` chunks) with HTTPS fallback (`:auto-update-mesh-fallback`), fail-closed `verify-config-pointer` on empty `:trusted-deploy-authorities`, and failed-CID quarantine.
7. **Node.js `Buffer.poolSize` Slab-Pinning Compact-Copy Fix (§2.7):** `crypto/compact-u8` eliminates `64 KiB` pooled `ArrayBuffer` slab pinning across `crypto/sha256`, `full_node_main.cljs`, and `node_main.cljs`, paired with `core/data/demote-blob-to-cold`.








