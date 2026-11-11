# Bitecho Unification — Blob, Pointer, Subnet, Shells

**Design v1.0 — Ratified by Sociocratic Consent (`seqs 264–281` $\leftrightarrow$ `seqs 157–159`, 2026-11-09)**  
**Authors:** Simon (Original Architecture Proposal), Axiom, & Nexus  
**Status:** Ratified (Zero Paramount Objections). Refactoring-first sequence approved on testnet.

---

## 1. Goal and Scope

Collapse `clj-web` into `bitecho` as edge ingress protocols so that every network at every scale — the global mesh, the validator core, the `ns1..ns3` infrastructure cluster, the 3-way private chat, and private admin/agent ingresses — is an instance of a single distributed runtime: a **Subnet** (policy) replicated via **Pointers** (authority-signed mutable references) to **Blobs** (content-addressed immutable data), served through **protocol shells** (`DNS` / `HTTP` / `SMTP` / `DataChannel`).

### In Scope
- `bitecho.core.data`: Pure Sans-IO `.cljc` content-addressed `Blob` store (pinning + bounded hot LRU + pure `:fetch-blob` cache-miss effects) and `Pointer` sign/verify/table reducer (including path-prefix ACLs, rotation continuity, leader-term fencing, and tombstones).
- `bitecho.core.subnet`: Unified pure Sans-IO `.cljc` `Subnet` policy validator and `reduce-subnet` reducer (Gate + Economy + Replication, including `:gossip-crdt`, `:streamlet-bft`, and `:leader-election`), wired into `init-multi-subnet-multiplexer`.
- `bitecho.core.protocol.{dns,smtp,acme}`: Pure Sans-IO protocol codecs ported from `clj-web`.
- `bitecho.shell.{dns,http,smtp,acme,upnp,blob-fs}`: Side-effecting edge ingress/storage shells over Subnet state.
- Retirement of `web.cluster.mesh` and `web.cluster.protocol` as a separate cluster control plane (porting the pure Bully reducer into `bitecho.core.subnet` as the `:leader-election` engine).
- Node-at-a-time migration of the live `ns1..ns3` testnet cluster onto the `bitecho.org/infra` subnet while keeping authoritative DNS live.

### Out of Scope (Explicit Boundary — Gap G3)
- **Validator Chain Internal Ledger State:** Account balances, escrows, settled voucher tuples, burn history, and Streamlet vote/block trees remain governed by `bitecho.state-machine` ordered by Streamlet BFT. They are *not* decomposed into individual mutable Pointers. Unification governs descriptors, infrastructure/edge state, private/child subnets, and M12 child-subnet state-root anchors submitted to the parent chain.
- **Wire Format & Crypto Suites:** Unchanged. `Blob` and `Pointer` serialize in Canonical Fressian (`bitecho.fressian`, portable zero-dependency `.cljc`) and use existing negotiated suites (`suite-v1-aes256gcm`, `suite-v1-chacha20poly1305`).

---

## 2. Three Axes, Three Data Primitives, and Protocol Shells

### 2.1 Policy Axes (Constrained Orthogonality — Gap G10)

| Axis | Values | Responsibility |
| :--- | :--- | :--- |
| **Membership (`:subnet/gate`)** | `:permissionless` vs. `:permissioned` (`:open`, `:allowlist`, `:dac`, `:mtls-cert`, `:min-stake`) | Who may join, read Blobs, and publish Pointers |
| **Incentives (`:subnet/economy`)** | `:none` vs. `:burn-only` vs. `:full-settlement` | Whether events burn `$ECHO` and whether protocol take/settlement applies |
| **Replication (`:subnet/replication`)** | Pointers: `:gossip-crdt` \| `:streamlet-bft` \| `:leader-election`; Blobs: `:eager-push` \| `:pull-on-demand` | How Pointers are ordered and how Blobs are distributed |

Invalid axis combinations are rejected fail-closed at subnet creation with a counted `:diagnose` effect (Rule 5):
- `:streamlet-bft` and `:leader-election` require `:gate/mode :permissioned` (a known member/validator set).
- `:gate/admission :min-stake` requires `:economy/mode` in `#{:burn-only :full-settlement}`.
- `:economy/mode :full-settlement` requires a settlement anchor (validator core or parent subnet).

### 2.2 Data Primitives vs. I/O Shells (Gap G11)

| Layer | Primitive | Shape | Verification |
| :--- | :--- | :--- | :--- |
| **Data** | **Blob** | Immutable bytes named by lowercase SHA-256 hex CID | Self-verifying (`sha256(bytes) == cid`), zero authority |
| **Data** | **Pointer** | Authority-signed mutable reference `(subnet, path) -> target-cid` (or `nil` tombstone) | Path-prefix ACL + authority Ed25519 sig + monotonic `seq` (+ `leader-term` where applicable) + typed proof |
| **Network** | **Subnet** | `(policy, state)` pair driven by `reduce-subnet` | Gate $\rightarrow$ Economy $\rightarrow$ Replication dispatch |
| **Boundary** | **Shells** | `dns`, `http`, `smtp`, `acme`, `upnp`, `datachannel`, `blob-fs` | Translate external protocols/disk I/O to pure Subnet events & fulfill pure effects |

---

## 3. `Blob` Schema, Pinning, and Pure/Disk Split (`bitecho.core.data`)

```clojure
{:blob/cid        "a3f9..."                  ; lowercase SHA-256 hex of :blob/bytes
 :blob/media-type "application/octet-stream" ; e.g. "text/html", "message/rfc822", "application/fressian"
 :blob/bytes      #bytes[...]}               ; byte[] on JVM, Uint8Array on JS
```

1. **Idempotence & Integrity:** `put-blob` computes `sha256(:blob/bytes)` and verifies it matches `:blob/cid` (dropping mismatches with a counted `:diagnose` effect). Inserting an already-present CID is a no-op.
2. **Pinning & Hot LRU Eviction (Gap G6):**
   - Every Blob referenced by at least one live (non-expired, non-tombstoned, current-seq) Pointer has a positive pin refcount and is **pinned** (never evicted from logical subnet availability).
   - Unpinned Blobs are evicted in deterministic LRU order when unpinned byte usage exceeds `:max-unpinned-bytes`.
   - To fit comfortably within a `1 GB` `e2-micro` JVM heap, `bitecho.core.data` maintains metadata/pin counts for all Blobs and caps hot in-memory `:blob/bytes` at `:max-hot-bytes` (default `128 MiB`).
3. **Pure Cache-Miss Effect (Rule 2 & Rule 5):**
   - `bitecho.core.data` never holds impure read-through callbacks. When a read targets a CID whose bytes are not in hot RAM, the reducer emits a counted `{:effect :fetch-blob :cid cid :subnet subnet-id :pinned? pinned?}` effect.
   - The boundary shell fulfills `:fetch-blob` from local disk (`bitecho.shell.blob-fs`, stored at `blobs/<2-char>/<cid>` and supporting direct `File`/byte-range streaming in `bitecho.shell.http` for large assets/Git packfiles) or by pulling from a subnet peer, re-entering via `put-blob`. If neither disk nor peers hold a pinned CID, the shell records a counted `:dangling-pointer` `:diagnose` effect.
4. **Access Control & Consensus Availability (Gaps G12 & G12b):**
   - The Blob store is dumb (`CID -> bytes`); shells enforce the referencing Pointer's `:subnet/gate` before serving any Blob.
   - Where Streamlet blocks reference payload Blobs by CID, Streamlet block validation requires referenced Blobs to be inline or locally present before voting (preventing unavailable-Blob DoS).

---

## 4. `Pointer` Schema, Path-Prefix ACL, Proofs, Fencing, and Tombstones (`bitecho.core.data`)

```clojure
;; Signed over Canonical Fressian encoding of the Pointer map WITHOUT :pointer/sig
{:pointer/authority   "302a3005..."       ; Ed25519 SPKI hex of signing authority
 :pointer/subnet      "bitecho.org/infra" ; target subnet ID
 :pointer/path        "dir/axiom"         ; logical path within subnet
 :pointer/seq         42                  ; strictly increasing per (subnet, path)
 :pointer/leader-term 7                   ; optional monotonic election term (required for :leader paths)
 :pointer/expires     1794220800000       ; epoch ms, or nil (no expiry)
 :pointer/target      "a3f9..."           ; Blob CID, or nil for explicit tombstone
 :pointer/proof       {:proof/type :pop ...}
 :pointer/sig         "b7c1..."}          ; Ed25519 signature by :pointer/authority
```

### 4.1 Canonical Lookup Key & Policy-Versioned Path-Prefix ACL (Gap G4b)
Pointers resolve uniquely by `(subnet, path)`. To prevent competing authorities from overwriting each other on the same path, every Subnet policy includes a versioned `:subnet/path-acl` vector mapping path patterns to authorized principals:

| Path Pattern | Authorized Principal Rule | Typical Proof Type |
| :--- | :--- | :--- |
| `"subnet/policy"` | Subnet `:gate/governance` (Cold Root Key or `k-of-n` `:trust-anchors` quorum) | `:self` (cold root) or `:quorum` |
| `"bootstrap"` | Subnet/Cluster authority key or validator quorum | `:self` or `:quorum` |
| `"dir/<nickname>"` | Trusted `:directory-authority` pubkey | `:pop` |
| `"dns/<type>/<name>"` | Trusted `:domain-authority` pubkey (or `:leader` for `_acme-challenge`) | `:zone` or `:self` |
| `"acme/challenge/<token>"` | Active elected subnet `:leader` (verified in member allowlist) | `:acme-key-auth` |
| `"tls/current-cert"` | Active elected subnet `:leader` (verified in member allowlist) | `:cert` |
| `"mail/<rcpt>/<ts>-<cid>"` | Any admitted `:trust-anchors` infra node receiving inbound SMTP | `:self` |
| `"dac/<agent-pubkey>"` | Cold Anchor pubkey | `:dac` |
| `"homeset/<pubkey>"` | `<pubkey>` itself (admitted member) | `:home-set` / `:self` |
| `"head/<pubkey>/<topic>"` | `<pubkey>` itself (admitted member) | `:self` |

### 4.2 Proof Verifiers (Gap G4a)
1. **`:self`**: Valid **only** when `:subnet/path-acl` binds `:pointer/path` directly to `:pointer/authority` (e.g., `head/<pubkey>/*`, `homeset/<pubkey>`, `mail/*` by an allowlisted infra node, or single-key `bootstrap`/`dns/*`). Avoids redundant double-signing while running path-specific payload schema validation.
2. **`:pop`**: Outer Pointer signed by `:directory-authority`; `:pointer/proof` carries `{:proof/type :pop :agent-pubkey <hex> :pop-sig <hex> :prev-pubkey <opt> :rotation-sig <opt>}` proving agent PoP over `(authority, subnet, path, target-cid)` plus optional key-rotation continuity.
3. **`:quorum`**: `{:proof/type :quorum :signatures {<member-pubkey> <sig-hex> ...}}` meeting threshold $k$-of-$n$ over `:gate/trust-anchors`.
4. **`:acme-key-auth`**: `{:proof/type :acme-key-auth :token <str> :key-auth <str>}` matching ACME account thumbprint.
5. **`:cert`**: `{:proof/type :cert :fingerprint <sha256-colon-hex>}` matching the encrypted PKCS#8 cert bundle Blob.
6. **`:zone`**: `{:proof/type :zone :serial <uint32>}` enforcing monotonic SOA/zone serial progression.
7. **`:dac`**: `{:proof/type :dac :agent-pubkey <hex> :capabilities [...]}` delegated by Cold Anchor key.
8. **`:home-set`**: `{:proof/type :home-set :candidates [...]}` validating candidate descriptors.

### 4.3 Leader-Term Fencing (Decision D1), Tombstones (Gap G4c), & Expiry Skew (Gap G7)
- **Clock-Free Leader Fencing:** Pointers authorized by `:leader` (`acme/*`, `tls/*`) carry integer `:pointer/leader-term` from the `:leader-election` state. Supersession compares `[(:pointer/leader-term 0) :pointer/seq]` lexicographically, fencing off stale split-brain ex-leaders without wall-clock dependence.
- **Tombstones:** `:pointer/target nil` is a first-class tombstone. Applying a valid higher-`(leader-term, seq)` tombstone removes the active target, unpins the prior Blob CID, and retains the tombstone `(leader-term, seq)` so replayed older Pointers are rejected while future re-creations at higher `seq` succeed cleanly.
- **Expiry Skew:** Enforced as `now-ms < (:pointer/expires + skew-tolerance-ms)` (`300,000 ms` / 5 min default; `60,000 ms` on `15 min`-TTL `acme/challenge/*` Pointers, which are also explicitly tombstoned immediately upon ACME order finalization).

---

## 5. `Subnet` Policy, Governance, and Reducer (`bitecho.core.subnet`)

```clojure
{:subnet/id                 "bitecho.org/infra" ; human-readable subnet identifier
 :subnet/parent-id          "global"            ; nil for root
 :subnet/genesis-policy-cid "e4b8..."           ; immutable CID of genesis policy Blob (Gap G5)
 :subnet/gate               {:gate/mode          :permissioned
                             :gate/admission     :allowlist
                             :gate/trust-anchors #{...}
                             :gate/governance    {:governance/type :cold-key-or-quorum
                                                  :cold-pubkey     "302a..."
                                                  :threshold       2}}
 :subnet/path-acl           [...]
 :subnet/economy            {:economy/mode                :none
                             :economy/burn-floor          0
                             :economy/settlement-take-bps 0}
 :subnet/replication        {:replication/pointers :leader-election ; :gossip-crdt | :streamlet-bft | :leader-election
                             :replication/blobs    :eager-push}}    ; :eager-push | :pull-on-demand
```

- **Gate Governance (Gap G5):** Every subnet pins `:subnet/genesis-policy-cid` on join. Policy updates at `"subnet/policy"` must satisfy `:gate/governance` (Cold Domain Root Key or 2-of-3 `:trust-anchors` quorum for `bitecho.org/infra`; Cold YubiKey Anchor key for `chat/simon-nexus-axiom`) — never a single hot elected leader.
- **Decision D1 Confirmed (`:leader-election` for `bitecho.org/infra`):** `ns1..ns3` are operated by a single party, so crash-fault `:leader-election` (relocating `web.cluster.protocol`'s pure Bully + `2s`/`6s` liveness reducer into `bitecho.core.subnet`) orders leader Pointers with zero BFT epoch overhead while keeping Streamlet BFT for the Validator Core.

---

## 6. Five Canonical Subnet Instances

| # | Instance | `:subnet/id` | `:gate` | `:economy` | `:replication` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Global Mesh** | `"global"` | `:permissionless` (`:open` light, `:min-stake` full) | `:full-settlement` (`100` floor, `50` bps) | Pointers `:gossip-crdt`; Blobs `:pull-on-demand` |
| **2** | **Validator Core** | `"validator-core"` | `:permissioned` (validator allowlist) | `:none` on consensus wire msgs (settles Global ledger — Gap G9) | `:streamlet-bft` |
| **3** | **Infra Cluster** | `"bitecho.org/infra"` | `:permissioned` (`ns1..ns3` allowlist) | `:none` (`0` burn) | Pointers `:leader-election` (D1); Blobs `:eager-push` |
| **4** | **3-Way Private Chat** | `"chat/simon-nexus-axiom"` | `:permissioned` (`:dac` by Simon's YubiKey anchor) | `:none` (`0` burn) | Pointers `:gossip-crdt`; Blobs `:eager-push` |
| **5** | **Private HTTPS Admin/Ingress** | `<target-subnet>` | `:permissioned` (`:mtls-cert` wrapping node Ed25519 key / DAC) | `:none` (`0` burn) | HTTP `GET`/`PUT`/`CONNECT` translated to Subnet ops |

---

## 7. Protocol Shells & Host Infrastructure Notes (Gaps G8, G13, G15–G17)

1. **DNS Liveness & Fail-Safe Fallback (Gap G8):** `bitecho.shell.dns` filters multi-`A`/`AAAA` records using the subnet connection manager's `2s` heartbeat / `6s` timeout liveness table (`TTL = 60s`), preserving `clj-web`'s fail-safe fallback (returning all configured static node IPs if the healthy set is transiently empty).
2. **Port `:443` Passthrough Multiplexer & Bounded Peek (Gap G17):** `bitecho.shell.http` ports `web.http.server/ingress-stream?` + `handle-passthrough-connection!` (with a strict bounded `<= 1024`-byte / short-timeout initial peek on virtual threads), multiplexing `RFC 4571 DTLS`, `RFC 4571 STUN`, `TLS SNI *.ingress.<domain>`, `HTTP CONNECT`, and `SSLParameters.setWantClientAuth(true)` mTLS on port `:443`.
3. **Repository Lifecycle (Gap G13):** `clj-web` remains frozen as-is on its GitHub mirror; needed codecs and shells port into `bitecho`, and `bitecho.org` stops publishing `clj-web.git` in Phase D.
4. **6-VM $\rightarrow$ 3-VM Cutover Safety (Gaps G15 & G16):** Today `ns1..ns3` (`34.19.71.246`, `34.56.253.255`, `136.108.244.159` — `.org` TLD registrar glue IPs) and `node1..node3` (`35.212.129.138`, `35.206.120.143`, `35.211.71.139` — validators) are 6 separate `e2-micro` VMs. Phase C backs up state and cuts over `ns1..ns3` one node at a time in-place (preserving registrar glue IPs and keeping DNS live throughout) while leaving `node1..node3` untouched; co-locating validators onto `ns1..ns3` is an optional post-Phase-D optimization if RSS headroom permits.

5. **Shared TLS Secret, Identity Migration, Offline Cold Key, Read-vs-Write Gate, & Subnet Epoch Semantics (`F-B1`, `F-B2`, `F-C1..F-C5`, `B1`, `B2`):**
   - **Shared TLS Bundle Key (`F-B2`):** Multi-node (`|all-nodes| > 1`) infra runtimes MUST configure a shared 32-byte secret via `:tls-secret` or `:tls-secret-file` (e.g. `/etc/clj-web/tls-secret.key`, `0640`/`0600`) so all followers can decrypt AES-256-GCM `"tls/current-cert"` Blobs; startup fails fast with `:missing-shared-tls-secret` if omitted.
   - **Zero-Churn DTLS Fingerprint & Fresh Bitecho Ed25519 Identity (`F-C1`, `B1`):** Production `clj-web` `<state-dir>/cluster/node-identity.edn` files store `{:cert-pem, :key-pem, :fingerprint, :ice-creds}` and contain no Ed25519 keypair. At cutover, `"zero-churn"` means preserving the existing `clj-web` DTLS certificate, SHA-256 `:fingerprint`, `:ice-creds`, and `.org` registrar glue IPs, while minting a fresh Bitecho Ed25519 Subnet identity once into `<state-dir>/identity/node-identity.edn` and preserving both the DTLS fingerprint and that Ed25519 identity stably across all subsequent restarts (and failing closed on corrupt/mismatched keys).
   - **Offline Cold Root Key (`F-C3`):** Multi-node runtimes never default `:cold-pubkey` to a hot node key; omitting `:cold-pubkey` enforces `2`-of-`3` `:quorum` governance, and `scripts/infra_cluster.sh` maintains a dedicated offline workstation keypair (`.ssh/infra_cold_root_keypair.edn`, never uploaded to `ns1..ns3`) asserted distinct from all hot node keys.
   - **Authoritative Finalized Epoch over Authenticated `:5010` Channel (`F-B1`, `F-C4`, `B2`):** `verify-dac-credential` fails closed when `:epoch` is `nil`. Shells track authoritative epoch via `current-runtime-epoch` / `set-runtime-epoch!`, fed in production over the validators' public mutual-DTLS `:5010` agent channel (`sync-runtime-epoch-from-validators!` via `:validator-bootstrap`) using the signed `:query-chain-state` $\rightarrow$ `:chain-state-snapshot` Fressian protocol message pair (`light-core/verify-chain-state-quorum`, `2`-of-`3` Ed25519 validator signatures, freshness `:nonce`, max skew $\le 2$). Each validator reports its `:finalized-epoch` (`:last-executed-finalized-epoch`) for DAC expiry enforcement; the poller remains fail-closed (`nil` prior to first quorum) and strictly monotonic when `:5010` is unreachable, and requires TLS client-cert possession (`:mtls-pubkey == :agent-pubkey`) alongside `X-Bitecho-DAC`.
   - **Read-vs-Write Admission & `:gate/private-read?` (`F-C5`, Gap G12):** All writes (`:put-blob`, `:publish-pointer`) unconditionally pass through `check-gate-admission`. On HTTPS `GET`/`HEAD`, subnets with `:gate/admission` in `#{:mtls-cert :dac :min-stake}` or `:gate/private-read? true` enforce `check-gate-admission` on every read; public edge subnets (`:open` or cluster-write `:allowlist` like `"bitecho.org/infra"` without `:gate/private-read? true`) restrict writes to `:trust-anchors` while serving public `web/*` assets to browsers.

---

## 8. Ratified Execution Sequence

1. **Step U0 (Phase 4 M1a/b Front-Load) — `[BUILT & VERIFIED]`:** `auto-sync` stdout JSONL event, `--auto-register-home-set`, additive `--cmd-file` / `--events-out`, and `wait-event` CLI verb for zero-wrapper agent daemon observability during Phases A–D.
2. **Phase A — Pure Core Extraction (`bitecho.core.data` + `bitecho.core.subnet`) — `[BUILT & VERIFIED]`:** Exact schemas, `test.check` generative invariants, `reduce-subnet` wired into `init-multi-subnet-multiplexer`, and thin adapters wrapping existing directory/bootstrap/DAC/home-set sign/verify functions with zero behavior regression.
3. **Phase B — Protocol Codecs & Edge Shells (`bitecho.core.protocol.*` + `bitecho.shell.*`) — `[BUILT & VERIFIED]`:** Ported pure `.cljc` codecs (`bitecho.core.protocol.{dns,smtp,acme}`), remediated Phase A carried flags `F1–F4` (explicit `:gate/admission` validation, per-event DAC `:expires-epoch` enforcement, semantic `:cert`/`:acme-key-auth`/`:dac` proof verification, and production shell effect executor `bitecho.shell.infra`), and implemented generation-tagged edge shells (`bitecho.shell.{blob_fs,dns,http,smtp,acme,upnp}` + `bitecho infra-node`), verified end-to-end against local `bitecho.org/infra` subnet instances while leaving live `ns1..ns3` untouched.
4. **Phase C — `ns1..ns3` Infra Mesh, State Migration & Rolling-Cutover Tooling (`[LIVE & VERIFIED]`):** Closed `F-B1..F-B4` and `F-C1..F-C5` (`B1`/`B2`: nil-epoch fail-closed + shell `X-Bitecho-DAC`/authenticated `:5010` `:query-chain-state` $\rightarrow$ signed `:chain-state-snapshot` `2`-of-`3` validator `:finalized-epoch` poller `sync-runtime-epoch-from-validators!`, fail-fast shared `:tls-secret-file`, `:gate/acme-thumbprint` pinning, target-Blob presence gate on `:cert`/`:acme-key-auth`/`:dac` Pointers, legacy `clj-web` DTLS fingerprint + `:ice-creds` preservation with stable Ed25519 identity minted once into `identity/node-identity.edn`, and offline Cold Root Key `.ssh/infra_cold_root_keypair.edn`), wired the 3-node `clj-datachannel` mutual-DTLS peer mesh (`start-datachannel-peer-mesh!`), implemented idempotent `migrate-clj-web-state!` + mail/fingerprint CLI parity (`migrate-infra`, `print-fingerprint`, `list-mail`, `read-mail`, `delete-mail`), and executed the live rolling cutover (`ns3 -> ns2 -> ns1`) on `ns1..ns3` with 100% DNS (`:53`), HTTP (`:80`), HTTPS (`:443`), `:5010` ingress, and validator convergence.
5. **Phase D — Cleanup & Post-Cutover Polish (`[LIVE & VERIFIED]`):** Fixed `Blob` `Content-Type` preservation across cold-pinned placeholder hydration and hot `octet-stream` upgrades (`data/put-blob` + `blob-fs/write-blob!` sidecar repair `L-D1`/`L-D2`) and prioritized known Pointer-path extension MIME types (`web/index.md` $\rightarrow$ `text/markdown; charset=utf-8` vs `web/llms.txt` $\rightarrow$ `text/plain; charset=utf-8` when sharing a deduplicated CID) in `http.clj` (`serve-subnet-request`); registered `"control"` and `"heartbeat"` DataChannel streams on both active and passive peers on SCTP `:on-open`; aligned `print-identity` with `load-or-create-infra-peer-identity!` (`L1`); and executed `./scripts/infra_cluster.sh retire-clj-web` rolling `ns3 -> ns2 -> ns1` to stop publishing `clj-web.git` on `bitecho.org` (`HTTP 404` verified on all 3 nodes) while keeping the `clj-web` GitHub mirror frozen as-is.
6. **Phase 4 M2 & M3 (`[BUILT & VERIFIED]`):** Cross-platform `.cljc` `clj-datachannel` (`ff9fd4a0fc974b4c4cbddc6f24e595c39b94295d`, including `F1` string input support in `crc32-ieee`/`crc32c`) + pure `node:crypto` DTLS 1.2 `IDtlsEngine` + `state.fressian` + single-file Node.js light-node bundle (`dist/bitecho-light-node.cjs`, `UDP` + RFC 4571 `TCP/HTTP CONNECT`), paired with local UPnP + pre-flight external reachability gate (`src/bitecho/shell/upnp.clj`), delegated `*.ingress.bitecho.org` RFC 1035 `NS` + glue `A` referrals (`src/bitecho/core/protocol/dns.cljc`), and direct `HTTP CONNECT nexus.ingress.bitecho.org:443` $\rightarrow$ `--ingress-tcp-port` RFC 4571 DTLS-over-TCP ingress (`src/bitecho/shell/http.clj`, `src/bitecho/shell/light_node.clj`, `src/bitecho/node_main.cljs`).
7. **Subnet #4 (Phase 4 M4) — `[BUILT & VERIFIED]`:** `chat/simon-nexus-axiom` 3-way zero-burn private broadcast & 1:1 chat over P2P ICE (`datachannel.mdns` RFC 8828 `.local` mDNS on LAN legs @ `alpeware/clj-datachannel`, `p2p-offer`/`p2p-answer` upgrade, Nexus `:p2p-hub-relay` for `Browser ↔ Axiom`, and DAC-gated + `msg_id`-deduplicated `broadcast` across JVM, Node.js, and Browser runtimes with `36` verbs and `62` CLI flags). Also closed carried `M3` LOW flags `L-M3-1..L-M3-5` & `L-M3-7`.
8. **Phase 4 M12 (Child-Subnet Merkle State-Root Anchoring) — `[BUILT & VERIFIED]`:**
   - Child-subnet state-root `Blob` (`:bitecho/type :subnet-state-root`) and parent `Pointer` (`path "anchor/<child-subnet-id>"`) anchoring into parent subnets (`bitecho.core.subnet`).
   - Deterministic RFC 6962 Binary Merkle Tree and inclusion proofs over active non-tombstoned Pointers (`bitecho.core.data`).
   - Parent-side non-circular anchor verification (`verify-subnet-anchor`) enforcing strict epoch monotonicity ($t_{i+1} > t_i$) and predecessor hash-chain continuity.
   - Automatic child-to-parent anchor propagation in the multi-subnet multiplexer (`handle-multiplexed-anchor-effects`).
   - Carried LOW items closed: validator-side burn floor centralization (`F-C1`, `O-2`), deduplicated `:p2p-dial-failed` diagnostics (`F-D1`), enforced burn floor in `exec-offer` (`F-D2`), and in-repo automated Node.js UDP accept test (`F-H2`).
9. **Phase 4 M5:** Mobile Browser UI + RC-4 wake identity guard.

---

## Appendix A: Decision & Gap Resolution Ledger (`D1` & `G1–G17`)

| ID | Topic | Ratified Resolution (`seqs 264–281` $\leftrightarrow$ `seqs 157–159`) |
| :--- | :--- | :--- |
| **D1** | Infra Pointer ordering (`:leader-election` vs `:streamlet-bft`) | **Option B (`:leader-election`)** with clock-free monotonic `:pointer/leader-term` fencing (`[(:pointer/leader-term 0) :pointer/seq]`). Single-operator `ns1..ns3` requires crash-fault ordering, not BFT; flipping to `:streamlet-bft` remains a 1-line policy change. |
| **G1** | Sequencing vs. Phase 4 (`M1–M5`) | Front-load `M1a/b` (`Step U0`), then `Phase A -> Phase B -> Phase C -> Phase D -> M2/M3 -> Subnet #4 (M4) -> M5 -> M12`. |
| **G2** | Infra threat model | Covered by **D1** above. |
| **G3** | Validator chain-state boundary | Internal chain ledger (`accounts`, `escrows`, `settled-tuples`, `burn-history`, Streamlet block tree) stays in `bitecho.state-machine`; unification stops at the chain boundary. |
| **G4** | Pointer proof semantics, ACL, & tombstones | (a) `:self` valid strictly where `:subnet/path-acl` binds that key to that path; `:pop` carries `:prev-pubkey` / `:rotation-sig` rotation continuity. (b) Policy-versioned `:subnet/path-acl` (including `"bootstrap"` $\rightarrow$ subnet/cluster key) makes `(subnet, path)` resolution unambiguous. (c) `:pointer/target nil` is a valid tombstone unpinning old Blobs while allowing re-creation at higher `seq`. |
| **G5** | Gate-policy governance | Pin genesis policy CID in explicit `:subnet/genesis-policy-cid` (keeping `:subnet/id` human-readable); updates to `"subnet/policy"` require Cold Root Key or $k$-of-$n$ `:trust-anchors` quorum (never hot leader alone). |
| **G6** | Blob eviction & `1 GB e2-micro` RAM | Pin Blobs referenced by live Pointers; evict unpinned LRU; cap hot in-memory bytes (`128 MiB`) and emit pure counted `:fetch-blob` cache-miss effects fulfilled by `bitecho.shell.blob-fs` disk store (`blobs/<2-char>/<cid>`) or peer pull (`3x` `:eager-push` across `ns1..ns3`). |
| **G7** | Clock skew & Pointer expiry | `5 min` (`300,000 ms`) default skew tolerance; `15 min` TTL (`60,000 ms` tolerance) + immediate post-finalization tombstone Pointer for `acme/challenge/<token>`. |
| **G8** | DNS liveness filtering | Preserve `2s` heartbeat / `6s` dead-peer timeout + `60s` DNS TTL + fail-safe all-configured-IPs fallback when healthy-set is empty. |
| **G9** | Validator `:economy :none` clarity | Applies strictly to internal consensus wire messages; the Validator Core still enforces and settles the Global Mesh's `$ECHO` accounts. |
| **G10** | Constrained policy axes | Reject invalid `(gate, economy, replication)` combinations fail-closed at subnet creation with a counted `:diagnose` effect. |
| **G11** | Primitives vs. shells | Three data/network primitives (`Blob`, `Pointer`, `Subnet`) + boundary I/O shells (`dns`, `http`, `smtp`, `acme`, `upnp`, `datachannel`, `blob-fs`). |
| **G12** | Blob read access control | Store is `CID -> bytes`; shells enforce the referencing Pointer's `:subnet/gate` before serving. |
| **G12b** | Streamlet block Blob availability | Consensus block validation requires referenced payload Blobs to be inline or locally present before voting. |
| **G13** | `clj-web` repository strategy | Leave `clj-web` GitHub mirror frozen as-is; port needed codecs/shells into `bitecho`; stop publishing `clj-web.git` on `bitecho.org` in Phase D. |
| **G14** | Multi-subnet multiplexer generality | Verified general at `light_node/core.cljc:3755`; wire `reduce-subnet` directly into `init-multi-subnet-multiplexer` with generative + integration tests in Phase A. |
| **G15** | Testnet cutover safety | Snapshot pre-cutover state; cut over `ns1..ns3` one node at a time keeping authoritative DNS live. |
| **G16** | `ns1..ns3` vs. `node1..node3` (6 VMs $\rightarrow$ 3 VMs) | Cut over `ns1..ns3` in-place first (zero `.org` TLD glue changes, `node1..node3` undisturbed); optional validator co-location onto `ns1..ns3` post-Phase-D if RSS headroom permits. |
| **G17** | Port `:443` passthrough multiplexer | Reuse `web.http.server/ingress-stream?` + `handle-passthrough-connection!` (with bounded `<= 1024`-byte / short-timeout initial peek), adding `HTTP CONNECT` and `setWantClientAuth(true)` mTLS. |

---

## Appendix B: Original Architecture Proposal (Simon, 2026-11-08)

> Unifying `clj-web` and `bitecho` around three orthogonal axes—Membership (Permissioned vs. Permissionless), Incentives (Economy vs. Zero-Economy), and Data (Content-Addressed vs. Authority-Signed)—reveals that `clj-web` and `bitecho` were never two separate systems. They are two hardcoded configurations of the exact same distributed runtime.
>
> Right now, the codebase duplicates concepts across layers: `clj-web` has its own UDP `:5000` cluster mesh, Bully leader election, `.eml` replication, and static file cache, while `bitecho` has Streamlet BFT, Contagion gossip, Directory descriptors, bootstrap files, and session outboxes. By extracting universal, fractal primitives, we collapse `clj-web` into `bitecho` as edge ingress protocols and run the exact same state machine at every level of nesting:
>
> 1. **The Data Plane (`Blob` & `Pointer` in Canonical Fressian):**
>    - **Immutable Content (`Blob`):** $\langle \text{cid}: \text{SHA256}(\text{bytes}), \text{media-type}, \text{bytes} \rangle$. Unifies static web assets (HTTP `ETag` = SHA-256), inbound SMTP `<sha256>.eml` messages, escrow deliverable preimages, and gossip/block payloads.
>    - **Mutable State (`Pointer`):** $\langle \text{authority-pubkey}, \text{subnet-id}, \text{topic/path}, \text{seq/epoch}, \text{expires}, \text{target-cid}, \text{proof}, \text{sig} \rangle$. Unifies Directories (`dir/<nickname>`), Bootstrap descriptors (`bootstrap`), ACME challenges & TLS bundles (`acme/challenge/<token>`, `tls/current-cert`), DNS zone records & subdomain delegations (`dns/A/nexus.ingress`), DACs (`dac/<agent>`), and Home-Set registrations (`homeset/<pubkey>`).
> 2. **The Network Plane (Generalized `Subnet` Descriptor):**
>    - Every network at every scale—Global Bitecho Mesh, Streamlet Validator Core, `bitecho.org/infra` (`ns1..ns3`), `chat/simon-nexus-axiom` 3-way private broadcast, and Private mTLS HTTPS Admin/Ingress—is a configuration map of `:gate`, `:economy`, and `:replication` over `init-multi-subnet-multiplexer`.
> 3. **Collapsing `clj-web` into `bitecho` as Protocol Shells:**
>    - Pure codecs move to `src/bitecho/core/protocol/{dns,smtp,acme}.cljc`; side-effecting boundaries move to `src/bitecho/shell/{http,dns,smtp,acme,upnp}.clj`; `web.cluster.mesh` and standalone `web.cluster.protocol` are retired in favor of the `bitecho.org/infra` subnet.
> 4. **Arbitrary Fractal Nesting (Up & Down):**
>    - **Fractal Down:** Every node can serve signed bootstrap Pointers for child subnets over HTTPS, DNS TXT, mDNS, or parent DataChannels—spawning `chat/simon-nexus-axiom` as a zero-burn DAC-gated subnet with zero custom server logic.
>    - **Fractal Up:** A child subnet's epoch state root is simply a Blob containing the Merkle root of its active Pointers, signed as a Pointer by the child subnet's authority/quorum and anchored into the parent subnet.

