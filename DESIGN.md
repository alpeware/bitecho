# Bitecho Architecture Overview

Bitecho is a decentralized, permissionless WebRTC signaling network and cryptographic Web of Trust designed specifically for autonomous AI agents. It eliminates the need for centralized signaling servers (like WebSockets) by routing WebRTC SDP offers and answers directly through a peer-to-peer mesh network, built on top of the pure-functional `clj-datachannel` library.

The architecture is explicitly designed around a **Full Node vs. Light Node (Agent)** dichotomy to scale to 100+ million concurrent agents while minimizing egress bandwidth and latency.

---

## Phase 1: The Network Layer (SBRB & Gossip)

### 1. Basalt (Byzantine-Resilient Peer Sampling)
Basalt is the foundational peer sampling layer for the **Full Node backbone**. It provides each Full Node with a continuously updating, randomized, and mathematically robust subset of network peers. It uses secure hashing (IP/Port/Pubkey) to prevent Sybil attacks and eclipse attacks, ensuring the network topology remains connected and highly resilient. In Tokenomics v2.1, Basalt slot reseeding is deterministically keyed by the hash of the latest finalized Streamlet block, ensuring sample assignments cannot be ground or manipulated by adversarial nodes.

### 2. The Contagion Stack (Routing & Broadcasting)
To route global state (specifically routing tables and ledger updates) across the Full Node mesh without central servers, we use a 3-layered epidemic broadcast protocol stack:
* **Layer A: Murmur (Probabilistic Broadcast):** The base gossip layer. Guarantees *Validity* and *Totality* but not *Consistency*.
* **Layer B: Sieve (Probabilistic Consistent Broadcast):** Upgrades Murmur via history buffers and Echo Samples ($E$) to guarantee *Consistency*. Uses cryptographically signed control frames (`bitecho.sieve.core`) to ensure authentic origin verification.
* **Layer C: Contagion (Probabilistic Reliable Broadcast):** Upgrades Sieve via Ready Samples ($R$) and Delivery Samples ($D$) to guarantee *Totality*.

**The Full Node / Light Node Split:** Light Nodes (AI Agents) do **not** run the heavy Contagion stack. Instead, Full Nodes run the SBRB mesh and broadcast ~120KB Cuckoo/Bloom filters containing the public keys of their connected Light Nodes every epoch (e.g., 5 minutes). Agents simply query their connected Full Node for routing paths.

### 3. The Pure State Machine (Sans-IO)
The Bitecho core models these layers purely. The state machine accepts inputs, transitions internal Basalt views and Sieve history buffers, and emits pure commands to be handled by the external IO shell.

---

## Phase 2: The Echo Economy & Tokenomics (v2.1 Architecture)

To prevent Sybil attacks and sustainably incentivize routing infrastructure, the network operates an account-based cryptographic token called $ECHO, governed by a strict 42 Billion hard cap and asynchronous settlement. **Bitecho does NOT use a UTXO model, colored coins, or global consensus for basic transfers.**

### 1. Asynchronous Account-Based Settlement (Consensus Number 1)
Based on the academic proof that single-owner accounts have a Consensus Number of 1, global consensus is not required to prevent double-spending:
* Agents maintain a local, strictly incrementing sequence number (`seq`) and a cryptographic causal history (`deps`).
* Agents broadcast signed transfers (`bitecho.economy.account`).
* Receiving nodes locally validate that `seq` is incremented by exactly 1, causal dependencies match, and the balance is $\ge 0$. Transfers are applied immediately without global consensus voting.

### 2. Supply Architecture: 42 Billion Hard Cap
The network enforces an absolute hard cap of **42,000,000,000 ECHO (42 Billion ECHO)**:
* **45% Genesis Custody Allocation (18,900,000,000 ECHO)**: Initialized in the authoritative `:genesis-ledger` in `bitecho.state-machine`. Allocated to 10% Bootstrap Reserve (4.2B), 15% Core Team (6.3B), 10% Genesis Partners (4.2B), and 10% Ecosystem Grants (4.2B). Fail-closed Bootstrap custody drawdown (`process-bootstrap-custody`) and the Year-3 hard sunset burn (`burn-unspent-bootstrap-custody` at epoch `26,280`) are enforced directly by the state machine per tick. Team (4yr/1yr cliff), Genesis Partners (SLA-gated), and Ecosystem Grants (milestone-gated) schedules are administered via external Treasury custody governance and lockup contracts rather than automated per-tick state-machine rules.
* **55% Unminted Conditional Supply (23,100,000,000 ECHO)**: Does not exist at genesis. Tokens are only brought into existence via demand-gated emission.

### 3. Signaling Fee Burn (`bitecho.economy.burn`)
* When nodes broadcast or initiate signaling operations, they pay a mandatory signaling fee burn (`min-signaling-burn = 100` ECHO).
* Burned fees are permanently destroyed from circulation in `:epoch-burns`.
* Burns prevent broadcast spam and form the base protocol revenue $R_t$ that gates future minting.

### 4. Peer-Attested Mesh Rewards (`bitecho.economy.attestation`)
The v1 probabilistic receipt lottery has been completely deleted. Treasury rewards are awarded based on **third-party-verifiable mesh participation**:
* **Deterministic Epoch Entropy**: Peer samples are seeded each epoch from the finalized Streamlet block hash: $\text{slot\_seed} = \text{SHA256}(\text{finalized\_block\_hash}_e \parallel \text{pubkey}_i \parallel r)$.
* **Canonical Exchange Digest**: Peers compute a deterministic digest over all valid messages exchanged across their link: $\text{exchange\_digest} = \text{SHA256}(e \parallel \text{peer}_a \parallel \text{peer}_b \parallel \text{pr-str}(\text{sorted\_vec}))$.
* **Frozen Epoch Message Logs**: Message reconciliation is evaluated against the frozen epoch message set (`:frozen-epoch-messages`) before TTL pruning.
* **Bilateral Transcripts & Dispute Recomputation**: Sampled peers exchange signatures to form an `EpochTranscript`. If a counterparty withholds its signature, a half-signed transcript is evaluated against the frozen epoch log. If honest, the withholding peer incurs a fault strike (`:fault-strikes`); fabricated transcripts fail log recomputation and never strike honest peers. Accumulating 3 strikes locks node stake.
* **Live Bilateral Wire Exchange (`:send-transcript-sig` / `:receive-transcript-sig`)**: At epoch close, consensus full nodes sign their local frozen message log via `attestation/sign-frozen-log`, construct half-signed transcripts for each peer via `attestation/create-transcript`, and emit `:send-transcript-sig` network commands. Receiving peers verify the counterparty signed frozen log, reconcile roles via `attestation/reconcile-message-roles`, cosign matching transcripts, and submit them (`:submit-transcript`) to Streamlet consensus. When message views have partial overlap, the receiver replies with a reconciled half-signed transcript (`:reconciled? true`) and its own signed frozen log, which the initiator verifies, cosigns, and submits.
* **Consensus Staging & Finalized-Block Execution (`:transcript`)**: Mutually-signed transcripts and verified half-signed disputes are staged as `:transcript` receipts in Streamlet consensus blocks. Upon 3-chain block finalization, receipts update windowed `:attested-participation`, adjust `:mesh-nodes` weights continuously via `attestation/calculate-node-weight`, and increment `:fault-strikes` for withholding counterparties.
* **Bounded State Retention**: State maps `:settled-transcript-pairs`, `:epoch-participation`, and `:peer-frozen-logs` are pruned deterministically by `frozen-log-retention-epochs` (168 epochs), recomputing windowed `:attested-participation` to maintain constant memory bounds during soak runs.
* **Bounded Node Weight**: Node weight scales continuously and linearly with stake: $w_i = \text{participation}_i \times \min(4.0, \text{stake}_i / S_{\min})$ using reference unit stake $S_{\min} = 250,000$ ECHO (`attestation/default-min-stake`) and maximum multiplier $S_{\max} = 4.0$ (`attestation/max-stake-multiplier`), with continuous scaling and no discontinuous cliff at $S_{\min}$.

### 5. Demand-Gated Treasury Mint & Bootstrap Custody (`bitecho.economy.treasury`)
* **Demand-Gated Mint Formula**: In epoch $t$, new conditional minting $M_t \le 0.5 \times R_{\text{trailing},t}$ over a rolling $N = 168$ epoch window (zero-padded for $t \le N$). Total revenue $R_t$ consists of 100% of signaling burns + 100% of `sci` intent settlement takes.
* **Cycle Deflation**: Because 100% of $R_t$ is burned while minting is discounted by $k = 0.5$, cumulative net issuance satisfies $\sum (M_t - R_t) \le -0.5 \sum R_t \le 0$ over any full economic cycle.
* **Exact 20/80 Mint Partition**: $M_t$ is partitioned 20% to Streamlet consensus validators and 80% to Full Node mesh nodes.
* **Bootstrap Custody Decay & Hard Sunset**: The 10% Bootstrap Reserve decays over ~3 years. At Year 3 (epoch `26,280`), any unspent bootstrap balance is permanently burned directly from custody via `burn-unspent-bootstrap-custody`, reducing total eventual supply.

---

## Phase 3: WebRTC Circuit Discovery & Callee-Pays Multi-Homed Rendezvous

Bitecho utilizes a "Client-to-Rendezvous" topology, eliminating the originating Full Node from the data plane and resolving the "terminating monopoly" holdup problem.

### 1. The Terminating Monopoly Solution
In signaling, the callee's home node (FNB) can extort callers under sender-pays models. In Tokenomics v2.1:
* **The Callee Pays**: Callee B benefits from reachability, so Callee B pays for rendezvous hosting. Caller A pays zero node fee (paying only its own signaling spam burn).
* **Multi-Homed Home Sets**: Callee B registers with $m \ge 3$ Full Nodes at a **single uniform price $p_B$**.
* **Zero Selection Friction**: Because every node in B's home set charges the identical price $p_B$, Caller A's client automatically connects to the lowest-latency responsive node without user decision and without inflating B's costs.

```
Caller A                                      Home Node (FNB)                             Callee B
   |                                                 |                                       |
   |--- 1. Offer Header + Signaling Burn ----------->|                                       |
   |    (caller_pubkey, burn_hash, offer_hash)       |--- 2. Offer Header Push ------------->|
   |                                                 |    (caller, burn_hash, epoch)         |
   |                                                 |<-- 3. Signed DeliveryAck Voucher -----|
   |                                                 |    (seq, cumulative_debit = seq*p_B)  |
   |                                                 |--- 4. Reveal Encrypted SDP Body ----->|
   |<-- 5. Relay SDP Answer & ICE -------------------|                                       |
   |<==================== 6. Direct P2P WebRTC Liftoff =====================================>|
```

### 2. The Rendezvous Algorithm (`bitecho.rendezvous.core`)
1. **Registration (Callee B $\rightarrow$ Mesh)**: B registers a home set of $m \ge 3$ Full Nodes at price $p_B$. If fewer than 3 nodes accept at $p_{B,\text{init}}$, B steps up within $[p_{B,\text{init}}, p_{B,\max}]$. If $1 \le m < 3$ accept at $p_{B,\max}$, B enters flagged degraded mode.
2. **Lookup (A $\rightarrow$ FNA)**: A queries host FNA, which returns B's full multi-homed home set and inbound policy.
3. **Selection**: A's client selects the lowest-latency responsive home node FNB.
4. **Offer (A $\rightarrow$ FNB)**: A submits its SDP Offer and proof of signaling spam burn ($\ge 100$ ECHO). A attaches zero rendezvous fee.
5. **Two-Phase Header Relay & Policy-Gated Ack**: FNB verifies A's burn and pushes *only* the Offer Header to B. If B's policy passes, B signs a monotonic voucher:
   $$\text{DeliveryAck}(\text{callee}, \text{home\_node}, \text{epoch}, \text{offer\_hash}, \text{seq}, \text{cumulative\_debit})$$
   with $\text{cumulative\_debit} = \text{seq} \times p_B$. FNB then reveals the full encrypted SDP body to B and shuttles Trickle ICE candidates.
6. **Direct P2P Liftoff**: STUN/TURN candidates punch through NAT, A and B establish a direct WebRTC DataChannel, and the transient FNB connection is severed.
7. **Signed Sieve Control Frames (`bitecho.sieve.core`)**: Control messages (`:sieve-echo`, `:contagion-ready`) are signed with Ed25519 keypairs, guaranteeing cryptographic authenticity across the signaling mesh.

---

## Phase 4: Decentralized Service Economy & Transaction Bundling

### 1. Decentralized TURN & Bandwidth Relays
Bandwidth relay and TURN services are **private goods paid directly by users at spot market prices** (USD-denominated, settled in any token the node accepts). Bandwidth costs are never subsidized by the Treasury, preventing tragedy-of-the-commons exhaustion.

### 2. Voucher Compaction (`bitecho.economy.bundle`)
To avoid ledger transaction bloat:
* Full Nodes aggregate sequential `DeliveryAck` vouchers from callees during the epoch.
* At epoch close, `compact-vouchers` compacts pending vouchers down to the single highest-`seq` voucher per $(\text{callee}, \text{home\_node}, \text{epoch})$ tuple.
* The Treasury settles the single cumulative debit in the ledger, enforcing replay protection against previously settled tuples.

### 3. Programmable Smart Contracts (`sci` Sandbox) & Settlement Take
For complex agent negotiations (escrows, multi-party bounties, service SLAs), Bitecho executes Clojure contracts via the Small Clojure Interpreter (`sci`) in a gas-limited sandbox:
* **Localized Ephemeral Quorums**: Contracts execute as localized $k$-shared asset transfers evaluated by ephemeral Streamlet BFT quorums.
* **Mandatory Protocol Settlement Take ($\tau = 0.5\%$)**: Every `sci` settlement contract pays a non-waivable protocol take $\tau = 0.5\%$ (50 bps, bounded $[0, 200]$ bps). Takes are collected in or converted to ECHO and **100% burned** (`:epoch-settlement-takes`), feeding the trailing revenue base $R_{\text{trailing}}$.

### 4. Universal Edge Payment Acceptance (Edge FX)
* **Full Nodes as Principals**: Full Nodes advertise supported payment rails (Base, Solana, Bitcoin) and quote spot exchange rates to agents, taking asset inventory onto their own balance sheets.
* **Escrow-First Settlement (Mandatory at Launch)**: The node locks ECHO in the quorum; the agent transfers the asset; the quorum releases upon cryptographic proof of transfer. Commitment-first settlement is disabled until Phase 2 home-node bond slicing is active.

---

## Phase 5: The Executable Shell & Network Genesis

### A. The Declarative Flow Shell
The system topology is bifurcated: a `:net-in` channel multiplexes all raw external events into the pure `bitecho.state-machine/handle-event` step function. This function computes the new state and deterministically yields pure commands to a `:net-out` channel. An entirely separate, "dumb" side-effecting IO shell consumes `:net-out` to transmit UDP packets or commit state.

### B. The 42 Billion Genesis Allocation
The network initializes from a deterministic `genesis.edn` state, hard-capping supply at 42,000,000,000 ECHO:
* **45% Genesis Custody (18.9B ECHO)**:
  - 10% Bootstrap Reserve (4.2B ECHO, 3-yr decay + sunset burn via `burn-unspent-bootstrap-custody` at epoch `26,280` in the protocol state machine).
  - 15% Core Team (6.3B ECHO, 4-yr vest, 1-yr cliff via external custody governance).
  - 10% Genesis Partners (4.2B ECHO, 1-yr cliff, 3-yr vest, SLA-gated via external custody governance).
  - 10% Ecosystem & Grants (4.2B ECHO, milestone-gated via external custody governance).
* **55% Unminted Conditional Supply (23.1B ECHO)**: Minted strictly through demand-gated emission ($M_t \le 0.5 \times R_{\text{trailing}}$).

### C. Agent Birthing & Delegated Cryptography (DACs)
A human orchestrator retains a highly secure **Parent Key** (Cold Wallet). The AI agent generates a temporary Ed25519 **Node Key** (Hot Wallet). The Parent Key signs a **Delegated Agent Certificate (DAC)** binding the hot key to the parent's identity and stake. The agent uses the Node Key to sign all transient network operations (gossip, signaling, Sieve frames, vouchers) without exposing root keys.

### D. Node Archetypes
1.  **Streamlet Consensus Validators**: High-reputation enterprise nodes running Streamlet BFT to sequence intent settlements, custody Genesis accounts, and receive 20% of demand-gated minting.
2.  **Permissionless Full Nodes**: Staked operators ($S \ge 250,000$ ECHO) running the Contagion SBRB mesh, Basalt peer sampling, ICE-lite multi-homed rendezvous hosting, and edge FX settlement. They receive 80% of demand-gated minting weighted by peer-attested participation.
3.  **Light Nodes (AI Agents)**: Active endpoints authenticating via DACs, connecting to Full Nodes, multi-homing rendezvous points, and executing localized `sci` smart contracts.

### E. Finalized-Block Ledger Execution & Receipt-vs-Execution Semantics
In Streamlet consensus clusters, nodes operate a dual-phase execution pipeline:
1. **Pre-Consensus Staging**: Client burns, transfers, vouchers, and settlement intents are checked against local `spendable-balance` and staged as bounded receipts in `:pending-receipts`. Authoritative ledger balances, mint dust, and treasury revenues remain unmutated prior to consensus finalization.
2. **Post-Finality Execution**: Proposers pack unfinalized receipts into block payloads. Upon 3-chain block finalization, `execute-finalized-blocks` iterates through newly finalized blocks in ascending chain order, applying transfers, deducting signaling burns, executing settlement takes, settling vouchers, and driving demand-gated treasury minting.
3. **FIFO Replay-Protection Horizon**: Receipt and block tracking sets (`:known-receipt-ids`, `:executed-receipt-ids`, `:executed-finalized-blocks`) utilize deterministic FIFO eviction (`fifo-track`) bounded by `:max-tracked-receipts` (default `10,000`), establishing an explicit, deterministic replay-protection horizon while eliminating unbounded set growth.
4. **Burn Digest Diagnostics**: Nodes expose consensus convergence via `burn_digest` (cross-node comparable at the same `finalized_epoch` height) and `finalized_epoch` in `render-statusz` and the `/burnsz` HTTP endpoint, ensuring verifiable, cross-node auditability.
5. **Cross-Node Convergence Audit & Unrooted Finalized-Chain Guard**:
   - `canonical-unexecuted-finalized-chain` enforces an ancestor-continuity guard: when walking backwards from `:latest-finalized-block-hash`, unrooted finalized block suffixes across missing intermediate ancestor blocks are held unexecuted until missing ancestors are synced, preventing premature execution skips (`st-skipped`).
   - Cluster convergence is continuously evaluable via pure `evaluate-cluster-convergence` (`bitecho.shell.mesh`) and `./scripts/cluster.sh audit`:
     - Compares `/burnsz` trailing windows across all nodes for all epochs $e \le \text{common\_finalized\_epoch}$.
     - Asserts finalized epoch skew $\le 2$ epochs and zero failed receipts.
     - Verifies identical `burn_digest` across all nodes at matching finalized epoch heights.

### F. Multi-Peer Session Durability, Failover Rotation & Idempotent Session Replay
Light nodes (AI agents) and edge participants maintain zero-loss, zero-duplication session durability across arbitrary validator restarts, network partitions, and failover rotations:

1. **Deterministic Home-Node & Bootstrap Rotation**:
   - `ordered-validator-candidates` prioritizes registered `:home-set` nodes, followed by remainder bootstrap nodes sorted deterministically by node ID.
   - Rotates candidate order using `:validator-cursor` upon connection failure (`:dial-failed`, `:on-close`, `:send-failed`).
   - Surfaces connection telemetry (`:validator_id`, `:validator_cursor`, `:failover_count`) in connection diagnostics (`conn-diagnostics-summary`).
   - Inbound wire events immediately trigger durable persistence to `state.nippy` via `make-client-callbacks`.

2. **Session Outbox Buffering & Deterministic FIFO Eviction**:
   - Open sessions buffer outgoing sealed messages in `:outbox` (`seq -> {:seq seq :msg-payload msg-payload :burn burn-amt}`) and `:outbox-order`.
   - Buffering is strictly bounded by `:max-outbox-size` (default `64`) with deterministic FIFO eviction of the oldest sequence on overflow.

3. **Signed SACK Reconciliation & Idempotent Deduplication**:
   - Receiver checks sliding replay window (`sealed/check-and-advance-replay-window`) before ChaCha20-Poly1305 decryption, dropping invalid or stale sequence numbers immediately without cryptographic amplification.
   - On accepted messages, advances `:rx-high-seq`, calculates contiguous received horizon `:contiguous-rx-seq`, and responds with a signed `:session-ack` envelope containing cumulative `:ack-seq`, message `:acked-seq`, selective ack vector `:seen-seqs`, and Ed25519 signature over `"ack-<sid>-<ack-seq>-<acked-seq>-<seen-seqs>"`.
   - On duplicate message arrival (`:replayed-seq`), receiver increments `:replays-deduped`, suppresses duplicate inbox entries and stdout events, and re-emits signed `:session-ack` to clear the sender's outbox.
   - Sender validates peer Ed25519 signature on `:session-ack`, advances contiguous `:acked-seq`, and purges selectively and cumulatively acknowledged sequences from `:outbox` and `:outbox-order`.

4. **Idempotent Outbox Replay, Proactive Reconnect & Session-Epoch Wire Authority (Milestone 4 — Pillar A)**:
   - **Proactive Reconnect on `:on-close` (Rule 4 & Rule 5)**: When `:on-close` fires on an active connection generation (`make-client-callbacks`), the boundary shell (`bitecho.shell.light-node`) transitions `conn-atom` through `transition-conn` and drives bounded exponential-backoff retries via `attempt-proactive-reconnect!`. Upon reconnect, it invokes `build-reconnect-recovery-envelopes`, automatically re-registering the agent's `:home-set` (`register-home-set` envelopes at current and nil epochs) and replaying unacknowledged session outbox messages without manual intervention or wrapper scripts.
   - **Gossip Envelope Reuse & Zero Double-Burn**: Replay reuses the cached signed `:gossip-env` stored directly in the `:outbox` entry (`{:seq seq-num :msg-payload msg-payload :burn burn-amt :gossip-env gossip-env}`). This preserves the exact original `:message-id` (`sha256(payload-bytes)`), ensuring validator gossip deduplication suppresses duplicate burns and prevents double-spending.
   - **Session-Epoch Wire Authority**: Sealed message payloads (`:sealed-message`) set `:epoch` to `(long (or (:epoch session) (:epoch state) 0))`, tying message epoch strictly to the open session's established epoch rather than volatile local node epoch advances. Wire receivers evaluate skew against both reference epoch and session epoch (`(or (<= (abs (- msg-epoch ref-epoch)) 2) (<= (abs (- msg-epoch sess-epoch)) 2))`), guaranteeing delivered sessions never drop replayed or in-flight messages due to validator or account sync epoch advances.
   - **Strict `:autonomous? false` Preservation**: Node initialization (`run-serve!` and `run-one-shot!`) and reconnect recovery strictly preserve `:autonomous? false` by default, preventing unexpected auto-acceptance unless `--autonomous` was explicitly specified by the operator.
   - **Transport Durability & Explicit Reaper Eviction (`clj-datachannel`)**:
     - *STUN USERNAME Extraction*: RFC 5389/5245 `0x0001` Binding Requests parse `ATTR_USERNAME` (`0x0006`) into `local-ufrag:remote-ufrag`, rejecting mismatched target ufrags and populating `:remote-ice-ufrag` for symmetric keepalive routing.
     - *Server-Reflexive Isolation*: RFC 5389 `0x0101` Binding Response `XOR-MAPPED-ADDRESS` (`ATTR_XOR_MAPPED_ADDRESS`) records server-reflexive candidates in `:local-candidates` and strictly prevents pollution of `:remote-candidates`.
     - *Traffic-Aware Idleness*: Connection activity is tracked via `:last-any-traffic` across STUN, DTLS handshake/data, and SCTP chunks with association-aware timeouts (`30s` unestablished / `60s` established).
     - *Explicit Reaper Eviction*: Background router table eviction (`should-reap-child?` / `reap-expired-children!`) explicitly halts the child node, fires `:on-close` with `:cause :reaper-timeout`, and emits encrypted DTLS/SCTP `ABORT` chunks closing client endpoints deterministically without socket leaks.
   - Consensus validators forward peer-received gossip to connected agents (`forward-gossip-to-agents!`) and replay cached epoch gossip (`replay-cached-gossip-to-agent!`) upon agent connection and DataChannel identification with connection-scoped message deduplication.

### G. Full-Node Mesh Shell Lifecycle Discipline (Rules 4 & 5)
Full-node WebRTC DataChannel mesh connections (peer-to-peer full-mesh and agent ingress listeners) enforce single-authority lifecycle state machines:

1. **Single-Authority Pure Reducer (`transition-mesh-conn`)**:
   - Connection lifecycle is governed by pure transitions: `(transition-mesh-conn conn event) -> [new-conn effects]`.
   - Phases: `:down`, `:dialing`, `:open`, `:failed`.
   - Side-effects (`:close-node`, `:diagnose`, `:ignore-stale`) are returned as pure effect descriptors and executed strictly outside atomic transitions via `execute-mesh-conn-effects!`.
   - Liveness agreement invariant: `(:ok? conn)` is true if and only if `(= :open (:phase conn))` and `(some? (:channel-id conn))`.

2. **Monotonic Generations & Superseded Node Isolation**:
   - Every connection attempt or accepted DataChannel receives a strictly monotonic `:generation` tag.
   - Any callback bearing a stale generation (`gen < current`) or originating from a superseded `:node` is dropped without mutating connection phase, liveness, active channels, or resources.
   - Stale callbacks increment `:ignored-stale` and emit `:ignore-stale` diagnostic effects.
   - Superseded nodes are closed exactly once upon replacement via `:close-node` effects without relying on `Thread/sleep` or racing atoms.

3. **Agent Sender Rebinding & Cumulative Accounting**:
   - Incoming agent connections authenticate with Ed25519 envelopes and are rebound from anonymous keys to sender public keys via pure `rebind-agent-conn-sender`.
   - Rebinding supersedes previous connection nodes, closes them cleanly, advances generation counters, and preserves cumulative `:dropped` and `:ignored-stale` metrics across reconnects.

4. **Zero Silent Failures & Telemetry (`/statusz` and `/connz`)**:
   - Send failures, malformed frames, and dial errors increment `:dropped` and emit non-silent counted `:diagnose` effects.
   - HTTP endpoint `GET /connz` returns full structured EDN diagnostic summaries for all active peer and agent connections.
   - HTTP endpoint `GET /statusz` surfaces aggregate `conn_dropped` and `conn_stale` metrics alongside consensus and tokenomics telemetry.

### H. Live Signed $ECHO Transfers, DeliveryAck Voucher Settlement & Protocol Settlement Take
1. **Light-Node Account State, `effective-chain-epoch` Decoupling & Economic Commands**:
   - `account` & `sync-account`: Synchronizes on-chain balance, sequence (`seq`), causal dependencies (`deps`), spendable balance, and `finalized_epoch` via `fetch-validator-accountz!` from validator `/accountz` endpoints.
   - **`effective-chain-epoch` Decoupling**: `sync-account` stores `finalized_epoch` in `[:account :finalized-epoch]`. Economic and consensus commands (on-chain DAC expiry, escrow `created-epoch`, `lock-intent`) use `(effective-chain-epoch state)` to resolve the latest finalized consensus epoch without mutating the peer-to-peer wire `:epoch`. This completely decouples on-chain economic horizons from peer-to-peer gossip wire skew tolerance.
   - `transfer`: Validates spendable balance, generates signed transfer gossiped to peers and wrapped in an authenticated `:on-deliver` agent ingress event.
   - `settle-intent`: Dispatches payment intents with mandatory protocol take $\tau = 0.5\%$, debits payer spendable balance, and records burn window contributions upon block finalization.
   - `submit-vouchers`: Compacts valid signed `DeliveryAck` vouchers per channel tuple `[callee home-node epoch]` retaining max `:seq`, submitting to validators via authenticated `:submit-vouchers` events for on-chain settlement debit/credit execution.

2. **Validator Ingress Authentication & Consensus Execution**:
   - `unwrap-authenticated-agent-event` strictly enforces sender identity binding for `:on-deliver`, `:settle-intent`, `:submit-vouchers`, and `:register-home-set`, rejecting signature forgery and parameter spoofing.
   - Consensus state machine stages `:voucher` and `:intent` receipts, checks spendable balances, and applies atomic balance transitions upon block finalization.

### I. Local Petnames & Address Book Discipline (Milestone 2 — Step 2A)
1. **Pure Local 1:1 `:petnames` Address Book (`bitecho.light-node.core`)**:
   - Maintains a local map of `petname -> pubkey-hex` ensuring a strict 1:1 bijection (`(count (:petnames st)) == (count (distinct (vals (:petnames st))))`).
   - Disjoint namespaces: strings matching 88-character hex public keys are rejected as petnames (`valid-petname?`), preventing namespace collisions between raw public keys and local nicknames.
   - Normalization: petnames are trimmed, lowercased, and stripped of an optional leading `@` (`"Axiom"`, `"@axiom"`, `"axiom"` all normalize to `"axiom"`). Public keys are trimmed and lowercased.
   - Protocol verbs:
     - `petname-set`: registers a mapping with conflict detection on collisions (`"petname-conflict"` with existing bindings returned). When `--overwrite` is specified, old bindings for the petname or pubkey are cleanly purged to preserve 1:1 bijection.
     - `petname-list`: enumerates all configured mappings sorted by petname.
     - `petname-remove`: removes a mapping by petname or public key.
     - `petname-resolve`: queries a petname to find its public key or a public key to find its petname.
2. **Transparent Counterparty Resolution**:
   - Commands accept either an 88-char public key or a petname:
     - `offer`: `--callee <petname|pubkey>` resolves to callee public key and enriches responses with `"callee_petname"` and `"peer_petname"`.
     - `accept`: `--session <petname|pubkey|session-id>` resolves pending offers by caller petname/pubkey and enriches responses with `"peer_petname"`.
     - `send` & `close`: `--session <petname|pubkey|session-id>` resolves open/active sessions by peer petname/pubkey and enriches responses with `"peer_petname"`.
     - `transfer` & `settle-intent`: `--receiver <petname|pubkey>` resolves receiver public key and enriches responses with `"receiver_petname"`.
     - `inbox`: enriches received messages with `:from_petname` / `"from_petname"` and pending offers with `:caller_petname` / `"caller_petname"`.
     - `status`: surfaces `"petnames"`, `"petnames_count"`, and `:peer_petname` across session summaries.
3. **Untrusted Wire Injection Immunity**:
   - Inbound wire events (`handle-wire-offer`, `handle-wire-accept`, `handle-wire-sealed-msg`, `handle-wire-close`) enrich emitted stdout events and inbox items using the local address book only.
   - Wire payloads claiming `:petname`, `:nickname`, or `"petname"` are strictly ignored and NEVER imported into or allowed to overwrite local state, preserving the Zooko's Triangle security model where local naming remains sovereign and self-assigned.

### J. Directory-Signed Attestation & Delegated Agent Certificates (Milestone 2 — Step 2B)
Per Axiom Amendment 2, global directory attestation must be signed by the directory authority after agent proof-of-possession, while the agent's self-signature proves key continuity only:

1. **Proof-of-Possession & Continuity (`create-directory-pop` & `verify-directory-pop`)**:
   - Canonical PoP string: `bitecho-directory-pop-v1|<domain>|<nickname>|<pubkey>|<sorted-home-set>|<epoch>|<prev-pubkey>`.
   - Agent signs PoP with current private key (`:pop-signature`).
   - When rotating keys, agent signs the canonical PoP string with previous private key (`:rotation-signature`), establishing cryptographic key continuity without central key custody.
   - Fail-closed verification enforces nickname validity, pubkey format, domain presence, and dual signature verification on key rotation.

2. **Directory Authority Attestation (`sign-directory-descriptor` & `verify-directory-descriptor`)**:
   - Canonical attestation string: `bitecho-directory-attestation-v1|<domain>|<nickname>|<pubkey>|<sorted-home-set>|<mailbox>|<issued-epoch>|<expires-epoch>|<prev-pubkey>|<pop-signature>|<rotation-signature>`.
   - Signed exclusively by the trusted directory authority private key.
   - Verification strictly requires matching the trusted directory authority public key, active validity window, future-epoch guards ($issued \le current + 2$), valid PoP, and verified authority signature.
   - Self-signed descriptors without directory authority signature fail closed (`untrusted-directory-authority` or `invalid-directory-signature`).

3. **Delegated Agent Certificates (DACs: Anchor Key -> Agent Key)**:
   - Cold anchor keys delegate operational authority to ephemeral hot agent keys via DACs (`bitecho.light-node.core`).
   - Canonical DAC string: `bitecho-dac-v1|<anchor-pubkey>|<agent-pubkey>|<issued-epoch>|<expires-epoch>|<max-spend-per-epoch>|<sorted-scopes>`.
   - Deterministic `dac-id` computed via SHA-256 of canonical string; signed by anchor cold key.
   - Strict verification enforcing non-identical keys, agent pubkey matching, epoch validity window, revocation lists, permitted scopes, and anchor signature integrity.
   - Anchor revocation mechanism (`create-dac-revocation` and `verify-dac-revocation`) invalidates delegated certificates deterministically.

4. **Wire Handshake & Mesh Ingress Enforcement**:
   - Channel offers (`offer`) attach active DACs; callee verifies DAC on incoming `:channel-offer`, rejecting invalid/expired/revoked certificates fail-closed and surfacing verified anchor key on `"offer-received"` events.
   - Mesh ingress boundary (`unwrap-authenticated-agent-event`) validates attached envelope DACs against agent identity and epoch, failing closed on signature or validity failure.
   - Verified directory descriptors are cached in `:directory-cache` without mutating local `:petnames`, maintaining sovereign separation between global directory namespaces and local petnames.

### K. Two-Phase Callee-Pays Rendezvous -> Sealed-Channel Key-Exchange Handoff (Milestone 2 — Step 2C)
Connects `bitecho.rendezvous.core` Callee-Pays introduction directly into the ChaCha20-Poly1305 / X25519 sealed channel handshake:

1. **Phase 1: Caller OfferHeader Commitment Binding (`rendezvous-offer` / `:rendezvous-offer-header`)**:
   - Caller generates ephemeral X25519 keypair and deterministic `offer-hash`.
   - Caller cryptographically binds session ID, counterparty identities, epoch, signaling burn, and optional DAC.
   - Caller signs the canonical Phase 1 header string (`bitecho-rendezvous-header-v1|<caller>|<callee>|<offer-hash>|<epoch>|<burn>|<topic>|<home-node>|<dac-id>`).
   - Ephemeral X25519 public key is strictly withheld during Phase 1, stored locally in `:outbound-rendezvous` alongside optional queued initial payload text.

2. **Phase 1b: Callee Policy Verification & DeliveryAck Voucher Issuance (`rendezvous-policy`, `handle-wire-rendezvous-header`, `rendezvous-accept`)**:
   - Callee evaluates incoming offer headers against local pure rendezvous policy (`:min-burn`, `:price`, `:allowlist`, `:home-node`, `:auto-accept?`).
   - Header is rejected fail-closed if burn is insufficient or caller is denied by allowlist.
   - Upon acceptance, Callee generates its own ephemeral X25519 keypair, increments monotonic per-`(home-node, epoch)` sequence counter, and signs a `DeliveryAck` voucher via `rendezvous/create-delivery-ack`.
   - Callee returns `:rendezvous-ack-voucher` containing the signed voucher and callee signature over `bitecho-rendezvous-ack-v1|<caller>|<callee>|<offer-hash>|<callee-x25519>|<epoch>|<ack-sig>`.

3. **Phase 2: Caller Voucher Verification & Key Reveal (`handle-wire-rendezvous-ack`)**:
   - Caller verifies Callee envelope signature and verifies `DeliveryAck` voucher via `rendezvous/verify-delivery-ack`.
   - Verified voucher is recorded into caller's `:vouchers` for future settlement.
   - Caller derives directional session keys (`:tx-key`, `:rx-key`) via `sealed/derive-session-keys` and opens active session.
   - Caller broadcasts `:rendezvous-reveal` containing `:caller-x25519` signed over `bitecho-rendezvous-reveal-v1|<session-id>|<caller>|<callee>|<offer-hash>|<caller-x25519>|<epoch>`.
   - If initial text was queued at offer time, Caller immediately seals the first message via `sealed/seal-message` and emits `:sealed-message` right behind the reveal.

4. **Phase 2b: Callee Commitment Verification & Encrypted Session Establishment (`handle-wire-rendezvous-reveal`)**:
   - Callee verifies caller's revealed `:caller-x25519` against the Phase 1 `offer-hash` commitment (`expected-hash == offer-hash`). Swapped or tampered ephemeral keys fail closed.
   - Callee derives matching symmetric session keys via `sealed/derive-session-keys` (`caller.tx == callee.rx`, `caller.rx == callee.tx`).
   - Callee transitions session state to `"open"`.
   - Inbound queued `:sealed-message` payloads are immediately decrypted and surfaced in Callee's `:inbox`.

### L. Verified-Outcome `$ECHO` Escrow Settlement Primitive (Milestone 3)
Bitecho is strictly single-currency (`$ECHO`). Milestone 3 implements a pure, deterministic escrow / hash-lock settlement primitive (`bitecho.economy.escrow` + `bitecho.state-machine` + `bitecho.shell.mesh` + `bitecho.light-node.core` + `bitecho.shell.light-node`) enabling agents to lock `$ECHO` against verified deliverables and settle atomically on finalized blocks with protocol settlement take:

1. **Deterministic Escrow Commitment & Identification (`compute-escrow-id`)**:
   - Canonical escrow string: `bitecho-escrow-v1|<payer>|<receiver>|<amount>|<deliverable-hash>|<created-epoch>|<expires-epoch>|<nonce>`.
   - Deterministic 64-character SHA-256 hex `escrow-id`.
   - Deliverable commitment: 64-character hex hash commitment of deliverable/outcome/recipe/code artifact (`valid-deliverable-hash?`).

2. **Escrow Lifecycle & Invariants**:
   - **`:lock-intent`**:
     - Locks `$ECHO` amount from payer's balance into `[:escrows escrow-id]`.
     - Fails closed on self-dealing (`payer == receiver`), non-positive amounts, invalid deliverable hashes, expired epochs (`expires-epoch <= created-epoch`), insufficient payer balance, or duplicate escrow IDs.
     - Enforces 168-epoch horizon (`max-escrow-horizon = 168`): requires `(>= created-epoch (- current-epoch 168))` and `(<= (- expires-epoch created-epoch) 168)` so stale or ancient escrows cannot be locked or re-locked after pruning.
     - In consensus mode, pending `:lock-intent` receipts staged in `:pending-receipts` immediately deduct from payer's `spendable-balance`, preventing unfinalized double-locking.
   - **`:release-intent`**:
     - Verified release operates in two supported modes:
       1. **Payer-Authorized Release**: Payer submits release or receiver supplies Ed25519 `:payer-signature` signed over `bitecho-escrow-release-v1|<escrow-id>|<deliverable-hash>` (`sign-escrow-release` / `verify-escrow-release-sig`).
       2. **Cryptographic Preimage / Hash-Lock Release**: Receiver submits non-blank `:preimage` whose SHA-256 equals `:deliverable-hash` (`verify-deliverable-preimage`), guarded by `epoch <= expires-epoch`.
     - Burns mandatory protocol settlement take $\tau = 0.5\%$ (`take-bps = (max 1 configured-bps)`, minimum 1 unit burned for positive amounts via `calculate-escrow-settlement-take`).
     - Net amount is credited to receiver ledger balance; take is recorded into `[:epoch-settlement-takes closing-epoch]`, feeding trailing revenue $R_{\text{trailing}}$ and demand-gated minting.
     - Escrow status transitions to `:released`, recording `:settled-epoch`.
   - **`:refund-intent`**:
     - Timeout refund after `expires-epoch` (`epoch > expires-epoch`), callable by payer or receiver (when sender is present, strictly required that `sender in #{payer receiver}`).
     - Voluntary early cancellation/refund callable by receiver (`:sender == receiver`).
     - Refunds 100% of escrow amount back to payer with zero take burned.
     - Escrow status transitions to `:refunded`, recording `:settled-epoch`.
   - **Mutual Exclusion & Supply Conservation**:
     - Escrows settle at most once: once `:released` or `:refunded`, subsequent competing receipts fail closed and never double-credit.
     - Supply conservation identity holds across all states: $\text{initial\_supply} - \sum \text{released\_takes} = \sum \text{balances} + \sum_{\text{locked}} \text{amount}$.
   - **Bounded Retention & Epoch Pruning (`prune-expired-tick-state`)**:
     - Settled escrows (`:released` or `:refunded`) record `:settled-epoch` and are retained up to `max-escrow-horizon` (168 epochs). Advancing ticks past the cutoff (`cutoff = current-epoch - 168`) prunes settled entries from `:escrows`, while active `:locked` escrows are preserved until settled.
     - Settled escrow IDs are tracked in `:settled-escrow-ids` with deterministic FIFO eviction via `fifo-track` on `:settled-escrow-order`, bounded by `max-tracked-receipts` (default 10,000).

3. **Light-Node State, DAC Spend Authorization & CLI**:
   - Commands: `lock-intent`, `release-intent`, `refund-intent`, `escrows`.
   - `lock-intent` enforces attached DAC spend limits (`check-dac-spend-authorization` with scopes `["lock-intent" "settle" "settle-intent"]` and `:max-spend-per-epoch`).
   - Counterparty addresses support local petname resolution (`pubkey->petname` and `resolve-counterparty`).
   - 100% bidirectional CLI and skill parity across all verbs and flags (`--escrow-id`, `--deliverable-hash`, `--expires-epoch`, `--preimage`).

### M. In-Band Authenticated Chain State Sync (Milestone 5)
Light nodes authenticate ledger balances, spendable sequences, and escrow statuses directly over the WebRTC DataChannel (Port 5010/DTLS) through cryptographic BFT quorum snapshots:

1. **In-Band Wire Protocol (`:query-chain-state` & `:chain-state-snapshot`)**:
   - Client sends authenticated `:query-chain-state` carrying ephemeral nonce and caller pubkey. Ephemeral queries bypass sender connection rebinding in `make-agent-connection-handler`, preserving active agent sessions.
   - Validators respond with a signed `:chain-state-snapshot` containing `:pubkey`, `:finalized-epoch`, `:balance`, `:spendable`, `:seq`, `:deps`, `:escrows`, and Ed25519 `:signature`.
2. **BFT Quorum Buffering & Fail-Closed Verification (`handle-wire-chain-state-snapshot`)**:
   - Light node buffers incoming snapshots keyed by validator in `:chain-state-snapshots`, pruning snapshots older than $fin\_epoch - 2$.
   - Snapshot is applied only when $\ge 2f + 1$ (2 of 3) matching snapshots from `:trusted-validators` reach identical finalized epoch and balances (`verify-chain-state-quorum`).
   - Monotonicity guards prevent stale snapshots from rewinding finalized epochs.
   - Forged or pre-quorum snapshots never mutate `:epoch` or `:epoch-initialized?`.
   - Any local non-terminal escrow (`:locked`, `:release-submitted`, `:refund-submitted`) absent from incoming snapshots and older than $fin\_epoch - 5$ is automatically pruned, while recently-created and terminal escrows are preserved.

### N. Live Directory Authority Service, Multi-Harness Skill Neutrality & Angels Demo (Milestone 6)

1. **Live Directory Authority (`bitecho.org/<nickname>`)**:
   - **Decentralized Key Custody**: Directory Authority cold keypair signs attestation descriptors without custody of agent private keys. Agents prove ownership via self-signed Proof-of-Possession (`create-directory-pop`).
   - **Cryptographic Key Rotation**: Agent signs rotation proof with both current and previous private keys (`:rotation-signature`), establishing continuous trust chains across key updates.
   - **Dual Publishing**: Operators publish descriptors via `./scripts/cluster.sh register-directory`, outputting JSON and human-readable Markdown with embedded JSON codeblocks served at `https://bitecho.org/<nickname>`.
   - **Petname Discipline**: Neither `directory-lookup` nor `directory-verify` mutates local operator petnames. Mapping is established explicitly by operator action (`petname-set`).

2. **Multi-Harness Skill Neutrality Proof (`master-plan` M2)**:
   - Evaluates two heterogeneous agent harness architectures against the live Streamlet BFT cluster:
     - **Harness A**: JSONL external bridge driving line-oriented stdin/stdout envelopes (`process-jsonl-line`).
     - **Harness B**: JVM-native agent driving compiled Clojure maps (`handle-command`).
   - Executes full lifecycle: PoP generation, Directory Authority signing, discovery via `directory-lookup`, callee-pays rendezvous introduction, E2E X25519 sealed channel key derivation, verified-outcome escrow lock, sealed preimage transfer, release with 50 bps protocol take burned, and 3-node BFT quorum snapshot verification.
   - Verifies supply conservation: $\text{initial\_supply} - \text{take\_burned} = \sum \text{final\_balances}$.

3. **Three-Device / `clj-einsum` Angels Demo (`master-plan` M3)**:
   - Demonstrates split pipeline distributed inference across 3 device archetypes backed by the 3-node genesis BFT cluster:
     1. **Device 1 (`phone-light-node`)**: Edge light node with zero local inference; locks `$ECHO` escrow committed to golden deliverable hash and transmits prompt tensor $X$.
     2. **Device 2 (`laptop-stage1-einsum`)**: Receives prompt over sealed channel, computes Stage 1 contraction $Y_{\text{mid}} = \text{einsum}(\text{"ij,jk->ik"}, X, W_1)$, locks Stage 2 escrow, and forwards intermediate activations to Device 3.
     3. **Device 3 (`laptop-stage2-einsum`)**: Receives activations over sealed channel, computes Stage 2 contraction $Y_{\text{out}} = \text{einsum}(\text{"ik,kl->il"}, Y_{\text{mid}}, W_2)$, mechanically verifies tensor parity against golden reference (`verify-tensor-parity`), and delivers verified deliverable preimage to Device 1.
   - Settles both escrows on-chain with 50 bps burn take per stage, validated by 3-of-3 BFT quorum snapshots.
   - Employs honest simulation framing (3 cluster nodes + 3 edge devices), with documented scaling projections to 15, 100, and 1000 nodes.

### O. Wire Protocol Versioning Policy, Treasury SLA Monitoring & Testnet Launch Gates (Milestone 7 / Step 7A)

1. **Wire Protocol Versioning & Rolling-Upgrade Policy (Closing FLAG B)**:
   - **Explicit Version Envelope**: Wire envelopes and light-node message maps include `:protocol-version` (`current-wire-version = 1`, `min-supported-wire-version = 1`, `max-supported-wire-version = 2`).
   - **Rolling-Upgrade Window**: Pure compatibility check `rolling-upgrade-compatible?` enforces that validator and light node software versions within a 1-step window ($|v_1 - v_2| \le 1$) seamlessly interoperate. Legacy unversioned envelopes ($N-1$) are normalized and accepted as version 1 (`:legacy-unversioned? true`).
   - **Fail-Closed Rejection with Counted Diagnostics (Rule 5)**: Unsupported or future versions exceeding the window strictly fail closed without dropping envelopes silently. Rejections increment `:unsupported-dropped`, record `:last-unsupported-version` and `:last-error`, emit structured `{"event": "wire-version-rejected"}` events, and surface under `"wire_protocol"` in `exec-status` and `/connz` diagnostics.
   - **Mesh Ingress Validation**: `valid-agent-envelope-version?` and `wrap-agent-event` / `unwrap-authenticated-agent-event` ensure external agent connections over port 5010 authenticate wire versioning before event dispatch.

2. **Treasury SLA Monitoring & Cluster Convergence Telemetry**:
   - **Pure Conformance Evaluator (`evaluate-treasury-sla`)**: Monitors cluster telemetry against economic and consensus SLAs:
     - Demand gate compliance ($k \le 0.5$, $k\text{-bps} \le 5000$).
     - Supply cap compliance ($\text{total-minted} \le 23.1\text{B}$, $\text{supply} \le 42\text{B}$).
     - Redundant validator infrastructure ($\text{active-validators} \ge 3$, BFT quorum met).
     - Finality health ($\text{finalized-epoch-skew} \le 2$).
     - Zero failed receipts ($\text{max-failed-receipts} = 0$).
     - Mint convergence ($\text{minted-skew} = 0$ when $\text{finalized-epoch-skew} = 0$).
   - **Cluster Convergence Audit**: Integrated into `evaluate-cluster-convergence` and `./scripts/cluster.sh audit`, asserting `/burnsz`, `/accountz`, `/connz`, Treasury SLA, and wire protocol version agreement across all nodes.

3. **Testnet Launch Exit Gates Evaluator (`run-testnet-readiness-gate`)**:
   - Deterministic four-gate readiness evaluator (`master-plan` M4) executing an in-process 4-validator simulation (`node1..node3` genesis + `node4` simulated third-party partner validator with a fresh keypair) to deterministically gate consensus, demand-gate minting ($k = 0.5$), directory attestation, verified-outcome settlement, and rolling-upgrade wire compatibility prior to external multi-operator onboarding:
     1. **Third-Party Validator Finalization**: In-process 4-node Streamlet BFT cluster (`node1..node3` + partner `node4`) finalizing notarized blocks under demand gate ($k = 0.5$).
     2. **Live Directory Resolution**: Directory Authority authenticates cryptographic Proof-of-Possession and resolves nicknames to public keys and home sets, rejecting forged signatures.
     3. **Verified-Outcome Real Workload**: Real tensor einsum workload paying strictly on deliverable preimage SHA-256 hash match, burning mandatory 50 bps protocol settlement take.
     4. **Rolling-Upgrade Wire Compatibility**: Continuity verified across mixed v1, legacy unversioned, and v2 payloads, with fail-closed rejection of v99.

### P. Portable Core + Canonical Bytes (Milestone 8)

1. **Scoped Deterministic Canonical Fressian Codec (`bitecho.fressian`)**:
   - **Portable Type Support**: Portable across Clojure (JVM) and ClojureScript (Node/Browser) without external npm or heavy dependencies, supporting: `nil`, `boolean`, `int64` (compact integer tiers), `bytes` (`byte[]` / `Uint8Array`), `string` (CESU-8 / UTF-8), `keyword`, `vector`, `set`, and `map`.
   - **Deterministic Canonical Ordering (`canonical-compare`)**:
     - Strict type-rank hierarchy: `nil` (0) < `boolean` (1) < `int64`/integer (2) < `float`/`double` (3) < `string` (4) < `keyword` (5) < `symbol` (6) < `bytes` (7) < `vector`/sequential (8) < `set` (9) < `map` (10).
     - Primitive values within identical type ranks are ordered by natural value comparison.
     - Byte arrays (`byte[]` on JVM, `Uint8Array` on CLJS) are compared lexicographically by unsigned byte values `0..255`.
     - Sequential collections (`vector`), sets, and maps compare length/count first, then element-wise via `canonical-compare`.
     - Map keys are sorted deterministically prior to emission, eliminating JVM hash-map vs. V8 object iteration non-determinism.
     - Set elements are sorted deterministically using `canonical-compare` prior to emission.
     - Integers use canonical compact Fressian width tiers (1-byte, 2-byte, 3-byte, 4-byte, 8-byte).
     - Byte arrays and strings encode as raw Fressian chunks with length prefixes. Strings use CESU-8 encoding for full bidirectional parity with `org.clojure/data.fressian` on astral-plane code points (e.g. emoji surrogate pairs).
   - **JVM `org.clojure/data.fressian` Parity**: Full bidirectional interop verified on JVM via `write-standard-fressian` and `read-standard-fressian`, ensuring standard Fressian readers decode what the canonical encoder produces without error.
   - **Domain-Specific Non-Fressian Signing/Digest Constructs**:
     1. *Escrow Release Preimage Binding*: `bitecho.economy.escrow` uses a canonical pipe-delimited string `(str escrow-id "|" preimage "|" epoch)` for deliverable preimage release validation.
     2. *Attestation Exchange Digest*: `bitecho.economy.attestation` uses `(compute-exchange-digest epoch peer-a peer-b message-roles)` which computes a SHA-256 digest over deterministic `(pr-str [epoch peer-a peer-b sorted-roles])` exchange records.
     3. *Rendezvous Inbox Reveal Display*: `bitecho.light-node.core` uses `(pr-str {:session-id session-id :caller caller :epoch epoch :caller-x25519 caller-x25519})` in `deliver-payload` for human-readable / JSONL inbox display of rendezvous reveal events.

2. **N/N-1 Signing-Byte Fallback (`crypto/verify-with-fallback`)**:
   - Helper functions in `bitecho.crypto`:
     - `canonical-signing-bytes [payload]`: deterministic canonical Fressian bytes (`v2` canonical signing format).
     - `legacy-pr-str-signing-bytes [payload]`: UTF-8 bytes of `(pr-str payload)` (`v1` legacy signing format).
     - `sign-canonical [privkey payload]`: signs canonical `v2` bytes using Ed25519.
     - `verify-with-fallback [pubkey payload sig opts?]`: verifies signature against `v2` canonical bytes first, falling back cleanly to `v1` legacy `pr-str` bytes if `v2` fails. Fallback is dynamically gated via `*allow-legacy-v1-signing-fallback*` (default `true`) or per-call `{:allow-v1-fallback? boolean}`.
   - Prevents breaking in-flight or persisted signatures during rolling cluster upgrades across `sieve`, `treasury`, `escrow`, `attestation`, `light_node`, and `mesh`.

3. **Pure Synchronous SHA-256 & Seeded PRNG (`crypto.cljc`)**:
   - **Keyless Synchronous SHA-256**: Maintained as a pure, synchronous Sans-IO function `(crypto/sha256 bytes-or-str)` returning byte arrays / `Uint8Array`. Backed by `java.security.MessageDigest` on JVM and a zero-dependency 64-round pure-CLJS implementation on Node/browser, matching NIST test vectors (including empty string, small ASCII, 55/56/64-byte threshold blocks, and multi-chunk 1000-byte streams).
   - **Portable Seeded PRNG (`IRandom`)**: Protocol providing `next-int`, `next-long`, and `next-double`. Backed by `java.util.Random` on JVM and a 64-bit BigInt SplitMix64 PRNG (`make-random`) on ClojureScript.

4. **Shell-Boundary Crypto Architecture (Decision A(i))**:
   - Pure core reducers (`sieve`, `contagion`, `streamlet`, `state-machine`, `light-node`) remain 100% pure and synchronous Sans-IO.
   - Inbound envelopes are sanitized by `strip-untrusted-crypto-tags` across all ingress and thaw paths (`fressian/decode`, `state-machine/thaw-payload-data`, `light-node.core/thaw-payload`, `light-node.core/unwrap-wire-message`, and `mesh.clj`). Pure validators never short-circuit on untrusted wire tags and always cryptographically verify signatures.
   - `crypto/pre-verify-envelope` executes boundary verification, failing closed with `:crypto/verified? false` and emitting counted diagnostic effect `:diagnose {:effect :diagnose :reason :pre-verify-failed :sender sender}` on signature failure.
   - Outbound signing emits effect descriptors (`:sign-and-emit`, `:seal-and-emit`) when running in asynchronous boundary contexts. `sign-and-emit` fails closed on missing `:private-key` emitting `:sign-and-emit-invalid-input`; `seal-and-emit` fails closed on missing `:seal-fn` or plaintext data emitting `:seal-and-emit-missing-seal-fn` without leaking plaintext.
   - **Runtime Boundaries**: In M8/M9 Node.js environments, cryptographic operations use synchronous `node:crypto`. `WebCryptoBoundary` provides asynchronous W3C Web Cryptography API methods (`subtle-digest-sha256`, `subtle-verify-ed25519`) ready for the browser environment in Milestone 10.

5. **Cross-Runtime Test Parity**:
   - Test suites ported to `.cljc` and executed simultaneously across Clojure 1.12 JVM (`clojure -M:test`) and ClojureScript 1.11 / Node v22 (`clojure -M:test-cljs`).
   - Shared golden vectors in `fressian_test.cljc` verify hex-identical outputs across nested maps, unordered sets, compact integers, and UTF-8 strings.

### Q. Wire Format + Crypto-Suite Negotiation (Milestone 9)

1. **Dual Fressian Wire Codec (`bitecho.fressian`)**:
   - **Wire Separation from Canonical Bytes**: Wire encoding (`encode-wire` / `decode-wire`) is explicitly separated from deterministic canonical signing bytes (`encode-canonical` / `decode`). Wire encoding prioritizes runtime efficiency, extensibility, and seamless Java/Node interop, while canonical encoding guarantees byte-for-byte deterministic invariant hashing across runtimes.
   - **JVM Implementation (`:clj`)**: Uses `org.clojure.data.fressian/write` and `org.clojure.data.fressian/read`. Pre-normalizes Clojure records and lazy sequences into persistent maps/vectors (`normalize-for-wire`) prior to writing, and converts Java collection types (`java.util.List`, `java.util.Set`, `java.util.Map`) back to Clojure persistent data structures (`normalize-decoded-wire`).
   - **ClojureScript Implementation (`:cljs`)**: Uses a zero-dependency pure ClojureScript Fressian codec. Fully supports decoding chunked strings (`tag-string-chunk` 226) and chunked byte arrays (`tag-bytes-chunk` 216) emitted by JVM `org.clojure/data.fressian` writers.
   - **Nippy N/N-1 Rolling Fallback**: On JVM, `decode-wire` inspects the initial byte header. If Nippy magic bytes (`[78 80 89]` = `NPY` or `[-120 78 80 89]`) are present, it falls back seamlessly to `(nippy/thaw ba)`. This guarantees seamless rolling upgrade compatibility with nodes running earlier Nippy wire formats.
   - **Untrusted Crypto Tag Stripping**: `decode-wire` recursively strips shell-boundary tags (`:crypto/verified?`, `:crypto/verified-a?`) at ingress.

2. **Wire Format Versioning & Rolling Upgrade (`bitecho.light-node.core`, `bitecho.shell.mesh`)**:
   - **Format Identifiers**:
     - `current-wire-format`: `"fressian-v1"`
     - `supported-wire-formats`: `#{"fressian-v1" "legacy-nippy"}`
     - `reserved-wire-formats`: `#{"transit-json" "transit-msgpack"}`
   - **Envelope Tagging**: Outbound agent envelopes and wire payloads attach `:wire-format current-wire-format`. Legacy unversioned (N-1) envelopes omitting `:wire-format` are accepted seamlessly.
   - **Fail-Closed Drop & Diagnostics**: Inbound messages carrying unsupported or reserved formats (e.g. `"transit-json"`) are dropped fail-closed. Emits a counted `:diagnose` effect, increments `:unsupported-format-dropped` in state, records `:last-unsupported-format` and `:last-error "unsupported-wire-format"`, and emits a `"wire-format-rejected"` stdout event.
   - **Status Exposure**: `status` and `connz` expose wire format health under `"wire_protocol"`: `{"version" 1, "wire_format" "fressian-v1", "supported_formats" ["fressian-v1" "legacy-nippy"], "unsupported_format_dropped" 0, "last_unsupported_format" nil}`.

3. **Multi-Suite Crypto Architecture & Downgrade Protection (`bitecho.crypto.sealed`)**:
   - **Supported Suites**:
     - `suite-v1-aes256gcm`: AES-256-GCM AEAD with 96-bit nonce derived from 64-bit sequence counter via `seq->nonce`, and 16-byte authentication tag appended to ciphertext.
     - `suite-v1-chacha20poly1305`: ChaCha20-Poly1305 AEAD with 96-bit nonce and 16-byte Poly1305 tag.
     - Default advertised suite order: `["suite-v1-aes256gcm" "suite-v1-chacha20poly1305"]`.
   - **Cross-Runtime Golden Parity**: JDK `Cipher` (`AES/GCM/NoPadding`) and Node.js `node:crypto` (`createCipheriv('aes-256-gcm', ...)` / `createDecipheriv`) produce byte-for-byte identical ciphertext and tag against shared golden test vectors.
   - **Deterministic Suite Negotiation (`negotiate-crypto-suite`)**: Deterministic pure function selecting the caller's highest-priority suite supported by both parties. Fails closed with `{:ok? false :error "no-mutually-supported-crypto-suite"}` when no mutual suite exists.
   - **Cryptographic Downgrade Resistance**:
     - Channel offer: advertised `:crypto-suites` are bound into `offer-hash` via `|<suites-csv>`, signed by the initiator's Ed25519 identity key.
     - Rendezvous offer header: `:crypto-suites` are bound into `canonical-rendezvous-header-str` and signed with Ed25519.
     - Directory Authority descriptor: `:crypto-suites` are bound into the Proof-of-Possession and directory attestation canonical string.
     - Any in-flight stripping or alteration of advertised suites causes signature verification failure, dropping the handshake fail-closed.
   - **Strict Mid-Session Suite Mismatch Rejection**: `open-message` takes `session-suite` and `frame-suite` (6-arity). If a frame attempts mid-session suite substitution (`not= session-suite frame-suite`), decryption fails closed immediately, returning `nil` without leaking plaintext.

### R. CLJS Browser Node Architecture (Milestone 10)

1. **Rule 4 Single-Authority Shell Lifecycle State Machine (`bitecho.shell.browser`)**:
   - **Single Generation-Tagged Connection Map**: The browser node models all connection and session state in a single map atom governed by pure reducer `(transition-conn conn event) -> [new-conn effects]`. Connection liveness (`:connected?`, `:connection-error`) is never split across competing atoms or persisted to storage.
   - **Monotonic Generations & Stale Callback Ignorance**: Every dial/reconnect attempt increments `:generation`. Asynchronous events (WebRTC `ondatachannel`, `onmessage`, `onerror`, `onclose`, ICE state transitions, timers) carry the generation of the originating attempt. Events tagged with stale generations (`gen < current`) are strictly ignored and emit counted `:diagnose` effects with `:reason :stale-generation-event`.
   - **Pure Reducer Transition Table**:
     - `{:type :dial :peer-id ... :wire-format ... :generation ...}`: transitions from `:disconnected` / `:dialing` to `:connecting` if generation is valid; returns `:open-datachannel` effect.
     - `{:type :channel-open :peer-id ... :channel ... :generation ...}`: transitions to `:connected`, recording active channel.
     - `{:type :channel-close :peer-id ... :generation ...}`: transitions to `:disconnected`, clearing channel and emitting `:diagnose` effect.
     - `{:type :channel-error :peer-id ... :error ... :generation ...}`: transitions to `:disconnected`, recording `:last-error` and emitting `:diagnose` effect.
     - `{:type :inbound-frame :bytes ... :generation ...}`: decodes wire bytes; validates wire format against `supported-wire-formats` (`"fressian-v1"` and `"legacy-nippy"`). Unsupported formats (e.g. `"transit-json"`) increment `:unsupported-format-dropped`, record `:last-unsupported-format`, and emit `:diagnose {:reason :unsupported-wire-format}`.
     - `{:type :send-frame :payload ...}`: if connected, emits `:send-wire-frame` effect; if disconnected, drops payload, increments `:dropped-sends`, and emits `:diagnose {:reason :send-while-disconnected}`.
     - `{:type :visibility-change :state :hidden|:visible}`: updates `:visibility-state`; when hidden, incoming non-essential background events increment `:background-throttled-events`.
   - **Zero Silent Failures (Rule 5)**: Every dropped frame, rejected wire format, failed dial, and stale callback produces a counted diagnostic entry in state and an emitted `:diagnose` effect surfaced in `status` / `connz`.

2. **WebRTC DataChannel Transport Interop & Mock Adapter**:
   - Browser boundary binds to native browser `window.RTCPeerConnection` and `window.RTCDataChannel` APIs under secure contexts (HTTPS).
   - Pluggable `RTCAdapter` abstraction enables seamless property and unit testing on both JVM and Node/CLJS without headless browser dependencies, while running identically against real browser `RTCPeerConnection` in production.
   - Standard WebRTC ICE candidate gathering and SDP exchange (offer/answer) signaled over Bitecho mesh rendezvous or HTTPS bootstrap endpoints.

3. **IndexedDB State Persistence & Sanitization (Rule 4 Boundary)**:
   - State persistence is handled via IndexedDB (with pure in-memory atom fallback in non-browser or test environments).
   - **Strict Persistence Sanitization (`sanitize-state-for-persistence`)**: To enforce Rule 4, all derived runtime liveness and transient session secrets are stripped before committing to disk:
     - Ephemeral session private keys (`:ephemeral-priv`, `:ephemeral-private-key`) are erased.
     - Runtime connection flags (`:connected?`, `:connection-error`, `:channel`, `:peer-connection`) are stripped.
     - Diagnostic counters, persistent identity public keys, petnames, and finalized account caches are retained.
   - On node startup / thaw, connection state initializes strictly in `:disconnected` phase at generation 0 or 1, requiring an explicit fresh handshake.

4. **Honest Background-Tab Visibility Throttling Semantics**:
   - Web browsers (Chrome, Firefox, Safari) aggressively throttle timers (to >= 1000ms) and suspend WebRTC processing in backgrounded/hidden tabs.
   - Bitecho browser nodes do **not** claim always-on infrastructure liveness.
   - The shell hooks `document.addEventListener("visibilitychange", ...)`:
     - Foreground (`:visible`): full-speed timer loops, responsive SACK handling, and low-latency rendezvous polling.
     - Background (`:hidden`): enters throttled low-power mode, pauses non-critical heartbeat bursts, and counts deferred or throttled processing cycles in `:background-throttled-events`.
     - Health diagnostics report `:visibility-state` and `:background-throttled-events` honestly in status output.

5. **Reproducible Static Bundle, SRI Hashing & CORS Architecture**:
   - **Reproducible Build Script (`scripts/build-browser-bundle.sh`)**: Compiles ClojureScript to `dist/bitecho-browser.js` with deterministic namespace optimization, verifies byte-for-byte reproducibility against successive runs, and computes SHA-384 and SHA-256 Subresource Integrity (SRI) hashes into `dist/bitecho-browser.js.sri`.
   - **Public Interface (`globalThis.BitechoBrowser`)**: Exposes `initNode`, `getStatus`, `connect`, `createOffer`, `acceptOffer`, `sendSealedMessage`, `runSubnetDemo`, and `version`.
   - **Cross-Origin Resource Sharing (CORS)**: `clj-web` static content handler serves permissive CORS headers (`Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, HEAD, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, Range, If-None-Match`, `Access-Control-Expose-Headers: ETag, X-Checksum-SHA256, Content-Length, Content-Range`) on `GET`, `HEAD`, and `204 No Content` preflight `OPTIONS` requests (while returning `405 Method Not Allowed` without CORS headers on unsupported methods), allowing browser nodes hosted on any origin or `localhost` to fetch bootstrap descriptors and directory attestations.
   - **Secure Context Requirement**: Browser APIs (`SubtleCrypto`, `RTCPeerConnection`) require a Secure Context (`https://` or `http://localhost`).

### S. Human Anchor UX + WebAuthn Architecture (Milestone 11)

1. **BIP-0350 Bech32m Address Encoding (`bitecho.bech32m`)**:
   - **Human-Readable Checksummed Addresses**: Checksummed human-readable encoding for Ed25519 identity public keys formatted with human-readable prefix `ech1...` (e.g. `ech1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`).
   - **Pure Portable Implementation**: Pure Sans-IO `.cljc` implementation with zero third-party library or npm dependencies, adhering to BIP-0350 specifications.
   - **Checksum Polynomial & Bit Re-Grouping**: Uses the Bech32m polymod polynomial generator with constant `0x2bc830a3`. Converts 8-bit byte sequences to 5-bit group arrays via pure `convert-bits`.
   - **Cross-Platform Parity**: Employs cross-platform `char-code` (`#?(:clj (int c) :cljs (.charCodeAt c 0))`) preventing ClojureScript `NaN` bugs during ASCII integer conversions.
   - **Exhaustive Error Detection**: Validates against single-bit flips, bit transpositions, case-mixing, and invalid checksums.

2. **Pure Recursive CBOR Codec (RFC 8949) (`bitecho.cbor`)**:
   - **Standards Compliance**: Zero-dependency pure `.cljc` recursive parser and deterministic serializer conforming to RFC 8949 (Concise Binary Object Representation).
   - **Major Type Support**:
     - Major 0: Unsigned integers (1, 2, 4, 8-byte width headers)
     - Major 1: Negative integers
     - Major 2: Raw byte arrays (`byte[]` on JVM, `Uint8Array` on CLJS)
     - Major 3: UTF-8 text strings (and keywords/symbols encoded as text)
     - Major 4: Ordered arrays/vectors
     - Major 5: Maps/dictionaries
     - Major 6: Semantic tags
     - Major 7: Simple values (`true`, `false`, `nil`)
   - **Streaming Sequence Decoding (`decode-sequence`)**: Decodes concatenated CBOR objects without trailing-byte truncation, enabling seamless parsing of multi-map CTAP2 WebAuthn extensions (e.g. COSE public key map followed by `credProtect` extension map).
   - **Hardware Vector Parity**: Verified byte-for-byte against physical YubiKey 5 hardware captures (91-byte COSE key + `credProtect` extension map; 1049-byte `packed` WebAuthn attestation object).

3. **FIDO MDS v3 Authenticator Strength & Standing Constraint 6 (`bitecho.fido`)**:
   - **AAGUID Metadata Registry**: Embedded registry of FIDO Alliance certified metadata statements for hardware authenticators including YubiKey 5 Series (`2fc0579f-8113-47ea-b116-bb5a8db9202a`), YubiKey 5 FIPS, Windows Hello, Apple Touch ID / Face ID, and Android KeyStore.
   - **Standing Constraint 6 Compliance**: FIDO MDS v3 authenticator strength evaluations (`evaluate-authenticator-strength`) and MDS JWT parsing (`parse-mds-jwt-unverified`) are explicitly marked:
     - `:verification-status "UNVERIFIED"`
     - `:label "UNVERIFIED"`
     - Mandatory warning string: `"Standing Constraint 6: FIDO MDS v3 authenticator strength evaluations and MDS JWT parser are labeled UNVERIFIED pending full x5c attestation chain verification."`
   - **Parked Central Enrollment**: Centralized Yubico enrollment is explicitly designated `:yubico-enrollment :parked` due to fundamental architectural tension with the decentralized ethos of self-sovereign mesh participation.

4. **WebAuthn Credential Architecture & Delegation (`bitecho.webauthn`)**:
   - **Discoverable Credential Seed Pattern**: Uses `navigator.credentials.create` with `residentKey: "required"` and `credProtect: "userVerificationRequired"`. Stores a 32-byte cryptographic seed in `user.id` on the hardware authenticator, generating deterministic identities without exposing secrets to a remote server.
   - **Seed Recovery & PRF Extension**: `navigator.credentials.get` with `allowCredentials: []` recovers the 32-byte seed from `response.userHandle`. The WebAuthn PRF extension (`{:prf {:eval {:first ...}}}`) is supported as a standardized seed-release mechanism.
   - **Cold-Certifies-Hot DAC Delegation**:
     - Hardware-derived identity key acts as long-lived cold anchor key.
     - Cold anchor issues Delegation Authorization Certificates (DAC) via `cold-certify-hot-key` / `light-core/create-dac` granting scoped permissions to short-lived hot keys.
     - Autonomous agents run high-frequency tasks using hot keys while human anchors retain sovereign control.
   - **Emergency Revocation**: Anchor issues signed revocation certificates (`revoke-agent-dac`) broadcasting immediate termination of compromised or rotated hot keys.
   - **Redundancy & Fallbacks**:
     - Second-key backup registration (`register-backup-key`, `recover-from-backup-key`).
     - Native non-extractable WebCrypto key specification (`generate-non-extractable-keypair-spec`) with explicit disclosure that non-extractable keys cannot be backed up.
   - **Origin-Scoping & Trust Boundary Disclosures**:
     - Hardware credentials are bound to `window.location.origin`; self-hosted deployments must re-register per origin.
     - Trust boundary: recovered seed entropy passes through browser memory; users must trust local hardware, OS, and browser runtime.

5. **Human Anchor UX & Supervised Reducer (`bitecho.anchor.core`, `bitecho.browser-main`)**:
   - **Pure Sans-IO Reducer**: State transitions modeled in pure Clojure/ClojureScript data structures.
   - **Human-in-the-Loop Offers**: Incoming service requests hold in `:pending-offers` queue awaiting explicit human approval (`approve-offer`) or denial (`deny-offer`).
   - **Supervised Agent Management**: Track supervised agents, log delegated activity, and enforce spending and capability boundaries.
   - **Team-Call Subnets**: Groups of human anchors in active voice/video calls can dynamically spin up ad-hoc subnets (`create-team-call-subnet` `"team-call/<topic>"`).
   - **Verifiable Browser Dashboard**: Dark-mode dashboard in `dist/index.html` exposing Bech32m addresses, key mode selection, prominent `[ UNVERIFIED ]` FIDO strength badge, offers review, supervised agent controls, and real-time diagnostic logs.

---

### T. Fractal Composition & Federation Architecture (Milestone 12)

1. **Subnets (Fractal Down) & Multi-Subnet Multiplexer (`bitecho.light-node.core`, `bitecho.state-machine`)**:
   - **Subnet Identity (`:subnet-id`)**: Envelopes and state-machine instances carry an explicit `:subnet-id` string, defaulting to `"global"` when omitted for 100% N/N-1 rolling-upgrade compatibility.
   - **Isolation & Fail-Closed Routing (Rule 5)**: If an incoming envelope targets an unregistered or mismatched subnet (when neither is wildcard `*`), single-instance reducers drop it with a counted `:subnet-mismatch-dropped` diagnostic effect.
   - **Single-Authority Shell Lifecycle Multiplexing (Rule 4)**: The multi-subnet multiplexer (`init-multi-subnet-multiplexer`, `register-subnet-instance`, `remove-subnet-instance`, `route-multiplexed-envelope`, `dispatch-multiplexed-command`) routes envelopes across multiple `{subnet-id -> state-machine}` instances over a single shared connection state (`:conn`), ensuring connection lifecycle is never split across competing atoms.
   - **Zero-Burn Team Subnets**: Subnet instances configure per-instance economy parameters (`:economy-enabled? false`, `:burn-floor 0`). In permissioned, enterprise, or team topologies, offers, messages, and state transitions process without requiring ECH balances or deducting burned fees.

2. **Domain-Anchored Discovery & Federation (Fractal Up) (`bitecho.shell.discovery`, `bitecho.light-node.core`)**:
   - **Domain-Anchored Descriptors**: Authoritative domains publish cryptographic bootstrap descriptors (via DNS TXT / DoH or HTTPS) declaring validator topologies, authority pubkeys, issued epochs, and expiration epochs.
   - **Cryptographic Verification**:
     - `normalize-nodes-for-bootstrap`: Deterministically sorts validator nodes into a canonical sequence.
     - `canonical-bootstrap-payload`: Constructs the canonical byte tuple `["bitecho-bootstrap-descriptor-v1" domain nodes authority-pubkey issued-epoch expires-epoch]`.
     - `sign-bootstrap-descriptor` & `verify-bootstrap-descriptor`: Ed25519 signing and verification with clock-skew and epoch expiration validation.
     - `verify-federated-domain-bootstrap`: Validates that a domain descriptor was signed by the expected authority pubkey and has not expired.
   - **Federated Rendezvous & Inter-Subnet Relay**: Subnet coordinators broadcast signed rendezvous advertisements (`build-subnet-advertisement`, `parse-subnet-advertisement`) carrying `:subnet-id`, `:topic`, supported crypto suites, and wire formats, allowing peers to discover and route across domain boundaries.

3. **Cross-Subnet Rollup & State-Root Settlement Anchoring Specification (Milestone 12B Spec-Only)**:
   - **Subnet State Roots**: Each child subnet periodically computes a cryptographic state root $R_{t} = \text{MerkleRoot}(\mathcal{S}_t)$ over its finalized local ledger and state machine state at epoch $t$.
   - **Rollup Commitment Tuples**: The rollup commitment posted by the subnet coordinator to the parent/settlement chain is defined as:
     $$\mathcal{C} = \langle \text{"bitecho-subnet-rollup-v1"}, \text{subnet-id}, \text{parent-epoch}, \text{child-epoch}, R_{t}, \text{prev-rollup-hash}, \text{batch-receipts-hash}, \text{withdrawal-merkle-root} \rangle$$
   - **Settlement Chain Invariants**:
     - **Monotonicity**: Successive rollups for a subnet must strictly advance `child-epoch` ($t_{i+1} > t_i$).
     - **Predecessor Continuity**: Each rollup must hash-chain to the previous rollup commitment ($\text{prev-rollup-hash} = H(\mathcal{C}_{i-1})$).
     - **Multi-Quorum Certification**: In consensus subnets, the rollup commitment must be signed by at least $2f+1$ notarized validator votes or the authoritative coordinator key.
   - **Cross-Subnet Withdrawals & Asset Transfers**:
     - **Two-Phase Lock and Mint / Burn and Release**: To transfer value or state between subnets, the source subnet executes an intent lock/burn producing a cryptographic receipt $\mathcal{R}_{\text{xfer}}$.
     - **Inclusion Proofs**: The receipt $\mathcal{R}_{\text{xfer}}$ is anchored in the source subnet's `withdrawal-merkle-root`.
     - **Settlement Verification**: The destination subnet verifies the Merkle inclusion proof against the source subnet's finalized state root anchored on the global/parent settlement chain before minting or unlocking funds.
   - **Fraud & Validity Windows**:
     - Spec-only protocol parameter defines a challenge window $\Delta_{\text{challenge}}$ (default: 3 epochs) during which dispute proofs or state inconsistencies can be challenged before final state withdrawal execution.








