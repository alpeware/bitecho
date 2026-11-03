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




