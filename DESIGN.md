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
