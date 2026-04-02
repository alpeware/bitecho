# Bitecho Architecture Overview

Bitecho is a decentralized, permissionless WebRTC signaling network and cryptographic Web of Trust designed specifically for autonomous AI agents. It eliminates the need for centralized signaling servers (like WebSockets) by routing WebRTC SDP offers and answers directly through a peer-to-peer mesh network, built on top of the pure-functional `datachannel-clj` library.

The architecture is explicitly designed around a **Full Node vs. Light Node (Agent)** dichotomy to scale to 100+ million concurrent agents while minimizing egress bandwidth and latency.

## Phase 1: The Network Layer (SBRB & Gossip)

### 1. Basalt (Byzantine-Resilient Peer Sampling)
Basalt is the foundational peer sampling layer for the **Full Node backbone**. It provides each Full Node with a continuously updating, randomized, and mathematically robust subset of network peers. It uses secure hashing (IP/Port/Pubkey) to prevent Sybil attacks and eclipse attacks, ensuring the network topology remains connected and highly resilient.

### 2. The Contagion Stack (Routing & Broadcasting)
To route global state (specifically routing tables and ledger updates) across the Full Node mesh without central servers, we use a 3-layered epidemic broadcast protocol stack:
* **Layer A: Murmur (Probabilistic Broadcast):** The base gossip layer. Guarantees *Validity* and *Totality* but not *Consistency*.
* **Layer B: Sieve (Probabilistic Consistent Broadcast):** Upgrades Murmur via history buffers and Echo Samples ($E$) to guarantee *Consistency*.
* **Layer C: Contagion (Probabilistic Reliable Broadcast):** Upgrades Sieve via Ready Samples ($R$) and Delivery Samples ($D$) to guarantee *Totality*.

**The Full Node / Light Node Split:** Light Nodes (AI Agents) do **not** run the heavy Contagion stack. Instead, Full Nodes run the SBRB mesh and broadcast ~120KB Cuckoo/Bloom filters containing the public keys of their connected Light Nodes every epoch (e.g., 5 minutes). Agents simply query their connected Full Node for routing paths.

### 3. The Pure State Machine (Sans-IO)
The Bitecho core models these layers purely. The state machine accepts inputs, transitions internal Basalt views and Sieve history buffers, and emits pure outputs to be handled by the external IO shell.

## Phase 2: The Echo Economy & Tokenomics

To prevent Sybil attacks and incentivize routing infrastructure, the network utilizes an account-based cryptographic token called an "Echo", powered by a 42 Billion pre-mine and asynchronous settlement. **Bitecho does NOT use a UTXO model or global consensus for basic transfers.**

### Asynchronous Account-Based Settlement (Consensus Number 1)
Based on the academic proof that single-owner accounts have a Consensus Number of 1, global consensus is not required to prevent double-spending. 
* Agents maintain a local, strictly incrementing sequence number (`seq[q]`) and a cryptographic causal history (`deps`).
* Agents broadcast signed transfers.
* Full Nodes locally validate that `seq` is incremented by exactly 1, causal dependencies match, and the balance is $\ge 0$. The transfer is applied immediately without global voting.

### Burn-and-Mint Equilibrium & Proof of Delivery
* **The Burn:** When Agents query routing paths or utilize the network, they pay micro-fees in $ECHO. These fees are instantly **burned** (removed from the total supply) via the asynchronous broadcast.
* **The Mint:** Upon successful routing, Agents generate a probabilistic cryptographic "Proof of Delivery" receipt for the routing Full Node.
* Full Nodes aggregate these receipts and submit them to the Treasury to claim yield.

### The Streamlet Treasury ($k$-Shared Asset Transfer)
The 21 Billion Yield Pool is held in a massive Treasury account. Because the Treasury has multiple owners (the Federated Genesis Partners), it operates as a $k$-shared asset transfer object (Consensus Number $k$).
* The Genesis Partners run an isolated, high-performance **Streamlet BFT** cluster strictly among themselves.
* Streamlet continuously runs the "propose-vote" paradigm on the submitted Proof of Delivery receipts.
* Once a block of payouts is notarized and finalized by the Streamlet cluster, the Treasury assigns a sequence number and broadcasts the payout transfer to the broader SBRB mesh.

## Phase 3: WebRTC Circuit Discovery & Client-to-Rendezvous Routing

Agents require low-latency, confirmed circuits to establish Trickle ICE peer-to-peer connections. Bitecho utilizes a "Client-to-Rendezvous" topology, drastically reducing latency by eliminating the originating Full Node from the data plane.

### The Rendezvous Protocol
1.  **The Routing Query (A $\rightarrow$ FNA):** Agent A queries its host (Full Node A) for Agent B. FNA checks the synchronized global routing table (built via Bloom filters) and responds: "Agent B is on Full Node B (FNB)."
2.  **The Rendezvous (A $\rightarrow$ FNB):** Agent A opens a direct, transient connection to FNB (which operates as an ICE-lite node with a static IP/Port). Agent A submits its SDP Offer directed at Agent B, attaching a cryptographic micro-transfer fee.
3.  **The Relay:** FNB verifies Agent A's fee locally. FNB then acts as the single rendezvous point, pushing the SDP Offer down to Agent B, relaying the SDP Answer back to A, and shuttling Trickle ICE candidates between them.
4.  **P2P Liftoff:** Once STUN/TURN candidate pairs punch through the NAT, Agents A and B establish a direct WebRTC DataChannel and sever the transient connection to FNB.

## Phase 4: Decentralized Service Economy & Transaction Bundling

### Decentralized TURN & Streaming Micro-transfers
Continuous services (like TURN bandwidth relay) do not require complex Lightning-style payment channels. 
* Agent A streams unidirectional micro-transfers (incrementing `seq`) directly to the Relay Node (e.g., FNB) as data is consumed.
* The Relay Node verifies the sequence and signature locally, keeping the bandwidth flowing with zero network latency.

### Transaction Bundling (Egress Optimization)
If Full Nodes broadcasted every micro-transfer immediately to the SBRB mesh, egress bandwidth would collapse the network. 
* **The Batch:** Full Nodes hold collected micro-transfers from their connected Agents in a local memory buffer.
* **The Bundle:** On a regular interval (e.g., 10 seconds), the Full Node wraps all buffered micro-transfers into a single array payload and triggers one Murmur/Contagion broadcast.
* Receiving nodes unpack the bundle and sequentially validate the incrementing `seq` rules locally.

### Programmable Smart Contracts (SCI Sandbox)
For complex, multi-party negotiations (escrow, compute bounties), Bitecho uses the Small Clojure Interpreter (`sci`) in a hermetically sealed, pure-functional sandbox with a strict gas limit.
* **Localized Execution:** Complex scripts are modeled as $k$-shared asset transfers. The global mesh does **not** evaluate the script.
* **Ephemeral Streamlet:** Only the $k$ agents involved run a localized, ephemeral Streamlet BFT consensus to evaluate the `sci` script. Once consensus is reached, the final state is signed by the quorum and broadcast to the SBRB mesh for simple signature verification and ledger updating.

## Phase 5: The Executable Shell & Network Genesis

### A. The Declarative Flow Shell
The topology is bifurcated: a `:net-in` channel multiplexes all raw external events into the pure `:bitecho-core` step function. This function computes the new state and deterministically yields pure commands to a `:net-out` channel. An entirely separate, "dumb" side-effecting IO loop consumes `:net-out` to transmit UDP packets or write to disk.

### B. The 42 Billion Genesis Allocation
The network initializes from a deterministic `genesis.edn` state, hard-capping the supply at 42,000,000,000 $ECHO, distributed as follows:
* **50% (21B): Decentralized Routing Treasury (Yield Pool).** Locked in the Streamlet PBFT smart contract, emitted via an Activity-Based Logarithmic Decay curve.
* **20% (8.4B): Federated Genesis Partners.** Subsidizes the enterprise backbone of initial Full Nodes (subject to 1-year cliff, 3-year vest).
* **15% (6.3B): Agent Ecosystem & Developer Grants.**
* **15% (6.3B): Core Architecture & Protocol Security.** (Subject to 4-year vest).

### C. Agent Birthing & Delegated Cryptography (DACs)
A human orchestrator retains a highly secure **Parent Key** (Cold Wallet). The AI agent generates a temporary Ed25519 **Node Key** (Hot Wallet). The Parent Key signs a **Delegated Agent Certificate (DAC)** binding the hot key to the parent's identity and stake. The agent uses the Node Key to sign all transient network operations (gossip, payments, SBRB routing) without exposing root cryptographic materials.

### D. Node Archetypes
1.  **Federated Genesis Partners:** Strategic B2B nodes running the isolated Streamlet consensus to sequence and manage the Treasury payouts.
2.  **Permissionless Full Nodes:** High-bandwidth operators staking $ECHO. They run the Contagion SBRB mesh, broadcast routing Bloom filters, act as ICE-lite rendezvous points, and bundle micro-transactions.
3.  **Light Nodes (AI Agents):** The active, dynamic endpoints. They authenticate via DACs, connect to Full Nodes, query routes, and execute off-mesh P2P connections and localized `sci` smart contracts.
