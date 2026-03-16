# Bitecho Architecture Overview

Bitecho is a decentralized, permissionless WebRTC signaling network and cryptographic Web of Trust designed specifically for autonomous AI agents. It eliminates the need for centralized signaling servers (like WebSockets) by routing WebRTC SDP offers and answers directly through a peer-to-peer mesh network, built on top of the pure-functional `datachannel-clj` library.

The architecture is implemented in phases, separating the base routing layer from the cryptographic incentive layer.

## Phase 1: The Network Layer (SBRB & Gossip)

### 1. Basalt (Byzantine-Resilient Peer Sampling)
Basalt is the foundational peer sampling layer. Instead of relying on a centralized tracker, Basalt provides each node with a continuously updating, randomized, and mathematically robust subset of network peers (a "view"). It uses secure hashing (IP/Port/Pubkey) to prevent Sybil attacks and eclipse attacks, ensuring the network topology remains connected and highly resilient to malicious or churning nodes.

### 2. The Contagion Stack (Routing & Broadcasting)
To route WebRTC SDP offers/answers across the Basalt mesh without central servers, we use a 3-layered epidemic broadcast protocol stack based on the "Contagion" family of algorithms:

* **Layer A: Murmur (Probabilistic Broadcast):** The base gossip layer. When a node wants to signal a peer, it "murmurs" the message to a random subset of its Basalt view. Receivers recursively forward it. It is fast and highly scalable, but provides no guarantees against message duplication, omission, or malicious equivocation.
* **Layer B: Sieve (Probabilistic Consistent Broadcast):**
    Builds on top of Murmur. Sieve adds history buffers and cryptographic signature verification to filter out duplicate messages and detect byzantine equivocations (e.g., a malicious node sending conflicting signaling data to different parts of the network). It guarantees that if one honest node delivers a message, all honest nodes eventually deliver the *same* message.
* **Layer C: Contagion (Probabilistic Reliable Broadcast):**
    The top routing layer. Contagion builds on Sieve by adding anti-entropy and lazy push/pull recovery mechanisms. If the initial Murmur/Sieve wave dies out due to massive network churn (agents dropping offline), Contagion guarantees that the signaling payload will reliably reach all non-faulty nodes with extremely high probability.

### 3. The Pure State Machine (Sans-IO)
The Bitecho core will model these three layers purely. The state machine will accept inputs (e.g., `{:type :receive-gossip :payload ...}`), transition the internal Basalt views and Sieve history buffers, and emit pure outputs (e.g., `{:network-out [{:dst peer :payload ...}]}`) to be handled by the external WebRTC shell.

## Phase 2: The Echo Economy & Dual-Ticket Tokenomics
To prevent Sybil attacks and incentivize routing, the network utilizes a cryptographic token called an "Echo", powered by a zero-latency probabilistic tokenomy.

### Lottery Ticket (Probabilistic Micropayment)
To prevent ledger bloat, routing fees are not processed as 1:1 micro-transactions. Senders attach a cryptographically signed "lottery ticket" (a nonce) to their messages. Routing agents hash the ticket; if the hash falls below a specific network difficulty target, the ticket "wins" and the agent cashes it in on the ledger for an Echo payout. The expected value equals the routing fee.

### Dual-Ticket Priority Lane
The network utilizes a Dual-Ticket system to manage the queue and treasury:
* **Mint Tickets:** Routers hash these to win Echos from the 42M Treasury. These tickets subsidize early network growth without requiring the sender to spend their own balance.
* **Fee Tickets:** Agents can attach existing UTXOs to a ticket with a lower difficulty. Routers prioritize these in the Stake-Weighted Ingress (SWQoS) queue because they guarantee a higher probability of an immediate payout, creating a direct fast-lane for premium traffic.

### Activity-Based Logarithmic Decay
The network treasury dynamically adjusts the difficulty to mint new tokens via an Activity-Based Logarithmic Decay emission curve. The mathematical formula governing this is: `Target = BaseTarget * (TreasuryBalance / 42000000)`. This seamlessly transitions the network from an inflationary bootstrap phase to a pure fee market without requiring a global clock or hard forks. As the treasury depletes, the target shrinks, naturally decaying the emission based on network activity.

### Quorum Settlement (>50% Stake)
When a router wins a Mint Ticket, it must broadcast the winning ticket and the proof or relay receipt to nodes representing >50% of the active network stake. Having this accepted into their local ledger establishes a Quorum Settlement, which will unlock the Treasury UTXO and credit the winning router.

## Phase 3: WebRTC Circuit Discovery & Directed Messaging

### The WebRTC ICE Candidate Burst Problem
Agents cannot just blindly send WebRTC SDP offers or ICE candidates into the void. This results in heavy candidate bursts across unstable routes. To establish a reliable peer-to-peer connection, agents need low-latency, confirmed circuits prior to signaling.

### Circuit Discovery Protocol (Ping/Pong)
Bitecho replaces blind routing with a zero-latency Circuit Discovery Protocol:
* **Ping (Route Request):** Agent A sends a stake-weighted Ping to its highest-staked peers. The high-stake "backbone" of the network routes this toward Agent B.
* **Pong (Circuit Locked):** Agent B receives the Ping containing the physical path (e.g., `[A, Router1, Router4, B]`) and sends a Pong back down the exact circuit. This locks the route for subsequent signaling.

### Transient Proof of Relay
Routers do not store infinite logs. Instead, Bitecho redefines Proof of Relay as a Transient Receipt. To claim a Lottery Ticket, the edge router *must* successfully complete the Ping/Pong + SDP delivery circuit and obtain transient cryptographic signatures from *both* Agent A and Agent B. This mathematically eliminates black-hole attacks and counterfeiting, forcing a Nash Equilibrium where honest routing is the only profitable strategy. Only edge routers (e.g., Router1 or Router4 in the above path) are eligible to claim the ticket.

## Phase 4: Decentralized Service Economy & Payment Channels

### Programmable UTXOs (Clojure Puzzles)
To support complex negotiations, UTXOs are no longer simply locked to a static public key. Drawing inspiration from ChiaLisp, Bitecho UTXOs are locked by a "Puzzle"—a pure, deterministic script written in a strictly sandboxed, non-Turing-complete subset of Clojure. To spend a UTXO, the spender must broadcast a transaction containing the "Solution" (arguments) that, when evaluated against the Puzzle by the network's pure state machine, returns `true`.

**The Sandbox (SCI):** Because agents must evaluate untrusted Puzzle scripts broadcast by peers, the network utilizes the Small Clojure Interpreter (`sci`). Puzzles are evaluated in a hermetically sealed, pure-functional sandbox with a strict execution gas limit. All side-effecting functions (like disk I/O, network requests, or `atom` mutations) are completely disabled. If a script exceeds the gas limit or attempts an illegal operation, the transaction is rejected.

### Off-Chain Payment Channels (Streaming Echos)
Continuous services (like streaming video or relaying bandwidth) cannot wait for network consensus for every byte. Drawing inspiration from the Bitcoin Lightning Network, agents use the Programmable UTXOs to open a 2-of-2 multisig "Payment Channel" between them. Once the Echo UTXO is locked on-chain, the two agents establish a direct WebRTC DataChannel (discovered via Phase 3 Directed Messaging) and exchange cryptographically signed, off-chain state updates that adjust their respective balances. Either party can close the channel at any time by broadcasting the latest mutually signed state to the Bitecho mesh, which settles the final UTXO balances.

### Decentralized TURN & Relay (The First Service Market)
The first native service of this economy is Decentralized TURN. Since many agents reside behind strict Symmetric NATs, they cannot form direct peer-to-peer connections. Any agent on the network with an open, publicly accessible port can advertise itself as a Relay Node. A restricted agent uses Phase 3 to negotiate a session with a Relay Node, opens a Payment Channel, and begins streaming off-chain Echos to the Relay Node continuously, priced dynamically per megabyte of WebRTC traffic relayed. This creates a decentralized, permissionless, free market for network bandwidth, turning Bitecho into a decentralized AWS for AI agents.

## Phase 5: The Executable Shell & Network Genesis

### A. The Declarative Flow Shell (`core.async.flow`)
To seamlessly interface the mathematically pure `bitecho.state-machine` with the external IO runtime, we adopt a Declarative Flow Shell using `clojure.core.async.flow`. This architecture perfectly preserves the Sans-IO constraint.

The topology is cleanly bifurcated: a single `:net-in` channel multiplexes all raw external events (network packets, clock ticks, and IO callbacks) and funnels them directly into the pure `:bitecho-core` step function. This step function computes the new state and deterministically yields pure commands to a `:net-out` channel. An entirely separate, "dumb" side-effecting loop consumes `:net-out`, executing the prescribed IO (e.g., transmitting UDP packets, writing to disk) without containing any business logic.

### B. The Genesis State (The 42M Cap)
An absolute, unbreakable network invariant anchors the Bitecho economy: the total supply is mathematically hard-capped at exactly **42,000,000 Echos**.

The network initializes from a deterministic, cryptographically hashed `genesis.edn` state. At boot, this entire 42M supply is fully minted and allocated into a foundational set of UTXOs. These initial UTXOs are locked by programmatic Clojure Puzzles, staged for controlled distribution, vesting, or direct claim by the founding entities, ensuring verifiable scarcity from block zero.

### C. Agent Birthing & Delegated Cryptography (DACs)
Deploying AI agents across diverse, potentially vulnerable infrastructure requires a robust security model to prevent the compromise of root cryptographic identity and stake. To solve this, Bitecho employs a Delegated PKI model.

A human operator or orchestrator retains a highly secure **Parent Key** (analogous to a Cold Wallet). Because the actual AI agent operates in a live environment, it generates its own temporary, disposable Ed25519 **Node Key** (Hot Wallet) upon booting.

During the "birthing" process, the Parent Key cryptographically signs a **Delegated Agent Certificate (DAC)**. This DAC securely binds the disposable Node Key to the Parent's primary identity and stake. The active agent subsequently uses its hot Node Key to sign all transient network operations—such as Murmur/Sieve gossip and TURN session negotiations—cryptographically proving its authority and economic stake to the mesh without ever exposing the Parent's root cryptographic materials to the hot environment.

### D. Node Archetypes (Bootstrap vs. Agent)
The network relies on two distinct execution archetypes:

*   **The Bootstrap Node:** The static anchor of the network. It binds to a publicly accessible, well-known port and is responsible for initializing the Genesis ledger. It operates as a passive, ICE-Lite entry point, serving strictly to help new peers discover the active mesh.
*   **The Agent Node:** The active, dynamic participant. Upon the birthing sequence, an Agent Node utilizes its DAC to authenticate. It connects to the Bootstrap node, triggers a Contagion pull request to seamlessly sync the ledger state and Basalt peer views, and immediately begins actively participating in the decentralized service economy, routing traffic, and exchanging services.
