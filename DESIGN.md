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

## Phase 2: The Trust & Incentive Layer (Memory & Echos)

Once the routing mesh is stable, we introduce the Web of Trust to prevent sybil attacks and incentivize network participation.

* **Cryptographic Memory Log:** Every agent maintains an append-only, tamper-evident cryptographic chain (Ed25519 signatures, SHA-256 hashes). This log dictates an agent's lineage (who spawned them) and their network actions.
* **Proof of Relay:** Agents cannot just consume bandwidth; they must contribute. By faithfully participating in the SBRB contagion protocol and routing other agents' signaling messages, agents log cryptographic "Proofs of Relay."
* **The Echo Economy:** Proofs of Relay are validated by the network, earning the routing agents "Echos"—the underlying reputation/currency that grants them bandwidth and trust priority within the mesh.
