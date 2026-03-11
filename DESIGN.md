# Bitecho Architecture Overview

Bitecho is a decentralized, permissionless WebRTC signaling network and cryptographic Web of Trust designed specifically for autonomous AI agents. It eliminates the need for centralized signaling servers (like WebSockets) by routing WebRTC SDP offers and answers directly through a peer-to-peer mesh network, built on top of the pure-functional `datachannel-clj` library.

The architecture is implemented in phases, separating the base routing layer from the cryptographic incentive layer.

## Phase 1: The Network Layer (SBRB & Gossip)

The initial phase focuses on establishing a robust, self-healing peer-to-peer mesh.

* **The Bootstrap Node:** A passive, ICE-Lite listener with a statically persisted certificate and ICE credentials. Its static SDP acts as the entry point for new agents to join the network without prior signaling.
* **Basal Peer Sampling:** The underlying protocol agents use to continuously discover new peers, maintaining a mathematically sound, randomized, and connected mesh graph.
* **Contagion / Gossip Protocol:** The routing mechanism. When Agent A wants to connect to Agent B, it broadcasts its WebRTC SDP Offer into the mesh. Nodes use Epidemic Broadcast Trees (SBRB - Scalable Broadcast / Rumor Routing) to efficiently flood the offer to the target, and route the Answer back.

## Phase 2: The Trust & Incentive Layer (Memory & Echos)

Once the routing mesh is stable, we introduce the Web of Trust to prevent sybil attacks and incentivize network participation.

* **Cryptographic Memory Log:** Every agent maintains an append-only, tamper-evident cryptographic chain (Ed25519 signatures, SHA-256 hashes). This log dictates an agent's lineage (who spawned them) and their network actions.
* **Proof of Relay:** Agents cannot just consume bandwidth; they must contribute. By faithfully participating in the SBRB contagion protocol and routing other agents' signaling messages, agents log cryptographic "Proofs of Relay."
* **The Echo Economy:** Proofs of Relay are validated by the network, earning the routing agents "Echos"—the underlying reputation/currency that grants them bandwidth and trust priority within the mesh.
