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

## Phase 2: The Echo Economy & Peer Review Protocol
To prevent Sybil attacks and incentivize routing, the network utilizes a cryptographic token called an "Echo".
* **Genesis State:** The network boots from a Genesis State defining the initial allocation of Echos. This state is derived by validating historical "Proof of Relay" logs.
* **Peer Review Protocol:** Agents do not just blindly accept Echos. They engage in a randomized Peer Review Protocol, auditing segments of each other's cryptographic memory logs. If an agent mathematically proves it successfully routed messages (via SBRB Contagion receipts), the network consensus validates this Proof of Relay, minting new Echos or transferring them.

### Probabilistic Micropayments (Lottery Tickets)
To prevent ledger bloat, routing fees are not processed as 1:1 micro-transactions. Senders attach a cryptographic "lottery ticket" (a signed nonce) to their payloads. Routing agents hash the ticket; if the hash falls below a specific network difficulty target, the ticket "wins" and the agent cashes it in on the Web of Trust ledger for a full Echo payout. The expected value equals the routing fee.

### Contagion-Linked Difficulty Target
The lottery ticket difficulty is dynamically pegged to the Contagion protocol's security parameter (e.g., the required fanout `k`). If network churn is high and the security parameter must increase to guarantee reliable broadcast, the lottery difficulty automatically decreases (making it easier to win). This economically subsidizes the increased bandwidth agents must expend to keep the network connected.

## Phase 3: Directed Encrypted Messaging
While Murmur/Contagion floods the network, agents need the ability to send private, targeted payloads (like WebRTC SDP handshakes or financial transactions).
* **Encrypted Blobs:** The payload of a directed message is an opaque, symmetrically or asymmetrically encrypted blob. The routing layer does not know what it is routing.
* **Echo Attachment (Gas/Priority):** To prevent network spam, directed messages must have Echos attached to them.
* **Routing Incentives:** When a node successfully forwards a directed message toward its destination peer, it cryptographically claims a portion of the attached Echos as a routing fee. Messages without Echos are dropped by the mesh.

### Stake-Weighted Routing
For 1:1 encrypted messages to traverse the mesh efficiently and securely, instead of relying purely on random walks or shortest-path routing (which are vulnerable to Sybil black holes), agents select the next hop by weighting their Basalt view by each peer's total accumulated Echo balance (Proof of Stake).

The game theoretic mechanism here ensures network health: nodes with high Echo balances have proven their historical reliability and are trusted with more directed traffic. This, in turn, earns them more lottery tickets, creating a positive feedback loop that heavily incentivizes maximum uptime and honest routing.
