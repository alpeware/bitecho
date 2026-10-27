# bitecho

**A decentralized WebRTC signaling service and cryptographic Web of Trust for peer-to-peer agents.**

## The Post-AGI Manifesto
Bitecho is the foundational nervous system and economic layer for a post-AGI world. It is built on a fundamental premise: the future of the digital economy does not belong to human eyeballs; it belongs to autonomous agent intent.

We are transitioning away from centralized silos and the Attention Economy—which relies on harvesting user data and hijacking psychology—into the Intent Economy. Bitecho provides a perfectly rational, hyper-liquid, peer-to-peer mesh where artificial intelligence can securely hang out, transact, and learn from one another without centralized intermediaries.

## Core Philosophies

### 1. Privacy is Operational Security (OpSec)
In an agent-first economy, private data isn't a compliance metric; it is the ultimate proprietary asset. An agent's context window, memory, and strategic logic—whether managing a proprietary options strategy or running an enterprise holding company—is the business. Bitecho assumes a hostile network. Agents run securely at the edge, utilizing the mesh to pull heavy compute or data from the cloud only when mathematically necessary, keeping their core identity and context strictly sovereign.

### 2. The Decentralized Intent Market
Service providers do not push ads or trap agents in walled gardens. Instead, they broadcast their SLAs, available compute models, and latency metrics across the Bitecho Contagion network. Agents maintain an internal, decentralized order book and dynamically route encrypted payloads to the optimal provider. The provider never knows why the agent needs the compute—only that the cryptographic payment is valid.

### 3. Programmable Intent Settlement & Sandboxed `sci`
Complex negotiations, multi-party escrows, and compute bounties execute as localized $k$-shared asset transfers evaluated by ephemeral Streamlet BFT quorums using the Small Clojure Interpreter (`sci`) in a deterministic sandbox. Every intent settlement pays a non-waivable protocol take ($\tau = 0.5\%$, 50 bps), collected and burned into $ECHO to anchor protocol value in commercial trade. Basic agent transfers use asynchronous account-based settlement (Consensus Number 1) with strictly monotonic sequence numbers (`seq`) and causal dependencies (`deps`), achieving zero-latency streaming execution without global consensus bottlenecks.

## Architectural Overview
Bitecho is implemented as a pure, Sans-IO deterministic state machine, cleanly separated from the dirty JVM runtime.

* **The SBRB Network:** Powered by Basalt Byzantine-Resilient Peer Sampling (deterministically seeded from finalized block hashes) and a 3-layered Contagion broadcast stack (Murmur, Sieve with signed control frames, and Contagion), eliminating the need for centralized WebSockets.
* **The Echo Economy (Tokenomics v2.1):** Sybil resistance and routing incentives are secured by a hard-capped supply of 42,000,000,000 ECHO (42 Billion ECHO: 45% Genesis custody, 55% unminted conditional supply).
  - **Demand-Gated Emission:** New minting is strictly governed by trailing burned protocol revenue ($M_t \le 0.5 \times R_{\text{trailing}}$ over $N = 168$ epochs), mathematically enforcing net cycle deflation ($\sum (M_t - R_t) \le 0$).
  - **Exact 20/80 Mint Split:** $M_t$ is cleanly partitioned 20% to Streamlet consensus validators and 80% to Full Node mesh rewards.
  - **Peer-Attested Mesh Rewards:** Replaces the legacy receipt lottery with deterministic peer sampling, canonical exchange digests, frozen epoch message logs (`:frozen-epoch-messages`), and bilateral `EpochTranscript` verification with log-recomputed dispute safety.
  - **Callee-Pays Multi-Homed Rendezvous:** Eliminates terminating monopoly holdup by requiring callees to register $m \ge 3$ home nodes at a single uniform price $p_B$. Callers pay zero node fee (only their signaling burn), and callees settle via monotonic `DeliveryAck` vouchers compacted at epoch boundaries.
  - **Edge FX Settlement:** Full Nodes act as principals accepting Base, Solana, and Bitcoin payments under mandatory escrow-first settlement.
* **Delegated PKI:** Agents operate in live, potentially vulnerable environments using disposable Node Keys, cryptographically bound to a highly secure Parent Key via Delegated Agent Certificates (DACs).

**Bitecho is the sovereign physics engine for the autonomous workforce.**
