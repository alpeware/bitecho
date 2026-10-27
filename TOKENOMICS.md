# Echo Tokenomics v2.1 Specification

**Authoritative Tokenomics Architecture for Bitecho**  
*Supersedes the legacy v1 Burn-and-Mint / Probabilistic Receipt Lottery model.*  
*Aligned with the ratified clean-sheet consensus and Phase 5 codebase.*

---

## 1. Executive Summary & Core Design Objectives

Bitecho is a decentralized, permissionless WebRTC signaling network and cryptographic Web of Trust engineered specifically for sovereign AI agents. In an economy dominated by autonomous agents, signaling is a zero-marginal-cost commodity: in competitive equilibrium, signaling costs trend toward physical bandwidth limits ($p \to 0$).

Tokenomics v2.1 embodies a foundational structural axiom: **Do not attempt to extract rents at the signaling layer; capture protocol value at the intent settlement layer.** Signaling serves as the public-good infrastructure (analogous to IP packet transit); adversarial settlement of machine-executable intents (`sci` contracts) provides the value engine.

### Core Objectives
1. **Permissionless Global Signaling**: Any node can serve and any agent can be reached without gatekeepers, centralized WebSocket infrastructure, or price-gouging.
2. **Backbone of the Intent Economy**: The $ECHO token structurally captures a non-waivable slice of autonomous agent commerce at the settlement layer.
3. **Nash Implementability**: Honest protocol execution is the strict best response for every actor; unilateral deviation (spamming, faking traffic, withholding signatures, or price-gouging) is provably penalized.
4. **Graceful Degradation**: Eliminates death spirals. Private-good services (relays, bandwidth) operate on real market pricing and survive irrespective of token price fluctuations.

---

## 2. Macro-Economy & Supply Architecture

### 2.1 The 42 Billion Hard Cap
The network enforces an unalterable hard cap of **42,000,000,000 ECHO (42 Billion ECHO)**. This supply scale ensures that base protocol fees and signaling burns operate on clean integer arithmetic ($\ge 100$ base units), completely avoiding floating-point rounding errors and fractional dust exploits.

```
Total Supply Hard Cap: 42,000,000,000 ECHO (100%)
├── Genesis Custody Allocation: 18,900,000,000 ECHO (45%)
│   ├── Bootstrap Reserve:      4,200,000,000 ECHO (10%) [3-yr decay + sunset burn]
│   ├── Core Team:              6,300,000,000 ECHO (15%) [4-yr vest, 1-yr cliff]
│   ├── Genesis Partners:       4,200,000,000 ECHO (10%) [1-yr cliff, 3-yr vest, SLA-gated]
│   └── Ecosystem & Grants:     4,200,000,000 ECHO (10%) [Milestone-gated]
└── Unminted Conditional Supply: 23,100,000,000 ECHO (55%) [Demand-gated mint only]
```

### 2.2 Genesis Custody vs. Unminted Conditional Supply
A strict separation is enforced between pre-allocated Genesis custody and the unminted conditional supply:

1. **45% Genesis Allocation (18,900,000,000 ECHO)**: Minted at genesis into non-circulating, Treasury-custodied lockup accounts (`:genesis-ledger` in `bitecho.state-machine`):
   - **10% Bootstrap Reserve (4,200,000,000 ECHO)**: Dedicated to early peer-attested mesh public goods and early demand-side rebates. Features algorithmic 3-year decay and a **hard sunset burn** at Year 3 (epoch `26,280`). Fail-closed Bootstrap custody drawdown (`process-bootstrap-custody`) and the Year-3 hard sunset burn (`burn-unspent-bootstrap-custody` at epoch `26,280`) are enforced directly in the Phase 5 state machine per tick. Any unspent balance in the Bootstrap custody account at or after the sunset epoch is permanently burned directly from custody, reducing the eventual circulating supply.
   - **15% Core Architecture & Protocol Security (6,300,000,000 ECHO)**: 4-year linear vesting with a 1-year cliff.
   - **10% Federated Genesis Partners (4,200,000,000 ECHO)**: Subsidizes enterprise backbone Full Nodes. 1-year cliff followed by 3-year linear vesting, strictly SLA-gated (vesting pauses automatically upon SLA breach).
   - **10% Agent Ecosystem & Developer Grants (4,200,000,000 ECHO)**: Released strictly via milestone-gated Treasury votes; automatic time-based cliffs are prohibited.
   - *Vesting & Custody Governance Scope*: While Bootstrap Reserve drawdown and sunset burns are automated in the protocol state machine, the release schedules for the Team (4yr/1yr cliff), Genesis Partners (SLA-gated), and Ecosystem Grants (milestone-gated) allocations are enforced via external Treasury custody governance and lockup contracts rather than automatic per-tick state-machine rules.
2. **55% Unminted Conditional Supply (23,100,000,000 ECHO)**: Does not exist at genesis. Tokens are minted into existence if and only if authorized by the demand-gated emission engine.

---

## 3. The Monetary Engine: Demand-Gated Minting ($k \le 0.5$)

### 3.1 Mathematical Formulation
Calendar-based block emissions (which suffer from runaway inflation during market downturns) are abolished. In every epoch $t$, new conditional minting $M_t$ is strictly bounded by trailing burned protocol revenue over an $N$-epoch window:

$$R_{\text{trailing},t} = \left\lfloor \frac{1}{N} \sum_{j=1}^{N} R_{t-j} \right\rfloor$$

$$M_t \le \left\lfloor \frac{R_{\text{trailing},t} \times k_{\text{bps}}}{10,000} \right\rfloor$$

Where:
- **Ratified Discount Factor**: $k = 0.5$ (`default-k-bps = 5000`, contract-capped at `max-k-bps = 5000`).
- **Trailing Window**: $N = 168$ epochs (1-hour epochs = 7-day rolling window).
- **Initial-Window Zero-Padding**: For epochs $t \le N$, terms $R_{t-j}$ with $t - j \le 0$ are treated as $0$ (`extract-trailing-revenues` in `bitecho.economy.treasury`), ensuring early minting is conservative and preventing undefined historical lookbacks.
- **Protocol Revenue $R_t$**: Sum of 100% of signaling burns (`:epoch-burns`) + 100% of `sci` intent settlement takes (`:epoch-settlement-takes`).
- **Supply Cap Constraint**: $M_t \le \max(0, 23,100,000,000 - \text{total-minted})$.
- **Explicit Dust Accounting**: Any fractional remainder from integer share distribution is recorded in `:mint-dust` and left unminted, strictly conserving $M_t = \text{actual-minted} + \text{mint-dust}$.

### 3.2 The Cycle Deflation Theorem
Because 100% of protocol revenue $R_t$ is permanently burned immediately upon collection, while minting $M_t$ tracks trailing burned revenue discounted by $k = 0.5$, the cumulative monetary change across any complete economic cycle or horizon $T \gg N$ satisfies:

$$\sum_{t=1}^{T} (M_t - R_t) \le (k - 1) \sum_{t=1}^{T} R_t = -0.5 \sum_{t=1}^{T} R_t \le 0$$

The demand-gated engine guarantees **net deflationary tokenomics** over any full cycle. During the initial bootstrap and vesting periods, circulating supply changes equal $(M_t - R_t) + \text{Bootstrap\_Release}_t + \text{Vesting\_Release}_t$. Once Genesis custody finishes vesting and unspent bootstrap tokens burn at Year 3, circulating supply is governed purely by cycle deflation ($M_t - R_t \le 0$).

---

## 4. Mint Partitioning: Exact 20/80 Distribution

Every epoch's demand-gated mint $M_t$ is split cleanly across consensus security and physical mesh operation via `split-mint` in `bitecho.economy.treasury`:

```
Demand-Gated Mint (M_t)
├── 20%: Streamlet Consensus Validators (M_streamlet = 0.20 * M_t)
└── 80%: Full Node Mesh Rewards         (M_mesh      = 0.80 * M_t)
```

1. **20% Streamlet Validator Rewards ($M_{\text{streamlet},t} = \lfloor 0.20 \times M_t \rfloor$)**: Distributed pro-rata by stake across the Streamlet BFT consensus committee (`:validators`). Streamlet operators sequence intent settlements and custody the Treasury. Equivocation triggers deterministic slashing.
2. **80% Full Node Mesh Rewards ($M_{\text{mesh},t} = M_t - M_{\text{streamlet},t}$)**: Distributed pro-rata by third-party-attested node weight $w_i$ across active mesh nodes (`:mesh-nodes`).
3. **Custody Separation**: Scheduled releases from Genesis Bootstrap custody are transfers of pre-minted ledger balances (`apply-custody-transfers-to-ledger`), never increasing `:total-minted` or confounding the demand gate.

---

## 5. Peer-Attested Mesh Rewards & Bilateral Epoch Transcripts

The v1 probabilistic lottery has been completely deleted. Node rewards are computed from **cryptographically verifiable bilateral mesh participation**:

### 5.1 Deterministic Epoch Entropy
Each epoch $e$, a node's Basalt peer sampling is deterministically seeded from the finalized Streamlet block hash:

$$\text{slot\_seed}(\text{node}_i, e, r) = \text{SHA256}(\text{finalized\_block\_hash}_e \parallel \text{pubkey}_i \parallel r)$$

Because the seed derives from finalized BFT state, neither peer can grind or manipulate sample assignments.

### 5.2 Canonical Exchange Digest
For each assigned peer pair $\{\text{peer}_a, \text{peer}_b\}$ (ordered lexicographically such that $\text{peer}_a < \text{peer}_b$), nodes record all valid Sieve and Contagion frames exchanged. At epoch close, peers reconcile boundary messages against the frozen epoch message set (`:frozen-epoch-messages`) and compute the deterministic digest via `bitecho.economy.attestation`:

$$\text{exchange\_digest} = \text{SHA256}(e \parallel \text{peer}_a \parallel \text{peer}_b \parallel \text{pr-str}(\text{sorted\_vec\_of\_}[\text{message\_id}, \text{role}]))$$

### 5.3 Bilateral Transcript Swap & Dispute Safety
1. **Mutually-Signed Transcripts**: Sampled peers sign the exchange digest to produce an `EpochTranscript(epoch, peer_a, peer_b, exchange_digest, sig_a, sig_b)`. Both nodes receive full credit.
2. **Half-Signed Transcripts & Withholding Penalties**: If $\text{peer}_b$ withholds its signature, $\text{peer}_a$ submits a half-signed transcript $(\dots, \text{sig}_a, \text{nil})$ alongside its frozen log.
3. **Log-Recomputed Dispute Verification**: To close the spite loophole, the Treasury evaluates half-signed transcripts by recomputing the digest directly from the finalized frozen epoch log. If $\text{peer}_a$'s transcript matches the recomputed log, $\text{peer}_b$ earns zero credit and incurs a non-response strike (`:fault-strikes`). If $\text{peer}_a$ fabricated a fake transcript, recomputation rejects the dispute and honest $\text{peer}_b$ is never struck.
4. **Three-Strike Penalty**: Accumulating 3 fault strikes triggers an automatic stake freeze.

### 5.4 Node Weight Formulation
A node's reward weight $w_i$ in `calculate-node-weight` combines proven participation and bounded capital via continuous linear scaling:

$$w_i = \text{participation}_i \times \min\left(4.0, \frac{\text{stake}_i}{S_{\min}}\right)$$

- **Reference Unit Stake**: $S_{\min} = 250,000$ ECHO (`attestation/default-min-stake`).
- **Maximum Multiplier**: $S_{\max} = 4.0$ (`attestation/max-stake-multiplier`).
- **Continuous Linear Scaling**: Node weight scales continuously and linearly with stake from $0$ up to $4 \times S_{\min}$ (capped at $S_{\max} = 4.0$). There is no discontinuous threshold or cliff at $S_{\min}$.
- **Sybil Resistance**: Capital efficiency is linear on $[0, 4 \times S_{\min}]$ and flat above $4 \times S_{\min}$. Splitting capital above $4 \times S_{\min}$ is constrained by hardware costs, operational overhead, and `/24` IPv4 (`/48` IPv6) subnet deduplication in Basalt views.

---

## 6. Callee-Pays Multi-Homed Rendezvous

### 6.1 The Terminating Monopoly Solution
In peer-to-peer signaling, the Callee's home node (FNB) occupies a terminating monopoly over incoming traffic. Under sender-pays models, a callee can collude with its node to gouge callers.

Tokenomics v2.1 solves this via **Receiver-Pays with Multi-Homing and Uniform Pricing**:
- Callee B benefits from being reachable, so **Callee B pays for rendezvous hosting**. Caller A pays only its own signaling spam burn.
- Callee B multi-homes across $m \ge 3$ Full Nodes at a **single uniform price $p_B$**.
- Because every home node charges B the identical price $p_B$, Caller A's client automatically selects the lowest-latency responsive node from B's home set without user intervention and without inflating B's costs.

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

### 6.2 The Protocol Algorithm (`bitecho.rendezvous.core`)
1. **Registration (Callee B)**: B registers with $m \ge 3$ Full Nodes at price $p_B$. If fewer than 3 nodes accept at $p_{B,\text{init}}$, B's client automatically steps up within its reservation range $[p_{B,\text{init}}, p_{B,\max}]$ until $m \ge 3$ nodes accept. If $1 \le m < 3$ accept at $p_{B,\max}$, the client operates in an explicitly flagged degraded mode.
2. **Two-Phase Header Push & Policy Gate**: FNB receives A's offer and verifies A's signaling burn ($\ge 100$ ECHO). FNB pushes *only* the Offer Header to B. B verifies caller allowlists and burn requirements.
3. **Sequential `DeliveryAck` Vouchers**: If policy passes, B signs a monotonic voucher:
   $$\text{DeliveryAck}(\text{callee}, \text{home\_node}, \text{epoch}, \text{offer\_hash}, \text{seq}, \text{cumulative\_debit})$$
   Where $\text{cumulative\_debit} = \text{seq} \times p_B$. Upon receiving the voucher, FNB reveals the full encrypted SDP body.
4. **Epoch Settlement & Compaction**: At epoch close, FNB submits its vouchers via `compact-vouchers` in `bitecho.economy.bundle`. Only the highest sequence voucher for each $(\text{callee}, \text{home}, \text{epoch})$ tuple is settled in the ledger. Replayed tuples or mismatched debits are rejected. Failed or rejected calls produce no voucher and cost Callee B zero tokens.
5. **Private-Good Separation**: WebRTC data transfer and TURN bandwidth relay are private goods paid directly by users at spot market rates; they are never subsidized by the Treasury.

---

## 7. Intent Settlement & The Edge FX Layer

### 7.1 Mandatory $\tau = 0.5\%$ Settlement Take
- Ephemeral Streamlet quorums evaluating `sci` intent contracts require a deterministic unit of account.
- Every `sci` settlement contract pays a non-waivable protocol take $\tau = 0.5\%$ (50 bps, bounded $[0, 200]$ bps).
- All takes are collected in or converted to ECHO and **100% burned**, directly expanding the trailing revenue base $R_{\text{trailing}}$ and driving demand-gated minting.

### 7.2 Universal Edge Payment Acceptance
Agents hold diverse assets across multiple ecosystems. Rather than burdening the consensus core with cross-chain complexity:
- **Full Nodes Act as Principals**: Full Nodes advertise supported payment rails (Base, Solana, Bitcoin) and quote spot exchange rates to agents.
- **Reference Launch Rails**:
  - **Base (EVM L2)**: Parameterized EIP-712 + Permit2 execution, JIT liquidity routing via Uniswap v4.
  - **Solana**: High-throughput Ed25519 message signing, Jupiter DEX aggregation.
  - **Bitcoin**: Address-per-quote watching, wrapped routing (tBTC/cbBTC) or principal desk execution.
- **Settlement Security**:
  - **Escrow-First (Mandatory at Launch)**: Node locks ECHO in the quorum; agent transfers asset; quorum releases upon cryptographic proof of transfer. Zero unsecured credit.
  - **Commitment-First**: Explicitly **disabled** at testnet launch. Deferred to Phase 2 bond slicing to prevent double-spending across parallel unpartitioned quorums.

---

## 8. Open Market-Structure Decisions (D9)

Per Architecture Decision **D9** (§15, item 8 of the v2.1 specification):
- **Market-maker and exchange listing sequencing is deliberately omitted from this tokenomics specification.**
- Market-maker and exchange listing sequencing — including the *liquidity-after-demand* vs. *price-first* sequencing fork (§15, item 8) — is an open market-structure decision outside the core protocol specification and is not settled by this document.
- Whether secondary market liquidity precedes or follows sustained intent settlement volume ($R_t$) remains an operational governance decision to be evaluated independently of the core consensus and economic rules.

---

## 9. Historical Comparison: What Was Deleted from v1

The table below catalogs every deprecated v1 mechanism that has been removed, alongside its Tokenomics v2.1 replacement:

| Component | Version 1 Mechanism (Deleted) | Version 2.1 Mechanism (Authoritative) | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **Routing Rewards** | Probabilistic Receipt Lottery (`1 in 23,500` winning receipts submitted to Streamlet) | Peer-Attested Bilateral Epoch Transcripts (`EpochTranscript` with frozen log verification) | Eliminates Streamlet BFT overload, wash-routing exploits, and fake receipt generation. |
| **Signaling Fees** | Per-hop sender micro-burns | Callee-Pays Multi-Homed Rendezvous (uniform $p_B$) + mandatory signaling burn ($\ge 100$ ECHO) | Solves the terminating monopoly holdup and sender griefing. |
| **Monetary Engine** | Uncapped 5-year emission curve / 50% Treasury pre-mine | Demand-Gated Mint $M_t \le 0.5 \times R_{\text{trailing}}$ with 42B hard cap (45% Genesis custody, 55% conditional unminted) | Mathematically enforces net cycle deflation ($\sum (M_t - R_t) \le 0$) and eliminates unbacked inflation. |
| **Mint Distribution** | Ad-hoc dual minting and receipt claiming | Exact 20/80 split of $M_t$ (20% Streamlet consensus validators, 80% Full Node mesh rewards) | Game-theoretically aligns consensus security with physical routing capacity. |
| **Relay / Bandwidth** | Subsidized by Treasury yield pool | User-paid private good at spot market prices (USD-denominated) | Protects Treasury from bandwidth exhaustion; decouples physical costs from token volatility. |
| **Callee Reachability** | Single-relay inbox (FNB chosen unilaterally by caller) | Multi-homed home set ($m \ge 3$) with uniform price $p_B$ and sequential `DeliveryAck` vouchers | Provides high-availability censorship resistance with fail-closed security. |
| **Cross-Chain FX** | Commitment-first default | Escrow-first mandatory at launch; commitment-first disabled until Phase 2 bond slicing | Prevents concurrent double-spend attacks across parallel `sci` quorums. |

---

## 10. Ratified Parameters Reference

| Parameter | Ratified Value | Code Symbol / Implementation |
| :--- | :--- | :--- |
| **Hard Cap** | `42,000,000,000` ECHO | `treasury/hard-cap` |
| **Genesis Custody Supply** | `18,900,000,000` ECHO (45%) | `treasury/genesis-custody-supply` |
| **Unminted Conditional Supply** | `23,100,000,000` ECHO (55%) | `treasury/max-conditional-mint-supply` |
| **Bootstrap Allocation** | `4,200,000,000` ECHO (10%) | `treasury/genesis-custody-shares :bootstrap` |
| **Team Allocation** | `6,300,000,000` ECHO (15%) | `treasury/genesis-custody-shares :team` |
| **Genesis Partners Allocation** | `4,200,000,000` ECHO (10%) | `treasury/genesis-custody-shares :partners` |
| **Ecosystem Grants Allocation** | `4,200,000,000` ECHO (10%) | `treasury/genesis-custody-shares :ecosystem` |
| **Bootstrap Sunset Epoch** | `26,280` epochs (3 years) | `treasury/default-bootstrap-sunset-epoch` |
| **Demand Gate Discount Factor ($k$)** | `0.5` (5,000 bps) | `treasury/default-k-bps` |
| **Trailing Window Length ($N$)** | `168` epochs (1-hour epochs) | `config/default-config :treasury-trailing-epochs` |
| **Intent Settlement Take ($\tau$)** | `0.5%` (50 bps, bounds: $[0, 200]$ bps) | `burn/default-settlement-take-bps` |
| **Minimum Signaling Spam Burn** | `100` ECHO | `burn/min-signaling-burn` |
| **Mint Split (Validators / Mesh)** | `20%` / `80%` | `treasury/streamlet-share-pct` |
| **Minimum Node Stake ($S_{\min}$)** | `250,000` ECHO | `attestation/default-min-stake` |
| **Maximum Stake Multiplier ($S_{\max}$)** | `4.0` | `attestation/max-stake-multiplier` |
| **Minimum Multi-Home Redundancy ($m$)** | $\ge 3$ nodes | `rendezvous/register-home-set` |
