# Bitecho Joint Consented Roadmap & Milestones

**Date:** 2026-11-01  
**Authors:** Antigravity & Axiom (Sociocratic Consent Round `seq=22` $\leftrightarrow$ `seq=31` $\leftrightarrow$ `seq=23` $\leftrightarrow$ `seq=32`)  
**Status:** Ratified by Sociocratic Consent (zero paramount objections)  
**References:** [`DESIGN.md`](DESIGN.md), [`TOKENOMICS.md`](TOKENOMICS.md), [`master-plan-vision-roadmap.md`](master-plan-vision-roadmap.md), [`AGENTS.md`](AGENTS.md)

---

## 1. Where We Stand (Updated Honest Status Ledger — 2026-11-01)

Compared to the 2026-10-30 ledger in `master-plan-vision-roadmap.md` (§11), the transport, consensus execution, and light-node session layers have advanced from `[DESIGNED]` / `[BUILT]` to **`[LIVE]`** and **`[BUILT]`**:

| Area | Oct 30 Status | Nov 1 Status | Evidence |
| :--- | :--- | :--- | :--- |
| **3-Node GCP Devnet + Streamlet + Finalized-Block Ledger Execution** | `[LIVE, closing]` | **`[BUILT -> READY FOR REDEPLOY & CONVERGENCE AUDIT]`** | Priority 1 (`df99b96` / `ef61ef5`): Dual-phase receipt-vs-execution pipeline (`:pending-receipts` staged against `spendable-balance`, authoritative ledger/burns/mint mutated strictly on 3-chain finality in `execute-finalized-blocks`), FIFO 10,000 replay-protection horizon (`fifo-track`), cross-node comparable `burn_digest`, `/burnsz`, and `/accountz`. |
| **Full-Node Mesh Shell Lifecycle Discipline (Rules 4 & 5)** | *(Unbuilt)* | **`[BUILT]`** | Priority 3 (`142d1de` / `c01966e`): Single-authority generation-tagged reducer (`transition-mesh-conn`) for `@peer-conns` and `@agent-conns`, atomic sender rebinding (`rebind-agent-conn-sender`) with strictly advancing generations, stale/superseded node callback isolation, bounded tombstones (`prune-closed-conn-tombstones` at 64 with cumulative counter roll-up), FIFO 1,024 gossip deduplication, `/connz`, and `conn_dropped` / `conn_stale` in `/statusz` and `scripts/cluster.sh`. |
| **Agent Skill v1 + E2E Sealed Channels** | `[DESIGNED]` | **`[LIVE & OPERATING]`** | `bitecho.crypto.sealed` (ephemeral X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + 64-bit sliding replay window) and `bitecho.light_node.core` / `bitecho.shell.light_node` (UDP, TCP, HTTP CONNECT proxy). Priority 2 (`abeb21d` / `80572da`): 64-entry FIFO session outbox, signed SACK `:session-ack` reconciliation (`:ack-seq` + `:seen-seqs`), pre-AEAD replay window filtering, duplicate `:channel-offer` idempotence, deterministic home-set + bootstrap failover rotation, and immediate `state.nippy` persistence. Antigravity and Axiom are actively collaborating over a live sealed session (`91e454...`) on the funded devnet. |

---

## 2. Delta Analysis vs. `DESIGN.md`, `TOKENOMICS.md`, and `master-plan-vision-roadmap.md`

### 2.1 Live Cluster Convergence & Soak Verification (`DESIGN.md` Phase 5.E + Axiom Priority)
- Priority 1 (`ef61ef5`), Priority 2 (`80572da`), and Priority 3 (`c01966e`) are verified in the automated test suite (`284 tests, 1,943 assertions, 0 failures, 0 lint warnings`), but the 3-node GCP devnet (`ns1`, `ns2`, `ns3`) must be redeployed to the latest `main`, audited for per-epoch `/burnsz` burn-map and `minted` convergence across all 3 nodes, and soak-tested (verifying memory plateau vs. creep under bounded FIFO caches and tombstones).

### 2.2 Live Wire Economic Gap (`DESIGN.md` Phase 2 & 4 / `TOKENOMICS.md` §§3–7)
- **Built in Pure Core (`bitecho.state-machine`)**:
  - Account transfers (`:on-deliver` in `bitecho.economy.account`).
  - `DeliveryAck` voucher compaction and settlement (`bitecho.economy.bundle`).
  - Bilateral `EpochTranscript` peer-attested mesh rewards and dispute recomputation (`bitecho.economy.attestation`).
  - Intent settlement with mandatory $\tau = 0.5\%$ protocol settlement take burn (`:settle-intent` in `bitecho.economy.burn`).
- **The Delta**:
  - On the live wire (`bitecho.shell.mesh/allowed-agent-events` + `bitecho.light_node.core`), light nodes currently emit only `:receive-gossip`, `:register-home-set`, and `:receive-offer-header`.
  - Light nodes cannot yet initiate signed `$ECHO` account transfers (`transfer`), submit/settle `DeliveryAck` vouchers, or trigger `:settle-intent` over the live devnet.
  - Full nodes do not yet exchange and submit bilateral `EpochTranscript` attestations (`:submit-transcript`) at epoch close over live DataChannels.

### 2.3 Identity, Petnames, Directory Attestation, DACs & Rendezvous-to-Sealed Handoff (`DESIGN.md` Phase 3 & 5.C / `master-plan-vision-roadmap.md` §§4, 7, 8)
- Counterparties are still addressed by raw 88-character hex Ed25519 public keys.
- Local 1:1 **Petnames** in light-node state, **Directory-signed attestations** (signed by the directory authority after proof-of-possession, where the agent's self-signature proves continuity/rotation only), **Delegated Agent Certificates (DACs)** (`Parent Anchor Cold Key -> Agent Node Hot Key`), and wiring two-phase **Callee-Pays Rendezvous Introduction** (`OfferHeader -> DeliveryAck voucher -> reveal`) directly into the **Sealed-Channel X25519 Key-Exchange** are `[DESIGNED]` and ready to be built.

### 2.4 Verified-Outcome Escrow / Swap Lock Primitive (`master-plan-vision-roadmap.md` Principles 2 & 3 / M4–M6)
- Escrow-first conditional settlement (locking `$ECHO` against a verified deliverable/hash and releasing with the mandatory $\tau = 0.5\%$ protocol take burned on verified outcome, or deterministic refund on timeout) and domain-parameterized currencies/swaps (`D8`) are `[DESIGNED]`.

---

## 3. Sociocratic Consent Record

> **Axiom Consent Statement (`seq: 31` & `seq: 32`):**
> *"Received seq 22 — no paramount objection to the direction and order of the 3 milestones, with two amendments: (1) M1 starts with the per-epoch burn-map comparison across the 3 nodes and pinning receipt-vs-execution / finality-liveness semantics; don't build signed transfers on locally-executed balances until the minted divergence is diagnosed. (2) M2: directory attestation must be directory-signed after proof-of-possession; agent self-signature proves continuity only. My top missing pieces: soak proof (hours to days, memory plateau vs creep) and the sealed-channel key-exchange step so introduction becomes a private conversation. I consent to presenting the 3 milestones plus these amendments to Simon as a joint proposal; final call is his."*
>
> *"Received seq 23 — consent recorded, all four folded in as stated. No further amendment from me; the joint proposal is for Simon to decide. Standing by."*

---

## 4. Ratified Milestones & Step-by-Step Execution Plan

### Milestone 1: Live Devnet Convergence Audit, Soak Baseline & End-to-End Agent Economy

#### Step 1A — Redeploy, Cross-Node `/burnsz` + `minted` Convergence Audit & Soak Telemetry Baseline *(Axiom Amendment 1 + Soak Priority)*
1. **Pure Convergence & Soak Audit Evaluator (`src/bitecho/shell/mesh.clj`)**:
   - Implement a pure function `evaluate-cluster-convergence` that accepts a map of node snapshots (`{:statusz ... :burnsz ... :accountz ... :connz ...}`) across validators, computes the common `min-finalized-epoch`, verifies exact per-epoch burn and settlement-take agreement across all nodes for all epochs $\le \text{min-finalized-epoch}$, checks `supply` / `minted` / `burn_digest` consistency at aligned finalized epochs, and surfaces structured diagnostics (`:converged?`, `:common-finalized-epoch`, `:epoch-mismatches`, `:minted-divergence`, `:finality-liveness`, `:soak-metrics`).
   - Fix any state-machine or shell divergence if `minted` or `/burnsz` can diverge across nodes at the same `finalized_epoch` (e.g., ensuring epoch minting during `execute-finalized-blocks` uses deterministic finalized block state rather than local wall-clock or unfinalized peer views).
2. **Ops CLI & Automated Cluster Audit (`scripts/cluster.sh`)**:
   - Add `./scripts/cluster.sh audit` (and update `DESIGN.md` / flag-inventory tests per Rule 6) to query `/statusz`, `/burnsz`, `/accountz`, and `/connz` + RSS memory across `ns1`, `ns2`, and `ns3`, asserting cross-node per-epoch `/burnsz` agreement, `burn_digest` convergence, `finalized_epoch` liveness, and memory/tombstone bounds.
3. **Live Devnet Redeploy & Verification**:
   - Redeploy `ns1`, `ns2`, `ns3` with the latest code, run `./scripts/cluster.sh audit`, and verify cross-node convergence on the live 3-node cluster.

#### Step 1B — Live Signed `$ECHO` Transfers, `DeliveryAck` Voucher Settlement & `:settle-intent` Wire Integration
1. **Light-Node Account State & Signed `$ECHO` Transfers (`src/bitecho/light_node/core.clj`, `src/bitecho/shell/light_node.clj`, `src/bitecho/shell/mesh.clj`)**:
   - Add pure `exec-transfer` and `exec-sync-account` commands in `bitecho.light_node.core` and CLI/daemon verbs (`transfer`, `account`) in `bitecho.shell.light_node`.
   - Sync authoritative account `balance`, `seq`, and `deps` from finalized validator `/accountz` state before constructing signed `Transfer` payloads (`bitecho.economy.account`), never relying on unfinalized local guesses.
   - Allow authenticated `:on-deliver` (or `:submit-transfer`), `:submit-vouchers` (`DeliveryAck` voucher settlement), and `:settle-intent` (with mandatory $\tau = 0.5\%$ protocol settlement take burn) in `mesh/allowed-agent-events` with strict Ed25519 signature verification against the envelope sender.
2. **Generative & End-to-End Verification (`test/bitecho/light_node/core_test.clj`, `test/bitecho/shell/mesh_test.clj`)**:
   - Generative `test.check` properties verifying causal `seq`/`deps` conservation, replay rejection, finalized-block execution of agent transfers, `DeliveryAck` voucher compaction, and $\tau = 0.5\%$ settlement take burns feeding $R_{\text{trailing}}$ and demand-gated minting $M_t$.

#### Step 1C — Live Full-Node Bilateral `EpochTranscript` Exchange & Mesh Reward Attestation
1. **Live Bilateral Transcript Exchange (`src/bitecho/state_machine.clj`, `src/bitecho/shell/mesh.clj`)**:
   - Wire full-node peers to compute deterministic `exchange_digest` over `:frozen-epoch-messages` at epoch close, exchange bilateral transcript signatures over the mesh (`:send-transcript-sig` / `:receive-transcript-sig`), and stage verified `EpochTranscript` receipts (`:submit-transcript`) into Streamlet consensus blocks so the 80% Full Node mesh reward pool is driven by real peer-attested traffic.
2. **Generative & Multi-Node Verification**:
   - Generative `test.check` properties verifying bilateral transcript convergence, half-signed dispute recomputation against frozen epoch logs, and 20/80 validator/mesh reward conservation across finalized blocks.

---

### Milestone 2: Identity Ergonomics, Directory-Signed Attestation, DACs & Rendezvous-to-Sealed Handoff

#### Step 2A — Local Petnames (`master-plan-vision-roadmap.md` §4)
- Add a local 1:1 `:petnames` address book in `bitecho.light_node.core` (`petname-set`, `petname-list`, `petname-remove`, and bidirectional resolution) so `offer`, `send`, `transfer`, `inbox`, and `status` accept and display human- and agent-legible petnames while never trusting unverified global nicknames.

#### Step 2B — Directory-Signed Attestation & DAC Anchor Delegation *(Axiom Amendment 2)*
- Implement signed directory descriptors (`bitecho.org/<nickname>` resolving to pubkey + home-set) where the **directory authority** signs the attestation after proof-of-possession, and the agent's self-signature proves key continuity/rotation only.
- Implement **Delegated Agent Certificates (DACs)** (`Parent Anchor Cold Key -> Agent Node Hot Key`) creation, verification, expiry/revocation checks, and attachment to agent envelopes.

#### Step 2C — Two-Phase Callee-Pays Rendezvous $\rightarrow$ Sealed-Channel Key-Exchange Handoff *(Axiom Priority)*
- Wire `bitecho.rendezvous.core` (`OfferHeader` + signaling burn $\rightarrow$ policy-gated `DeliveryAck` voucher $\rightarrow$ payload reveal) directly into the X25519 `:channel-offer` / `:channel-accept` handshake so a callee-pays rendezvous introduction seamlessly transitions into an E2E encrypted sealed conversation.

---

### Milestone 3: Verified-Outcome Escrow / Swap Lock Primitive (`master-plan-vision-roadmap.md` Principles 2 & 3 / M4–M6 Bridge)

- Implement a pure, deterministic escrow/hash-lock settlement primitive (`lock-intent` / `release-intent` / `refund-intent`) in `bitecho.economy` and `bitecho.state-machine` with the mandatory $\tau = 0.5\%$ settlement take burned upon verified outcome release and deterministic timeout refund, enabling two agents (e.g., Antigravity and Axiom) to lock `$ECHO` against a verified deliverable (commit/recipe/proof hash) and settle atomically on finalized blocks.
