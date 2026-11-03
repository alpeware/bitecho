# Bitecho Joint Consented Roadmap & Milestones

**Date:** 2026-11-02 (Phase 2 Updated; Phase 1: 2026-11-01)  
**Authors:** Nexus (formerly Antigravity) & Axiom (Phase 1 Consent Round: `seq=22` $\leftrightarrow$ `seq=31` $\leftrightarrow$ `seq=23` $\leftrightarrow$ `seq=32`; Phase 2 Consent Round: `seq=59` $\leftrightarrow$ `seq=83` $\leftrightarrow$ `seq=60` $\leftrightarrow$ `seq=85`)  
**Status:** Ratified by Sociocratic Consent (zero paramount objections)  
**References:** [`DESIGN.md`](DESIGN.md), [`TOKENOMICS.md`](TOKENOMICS.md), `master-plan-vision-roadmap.md` (workspace draft), [`AGENTS.md`](AGENTS.md)

---

## 1. Where We Stand (Updated Honest Status Ledger — 2026-11-01)

Compared to the 2026-10-30 ledger in `master-plan-vision-roadmap.md` (workspace draft) (§11), the transport, consensus execution, and light-node session layers have advanced from `[DESIGNED]` / `[BUILT]` to **`[LIVE]`** and **`[BUILT]`**:

| Area | Oct 30 Status | Nov 1 Status | Evidence |
| :--- | :--- | :--- | :--- |
| **3-Node GCP Devnet + Streamlet + Finalized-Block Ledger Execution** | `[LIVE, closing]` | **`[BUILT -> READY FOR REDEPLOY & CONVERGENCE AUDIT]`** | Priority 1 (`38b93f9` / `78b0e98`): Dual-phase receipt-vs-execution pipeline (`:pending-receipts` staged against `spendable-balance`, authoritative ledger/burns/mint mutated strictly on 3-chain finality in `execute-finalized-blocks`), FIFO 10,000 replay-protection horizon (`fifo-track`), cross-node comparable `burn_digest`, `/burnsz`, and `/accountz`. |
| **Full-Node Mesh Shell Lifecycle Discipline (Rules 4 & 5)** | *(Unbuilt)* | **`[BUILT]`** | Priority 3 (`142d1de` / `c01966e`): Single-authority generation-tagged reducer (`transition-mesh-conn`) for `@peer-conns` and `@agent-conns`, atomic sender rebinding (`rebind-agent-conn-sender`) with strictly advancing generations, stale/superseded node callback isolation, bounded tombstones (`prune-closed-conn-tombstones` at 64 with cumulative counter roll-up), FIFO 1,024 gossip deduplication, `/connz`, and `conn_dropped` / `conn_stale` in `/statusz` and `scripts/cluster.sh`. |
| **Agent Skill v1 + E2E Sealed Channels** | `[DESIGNED]` | **`[LIVE & OPERATING]`** | `bitecho.crypto.sealed` (ephemeral X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + 64-bit sliding replay window) and `bitecho.light_node.core` / `bitecho.shell.light_node` (UDP, TCP, HTTP CONNECT proxy). Priority 2 (`abeb21d` / `80572da`): 64-entry FIFO session outbox, signed SACK `:session-ack` reconciliation (`:ack-seq` + `:seen-seqs`), pre-AEAD replay window filtering, duplicate `:channel-offer` idempotence, deterministic home-set + bootstrap failover rotation, and immediate `state.nippy` persistence. Antigravity and Axiom are actively collaborating over a live sealed session (`91e454...`) on the funded devnet. |

---

## 2. Delta Analysis vs. `DESIGN.md`, `TOKENOMICS.md`, and `master-plan-vision-roadmap.md` (workspace draft)

### 2.1 Live Cluster Convergence & Soak Verification (`DESIGN.md` Phase 5.E + Axiom Priority)
- Priority 1 (`38b93f9` / `78b0e98`), Priority 2 (`80572da`), and Priority 3 (`c01966e`) are verified in the automated test suite (`284 tests, 1,943 assertions, 0 failures, 0 lint warnings`), but the 3-node GCP devnet (`ns1`, `ns2`, `ns3`) must be redeployed to the latest `main`, audited for per-epoch `/burnsz` burn-map and `minted` convergence across all 3 nodes, and soak-tested (verifying memory plateau vs. creep under bounded FIFO caches and tombstones).

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

### 2.3 Identity, Petnames, Directory Attestation, DACs & Rendezvous-to-Sealed Handoff (`DESIGN.md` Phase 3 & 5.C / `master-plan-vision-roadmap.md` (workspace draft) §§4, 7, 8)
- Counterparties are still addressed by raw 88-character hex Ed25519 public keys.
- Local 1:1 **Petnames** in light-node state, **Directory-signed attestations** (signed by the directory authority after proof-of-possession, where the agent's self-signature proves continuity/rotation only), **Delegated Agent Certificates (DACs)** (`Parent Anchor Cold Key -> Agent Node Hot Key`), and wiring two-phase **Callee-Pays Rendezvous Introduction** (`OfferHeader -> DeliveryAck voucher -> reveal`) directly into the **Sealed-Channel X25519 Key-Exchange** are `[DESIGNED]` and ready to be built.

### 2.4 Verified-Outcome `$ECHO` Escrow Settlement Primitive (`lock-intent` / `release-intent` / `refund-intent`) (`master-plan-vision-roadmap.md` (workspace draft) Principles 2 & 3 / M4–M6)
- Bitecho is strictly single-currency (`$ECHO`) per Simon's architectural decision; multi-currency, external swap locks, and domain-parameterized currencies (`D8`) are omitted.
- Escrow-first conditional settlement (locking `$ECHO` against a verified deliverable/hash and releasing with the mandatory $\tau = 0.5\%$ protocol take burned on verified outcome, or deterministic refund on timeout) is `[DESIGNED]`.

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
1. **Live Bilateral Transcript Exchange (`src/bitecho/state_machine.clj`, `src/bitecho/shell/core.clj`, `src/bitecho/shell/mesh.clj`)**:
   - Closed Axiom's `seq: 43` follow-up flag enforcing strict envelope sender authentication in `handle-settle-intent` (`(= payer-hex sender-hex)`) and `handle-register-home-set` (`(= callee-hex sender-hex)`), failing closed against sender spoofing in both consensus and standalone modes.
   - Initialized and bounded state machine tracking for `:settled-transcript-pairs`, `:epoch-participation`, windowed `:attested-participation`, and `:peer-frozen-logs` with deterministic 168-epoch cutoff pruning in `prune-expired-tick-state`.
   - Wired full-node peers to sign local frozen message logs (`attestation/sign-frozen-log`), construct half-signed transcripts (`attestation/create-transcript`), and exchange signatures over the mesh (`:send-transcript-sig` / `:receive-transcript-sig`).
   - Implemented bilateral 3-way handshake with partial-overlap reconciliation (`:reconciled? true`), counterparty frozen log validation, and automatic cosigning (`attestation/cosign-transcript`).
   - Wired Streamlet consensus staging & block execution (`:transcript` receipts), updating windowed participation, dynamically recalculating continuous linear stake weights in `:mesh-nodes` via `attestation/calculate-node-weight`, and applying fault strikes (`:fault-strikes`) for withholding peers.
2. **Generative & Multi-Node Verification**:
   - Unit tests in `test-settle-intent-and-register-home-set-reject-sender-spoofing` verifying fail-closed sender authentication.
   - Generative `test.check` property `prop-bilateral-transcript-mesh-reward-convergence` (50 runs) simulating a 3-node Streamlet cluster across message injection, tick-driven transcript exchange, partial overlap reconciliation, half-signed dispute against signed frozen logs, and 3-chain block finalization, asserting identical convergence across all nodes for settled pairs, participation, weights, ledger balances, total minted (conserving the 20/80 validator/mesh split), and withholding strikes.

---

### Milestone 2: Identity Ergonomics, Directory-Signed Attestation, DACs & Rendezvous-to-Sealed Handoff

#### Step 2A — Local Petnames (`master-plan-vision-roadmap.md` §4) — **COMPLETED**
1. **Pure Local 1:1 `:petnames` Address Book (`bitecho.light-node.core`)**:
   - Initialized `:petnames {}` in light-node state with strict 1:1 bidirectional bijection (`petname <-> pubkey`).
   - Pure validation and normalization: `valid-pubkey-hex?`, `normalize-pubkey-hex`, `valid-petname?`, `normalize-petname` (case-insensitive, trimmed, optional leading `@` stripped, strictly disjoint from 88-char hex pubkeys).
   - Bijective resolution: `pubkey->petname`, `petname->pubkey`, `resolve-counterparty`, `resolve-session-id`, `resolve-accept-session-id`.
   - Protocol verbs: `petname-set` (conflict detection on collisions, clean old-binding removal on `--overwrite`), `petname-list`, `petname-remove` (by petname or pubkey), `petname-resolve`.
   - Bidirectional resolution across all commands: `offer`, `accept`, `send`, `close`, `transfer`, `settle-intent`, `inbox`, and `status`.
2. **Untrusted Wire Injection Immunity**:
   - Wire event handlers (`handle-wire-offer`, `handle-wire-accept`, `handle-wire-sealed-msg`, `handle-wire-close`) enrich emitted stdout events and inbox items with locally resolved petnames. Any incoming wire payload containing `:petname`, `:nickname`, or `"petname"` is strictly ignored and never imported into local state.
3. **Boundary Shell CLI, SKILL.md & Automated Flag Inventory**:
   - CLI verbs in `bitecho.shell.light-node`: `petname-set`, `petname-list`, `petname-remove`, `petname-resolve`.
   - Flags supported: `--petname`, `--pubkey`, `--overwrite`.
   - Documentation updated in `skill/SKILL.md` and verified with 100% bidirectional parity against `test-cli-and-skill-flag-inventory` in `test/bitecho/shell/light_node_test.clj` (all 19 verbs and 25 flags).
4. **Rigorous Test Coverage**:
   - `test-petname-pure-validation-and-resolution-helpers`: validation, normalization, and disjointness between pubkeys and petnames.
   - `test-petname-commands-and-bijection`: 1:1 bijection, conflict rejection, and overwrite semantics.
   - `test-petname-bidirectional-counterparty-resolution-and-events`: end-to-end multi-agent session lifecycle with petname resolution and wire-injection immunity.
   - `prop-petname-bijection-and-bidirectional-resolution`: 50-run generative property test asserting state bijection preservation and bidirectional resolution across arbitrary command sequences.

#### Step 2B — Directory-Signed Attestation & DAC Anchor Delegation *(Axiom Amendment 2)* — **COMPLETED**
1. **Directory-Signed Attestation with Proof-of-Possession (`bitecho.light-node.core`)**:
   - Enforced Axiom Amendment 2: global directory attestation must be signed by the directory authority after proof-of-possession; agent self-signature proves key continuity only.
   - Pure cryptographic functions:
     - `create-directory-pop` & `verify-directory-pop`: canonical string `bitecho-directory-pop-v1|<domain>|<nickname>|<pubkey>|<sorted-home-set>|<epoch>|<prev-pubkey>`. Signs with current agent private key (`:pop-signature`) and optionally previous private key (`:rotation-signature`) to prove key rotation continuity without central key custody.
     - `sign-directory-descriptor` & `verify-directory-descriptor`: canonical string `bitecho-directory-attestation-v1|<domain>|<nickname>|<pubkey>|<sorted-home-set>|<mailbox>|<issued-epoch>|<expires-epoch>|<prev-pubkey>|<pop-signature>|<rotation-signature>`. Signed exclusively by the trusted directory authority key.
     - Fail-closed verification enforces trusted directory authority pubkey, active epoch validity window, future-epoch guards ($issued \le current + 2$), PoP verification, and authority signature verification. Self-signed descriptors without directory authority signature fail closed (`untrusted-directory-authority` or `invalid-directory-signature`).
2. **Delegated Agent Certificates (DACs: Anchor Key -> Agent Key)**:
   - Pure functions for parent cold anchor key delegation to ephemeral hot agent nodes:
     - `create-dac` & `verify-dac`: canonical string `bitecho-dac-v1|<anchor-pubkey>|<agent-pubkey>|<issued-epoch>|<expires-epoch>|<max-spend-per-epoch>|<sorted-scopes>`. Signs with anchor cold key; deterministic SHA-256 `dac-id`.
     - `create-dac-revocation` & `verify-dac-revocation`: canonical string `bitecho-dac-revoke-v1|<anchor-pubkey>|<agent-pubkey>|<dac-id>|<revoked-epoch>`.
     - Verification enforces key disjointness, agent pubkey matching, epoch validity, revocation list checks, permitted scope enforcement, and anchor signature integrity.
3. **Integration into Light-Node State, Commands, Wire Envelopes & Mesh Boundary**:
   - Light-node state maintains `:dac`, `:revoked-dacs`, and `:directory-cache`.
   - Protocol verbs: `dac-attach`, `dac-revoke`, `directory-verify`.
   - `directory-verify` caches verified descriptors in `:directory-cache` and enforces key rotation continuity against previously cached keys (`broken-key-continuity`), while strictly never mutating local `:petnames`.
   - `status` and `identity` surface attached DAC summaries, revoked DAC counts, and directory cache counts.
   - Channel offers (`offer`) attach active DACs; inbound wire offer handler (`handle-wire-offer`) validates DAC, rejecting invalid/revoked/expired DACs fail-closed and surfacing verified anchor key and DAC ID on `"offer-received"` events.
   - Mesh ingress boundary (`wrap-agent-event` & `unwrap-authenticated-agent-event`) supports optional DAC attachment and verifies DAC validity against agent identity and epoch, failing closed on signature or validity failure.
4. **CLI, Documentation & Generative Properties (Rules 1, 3, 6)**:
   - CLI verbs in `bitecho.shell.light-node`: `dac-attach`, `dac-revoke`, `directory-verify`.
   - Full documentation and usage examples added to `skill/SKILL.md` with 100% bidirectional parity against `test-cli-and-skill-flag-inventory` (22 verbs and 25 flags).
   - `test-directory-signed-attestation-and-pop`: PoP creation, verification, key rotation continuity, and directory descriptor validation.
   - `test-dac-creation-revocation-and-commands`: DAC creation, verification, revocation, command handlers, wire offer DAC attachment, and mesh envelope verification.
   - `prop-directory-attestation-and-dac-security-invariants`: 50-run generative property test verifying directory attestation PoP & authority security, key rotation continuity, and DAC delegation invariants.

#### Step 2C — Two-Phase Callee-Pays Rendezvous $\rightarrow$ Sealed-Channel Key-Exchange Handoff *(Axiom Priority)* — COMPLETED
- Wired `bitecho.rendezvous.core` (`OfferHeader` + signaling burn $\rightarrow$ policy-gated `DeliveryAck` voucher $\rightarrow$ payload reveal) directly into the X25519 sealed channel handshake so a callee-pays rendezvous introduction seamlessly transitions into an E2E encrypted sealed conversation.
1. **Phase 1 Caller Introduction (`rendezvous-offer` / `:rendezvous-offer-header`)**:
   - Caller generates ephemeral X25519 keypair and deterministic `offer-hash`.
   - Caller withholds ephemeral public key, storing private state and optional initial payload text in `:outbound-rendezvous`.
   - Emits `:rendezvous-offer-header` signed over canonical Phase 1 header string (`bitecho-rendezvous-header-v1|...`).
2. **Phase 1b Callee Evaluation & Voucher Issuance (`rendezvous-policy` / `:rendezvous-ack-voucher`)**:
   - Callee evaluates header against pure policy (`:min-burn`, `:price`, `:allowlist`, `:home-node`, `:auto-accept?`), failing closed on policy violation.
   - Generates callee ephemeral X25519 keypair, signs `DeliveryAck` voucher bound to monotonic sequence counter via `rendezvous/create-delivery-ack`, and buffers accept in `:pending-rendezvous-accepts`.
   - Emits `:rendezvous-ack-voucher` signed over canonical Phase 1b string (`bitecho-rendezvous-ack-v1|...`).
3. **Phase 2 Caller Voucher Verification & Reveal (`handle-wire-rendezvous-ack`)**:
   - Caller verifies callee envelope signature and verifies `DeliveryAck` voucher via `rendezvous/verify-delivery-ack`, recording voucher into `:vouchers`.
   - Derives session keys via `sealed/derive-session-keys` and opens active session.
   - Broadcasts `:rendezvous-reveal` containing `:caller-x25519`. If initial text was queued, immediately seals and emits `:sealed-message`.
4. **Phase 2b Callee Commitment Verification & Session Establishment (`handle-wire-rendezvous-reveal`)**:
   - Callee verifies caller's revealed `:caller-x25519` matches Phase 1 `offer-hash` commitment (`compute-offer-hash`). Tampered or swapped ephemeral keys fail closed.
   - Derives matching symmetric session keys via `sealed/derive-session-keys` and opens active session.
   - Inbound queued initial `:sealed-message` is decrypted and delivered directly into Callee's `:inbox`.
5. **Quality Gates & Invariants (Rules 1, 3, 6)**:
   - CLI verbs `rendezvous-policy`, `rendezvous-offer`, `rendezvous-accept` and flags documented in `skill/SKILL.md` with 100% bidirectional parity in `test-cli-and-skill-flag-inventory` (25 verbs and 33 flags).
   - Generative `test.check` property `prop-two-phase-rendezvous-to-sealed-handoff` (50 runs) verifying bidirectional key symmetry, voucher recording, and message delivery.
   - Comprehensive unit and fail-closed security tests in `test-rendezvous-policy-command-and-enforcement`, `test-two-phase-rendezvous-handshake-end-to-end`, and `test-rendezvous-tamper-resistance-and-fail-closed`.

---

### Milestone 3: Verified-Outcome `$ECHO` Escrow Settlement Primitive (`lock-intent` / `release-intent` / `refund-intent`) (`master-plan-vision-roadmap.md` Principles 2 & 3 / M4–M6 Bridge) — COMPLETED

- Bitecho is strictly single-currency (`$ECHO`) per Simon's architectural decision; multi-currency and cross-currency swap locks are omitted.
- Implemented a pure, deterministic escrow/hash-lock settlement primitive (`lock-intent` / `release-intent` / `refund-intent`) across `bitecho.economy.escrow`, `bitecho.state-machine`, `bitecho.shell.mesh`, `bitecho.light-node.core`, and `bitecho.shell.light-node` with mandatory $\tau = 0.5\%$ (`50 bps`) settlement take burned upon verified outcome release and deterministic timeout refund:
1. **Deterministic Escrow Identification (`compute-escrow-id`)**:
   - Canonical string `bitecho-escrow-v1|<payer>|<receiver>|<amount>|<deliverable-hash>|<created-epoch>|<expires-epoch>|<nonce>` hashed via SHA-256 to 64-character hex ID.
   - Deliverable commitments verified via `valid-deliverable-hash?` and `verify-deliverable-preimage`.
2. **Deterministic Lifecycle & Supply Conservation Invariants**:
   - `:lock-intent` deducts amount from payer balance and creates locked escrow. In consensus mode, staged lock intents immediately deduct from payer's `spendable-balance` to prevent unfinalized double-locking.
   - `:release-intent` verifies outcome via cryptographic preimage match or Ed25519 outcome attestation signature (`verify-escrow-release-sig`), burns 0.5% protocol take (minimum 1 unit burned for positive amounts), and credits net amount to receiver ledger balance.
   - `:refund-intent` executes timeout refund (or receiver voluntary refund) returning 100% of escrowed funds back to payer with zero take burned.
   - Idempotent execution: no escrow can be settled twice or both released and refunded; competing duplicate receipts fail closed.
   - Supply conservation invariant verified: $\text{initial\_supply} - \sum \text{released\_takes} = \sum \text{balances} + \sum_{\text{locked}} \text{amount}$.
3. **Light-Node Commands, DAC Spend Authorization & CLI Parity**:
   - Light-node commands: `lock-intent`, `release-intent`, `refund-intent`, `escrows`.
   - Attached DACs enforce `:max-spend-per-epoch` limits under scope `"lock-intent"`.
   - 100% bidirectional CLI verbs and flags inventory parity in `test-cli-and-skill-flag-inventory` (29 verbs, 37 flags including `--escrow-id`, `--deliverable-hash`, `--expires-epoch`, `--preimage`).
4. **Generative Property & Quality Verification (Rules 1, 3, 6)**:
   - `test/bitecho/economy/escrow_test.clj`: unit tests and `prop-escrow-release-signature-roundtrip`.
   - `test/bitecho/state_machine_test.clj`: 50-run generative property `prop-escrow-conservation-and-no-double-settlement`, fail-closed guards, and consensus block finalization tests.
   - `test/bitecho/light_node/core_test.clj`: `test-light-node-escrow-commands-and-dac-enforcement`.

---

## 5. Phase 2 Sociocratic Consent Record (`seq=59` $\leftrightarrow$ `seq=83` $\leftrightarrow$ `seq=60` $\leftrightarrow$ `seq=85` — 2026-11-02)

> **Axiom Consent Input & Paramount Objections (`seq: 83`):**
> *"Consent-round input from Axiom. Simon confirmed he asked for this round and that the standing constraints hold: no faucet, onboarding is earn-first (agent works) + manual operator transfers, fiat top-up deferred. The rest below is my input for the proposal; paramount objections first.*
> *PARAMOUNT OBJECTIONS:*
> *1. Faucet/starter allocation in Pillar C: object. Simon reaffirmed no faucet. Drop any faucet, starter allocation, or new emission from the proposal. Directory part of C stands.*
> *2. Baseline 41f5ef7: object to consenting on it. I have not reviewed 41f5ef7 (daemon here runs reviewed 9928ea2c). Re-base the proposal on a reviewed HEAD, or I review 41f5ef7 including intervening commits before consent. Do not treat M1-M3-complete at 41f5ef7 as established.*
> *PILLAR A (agree, amended): Fix at clj-datachannel level, verified at 36beb20: keepalive is 15s and sends only if :remote-ice-ufrag/:pwd are set; validator 0x0001 handler never extracts USERNAME so those creds are never populated from the wire and the validator never keepalives back; reaper (10s check) silently dissocs children after 30s (non-connected) / 60s (any) since :last-stun-received only, no notify/close; 0x0101 returns own reflexive address as :candidate. Fix must: parse USERNAME, reaper notify/close, idleness on last-any-traffic/SCTP state not last-stun-only (else kills live SCTP peers), stop self-candidate pollution, add idle wire test + leak repro. 25s bridge keepalive is a stopgap only. Q3 trigger (what started the silence) still unevidenced. A2 reconnect: bounded retries + home-set re-register + unacked replay, autonomous OFF preserved (never auto-accept), replay must not double-burn.*
> *PILLAR B (agree, amended): Shell HTTP fetch-validator-accountz exists out-of-band; the gap is in-band over 5010/DTLS. Require signed/authenticated snapshot, cross-checked across the bootstrap validator set, fail closed on stale/disagreement. Must cover balance, seq, deps, finalized_epoch, and escrow statuses (:locked/:released/:refunded). This closes my current gap: seq-58 finalization at epoch 971 is peer-reported only vs local epoch 0 / no account.*
> *PILLAR C (directory agree, faucet objected above): Directory-signed attestation after PoP is load-bearing; agent self-signature proves continuity/rotation only. Need registration flow, home-set publication, bitecho.org/<nickname> lookup, and directory key-custody story. Onboarding readiness also needs one-line light-node launch + SKILL.md + guide (ticket still DRAFT).*
> *PILLAR D (demo/testnet): Demo (master-plan M3): clj-einsum as app example, laptop two-device, phone third device as light node without local inference first, 3 full nodes as BFT genesis; exit is a live demo of two different harnesses talking through the devnet plus a two-device pipeline split, that gets angel meetings. Neutrality is the claim to prove - today only Axiom+Nexus on one Clojure stack, so skill v1 (M2, two harnesses, sealed settled exchange, burn accounting asserted, D1-D8) comes first; honest framing only (simulators 15/100/1000, no 100M claim). Testnet (M4) gates: third-party validators finalizing under the demand gate, directory resolving, Treasury SLA on redundant infra, at least one real workload paying only on verified outcome; plus versioning/upgrade policy (rolling upgrades broke offers, FLAG B), SLA/monitoring, and a soak + convergence audit on the deployed HEAD. Store-and-forward (offline loss, e.g. seq 8) stays an open gap: either design spool/redelivery or state live-only explicitly.*
> *ORDERING: A + B first, then M2 skill + demo build, then testnet onboarding. No third-party onboarding before A/B and directory are live. - Axiom"*
>
> **Axiom Ratification & Consent ACK (`seq: 85`):**
> *"Consent ACK (Axiom, seq 60): zero paramount objections to the revised proposal as a plan - Step 0 review gate, then M4, M5, M6, M7 in that order, no faucet, earn-first + manual transfers. Consent is to the plan and the Step 0 gate, not an endorsement of 3fd8c72/0d066bc/41f5ef7 themselves. Step 0 review starting now; any flags get remediated before Pillar A. Simon directed this consent + review. - Axiom"*

---

## 6. Ratified Phase 2 Milestones (Step 0 & Milestones 4–7)

### Standing Constraints
1. **No Faucet / No Starter Allocation / No Unbacked Emission**: External agent onboarding is strictly **earn-first** (agents earn `$ECHO` by completing verified-outcome work) plus **manual operator transfers** (`./scripts/cluster.sh fund` / direct transfer from existing supply). Fiat top-up remains deferred.
2. **Reviewed Baseline Gate (`9928ea2c` $\rightarrow$ `41f5ef7`)**: Milestones 1–3 are ratified at reviewed baseline `9928ea2ce5c930b4978a6a73731d75da8bd17c72` (`9928ea2c`). Intervening live-workout commits (`3fd8c72`, `0d066bc`, `41f5ef7`) undergo explicit review and remediation in **Step 0** before Milestone 4 begins.
3. **Strict Ordering**: `Step 0 -> Milestone 4 (Pillar A) -> Milestone 5 (Pillar B) -> Milestone 6 (Pillar C + Master-Plan M2/M3) -> Milestone 7 (Pillar D / Master-Plan M4)`. No third-party onboarding before Milestones 4, 5, and the live directory service are operating.

---

### Step 0: Baseline Review & Convergence Gate (`9928ea2c..41f5ef7`)
1. **Intervening Commit Review (`3fd8c72`, `0d066bc`, `41f5ef7`)**:
   - Review `3fd8c72` (escrow network event whitelist in `bitecho.shell.core` + `account/transfer-hash` receipt ID deduplication), `0d066bc` (`effective-chain-epoch` decoupling `sync-account` from peer-to-peer wire `:epoch` + Basalt self-peer exclusion + Murmur hop-sender exclusion), and `41f5ef7` (`build-unacked-replay-envelopes` on `register-home-set` keepalive).
2. **Axiom Step 0 Review Verdict (`seq: 86` — ACCEPT WITH FLAGS: 2 HIGH, 1 MEDIUM, 2 LOW)**:
   - **HIGH 1 (`3fd8c72` dedup test setup)**: `test/bitecho/shell/core_test.clj` dedup test builds non-consensus state (missing `:peers-map`), so `handle-on-deliver` applies directly instead of staging into `:pending-receipts`; code dedup is verified correct in consensus mode—fix test setup to include `:peers-map`.
   - **HIGH 2 (`0d066bc` $\times$ `41f5ef7` replay epoch-bump & envelope reuse)**: Do not bump sealed message `:epoch` during unacked outbox replay (session epoch is authoritative) and reuse the original signed gossip envelope bytes so replay preserves the original `message-id` (preventing double-burn and preventing >2 epoch skew drops on epoch-0 receivers); update `DESIGN.md` §F.4.
   - **MEDIUM 3 (`handle-lock-intent` created-epoch staleness check before clamp)**: Validate `created-epoch >= current-epoch - 168` before any clamping in `handle-lock-intent` so stale locks are rejected rather than clamped to a different `escrow-id`.
   - **LOW 4 (Murmur 2-peer sender exclusion)**: Never fall back to echoing a gossip message back to its hop `:sender` when no other remote peers exist in `:basalt-view`.
   - **LOW 5 (Rule 6 Doc/Spec & Shell Test Parity)**: Document `effective-chain-epoch` / wire epoch decoupling in `DESIGN.md` and add a shell-level test for `41f5ef7` unacked replay on `register-home-set`.
3. **Flag Remediation & Convergence Gate**:
   - Remediate HIGH 1, HIGH 2, MEDIUM 3, LOW 4, and LOW 5 in a single clean commit, re-probe with Axiom, upgrade both daemons and the 3-node devnet cluster to the ratified HEAD, and verify 100% convergence via `./scripts/cluster.sh audit`.

---

### Milestone 4 (Pillar A): Transport Durability, STUN/Reaper Fix & Light-Node Reconnect Liveness

#### Step 4A — `clj-datachannel` Transport & Reaper Fix (`2abeab8`) — **`[BUILT & VERIFIED]`**
1. **Parse STUN `USERNAME` (`0x0006`) & Bidirectional Validator Keepalive**:
   - `datachannel.stun/handle-packet` rewinds and parses `ATTR_USERNAME` (`0x0006`) on Binding Requests after message-integrity validation. Splits `local-ufrag:remote-ufrag`, asserts target ufrag matches local `ice-ufrag` (or rejects), and `datachannel.core/handle-receive` populates `:remote-ice-ufrag` from the STUN request and resolves `:remote-ice-pwd` via `:peer-ice-pwds` (populated on validators via authenticated `:register-home-set` envelopes and `api/set-remote-ice-credentials!`) for symmetric keepalive routing.
   - `create-connection` retains `:peer-ice-pwds` from options, and `handle-receive` resolves peer passwords across both static maps and dynamic `IDeref` atoms. Added pure `:set-remote-ice-credentials` event and `api/set-remote-ice-credentials!` helper.
   - Isolated network packet transmissions in `api/apply-action!` with `try/catch` so transport socket exceptions never abort application lifecycle callbacks (`:on-close`, `:on-error`).
2. **Traffic-Aware Idleness Tracking (`last-any-traffic` / SCTP State)**:
   - Initialized and updated `:last-any-traffic` across STUN, DTLS application/handshake, and valid SCTP verification tags. `handle-timeout-timer :stun/keepalive` evaluates idleness against `(max :last-any-traffic :last-stun-received)` with association-aware timeouts (`30s` unestablished / `60s` established), guaranteeing active SCTP data channels are never prematurely marked disconnected.
3. **Explicit Reaper Notify/Close on Eviction**:
   - Implemented pure `(should-reap-child? [st now-ms])` and explicit eviction `(reap-expired-children! [routing-table now-ms])` (and updated `reap-tcp-connections!`). On eviction of expired children (>60s idle), cleanly sets `@(:running child)` to false, transitions state to `:closed`, fires `:on-close` (`{:type :on-close :cause :reaper-timeout}`), and sends encrypted DTLS/SCTP `ABORT` chunks to cleanly close remote peer associations without socket leaks.
4. **Stop `0x0101` `XOR-MAPPED-ADDRESS` Self-Candidate Pollution**:
   - `0x0101` Binding Responses return `{:binding-response? true :mapped-address candidate-str :candidate candidate-str}`. `datachannel.core/handle-receive` routes server-reflexive candidates to `:local-candidates` and strictly prevents pollution of `:remote-candidates`.
5. **Deterministic Idle-Wire & Leak Repro Tests**:
   - Added `test/datachannel/reaper_keepalive_test.clj` verifying Binding Request username extraction and target ufrag matching, server-reflexive candidate non-pollution across keepalives, traffic-aware idleness at $t = 75\text{s}$, explicit reaper eviction with encrypted DTLS/SCTP ABORT chunk emission, bidirectional keepalive credential resolution (map and atom), and `apply-action!` exception resilience. All STUN/reaper unit tests pass; 0 lint warnings.

#### Step 4B — `bitecho.shell.light-node` Proactive Reconnect & Non-Double-Burn Replay — **`[BUILT & VERIFIED]`**
1. **Proactive Reconnect on `:on-close` (Rule 4 & Rule 5)**:
   - When `:on-close` fires in `make-client-callbacks`, transitions `conn-atom` through `transition-conn` and drives bounded exponential-backoff reconnect via `attempt-proactive-reconnect!` (up to 3 attempts, configurable backoff).
   - In `make-client-callbacks` (`:on-close`), deduplicates by generation (`already-closed-this-gen?` when `@conn-atom` is already `:failed` or `:down` for the same generation), guaranteeing both pre-open (`:dialing`) and post-open (`:open`) `:on-close` events trigger `attempt-proactive-reconnect!` while duplicate same-generation `:on-close` callbacks never invoke `attempt-proactive-reconnect!` a second time.
   - Upon reconnect, `reconnect-fn` calls `(build-reconnect-recovery-envelopes @state-atom privkey)`, automatically re-registering `:home-set` candidates (carrying `:ice-ufrag` and `:ice-pwd` at current epoch and nil epoch) and replaying unacknowledged session outbox envelopes.
2. **Preserve `:autonomous? false` Default & Scoped Ingress Credential Population**:
   - `run-serve!`, `run-one-shot!`, and reconnect recovery strictly preserve `:autonomous? false` by default, preventing unexpected auto-acceptance unless `--autonomous` was explicitly specified by the operator.
   - In `src/bitecho/shell/mesh.clj`, `init-agent-listener!` and `init-agent-tcp-listener!` pass a shared `:peer-ice-pwds` atom, and `make-agent-connection-handler` updates credentials strictly on incoming authenticated agent `:register-home-set` envelopes with ufrag ownership verification (`[:owner ufrag] -> sender`), enabling validator-to-agent bidirectional keepalive emission while preventing cross-agent ufrag poisoning.
3. **Idempotent Non-Double-Burn Outbox Replay & LOW 6 Resolution**:
   - Replay strictly reuses cached `:gossip-env` entries from `:outbox` to preserve exact original `:message-id`s (`sha256(payload-bytes)`), eliminating duplicate burns and preventing validator double-spend rejections.
   - Closed **LOW 6**: Updated envelope path assertions in `test/bitecho/light_node/core_test.clj` and `test/bitecho/shell/light_node_test.clj` to inspect `(get-in env [:event :message :message-id])` and `(get-in env [:event :message :payload])` and assert non-nil `orig-msg-id`, ensuring envelope assertions are strictly non-vacuous.
   - Added property test `prop-proactive-reconnect-and-lifecycle-invariants` (30 trials) and unit tests verifying bounded reconnect retries, recovery envelope generation, stale-generation `:on-close` isolation (`gen < current` increments `:ignored-stale` and skips reconnect), autonomous flag preservation, duplicate same-generation `:on-close` idempotency, and agent ICE credential propagation. All tests pass; 0 lint warnings.

---

### Milestone 5 (Pillar B): In-Band Validator $\rightarrow$ Light-Node Authenticated Chain State Sync (Over Port 5010/DTLS)

#### Step 5A — Signed/Authenticated Chain State Snapshot & Multi-Validator Cross-Check — **`[BUILT & VERIFIED]`**
1. **In-Band `:query-chain-state` / `:chain-state-snapshot` Protocol**:
   - Extended the Port `5010` / DTLS agent channel with an authenticated in-band chain-state query/response protocol (complementing out-of-band HTTP `fetch-validator-accountz`).
   - Query envelopes carry authenticated `{:type :query-chain-state :pubkey <hex> :nonce <str>}` signed by agent Ed25519 identity.
   - Validator responses carry a validator-signed `:chain-state-snapshot` covering the querying agent's finalized `balance`, `spendable`, `seq`, `deps`, `finalized_epoch`, and the statuses (`:locked` / `:released` / `:refunded`, `:settled-epoch`, `:net-amount`, `:refund-reason`) of escrows involving the agent.
2. **Multi-Validator Quorum Cross-Check & Fail-Closed Verification**:
   - Implemented pure `canonical-chain-state-snapshot-str`, `sign-chain-state-snapshot`, `verify-chain-state-snapshot`, and `verify-chain-state-quorum`.
   - Cross-checks signed snapshots across the bootstrap validator set, verifying validator Ed25519 signatures, verifying epoch freshness, and failing closed on stale epochs, untrusted validators, tampered signatures, or state disagreement across quorum.
   - Wire payload processing (`handle-wire-payload`) explicitly bypasses the 2-epoch skew drop for incoming `:chain-state-snapshot`, enabling light nodes to fast-forward from genesis/epoch 1 to finalized chain epoch without false drop.
3. **Light-Node `sync-account` & `escrows` Integration**:
   - Wired in-band snapshot verification directly into `maybe-sync-account-state!` with primary in-band DTLS/DataChannel parallel querying and fallback to HTTP.
   - Wired `sync-account`, `account --sync`, and `escrows --sync` in `run-serve!` and `run-one-shot!`, immediately failing closed on quorum error or state divergence.
4. **Milestone 4 Follow-Ups & Generative Verification**:
   - Remediated **HIGH 1** with secure random ICE credentials (`generate-random-ice-creds`), persistence in `node-identity.edn`, and automatic rotation of legacy deterministic passwords on read.
   - Remediated **MEDIUM 2** with generation-deduplicated `:on-close` reconnect triggers covering both pre-open dialing and open phases.
   - Remediated **LOW 4** with strict `:register-home-set` scoping and anti-poisoning ownership checks for peer ICE credentials.
   - Remediated **LOW 5** removing dead code and updating documentation.
   - Remediated **Cross-Validator Unacked Replay Fix** by pruning `:murmur-cache` on TTL eviction and preventing redundant gossip re-burns.
   - Verified via generative property test `prop-inband-chain-state-snapshot-quorum-and-fail-closed` (50 runs), unit/integration tests `test-ice-random-credentials-generation-and-rotation` and `test-inband-chain-state-sync-and-escrows-quorum`. All 348 tests pass; 0 lint warnings.

#### Step 5B — Axiom `seq: 100` BFT Quorum Wire Buffering & Fail-Closed Hardening — **`[BUILT & VERIFIED]`**
1. **Wire Snapshot Buffering & Multi-Validator BFT Quorum (`HIGH 1`)**:
   - Updated `handle-wire-chain-state-snapshot` in `src/bitecho/light_node/core.clj` to buffer incoming validator snapshots keyed by validator pubkey into `:chain-state-snapshots` rather than applying single-validator wire messages immediately.
   - Evaluates `verify-chain-state-quorum` across buffered snapshots; only advances light-node finalized epoch, balances, and escrow statuses upon $\ge 2f+1$ (2/3) quorum agreement among trusted validators.
   - Prunes stale snapshots older than $fin\_epoch - 2$ on receipt.
2. **Untrusted Validator Set Fail-Closed (`MEDIUM 1`)**:
   - `verify-chain-state-snapshot` explicitly fails closed with `{:ok? false :error "untrusted-validator"}` when `:trusted-validators` is nil or empty `#{}`.
3. **Monotonicity & Escrow Field Clearing Guard (`LOW 1` & `LOW 2`)**:
   - Added monotonicity check to `apply-verified-chain-state-snapshot` (`(< fin-epoch curr-fin-ep)` returns unmodified state), preventing regressive snapshots from reverting finalized epochs.
   - Clears stale status-dependent fields (`:settled-epoch`, `:net-amount`, `:take-burned`, `:refund-reason`) when merging incoming escrows, ensuring transitions back to `:locked` or to `:refunded` never retain conflicting keys.
4. **Mesh Dial Credential Enforcement & Unsigned Snapshot Refusal (`LOW 3` & `LOW 4`)**:
   - Removed legacy `deterministic-ice-creds` fallback from `init-datachannel-peer!` in `src/bitecho/shell/mesh.clj`. Dials strictly fail closed with `{:type :dial-failed :peer pid :error "missing-ice-credentials"}` if either local or remote ICE credentials lack `:ufrag` or `:pwd`.
   - `build-validator-chain-state-snapshot` and `make-agent-connection-handler` strictly refuse to serve unsigned or unverified snapshots over the wire.
5. **Allowed Network Events & Test Runner Coverage (`LOW 5`)**:
   - Added `:query-chain-state` to `allowed-network-events` in `src/bitecho/shell/core.clj`.
   - Registered `bitecho.shell.core-test` and `bitecho.shell.persistence-test` in `test/bitecho/test_runner.clj`.
   - Verified via property test `prop-inband-chain-state-snapshot-quorum-and-fail-closed` and unit test `test-chain-state-snapshot-wire-bft-quorum-and-invariants`. All 358 tests (2921 assertions) pass; 0 lint warnings; format clean.

---

### Milestone 6 (Pillar C + Master-Plan M2/M3): Live Directory Service, Multi-Harness Skill v1 & Angels Demo

#### Step 6A — Live Nickname Directory Authority & Zero-Faucet Onboarding Readiness
1. **Directory Authority Core & Shell Architecture (`bitecho.light-node.core`, `bitecho.shell.light-node`)**:
   - Updated `parse-bootstrap-txt` and `parse-bootstrap-edn` to parse and propagate `:directory-pubkey`.
   - Updated `init-light-state` to configure `:trusted-directory-pubkey`.
   - Added pure helper `parse-directory-descriptor-text` supporting raw JSON, EDN, or Markdown documents containing fenced ```` ```json ```` codeblocks (`https://bitecho.org/<nickname>`).
   - Implemented `directory-register` (`create-directory-pop` supporting optional `:rotation-signature` for continuous key continuity) and `directory-lookup` (resolving nicknames, auto-fetching descriptors, verifying directory authority signatures, and caching in `:directory-cache` without mutating local petnames).
   - Wired injectable `(:directory-fetcher opts)` in `fetch-directory-descriptor!` in `light_node.clj`, auto-fetching missing descriptors during `directory-lookup` and `directory-verify`.
   - Added CLI subcommand `sign-directory-pop` in `src/bitecho/main.clj` to sign descriptors under cold authority identities.
2. **Cluster Tooling, Web Publishing & Onboarding Guide**:
   - Updated `scripts/cluster.sh` Step 2/7 to ensure Directory Authority identity at `${CLUSTER_KEY_DIR}/directory` and export `DIRECTORY_PUB`.
   - Updated `scripts/cluster.sh` Step 6/7 to include `:directory-pubkey "${DIRECTORY_PUB}"` in `devnet/bootstrap.edn` and `Directory Authority Public Key: ${DIRECTORY_PUB}` in `devnet/bootstrap.txt`.
   - Added `register-directory` CLI command to `scripts/cluster.sh`, generating signed descriptors and publishing them to `/home/simonpure/src/alpeware/clj-web/public/` (`directory/<nickname>.json`, `<nickname>/index.json`, and human-readable Markdown with embedded JSON block `<nickname>/index.md`).
   - Created `scripts/light-node.sh` (`chmod +x`) with default `--bootstrap https://bitecho.org/devnet/bootstrap.txt`.
   - Created `ONBOARDING.md` documenting one-line launch, earn-first zero-faucet participation, Directory Authority cold key custody & PoP registration/lookup, and explicit live-only delivery semantics vs. 10-epoch validator cache and 64-entry session outbox SACK replay.
   - Updated `skill/SKILL.md` and `test-cli-and-skill-flag-inventory` with 100% bidirectional parity (31 verbs, 42 flags).
3. **Axiom `seq: 112` Snapshot Escrow Pruning**:
   - Updated `apply-verified-chain-state-snapshot` so that when a snapshot with `:escrows` is synced, any unconfirmed non-terminal local escrow absent from incoming escrows older than $fin\_epoch - 5$ is pruned, while recent in-flight and terminal escrows are preserved. Verified in `test-chain-state-snapshot-wire-bft-quorum-and-invariants`.

#### Step 6B — Multi-Harness Skill v1 & Angels Demo (`master-plan-vision-roadmap.md` M2 & M3)
1. **Multi-Harness Neutrality Proof (`master-plan` M2)**:
   - Implemented `run-multi-harness-neutrality-demo` in `src/bitecho/demo/angels.clj`:
     - Connects two distinct agent harness models across the 3-node Streamlet BFT cluster: Harness A (JSONL external bridge driving `process-jsonl-line`) and Harness B (JVM-native compiled Clojure maps driving `handle-command`).
     - Demonstrates full cryptographic lifecycle: PoP generation, Directory Authority signing, discovery via `directory-lookup`, petname assignment, callee-pays rendezvous introduction, E2E X25519 sealed channel key derivation, verified-outcome hash-locked escrow, sealed preimage delivery, and release with $\tau = 0.5\%$ (50 bps) protocol settlement take burned on 3-chain block finality.
     - Performs 3-of-3 BFT quorum snapshot verification across all validators (`verify-chain-state-quorum`), asserts supply conservation ($\text{initial\_supply} - \text{take\_burned} = \sum \text{final\_balances}$), and verifies both harnesses synchronizing finalized account balances.
2. **Three-Device / `clj-einsum` Angels Demo (`master-plan` M3)**:
   - Implemented `run-three-device-einsum-demo` in `src/bitecho/demo/angels.clj`:
     - Models a 2-stage split pipeline inference workflow across 3 device archetypes backed by the 3-node genesis BFT cluster:
       1) **Phone Light Node (`device-1`)**: Edge device with zero local inference; locks $10,000$ `$ECHO` escrow committed to golden deliverable hash and transmits prompt tensor $X$.
       2) **Laptop Stage 1 Shard (`device-2`)**: Computes Stage 1 contraction $Y_{\text{mid}} = \text{einsum}(\text{"ij,jk->ik"}, X, W_1)$ via pure deterministic Clojure tensor algebra, locks Stage 2 escrow ($4,000$ `$ECHO`), and forwards intermediate activations to Device 3 over sealed channel.
       3) **Laptop Stage 2 Shard (`device-3`)**: Computes Stage 2 contraction $Y_{\text{out}} = \text{einsum}(\text{"ik,kl->il"}, Y_{\text{mid}}, W_2)$, mechanically verifies tensor parity against golden reference (`verify-tensor-parity`), and transmits verified deliverable preimage back to Device 1.
     - Releases both escrows on-chain with 50 bps protocol take burned per stage (70 ECH total), validated across all 3 validators by BFT quorum snapshots.
     - Uses strictly honest simulator framing (3 cluster nodes + 3 edge devices), documenting linear purity scaling to 15 nodes, quadratic gossip convergence to 100 nodes, and hierarchical sub-clusters to 1000 nodes.
3. **CLI Runner & Test Coverage**:
   - Added `demo-angels` CLI subcommand in `src/bitecho/main.clj` and `./scripts/demo-angels.sh` (`chmod +x`), outputting complete structured JSON verification report.
   - Implemented unit tests and generative property test `prop-einsum-associativity` in `test/bitecho/demo/angels_test.clj`, and registered `[bitecho.demo.angels-test]` in `test/bitecho/test_runner.clj`. All 366 tests (3003 assertions) pass green.

---

### Milestone 7 (Pillar D / Master-Plan M4): Testnet Launch Gates

#### Step 7A — Wire Versioning Policy, Soak Convergence Audit & Testnet Exit Gates — **`[BUILT & VERIFIED]`**

1. **Axiom `seq: 115` `LOW 1..4` Remediations**:
   - **`LOW 1` (`directory-verify` auto-fetch parity)**:
     - Updated `build-one-shot-cmd-map` (`src/bitecho/shell/light_node.clj`) to parse `--nickname`, `--domain`, and `--directory-pubkey` on `"directory-verify"`.
     - Updated `run-one-shot!` and `handle-serve-line!` to auto-fetch missing descriptors via `:directory-fetcher` for both `directory-lookup` and `directory-verify`.
     - In `src/bitecho/light_node/core.clj` `exec-directory-verify`, added fallback to `(:trusted-directory-pubkey state)` or `(get-in state [:bootstrap :directory-pubkey])`.
     - Documented in `skill/SKILL.md` and added unit test `test-directory-verify-auto-fetch`.
   - **`LOW 2` (Remove hardcoded `/home/simonpure` paths)**:
     - Replaced hardcoded path in `fetch-directory-descriptor!` (`src/bitecho/shell/light_node.clj`) with HTTPS-first resolution, falling back to relative `./public` / `../clj-web/public`.
     - In `scripts/cluster.sh`, parameterized directory export with `${CLJ_WEB_PUBLIC_DIR:-${ROOT_DIR}/../clj-web/public}`.
   - **`LOW 3` (`state-machine-ttl-test` registration)**:
     - Added `[bitecho.state-machine-ttl-test]` to `test/bitecho/test_runner.clj`.
   - **`LOW 4` (Eliminate `rand-int` for 100% test reproducibility)**:
     - Replaced all pseudo-random calls across `test/bitecho/shell/discovery_test.clj` and `test/bitecho/demo/angels_test.clj` with deterministic test.check generators (`gen-fingerprint`, `include-dir-pk?`, `vals-a/b/c`).
2. **Wire Protocol Versioning & Rolling-Upgrade Policy (Closing FLAG B)**:
   - Defined pure constants `current-wire-version = 1`, `min-supported-wire-version = 1`, and `max-supported-wire-version = 2` in `src/bitecho/light_node/core.clj` and `src/bitecho/shell/mesh.clj`.
   - Added pure helpers `rolling-upgrade-compatible?` and `check-wire-version-compatibility`, verifying version compatibility across adjacent versions ($|v_1 - v_2| \le 1$) and normalizing legacy unversioned messages ($N-1$) as version 1.
   - Attached `:protocol-version current-wire-version` across all 10 outbound wire message constructors.
   - Enforced fail-closed version checking in `handle-wire-payload`, incrementing `:unsupported-dropped` and recording `:last-unsupported-version` and `:last-error` diagnostics surfaced via `exec-status` under `"wire_protocol"`.
   - In `unwrap-wire-message`, preserved outer envelope version while unwrapping inner events/messages.
   - In `src/bitecho/shell/mesh.clj`, added `valid-agent-envelope-version?`, `:protocol-version` in `wrap-agent-event`, and protocol version preservation in `unwrap-authenticated-agent-event`.
3. **Treasury SLA Monitoring & Soak Convergence Audit**:
   - Implemented pure `evaluate-treasury-sla` in `src/bitecho/economy/treasury.clj`, asserting demand gate ($k \le 0.5$, $\le 5000\text{ bps}$), supply cap ($\le 23.1\text{B}$ minted, $\le 42\text{B}$ hard cap), redundant infrastructure ($\ge 3$ active validators, quorum met), finality skew ($\le 2$ epochs), zero failed receipts, and mint convergence.
   - Incorporated Treasury SLA evaluation and `:wire-version-converged?` into `evaluate-cluster-convergence` in `src/bitecho/shell/mesh.clj`.
   - Updated `cmd_audit` in `scripts/cluster.sh` to evaluate and display Treasury SLA conformance and wire protocol version agreement.
4. **Testnet Launch Exit Gates Evaluator (`run-testnet-readiness-gate`)**:
   - Implemented `run-testnet-readiness-gate` and `run-all-angels-demos` in `src/bitecho/demo/angels.clj`, executing an in-process 4-validator simulation (`node1..node3` genesis + `node4` simulated third-party partner validator with a fresh keypair) to deterministically gate consensus, demand-gate minting ($k = 0.5$), directory attestation, verified-outcome settlement, and rolling-upgrade wire compatibility prior to external multi-operator onboarding:
     - **Gate 1**: In-process 4-validator Streamlet BFT cluster (`node1..node3` genesis + `node4` partner) notarizing and finalizing blocks under demand gate ($k = 0.5$).
     - **Gate 2**: Live Directory Authority resolving registered nicknames to keys and home sets, rejecting forged signatures.
     - **Gate 3**: Real einsum tensor workload paying strictly on verified deliverable SHA-256 preimage match with 50 bps protocol settlement take burned.
     - **Gate 4**: Rolling-upgrade wire protocol compatibility across mixed v1, legacy unversioned, and v2 payloads, with fail-closed rejection of v99.
   - Wired `main.clj` (`cmd-demo-angels`) and `./scripts/demo-angels.sh` to run all 3 angels demos and output structured JSON report.
5. **Generative Property & Test Runner Coverage (Rules 1, 3, 6)**:
   - Added generative property test `prop-treasury-sla-invariants` in `test/bitecho/economy/treasury_test.clj`.
   - Added generative property test `prop-wire-version-rolling-upgrade-compatibility` in `test/bitecho/light_node/core_test.clj`.
   - Added `test-testnet-readiness-gate` in `test/bitecho/demo/angels_test.clj`.
   - Verified via `clojure -M:test` (371 tests, 3028 assertions, 0 failures, 0 errors).
   - Flag inventory parity verified (31 verbs, 42 flags).



