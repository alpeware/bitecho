## Phase 1: Routing & Gossip State Machine

- [x] Implement `bitecho.crypto` namespace (SHA-256 hashing, Ed25519 keypair generation, signing, and verification).

- [x] Implement `bitecho.basalt.core` data structures: define the Peer record (IP, port, pubkey, age, hash) and the View initialization logic.
- [x] Implement `bitecho.basalt.core` push/pull logic: pure functions to select random peers for exchange and increment peer ages.
- [x] Implement `bitecho.basalt.core` view merging: pure logic to merge a received view with the local view, respecting max view size and dropping oldest/duplicate peers.

- [x] Implement `bitecho.murmur.core` broadcast initiation: a pure function that takes a payload, generates a message ID, and selects `k` random peers from the Basalt view to gossip to.
- [x] Implement `bitecho.murmur.core` forwarding: pure logic to handle `{:type :receive-gossip}`. Must maintain a bounded cache of recently seen message IDs and forward unseen messages to `k` peers.

- [x] Implement `bitecho.sieve.core` validation: wrap Murmur payloads in Ed25519 signatures. Drop incoming messages that fail signature verification.
- [x] Implement `bitecho.sieve.core` equivocation detection: track signatures per sender to detect and drop conflicting payloads (Byzantine behavior).

- [x] Implement `bitecho.contagion.core` anti-entropy summaries: pure logic triggered by a `:tick` event to generate a digest of known message IDs and target a random Basalt peer.
- [x] Implement `bitecho.contagion.core` lazy pull: pure logic to process incoming summaries, calculate the set difference, and emit requests for missing payloads.

- [x] Implement `bitecho.state-machine`: the root reducer that ties Basalt, Murmur, Sieve, and Contagion into a single pure `(handle-event state event)` function.
- [x] Write generative state-machine fuzzer (`test.check`) to prove the Bitecho pure core maintains connected Basalt views and reliably delivers messages under simulated network drops.

## Verify Phase 1: SBRB Layer Isolation & Verification

- [x] **Enforce E2E Timeout:** Update `dev/bitecho/simulator/contagion_e2e.clj`. Replace the indefinite `(async/<!! done-ch)` block at the end of `-main` with an `async/alts!!` that races `done-ch` against an `(async/timeout 15000)`. If the timeout wins, throw an `ex-info` stating "Contagion broadcast failed to reach all honest nodes within 15 seconds" to fail the CI loop.
- [x] **Basalt Isolation Simulator:** Create `dev/bitecho/simulator/basalt_e2e.clj`. Write a simulation where 15 nodes boot, but ONLY process `:tick` and `:receive-push-view` events. Prove that after N ticks, the network topology converges (i.e., every node's Basalt view contains a healthy, randomized mix of the network, preventing network partitions). Fix any pure logic bugs in `basalt.core` or `state-machine` if this fails.
- [x] **Murmur Isolation Simulator:** Create `dev/bitecho/simulator/murmur_e2e.clj`. Disable Sieve signature checks and Contagion anti-entropy. Inject a raw `:broadcast` event. Prove that pure Murmur gossip probabilistically reaches a majority of the network before the cache evicts it. Fix any queue eviction or forwarding bugs if it storms or dies out prematurely.
- [x] **Sieve Isolation Simulator:** Create `dev/bitecho/simulator/sieve_e2e.clj`. Re-enable Sieve. Prove that Sieve echoes correctly track `E-hat` thresholds and emit `:send-contagion-ready` messages without dropping valid signatures or permanently blacklisting honest senders.
- [x] **Contagion Integration Fix:** Run `clojure -M:simulate -m bitecho.simulator.contagion-e2e`. With the underlying layers proven, debug why the final `D-hat` delivery thresholds are not being met. Fix the core state machine logic until the simulator passes before the 15-second timeout.

## Phase 2: The Echo Economy & Tokenomics

### Part A: Asynchronous Account-Based Settlement
- [x] Implement `bitecho.economy.account` data structures: define pure records for `AccountState` (balance, seq, deps) and `Transfer` (sender, receiver, amount, seq, deps, signature).
- [x] Implement `bitecho.economy.account` validation: pure function `(validate-transfer current-state transfer)`. Must enforce `seq` increments by exactly 1, causal dependencies match, balance >= 0, and signature is valid.
- [x] Implement `bitecho.economy.account` transition logic: pure function `(apply-transfer state transfer)` that decrements sender, increments receiver, and updates local causal history.
- [ ] Write generative fuzz tests (`test.check`) for account state transitions to prove double-spending is impossible without global consensus.
- [ ] **Account Isolation Simulator:** Create `dev/bitecho/simulator/account_e2e.clj`. Simulate asynchronous account transfers across the SBRB mesh. Inject malicious double-spend attempts and prove that honest nodes correctly reject invalid sequence increments and independently converge on the correct ledger state.

### Part B: Burn-and-Mint & Proof of Delivery
- [ ] Implement `bitecho.economy.burn` logic: pure function `(deduct-routing-fee state transfer)` that burns the ECHO micro-fee by removing it from the total supply.
- [ ] Implement `bitecho.economy.receipt` generation: pure function to create a probabilistic cryptographic "Proof of Delivery" receipt when an Agent successfully receives routed data.
- [ ] Implement `bitecho.economy.bundle` logic: pure functions for a Full Node to buffer validated micro-transfers and bundle them into a single array payload for Murmur broadcast.
- [ ] **Bundling Isolation Simulator:** Create `dev/bitecho/simulator/bundle_e2e.clj`. Simulate Light Nodes streaming high-frequency micro-transactions to a Full Node. Prove the Full Node correctly batches them, respecting a time-based interval, and emits a single, compressed Murmur broadcast to optimize egress bandwidth.

### Part C: Streamlet BFT Treasury (k-Shared Asset Transfer)
- [ ] Implement `bitecho.streamlet.core` data structures: define pure records for `Block` (epoch, parent-hash, payload, proposer) and `Vote` (block-hash, epoch, voter-signature).
- [ ] Implement `bitecho.streamlet.core` propose-vote paradigm: pure functions `(propose-block state epoch)` and `(cast-vote state block)`.
- [ ] Implement `bitecho.streamlet.core` notarization logic: pure function to track vote accumulations and transition a block to `notarized` when it reaches the 2n/3 threshold.
- [ ] Implement `bitecho.streamlet.core` finalization logic: pure function to scan the notarized chain and finalize a prefix when three adjacent blocks have consecutive epoch numbers.
- [ ] Write generative state-machine fuzzer (`test.check`) for Streamlet to prove safety (consistency) and liveness under simulated adversarial network delays.
- [ ] Implement `bitecho.economy.treasury` integration: pure logic to accept finalized Streamlet blocks of Proof of Delivery receipts, assign a sequence number, and emit a payout transfer command.
- [ ] **Streamlet Isolation Simulator:** Create `dev/bitecho/simulator/streamlet_e2e.clj`. Simulate an isolated cluster of `k` Genesis Partners running the Streamlet BFT consensus. Introduce extreme network jitter and partitions. Prove that the cluster maintains safety (no conflicting finalizations) and regains liveness to finalize Proof-of-Delivery payouts when synchrony is restored.