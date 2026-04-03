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
