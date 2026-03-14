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

## Phase 2: The Echo Economy (Lottery & Ledger)
- [x] Implement `bitecho.lottery.core`: pure functions to generate a cryptographic lottery ticket (payload hash + nonce + signature) and evaluate if `hash(ticket) < difficulty`.
- [x] Implement `bitecho.economy.ledger`: define the Genesis state data structure and pure functions to apply valid lottery ticket payouts to an agent's Echo balance (UTXO Model).
- [x] Implement `bitecho.peer-review.core`: pure logic to validate a "Proof of Relay" (verifying a sequence of Contagion broadcast receipts and Sieve signatures).
- [x] Implement `bitecho.economy.difficulty`: a pure function that calculates the current lottery difficulty target dynamically based on the Contagion `k` fanout parameter and network size estimates.

## Phase 3: Directed Messaging (Stake-Weighted Routing)
- [x] Implement `bitecho.message.envelope`: define the pure spec and wrapping logic for a directed message envelope (destination pubkey, encrypted payload blob, attached lottery ticket).
- [x] Implement `bitecho.routing.weighted`: pure logic to select a next-hop routing target by weighting the current Basalt view according to each peer's known Echo balance.
- [x] Update `bitecho.state-machine`: integrate Phase 2 and 3 into the core reducer. Add handlers for `{:type :route-directed-message}` that validates the attached lottery ticket, claims the fee if it wins, and forwards the envelope via the stake-weighted routing logic.

## Phase 4: Programmable UTXOs & Payment Channels
- [x] Implement `bitecho.economy.sci-sandbox`: wrap `sci/eval-string` to create a strictly isolated, pure-functional Clojure interpreter. Disable all I/O and state mutations, and implement a basic instruction counter (or timeout) to prevent infinite loops.
- [x] Refactor `bitecho.economy.ledger`: update the UTXO schema. Replace `:owner-pubkey` with `:puzzle-hash`. Update `process-transaction` so that instead of just checking an Ed25519 signature, it executes `(sci-sandbox/eval puzzle solution)`. The transaction is only valid if the script returns `true`.
- [x] Implement `bitecho.channels.core`: define the pure data structures for a 2-of-2 multisig Payment Channel state. Implement functions to create an initial state, generate a multisig Puzzle, and mutually sign off-chain balance updates.
- [x] Implement `bitecho.services.turn`: define the specific pure negotiation protocol (DataChannel messages) for an agent to request a TURN allocation, verify the opening of an off-chain Payment Channel, and issue iterative balance updates per byte relayed.
- [x] Update `bitecho.state-machine` and `state_machine_test.clj`: Integrate Phase 4 by adding event handlers for the Payment Channel lifecycle (e.g., `{:type :open-channel}`, `{:type :update-channel}`, `{:type :settle-channel}`) and TURN service negotiation. Ensure the root reducer correctly transitions these states, updates the SCI-based ledger on settlement, and emits the proper `:network-out` commands. Update the generative tests to fuzz these new state transitions and prove channel settlements are secure.

## Phase 5: The Shell & Network Genesis
- [x] Add `org.clojure/core.async {:mvn/version "1.9.829-alpha2"}` to `deps.edn`.
- [x] Implement `bitecho.crypto.delegation`: define pure functions to generate, sign, and verify Delegated Agent Certificates (DACs) linking a temporary Node Key to a Parent Key.
- [x] Implement `bitecho.shell.core`: create a transparent `core.async/go-loop` adapter to wrap `bitecho.state-machine`, managing `:events-in` and `:net-out` channels. *(Note: Pivoted away from `core.async.flow` to favor architectural simplicity).*
- [x] Implement `bitecho.shell.bootstrap` and `bitecho.shell.agent`: define the `-main` entry points for the executables. Stub the datachannel/IO sinks, focusing purely on initializing the `go-loop` shell, the channels, and the Genesis state.
- [x] Implement `bitecho.shell.integration-test`: create a mock network router to wire up 4 concurrent node shells in-memory and prove Contagion/Sieve gossip propagates successfully across asynchronous channels.

## Phase 6: Security Audit Remediation
- [x] **CRIT-01 (Zero-Authorization Theft of Standard UTXOs):** Standard puzzles must enforce Ed25519 signature validation against the transaction hash (e.g., `(crypto/verify pubkey tx-hash signature)`).
- [x] **CRIT-02 (Remote Command Execution / State Injection via Flow Topology):** Implement a strict ingress routing boundary. External network messages must be explicitly mapped to a safe, whitelisted subset of allowed network events (e.g., `:receive-gossip`, `:receive-summary`).
- [x] **CRIT-03 (Arbitrary Multisig Transaction Forgery (Unbound `tx-hash`)):** The SCI sandbox evaluation environment must inject the internally computed `tx-hash` natively as an immutable binding context. It must never be supplied by the spending solution.
- [x] **CRIT-04 (SCI Sandbox Resource Exhaustion DoS (Billion Laughs)):** AST blacklisting is fundamentally insufficient. Implement strict instruction-metering limits (gas) natively via SCI's configuration interceptors, and bound memory allocations.
- [x] **CRIT-05 (Unbounded Broadcast Storms (Vector Queue Eviction Bug)):** Initialize the cache queue using `clojure.lang.PersistentQueue/EMPTY` instead of a vector.
- [x] **CRIT-06 (Complete Bypass of Sieve Cryptographic Verification):** Add `(sieve/validate-message message)` logic to the gossip handler and drop payloads that fail validation. *(Completed in PR #44)*
- [x] **HIGH-01 (Cross-Channel State Replay Attacks):** Include `channel-id` and participant keys inside the `update-map` before it is converted to a canonical string and hashed.
- [x] **HIGH-02 (Basalt Sybil/Eclipse Attack via Deterministic Hash Collision):** Insert explicit delimiters (e.g., a null byte `\x00` or `|`) between fields when constructing the `hash-input` ByteBuffer.
- [x] **HIGH-03 (Sieve Equivocation Tracker Permanently Blacklists Senders):** The equivocation history must track signatures scoped to a specific `message-id` or sequence number, not globally by sender.
- [x] **HIGH-04 (Remote DoS via Unhandled Hex Parsing Exceptions):** Add length parity validation to `hex->bytes`. Wrap external input parsing in defensive `try/catch` blocks.
- [x] **HIGH-05 (Transaction Hash Non-Determinism Forking Consensus):** Canonicalize the transaction data structure before serialization. Convert the `tx` map to a deterministically ordered collection (e.g., `(into (sorted-map) tx)`) or explicitly sort keys prior to applying `pr-str` and hashing.
- [ ] **HIGH-06 (Replay Attacks in TURN Payment Channel Off-Chain Updates):** Channel state tracking must enforce monotonic progression independently. The `turn-relay-request` verification must strictly compare the update against the server's latest localized channel state, rejecting any nonce `N` where `N <= current_nonce`.
- [ ] **HIGH-07 (Payment Channel Balance Conservation Bypass):** Add a strict invariant check ensuring `balance-a + balance-b` is conserved.
- [ ] **HIGH-08 (Lottery Ticket Claimer Spoofing):** Derive the `claimer-pubkey` from the node's internal state, not the unverified event payload.
