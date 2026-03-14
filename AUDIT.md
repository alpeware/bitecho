# Comprehensive Security Audit Report

**Project:** Alpeware-Bitecho (Decentralized WebRTC Signaling & Web of Trust)

**Date:** March 13, 2026

**Auditor:** Senior Protocol Security Specialist

**Status:** **CRITICAL ACTION REQUIRED**

## 1. Executive Summary

A comprehensive security and architecture audit was performed on the `alpeware-bitecho` codebase. The scope included the peer-to-peer gossip layers (Basalt, Murmur, Contagion), cryptographic primitives (Sieve, DACs), the `core.async.flow` state machine execution, and the SCI-sandboxed UTXO economy.

While the architecture showcases excellent engineering discipline by strictly separating pure state transitions from side-effecting shells (Sans-IO), **the audit uncovered catastrophic security vulnerabilities across all core layers.** These include zero-authorization theft of all network funds, trivially exploitable smart contract bypasses, guaranteed network broadcast storms, and severe remote Denial-of-Service (DoS) vectors.

**Recommendation:** The system is critically insecure. Deployment to any live environment must be halted immediately until the architectural and cryptographic flaws detailed below are completely remediated.

---

## 2. Critical Vulnerabilities

### [CRIT-01] Zero-Authorization Theft of Standard UTXOs

* **Component:** `bitecho.economy.ledger/standard-puzzle-hash`
* **Description:** The default UTXO locking puzzle for single-owner funds is defined simply as `(= "<pubkey-hex>" solution)`. When spending a UTXO, `valid-puzzle-execution?` evaluates this puzzle script against the user-provided `solution`. Because the puzzle only checks if the solution string matches the public key, **it completely omits cryptographic signature verification.**
* **Impact:** Any observer can spend any standard UTXO belonging to any user simply by submitting a transaction that claims the UTXO and provides the victim's plaintext public key as the `solution`. This results in a 100% loss of standard funds across the network.
* **Remediation:** Standard puzzles must enforce Ed25519 signature validation against the transaction hash (e.g., `(crypto/verify pubkey tx-hash signature)`).

### [CRIT-02] Remote Command Execution / State Injection via Flow Topology

* **Component:** `bitecho.shell.flow/state-machine-step`
* **Description:** The `state-machine-step` adapter routes messages from the external network (`:net-in`) directly into the pure `bitecho.state-machine/handle-event` reducer without any structural boundary validation or ingress filtering.
* **Impact:** A remote attacker can send raw EDN payloads over the network specifying internal, highly-privileged event types like `{:type :settle-channel ...}` or `{:type :route-directed-message, :payout-amount 42000000, :claimer-pubkey "attacker" ...}`. The state machine will process these as trusted commands, allowing the attacker to instantly mint tokens, overwrite channels, or alter the local ledger without authorization.
* **Remediation:** Implement a strict ingress routing boundary. External network messages must be explicitly mapped to a safe, whitelisted subset of allowed network events (e.g., `:receive-gossip`, `:receive-summary`).

### [CRIT-03] Arbitrary Multisig Transaction Forgery (Unbound `tx-hash`)

* **Component:** `bitecho.channels.core/generate-multisig-puzzle`
* **Description:** The 2-of-2 multisig puzzle correctly uses `crypto/verify` for signatures, but it pulls the transaction hash directly from the attacker-controlled `solution` payload: `tx-hash-bytes (hex->bytes (:tx-hash solution))]`. The ledger's `process-transaction` logic never enforces that `(:tx-hash solution)` matches the *actual* hash of the transaction currently being evaluated.
* **Impact:** An attacker can observe a valid off-chain or on-chain multisig signature exchange, construct a completely new malicious transaction draining the channel to themselves, and provide the old `tx-hash` and old signatures in the `solution`. The script will evaluate to `true`.
* **Remediation:** The SCI sandbox evaluation environment must inject the internally computed `tx-hash` natively as an immutable binding context. It must never be supplied by the spending solution.

### [CRIT-04] SCI Sandbox Resource Exhaustion DoS (Billion Laughs)

* **Component:** `bitecho.economy.sci-sandbox/eval-string`
* **Description:** To prevent Turing-completeness, the sandbox relies on AST symbol blacklisting (blocking `loop`, `recur`, `while`). However, this fails to prevent geometric memory allocation via standard sequence functions like `concat`, `into`, or `str`. An attacker can submit a puzzle script well under the 4096-byte limit that crashes the JVM:
`(let [a "A" b (str a a a) c (str b b b) ... z (str y y y)] z)`
* **Impact:** Processing this script will instantly cause a `java.lang.OutOfMemoryError`, permanently crashing every node on the network that attempts to validate the transaction.
* **Remediation:** AST blacklisting is fundamentally insufficient. Implement strict instruction-metering limits (gas) natively via SCI's configuration interceptors, and bound memory allocations.

### [CRIT-05] Unbounded Broadcast Storms (Vector Queue Eviction Bug)

* **Component:** `bitecho.murmur.core/update-cache` & `bitecho.state-machine/init-state`
* **Description:** The Murmur gossip cache is intended to track the last 1000 message IDs to prevent broadcast storms. It initializes `:queue` as a standard Clojure vector (`[]`). In Clojure vectors, `conj` appends to the *end*, and both `peek` and `pop` operate on the *end* of the sequence. Once the vector reaches `max-size`, `(pop new-queue)` instantly removes the *newest* message just added, rather than the oldest message at the front.
* **Impact:** Nodes will permanently forget all newly received messages once the cache reaches 1000 entries. Every subsequent re-transmission of a new message will be treated as unseen, resulting in an infinite broadcast storm that will immediately exhaust network bandwidth and CPU.
* **Remediation:** Initialize the cache queue using `clojure.lang.PersistentQueue/EMPTY` instead of a vector.

### [CRIT-06] Complete Bypass of Sieve Cryptographic Verification

* **Component:** `bitecho.state_machine/handle-receive-gossip`
* **Description:** Phase 1 dictates that Sieve acts as the cryptographic filter for incoming gossip. However, `handle-receive-gossip` receives network events and routes them directly into the Murmur cache (`murmur/receive-gossip`) and Contagion trackers without ever invoking `sieve/validate-message`.
* **Impact:** The network will blindly propagate unsigned, forged, and maliciously altered messages. The entire Byzantine-resilient layer is effectively dead code.
* **Remediation:** Add `(sieve/validate-message message)` logic to the gossip handler and drop payloads that fail validation.

---

## 3. High Vulnerabilities

### [HIGH-01] Cross-Channel State Replay Attacks

* **Component:** `bitecho.channels.core/mutually-sign-update`
* **Description:** When negotiating off-chain Payment Channels, participants sign an `update-map` containing `{:nonce, :balance-a, :balance-b}`. This map does not commit to a specific `channel-id` or participant public keys.
* **Impact:** If Alice and Bob have multiple concurrent or historical payment channels, Bob can intercept a signed update from Channel A and replay it validly on Channel B, overwriting its state and stealing funds.
* **Remediation:** Include `channel-id` and participant keys inside the `update-map` before it is converted to a canonical string and hashed.

### [HIGH-02] Basalt Sybil/Eclipse Attack via Deterministic Hash Collision

* **Component:** `bitecho.basalt.core/make-peer`
* **Description:** Peer IDs are hashed by concatenating `ip`, `port`, and `pubkey` into a `ByteBuffer` without delimiters. `IP: "127.0.0.1" + Port: "80"` creates the exact same byte string prefix as `IP: "127.0.0.18" + Port: "0"`.
* **Impact:** An attacker can engineer peer-id collisions to mount highly targeted eclipse attacks. By exploiting `merge-views`' preference for younger peers (age 0), the attacker can deterministically overwrite honest nodes in victims' routing tables.
* **Remediation:** Insert explicit delimiters (e.g., a null byte ` ` or `|`) between fields when constructing the `hash-input` ByteBuffer.

### [HIGH-03] Sieve Equivocation Tracker Permanently Blacklists Senders

* **Component:** `bitecho.sieve.core/check-equivocation`
* **Description:** The equivocation detector stores state globally as a map of `sender -> signature`. If an honest agent broadcasts Message 1, their signature is stored. If they subsequently broadcast legitimate Message 2 (which has a different signature), the system checks the global map, sees a mismatch, and falsely flags it as an equivocation.
* **Impact:** If Sieve were active (see CRIT-06), every agent would be strictly limited to sending exactly one message for the entire lifetime of the network.
* **Remediation:** The equivocation history must track signatures scoped to a specific `message-id` or sequence number, not globally by sender.

### [HIGH-04] Remote DoS via Unhandled Hex Parsing Exceptions

* **Component:** `bitecho.basalt.core/hex->bytes`
* **Description:** The custom hex decoder lacks length parity checks. Passing an odd-length string will throw a `StringIndexOutOfBoundsException`.
* **Impact:** Because this occurs inside the synchronous pure state machine, an attacker sending a single malformed hex string via gossip will permanently crash the `core.async` flow loop of the receiving node.
* **Remediation:** Add length parity validation to `hex->bytes`. Wrap external input parsing in defensive `try/catch` blocks.

### [HIGH-05] Transaction Hash Non-Determinism Forking Consensus

* **Component:** `src/bitecho/economy/ledger.clj` (`process-transaction`)
* **Description:** To generate unique Output IDs (`tx-hash`), the `process-transaction` function computes the SHA-256 hash of the transaction map using `(pr-str tx)`: `tx-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str tx) "UTF-8")))`. Clojure maps (specifically small array maps vs large hash maps) do not guarantee deterministic key iteration order. `pr-str` will serialize the map with whatever internal order the JVM provides.
* **Impact:** Identical transactions processed by different agents may yield entirely different `tx-hash` values depending on their JVM state or memory layout. This destroys UTXO fungibility and causes immediate ledger forks across the network since peers will disagree on the valid Output IDs created by a transaction.
* **Remediation:** Canonicalize the transaction data structure before serialization. Convert the `tx` map to a deterministically ordered collection (e.g., `(into (sorted-map) tx)`) or explicitly sort keys prior to applying `pr-str` and hashing.

### [HIGH-06] Replay Attacks in TURN Payment Channel Off-Chain Updates

* **Component:** `src/bitecho/services/turn.clj` (`handle-relay-request`)
* **Description:** During off-chain state updates for data relay (`handle-relay-request`), the server checks that the incoming update nonce strictly increments the initial state's nonce: `(= expected-nonce (:nonce update))`. While this verifies that the client is moving the state forward relative to the provided `initial-state`, there is no mechanism tying the update to a globally progressing channel clock if `initial-state` can be rolled back. Since off-chain messages can be captured and replayed on the network layer (e.g., over UDP/WebRTC data channels), a rogue client or intermediate routing proxy could replay an old `turn-relay-request` against an older snapshot of the state if the server's channel reference isn't strictly monotonic.
* **Impact:** An attacker could replay previously mutually signed payment updates, forcing the channel into an older state and effectively reversing payments made for TURN data relay, resulting in stolen bandwidth.
* **Remediation:** Channel state tracking must enforce monotonic progression independently. The `turn-relay-request` verification must strictly compare the update against the server's latest localized channel state, rejecting any nonce `N` where `N <= current_nonce`.

### [HIGH-07] Payment Channel Balance Conservation Bypass

* **Component:** `bitecho.channels.core/mutually-sign-update`
* **Description:** The channel update logic validates signatures and nonces but fails to assert that the sum of the new balances equals the sum of the original balances.
* **Impact:** A malicious or compromised channel participant can propose an off-chain update that mints new tokens out of thin air while maintaining valid signatures and nonces. When settled, this violates the global UTXO conservation invariant, inflating the Echo supply.
* **Remediation:** Add a strict invariant check ensuring `balance-a + balance-b` is conserved.

### [HIGH-08] Lottery Ticket Claimer Spoofing

* **Component:** `bitecho.state-machine/handle-route-directed-message`
* **Description:** The state machine extracts the `claimer-pubkey` directly from the event payload rather than enforcing that the claimer is the local node's actual identity.
* **Impact:** A peer routing a message can maliciously modify the `claimer-pubkey` field in the payload to redirect the lottery ticket reward to their own pubkey instead of the actual routing node's pubkey, stealing routing incentives from honest nodes.
* **Remediation:** Derive the `claimer-pubkey` from the node's internal state, not the unverified event payload.

---

## 4. Medium Severity & Architectural Flaws

### [MED-01] Unbounded Anti-Entropy Summaries (Memory Exhaustion)

* **Component:** `bitecho.state-machine.clj` & `bitecho.contagion.core`
* **Description:** `:contagion-known-ids` grows indefinitely. `generate-summary` sends the entire set over the network every tick. Over time, this leads to massive memory bloat and network bandwidth saturation as nodes endlessly synchronize ever-growing sets of historical message IDs.
* **Remediation:** Implement a sliding time-window or chronological Time-to-Live (TTL) eviction strategy for `known-ids`.

### [MED-02] Trivial Bypass of Proof of Relay

* **Component:** `bitecho.peer_review.core/validate-proof-of-relay`
* **Description:** The validation function explicitly returns `true` if the submitted `proof-sequence` is empty. If peer-review logic relies on this boolean to authorize economic payouts, an attacker can submit an empty array to mathematically "prove" successful message transit without executing any actual routing work.
* **Remediation:** Enforce that a valid proof sequence must contain a sequence length greater than zero.

### [MED-03] Permanent Delegation Missing Expiration (DACs)

* **Component:** `bitecho.crypto.delegation`
* **Description:** Delegated Agent Certificates (DACs) permanently bind a temporary hot Node Key to an entity's Parent Key. The `canonicalize-dac` map lacks an `exp` (expiration) timestamp. If an ephemeral Node Key is compromised, the attacker has permanent, unrevokable access to the parent's network identity and routing balances.
* **Remediation:** Upgrade the DAC schema to include an expiration timestamp and validate it during Sieve verification.
