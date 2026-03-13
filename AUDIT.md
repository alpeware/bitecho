# Bitecho Security Audit Report

**Audited Commit Hash:** `5ddedb5d16078152bd7ead1c36f6bada88ffdce0`

This document details the findings of a deep architectural and cryptographic security review of the `alpeware-bitecho` codebase. Findings are categorized by severity.

---

## 1. CRITICAL: Sieve Consistent Broadcast Validation Bypass
**Component:** `src/bitecho/state_machine.clj` (`handle-receive-gossip`)

**Description:**
The Murmur probabilistic broadcast layer receives incoming gossip messages via `handle-receive-gossip` and forwards them to `k` peers. However, the root reducer (`state_machine.clj`) completely omits calls to `bitecho.sieve.core/validate-message` and `bitecho.sieve.core/check-equivocation`. The Sieve validation logic is entirely bypassed.

**Impact:**
Any peer can forge messages (e.g., Sieve payloads) with invalid Ed25519 signatures or publish equivocations (Byzantine behavior). The network will blindly cache and forward these invalid messages via the Contagion stack, leading to widespread Sieve consensus failures and allowing Sybil attackers to flood the network with forged SBRB broadcasts.

**Remediation:**
In `state_machine.clj`, integrate `sieve/validate-message` and `sieve/check-equivocation` inside `handle-receive-gossip` *before* adding the message to the Murmur cache or forwarding it. Drop the message if it fails signature verification or is determined to be an equivocation.

---

## 2. CRITICAL: Denial-of-Service via SCI Sandbox Memory Exhaustion (String Bomb)
**Component:** `src/bitecho/economy/sci_sandbox.clj` (`eval-string`)

**Description:**
The pure-functional `sci-sandbox` correctly restricts execution by forbidding infinite sequences (`range`, `repeat`), recursion (`loop`, `recur`), and enforcing a strict `max-script-size` (4096 bytes). However, it does not prevent exponential string concatenation. An attacker can craft a 4KB script that repeatedly concatenates strings (e.g., `(let [x1 (str x x) x2 (str x1 x1) ...])`).

**Impact:**
Because `eval-string` executes synchronously in the state machine reducer, processing a malicious UTXO puzzle or solution containing a string concatenation bomb will trigger an `OutOfMemoryError` (OOM), instantly crashing the agent. This represents a zero-cost deterministic remote Denial-of-Service (DoS) against any node that attempts to evaluate the forged transaction.

**Remediation:**
Inject a strict memory/length limit on string operations within the `sci-sandbox` or implement a deeply bounded instruction counter (gas meter) using `sci.core/set-max-instructions!`.

---

## 3. HIGH: Transaction Hash Non-Determinism Forking Consensus
**Component:** `src/bitecho/economy/ledger.clj` (`process-transaction`)

**Description:**
To generate unique Output IDs (`tx-hash`), the `process-transaction` function computes the SHA-256 hash of the transaction map using `(pr-str tx)`:
```clojure
tx-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str tx) "UTF-8")))
```
Clojure maps (specifically small array maps vs large hash maps) do not guarantee deterministic key iteration order. `pr-str` will serialize the map with whatever internal order the JVM provides.

**Impact:**
Identical transactions processed by different agents may yield entirely different `tx-hash` values depending on their JVM state or memory layout. This destroys UTXO fungibility and causes immediate ledger forks across the network since peers will disagree on the valid Output IDs created by a transaction.

**Remediation:**
Canonicalize the transaction data structure before serialization. Convert the `tx` map to a deterministically ordered collection (e.g., `(into (sorted-map) tx)`) or explicitly sort keys prior to applying `pr-str` and hashing.

---

## 4. HIGH: Replay Attacks in TURN Payment Channel Off-Chain Updates
**Component:** `src/bitecho/services/turn.clj` (`handle-relay-request`)

**Description:**
During off-chain state updates for data relay (`handle-relay-request`), the server checks that the incoming update nonce strictly increments the initial state's nonce:
```clojure
(= expected-nonce (:nonce update))
```
While this verifies that the client is moving the state forward relative to the provided `initial-state`, there is no mechanism tying the update to a globally progressing channel clock if `initial-state` can be rolled back. Since off-chain messages can be captured and replayed on the network layer (e.g., over UDP/WebRTC data channels), a rogue client or intermediate routing proxy could replay an old `turn-relay-request` against an older snapshot of the state if the server's channel reference isn't strictly monotonic.

**Impact:**
An attacker could replay previously mutually signed payment updates, forcing the channel into an older state and effectively reversing payments made for TURN data relay, resulting in stolen bandwidth.

**Remediation:**
Channel state tracking must enforce monotonic progression independently. The `turn-relay-request` verification must strictly compare the update against the server's latest localized channel state, rejecting any nonce `N` where `N <= current_nonce`.
