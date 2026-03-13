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

## 3. CRITICAL: Zero-Authorization Theft of Standard UTXOs
**Component:** `bitecho.economy.ledger/standard-puzzle-hash`

**Description:**
The standard UTXO puzzle only checks if the solution string matches the pubkey. It completely omits Ed25519 signature verification.

**Impact:**
An attacker can steal any standard UTXO by simply constructing a solution containing the target's public key as a string, completely bypassing cryptographic authorization. This leads to an immediate, total loss of funds across the network.

**Remediation:**
Rewrite `standard-puzzle-hash` to generate a script that executes `crypto/verify` using the transaction hash.

---

## 4. CRITICAL: Remote Command Execution via Flow Ingress
**Component:** `bitecho.shell.flow/state-machine-step`

**Description:**
`:net-in` routes directly to the pure reducer without filtering. An attacker can send raw EDN payloads specifying highly privileged internal events (like `:settle-channel`).

**Impact:**
Malicious peers can send crafted network packets containing internal state machine event structures to remotely execute privileged commands (e.g., closing channels, forcing payouts). This breaks the Sans-IO abstraction and leads to full remote compromise of the victim's local node state.

**Remediation:**
Implement a strict ingress filter that only maps external network messages to a whitelisted subset of events (e.g., `:receive-gossip`).

---

## 5. CRITICAL: Arbitrary Multisig Transaction Forgery
**Component:** `bitecho.channels.core/generate-multisig-puzzle` & `sci-sandbox/eval-string`

**Description:**
The 2-of-2 multisig puzzle pulls the `tx-hash` directly from the attacker-controlled `solution` payload rather than the internally computed transaction hash.

**Impact:**
Attackers can forge multisig spending transactions by replaying previous valid signatures over an attacker-supplied hash within the solution payload. This undermines the payment channel integrity, allowing unauthorized extraction of bonded Echo funds.

**Remediation:**
The SCI sandbox must inject the internally computed `tx-hash` natively into the binding context; it must never be supplied by the spending solution.

---

## 6. CRITICAL: Unbounded Broadcast Storms (Vector Queue Eviction Bug)
**Component:** `bitecho.murmur.core/update-cache`

**Description:**
The Murmur cache initializes `:queue` as a standard vector `[]`. Calling `pop` on a vector removes the newest item, not the oldest, causing the cache to permanently forget new messages once full.

**Impact:**
Once the bounded Murmur cache fills, `pop` evicts the most recently added message IDs instead of the oldest. This fundamentally breaks duplicate message detection for new gossip, resulting in infinite routing loops and devastating broadcast storms that will partition the P2P network.

**Remediation:**
Initialize the cache queue using `clojure.lang.PersistentQueue/EMPTY`.

---

## 7. HIGH: Transaction Hash Non-Determinism Forking Consensus
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

## 8. HIGH: Replay Attacks in TURN Payment Channel Off-Chain Updates
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

---

## 9. HIGH: Payment Channel Balance Conservation Bypass
**Component:** `bitecho.channels.core/mutually-sign-update`

**Description:**
The channel update logic validates signatures and nonces but fails to assert that the sum of the new balances equals the sum of the original balances.

**Impact:**
A malicious or compromised channel participant can propose an off-chain update that mints new tokens out of thin air while maintaining valid signatures and nonces. When settled, this violates the global UTXO conservation invariant, inflating the Echo supply.

**Remediation:**
Add a strict invariant check ensuring `balance-a + balance-b` is conserved.

---

## 10. HIGH: Lottery Ticket Claimer Spoofing
**Component:** `bitecho.state-machine/handle-route-directed-message`

**Description:**
The state machine extracts the `claimer-pubkey` directly from the event payload rather than enforcing that the claimer is the local node's actual identity.

**Impact:**
A peer routing a message can maliciously modify the `claimer-pubkey` field in the payload to redirect the lottery ticket reward to their own pubkey instead of the actual routing node's pubkey, stealing routing incentives from honest nodes.

**Remediation:**
Derive the `claimer-pubkey` from the node's internal state, not the unverified event payload.
