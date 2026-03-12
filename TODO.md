# Bitecho Phase 1: Routing & Gossip State Machine

## Cryptographic Foundation
- [x] Implement `bitecho.crypto` namespace (SHA-256 hashing, Ed25519 keypair generation, signing, and verification).

## 1. Basalt (Peer Sampling)
- [x] Implement `bitecho.basalt.core` data structures: define the Peer record (IP, port, pubkey, age, hash) and the View initialization logic.
- [x] Implement `bitecho.basalt.core` push/pull logic: pure functions to select random peers for exchange and increment peer ages.
- [x] Implement `bitecho.basalt.core` view merging: pure logic to merge a received view with the local view, respecting max view size and dropping oldest/duplicate peers.

## 2. Murmur (Probabilistic Broadcast)
- [x] Implement `bitecho.murmur.core` broadcast initiation: a pure function that takes a payload, generates a message ID, and selects `k` random peers from the Basalt view to gossip to.
- [x] Implement `bitecho.murmur.core` forwarding: pure logic to handle `{:type :receive-gossip}`. Must maintain a bounded cache of recently seen message IDs and forward unseen messages to `k` peers.

## 3. Sieve (Consistent Broadcast)
- [x] Implement `bitecho.sieve.core` validation: wrap Murmur payloads in Ed25519 signatures. Drop incoming messages that fail signature verification.
- [x] Implement `bitecho.sieve.core` equivocation detection: track signatures per sender to detect and drop conflicting payloads (Byzantine behavior).

## 4. Contagion (Reliable Broadcast)
- [x] Implement `bitecho.contagion.core` anti-entropy summaries: pure logic triggered by a `:tick` event to generate a digest of known message IDs and target a random Basalt peer.
- [x] Implement `bitecho.contagion.core` lazy pull: pure logic to process incoming summaries, calculate the set difference, and emit requests for missing payloads.

## 5. Integration & Fuzzing
- [x] Implement `bitecho.state-machine`: the root reducer that ties Basalt, Murmur, Sieve, and Contagion into a single pure `(handle-event state event)` function.
- [x] Write generative state-machine fuzzer (`test.check`) to prove the Bitecho pure core maintains connected Basalt views and reliably delivers messages under simulated network drops.

## Bitecho Phase 2: The Echo Economy (Lottery & Ledger)
- [x] Implement `bitecho.lottery.core`: pure functions to generate a cryptographic lottery ticket (payload hash + nonce + signature) and evaluate if `hash(ticket) < difficulty`.
- [x] Implement `bitecho.economy.ledger`: define the Genesis state data structure and pure functions to apply valid lottery ticket payouts to an agent's Echo balance (UTXO Model).
- [x] Implement `bitecho.peer-review.core`: pure logic to validate a "Proof of Relay" (verifying a sequence of Contagion broadcast receipts and Sieve signatures).
- [x] Implement `bitecho.economy.difficulty`: a pure function that calculates the current lottery difficulty target dynamically based on the Contagion `k` fanout parameter and network size estimates.

## Bitecho Phase 3: Directed Messaging (Stake-Weighted Routing)
- [x] Implement `bitecho.message.envelope`: define the pure spec and wrapping logic for a directed message envelope (destination pubkey, encrypted payload blob, attached lottery ticket).
- [x] Implement `bitecho.routing.weighted`: pure logic to select a next-hop routing target by weighting the current Basalt view according to each peer's known Echo balance.
- [x] Update `bitecho.state-machine`: integrate Phase 2 and 3 into the core reducer. Add handlers for `{:type :route-directed-message}` that validates the attached lottery ticket, claims the fee if it wins, and forwards the envelope via the stake-weighted routing logic.
