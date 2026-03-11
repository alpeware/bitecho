# Bitecho Phase 1: Routing & Gossip State Machine

## Cryptographic Foundation
- [x] Implement `bitecho.crypto` namespace (SHA-256 hashing, Ed25519 keypair generation, signing, and verification).

## 1. Basalt (Peer Sampling)
- [x] Implement `bitecho.basalt.core` data structures: define the Peer record (IP, port, pubkey, age, hash) and the View initialization logic.
- [x] Implement `bitecho.basalt.core` push/pull logic: pure functions to select random peers for exchange and increment peer ages.
- [ ] Implement `bitecho.basalt.core` view merging: pure logic to merge a received view with the local view, respecting max view size and dropping oldest/duplicate peers.

## 2. Murmur (Probabilistic Broadcast)
- [ ] Implement `bitecho.murmur.core` broadcast initiation: a pure function that takes a payload, generates a message ID, and selects `k` random peers from the Basalt view to gossip to.
- [ ] Implement `bitecho.murmur.core` forwarding: pure logic to handle `{:type :receive-gossip}`. Must maintain a bounded cache of recently seen message IDs and forward unseen messages to `k` peers.

## 3. Sieve (Consistent Broadcast)
- [ ] Implement `bitecho.sieve.core` validation: wrap Murmur payloads in Ed25519 signatures. Drop incoming messages that fail signature verification.
- [ ] Implement `bitecho.sieve.core` equivocation detection: track signatures per sender to detect and drop conflicting payloads (Byzantine behavior).

## 4. Contagion (Reliable Broadcast)
- [ ] Implement `bitecho.contagion.core` anti-entropy summaries: pure logic triggered by a `:tick` event to generate a digest of known message IDs and target a random Basalt peer.
- [ ] Implement `bitecho.contagion.core` lazy pull: pure logic to process incoming summaries, calculate the set difference, and emit requests for missing payloads.

## 5. Integration & Fuzzing
- [ ] Implement `bitecho.state-machine`: the root reducer that ties Basalt, Murmur, Sieve, and Contagion into a single pure `(handle-event state event)` function.
- [ ] Write generative state-machine fuzzer (`test.check`) to prove the Bitecho pure core maintains connected Basalt views and reliably delivers messages under simulated network drops.
