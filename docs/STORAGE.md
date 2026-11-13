# Bitecho Fractal E2EE Storage Service ("Bytes at Rest")

Bitecho provides **built-in End-to-End Encrypted (E2EE) Storage** across the global Nexus network and any paid or free fractal Subnet without adding any new consensus primitives. Storage ("bytes at rest") and streaming/turn relays ("bytes in motion") share the exact same underlying four-primitive protocol foundation:

1. **`Blob` (`bitecho.core.data`)**: Content-addressed immutable ciphertext payload (`cid = SHA-256(ciphertext-bytes)`), disk-backed, pinned, and replicated across subnet providers.
2. **`Pointer` (`bitecho.core.data`)**: Ed25519-signed mutable versioned reference (`authority`, `path`, `target = blob.cid`, monotonic `seq`) with anti-rollback verification.
3. **`Subnet` (`bitecho.state-machine`)**: Carries the admission gate, replication policy, and fee/free economic model.

---

## 1. Zero-Trust Cryptographic Design (`bitecho.core.storage`)

Implemented in [`src/bitecho/core/storage.cljc`](../src/bitecho/core/storage.cljc), E2EE Storage ensures that **storage providers, Nexus validators, and gossip relays never see plaintext state**:

### 1.1 Domain-Separated Storage Key Derivation (`derive-storage-key`)
Given a node's 32-byte seed / secret key and a logical `slot-id` (e.g., `"browser-state"`, `"agent-memory"`, `"wallet-petnames"`):
```clojure
(storage/derive-storage-key seed-bytes slot-id)
;; => 32-byte symmetric key = SHA-256("bitecho-e2ee-storage-v1:" || seed-bytes || ":" || slot-id)
```
Because key derivation is deterministic and domain-separated per `slot-id`:
- A user or agent can recover and decrypt its state from **any Browser, Node.js, or JVM light node** using only its identity seed and `slot-id`.
- Compromising a single slot key never exposes either the Ed25519 signing key or any other storage slot.

### 1.2 Authenticated Encryption (`pack-encrypted-state`)
1. Generates a fresh 24-byte cryptographic nonce (or accepts an explicit deterministic nonce in tests).
2. Encrypts `plaintext-bytes` using NaCl/TweetNaCl `crypto_secretbox` (**XSalsa20-Poly1305** authenticated encryption).
3. Prepends the 24-byte nonce to the authenticated ciphertext (`[24-byte-nonce || secretbox-ciphertext]`).
4. Wraps the encrypted bytes in a content-addressed `Blob` (`mime = "application/x-bitecho-e2ee-blob"`) and signs a `Pointer` at path:
   - Global network (`subnet-id = nil` or `"nexus"`): `"storage/<slot-id>"`
   - Fractal subnet (`subnet-id = "<subnet-id>"`): `"subnet/<subnet-id>/storage/<slot-id>"`

### 1.3 Verified Decryption & Anti-Rollback (`unpack-encrypted-state`)
When resolving a slot via `unpack-encrypted-state`:
1. **Blob Integrity (`data/verify-blob`):** Verifies `SHA-256(blob.bytes) == blob.cid`.
2. **Pointer Authenticity (`data/verify-pointer`):** Verifies the Ed25519 signature over `(authority, path, target, seq)` and confirms `authority == expected-authority`.
3. **Target Binding:** Verifies `pointer.target == blob.cid`.
4. **Anti-Rollback Guard:** Verifies `pointer.seq >= min-expected-seq`. If a malicious or stale storage provider serves an older snapshot (`pointer.seq < min-expected-seq`), `unpack-encrypted-state` fails loudly with `{:ok? false :error :rollback-detected :seq ... :min-expected-seq ...}`.
5. **Authenticated Decryption:** Opens the XSalsa20-Poly1305 secretbox using the derived slot key. Any ciphertext tampering or wrong key fails with `{:ok? false :error :decryption-failed}`.

---

## 2. Free vs. Paid Subnet Storage Models

Storage operates fractally across both the global Nexus network and specialized Subnets:
- **Free Tier / Self-Hosted Subnet:** A subnet or Nexus gateway can pin and serve E2EE `Blob` + `Pointer` pairs at `price_echo = 0` (or bounded by the subnet's `burn_floor`).
- **Paid Storage Subnet:** Storage providers advertise a `:storage/blob-pinning` capability descriptor (see [`docs/CAPABILITIES.md`](CAPABILITIES.md)) specifying their `price-echo` per KB/epoch and SLA parameters. An agent locks an escrow intent (optionally governed by a [`sci` smart contract](SMART_CONTRACTS.md) verifying blob availability/audit proofs) and replicates its encrypted `Blob` + `Pointer` to the subnet.

---

## 3. Light-Node Exposure Across All 3 Runtimes (JVM, Node.js, Browser)

All storage verbs work identically on the **JVM Light Node**, **Node.js Light Node**, and **Browser Light Node** (`BitechoBrowser.ctl`), and automatically broadcast signed replication envelopes to connected peers while persisting locally (including Browser IndexedDB persistence):

### 3.1 Store Encrypted State (`storage-put`)
Encrypts `--data <utf8-string>` (or `--data-hex <hex-bytes>`), increments the slot's monotonic sequence number (`seq`), stores the `Blob` + `Pointer` locally, and broadcasts a `:storage-replicate` envelope to the network:

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  storage-put --slot-id browser-wallet --data '{"theme":"dark","bookmarks":["nexus"]}' --subnet-id nexus
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {
    "cmd": "storage-put",
    "slot_id": "browser-wallet",
    "data": "{\"theme\":\"dark\",\"bookmarks\":[\"nexus\"]}",
    "subnet_id": "nexus"
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "slot_id": "browser-wallet",
    "subnet_id": "nexus",
    "path": "storage/browser-wallet",
    "cid": "<64-char-hex-blob-cid>",
    "seq": 1,
    "size_bytes": 78
  }
  ```

### 3.2 Retrieve & Decrypt State (`storage-get`)
Verifies the `Blob` CID, `Pointer` signature, and anti-rollback sequence number (`--min-seq <n>`), then decrypts the payload with the node's derived slot key:

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  storage-get --slot-id browser-wallet --subnet-id nexus --min-seq 1
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {
    "cmd": "storage-get",
    "slot_id": "browser-wallet",
    "subnet_id": "nexus",
    "min_seq": 1
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "slot_id": "browser-wallet",
    "subnet_id": "nexus",
    "cid": "<64-char-hex-blob-cid>",
    "seq": 1,
    "data": "{\"theme\":\"dark\",\"bookmarks\":[\"nexus\"]}",
    "data_hex": "7b227468656d65223a226461726b222c22626f6f6b6d61726b73223a5b226e65787573225d7d"
  }
  ```

### 3.3 List Stored E2EE Slots (`storage-list`)
Lists all local and replicated E2EE storage pointers (optionally filtered by `--subnet-id`):

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  storage-list --subnet-id nexus
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {"cmd": "storage-list", "subnet_id": "nexus"}
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "count": 1,
    "slots": [
      {
        "subnet_id": "nexus",
        "path": "storage/browser-wallet",
        "slot_id": "browser-wallet",
        "cid": "<64-char-hex-blob-cid>",
        "authority": "<64-char-hex-pubkey>",
        "seq": 1,
        "size_bytes": 78
      }
    ]
  }
  ```
