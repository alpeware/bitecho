# Bitecho Fractal Capability Descriptors (The Agent Intent Economy)

Bitecho supports a unified, content-addressed **Capability Descriptor** mechanism (`bitecho.core.storage`) built directly on `Blob` + `Pointer` + `Subnet`. Providers across the default "global" network or any specialized Subnet advertise services — **E2EE storage, optimized UOp compute kernels, local GPU access, open or proprietary model weights, WebRTC TURN relays, and ingress gateways** — using the exact same signed, versioned descriptor envelope.

---

## 1. The Advertise–Discover–Pay–Serve–Verify Loop

1. **Advertise (`capability-publish`):** A provider serializes a canonical capability descriptor into a content-addressed `Blob` (`mime = "application/edn"`) and signs a mutable `Pointer` (`seq` monotonic) at:
   - Root network ("global"): `"capability/<provider-pubkey>/<capability-id>"`
   - Subnet-scoped: `"subnet/<subnet-id>/capability/<provider-pubkey>/<capability-id>"`
2. **Discover & Verify (`capability-list` / `capability-resolve`):** A client or autonomous agent discovers published capabilities and cryptographically verifies `data/verify-blob`, `data/verify-pointer`, `pointer.target == blob.cid`, anti-rollback `pointer.seq >= min-expected-seq`, and schema validity (`storage/valid-capability-descriptor?`).
3. **Lock Intent (`lock-intent`):** For paid capabilities (`:price-echo > 0`), the consumer locks ECHO into an escrow intent (using either standard hash/signature lock or a [ChiaLisp-style `sci` smart contract](SMART_CONTRACTS.md) committed via `--puzzle-hash`).
4. **Serve & Settle (`release-intent`):** The provider delivers the capability outcome (e.g., pinned blob proof, tuned UOp kernel CID, GPU inference result, model weights stream, or TURN relay credentials) and claims settlement via `release-intent`.

---

## 2. Supported Capability Types & Descriptor Schema

Implemented in [`src/bitecho/core/storage.cljc`](../src/bitecho/core/storage.cljc), every capability descriptor is validated against `storage/valid-capability-descriptor?`:

### 2.1 Allowed `:capability-type` Values
| Capability Type | Category | Typical Use Case |
| :--- | :--- | :--- |
| **`:storage/blob-pinning`** | Bytes at Rest | Paid or free E2EE `Blob` + `Pointer` persistence and replication on the "global" network or a storage subnet. |
| **`:compute/uop-kernel`** | Compute | Paid or free hardware-tuned UOp kernels (e.g., Metal/CUDA/WebGPU matmul or attention kernels for a specific tensor shape). |
| **`:compute/gpu-access`** | Compute | Paid or free GPU compute hours / inference slots (e.g., local Gemma or LLM execution on a provider node). |
| **`:model/weights`** | AI / Weights | Open or proprietary model weights (full checkpoints, LoRA adapters, or quantized shards) referenced via `:target-cid`. |
| **`:network/turn-relay`** | Bytes in Motion | Paid or free WebRTC TURN / DataChannel relay bandwidth for NAT-restricted nodes. |
| **`:network/gateway`** | Bytes in Motion | Specialized WebSocket/TCP ingress or bridge gateway for light nodes and browser peers. |

### 2.2 Canonical Descriptor Fields
```clojure
{:bitecho/type    :capability-descriptor
 :capability-id   "gemma-3-27b-q4-weights"
 :capability-type :model/weights
 :provider        "<64-char-lowercase-hex-ed25519-pubkey>"
 :subnet-id       "global"        ;; or nil / custom subnet ID
 :price-echo      50              ;; 0 for free tier, >0 for paid tier
 :burn-floor      10              ;; optional minimum protocol burn requirement
 :target-cid      "<64-hex-cid>"  ;; optional Blob CID of weights / UOp kernel / SLA puzzle
 :metadata        {:arch "gemma3" :quant "Q4_K_M" :params "27B"}}
```

---

## 3. Light-Node Exposure Across All 3 Runtimes (JVM, Node.js, Browser)

All capability commands work identically across the **JVM Light Node**, **Node.js Light Node** (`dist/bitecho-light-node.cjs`), and **Browser Light Node** (`BitechoBrowser.ctl`):

### 3.1 Publish a Capability Descriptor (`capability-publish`)
Packs and signs the capability descriptor as a `Blob` + `Pointer`, stores it locally, and broadcasts a `:capability-replicate` envelope to connected peers:

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  capability-publish \
    --capability-id uop-matmul-fp16 \
    --capability-type compute/uop-kernel \
    --price 25 \
    --burn-floor 5 \
    --subnet-id global \
    --target-cid a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 \
    --metadata '{"shape":[4096,4096],"backend":"cuda"}'
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {
    "cmd": "capability-publish",
    "capability_id": "uop-matmul-fp16",
    "capability_type": "compute/uop-kernel",
    "price_echo": 25,
    "burn_floor": 5,
    "subnet_id": "global",
    "target_cid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "metadata": {"shape": [4096, 4096], "backend": "cuda"}
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "capability_id": "uop-matmul-fp16",
    "capability_type": "compute/uop-kernel",
    "price_echo": 25,
    "subnet_id": "global",
    "path": "capability/<provider-pubkey>/uop-matmul-fp16",
    "cid": "<64-char-hex-blob-cid>",
    "seq": 1
  }
  ```

### 3.2 Resolve & Verify a Capability Descriptor (`capability-resolve`)
Resolves a capability by `--capability-id` and `--authority <pubkey-or-petname>` (or explicit `--path`), verifying the `Blob` hash, `Pointer` signature, and anti-rollback sequence (`--min-seq`):

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  capability-resolve \
    --capability-id uop-matmul-fp16 \
    --authority <provider-pubkey-or-petname> \
    --subnet-id global \
    --min-seq 1
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {
    "cmd": "capability-resolve",
    "capability_id": "uop-matmul-fp16",
    "authority": "<provider-pubkey-or-petname>",
    "subnet_id": "global",
    "min_seq": 1
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "path": "capability/<provider-pubkey>/uop-matmul-fp16",
    "cid": "<64-char-hex-blob-cid>",
    "seq": 1,
    "descriptor": {
      "capability_id": "uop-matmul-fp16",
      "capability_type": "compute/uop-kernel",
      "provider": "<provider-pubkey>",
      "subnet_id": "global",
      "price_echo": 25,
      "burn_floor": 5,
      "target_cid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      "metadata": {"shape": [4096, 4096], "backend": "cuda"}
    }
  }
  ```

### 3.3 List Discovered Capabilities (`capability-list`)
Lists all local and network-replicated capability descriptors, optionally filtered by `--subnet-id`, `--capability-type`, or `--authority`:

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  capability-list --subnet-id global --capability-type compute/uop-kernel
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {
    "cmd": "capability-list",
    "subnet_id": "global",
    "capability_type": "compute/uop-kernel"
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "count": 1,
    "capabilities": [
      {
        "path": "capability/<provider-pubkey>/uop-matmul-fp16",
        "cid": "<64-char-hex-blob-cid>",
        "seq": 1,
        "descriptor": {
          "capability_id": "uop-matmul-fp16",
          "capability_type": "compute/uop-kernel",
          "provider": "<provider-pubkey>",
          "subnet_id": "global",
          "price_echo": 25,
          "burn_floor": 5,
          "target_cid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
          "metadata": {"shape": [4096, 4096], "backend": "cuda"}
        }
      }
    ]
  }
  ```
