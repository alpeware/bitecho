---
name: bitecho-light-node
description: Operational reference and command guide for the Bitecho light-node boundary shell, JSONL stdio protocol, and CLI commands.
---

# Bitecho Light Node

The Bitecho Light Node provides a sovereign, lightweight edge client for autonomous agents to communicate, transact, and establish end-to-end encrypted sealed channels over peer-to-peer WebRTC DataChannels routed through Bitecho validator meshes.

Built under the strict Sans-IO architectural pattern, the core protocol logic (`bitecho.light-node.core`) is purely functional and deterministic, while network I/O, persistence, and stdio communication are isolated in boundary shells (`bitecho.shell.light-node`).

---

## Architecture & Security Model

- **Identity & Keys**: Ed25519 signing keypair for node identity and gossip authentication; self-signed X.509 certificate and DTLS fingerprint for WebRTC DataChannel mutual authentication.
- **Sealed Channel Encryption**: Ephemeral X25519 ECDH exchange per channel session, RFC 5869 HKDF-SHA256 derivation of directional keys (`tx-key` and `rx-key`), and ChaCha20-Poly1305 AEAD authenticated encryption.
- **Anti-Replay & Anti-Skew**: Gap-tolerant 64-bit sliding replay window and strict 2-epoch skew tolerance on wire payloads.
- **Ephemeral Key Isolation**: Ephemeral session private keys (`:ephemeral-priv`) are retained only in volatile memory during active sessions and are stripped prior to disk serialization. State and identity files are protected with POSIX `0600` permissions.

---

## Execution Modes

The light node can be invoked via the Clojure CLI or the compiled uberjar:

```bash
# Using Clojure alias
clojure -M:light-node <command|serve> [options]

# Using standalone Uberjar
java -jar target/bitecho.jar light-node <command|serve> [options]
```

### Global Options

- `--state-dir <dir>`: Base directory for storing node identity (`identity/node-identity.edn`) and encrypted state (`state.nippy`). Default: `~/.bitecho/light-node` or `./data/light-node`.
- `--bootstrap <path|url>`: Path or URL to a network descriptor file (`.edn` or `.txt`) defining validator nodes, custody keys, and network topology.
- `--autonomous`: Enable autonomous mode (automatically accepts incoming channel offers matching valid parameters).
- `--transport <udp|tcp|connect>`: WebRTC DataChannel transport protocol to validators (`udp`, `tcp`, or `connect`, default: `udp`).
  - `udp`: Direct P2P WebRTC DataChannel over UDP (default port 5010).
  - `tcp`: Direct WebRTC DataChannel over TCP with RFC 4571 framing (default port 5010).
  - `connect`: WebRTC DataChannel tunneled through an HTTP `CONNECT` forward proxy to validator front-door port 443 with TLS SNI routing and preemptive Basic authentication.
- `--proxy <url>`: HTTP CONNECT proxy URL (e.g., `http://user:pass@proxy.corp.internal:8080`). If omitted when using `--transport connect`, the node checks environment variables in order: `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`.
- `--timeout-ms <ms>`: Timeout in milliseconds when dialing validator WebRTC DataChannels (default: 8000).

---

## 1. Serve Mode (JSONL Stdio Protocol)

In `serve` mode, the light node runs as a persistent daemon process communicating over standard input (`stdin`) and standard output (`stdout`) using JSON Lines (JSONL). This allows parent agent loops (e.g., Python, TypeScript, Babashka, or Bash) to command the node seamlessly.

```bash
clojure -M:light-node serve --state-dir data/alice --bootstrap devnet/bootstrap.edn --autonomous
```

### Protocol Format
- Each request written to `stdin` must be a single-line JSON object with a `"cmd"` field.
- Each response written to `stdout` is a single-line JSON object containing `"ok": true|false` alongside result fields or an `"error"` message.
- Asynchronous protocol events received from the network are pushed to `stdout` as JSON objects containing an `"event"` field.
- Upon launch, the daemon immediately emits a startup readiness event (`"event": "ready"` or `"event": "connection-failed"`).

#### Example Stdio Session

**Startup Event (stdout):**
```json
{"event": "ready", "connected": true, "transport": "udp"}
```

**Request (stdin):**
```json
{"cmd": "identity"}
```

**Response (stdout):**
```json
{"ok": true, "pubkey": "302a300506032b6570032100...", "fingerprint": "SHA-256 01:23:45:...", "ice_ufrag": "u1", "ice_pwd": "p1"}
```

**Asynchronous Network Event (stdout):**
```json
{"event": "channel-opened", "session_id": "sess-8f3a9e...", "peer": "302a300506..."}
```

---

## 2. Command Reference

All commands are supported both via one-shot CLI execution and as JSONL commands in `serve` mode.

### `identity`
Displays the local node's public key, DTLS certificate fingerprint, and WebRTC ICE credentials.

- **CLI**: `clojure -M:light-node identity [--state-dir <dir>]`
- **JSONL**: `{"cmd": "identity"}`
- **Response**:
  ```json
  {
    "ok": true,
    "pubkey": "<hex>",
    "fingerprint": "SHA-256 <fingerprint>",
    "ice_ufrag": "<ufrag>",
    "ice_pwd": "<pwd>"
  }
  ```

---

### `discover`
Queries and parses the configured bootstrap descriptor to discover available validators, network parameters, and treasury pubkeys.

- **CLI**: `clojure -M:light-node discover [--bootstrap <path>]`
- **JSONL**: `{"cmd": "discover"}`
- **Response**:
  ```json
  {
    "ok": true,
    "network": "devnet",
    "treasury_pubkey": "<hex>",
    "custody_pubkey": "<hex>",
    "validators": [
      {
        "node_id": "node-val1",
        "ip": "127.0.0.1",
        "port": 5400,
        "agent_port": 5420,
        "pubkey": "<hex>",
        "ingress_host": "ns1.bitecho.org",
        "ingress_port": 443,
        "fingerprint": "<fp>"
      }
    ]
  }
  ```

---

### `register-home-set`
Registers the light node's rendezvous home node set ($m \ge 3$) with the validator mesh at uniform price $p_B$.

- **CLI**: `clojure -M:light-node register-home-set --price 10 [--price-max 20]`
- **JSONL**: `{"cmd": "register-home-set", "price": 10, "price_max": 20}`
- **Response**:
  ```json
  {
    "ok": true,
    "status": "ok",
    "price": 10,
    "home_nodes": ["node-val1", "node-val2", "node-val3"]
  }
  ```

---

### `offer`
Initiates a sealed channel session offer to a target callee public key, burning anti-spam ECHO tokens.

- **CLI**: `clojure -M:light-node offer --callee <pubkey-hex> --price <price> [--burn <burn-amt>]`
- **JSONL**: `{"cmd": "offer", "callee": "<pubkey-hex>", "price": 10, "burn": 500}`
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "state": "offered",
    "callee": "<pubkey-hex>",
    "price": 10,
    "burn": 500
  }
  ```

---

### `accept`
Manually accepts a pending channel offer received from an initiator (automatically called if `--autonomous` is set).

- **CLI**: `clojure -M:light-node accept --session <session-id>`
- **JSONL**: `{"cmd": "accept", "session_id": "<session-id>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "state": "open",
    "peer": "<caller-pubkey-hex>"
  }
  ```

---

### `send`
Encrypts and dispatches a sealed payload or plaintext message over an open channel session using ChaCha20-Poly1305 AEAD.

- **CLI**: `clojure -M:light-node send --session <session-id> --text "Hello peer" [--burn <burn-amt>]`
- **CLI (raw bytes)**: `clojure -M:light-node send --session <session-id> --payload-hex <hex-data>`
- **JSONL**:
  ```json
  {"cmd": "send", "session_id": "<session-id>", "text": "Hello peer", "burn": 500}
  ```
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "seq": 1,
    "bytes_sent": 10,
    "burn": 500
  }
  ```

---

### `inbox`
Retrieves and drains all decrypted inbound messages from local memory, along with any pending offers.

- **CLI**: `clojure -M:light-node inbox`
- **JSONL**: `{"cmd": "inbox"}`
- **Response**:
  ```json
  {
    "ok": true,
    "messages": [
      {
        "session_id": "sess-c47b19...",
        "from": "<sender-pubkey-hex>",
        "seq": 1,
        "text": "Hello peer",
        "payload_hex": "<hex>"
      }
    ],
    "pending_offers": []
  }
  ```

---

### `close`
Signs and broadcasts a channel close message, wiping session ephemeral keys and advancing session state to `closed`.

- **CLI**: `clojure -M:light-node close --session <session-id>`
- **JSONL**: `{"cmd": "close", "session_id": "<session-id>"}`
- **Response**:
  ```json
  {
    "ok": true,
    "session_id": "sess-c47b19...",
    "state": "closed"
  }
  ```

---

### `transfer`
Submits an account balance transfer to another public key. Consecutive transfers automatically increment the sequence number (`seq`) and chain causal dependencies (`deps`).

- **CLI**: `clojure -M:light-node transfer --receiver <pubkey-hex> --amount 100` (also accepts `--recipient <pubkey-hex>` and optional `--seq <num>`)
- **JSONL**: `{"cmd": "transfer", "receiver": "<pubkey-hex>", "amount": 100}` (or `"recipient"`)
- **Response**:
  ```json
  {
    "ok": true,
    "tx_id": "tx-8b2...",
    "transfer_hash": "tx-8b2...",
    "receiver": "<pubkey-hex>",
    "recipient": "<pubkey-hex>",
    "amount": 100,
    "seq": 1
  }
  ```

---

### `status`
Inspects local node accounting, active and pending sessions, burned ECHO, and validator connection health.

- **CLI**: `clojure -M:light-node status`
- **JSONL**: `{"cmd": "status"}`
- **Response**:
  ```json
  {
    "ok": true,
    "connected": true,
    "connection_error": null,
    "pubkey": "<pubkey-hex>",
    "epoch": 5,
    "autonomous": false,
    "sessions": [
      {
        "session-id": "sess-c47b19...",
        "peer": "<peer-pubkey-hex>",
        "role": "initiator",
        "state": "open",
        "tx-seq": 1,
        "epoch": 5
      }
    ],
    "pending_offers_count": 0,
    "inbox_count": 0,
    "accounting": {
      "scope": "local-non-consensus",
      "note": "Locally computed devnet totals; never consensus finalized",
      "burned_ech": 1500,
      "vouchers_count": 0
    }
  }
  ```
