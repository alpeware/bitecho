# Bitecho Light-Node Protocol & Gateway Specification (`docs/SPEC.md`)

## 1. HTTP Relay Gateway (`/relay/v1/*`) Contract

The Bitecho HTTP Relay Gateway provides an asymmetric, zero-burn, air-gappable transport bridge for light nodes and web clients unable to maintain direct DataChannel UDP/TCP mesh connections.

### 1.1 Bridge Modes: `:relay-validator-bridge?`

Relay server instances operate in one of two distinct modes:

- **Standalone Zero-Burn Gateway (`:relay-validator-bridge? false`):**
  - Serves as an ephemeral message and broadcast broker between peers without touching consensus or validator state.
  - Zero token burn requirements; all messages and offers route via internal inboxes.
- **Validator Bridge (`:relay-validator-bridge? true`):**
  - Acts as a full bridge connected to the validator cluster mesh.
  - Bridges incoming gossip envelopes to cluster validators and forwards validator-signed responses (such as `:chain-state-snapshot`) back into target account inboxes.

### 1.2 Endpoints

All relay endpoints enforce UTF-8 JSON payloads and canonical Ed25519 signature checks.

#### `POST /relay/v1/poll`
Polls for queued messages addressed to `pubkey` and public broadcast envelopes.
- **Request:**
  ```json
  {
    "pubkey": "<64-or-88-char-hex-pubkey>",
    "since_seq": 0,
    "since_broadcast_seq": 0,
    "timestamp_ms": 1794510041000,
    "nonce": "poll-0-<hex>-1794510041000",
    "signature": "<128-char-hex-signature>"
  }
  ```
  *Canonical string for signature:* `(str "relay-poll:" pubkey ":" since-seq ":" since-broadcast-seq ":" timestamp-ms ":" nonce)`
- **Response:**
  ```json
  {
    "ok": true,
    "messages": [
      {
        "relay_seq": 1,
        "envelope_hex": "<hex>",
        "timestamp_ms": 1794510042000
      }
    ],
    "broadcasts": [
      {
        "broadcast_seq": 1,
        "envelope_hex": "<hex>",
        "timestamp_ms": 1794510042000
      }
    ]
  }
  ```

#### `POST /relay/v1/send`
Submits an envelope for forwarding to target inboxes or network broadcast.
- **Request:**
  ```json
  {
    "envelope_hex": "<hex>"
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "relay_seq": 1
  }
  ```
  *Note:* Submissions carrying valid validator-signed `:chain-state-snapshot` envelopes (`:validator-pubkey` and `:signature`) are verified via canonical snapshot signing payloads and routed directly into the queried account's inbox.

#### `POST /relay/v1/ack`
Acknowledges receipt of polled envelopes, allowing the gateway to garbage collect delivered items.
- **Request:**
  ```json
  {
    "pubkey": "<hex>",
    "ack_seq": 1,
    "ack_broadcast_seq": 1,
    "timestamp_ms": 1794510043000,
    "nonce": "ack-1-<hex>-1794510043000",
    "signature": "<hex>"
  }
  ```
  *Canonical string for signature:* `(str "relay-ack:" pubkey ":" ack-seq ":" ack-broadcast-seq ":" timestamp-ms ":" nonce)`
- **Response:**
  ```json
  {
    "ok": true
  }
  ```

#### `POST /relay/v1/chain-state`
Queries validator quorum for an account's authenticated chain state snapshot.
- **Request:**
  ```json
  {
    "pubkey": "<hex>"
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "snapshot": {
      "type": "chain-state-snapshot",
      "pubkey": "<hex>",
      "epoch": 42,
      "balance": 1000000,
      "spendable": 1000000,
      "seq": 5,
      "validator_pubkey": "<hex>",
      "signature": "<hex>"
    }
  }
  ```

#### `GET /healthz`
Liveness probe returning HTTP 200 `{"ok": true}`.

---

## 2. Chunked Envelope Transport Format

For ultra-reliable manual cut-and-paste or air-gapped terminal transfer, envelope hex payloads are formatted in numbered, fixed-width chunks with cryptographic integrity tags:

```text
L01 [200c sha=89abcdef]: <200 hex chars>
L02 [200c sha=12345678]: <200 hex chars>
L03 [48c sha=abcdef01]: <remaining 48 hex chars>
```

### Parsing Rules:
1. **Line Normalization:** Pure parser `strip-chunk-prefixes` strips line prefix labels (`L01`, `L02`), length tags (`[200c sha=...]`), whitespace, and trailing newlines.
2. **Integrity Prefix:** The 8-character `sha=` parameter represents the first 8 hex characters of the SHA-256 digest of the chunk's payload, enabling visual confirmation of line integrity.
3. **Payload Extraction:** `parse-poll-payloads` handles raw JSON envelopes, individual hex lines, chunked hex strings, and signed `:chain-state-snapshot` maps interchangeably.

---

## 3. Light-Node Control Daemon Interface (`ctl`)

When running in daemon mode (`serve`), light nodes expose a local loopback-only control interface for IPC and operator automation.

### 3.1 Control Metadata & Security
- **File Location:** `<state-dir>/control.json`
- **File Permissions:** `0600` (`-rw-------`, POSIX compliant)
- **Contents:**
  ```json
  {
    "port": 5020,
    "token": "32-byte-hex-random-token",
    "pid": 12345
  }
  ```
- **Binding:** Strictly loopback `127.0.0.1`.
- **Authentication:** All requests must include `Authorization: Bearer <token>`.
- **Lifecycle:** On graceful shutdown or signal termination (SIGINT, SIGTERM), the socket is closed and `<state-dir>/control.json` is atomically unlinked.

### 3.2 Command Dispatch (`POST /ctl`)
Any valid light-node command map may be sent to `/ctl`:
```json
{
  "cmd": "send",
  "to": "alice",
  "text": "Hello, world!"
}
```

### 3.3 Event Notification Long-Polling (`cmd: "wait"`)
The `wait` command provides zero-latency notification of asynchronous network events:
```json
{
  "cmd": "wait",
  "timeout_ms": 10000
}
```
If actionable events (`message-received`, `offer-received`, `channel-opened`, `p2p-connected`, `p2p-disconnected`, `diagnostic`) are buffered in `:event-queue`, they are drained and returned immediately. If the queue is empty, the daemon holds the HTTP connection open until an event is enqueued or `timeout_ms` expires.
