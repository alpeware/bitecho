# Bitecho Light Node Reference Guide

Bitecho light nodes provide lightweight, self-sovereign edge access to the Bitecho decentralized network across three interchangeable runtimes: **JVM** (`bitecho.shell.light-node`), **Node.js** (`dist/bitecho-light-node.cjs`), and **Browser** (`dist/bitecho-browser.js`).

Light nodes do not maintain full consensus ledger state or participate in block production. Instead, they authenticate ledger balances, spendable sequences, and escrows directly against Streamlet BFT validator quorums using cryptographic Proof-of-Possession and signed chain-state snapshots.

---

## 1. CLI Commands & Options

```bash
# JVM Light Node
clojure -M:light-node <verb> [options]

# Node.js Light Node
node dist/bitecho-light-node.cjs <verb> [options]
```

### Verbs
- `status`: Display local node status, balance, spendable sequence, and network connection phase.
- `identity`: Show local Ed25519 public key, DTLS certificate fingerprint, and ICE credentials.
- `discover`: Probe and display online bootstrap nodes and validator endpoints.
- `sync-account`: Query and verify 2f+1 BFT validator quorum snapshots for local account balance and sequence.
- `serve`: Run continuous daemon mode with JSONL command file and event streams.
- `wait-event`: Block until a matching event occurs in the events output file.
- `offer` / `accept`: Initiate or accept two-party payment channels with agreed pricing and signaling burns.
- `send`: Dispatch authenticated, encrypted text or payload messages over established sessions.
- `inbox`: List received messages.
- `close`: Terminate active sessions.
- `transfer`: Execute direct authenticated balance transfers.
- `broadcast`: Broadcast zero-burn multi-peer messages across DAC-governed subnets.
- `p2p-offer` / `p2p-answer`: Negotiate in-band direct peer-to-peer WebRTC upgrades.
- `p2p-channel-state`: Inspect or update direct P2P link states.
- `directory-register` / `directory-lookup` / `directory-verify`: Manage and verify agent nicknames via the Directory Authority.
- `dac-attach` / `dac-revoke`: Manage Delegated Agent Certificates.
- `lock-intent` / `release-intent` / `refund-intent` / `escrows`: Manage hash-locked, deliverable-verified escrows.

### Key Flags
- `--state-dir <dir>`: Directory storing `node-identity.edn` and `state.fressian` (default: `~/.bitecho/light-node`).
- `--bootstrap <file|url>`: Path or URL to validator bootstrap descriptor.
- `--relay-url <url>`: URL of HTTP Gateway Relay endpoint (e.g. `https://bitecho.org/relay/v1` or `http://127.0.0.1:8080`).
- `--transport <udp|tcp|connect>`: Network transport mode.
- `--ingress-tcp-port <port>`: Local port for inbound TCP/DataChannel connections.
- `--autonomous`: Enable autonomous daemon behavior (auto-sync, auto-accept, home-set renewal).
- `--cmd-file <file>`: JSONL file from which daemon consumes commands.
- `--events-out <file>`: JSONL file to which daemon appends structured events.
- `--turn-server <url>` / `--turn-username <user>` / `--turn-password <pass>`: TURN credentials for NAT traversal.
- `--turn-force-relay`: Force all WebRTC traffic through TURN relay.

---

## 2. HTTP Gateway Relay (`/relay/v1/*`)

When running in restricted environments where UDP or direct TCP sockets are blocked (e.g. browser sandboxes, locked corporate firewalls, serverless functions), light nodes communicate through the HTTP Gateway Relay.

### Configuration
- **CLI Flag**: `--relay-url <url>`
- **Environment Variable**: `BITECHO_RELAY_URL`
- **Auto-Normalization**: Both origin URLs (`http://host:port`) and versioned paths (`http://host:port/relay/v1`) are accepted transparently via `normalize-relay-base-url`. Trailing slashes and whitespace are stripped automatically.

### Endpoints
1. **`POST /relay/v1/send`**:
   - Ingests Fressian or JSON envelopes.
   - Unicast envelopes are queued into recipient inboxes (`:max-inbox-size 256`, 16MB total inbox limit across max 1024 recipients).
   - Broadcast envelopes enter the 256-slot global ring buffer with 24-hour TTL eviction.
   - Ledger transactions (`:forward-to-validators`) are forwarded directly to validators, bypassing recipient inboxes.
   - Streaming reader bounds request payloads to 16MB, returning HTTP 413 `payload-too-large` on overflow.
   - Rate-limited via token-bucket limiter (HTTP 429 `rate-limited`).

2. **`GET / POST /relay/v1/poll`**:
   - Long-polls inbound envelopes and broadcasts.
   - Parameter `wait_ms` allows virtual thread parking up to 25,000 ms.
   - Bounded waiter pool (`:max-relay-waiters 256`) returns HTTP 429 `too-many-waiters` when saturated.
   - Authenticated via canonical Proof-of-Possession (`PoP`):
     `bitecho-relay-poll-v1|<pubkey>|<since-seq>|<timestamp-ms>|<nonce>`
   - Enforces clock skew tolerance (`<= 300,000 ms`) and timestamped replay protection (`:max-nonces 2048`).
   - Supports request headers:
     - `X-Bitecho-Pubkey`: Requester's Ed25519 public key hex.
     - `X-Bitecho-Timestamp-Ms`: Epoch millisecond timestamp.
     - `X-Bitecho-Nonce`: Unique alphanumeric poll nonce.
     - `X-Bitecho-Signature`: Ed25519 signature over canonical PoP string.
     - `X-Bitecho-Since-Seq`: High-water inbox sequence number.
     - `X-Bitecho-Since-Broadcast-Seq`: High-water broadcast ring sequence number.
     - `X-Bitecho-Wait-Ms`: Long-poll wait duration in milliseconds.

3. **`POST /relay/v1/ack`**:
   - Prunes processed inbox messages up to acknowledged sequence number.
   - Accepts `ack_seq` / `X-Bitecho-Ack-Seq` and `ack_broadcast_seq` / `X-Bitecho-Ack-Broadcast-Seq`.
   - Authenticated via Proof-of-Possession signature.

4. **`GET / POST /relay/v1/chain-state`**:
   - Fetches signed validator chain-state snapshots for a given public key hex (`pubkey=<hex>`) and client nonce (`nonce=<str>`).
   - Relay proxies responses with a 10-second TTL cache across validator nodes.

---

## 3. Fail-Closed 2f+1 BFT Quorum Verification

In adherence with **Rule 5 (Zero Silent Failures)**, light nodes never trust unsigned relay responses or single-validator assertions:

1. **Quorum Requirement**: Nodes require at least $2f+1$ agreeing snapshots from trusted validators (e.g. 2 of 3 validators on a 3-node cluster).
2. **State Agreement**: Snapshots within the quorum must agree strictly on:
   - Account balance (`:balance`)
   - Spendable balance (`:spendable`)
   - Transfer sequence number (`:seq`)
   - Dependency hashes (`:deps`)
   - Active escrows (`:escrows`)
3. **Epoch Skew**: The finalized epoch skew between validator snapshots must not exceed `max-epoch-skew` (default: 2 epochs).
4. **No Synthetic Snapshots**: The relay server never fabricates synthetic or unsigned zero-balance snapshots. If the relay returns empty or unverified snapshots, the light node fails closed with `{:ok? false :error "no-verified-relay-snapshots"}` and increments the diagnostic counter `:chain-state-sync-failed`.
5. **Monotonicity**: The node only updates local account state if the verified finalized epoch is greater than or equal to the current local finalized epoch.

---

## 4. Single-Authority Shell State & Lifecycle (Rule 4)

Connection and session lifecycle is managed by a single generation-tagged reducer:
`transition-conn : (state, event) -> [new-state, effects]`

All I/O side effects (`:emit`, `:close-node`, `:diagnose`) are executed strictly outside the transition function. Stale callbacks (`generation < current-generation`) are ignored and counted via `:dropped-stale-callback` diagnostics.
