# Bitecho CLI Command Reference (`68 -> 12` Canonical Verb Desugaring)

In **Bitecho `v0.23.9` (`BIP-005: Unification III`)**, the CLI and JSONL command surface is unified around **12 canonical verbs**:

`put`, `get`, `list`, `transfer`, `lock`, `spend`, `connect`, `send`, `inbox`, `wait`, `serve`, `ctl`

All **68 legacy domain verbs** (`cli/supported-cli-verbs`) and **8 runner/shell aliases** remain 100% supported and deterministically desugar via `bitecho.light-node.cli/desugar-cli-cmd-map` (`F-U1`, `F-U2`).

---

## 1. The 12 Canonical Verbs

| Canonical Verb | Purpose | Primary Flags |
| :--- | :--- | :--- |
| `put` | Publish or update any Blob + signed Pointer (artifacts, encrypted storage slots, capabilities, BIPs, votes, petnames, directory entries, subnet anchors, or tombstones) | `--subnet-id`, `--path`, `--file`, `--text`, `--hex`, `--seq`, `--burn`, `--slot-id`, `--capability-id`, `--bip-id`, `--circle`, `--petname`, `--nickname` |
| `get` | Read node status, identity, account balance, or resolve any Pointer + Blob by path/slot/capability/BIP/petname/nickname | `--subnet-id`, `--path`, `--out-file`, `--slot-id`, `--capability-id`, `--bip-id`, `--petname`, `--nickname`, `--sync`, `--balance` |
| `list` | List active Pointers, subscribed subnets, capabilities, bounties, escrows, petnames, or storage slots | `--subnet-id`, `--prefix`, `--subscribe-subnets`, `--capability-type`, `--authority` |
| `transfer` | Transfer ECH tokens to a recipient public key, `ech1...` address, or petname | `--to`, `--receiver`, `--recipient`, `--amount`, `--seq`, `--burn`, `--min-balance` |
| `lock` | Lock ECH into a ChiaLisp-style SCI puzzle escrow or bilateral 3-of-3 bounty | `--to`, `--receiver`, `--amount`, `--deliverable-hash`, `--puzzle-hash`, `--puzzle-source`, `--expires-epoch`, `--timeout-epoch`, `--bounty-id` |
| `spend` | Settle or refund a locked puzzle escrow / 3-of-3 bounty, or evaluate/hash a puzzle | `--escrow-id`, `--preimage`, `--puzzle-source`, `--solution`, `--bounty-id`, `--builder`, `--auditor`, `--patch-cid`, `--sha256` |
| `connect` | Open, accept, upgrade (WebRTC P2P), or close a session, or configure rendezvous home sets & policy | `--to`, `--callee`, `--session-id`, `--price`, `--burn`, `--wait-open-ms`, `--candidates`, `--connected`, `--nodes`, `--offer-hash` |
| `send` | Send an E2EE sealed message to a peer/session or broadcast to a subnet | `--to`, `--session-id`, `--subnet-id`, `--text`, `--payload-hex`, `--burn`, `--min-balance` |
| `inbox` | Read/peek inbound sealed messages and broadcasts, acknowledge sequences, or import/export air-gapped shuttle frames | `--subnet-id`, `--peek`, `--hex`, `--file` |
| `wait` | Block until actionable network events or sequence cursors arrive | `--timeout-ms`, `--min-seq`, `--min-broadcast-seq`, `--block`, `--until-event`, `--session-id`, `--after-ts` |
| `serve` | Run the persistent background daemon with JSONL stdio, auto-sync, and loopback `/ctl` | `--state-dir`, `--bootstrap`, `--relay-url`, `--subnet-id`, `--autonomous`, `--auto-sync`, `--daemon`, `--control-port` |
| `ctl` | Execute any canonical or legacy verb against a running local `serve` daemon | `--state-dir`, `--control-port` |

---

## 2. Complete `68/68` Legacy Verb Desugaring Table (`F-U1`)

| # | Legacy Verb | Canonical Verb | Canonical Invocation Equivalent |
| :--- | :--- | :--- | :--- |
| 1 | `accept` | `connect` | `connect --session-id <sid>` |
| 2 | `account` | `get` | `get --sync` / `get --balance <n>` |
| 3 | `ack` | `inbox` | `inbox --up-to-seq <n>` |
| 4 | `anchor-subnet` | `put` | `put --subnet-id <child> --parent-subnet <parent>` |
| 5 | `artifact-get` | `get` | `get --subnet-id <s> --path <p>` |
| 6 | `artifact-list` | `list` | `list --subnet-id <s> [--prefix <p>]` |
| 7 | `artifact-put` | `put` | `put --subnet-id <s> --path <p> --file <f> [--burn <n>]` |
| 8 | `artifact-revoke` | `put` | `put --subnet-id <s> --path <p> --tombstone` |
| 9 | `bip-consent` | `put` | `put --bip-id <id> --circle <c> --weight <w> [--burn <n>]` |
| 10 | `bip-object` | `put` | `put --bip-id <id> --circle <c> --counterexample-edn <edn>` |
| 11 | `bip-status` | `get` | `get --bip-id <id>` |
| 12 | `bip-submit` | `put` | `put --bip-id <id> --title <t> --spec-edn <edn> [--burn <n>]` |
| 13 | `bounties` | `list` | `list --bounties [--subnet-id <s>]` |
| 14 | `bounty-create` | `lock` | `lock --bounty-id <id> --target-cid <cid> --amount <n>` |
| 15 | `bounty-settle` | `spend` | `spend --bounty-id <id> --builder <b> --auditor <a> --patch-cid <c>` |
| 16 | `broadcast` | `send` | `send --subnet-id <s> --text <msg> [--burn <n>]` |
| 17 | `capability-list` | `list` | `list --capability-type <t>` |
| 18 | `capability-publish` | `put` | `put --capability-id <id> --capability-type <t> --price <p>` |
| 19 | `capability-resolve` | `get` | `get --capability-id <id> [--authority <pk>]` |
| 20 | `close` | `connect` | `connect --session-id <sid> --close` |
| 21 | `dac-attach` | `ctl` | `ctl dac-attach` |
| 22 | `dac-revoke` | `ctl` | `ctl dac-revoke` |
| 23 | `directory-lookup` | `get` | `get --nickname <nick> [--domain <d>]` |
| 24 | `directory-register` | `put` | `put --nickname <nick> [--domain <d>] [--mailbox <m>]` |
| 25 | `directory-verify` | `get` | `get --nickname <nick> --verify` |
| 26 | `discover` | `list` | `list --discover` |
| 27 | `epoch-tick` | `ctl` | `ctl epoch-tick --epoch <e>` |
| 28 | `escrows` | `list` | `list --escrows [--sync]` |
| 29 | `export-ack` | `inbox` | `inbox --up-to-seq <n> --offline` |
| 30 | `export-offer` | `connect` | `connect --to <peer> --offline` |
| 31 | `export-poll` | `inbox` | `inbox --since-seq <n>` |
| 32 | `export-send` | `send` | `send --to <peer> --text <msg> --offline` |
| 33 | `help` | `ctl` | `ctl --help` |
| 34 | `identity` | `get` | `get --identity` |
| 35 | `import` | `inbox` | `inbox --hex <hex>` |
| 36 | `import-poll` | `inbox` | `inbox --payload <json>` |
| 37 | `inbox` | `inbox` | `inbox [--subnet-id <s>] [--peek]` |
| 38 | `lock-intent` | `lock` | `lock --to <peer> --amount <n> --puzzle-hash <h>` |
| 39 | `offer` | `connect` | `connect --to <peer> [--price <p>] [--burn <n>]` |
| 40 | `p2p-answer` | `connect` | `connect --session-id <sid> --candidates <c> --answer` |
| 41 | `p2p-channel-state` | `connect` | `connect --session-id <sid> --connected <bool>` |
| 42 | `p2p-offer` | `connect` | `connect --session-id <sid> --candidates <c>` |
| 43 | `petname-list` | `list` | `list --petnames` |
| 44 | `petname-remove` | `put` | `put --petname <n> --remove` |
| 45 | `petname-resolve` | `get` | `get --petname <n>` |
| 46 | `petname-set` | `put` | `put --petname <n> --pubkey <pk> [--overwrite]` |
| 47 | `puzzle-eval` | `spend` | `spend --puzzle-source <src> --solution <sol> --eval-only` |
| 48 | `puzzle-hash` | `spend` | `spend --puzzle-source <src> --hash-only` |
| 49 | `query-chain-state` | `get` | `get --chain-state` |
| 50 | `refund-intent` | `spend` | `spend --escrow-id <id> --refund` |
| 51 | `register-home-set` | `connect` | `connect --nodes <n1,n2,n3> --price <p>` |
| 52 | `release-intent` | `spend` | `spend --escrow-id <id> [--preimage <p>] [--solution <s>]` |
| 53 | `rendezvous-accept` | `connect` | `connect --offer-hash <h> [--from <pk>]` |
| 54 | `rendezvous-offer` | `connect` | `connect --to <peer> --topic <t> [--burn <n>]` |
| 55 | `rendezvous-policy` | `connect` | `connect --min-burn <n> [--allowlist <pks>] [--auto-accept]` |
| 56 | `retransmit-outbox` | `send` | `send --session-id <sid> --retransmit` |
| 57 | `send` | `send` | `send --to <peer> --text <msg> [--burn <n>]` |
| 58 | `settle-intent` | `spend` | `spend --to <peer> --amount <n>` |
| 59 | `status` | `get` | `get` |
| 60 | `storage-get` | `get` | `get --subnet-id <s> --slot-id <slot>` |
| 61 | `storage-list` | `list` | `list --slots [--subnet-id <s>]` |
| 62 | `storage-put` | `put` | `put --subnet-id <s> --slot-id <slot> --data <d>` |
| 63 | `submit-vouchers` | `spend` | `spend --vouchers` |
| 64 | `subscribe-subnets` | `list` | `list --subscribe-subnets <s1,s2>` |
| 65 | `sync-account` | `get` | `get --sync` |
| 66 | `transfer` | `transfer` | `transfer --to <peer> --amount <n> [--burn <n>]` |
| 67 | `verify-subnet-anchor` | `get` | `get --subnet-id <child> --parent-subnet <parent>` |
| 68 | `wait` | `wait` | `wait [--timeout-ms <ms>] [--min-seq <n>] [--block]` |

---

## 3. Complete `8/8` Runner & Shell Alias Desugaring Table (`F-U1`)

| # | Shell / Runner Alias | Canonical Verb | Description |
| :--- | :--- | :--- | :--- |
| 1 | `serve` | `serve` | Persistent JSONL / loopback control daemon |
| 2 | `ctl` | `ctl` | Loopback HTTP `/ctl` client |
| 3 | `daemon` | `serve` | Process supervisor (`daemon start|stop|status|restart`) |
| 4 | `wait-event` | `wait` | File-backed `--events-out` blocking watcher |
| 5 | `export-p2p-offer` | `connect` | Air-gapped WebRTC SDP offer export |
| 6 | `export-p2p-answer` | `connect` | Air-gapped WebRTC SDP answer export |
| 7 | `export-reveal` | `connect` | Air-gapped rendezvous reveal export |
| 8 | `import-envelope` | `inbox` | Air-gapped raw Fressian hex envelope import |
