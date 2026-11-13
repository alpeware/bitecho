# Bitecho Smart Contracts (ChiaLisp-Style Content-Addressed `sci` Puzzles)

Bitecho generalizes escrow settlement from a fixed preimage/signature rule to **ChiaLisp-style content-addressed `sci` smart contracts** (`bitecho.economy.puzzle`). Instead of storing mutable contract state on-chain, an escrow intent commits to a **puzzle hash** (`:puzzle-hash`), which is the content-addressed `Blob` CID of a pure Clojure S-expression evaluated in a deterministic [Small Clojure Interpreter (`sci`)](https://github.com/babashka/sci) sandbox at settlement time.

---

## 1. Architectural Model & ChiaLisp Parallel

| Concept | ChiaLisp (Chia Network) | Bitecho `sci` Smart Contracts |
| :--- | :--- | :--- |
| **Code Identity** | Puzzle Hash (`sha256tree` of CLVM puzzle) | `:puzzle-hash` = `Blob` CID (`SHA-256` lowercase 64-char hex of canonicalized S-Expression AST) |
| **Locking Funds** | Coin locked to puzzle hash | `lock-intent` locks `amount` ECHO to `:puzzle-hash` (stored on the escrow record) |
| **Spend / Settlement** | Reveal puzzle + solution -> produces conditions | `release-intent` reveals `:puzzle-source` + `:solution` -> `eval-puzzle` returns condition maps |
| **Protocol Conservation** | Sum of `CREATE_COIN` outputs <= coin value | Sum of `:release` + `:refund` condition amounts <= `escrow.amount` (with automatic remainder refund and 0.5% protocol settlement fee / burn conservation) |
| **Execution Model** | Pure functional lisp without side effects | Hermetically sealed Sans-IO Small Clojure Interpreter (`sci`) |

### 1.1 Canonical S-Expression AST Hashing (`puzzle-cid`)
In Chia, a puzzle is a binary tree of cons cells hashed via `sha256tree(node) = SHA-256(1 || sha256tree(left) || sha256tree(right))`, which naturally ignores formatting, comments, or whitespace.

In Bitecho, `puzzle/puzzle-cid` parses the source text into an S-expression AST using `edamame.core/parse-string-all`, recursively strips all reader metadata (line numbers, column offsets) and comment forms, and canonicalizes the AST into disjoint tagged forms:
- `[:list ...]` for lists
- `[:vec ...]` for vectors
- `[:map ...]` for sorted maps
- `[:set ...]` for sorted sets
- `[:sym ...]` for symbols
- `[:kw ...]` for keywords
- Primitives (`string`, `int`, `boolean`, `nil`)

The canonicalized AST is then serialized via deterministic canonical Fressian (`fressian/encode-canonical`) and hashed using standard `Blob` CID calculation (`SHA-256`). Consequently:
- Adding comments (`;; explanation`) or whitespace changes does **not** alter the puzzle's `:puzzle-hash`.
- Variable indentation or map key reordering produces the exact same cryptographic CID.
- Semantic tampering or logic changes instantly yield a different CID, preventing unauthorized puzzle substitution.

### 1.2 Standard HTLC Puzzle Unification (`standard-htlc-puzzle-source`)
Every legacy preimage/payer-authorized escrow in Bitecho is represented by the canonical **Standard HTLC Puzzle** (`puzzle/standard-htlc-cid`):

```clojure
(fn [env solution]
  (let [mode (:mode solution)]
    (cond
      ;; Mode 1: Deliverable preimage revealed by payer or receiver before expiration
      (= mode :preimage)
      (let [preimage (str (:preimage solution))]
        (if (and (= (sha256-hex preimage) (:deliverable-hash env))
                 (<= (:epoch env) (:expires-epoch env)))
          [{:type :release :receiver (:receiver env) :amount (:amount env)}]
          []))

      ;; Mode 2: Direct release authorization signed by payer
      (= mode :payer-authorized)
      [{:type :release :receiver (:receiver env) :amount (:amount env)}]

      ;; Default: reject invalid spend solution
      :else [])))
```

When an escrow is created without an explicit `:puzzle-hash`, it defaults to `(puzzle/standard-htlc-cid)`. The state machine executes both legacy HTLCs and arbitrary smart contracts through the exact same unified reducer pipeline, preserving strict authorization rules and telemetry keywords (`:payer-authorized`, `:preimage-verified`, `:puzzle-verified`).

---

## 2. Deterministic `sci` Sandbox Specification

Implemented in [`src/bitecho/economy/puzzle.cljc`](../src/bitecho/economy/puzzle.cljc), `eval-puzzle` executes inside a hermetically sealed, Sans-IO `sci` environment across JVM, Node.js, and Browser runtimes:

### 2.1 Security & Determinism Guarantees
- **Denied Host & Mutable Primitives:** `clojure.core/eval`, `read-string`, `slurp`, `spit`, `load-file`, `future`, `pmap`, `pcalls`, `pvalues`, `agent`, `send`, `send-off`, `atom`, `ref`, `var`, `alter-var-root`, `intern`, `ns`, `in-ns`, `require`, `use`, `import`, `refer`, `System`, `Thread`, `java.io.File`, `Math/random`, `rand`, `rand-int`, `rand-nth`, `shuffle`, `loop`, and `recur` are denied (`:deny` list in `sandbox-opts`).
- **Source Hygiene Guard:** Any `puzzle-source` containing reader macros (`#=(...)`, `#var`), Java interop (`java.`, `System/`, `Thread/`, `Class/`), or `js/` host access is immediately rejected with `:error :forbidden-construct` before parsing.
- **Size & Fuel Metering:**
  - `default-max-bytes`: `16,384` bytes (`16 KB`) for puzzle source and solution payloads.
  - `default-max-steps`: `10,000` deterministic AST/collection evaluation steps + bounded `range` materialization (`<= 256` elements). Exhausting the budget returns `{:valid? false :error :puzzle-budget-exceeded}`.

### 2.2 Injected Sandbox Bindings
Every puzzle expression has read-only access to:
1. **`escrow`** (also aliased as **`env`** and **`context`**) — Map of the locked escrow intent and execution context:
   ```clojure
   {:intent-id        "intent-123"
    :escrow-id        "intent-123"
    :payer            "<64-char-hex-ed25519-pubkey>"
    :receiver         "<64-char-hex-ed25519-pubkey>"
    :amount           1000
    :deliverable-hash "<64-char-hex>"
    :puzzle-hash      "<64-char-hex-cid>"
    :timeout-epoch    50
    :expires-epoch    50
    :epoch            12}
   ```
2. **`solution`** — Caller-supplied data structure (Clojure/JSON map, vector, string, or number) passed in `release-intent`.
3. **Cryptographic & Helper Primitives:**
   - `(sha256-hex x)` (also aliased as `(sha256 x)`): Lowercase 64-char SHA-256 hex digest of string, byte array, or Fressian-encoded data `x`.
   - `(verify-sig pubkey-hex msg-str-or-bytes sig-hex)` (also aliased as `(verify-signature ...)`): Deterministic Ed25519 signature verification (`true` / `false`).
   - `(bytes= a b)`: Equality on strings or byte arrays.

---

## 3. Settlement Conditions Language

A valid puzzle must evaluate to a **non-empty sequential collection of condition maps** (or vector pairs like `[:release receiver amount]` and `[:refund payer amount]`). Every condition map is validated against `escrow`:

| Condition Type | Schema | Semantics |
| :--- | :--- | :--- |
| **`:release`** | `{:type :release :receiver "<64-hex-pubkey>" :amount <pos-int>}` | Releases `:amount` ECHO to `:receiver` (subject to 0.5% protocol settlement fee: 50% burned, 50% routed to treasury). |
| **`:refund`** | `{:type :refund :receiver "<payer-pubkey>" :value <pos-int>}` (or `:amount`) | Refunds `:amount` ECHO back to `escrow.payer` with zero protocol fee. `:receiver` must equal `escrow.payer`. |
| **`:assert-epoch-gte`** | `{:type :assert-epoch-gte :epoch <non-neg-int>}` | Requires `context.epoch >= condition.epoch`; otherwise evaluation fails with `:epoch-before-min`. |
| **`:assert-epoch-lte`** | `{:type :assert-epoch-lte :epoch <non-neg-int>}` | Requires `context.epoch <= condition.epoch`; otherwise evaluation fails with `:epoch-after-max`. |
| **`:assert-sig`** | `{:type :assert-sig :pubkey "<64-hex>" :message "<str>" :signature "<128-hex>"}` | Requires a valid Ed25519 signature over `:message` by `:pubkey`; otherwise evaluation fails with `:invalid-signature-condition`. |
| **`:assert-sha256`** | `{:type :assert-sha256 :preimage "<str>" :hash "<64-hex>"}` | Requires `(= (sha256-hex preimage) hash)`; otherwise evaluation fails with `:hash-mismatch-condition`. |

### Conservation & Automatic Remainder Refund
- Let `total-out` be the sum of `:amount` across all `:release` and `:refund` conditions.
- If `total-out > (:amount escrow)`, evaluation fails with `{:valid? false :error :conservation-violated}`.
- If `total-out < (:amount escrow)`, `eval-puzzle` automatically appends a remainder refund condition:
  ```clojure
  {:type :refund-remainder :receiver (:payer escrow) :amount (- (:amount escrow) total-out)}
  ```
  Wait-free partial releases (e.g., milestone payouts, SLA penalty deductions, or multi-party splits between a compute provider and a verifier agent) are therefore settled atomically in a single transaction while returning any unspent remainder to the payer.

---

## 4. Canonical Puzzle Examples

### Example A: Hash-Time-Locked Milestone Split (Compute Provider + Verifier)
```clojure
(let [secret (:secret solution)
      verifier-pk (:verifier solution)]
  (if (= (sha256-hex secret) (:deliverable-hash escrow))
    [{:type :release :receiver (:receiver escrow) :amount 900}
     {:type :release :receiver verifier-pk        :amount 100}]
    []))
```

### Example B: Oracle / Auditor Co-Signed SLA Contract with Partial Refund
```clojure
[{:type :assert-epoch-lte :epoch (:timeout-epoch escrow)}
 {:type :assert-sig
  :pubkey "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  :message (str (:intent-id escrow) ":" (:payout solution))
  :signature (:oracle-sig solution)}
 {:type :release
  :receiver (:receiver escrow)
  :amount (:payout solution)}]
;; Any remainder (- (:amount escrow) (:payout solution)) is automatically refunded to (:payer escrow).
```

---

## 5. Execution Topology & Scalability: Consensus Number 1 vs. $\infty$

A fundamental design question for distributed agent systems is why Bitecho separates ordinary single-owner payments from multi-party smart contracts:

### 5.1 Consensus Number 1 (Asynchronous Single-Owner Transfers)
In distributed computing theory (Herlihy's consensus hierarchy), operations on objects with **Consensus Number 1** (e.g., read/write registers, private single-owner account balances) do **not require global consensus or sequential ordering**.
- When an agent signs a transfer or publishes a pointer update, the operation only mutates their own ledger sequence and unspent balance.
- Multiple agents can issue transfers concurrently with zero cross-transaction lock contention. Single-owner transfers scale horizontally $O(1)$ and can be validated asynchronously.

### 5.2 Consensus Number $\infty$ (Contended Multi-Party Escrows)
Objects with **Consensus Number $\infty$** (compare-and-swap, shared pools, mutual escrows) require global consensus to determine the winning spender among competing claimants.
- In Bitecho, Streamlet BFT is invoked **only** when consensus is mathematically necessary: allocating sequence numbers, ordering block batches, and evaluating `:escrow-release` smart contracts.
- **Bound on Evaluation Cost:** Every puzzle evaluation is strictly bounded by $10,000$ steps and a $50\text{ ms}$ wall-clock timeout. On standard commodity hardware (e.g. 8-core AMD/Intel), validators can evaluate $\approx 500{-}1,600$ smart contract releases per second.
- **Infinite Off-Chain Scalability:** Because escrows can act as payment-channel funding pots, two agents can exchange millions of off-chain state updates over peer WebRTC DataChannels per second and only hit Streamlet BFT twice: once to lock and once to settle.

---

## 6. Fractal Subnets: Zero-Cost Contract Reuse

In Bitecho, a **Subnet** is not a separate chain or a complex layer-2 roll-up with its own custom VM. A subnet is simply a domain-scoped admission gate and replication policy governed by the same pure state transition functions.

Because the `sci` puzzle engine is implemented as a pure Sans-IO library (`bitecho.economy.puzzle`), **every Subnet automatically gets the full smart contract capability with zero additional code**:
- Subnet hosts can define custom admission puzzles (requiring proof-of-burn, proof-of-stake, or valid DAC tokens).
- Capability escrows within a private or consortium subnet evaluate with the exact same security, deterministic gas metering, and condition semantics as the root `"global"` network.

---

## 7. Translating Web3 Primitives & Trade-offs vs. EVM

| Web3 Concept | Ethereum / EVM Equivalent | Bitecho Content-Addressed S-Expression Architecture |
| :--- | :--- | :--- |
| **State Storage** | Global mutable storage trie (`sstore`/`sload`) | Encrypted `Blob` (CAS payload) + Ed25519 `Pointer` (monotonic `seq`) |
| **Token Standards** | ERC-20 / ERC-721 contract with balance mapping | Native multi-asset subnets or capability descriptors with content-addressed IDs |
| **Multi-Sig / Vault** | Gnosis Safe contract maintaining owner arrays | Single puzzle asserting $M$-of-$N$ `(verify-sig ...)` conditions over caller solutions |
| **Oracles** | Chainlink oracle contracts updating on-chain variables | `assert-sig` conditions over timestamped price messages signed by oracle pubkeys |
| **Re-Entrancy** | Major vulnerability; requires re-entrancy guards | **Mathematically impossible.** Puzzles produce pure condition lists; no external contract calls exist during evaluation. |
| **MEV & Frontrunning** | Severe; searchers reorder transactions in mempool | **Minimized.** Escrows are strictly pairwise/authorized; condition evaluations are deterministic and non-speculative. |

By choosing deterministic predicates over shared mutable state, Bitecho eliminates re-entrancy attacks, eliminates gas auction front-running, and enables instant client-side simulation across any browser or mobile light node.

---

## 8. Light-Node Exposure Across All 3 Runtimes (JVM, Node.js, Browser)

All smart contract operations are exposed identically across the **JVM Light Node**, **Node.js Light Node** (`dist/bitecho-light-node.cjs`), and **Browser Light Node** (`BitechoBrowser.ctl`):

### 8.1 Compute a Puzzle's Content-Addressed Hash (`puzzle-hash`)
Computes the canonical `SHA-256` CID (`puzzle_hash`) of a `sci` puzzle expression locally (Sans-IO, comments and whitespace stripped):

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  puzzle-hash --puzzle-source '(if (= (sha256-hex (:secret solution)) (:deliverable-hash escrow)) [{:type :release :receiver (:receiver escrow) :amount (:amount escrow)}] [])'
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {"cmd": "puzzle-hash", "puzzle_source": "(if (= (sha256-hex (:secret solution)) (:deliverable-hash escrow)) [{:type :release :receiver (:receiver escrow) :amount (:amount escrow)}] [])"}
  ```
- **Response:**
  ```json
  {"ok": true, "puzzle_hash": "<64-char-hex-cid>", "size_bytes": 135}
  ```

### 8.2 Dry-Run / Test a Puzzle Locally (`puzzle-eval`)
Evaluates a `sci` puzzle against a candidate `solution` and simulated `escrow`/`context` before locking or spending funds on the network:

- **CLI (JVM / Node.js / Browser `ctl`):**
  ```bash
  puzzle-eval \
    --puzzle-source '[{:type :release :receiver (:receiver escrow) :amount (:payout solution)}]' \
    --solution '{"payout": 750}' \
    --amount 1000 \
    --epoch 10
  ```
- **JSONL (`serve` stdin / `ctl`):**
  ```json
  {
    "cmd": "puzzle-eval",
    "puzzle_source": "[{:type :release :receiver (:receiver escrow) :amount (:payout solution)}]",
    "solution": {"payout": 750},
    "amount": 1000,
    "epoch": 10
  }
  ```
- **Response:**
  ```json
  {
    "ok": true,
    "valid": true,
    "puzzle_hash": "<64-char-hex-cid>",
    "conditions": [
      {"type": "release", "receiver": "<receiver-pubkey>", "amount": 750},
      {"type": "refund-remainder", "receiver": "<payer-pubkey>", "amount": 250}
    ]
  }
  ```

### 8.3 Lock Escrow to a Smart Contract (`lock-intent`)
`lock-intent` accepts `--puzzle-hash <64-hex>` (or `--puzzle-source "<sci-expr>"`, which automatically computes `:puzzle-hash` via `puzzle/puzzle-cid`). If `--deliverable-hash` is omitted when `--puzzle-hash` is provided, `:deliverable-hash` defaults to `:puzzle-hash`:

```bash
lock-intent \
  --receiver <provider-pubkey-or-petname> \
  --amount 1000 \
  --puzzle-hash <64-char-hex-cid> \
  --timeout-epoch 50
```

### 8.4 Settle a Smart Contract Escrow (`release-intent`)
`release-intent` accepts `--puzzle-source "<sci-expr>"` and `--solution '<json-or-edn>'` and broadcasts the signed `:release-intent` envelope to the validator network:

```bash
release-intent \
  --intent-id <intent-id> \
  --puzzle-source '[{:type :release :receiver (:receiver escrow) :amount (:payout solution)}]' \
  --solution '{"payout": 750}'
```
