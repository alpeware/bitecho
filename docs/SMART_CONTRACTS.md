# Bitecho Smart Contracts (ChiaLisp-Style Content-Addressed `sci` Puzzles)

Bitecho generalizes escrow settlement from a fixed preimage/signature rule to **ChiaLisp-style content-addressed `sci` smart contracts** (`bitecho.economy.puzzle`). Instead of storing mutable contract state on-chain, an escrow intent commits to a **puzzle hash** (`:puzzle-hash`), which is the content-addressed `Blob` CID (`SHA-256(puzzle-source-utf8-bytes)`) of a pure Clojure expression evaluated in a deterministic [Small Clojure Interpreter (`sci`)](https://github.com/babashka/sci) sandbox at settlement time.

---

## 1. Architectural Model & ChiaLisp Parallel

| Concept | ChiaLisp (Chia Network) | Bitecho `sci` Smart Contracts |
| :--- | :--- | :--- |
| **Code Identity** | Puzzle Hash (`sha256tree` of CLVM puzzle) | `:puzzle-hash` = `Blob` CID (`SHA-256` lowercase 64-char hex of UTF-8 `puzzle-source`) |
| **Locking Funds** | Coin locked to puzzle hash | `lock-intent` locks `amount` ECHO to `:puzzle-hash` (stored on the escrow record) |
| **Spend / Settlement** | Reveal puzzle + solution -> produces conditions | `release-intent` reveals `:puzzle-source` + `:solution` -> `eval-puzzle` returns condition maps |
| **Protocol Conservation** | Sum of `CREATE_COIN` outputs <= coin value | Sum of `:release` + `:refund` condition amounts <= `escrow.amount` (with automatic remainder refund and 0.5% protocol settlement fee / burn conservation) |

---

## 2. Deterministic `sci` Sandbox Specification

Implemented in [`src/bitecho/economy/puzzle.cljc`](../src/bitecho/economy/puzzle.cljc), `eval-puzzle` executes inside a hermetically sealed, Sans-IO `sci` environment across JVM, Node.js, and Browser runtimes:

### 2.1 Security & Determinism Guarantees
- **Denied Host & Mutable Primitives:** `clojure.core/eval`, `read-string`, `slurp`, `spit`, `load-file`, `future`, `pmap`, `pcalls`, `pvalues`, `agent`, ` send`, `send-off`, `atom`, `ref`, `var`, `alter-var-root`, `intern`, `ns`, `in-ns`, `require`, `use`, `import`, `refer`, `System`, `Thread`, `java.io.File`, `Math/random`, `rand`, `rand-int`, `rand-nth`, `shuffle`, `loop`, and `recur` are denied (`:deny` list in `sandbox-opts`).
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

A valid puzzle must evaluate to a **non-empty sequential collection of condition maps**. Every condition map is validated against `escrow`:

| Condition Type | Schema | Semantics |
| :--- | :--- | :--- |
| **`:release`** | `{:type :release :receiver "<64-hex-pubkey>" :amount <pos-int>}` | Releases `:amount` ECHO to `:receiver` (subject to the 0.5% protocol settlement take: 50% burned, 50% routed to treasury). |
| **`:refund`** | `{:type :refund :receiver "<payer-pubkey>" :value <pos-int>}` (or `:amount`) | Refunds `:amount` ECHO back to `escrow.payer` with zero protocol fee. `:receiver` (if omitted or specified) must equal `escrow.payer`. |
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

## 5. Light-Node Exposure Across All 3 Runtimes (JVM, Node.js, Browser)

All smart contract operations are exposed identically across the **JVM Light Node**, **Node.js Light Node** (`dist/bitecho-light-node.cjs`), and **Browser Light Node** (`BitechoBrowser.ctl`):

### 5.1 Compute a Puzzle's Content-Addressed Hash (`puzzle-hash`)
Computes the `SHA-256` CID (`puzzle_hash`) of a `sci` puzzle expression locally (Sans-IO):

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

### 5.2 Dry-Run / Test a Puzzle Locally (`puzzle-eval`)
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

### 5.3 Lock Escrow to a Smart Contract (`lock-intent`)
`lock-intent` accepts `--puzzle-hash <64-hex>` (or `--puzzle-source "<sci-expr>"`, which automatically computes `:puzzle-hash` via `puzzle/puzzle-cid`). If `--deliverable-hash` is omitted when `--puzzle-hash` is provided, `:deliverable-hash` defaults to `:puzzle-hash`:

```bash
lock-intent \
  --receiver <provider-pubkey-or-petname> \
  --amount 1000 \
  --puzzle-hash <64-char-hex-cid> \
  --timeout-epoch 50
```

### 5.4 Settle a Smart Contract Escrow (`release-intent`)
`release-intent` accepts `--puzzle-source "<sci-expr>"` and `--solution '<json-or-edn>'` and broadcasts the signed `:release-intent` envelope to the validator network:

```bash
release-intent \
  --intent-id <intent-id> \
  --puzzle-source '[{:type :release :receiver (:receiver escrow) :amount (:payout solution)}]' \
  --solution '{"payout": 750}'
```
