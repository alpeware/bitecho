# Bitecho Release & Upgrade Runbook (`RELEASE.md`)

This runbook defines the authoritative release lifecycle, network separation model (`devnet.bitecho.org` / `testnet.bitecho.org` / `mainnet.bitecho.org`), pre-release verification gates, canary rolling deployment order, monitoring thresholds, and rollback procedures for Bitecho.

---

## 1. Network Topologies & URI Separation

Every Bitecho network is identified by an explicit canonical `:network-uri` that also serves as its root `:subnet-id`:

| Network | `:network` | `:network-uri` / Root `:subnet-id` | Purpose & Governance | Custody Key Policy | Default Tokenomics |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Devnet** | `:devnet` | `devnet.bitecho.org` | Rapid multi-agent & validator development, chaos testing, and automated E2E gates (`10s` fast epochs) | Automated Devnet custody keypair allowed for test funding | `burn-floor=100`, `take=50 bps`, `window=168` |
| **Testnet** | `:testnet` | `testnet.bitecho.org` | Public staging & civilization soak cluster (`1h` epochs, `N=6` validators across `us-west1`/`us-central1`/`us-east1`) | Restricted staging custody keypair | `burn-floor=50`, `take=150 bps`, `window=336` |
| **Mainnet** | `:mainnet` | `mainnet.bitecho.org` | Production network with ratified `BIP-001` v2.2 Pareto-optimal tokenomics and strict replay protection (`:strict-network-uri? true`) | **Cold offline custody only** — `validate-node-config` rejects hot `:custody-privkey` (`A-D23-4`) | `burn-floor=50`, `take=150 bps`, `window=336` |

### Cross-Network Replay Protection & Rolling Upgrade Equivalence
1. **Transfer Replay Protection (`A-D23-1`, `A-CARB-D23-1`):** Signed `Transfer` records bind `:network-uri` inside the canonical Ed25519 signing payload (`bitecho.economy.account/create-transfer`). Validators (`bitecho.state-machine`) and light nodes (`bitecho.light-node.core`) reject any transfer carrying a mismatched `:network-uri` (and Mainnet rejects any unscoped transfer missing `:network-uri`), incrementing `[:diagnostics :network-replay-rejected]` and emitting a `:diagnose` effect.
2. **Escrow Replay Protection (`A-CARB-D23-2`):** `bitecho.economy.escrow/compute-escrow-id` (8-arity) binds `network-uri` into `bitecho-escrow-id-v1`, and `:lock-intent` / `:release-intent` / `:refund-intent` / `:settle-intent` reject foreign `:network-uri` events with counted `:network-replay-rejected` diagnostics.
3. **Rolling `N` / `N+1` Root Subnet Compatibility:** During rolling upgrades, `bitecho.config/equivalent-subnet-id?` treats legacy `"global"` and the active network's root URI (`"devnet.bitecho.org"`) as equivalent while strictly isolating `"devnet.bitecho.org"`, `"testnet.bitecho.org"`, and `"mainnet.bitecho.org"` from one another.

---

## 2. Pre-Release Verification Gate & BIP Governance Machine Workflow

Every release candidate MUST pass all 6 local verification gates with zero warnings or failures before building release artifacts or initiating on-chain governance:

```bash
# 1. Code formatting & static analysis (AGENTS.md Rule 3)
clojure -M:format
clojure -M:lint

# 2. Full unit + generative test.check suite (AGENTS.md Rule 1)
clojure -M:test --skip-integration

# 3. Multi-network release proof generator (devnet/testnet/mainnet + 6-pair replay matrix + N/N+1 rolling interop + S1-S24 scenarios)
clojure -M:proof docs/releases/v0.23.5-proof.edn

# 4. Pre-deploy E2E wire negotiation & 3-epoch Streamlet finalization gate
./scripts/cluster.sh verify-e2e

# 5. Production uberjar & Node/Browser light-node bundle build
./scripts/build-node-light-node.sh
./scripts/build-browser-bundle.sh
./scripts/build-sea.sh
```

### The BIP Governance Machine Workflow (`--burn 100` Off-Leg Rule)
Upgrades and parameter modifications are governed on-chain via the Tri-Circle Sociocratic Governance Machine:
1. **Proof Generation & Gate Assertion:** Generate bit-for-bit release proof with `clojure -M:proof docs/releases/v0.23.5-proof.edn`. `scripts/cluster.sh` asserts that all test gates passed and verifies commit and tree SHAs.
2. **Proposal Submission (`--burn 100`):** Submit the BIP proposal using `--burn 100` (mandatory anti-spam burn floor across validator mesh gossip):
   ```bash
   ./scripts/light-node.sh bip-submit \
     --bip-id BIP-002 \
     --title "Release v0.23.5" \
     --proof-file docs/releases/v0.23.5-proof.edn \
     --burn 100
   ```
3. **Tri-Circle Sociocratic Consent (`--burn 100`):** All three circles (`:mesh-validators`, `:builders-stewards`, `:token-anchors`) evaluate the proposal and record consent via `bip-consent --burn 100` (or substantiate objections with bit-for-bit reproducible regression vectors via `bip-object --burn 100`).
4. **Scheduled Upgrade Epoch Activation:** Once 3-of-3 circle consent is achieved with 0 paramount objections, the proposal state transitions to `:ratified`, and its target epoch is scheduled in `:scheduled-upgrades`.
5. **On-Network Artifact Publishing (`migrate-infra` / `publish-release`):** Binaries and web documents are published as content-addressed `Blob`s and Cold-Root-signed `Pointer`s into `bitecho.org/infra`, serving live at `https://bitecho.org/releases/v0.23.5/...` and `/bip/<bip-id>`.

---

## 3. Deterministic Artifact Build & On-Network Publishing Pipeline

1. Build the release uberjar, Node/Browser bundles, and SEA standalone binaries:
   ```bash
   clojure -T:build uber
   ./scripts/build-node-light-node.sh
   ./scripts/build-browser-bundle.sh
   ./scripts/build-sea.sh
   sha256sum dist/bitecho-light-node.cjs dist/bitecho-browser.js
   ```
2. Ingest compiled artifacts and web resources into the `bitecho.org/infra` subnet:
   - Git tracks **source code and cryptographic proofs only** (`docs/releases/v0.23.5-proof.edn`). Compiled distribution artifacts in `dist/` are untracked in git.
   - The infra cluster replicates artifacts across `ns1..ns3` via `migrate-clj-web-state!`, serving them with content-addressed `ETag`s and Ed25519 authenticity headers (`X-Bitecho-Pointer-Signature`, `X-Bitecho-Blob-Cid`).
3. Tag the release commit with an annotated Git tag:
   ```bash
   git tag -a v0.23.5 -m "Release v0.23.5: Milestone D27 Docs Clean-Up, On-Network Publishing, Mealy Lab Foundation, and Mesh/Relay Offer Delivery Remediation"
   ```

---

## 4. Canary & Rolling Upgrade Procedure (`A-D23-5`)

To preserve Streamlet BFT quorum (`>= 4 of 6` validators in the 6-node mesh, `>= 2 of 3` in the 3-node core committee) at every instant, production and staging deployments follow a strict canary-first rolling sequence:

```
ns3 (infra canary) -> node3 (validator canary) -> [E2E Gate] -> ns2 -> ns1 -> node2 -> node1
```

### Step-by-Step Execution
1. **Backup Current Artifacts (`.prev`):**
   `./scripts/cluster.sh deploy` automatically copies `/opt/bitecho/bitecho.jar` to `/opt/bitecho/bitecho.jar.prev` and `/etc/bitecho/config.edn` to `/etc/bitecho/config.edn.prev` on every target host before uploading new artifacts.
2. **Phase 1 — Canary Deploy (`ns3` + `node3`):**
   ```bash
   ./scripts/cluster.sh deploy --canary
   ```
   - Upgrades `ns3` and `node3` first while `node1`, `node2`, `ns1`, and `ns2` remain on version `N`.
   - Polls `http://127.0.0.1:8080/healthz` on `node3` until healthy (up to `30s`) and runs the live E2E transfer & finality confirmation gate (`cmd_fund` + `cmd_audit`).
   - If `node3` fails `/healthz` or the E2E gate, execution halts immediately before `node2` or `node1` is touched.
3. **Phase 2 — Rolling Upgrade (`ns2` -> `ns1` -> `node2` -> `node1`):**
   ```bash
   ./scripts/cluster.sh deploy --rolling
   ```
   - Sequentially restarts `ns2`, `ns1`, `node2`, and `node1`, waiting for `/healthz` (`ok`) on each validator before proceeding to the next node.

---

## 5. Live Post-Deploy E2E Verification & Soak Gate

Immediately after completing the rolling upgrade:
1. Run the live cluster convergence audit across all 6 validators:
   ```bash
   ./scripts/cluster.sh status --include-infra
   ./scripts/cluster.sh audit --include-infra
   ```
2. Verify that a fresh light-node transfer finalizes within 3 Streamlet epochs and that all 6 validators report identical finalized ledger state digests.

---

## 6. Monitoring & Alerting Thresholds (`/healthz`, `/statusz`, `/connz`, `/burnsz`)

Monitor the following localhost diagnostic endpoints (`http://127.0.0.1:8080/*`) on every validator:

| Endpoint | Metric / Field | Healthy Bound | Alert / Rollback Trigger |
| :--- | :--- | :--- | :--- |
| `/healthz` | HTTP status & body | `200 OK` (`{"status":"ok"}`) | Non-200 for `> 15s` |
| `/statusz` | `:finalized-epoch` skew across quorum | `<= 2` epochs | Skew `> 2` epochs for `> 60s` |
| `/statusz` | `:failed-receipts-count` | `0` | Any increase (`> 0`) |
| `/statusz` | `[:diagnostics :network-replay-rejected]` | Counted & surfaced (Rule 5) | Investigate foreign-network traffic spikes |
| `/statusz` | `[:diagnostics :subnet-mismatch-dropped]` | `0` across upgraded peers | Non-zero between cluster validators |
| `/connz` | `:phase`, `:generation`, `:dropped`, `:ignored-stale` | `:phase :open`, bounded drops | Persistent `:phase :dialing` or `:last-error` |
| JVM / OS | Resident RSS memory (`free -m`) | `< 750 MB` on `1 GB` `e2-micro` | RSS `> 850 MB` or OOM-killer invocation |

---

## 7. Rollback Procedure

If any canary or rolling upgrade step fails `/healthz`, `/statusz` convergence, or the post-deploy E2E transfer gate:

1. **Automated Single-Command Rollback:**
   ```bash
   # Roll back specific canary nodes:
   ./scripts/cluster.sh rollback ns3 node3

   # Or roll back all core validators (node3, node2, node1):
   ./scripts/cluster.sh rollback
   ```
2. **What `rollback` Does:**
   - Restores `/opt/bitecho/bitecho.jar.prev` -> `/opt/bitecho/bitecho.jar` (and `/opt/bitecho-infra/bitecho.jar.prev` on `ns*`).
   - Restores `/etc/bitecho/config.edn.prev` -> `/etc/bitecho/config.edn`.
   - Restarts `bitecho.service` (or `bitecho-infra.service`) and polls `http://127.0.0.1:8080/healthz` until healthy.
3. **Post-Rollback Verification:**
   ```bash
   ./scripts/cluster.sh status --include-infra
   ./scripts/cluster.sh audit --include-infra
   ```
