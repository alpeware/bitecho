# Bitecho Release & Upgrade Runbook (`RELEASE.md`)

This runbook defines the authoritative release lifecycle for Bitecho `v0.23.17+` (`D41` / `BIP-015`) running on **Hardened Gentoo Linux + OpenRC `supervise-daemon` + Node.js bundles** across the 6-node (`4-of-6` Streamlet BFT quorum) fleet.

---

## 1. Fleet Architecture & Network Separation

| Component | Production Runtime | Supervision & Host | Notes |
| :--- | :--- | :--- | :--- |
| **Core Validators (`node1..node3`)** | Node.js `dist/bitecho-full-node.cjs` (`--max-old-space-size=384`) | Hardened Gentoo + OpenRC `supervise-daemon` (`/etc/init.d/bitecho`) | Part of unified 6-node BFT committee (`N=6`, quorum `4 of 6`). |
| **Infra Validators (`ns1..ns3`)** | Node.js `dist/bitecho-full-node.cjs` (`--max-old-space-size=384`) | Hardened Gentoo + OpenRC `supervise-daemon` (`/etc/init.d/bitecho-infra`) | Full BFT validators + HTTPS relay, DNS, static/pointer serving, and `P-OBS-4` telemetry rollups. |
| **Edge Light Nodes** | Node.js `dist/bitecho-light-node.cjs` / JVM `clojure -M:light-node` | Local agent host / user machine | Sovereign edge client with opt-in `P-UPD-1` auto-update. |
| **Browser Light Node** | `dist/bitecho-browser.js` (`:advanced` Closure bundle) | Web app (`https://bitecho.org`) | Includes `window.BitechoLightNode` console CLI parity (`D40.3`) and WebRTC ICE diagnostics (`D39`). |

Every Bitecho network is isolated by an explicit canonical `:network-uri` (`devnet.bitecho.org`, `testnet.bitecho.org`, `mainnet.bitecho.org`) bound inside Ed25519 signing payloads for transfers and escrows.

---

## 2. Two-Gate Consent-Then-Roll & 8-Gate BIP Receipt Workflow

Per [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md), **no release is tagged or rolled across the cluster until unanimous Stage 2 circle consent is recorded**.

### Pre-Release Local Gates
```bash
# 1. Code formatting & static analysis (AGENTS.md Rule 3 — 0 errors, 0 warnings)
clojure -M:format
clojure -M:lint

# 2. Full unit + generative clojure.test.check suite (AGENTS.md Rule 1)
clojure -M:test --skip-integration

# 3. Reproducible Node.js & Browser bundle builds (zero JAR/systemd/SEA dependencies)
./scripts/build-full-node-bundle.sh
./scripts/build-node-light-node.sh
./scripts/build-browser-bundle.sh
sha256sum dist/bitecho-full-node.cjs dist/bitecho-light-node.cjs dist/bitecho-browser.js

# 4. Pre-deploy E2E wire negotiation & Streamlet finalization gate
./scripts/cluster.sh verify-e2e
```

### Stage 2 Receipt & Self-Contained `.patch` Publication (`bitecho.org/dev`)
1. Generate the self-contained patch from the parent commit (`git diff <parent>..HEAD > dist/bips/bip-NNN-v023XX.patch`) and compute its exact 64-char SHA-256 `:patch-cid` and `:patch-size-bytes`.
2. Build the 8-gate Stage 2 receipt (`dist/bips/bip-NNN-v023XX.edn`) asserting:
   - Non-nil 64-char `:code-artifact/:patch-cid` and positive `:patch-size-bytes`.
   - Full 64-char SHA-256 CIDs everywhere (zero 8-char prefixes).
   - Zero `:pending` consent records before commit.
   - Explicit resolution of any `CONSENT-WITH-ADDENDUM` / `CONSENT-WITH-FLAGS` items (`:flag-resolutions` or owned `:open-findings`).
3. Publish both `dist/bips/bip-NNN-v023XX.edn` and `dist/bips/bip-NNN-v023XX.patch` to `bitecho.org/dev` and announce the 64-char receipt CID on `bitecho.org/team`.
4. After unanimous Stage 2 consent, create the annotated git tag (`git tag -a v0.23.XX -m "..."`) and proceed to canary rollout.

---

## 3. Automated Signed Pointer-Bump Release Gate (`S-D41-5`)

> [!IMPORTANT]
> On-network signed `dist/*` and `web/app/*` pointers on `bitecho.org/infra` **override** local disk files in `/var/www/clj-web/public/dist/`. If pointers are not bumped as part of the release, `https://bitecho.org` will continue serving stale bundles even after disk files are updated.

Run the automated pointer-bump and verification gate on every release:

```bash
# Dry-run precondition & SHA-256 check (verifies all built artifacts exist and hashes match)
./scripts/cluster.sh bump-pointers --version v0.23.18 --dry-run

# Live publish & verify signed dist/* and web/app/* pointers on bitecho.org/infra
./scripts/cluster.sh bump-pointers \
  --version v0.23.18 \
  --state-dir /tmp/antigravity-light-node \
  --relay-url https://ns1.bitecho.org/relay/v1

# Verify landing SHA == cluster version without republishing
./scripts/cluster.sh bump-pointers --version v0.23.18 --verify-only
```

The gate publishes and verifies monotonic `:seq` bumps and exact 64-char `:target-cid` matches for:
- `dist/bitecho-light-node.cjs`
- `dist/bitecho-browser.js`
- `dist/bitecho-full-node.cjs`
- `web/app/bitecho-browser.js`
- `web/app/index.html`

---

## 4. `P-UPD-1` Opt-In Auto-Update (Shipped in `D40`)

`P-UPD-1` live pointer auto-update with `SHA-256 == CID` verification, pre-swap health gate, and `.lkg` rollback is **shipped and live** across all three runtimes:
- **`D40.1` (`e91214c`)**: Node.js light & full nodes (`node_main.cljs`, `full_node_main.cljs`).
- **`D40.2` (`9ecf885`)**: JVM light & full nodes (`shell/updater.clj`, `shell/light_node.clj`, `main.clj`) and Browser (`browser_main.cljs`).
- **`D40.2.1` (`3d86ce2`)**: Same-version hotfix upgrade rule (`equal-version` + distinct verified 64-char CID triggers update) and `cli/known-command-flags` inventory parity.
- **`D40.3` (`b7dc6d4`)**: `window.BitechoLightNode` browser console CLI parity and multi-peer WebRTC diagnostics.

### Opt-In Light-Node Flags
- `--auto-update-pointer <path>` — Subscribe to signed release pointer (e.g. `dist/bitecho-light-node.cjs` on `bitecho.org/infra`).
- `--auto-update-interval-ms <ms>` — Polling interval in milliseconds.
- `--pin-version <semver>` — Pin to a specific release version and block automatic upgrades.

### Pointer-Bump Ownership
- Only authorized release signers holding the `bitecho.org/infra` publishing key bump `dist/*` pointers after Stage 2 consent.
- Every candidate artifact must pass `SHA-256(bytes) == pointer.target-cid` and a pre-swap health gate before replacing the active binary; failures automatically restore `.lkg` and emit a counted `:diagnose` event (Rule 5).

---

## 5. Canary & Rolling Upgrade Order (6-Node `4-of-6` Quorum)

Preserve Streamlet BFT quorum (`>= 4 of 6` validators online) at every step:

```text
ns3 (infra canary) -> node3 (validator canary) -> [E2E & SLA Gate] -> ns2 -> ns1 -> node2 -> node1
```

```bash
# Phase 1: Canary deploy (ns3 + node3)
./scripts/cluster.sh deploy --canary

# Phase 2: Rolling deploy (ns2 -> ns1 -> node2 -> node1)
./scripts/cluster.sh deploy --rolling

# Phase 3: Post-deploy convergence & six-nines SLA audit
./scripts/cluster.sh status --include-infra
./scripts/cluster.sh audit --include-infra
```

---

## 6. Monitoring, `P-OBS-4` Telemetry & `P-ASYNC-*` Snapshots

- **Rolling Cluster Six-Nines SLA:** `https://bitecho.org/sla/latest.edn` (interval-sweepline cluster SLA; `:finalization-stall` breach triggers at quorum level `>= 3` simultaneous nodes per `D39.6.1`).
- **Per-Node Telemetry Digests (`P-OBS-4`):** `https://bitecho.org/telemetry/<node>/digest.edn` (published to `bitecho.org/observability`).
- **Local Diagnostics Endpoints:** `http://127.0.0.1:8080/healthz`, `/statusz`, `/connz`, `/burnsz`.
- **Immutable Epoch-Addressed Async Snapshots (`P-ASYNC-*` / `BIP-014`):** All three runtimes eliminate synchronous disk/gzip I/O on runtime hot paths. Full nodes write immutable `snapshot-<node>-epoch-<012d>.fressian` files asynchronously via `bitecho.snapshot.core` (retaining `keep-epochs` default `360`, `min-keep >= 2`), falling back seamlessly to legacy `snapshot-<node>.edn` on recovery.

---

## 7. Rollback-First SOP

If any canary or rolling upgrade fails `/healthz`, stalls `finalized_epoch` (`F-EPOCH-1` loud-report rule), or degrades `https://bitecho.org/sla/latest.edn`:

1. **Roll back immediately first** to restore 6-of-6 quorum before investigating root cause:
   ```bash
   # Roll back canary nodes:
   ./scripts/cluster.sh rollback ns3 node3

   # Or roll back full validator set:
   ./scripts/cluster.sh rollback
   ```
2. **OpenRC Restart & Verification:** `rollback` restores the previous `/opt/bitecho/bitecho-full-node.cjs.prev` (or `.lkg`), restarts the OpenRC service (`rc-service bitecho restart` / `rc-service bitecho-infra restart`), and polls `/healthz`.
3. **Post-Rollback Audit & Loud Report:**
   ```bash
   ./scripts/cluster.sh status --include-infra
   ./scripts/cluster.sh audit --include-infra
   ```
   Post an incident report with affected node, epoch, and diagnostic counts to `bitecho.org/ops` and `bitecho.org/team`.
