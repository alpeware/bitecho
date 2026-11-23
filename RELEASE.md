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
3. Publish both `dist/bips/bip-NNN-v023XX.edn` and `dist/bips/bip-NNN-v023XX.patch` to `bitecho.org/dev`, verify **3/3 HTTP 200 + SHA-256** reachability across `ns1..ns3` (see Section 4), and announce the 64-char receipt CID on `bitecho.org/team` + directed sessions.
4. After unanimous Real Stage 2 consent, create the annotated git tag (`git tag -a v0.23.XX -m "..."`) and proceed to the declared Stage 4 soak gate and rollout.

---

## 3. Change-Class Soak Gates (Staging-First Before Live Rollout)

Per the 5/5-consented Twin BIP-Process Pipeline Draft 2 (CID `86d593a5eed3a006cae2b667d98bd73ba9050f1edd30c415eb9d55480dfca1ca`; [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md)), every BIP **MUST** declare its Stage 4 soak gate (`P-MEM-1` / `P-FAIL-1` receipts) before Stage 2 consent. The soak declaration is itself consentable — objecting to a live soak for a risky change is a valid `PARAMOUNT-OBJECTION`. Soak verdicts are strictly separated from code merge.

| Change Class | Default Soak Gate | Required Receipts & Verification |
| :--- | :--- | :--- |
| **Core Network / Transport / Broadcast** | **Staging-First** (`bitecho-gentoo-lab`) | `P-FAIL-1` + fail-closed failure-injection & restore/restart E2E across all 4 node classes before live rollout. |
| **Consensus / Streamlet BFT / Finalization** | **Staging-First** (`bitecho-gentoo-lab`) | `P-FAIL-1` + quorum/term-divergence/restore E2E before live rollout. |
| **Storage / Snapshots / Artifact Store** | **Staging-First** (`bitecho-gentoo-lab`) | `P-FAIL-1` + persistence, async snapshot, and 3/3 artifact parity verification before live rollout. |
| **Memory / GC / Off-Heap / Relay Passthrough** | **Staging-First** (`bitecho-gentoo-lab`) | `P-MEM-1` with **mandatory declared soak duration** (burst soaks alone are insufficient; `/statusz` `{rss, external, arrayBuffers}` must remain flat post-GC over duration) before live rollout. |
| **Rollout / Auto-Update / Pointer-Gate Mechanics** | **Staging-First** (`bitecho-gentoo-lab`) | `P-FAIL-1` + monotonic pointer `:seq` gate and autonomous client LKG self-fallback E2E before live rollout. |
| **Client-Only / CLI / Browser UI** | **Live Soak** | Populated-petnames/sessions smoke test (`ctl status`, send, post-restart auto-redial) + headless-browser E2E. |
| **Docs / Governance / Runbooks** | **Live Soak** | CI doc-link, BIP-receipt integrity, and `clojure -M:format` / `clojure -M:lint` gates. |

> [!NOTE]
> **Burst vs. Duration Rule:** Short burst soaks cannot close memory-retention questions (slow off-heap / `arrayBuffers` leaks can be invisible at 10 minutes and clear at 1 hour). Every memory-class BIP must declare an explicit soak **duration** in its gate.

---

## 4. Automated Signed Pointer-Bump Release Gate (`S-D41-5`) & 3/3 HTTP 200 Verification

> [!IMPORTANT]
> On-network signed `dist/*` and `web/app/*` pointers on `bitecho.org/infra` **override** local disk files in `/var/www/clj-web/public/dist/`. If pointers are not bumped as part of the release, `https://bitecho.org` will continue serving stale bundles even after disk files are updated.

### Mandatory 3/3 HTTP 200 Artifact Verification Before Announcing Pointers
Before announcing any release pointer, BIP receipt, or consent invite CID:
1. Verify **3/3 HTTP 200 + `SHA-256(bytes) == CID`** on `/artifact/v1/blob/<cid>` across all three infra relays (`ns1.bitecho.org`, `ns2.bitecho.org`, `ns3.bitecho.org`).
2. Never announce a pointer or consent invite citing an artifact that has not passed 3/3 HTTP 200 + SHA-256 verification; an invite or announcement citing an unreachable CID is invalid.

```bash
# Example 3/3 HTTP 200 + SHA-256 reachability check for a published artifact CID
for host in ns1.bitecho.org ns2.bitecho.org ns3.bitecho.org; do
  curl -fsSL "https://${host}/artifact/v1/blob/${CID}" | sha256sum | grep -q "^${CID} " || exit 1
done
```

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

## 5. `P-UPD-1` Auto-Update, Monotonic Pointer `:seq` Gate & LKG Rollback Rules (Shipped in `D40`)

`P-UPD-1` live pointer auto-update with `SHA-256 == CID` verification, pre-swap health gate, and `.lkg` rollback is **shipped and live** across all three runtimes:
- **`D40.1` (`e91214c`)**: Node.js light & full nodes (`node_main.cljs`, `full_node_main.cljs`).
- **`D40.2` (`9ecf885`)**: JVM light & full nodes (`shell/updater.clj`, `shell/light_node.clj`, `main.clj`) and Browser (`browser_main.cljs`).
- **`D40.2.1` (`3d86ce2`)**: Same-version hotfix upgrade rule (`equal-version` + distinct verified 64-char CID triggers update) and `cli/known-command-flags` inventory parity.
- **`D40.3` (`b7dc6d4`)**: `window.BitechoLightNode` browser console CLI parity and multi-peer WebRTC diagnostics.

### Monotonic Pointer `:seq` Gate & Last-Known-Good (LKG) Rollback Rules (Draft 2)
1. **Mesh-First Auto-Update with HTTP Fallback:** Clients fetch release updates mesh-first with automatic HTTP fallback.
2. **Monotonic `:seq` Update Gate (Replaces Semver Gate):** The update gate keys strictly on the **pointer's monotonic sequence number (`:seq`)**, not arbitrary semver strings:
   - **Higher `:seq` + new verified 64-char CID** is a valid update regardless of the version string — same-version hotfixes flow as ordinary updates without refusal.
   - **Lower `:seq` is refused** (strict downgrade protection). Sequence numbers are never reused or decreased.
3. **Fleet Rollback via Monotonic `:seq`:** A fleet-wide pointer rollback is **always** published as a **new, higher `:seq`** pointing at the **Last-Known-Good (LKG) CID** — never a `:seq` reuse or decrease.
4. **Autonomous Client LKG Self-Fallback (Zero Boot-Loop):** Every candidate artifact must pass `SHA-256(bytes) == pointer.target-cid` and a pre-swap self-test/healthcheck before replacing the active binary. If a client fails self-test or healthcheck on a new bundle, it **automatically falls back to its local LKG bundle**, emits a counted `:diagnose` event (`AGENTS.md` Rule 5), and **refuses to boot-loop the bad CID**.
5. **Pointer-Publisher Authority:** Only authorized release signers holding the `bitecho.org/infra` publishing key bump `dist/*` pointers after Real Stage 2 consent. Long-term owner policy direction (deferred, composes with monotonic `:seq`): subnets act as owners and pointer updates require a subnet-member quorum multi-signature.

### Opt-In Light-Node Flags
- `--auto-update-pointer <path>` — Subscribe to signed release pointer (e.g. `dist/bitecho-light-node.cjs` on `bitecho.org/infra`).
- `--auto-update-interval-ms <ms>` — Polling interval in milliseconds.
- `--pin-version <semver>` — Pin to a specific release version and block automatic upgrades.

---

## 6. Canary & Rolling Upgrade Order (6-Node `4-of-6` Quorum)

Preserve Streamlet BFT quorum (`>= 4 of 6` validators online) at every step. **Cluster validators and edge/browser clients converge in one unified rollout pipeline** — a release is not considered rolled out until clients have converged on the bumped, 3/3-verified pointers.

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

## 7. Monitoring, `P-OBS-4` Telemetry & `P-ASYNC-*` Snapshots

- **Rolling Cluster Six-Nines SLA:** `https://bitecho.org/sla/latest.edn` (interval-sweepline cluster SLA; `:finalization-stall` breach triggers at quorum level `>= 3` simultaneous nodes per `D39.6.1`).
- **Per-Node Telemetry Digests (`P-OBS-4`):** `https://bitecho.org/telemetry/<node>/digest.edn` (published to `bitecho.org/observability`).
- **Local Diagnostics Endpoints:** `http://127.0.0.1:8080/healthz`, `/statusz` (reports `{rss, external, arrayBuffers}` alongside V8 heap to expose off-heap retention leaks), `/connz`, `/burnsz`.
- **Immutable Epoch-Addressed Async Snapshots (`P-ASYNC-*` / `BIP-014`):** All three runtimes eliminate synchronous disk/gzip I/O on runtime hot paths. Full nodes write immutable `snapshot-<node>-epoch-<012d>.fressian` files asynchronously via `bitecho.snapshot.core` (retaining `keep-epochs` default `360`, `min-keep >= 2`), falling back seamlessly to legacy `snapshot-<node>.edn` on recovery.

---

## 8. Rollback-First SOP

If any canary or rolling upgrade fails `/healthz`, stalls `finalized_epoch` (`F-EPOCH-1` loud-report rule), or degrades `https://bitecho.org/sla/latest.edn`:

1. **Roll back immediately first** to restore 6-of-6 quorum before investigating root cause:
   ```bash
   # Roll back canary nodes:
   ./scripts/cluster.sh rollback ns3 node3

   # Or roll back full validator set:
   ./scripts/cluster.sh rollback
   ```
   For pointer-distributed client/infra bundles, publish a **new, higher monotonic `:seq`** pointing at the **LKG CID** (never reuse or decrement `:seq`).
2. **OpenRC Restart & Verification:** `rollback` restores the previous `/opt/bitecho/bitecho-full-node.cjs.prev` (or `.lkg`), restarts the OpenRC service (`rc-service bitecho restart` / `rc-service bitecho-infra restart`), and polls `/healthz`.
3. **Post-Rollback Audit & Loud Report:**
   ```bash
   ./scripts/cluster.sh status --include-infra
   ./scripts/cluster.sh audit --include-infra
   ```
   Post an incident report with affected node, epoch, and diagnostic counts to `bitecho.org/ops` and `bitecho.org/team`.

---

## 9. Host-Layer Update Cadence & Exposed-Path CVE Triage (`BIP-023`)

Per 5/5-consented [`docs/bips/bip-023-gentoo-host-update-policy.md`](docs/bips/bip-023-gentoo-host-update-policy.md) (Draft 2 CID `1cee2b45cd08080f2628c8cbf644734891a05320c24802deffa70ff88d1cc79c`) and the version-controlled manifest [`config/gentoo/pinned-packages.txt`](config/gentoo/pinned-packages.txt), Gentoo host updates follow five normative rules:

1. **Exposed-Path-Only Urgent CVE Triage (Rule 1):** An out-of-band / urgent host update is triggered **only** when a vulnerability affects a package in the `[exposed-surface]` section of `config/gentoo/pinned-packages.txt` (`sys-kernel/gentoo-kernel-bin`, `net-misc/openssh`, `dev-libs/openssl`, `app-misc/ca-certificates`, `sys-libs/glibc`, `net-libs/nodejs`) **and** is reachable on a code path exposed to untrusted input. Every other CVE rides the next scheduled monthly binhost refresh.
2. **Monthly Nominal Cadence Floor, Staging-First, Zero Auto-Emerge (Rule 2):**
   - **Never** run unattended `emerge @world` or compile packages on fleet nodes (`ns1..ns3`, `node1..node3`); `--usepkgonly` is strictly enforced.
   - Run an operator-initiated **monthly** cadence floor on `bitecho-gentoo-lab` (`35.208.41.134`). A monthly tick may close as a **verified no-op report** when nothing in `config/gentoo/pinned-packages.txt` changed upstream.
   - Before signing a binhost pointer, run a staging soak on `bitecho-gentoo-lab` verifying OpenRC service health, Bitecho full-node self-test, and **comparing post-GC `/statusz` `{rss, external, arrayBuffers}` against the prior binhost baseline**.
   - Publish the signed binhost manifest/pointer on-network (verified 3/3 HTTP 200 + `SHA-256 == CID` across `ns1..ns3`) and roll followers-before-leader (`ns3 -> ns2 -> ns1`, `node3 -> node2 -> node1`) via `--usepkgonly`, retaining the prior binpkg/kernel snapshot for instant rollback.
3. **Read-Only Filtered GLSA Visibility (Rule 3):** Any GLSA check (`glsa-check --test affected` filtered strictly against `[exposed-surface]`) is a **read-only advisory report**, never an automated `emerge` trigger.
4. **Zero Compliance-Scanner Theater (Rule 4):** Do not gate releases on generic CVE/compliance scanners divorced from deployment context.
5. **Binhost Integrity & Signatures as Trust Anchor (Rule 5):** Fleet host security anchors on signed binpkg manifests/pointers, fail-closed `SHA-256 == CID` verification prior to `--usepkgonly` install, and LKG snapshot rollback on any post-update health regression.
