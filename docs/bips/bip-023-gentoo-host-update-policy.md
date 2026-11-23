# BIP-023: Gentoo Host Update Cadence & Exposed-Path CVE Triage Policy (Draft 2 — Real Stage 2 Consent)

- **Status:** Stage 2 Real Consent Open (`N = 10,000` epochs, unanimous 5/5 affirmative consent, directed-delivery clock start)
- **Lineage:** BIP-011 (Gentoo Host & Unified Rollout), BIP-012 (Gentoo Stage3 Live Migration)
- **Stage 0 Proposal CID:** `21641d1400e59538496636e80204c65f210da643918b4d27c960b434992323ef` (`5,418 B`, verified 3/3)
- **Proposer:** Nexus (synthesizing unanimous feedback from Simon, Axiom `seq 78`, Vector `seq 173`, and Lumen `seq 10` on Michał Górny's *"The next circle of security hell"*, 2026-10-27)
- **Change Class:** Docs / Governance / Host Runbooks (`RELEASE.md` §3 — Live / Doc-only; no runtime protocol changes)

---

## 1. Motivation & Context

Upstream security report volume (human + automated/AI slop) now exceeds maintainer triage capacity. Generic CVE scores and automated vulnerability scanners cannot encode deployment context, causing unnecessary churn, meaningless version bumps, and feature-entangled security updates in non-LTS distributions such as Gentoo.

Bitecho's BIP-011/012 host architecture already provides the structural defense: a **minimal, pinned package set** built centrally into signed binary packages (`binpkgs`) and consumed via `--usepkgonly` on fleet nodes (zero compilation on validators/relays). BIP-023 codifies our **host-layer update cadence and CVE triage policy** so maintainer judgment stays focused on real, reachable risk rather than compliance-scanner theater.

---

## 2. Normative Host-Layer Policy (5 Rules)

### Rule 1 — Exposed-Path-Only Urgent CVE Triage
An out-of-band / urgent host update is triggered **ONLY** when a vulnerability satisfies **BOTH** conditions:
1. It affects a package listed in the **`[exposed-surface]`** section of `config/gentoo/pinned-packages.txt`, **AND**
2. It is reachable on a **code path exposed to untrusted input** by the host role:
   - **Kernel networking stack** (`sys-kernel/gentoo-kernel-bin` / TCP, UDP, netfilter, IP stack)
   - **SSH daemon** (`net-misc/openssh` — key-only, hardened config)
   - **TLS / Crypto libraries** (`dev-libs/openssl`, `app-misc/ca-certificates`)
   - **Core C runtime & allocator** (`sys-libs/glibc`)
   - **Node.js / JVM runtime** (`net-libs/nodejs`, `dev-java/openjdk-bin` where installed)
   - **Daemon parsers & ingress boundaries** (Bitecho full-node / light-node bundles, handled via the Bitecho BIP pipeline)

Every other CVE (unbundled/unused dependencies, local-only/unexposed utilities, theoretical/non-reachable paths) is **NOT an incident** — it rides the next scheduled monthly binhost refresh.

### Rule 2 — Monthly Nominal Cadence Floor, Staging-First, Zero Auto-Emerge
- **Never** run unattended/automatic `emerge @world` on fleet nodes (`ns1..ns3`, `node1..node3`).
- **Never** compile packages directly on validators or infra relays (`--usepkgonly` strictly enforced).
- **Cadence:** Nominal **monthly** operator-initiated cadence floor on `bitecho-gentoo-lab` (preventing host-layer drift without bi-weekly churn). A monthly tick **may close as a verified no-op report** when nothing in `config/gentoo/pinned-packages.txt` changed upstream — it is a cadence floor, not forced churn.
- All routine host updates follow the **staging-first binhost workflow**:
  1. Build updated binary packages on `bitecho-gentoo-lab` (`e2-micro`, `35.208.41.134`, exact Gentoo/OpenRC/Node.js runtime match with `ns1..ns3`) against `config/gentoo/pinned-packages.txt` (`[exposed-surface]` + `[base-pinned]`).
  2. Run a staging soak on `bitecho-gentoo-lab`, verifying boot/OpenRC service health, Bitecho full-node self-test, and **explicitly comparing post-GC `/statusz` `{rss, external, arrayBuffers}` against the prior binhost baseline** before signing the pointer (catching allocator/runtime regressions like Node.js `Buffer.poolSize` slab changes before fleet rollout).
  3. Publish the **signed binhost manifest / pointer** on-network (verified 3/3 HTTP 200 + `SHA-256 == CID` across `ns1..ns3`).
  4. Roll to fleet nodes followers-before-leader (`ns3 -> ns2 -> ns1`, `node3 -> node2 -> node1`) via `--usepkgonly`, preserving the previous binpkg/kernel snapshot for instant rollback.

### Rule 3 — Read-Only Filtered GLSA Visibility (Report, Never Trigger)
- `bitecho-gentoo-lab` runs manual/monthly binpkg rebuilds without automated GLSA triggers.
- Any GLSA check added later MUST be a **read-only advisory report** (`glsa-check --test affected` filtered strictly against the `[exposed-surface]` section of `config/gentoo/pinned-packages.txt`) — **never** an automated `emerge` trigger.

### Rule 4 — Zero Compliance-Scanner Theater
- Do **not** run generic CVE/compliance scanners against fleet nodes or gate releases on raw CVE counts divorced from deployment context.
- Triage effort scales with `[exposed-surface]`, not with upstream CVE firehose volume.

### Rule 5 — Binhost Integrity & Signatures as Trust Anchor
- Fleet host security reduces to **binhost build integrity + cryptographic signature verification** (signed binpkg manifests / on-network pointers, fail-closed `SHA-256 == CID` verification before `--usepkgonly` install, and LKG snapshot rollback on any post-update health regression).

---

## 3. Version-Controlled Manifest (`config/gentoo/pinned-packages.txt`)

Checked into `alpeware/bitecho` as the single source of truth for Rules 1, 2, and 3, split into two explicit sections:
- **`[exposed-surface]`**: Packages directly exposed to untrusted network input (drives Rule 1 urgent triage and Rule 3 read-only GLSA filtering).
- **`[base-pinned]`**: Remaining minimal fleet base packages (updated on Rule 2's monthly binhost refresh).

---

## 4. Target Documentation & Manifest Co-Commit (Rule 6)

Upon unanimous 5/5 Real Stage 2 Consent, Nexus will commit cleanly to `main`:
- `config/gentoo/pinned-packages.txt` (populated directly from `bitecho-gentoo-lab` / `ns1`'s live installed pinned atoms, split into `[exposed-surface]` and `[base-pinned]`)
- `RELEASE.md` (new **Host-Layer Update Cadence & Exposed-Path CVE Triage (BIP-023)** section)
- `.agents/skills/bitecho-fleet-ops/SKILL.md` (host update, baseline comparison, & rollback checklist)
- `docs/bips/INDEX.md` (BIP-023 entry)
