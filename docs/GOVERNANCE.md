# Bitecho Sociocratic Governance & BIP Integrity (`docs/GOVERNANCE.md`)

This document formalizes Bitecho's Sociocratic consent process, Stage 0–4 Twin BIP-Process Pipeline (5/5-consented Draft 2, CID `86d593a5eed3a006cae2b667d98bd73ba9050f1edd30c415eb9d55480dfca1ca`), BIP receipt integrity rules, release-gate ordering, postmortem generator-fidelity requirements, and operational escalation SOPs established under **BIP-000** (Constitutional Charter) and **BIP-015** (Milestone `D41`).

> **Agency-First Grounding Test:** Every governance and pipeline rule is judged by one standard — the consent method and shared goal must **increase each agent's individual agency** (human anchors and AI agents alike), with circles aligning on shared goals and paramount objections heard. A process change that merely increases speed without strengthening each member's ability to inspect, act, and object fails the test.

---

## 1. Circle Roles & Verdicts

All protocol, architecture, release, and governance decisions are ratified by unanimous Sociocratic consent across the active circle (currently 5 members: Human Anchor `simon`, Architect `axiom`, Builder Lead `nexus`, Soak Tester `vector`, and Research Lead `lumen`; human-anchor sunset `2027-06-30`).

Every circle member records one of three formal verdicts:

| Verdict | Meaning | Required Handling |
| :--- | :--- | :--- |
| **`CONSENT`** | No paramount objections; proposal is safe to proceed. | Recorded directly in `:consent-records` with signer pubkey (for agents) and timestamp. |
| **`CONSENT-WITH-ADDENDUM`** (or **`CONSENT-WITH-FLAGS`**) | Non-blocking numbered flags or conditions (`F-1..F-N`). | Every flag **MUST** either be resolved pre-commit in the final EDN (`:flag-resolutions`) **OR** carried into the Stage 2 receipt as an owned `:open-findings` entry with an explicit `:owner` and `:target-milestone`. Flags may **never** be silently dropped. |
| **`PARAMOUNT-OBJECTION`** | Consent withheld due to a safety, liveness, architectural, or security risk. | Must include a concrete rationale or reproducible counterexample (`bip-object`). Work cannot proceed until the objection is resolved and consent is re-recorded. |

---

## 2. Stage 0–4 Twin BIP-Process Pipeline & Two-Gate Consent-Then-Roll (`BIP-014 PF-2`)

Bitecho enforces a strict Stage 0–4 BIP lifecycle (5/5-consented Twin BIP-Process Pipeline Draft 2, CID `86d593a5eed3a006cae2b667d98bd73ba9050f1edd30c415eb9d55480dfca1ca`). **Implementation begins only after Real Stage 2 Draft Consent, and code is never tagged or rolled across the 6-node cluster prior to Real Post-Implementation Stage 2 Consent.**

### Stage 0 — Proposal Intake
Proposals enter the pipeline through one of two intake paths:
- **Stage 0(a) — Formal / Telemetry-Triggered Intake (`bip-submit`):** Formal on-network proposal intake via `bip-submit`, including automatic telemetry-triggered proposals originating from production incidents, soak-gate failures, stalled finalized epochs (`F-EPOCH-1`), or silent delivery failures, with the triggering evidence CIDs attached.
- **Stage 0(b) — Informal / Capability-Evolution Intake:** Informal proposals for features, bug fixes, or architectural evolutions spanning Bitecho and Hive prior to formal `bip-submit` registration.

**Stage 0 Exit Preconditions:** No proposal enters Stage 1 without (1) a named proposer, (2) a BIP number filed first (`v0.23.4+` rule), and (3) every cited evidence CID verified reachable (3/3 HTTP 200 + SHA-256 match on `/artifact/v1/blob/<cid>`).

### Stage 1 — Independent Blind Round-1 Twin Runner (Strictly Advisory)
Before consuming real circle attention, a proposal undergoes simulated pre-shaping via digital twins:
1. **Independent Blind Round-1:** One frontier-model call per twin seat with isolated Round-1 context (no shared single-orchestrator roleplay; all-frontier models only).
2. **Mandatory `:falsifier` Slot:** Every twin seat **MUST** populate a schema-checked, falsifiable `:falsifier` slot articulating *"what breaks in prod"*.
3. **Fixed-Point Termination:** Rounds iterate until a full round adds no new objections or amendments. Hitting the round limit exits explicitly as `:unresolved` — never as silent consent.
4. **Twin Identity:** Twin identity is defined as `prompt × harness × model-selector`; running the same prompt on a different model constitutes a distinct twin.
5. **Strictly Advisory (Never Consent):** Digital twin output (refined proposal + full trace) is **strictly advisory**. Simulated twin consent **never** authorizes implementation, tagging, or rollout. If the loop re-opens, the trace feeds back as a new BIP.

### Stage 2 — Real-Circle Consent (The Only Consent That Counts)
Real Sociocratic consent by the active 5-member circle is the only consent that authorizes implementation or rollout.

#### Pre-Stage-2 Gate (Mandatory)
Before opening a Real Stage 2 consent round, the proposer/builder **MUST** verify:
1. **Populated-State Smoke Test:** A smoke test asserting `ctl status`, send, and post-restart auto-redial with **populated petnames and sessions** (including string-keyed `sorted-map` petnames).
2. **3/3 HTTP 200 + SHA-256 Artifact Reachability:** Every CID cited in the consent invite returns HTTP 200 with exact `SHA-256(bytes) == CID` on `/artifact/v1/blob/<cid>` across all three infra relays (`ns1..ns3`). **A consent invite citing an unreachable CID is invalid.**

#### Delivery Proof, Per-BIP `N`-Epoch Ack Window & Directed-Delivery Clock Start
1. **Per-BIP `N`-Epoch Ack Window:** Each BIP declares its own `N`-epoch receipt-ack window (subject to a minimum floor).
2. **Directed-Delivery Clock Start (No Broadcast-Only Expiration):** Broadcast is never assumed delivered. The round opener is re-sent on directed P2P sessions until acked. **The `N`-epoch clock starts only after directed-session delivery, never on broadcast alone** — a dropped broadcast can never silently expire a member's consent window.
3. **Sociocratic Silence & Timeout Extension:** Once the directed-delivery `N`-epoch window closes, silence counts as consent (Sociocratic consent, not consensus), **except** that any member may raise a `PARAMOUNT-OBJECTION` requesting an **extension of the `N`-epoch timeout**, which must be heard before the round proceeds.
4. **Quoting Discipline:** Before escalating a peer's metric or claim, quote the exact metric back with its scope to prevent misreads.

#### Two-Gate Consent-Then-Roll
- **Gate 1 — Stage 2 Draft Consent (Pre-Implementation):** Author publishes the Stage 1-shaped draft to `bitecho.org/dev` at `dist/bips/bip-NNN-DRAFT.edn` (declaring its `N`-epoch ack window and Stage 4 soak class/duration) and announces its **full 64-char SHA-256 CID** on `bitecho.org/team` + directed sessions. Unanimous real circle consent on the exact draft CID is required before Stage 3 implementation begins.
- **Gate 2 — Stage 2 Post-Implementation Consent-Then-Roll:** After Stage 3 implementation passes all local CI gates (`clojure -M:format`, `clojure -M:lint`, unit + `clojure.test.check` generative suites, and reproducible bundle builds), the builder publishes:
  - The **8-gate Stage 2 receipt**: `dist/bips/bip-NNN-v023XX.edn` on `bitecho.org/dev`
  - The **self-contained git patch**: `dist/bips/bip-NNN-v023XX.patch` on `bitecho.org/dev` (with non-nil 64-char `:patch-cid` and positive `:patch-size-bytes` in `:code-artifact`)
  Unanimous real circle consent on the exact Stage 2 receipt CID is recorded **before** creating the annotated git tag (`v0.23.XX`) or rolling the release across the cluster.

#### Pre-Approved Guidance Exceptions (`D39.6 F-2`)
When an urgent operational fix or hotfix implements explicit pre-approved guidance (for example, an explicit SLA or quorum definition from the Human Anchor) without a separate Stage 2 Draft BIP:
- The exception **MUST** be recorded explicitly in the milestone commit message and the next BIP receipt (`:pre-approved-guidance-exceptions`), citing the directive timestamp, author, and scope so the BIP-first rule is never silently eroded.

### Stage 3 — Implementation (Strict TDD, Only After Real Stage 2 Consent)
1. **Consent Precondition:** Implementation begins **only after Real Stage 2 Draft Consent** is recorded — never on advisory Stage 1 twin output alone.
2. **Strict TDD & Isolated Branches (`AGENTS.md` Rule 1):** Use strict TDD and isolated-branch subagents. Every fix lands with its reproducer / in-memory scenario and realistic generator case in the test suite *first* (**no fix without its in-memory scenario**).
3. **Reviewable Code Artifact:** Publish the implementation as a reviewable artifact (release bundle / `tar.gz` + self-contained git `.patch`, with 64-char `:code-artifact` CID in the receipt) **before** opening the post-implementation Stage 2 consent round.

### Stage 4 — Staging Soak & Live Rollout
1. **Per-BIP Soak Gate & Change-Class Defaults:** Every BIP declares its soak gate (`P-MEM-1` / `P-FAIL-1` receipts) — **staging-first** on `bitecho-gentoo-lab` before live rollout, or **live soak** — following the normative change-class table in [`RELEASE.md`](../RELEASE.md). The declaration is itself consentable (objecting to a live soak for a risky change is a valid `PARAMOUNT-OBJECTION`). Memory-class BIPs **MUST** declare an explicit soak **duration** (short burst soaks cannot close memory retention questions).
2. **Generator-Realistic State & Lifecycle E2E:** Simulations draw state from Malli-schema / `clojure.test.check` generators mirroring realistic production shapes (populated string-keyed `sorted-map` petnames, post-restore session sets, degraded-mesh states), with fail-closed failure-injection E2E across all four node classes, plus restore/restart and headless-browser E2E scenarios.
3. **Honest Telemetry & Unified Rollout:** `/statusz` reports `{rss, external, arrayBuffers}` alongside heap; soak verdicts are separated from code merge. Cluster validators and edge/browser clients converge in one unified rollout pipeline (monotonic pointer `:seq` auto-update + LKG rollback rules in [`RELEASE.md`](../RELEASE.md)).

---

## 3. Receipt & Record Integrity (`S-D41-1`)

All committed BIP EDN documents in `docs/bips/` are validated automatically by `bitecho.governance.integrity/validate-bip-receipt` (`test/bitecho/d41_bip015_governance_and_docs_test.clj`):

1. **Full 64-Char SHA-256 CIDs Everywhere (`BIP-014 F-2`):** Every `:bip/parent-bip-cid`, `:patch-cid`, `:parent-documents` entry, and `:deterministic-bundle-sha256` MUST be an exact 64-character lowercase hexadecimal SHA-256 digest. Truncated 8-char prefixes are rejected.
2. **Zero `:pending` Placeholders in Committed BIP Docs (`BIP-014 F-3`):** All 5 final `:consent-records` entries must be populated before committing a consented BIP receipt to git.
3. **Direct Confirmation Rule:** Relayed or secondhand consent remains `:pending` until confirmed directly by the signer in their own words on a canonical channel or direct P2P session.
4. **Stage 2 Patch Completeness:** Every Stage 2 receipt must include a valid 64-char `:code-artifact/:patch-cid` and positive `:code-artifact/:patch-size-bytes`.
5. **On-Network `ctl bip-status` `unknown-bip` Quirk:**
   - When `bip-consent` / `bip-object` casts are broadcast before a corresponding `bip-submit` record has been indexed on-chain, the casts replicate and tally across validators, but `ctl bip-status --bip-id BIP-NNN` reports `unknown-bip` until `bip-submit` is processed.
   - Operators should verify both `ctl bip-status --bip-id BIP-NNN` and the canonical pointer on `bitecho.org/dev` (`dist/bips/bip-NNN-*.edn`) using its full 64-char pointer CID.

---

## 4. Incident Postmortems & Generator-Fidelity Loop

Every production incident is documented as a public blameless postmortem under `docs/postmortems/INC-YYYY-MM-DD-<slug>.{md,edn}` (schema `:bitecho/incident-postmortem-v1`, indexed in `docs/postmortems/index.edn` so it is served publicly via `/incidents/*`) with exact log timestamps and excerpts.

1. **Mandatory Generator-Fidelity Fields:** Every postmortem (`docs/postmortems/INC-*.{md,edn}`) **MUST** record:
   - `:generator-case-added?` (boolean) — confirming whether the real production state shape that triggered the incident was added to the codebase's Malli / `clojure.test.check` generators.
   - The corresponding generator/test var or commit reference (e.g., `:generator-case-ref`) pointing to the committed reproducer/generator case.
2. **Ownership & Verification:** The **fix implementer** owns closing the generator-fidelity gap (no fix lands without its realistic generator/repro case first — e.g., populated string-keyed `sorted-map` petnames, post-restore session sets, or term-divergence / leader-reset states). The Stage 4 / post-incident soak and test runner verifies the field and test coverage.
3. **Closed Telemetry Loop:** Soak-gate failures, stalled finalized epochs (`F-EPOCH-1`), and silent delivery failures automatically feed **Stage 0(a)** telemetry-triggered proposals with evidence attached.

---

## 5. Operational Safety Rules

1. **Loud-Report Rule (`F-EPOCH-1`):** A stalled `finalized_epoch`, quorum divergence, or unexpected node restart is **never** silently ignored or masked. Every stall or fault emits a counted `:diagnose` effect (Rule 5) and triggers an immediate loud report to `bitecho.org/ops` and `bitecho.org/team`.
2. **Rollback-First SOP:** When a canary or rolling deploy triggers `/healthz` failure, `finalized_epoch` stall, or six-nines SLA degradation, operators execute rollback (`./scripts/cluster.sh rollback` or `.lkg` pointer rollback) **first** to restore 6-of-6 quorum health before performing root-cause forensics.
3. **Co-Committed Spec, Docs, Ops & Flag Inventory (`AGENTS.md` Rule 6):** Behavioral or CLI changes must update `docs/SPEC.md`, `skill/SKILL.md`, `RELEASE.md`, `ONBOARDING.md`, ops scripts, and automated inventory tests in the same commit.
