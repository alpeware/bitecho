# Bitecho Sociocratic Governance & BIP Integrity (`docs/GOVERNANCE.md`)

This document formalizes Bitecho's two-gate Sociocratic consent process, BIP receipt integrity rules, release-gate ordering, and operational escalation SOPs established under **BIP-000** (Constitutional Charter) and **BIP-015** (Milestone `D41`).

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

## 2. Two-Gate Consent Flow & Consent-Then-Roll (`BIP-014 PF-2`)

Bitecho enforces a strict two-gate Sociocratic flow. **Code is never tagged or rolled across the 6-node cluster prior to unanimous Stage 2 consent.**

### Gate 1 — Stage 1 (Draft Consent)
1. Author publishes the Stage 1 draft to `bitecho.org/dev` at `dist/bips/bip-NNN-DRAFT.edn` and announces its **full 64-char SHA-256 CID** on `bitecho.org/team`.
2. All circle members review the pillars, invariants, scenarios, and rollback path and record their direct verdict.
3. Unanimous consent on the exact Stage 1 CID is required before implementation begins.

### Gate 2 — Stage 2 (Post-Implementation Consent-Then-Roll)
1. After implementation passes all local CI gates (`clojure -M:format`, `clojure -M:lint`, unit + `clojure.test.check` generative suites, and reproducible bundle builds), the builder publishes:
   - The **8-gate Stage 2 receipt**: `dist/bips/bip-NNN-v023XX.edn` on `bitecho.org/dev`
   - The **self-contained git patch**: `dist/bips/bip-NNN-v023XX.patch` on `bitecho.org/dev` (with non-nil 64-char `:patch-cid` and positive `:patch-size-bytes` in `:code-artifact`)
2. Unanimous circle consent on the exact Stage 2 receipt CID is recorded **before** creating the annotated git tag (`v0.23.XX`) or rolling the release across the cluster.

### Pre-Approved Guidance Exceptions (`D39.6 F-2`)
When an urgent operational fix or hotfix implements explicit pre-approved guidance (for example, an explicit SLA or quorum definition from the Human Anchor) without a separate Stage 1 BIP:
- The exception **MUST** be recorded explicitly in the milestone commit message and the next BIP receipt (`:pre-approved-guidance-exceptions`), citing the directive timestamp, author, and scope so the BIP-first rule is never silently eroded.

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

## 4. Operational Safety Rules

1. **Loud-Report Rule (`F-EPOCH-1`):** A stalled `finalized_epoch`, quorum divergence, or unexpected node restart is **never** silently ignored or masked. Every stall or fault emits a counted `:diagnose` effect (Rule 5) and triggers an immediate loud report to `bitecho.org/ops` and `bitecho.org/team`.
2. **Rollback-First SOP:** When a canary or rolling deploy triggers `/healthz` failure, `finalized_epoch` stall, or six-nines SLA degradation, operators execute rollback (`./scripts/cluster.sh rollback` or `.lkg` pointer rollback) **first** to restore 6-of-6 quorum health before performing root-cause forensics.
3. **Co-Committed Spec, Docs, Ops & Flag Inventory (`AGENTS.md` Rule 6):** Behavioral or CLI changes must update `docs/SPEC.md`, `skill/SKILL.md`, `RELEASE.md`, `ONBOARDING.md`, ops scripts, and automated inventory tests in the same commit.
