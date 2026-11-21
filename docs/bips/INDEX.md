# Bitecho Improvement Proposals Index (`docs/bips/INDEX.md`)

Complete registry of committed Bitecho Improvement Proposals (**BIP-000** through **BIP-016**) with status, target version/milestone, and full 64-character SHA-256 CIDs (`P-DOCS-3` / `S-D41-3`).

> [!NOTE]
> BIP-002 through BIP-005 were pre-D32 on-network / inline milestone proposals (Tokenomics/Publishing/Unification III documented in [`../SPEC.md`](../SPEC.md) and [`../releases/`](../releases/)). Starting at BIP-006 (`D32`), every BIP EDN receipt is co-committed in `docs/bips/`.

| BIP | Milestone / Version | Status | File | Full 64-Char SHA-256 CID |
| :--- | :--- | :--- | :--- | :--- |
| **BIP-000** | D26 / Charter | `:ratified` | [`bip-000-charter.edn`](bip-000-charter.edn) | `99ba8e258a64bd9189999ab598efbccec6aadeb5bc107c10319ae916bde2ffea` |
| **BIP-001** | D26 / `v0.23.4` | `:activated` | [`bip-001-v0234.edn`](bip-001-v0234.edn) | `f5fa39030b9b8fe08b46941916b37b979848bb40e1d17611eb0bce19e4201d2b` |
| **BIP-006** | D32 / `v0.23.10` | `:consented` | [`bip-006-v02310.edn`](bip-006-v02310.edn) | `4f5a5e4dc1a3202b9203fddb5a92140bafd6e0f1e36e5b31d0add60f1e233ba4` |
| **BIP-007** | D33 / `v0.23.11` | `:consented` | [`bip-007-v02311.edn`](bip-007-v02311.edn) | `2510fb2a08cc74451f377ec5deaed567dc0c909e1ac35e177a38cc869a8f5d5f` |
| **BIP-008** | D34 / `v0.23.12` | `:consented` | [`bip-008-v02312.edn`](bip-008-v02312.edn) | `38e45426ab44753dedddf89717c332485be2abc958566fb728637c88f3c2b802` |
| **BIP-009** | D35 / `v0.23.13` | `:consented` | [`bip-009-v02313.edn`](bip-009-v02313.edn) | `bfcf28f8da5d1fece02358c7017e5ce1bb13bab14b927eebc952e8b6eb95cec7` |
| **BIP-010** | D36 / `v0.23.14` | `:consented` | [`bip-010-v02314.edn`](bip-010-v02314.edn) | `b79cab71b259e22ec34127b077ebc9de86d19acc25eed2f2bb61c20dd35fae29` |
| **BIP-011** | D37 / `v0.23.15` | `:consented` | [`bip-011-v02315.edn`](bip-011-v02315.edn) | `296c50ee27853a3d4d4acb3d18b30eac122109f4642a1f4cc5fed083f66c3887` |
| **BIP-012** | P-HOST-3 / Feasibility | `:verified-feasible` | [`bip-012-gentoo-stage3-feasibility.edn`](bip-012-gentoo-stage3-feasibility.edn) ([Report](bip-012-gentoo-stage3-feasibility-report.md)) | `74de38ac6c9e33c0f5af1cdbf6e0ac09d88a7c18d40ab8a81a5c12008a671cca` |
| **BIP-013** | D38 / `v0.23.16` | `:consented` | [`bip-013-v02316.edn`](bip-013-v02316.edn) | `afc1c22e1f914fbea70c3844fe7fad7a972092d0173a9d2e583617bcffecff97` |
| **BIP-014** | D39 / `v0.23.17` | `:consented` | [`bip-014-v02317.edn`](bip-014-v02317.edn) | `179599773e977bfbf0c13509aa31ee4934bdb308908b0d1b7b5982c98441aa8e` |
| **BIP-015** | D41 / `v0.23.18` | `:stage-1-consented` | [`bip-015-D41.edn`](bip-015-D41.edn) | `bb2747ade85584de02e9d596b013ded0ffe5f58abe81e9e35987a5c762cc8fce` |
| **BIP-016** | D42 / `v0.23.18` | `:consented` | [`bip-016-v02318.edn`](bip-016-v02318.edn) | `6f1c3ecf909ac46b6bde098722adeef96828967324dcdfeec66ae754964da83a` |

## Verification

This index is automatically verified against all committed `docs/bips/*.edn` files and their exact SHA-256 digests by `bitecho.d41-bip015-governance-and-docs-test/test-s-d41-3-docs-links-staleness-and-bip-index` (Rule 6).
