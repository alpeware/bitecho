---
name: bitecho-fleet-ops
description: >-
  Runbook for operating, inspecting, and rolling upgrades on the Bitecho devnet
  fleet (ns1..ns3 infra relays, node1..node3 validators), publishing web/app/release
  manifests with fail-closed SRI checks, and listening for light-node events.
  Use when SSHing into fleet nodes, rolling bundles, inspecting /statusz or logs,
  or publishing releases.
---

# Bitecho Fleet & Release Operations

## SSH Access & Paths
* **Infra relays (`ns1..ns3.bitecho.org`):**
  * User: `cljweb` | Key: `../clj-web/.ssh/clj_web_ed25519`
  * Host OS: Gentoo / OpenRC (no `sudo` binary)
  * State dir: `/var/lib/clj-web` | Blobs: `/var/lib/clj-web/blobs/<2>/<cid>`
  * Logs: `/var/log/bitecho-infra/stderr.log`, `/var/log/bitecho-infra/stdout.log`
  * Config: `/etc/bitecho-infra/config.edn` | Init: `/etc/init.d/bitecho-infra`
* **Validators (`node1..node3`):**
  * User: `bitecho` | Key: `.ssh/bitecho_cluster_ed25519`
* **Staging lab (`bitecho-gentoo-lab`, `35.208.41.134`):**
  * `ssh -i ~/.ssh/google_compute_engine -o IdentitiesOnly=yes simonpure@35.208.41.134`
  * Spec: `e2-micro` (`940 MiB` RAM), Gentoo `6.18.63-gentoo-dist-bin`, Node `v26.13.1` (exact OS/runtime match with `ns1..ns3`; ideal for 1-node staging/profiling).
  * **Safety constraint:** Never delete `bitecho-gentoo-lab`.

## Rolling Upgrades & Release Verification
1. Roll followers before leader: `ns3 -> ns2 -> ns1`, and `node3 -> node2 -> node1`.
2. Verify `/statusz` (`role`, `finalized_epoch`, `diagnostics-counts`) and identical bundle SHA-256 across all 6 nodes.
3. For `web/app/release` updates (BIP-017b fail-closed SRI):
   * Every `.js` and `.mjs` asset must carry an `:sri` field.
   * Update `legacy.html` CID whenever `bitecho-browser.js` changes.

## Local Light-Node Event Listener
* Always use standalone `wait-event` (not `ctl wait-event`, which hits a 15s control-socket timeout) and pass `--events-out /tmp/antigravity-light-node/stdout.jsonl` (matching the daemon's `--events-out`):
  `node dist/bitecho-light-node.cjs light-node wait-event --state-dir /tmp/antigravity-light-node --events-out /tmp/antigravity-light-node/stdout.jsonl --timeout-ms 3600000 --since-ms $(date +%s%3N)`
