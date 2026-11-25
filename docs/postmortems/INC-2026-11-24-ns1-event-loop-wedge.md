# INC-2026-11-24: `ns1` Overnight Event-Loop Wedge & Snapshot Bloat

- **Incident ID:** `INC-2026-11-24-ns1-event-loop-wedge`
- **Severity:** `sev-2`
- **Date:** 2026-11-24
- **Affected Node(s):** `ns1.bitecho.org` (`e2-micro`, 1 GB RAM, `pid 6629`); healthy edge peers `ns2.bitecho.org` and `ns3.bitecho.org` maintained consensus finality with zero halt.
- **Remediation BIP:** **BIP-025** (Core-State vs Value-Aware Local Cache Split, Async Coalesced Persistence, First-Class Latency Telemetry & `ns1` Full-Node Snapshot/GC Hardening)

## 1. Summary

Overnight on 2026-11-24, `ns1.bitecho.org` (`pid 6629`) experienced progressive RSS growth (`VmRSS` reaching `273.6 MiB`) and escalating Node.js event-loop freezes (`16.3s -> 42.5s`), wedging HTTP/relay responsiveness on `ns1` while `ns2` and `ns3` continued finalizing epochs normally. Forensic inspection simultaneously uncovered monolithic light-node `state.fressian` bloat (Vector `845.05 MiB` with `99.69%` duplicated `:blobs` + `:artifact-blobs`), unbounded JSONL event/stdout logs (`280.88 MiB` / `689 MiB`), and an observability blind spot where severe stalls remained hidden behind `sync.stalled: false`.

## 2. Root Causes (Blameless Technical Analysis)

1. **Unbounded / Under-Bounded Full-Node Snapshot Structures (`snapshot-ns1-epoch-000000100026.fressian` = `6.69 MB`):**
   - `:executed-root-depths` accumulated `12,029` entries because `streamlet.core/record-executed-root-depths` appended every finalized block hash without pruning in `state-machine/prune-expired-tick-state`.
   - `:expired-gossip-ids` and `:expired-gossip-order` grew to `5,846` entries each toward the oversized `10,000` shared receipt ceiling.
   - `:epoch-to-message-roles` leaked `1,189` orphaned epoch entries because `expired-epochs` was derived solely from `(keys epoch-to-messages)`.
2. **Stop-the-World Off-Heap GC Thrashing (`1,188` forced `global.gc()` calls, ~every 36s):**
   - `start-offheap-gc-monitor!` (`full_node_main.cljs`) gated on `8 MiB` `arrayBuffers` / `16 MiB` `external` with a `30s` cooldown and zero hysteresis or ineffective-GC backoff, repeatedly freezing the event loop when off-heap allocations were small and un-reclaimable.
3. **Hot-Cache Boundary Thrashing (`1,702` `blob-hot-evicted` events):**
   - `core.data/evict-hot-lru` evicted one entry at a time right at `:max-hot-bytes` (`16 MiB`) with no low-water hysteresis or scan-resistant admission.
4. **Missing Hard `SIGTERM` Exit Watchdog:**
   - Neither `full_node_main.cljs` nor `node_main.cljs` armed a hard `5s` `SIGTERM` exit watchdog, allowing a wedged process to hang during graceful shutdown until `SIGKILL`.
5. **Observability Blind Spot:**
   - `/statusz` and `bitecho.status/v1` did not surface `state_bytes`, `cache_bytes`, `state_save_latency_ms`, `ctl_latency_ms`, `event_loop_lag_ms`, or `snapshot_encode_ms` (`last`/`p95`/`max`) with thresholded Rule 5 diagnostics.

## 3. Remediation (BIP-025)

All root causes are remediated and verified by generative `clojure.test.check` invariants in `test/bitecho/d53_bip025_cache_persistence_telemetry_test.cljc`:
- Strict `O(1)` caps on `:executed-root-depths` (`512`), `:expired-gossip-ids` / `:expired-gossip-order` (`1,024`), and `:epoch-to-message-roles` (`gossip-ttl-epochs + 4`).
- Off-heap GC hysteresis (`32 MiB` `arrayBuffers` / `64 MiB` `external`, `120s` base cooldown, exponential backoff to `600s` on `<10%` reclaim with `:offheap-gc-ineffective-backoff` and `gc_pause_ms`).
- Hot-LRU `0.85` low-water hysteresis and 2-hit scan-resistant admission in `bitecho.core.data`.
- Hard `5s` `SIGTERM` exit watchdog (`:shutdown-watchdog-forced-exit`, exit `124`) in `full_node_main.cljs` and `node_main.cljs`.
- Structural Core-State vs Value-Aware Local Cache split (`bitecho.cache.core`), async coalesced persistence, rotate-1 `--events-out` log cap (`32 MiB`), and first-class latency/storage telemetry in `bitecho.status/v1` and `/statusz`.
