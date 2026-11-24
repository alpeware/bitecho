(ns bitecho.status.core
  "Single Canonical Sans-IO `ctl/status` & `/statusz` Renderer (BIP-022 Stage B, Row 4;
   Rules 2, 4, 5).
   Shared identically by Browser, Node.js Light, JVM Light, and Full Node shells.
   Uses `safe-map-get` throughout to prevent CLJS `sorted-map` `CompareError` on
   string-keyed maps (such as `:petnames`)."
  (:require [bitecho.config :as config]
            [bitecho.config.flags :as flags]
            [bitecho.sync.core :as sync-core]
            [clojure.string :as str]))

(def status-schema-version
  "Canonical BIP-022 Stage B status wire schema version."
  "bitecho.status/v1")

(def ^:private default-unacked-age-threshold-ms 30000)
(def ^:private default-delivery-ring-max-entries 200)

(defn safe-map-get
  "CLJS-safe map lookup that never throws `CompareError` when probing a string-keyed
   `sorted-map` (e.g. `:petnames`) with a keyword key or vice versa."
  ([m k] (safe-map-get m k nil))
  ([m k not-found]
   (if (map? m)
     (try
       (get m k not-found)
       (catch #?(:clj Exception :cljs :default) _
         not-found))
     not-found)))

(defn- kw-or-str->name
  [v default-str]
  (cond
    (keyword? v) (name v)
    (symbol? v) (name v)
    (and (string? v) (not (str/blank? v))) v
    :else default-str))

(defn- kw-or-str->snake
  [k]
  (-> (cond
        (keyword? k) (name k)
        (symbol? k) (name k)
        :else (str k))
      (str/replace "-" "_")))

(defn- map->snake-str-map
  [m]
  (if (map? m)
    (reduce-kv (fn [acc k v]
                 (assoc acc (kw-or-str->snake k) v))
               {}
               m)
    {}))

(defn- pubkey->petname
  [state pubkey]
  (when (and (string? pubkey) (map? (safe-map-get state :petnames)))
    (some (fn [[pname pk]]
            (when (= pk pubkey) (str pname)))
          (safe-map-get state :petnames))))

(defn- compute-unacked-aged-count
  [state now-ms]
  (let [now (long (or now-ms 0))
        thresh (long (or (safe-map-get state :unacked-age-threshold-ms) default-unacked-age-threshold-ms))
        sessions (safe-map-get state :sessions)]
    (if (and (pos? now) (map? sessions))
      (reduce (fn [acc [_ s]]
                (let [outbox (safe-map-get s :outbox)]
                  (if (map? outbox)
                    (+ acc
                       (count (filter (fn [[_ entry]]
                                        (let [ts (long (or (safe-map-get entry :sent-at-ms)
                                                           (safe-map-get entry :timestamp-ms)
                                                           0))]
                                          (and (pos? ts) (>= (- now ts) thresh))))
                                      outbox)))
                    acc)))
              0
              sessions)
      0)))

(defn- normalize-security-flags
  [state runtime-ctx]
  (let [provided (safe-map-get runtime-ctx :security-flags)
        base-echo (if (map? provided)
                    (if (contains? provided :keystore-security-tier)
                      provided
                      (flags/build-security-flags-echo provided))
                    (flags/build-security-flags-echo
                     {:subnet-id (or (safe-map-get state :subnet-id) "global")
                      :subnet-id-overridden? (boolean (safe-map-get state :subnet-id-overridden? false))
                      :trusted-dac-anchors (safe-map-get state :trusted-dac-anchors)
                      :trusted-dac-anchors-provenance (safe-map-get state :trusted-dac-anchors-provenance)
                      :trusted-deploy-authorities (safe-map-get state :trusted-deploy-authorities)
                      :pin-version (safe-map-get state :pin-version)
                      :auto-update-pointer (safe-map-get state :auto-update-pointer)
                      :keystore-security-tier (or (safe-map-get state :keystore-security-tier) :legacy-file-0600)}))
        wire (flags/security-flags->wire base-echo)]
    (assoc wire
           "subnet_override" (boolean (get wire "subnet_id_overridden"))
           "keystore_tier" (get wire "keystore_security_tier"))))

(defn- normalize-lock-status
  [lock-state]
  (let [ls (when (map? lock-state) lock-state)
        role (kw-or-str->name (or (safe-map-get ls :role) (safe-map-get ls "role")) "unlocked")
        lock-id (or (safe-map-get ls :lock-id) (safe-map-get ls "lock_id"))
        holder-pid (or (safe-map-get ls :holder-pid) (safe-map-get ls "holder_pid"))
        gen (max 0 (long (or (safe-map-get ls :generation) (safe-map-get ls "generation") 0)))
        reclaimed? (boolean (or (safe-map-get ls :reclaimed-stale-lock?)
                                (safe-map-get ls "reclaimed_stale_lock")
                                false))]
    {"role" role
     "lock_id" lock-id
     "holder_pid" holder-pid
     "generation" gen
     "reclaimed_stale_lock" reclaimed?}))

(defn- normalize-sync-status
  [state sync-state]
  (let [ss (when (map? sync-state) sync-state)
        tracker (safe-map-get state :auto-sync-stall-tracker)
        st-diags (safe-map-get state :diagnostics)
        ss-diags (safe-map-get ss :diagnostics)
        enabled? (if (and ss (contains? ss :enabled?)) (boolean (safe-map-get ss :enabled?)) true)
        interval-ms (max sync-core/min-sync-interval-ms
                         (long (or (when ss (sync-core/effective-interval-ms ss))
                                   sync-core/default-sync-interval-ms)))
        in-flight? (boolean (safe-map-get ss :in-flight? false))
        sync-gen (max 0 (long (or (safe-map-get ss :generation) 0)))
        fin-ep (max 0 (long (or (safe-map-get ss :last-finalized-epoch)
                                (safe-map-get tracker :last-finalized-epoch)
                                (safe-map-get (safe-map-get state :account) :finalized-epoch)
                                (safe-map-get state :epoch)
                                0)))
        stalled? (if (and ss (contains? ss :stalled?))
                   (boolean (safe-map-get ss :stalled?))
                   (boolean (safe-map-get tracker :stalled? false)))
        stall-dur (max 0 (long (or (when (and ss (contains? ss :stall-duration-ms))
                                     (safe-map-get ss :stall-duration-ms))
                                   (safe-map-get tracker :stall-duration-ms)
                                   0)))
        stall-thresh (max 1 (long (or (safe-map-get ss :stall-threshold-ms)
                                      sync-core/default-stall-threshold-ms)))
        stalled-cnt (max 0 (long (max (long (or (safe-map-get ss-diags :auto-sync-stalled)
                                                (safe-map-get ss-diags :finalized-epoch-stalled)
                                                0))
                                      (long (or (safe-map-get st-diags :auto-sync-stalled)
                                                (safe-map-get st-diags :finalized-epoch-stalled)
                                                0)))))
        last-err (or (safe-map-get ss :last-error)
                     (safe-map-get state :auto-sync-last-error)
                     (safe-map-get st-diags :auto-sync-last-error))
        last-adv (or (safe-map-get ss :last-advanced-ms)
                     (safe-map-get tracker :last-advanced-ms))]
    {"enabled" enabled?
     "interval_ms" interval-ms
     "in_flight" in-flight?
     "generation" sync-gen
     "finalized_epoch" fin-ep
     "stalled" stalled?
     "stall_duration_ms" stall-dur
     "stall_threshold_ms" stall-thresh
     "stalled_count" stalled-cnt
     "last_error" last-err
     "last_advanced_ms" last-adv}))

(defn- normalize-diagnostics
  [state runtime-ctx phase-str eff-gen last-err]
  (let [st-diags (or (safe-map-get state :diagnostics) {})
        conn (safe-map-get runtime-ctx :conn)
        conn-diags (or (safe-map-get conn :diagnostics)
                       (safe-map-get state :conn-diagnostics)
                       {})
        sync-diags (or (safe-map-get (safe-map-get runtime-ctx :sync-state) :diagnostics) {})
        lock-diags (or (safe-map-get (safe-map-get runtime-ctx :lock-state) :diagnostics) {})
        mesh-summary (safe-map-get runtime-ctx :mesh-summary)
        extra-merged (merge (map->snake-str-map st-diags)
                            (map->snake-str-map conn-diags)
                            (map->snake-str-map sync-diags)
                            (map->snake-str-map lock-diags))
        dropped (+ (long (or (safe-map-get mesh-summary :dropped)
                             (safe-map-get conn-diags :dropped)
                             0))
                   (long (or (safe-map-get st-diags :dropped) 0)))
        ignored-stale (+ (long (or (safe-map-get mesh-summary :ignored-stale)
                                   (safe-map-get conn-diags :ignored-stale)
                                   0))
                         (long (or (safe-map-get sync-diags :ignored-stale) 0))
                         (long (or (safe-map-get lock-diags :ignored-stale) 0))
                         (long (or (safe-map-get st-diags :ignored-stale) 0)))
        auto-sync-stalled (max (long (or (safe-map-get sync-diags :auto-sync-stalled) 0))
                               (long (or (safe-map-get st-diags :auto-sync-stalled) 0))
                               (long (or (safe-map-get st-diags :finalized-epoch-stalled) 0)))
        fin-ep-stalled (max (long (or (safe-map-get sync-diags :finalized-epoch-stalled) 0))
                            (long (or (safe-map-get st-diags :finalized-epoch-stalled) 0))
                            (long (or (safe-map-get conn-diags :finalized-epoch-stalled) 0))
                            auto-sync-stalled)
        auto-sync-failed (max (long (or (safe-map-get sync-diags :auto-sync-failed) 0))
                              (long (or (safe-map-get conn-diags :auto-sync-failed) 0))
                              (long (or (safe-map-get st-diags :auto-sync-failed) 0)))
        dup-rejected (max (long (or (safe-map-get lock-diags :duplicate-serve-instance-rejected) 0))
                          (long (or (safe-map-get st-diags :duplicate-serve-instance-rejected) 0)))
        stale-reclaimed (max (long (or (safe-map-get lock-diags :stale-serve-lock-reclaimed) 0))
                             (long (or (safe-map-get st-diags :stale-serve-lock-reclaimed) 0)))
        tab-handoff (max (long (or (safe-map-get lock-diags :browser-tab-leader-handoff) 0))
                         (long (or (safe-map-get st-diags :browser-tab-leader-handoff) 0)))]
    (merge extra-merged
           {"phase" phase-str
            "generation" (max 0 (long eff-gen))
            "last_error" last-err
            "dropped" (max 0 dropped)
            "ignored_stale" (max 0 ignored-stale)
            "auto_sync_stalled" (max 0 auto-sync-stalled)
            "finalized_epoch_stalled" (max 0 fin-ep-stalled)
            "auto_sync_failed" (max 0 auto-sync-failed)
            "duplicate_serve_instance_rejected" (max 0 dup-rejected)
            "stale_serve_lock_reclaimed" (max 0 stale-reclaimed)
            "browser_tab_leader_handoff" (max 0 tab-handoff)})))

(defn render-status
  "Single canonical Sans-IO status renderer shared by Browser, Node.js Light,
   and JVM Light nodes (plus canonical observability projection for Full Node).
   Reads runtime liveness exclusively from `runtime-ctx` (Rule 4) and never mutates
   or requires persisted `:connected?` / `:connection-error`.
   Returns canonical string-keyed wire map conforming to `bitecho.status/v1`."
  [state runtime-ctx]
  (let [st (or state {})
        rctx (or runtime-ctx {})
        runtime-str (kw-or-str->name (safe-map-get rctx :runtime) "nodejs")
        now-ms (long (or (safe-map-get rctx :now-ms) (safe-map-get st :now-ms) 0))
        conn (safe-map-get rctx :conn)
        mesh-summary (safe-map-get rctx :mesh-summary)
        lock-state (safe-map-get rctx :lock-state)
        sync-state (safe-map-get rctx :sync-state)
        lock-wire (normalize-lock-status lock-state)
        sync-wire (normalize-sync-status st sync-state)
        is-secondary? (= "secondary" (get lock-wire "role"))
        has-live-ctx? (boolean (or conn mesh-summary))
        open-peers (vec (or (safe-map-get mesh-summary :open-peers) []))
        dialing-peers (vec (or (safe-map-get mesh-summary :dialing-peers) []))
        closed-peers (vec (or (safe-map-get mesh-summary :closed-peers) []))
        open-count (if (some? mesh-summary)
                     (count open-peers)
                     (long (or (safe-map-get rctx :mesh-open-peers)
                               (safe-map-get st :mesh-open-peers)
                               0)))
        relay-fallback? (if (some? mesh-summary)
                          (boolean (safe-map-get mesh-summary :relay-fallback-active? false))
                          (boolean (or (safe-map-get rctx :relay-fallback-active?)
                                       (safe-map-get st :relay-fallback-active?)
                                       false)))
        degraded? (boolean (or (safe-map-get mesh-summary :degraded?)
                               (= :degraded (safe-map-get conn :phase))
                               false))
        raw-phase (cond
                    is-secondary? :standby
                    (some? (safe-map-get mesh-summary :phase)) (safe-map-get mesh-summary :phase)
                    (some? (safe-map-get conn :phase)) (safe-map-get conn :phase)
                    (and has-live-ctx? (pos? open-count)) :open
                    :else :idle)
        phase-str (kw-or-str->name raw-phase "idle")
        eff-gen (max 0 (long (or (safe-map-get mesh-summary :generation)
                                 (safe-map-get conn :generation)
                                 (get lock-wire "generation")
                                 0)))
        conn-err (if has-live-ctx?
                   (or (safe-map-get mesh-summary :last-error)
                       (safe-map-get (safe-map-get conn :diagnostics) :last-error)
                       (safe-map-get conn :last-error))
                   (safe-map-get st :connection-error))
        connected? (cond
                     is-secondary? false
                     (contains? rctx :connected?) (boolean (safe-map-get rctx :connected?))
                     has-live-ctx? (boolean (or (pos? open-count)
                                                relay-fallback?
                                                (= :open (safe-map-get conn :phase))
                                                (= :connected (safe-map-get conn :phase))))
                     :else (boolean (safe-map-get st :connected? false)))
        transport-healthy? (cond
                             is-secondary? false
                             (contains? rctx :transport-healthy?) (boolean (safe-map-get rctx :transport-healthy?))
                             has-live-ctx? (and connected? (nil? conn-err) (not degraded?))
                             :else (if (contains? st :transport-healthy?)
                                     (boolean (safe-map-get st :transport-healthy?))
                                     (and connected? (nil? conn-err))))
        diagnostics (normalize-diagnostics st rctx phase-str eff-gen conn-err)
        inbox-items (or (safe-map-get st :inbox) [])
        sessions-map (or (safe-map-get st :sessions) {})
        sessions-summary (vec (for [[_ s] sessions-map
                                    :let [peer (safe-map-get s :peer)
                                          pname (pubkey->petname st peer)]]
                                (cond-> (select-keys s [:session-id :peer :role :state :tx-seq :epoch :acked-seq :rx-high-seq :replays-deduped :outbox-evicted])
                                  true (assoc :unacked-count (count (or (safe-map-get s :outbox) {})))
                                  pname (assoc :peer-petname pname :peer_petname pname))))
        sessions-detail (vec (for [[sid s] sessions-map
                                   :let [p2p (or (safe-map-get s :p2p) {})
                                         p2p-conn? (boolean (safe-map-get p2p :connected? false))
                                         transport (or (safe-map-get p2p :transport)
                                                       (safe-map-get p2p :remote-transport)
                                                       (safe-map-get (safe-map-get s :p2p-meta) :preferred-transport)
                                                       "mesh")]]
                               {"session_id" sid
                                "peer" (safe-map-get s :peer)
                                "subnet_id" (or (safe-map-get s :subnet-id) (safe-map-get st :subnet-id) "global")
                                "status" (safe-map-get s :state)
                                "p2p_connected" p2p-conn?
                                "p2p_transport" transport
                                "acked_seq" (long (or (safe-map-get s :acked-seq) 0))
                                "unacked_count" (count (or (safe-map-get s :outbox) {}))
                                "outbox_evicted" (long (or (safe-map-get s :outbox-evicted) 0))
                                "tx_tainted" (boolean (safe-map-get s :tx-tainted? false))
                                "rekey_required" (boolean (safe-map-get s :rekey-required? false))
                                "reoffer_recommended" (boolean (safe-map-get s :reoffer-recommended? false))}))
        petnames-raw (or (safe-map-get st :petnames) {})
        petnames-sorted (try
                          (into (sorted-map) (map (fn [[k v]] [(str k) v]) petnames-raw))
                          (catch #?(:clj Exception :cljs :default) _
                            (sorted-map)))
        dt (or (safe-map-get st :delivery-telemetry) {})
        unacked-aged (compute-unacked-aged-count st now-ms)
        delivery-telemetry-resp {"sent" (long (or (safe-map-get dt :sent) 0))
                                 "acked" (long (or (safe-map-get dt :acked) 0))
                                 "unacked_aged" unacked-aged
                                 "unacked_age_threshold_ms" (long (or (safe-map-get st :unacked-age-threshold-ms)
                                                                      default-unacked-age-threshold-ms))
                                 "evicted_by_reason" (map->snake-str-map (safe-map-get dt :evicted-by-reason))
                                 "received_but_not_emitted" (map->snake-str-map (safe-map-get dt :received-but-not-emitted))
                                 "fanout" (map->snake-str-map (safe-map-get dt :fanout))
                                 "ring_buffer_count" (count (or (safe-map-get dt :ring-buffer) []))
                                 "ring_buffer_max" default-delivery-ring-max-entries}
        acct (safe-map-get st :account)
        fin-ep (get sync-wire "finalized_epoch")
        epoch (max 0 (long (or (safe-map-get st :epoch) fin-ep 0)))
        balance (max 0 (long (or (safe-map-get acct :balance) (safe-map-get st :balance) 0)))
        spendable (max 0 (long (or (safe-map-get acct :spendable) balance 0)))
        wire-diag (or (safe-map-get st :wire-version-diagnostics) {})
        wire-proto (or (safe-map-get rctx :wire-protocol)
                       {"version" 2
                        "min_supported" 1
                        "max_supported" 2
                        "unsupported_dropped" (long (or (safe-map-get wire-diag :unsupported-dropped) 0))
                        "last_unsupported_version" (safe-map-get wire-diag :last-unsupported-version)
                        "wire_format" "fressian-v1"
                        "supported_formats" ["fressian-v1" "legacy-nippy"]
                        "unsupported_format_dropped" (long (or (safe-map-get wire-diag :unsupported-format-dropped) 0))
                        "last_unsupported_format" (safe-map-get wire-diag :last-unsupported-format)})
        ver (str (or (safe-map-get rctx :version) config/version))]
    {"ok" true
     "schema_version" status-schema-version
     "version" ver
     "runtime" runtime-str
     "pubkey" (safe-map-get st :pubkey)
     "subnet_id" (str (or (safe-map-get st :subnet-id) "global"))
     "subscribed_subnets" (vec (sort (map str (or (safe-map-get st :subscribed-subnets) #{}))))
     "connected" connected?
     "transport_healthy" transport-healthy?
     "phase" phase-str
     "generation" eff-gen
     "finalized_epoch" fin-ep
     "peers" {"open_count" (max 0 open-count)
              "open" open-peers
              "dialing" dialing-peers
              "closed" closed-peers
              "relay_fallback_active" relay-fallback?
              "degraded" degraded?}
     "sessions" sessions-summary
     "sessions_detail" sessions-detail
     "petnames_count" (count petnames-sorted)
     "security_flags" (normalize-security-flags st rctx)
     "sync" sync-wire
     "instance_lock" lock-wire
     "delivery_telemetry" delivery-telemetry-resp
     "diagnostics" diagnostics
     ;; Backwards-compatible top-level mirrors retained for existing scripts/tools:
     "connection_error" conn-err
     "stalled" (get sync-wire "stalled")
     "stall_duration_ms" (get sync-wire "stall_duration_ms")
     "finalized_epoch_stalled_count" (get sync-wire "stalled_count")
     "auto_sync_last_error" (get sync-wire "last_error")
     "mesh_open_peers" (max 0 open-count)
     "relay_fallback_active" relay-fallback?
     "epoch" epoch
     "balance" balance
     "spendable" spendable
     "unread_events" (count (or (safe-map-get st :event-queue) []))
     "inbox_count" (count inbox-items)
     "petnames" petnames-sorted
     "wire_protocol" wire-proto}))

(defn project-browser-status
  "Thin pure projection over `(render-status state runtime-ctx)` for Browser JS consumers:
   preserves ALL canonical snake_case keys verbatim at top level and projects backwards-compatible
   camelCase aliases so existing UI code continues working without schema drift."
  [canonical-status browser-extras]
  (let [canon (or canonical-status {})
        peers (or (get canon "peers") {})
        dt (or (get canon "delivery_telemetry") {})
        camel-aliases {"subnetId" (get canon "subnet_id")
                       "transportHealthy" (get canon "transport_healthy")
                       "meshConnected" (pos? (long (or (get canon "mesh_open_peers") 0)))
                       "meshOpenPeers" (long (or (get canon "mesh_open_peers") 0))
                       "relayFallbackActive" (boolean (get canon "relay_fallback_active"))
                       "connectedNodes" (vec (or (get peers "open") []))
                       "closedNodes" (vec (or (get peers "closed") []))
                       "dialingNodes" (vec (or (get peers "dialing") []))
                       "degraded" (boolean (get peers "degraded"))
                       "deliveryTelemetry" {"sent" (long (or (get dt "sent") 0))
                                            "acked" (long (or (get dt "acked") 0))
                                            "unackedAged" (long (or (get dt "unacked_aged") 0))
                                            "evictedByReason" (or (get dt "evicted_by_reason") {})
                                            "receivedButNotEmitted" (or (get dt "received_but_not_emitted") {})
                                            "fanout" (or (get dt "fanout") {})
                                            "ringBufferCount" (long (or (get dt "ring_buffer_count") 0))}
                       "securityFlags" (get canon "security_flags")
                       "instanceLock" (get canon "instance_lock")
                       "autoSync" (get canon "sync")}]
    (merge camel-aliases
           (or browser-extras {})
           canon)))

(defn merge-full-node-statusz-contract
  "Merges canonical Stage B observability keys (`schema_version`, `security_flags`,
   `instance_lock`, normalized `diagnostics`) into Full Node `/statusz` without
   breaking existing fleet monitoring fields (`node_id`, `role`, `leader`, `term`,
   `finalized_epoch`, `memory`, `passthrough`)."
  [base-statusz runtime-ctx]
  (let [base (or base-statusz {})
        rctx (or runtime-ctx {})
        kw-keys? (boolean (some keyword? (keys base)))
        sec-flags (or (safe-map-get base :security_flags)
                      (safe-map-get base "security_flags")
                      (normalize-security-flags {} rctx))
        sec-flags-norm (if (map? sec-flags)
                         (assoc sec-flags
                                "subnet_override" (boolean (or (get sec-flags "subnet_override")
                                                               (get sec-flags "subnet_id_overridden")
                                                               false))
                                "keystore_tier" (or (get sec-flags "keystore_tier")
                                                    (get sec-flags "keystore_security_tier")
                                                    "legacy-file-0600"))
                         (normalize-security-flags {} rctx))
        lock-wire (normalize-lock-status (safe-map-get rctx :lock-state))
        existing-diag (or (safe-map-get base :diagnostics)
                          (safe-map-get base "diagnostics")
                          {})
        lock-diags (or (safe-map-get (safe-map-get rctx :lock-state) :diagnostics) {})
        merged-diag (merge existing-diag
                           (if kw-keys?
                             {:duplicate_serve_instance_rejected (long (or (safe-map-get lock-diags :duplicate-serve-instance-rejected) 0))
                              :stale_serve_lock_reclaimed (long (or (safe-map-get lock-diags :stale-serve-lock-reclaimed) 0))}
                             {"duplicate_serve_instance_rejected" (long (or (safe-map-get lock-diags :duplicate-serve-instance-rejected) 0))
                              "stale_serve_lock_reclaimed" (long (or (safe-map-get lock-diags :stale-serve-lock-reclaimed) 0))}))]
    (if kw-keys?
      (assoc base
             :schema_version status-schema-version
             :security_flags sec-flags-norm
             :instance_lock lock-wire
             :diagnostics merged-diag)
      (assoc base
             "schema_version" status-schema-version
             "security_flags" sec-flags-norm
             "instance_lock" lock-wire
             "diagnostics" merged-diag))))
