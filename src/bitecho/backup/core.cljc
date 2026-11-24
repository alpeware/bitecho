(ns bitecho.backup.core
  "Row 6 — Pure Sans-IO Encrypted On-Network State Backup & Restore Core (`:bitecho.backup/v1`).
   Shared identically across Browser, Node.js Light, JVM Light, and Full Node (Rules 2, 4, 5):
   - Domain-separated XSalsa20-Poly1305 AEAD encryption via `IKeyProvider` (zero plaintext bytes in blob)
   - 64-char raw Ed25519 vs 88-char SPKI-DER pubkey normalization for `storage/<pubkey>/<slot>`
   - BIP-016 grow-only deletion tombstones (`:petname-tombstones`, `:artifact-tombstones`)
   - Lumen `seq 7` per-session auto-quarantine on stale `tx-seq` rollback (never blocks healthy sessions/startup)
   - Rule 4 purity: strips all derived runtime liveness and raw private-key fields."
  (:require [bitecho.core.data :as data]
            [bitecho.core.storage :as storage]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.key-provider :as kp]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def backup-schema-version
  "Canonical encrypted backup payload schema version."
  "bitecho.backup/v1")

(def backup-domain-context
  "Domain separation string passed to `IKeyProvider/derive-domain-key`."
  "bitecho-e2ee-backup-v1")

(def default-backup-slot
  "Default self-owned backup pointer slot under `storage/<pubkey>/<slot>`."
  "state-backup-v1")

(def excluded-runtime-liveness-keys
  "Rule 4: Derived runtime liveness and raw private-key fields MUST NEVER be serialized into on-network backups."
  #{:connected? :connection-error :conn-diagnostics :p2p :active-ws
    :mesh-conns :auto-sync-in-flight? :instance-lock :private-key :privkey})

(defn safe-map-get
  "CLJS-safe map lookup that never throws `CompareError` on string-keyed `sorted-map`s."
  ([m k] (safe-map-get m k nil))
  ([m k not-found]
   (if (map? m)
     (try
       (get m k not-found)
       (catch #?(:clj Exception :cljs :default) _
         not-found))
     not-found)))

(defn backup-pointer-path
  "Returns canonical self-owned storage path: `\"storage/<normalized-64-hex-pubkey>/<slot>\"`."
  ([pubkey-hex] (backup-pointer-path pubkey-hex default-backup-slot))
  ([pubkey-hex slot]
   (let [norm-pk (or (kp/normalize-pubkey-hex pubkey-hex) (str pubkey-hex))
         slot-str (if (and (string? slot) (not (str/blank? slot)))
                    (str/trim slot)
                    default-backup-slot)]
     (str "storage/" norm-pk "/" slot-str))))

(defn- sanitize-petname-map
  [m]
  (into (sorted-map)
        (for [[k v] (or m {})
              :when (and (some? k) (some? v))]
          [(if (keyword? k) (name k) (str k)) (str v)])))

(defn- sanitize-petname-meta
  [m]
  (into (sorted-map)
        (for [[pk meta-m] (or m {})
              :when (and (some? pk) (map? meta-m))]
          [(or (kp/normalize-pubkey-hex pk) (str pk))
           (select-keys meta-m [:petname :voice-id :color])])))

(defn- sanitize-petname-tombstones
  [m]
  (into (sorted-map)
        (for [[pk rec] (or m {})
              :when (and (some? pk) (map? rec))]
          [(or (kp/normalize-pubkey-hex pk) (str pk))
           (cond-> {:deleted-ms (long (or (safe-map-get rec :deleted-ms) 0))
                    :seq (long (or (safe-map-get rec :seq) 0))}
             (safe-map-get rec :petname)
             (assoc :petname (str (safe-map-get rec :petname))))])))

(defn- sanitize-artifact-tombstones
  [m]
  (into (sorted-map)
        (for [[k v] (or m {})
              :when (and (some? k) (some? v))]
          [(if (vector? k) (mapv str k) (str k)) v])))

(defn- sanitize-sessions
  [m]
  (into (sorted-map)
        (for [[sid s] (or m {})
              :when (and (some? sid) (map? s))]
          [(str sid)
           (cond-> {:peer (str (or (safe-map-get s :peer) ""))
                    :subnet-id (str (or (safe-map-get s :subnet-id) "global"))
                    :state (str (or (safe-map-get s :state) "unknown"))
                    :epoch (long (or (safe-map-get s :epoch) 0))
                    :tx-seq (long (or (safe-map-get s :tx-seq) 0))
                    :rx-high-seq (long (or (safe-map-get s :rx-high-seq) 0))
                    :acked-seq (long (or (safe-map-get s :acked-seq) 0))}
             (true? (safe-map-get s :tx-tainted?)) (assoc :tx-tainted? true)
             (true? (safe-map-get s :rekey-required?)) (assoc :rekey-required? true)
             (true? (safe-map-get s :quarantined?)) (assoc :quarantined? true)
             (safe-map-get s :quarantine-reason) (assoc :quarantine-reason (safe-map-get s :quarantine-reason)))])))

(defn- build-session-high-water
  [state sessions-map]
  (let [existing (or (safe-map-get state :session-high-water) {})
        from-sessions (reduce-kv (fn [acc sid s]
                                   (let [prev (safe-map-get existing sid {})
                                         tx (max (long (or (safe-map-get s :tx-seq) 0))
                                                 (long (or (safe-map-get prev :tx-seq) 0)))
                                         rx (max (long (or (safe-map-get s :rx-high-seq) 0))
                                                 (long (or (safe-map-get prev :rx-high-seq) 0)))]
                                     (assoc acc sid {:tx-seq tx :rx-high-seq rx})))
                                 (sorted-map)
                                 sessions-map)]
    (reduce-kv (fn [acc sid prev]
                 (if (contains? acc (str sid))
                   acc
                   (assoc acc (str sid)
                          {:tx-seq (long (or (safe-map-get prev :tx-seq) 0))
                           :rx-high-seq (long (or (safe-map-get prev :rx-high-seq) 0))})))
               from-sessions
               existing)))

(defn extract-backup-payload
  "Purely extracts a deterministic, Rule-4-compliant, secret-free `:bitecho.backup/v1` payload
   from any shell's state map (Browser, Node.js, JVM, or Full Node config/rolodex).
   Strictly strips all `excluded-runtime-liveness-keys` and uses `safe-map-get` for CLJS sorted-map safety."
  [state {:keys [node-role seq now-ms pubkey]}]
  (let [clean-state (apply dissoc (or state {}) excluded-runtime-liveness-keys)
        norm-pk (or (kp/normalize-pubkey-hex (or pubkey (safe-map-get clean-state :pubkey))) "")
        sessions-map (sanitize-sessions (safe-map-get clean-state :sessions))
        subs-vec (vec (sort (distinct (map str (or (safe-map-get clean-state :subscribed-subnets) [])))))]
    {:schema backup-schema-version
     :pubkey norm-pk
     :node-role (or node-role :light)
     :seq (max 1 (long (or seq (inc (long (or (safe-map-get clean-state :backup-seq) 0))))))
     :created-ms (long (or now-ms 0))
     :subnet-id (str (or (safe-map-get clean-state :subnet-id) "global"))
     :subscribed-subnets subs-vec
     :petnames (sanitize-petname-map (safe-map-get clean-state :petnames))
     :petname-meta (sanitize-petname-meta (safe-map-get clean-state :petname-meta))
     :petname-tombstones (sanitize-petname-tombstones (safe-map-get clean-state :petname-tombstones))
     :artifact-tombstones (sanitize-artifact-tombstones (safe-map-get clean-state :artifact-tombstones))
     :sessions sessions-map
     :session-high-water (build-session-high-water clean-state sessions-map)
     :rolodex-seq (long (or (safe-map-get (safe-map-get clean-state :rolodex) :seq)
                            (safe-map-get clean-state :rolodex-seq)
                            0))}))

(defn- provider-error?
  [x]
  (and (map? x) (false? (:ok? x)) (some? (:error x))))

(defn pack-encrypted-backup
  "Purely encodes `backup-payload` as canonical Fressian, derives the 32-byte backup key via
   `(kp/derive-domain-key key-provider \"bitecho-e2ee-backup-v1\")`, encrypts with XSalsa20-Poly1305
   (24-byte nonce || 16-byte Poly1305 tag || ciphertext — ZERO plaintext bytes in blob),
   builds a content-addressed `Blob` (`application/x-bitecho-e2ee-fressian`), and signs a
   monotonic `Pointer` at `storage/<pubkey>/<slot>` via `(kp/sign key-provider ...)`.
   Returns `{:ok? true :blob blob :pointer pointer :cid cid :path path :seq seq}`
   or `{:ok? false :error <canonical-kw> :effects [{:effect :diagnose ...}]}`."
  [{:keys [key-provider state subnet-id slot seq leader-term nonce-bytes node-role now-ms]}]
  (let [own-pk (when key-provider (kp/public-key key-provider))]
    (if (or (nil? key-provider) (str/blank? (str own-pk)))
      {:ok? false
       :error :hardware-unlock-required
       :effects [{:effect :diagnose :reason :hardware-unlock-required :stage :backup-pack}]}
      (let [sym-key (kp/derive-domain-key key-provider backup-domain-context)]
        (if (provider-error? sym-key)
          {:ok? false
           :error (:error sym-key)
           :effects [{:effect :diagnose :reason (:error sym-key) :stage :backup-derive-key}]}
          (let [sub-id (str (or subnet-id "bitecho.org/infra"))
                slot-name (if (and (string? slot) (not (str/blank? slot))) slot default-backup-slot)
                seq-num (max 1 (long (or seq 1)))
                term-num (max 1 (long (or leader-term 1)))
                path (backup-pointer-path own-pk slot-name)
                payload (extract-backup-payload state {:node-role node-role
                                                       :seq seq-num
                                                       :now-ms now-ms
                                                       :pubkey own-pk})
                pt-bytes (fressian/encode-canonical payload)
                nonce (or nonce-bytes (crypto/random-bytes 24))
                enc-bytes (storage/encrypt-storage-payload sym-key nonce pt-bytes)
                blob (data/make-blob enc-bytes "application/x-bitecho-e2ee-fressian")
                ptr-template {:pointer/subnet sub-id
                              :pointer/path path
                              :pointer/authority own-pk
                              :pointer/seq seq-num
                              :pointer/leader-term term-num
                              :pointer/target (:blob/cid blob)
                              :pointer/proof {:proof/type :self}}
                canon-ptr (data/canonical-pointer-map ptr-template)
                sig-bytes (kp/sign key-provider
                                   (crypto/canonical-signing-bytes
                                    (data/canonical-pointer-signing-payload canon-ptr)))]
            (if (provider-error? sig-bytes)
              {:ok? false
               :error (:error sig-bytes)
               :effects [{:effect :diagnose :reason (:error sig-bytes) :stage :backup-sign-pointer}]}
              (let [pointer (assoc canon-ptr :pointer/sig (str/lower-case (fressian/bytes->hex sig-bytes)))]
                {:ok? true
                 :blob blob
                 :pointer pointer
                 :cid (:blob/cid blob)
                 :path path
                 :subnet-id sub-id
                 :seq seq-num
                 :effects []}))))))))

(defn- fail-unpack
  [err detail]
  {:ok? false
   :error err
   :effects [(merge {:effect :diagnose :reason err :stage :backup-unpack} detail)]})

(defn unpack-encrypted-backup
  "Purely verifies:
     1. `SHA-256(blob/bytes) == blob/cid` (`:invalid-blob-cid`)
     2. `pointer/signature` valid for `own-pubkey` (`:invalid-pointer-signature`)
     3. `pointer/target == blob/cid` (`:pointer-target-mismatch`)
     4. `pointer/path == storage/<own-pubkey>/<slot>` (`:backup-path-owner-mismatch`)
     5. `pointer/seq >= min-expected-seq` (`:stale-pointer-rollback`)
   Decrypts with `(kp/derive-domain-key key-provider \"bitecho-e2ee-backup-v1\")` and decodes
   canonical Fressian. Returns `{:ok? true :payload map :seq long :cid str :path str}`
   or `{:ok? false :error <kw> :effects [{:effect :diagnose ...}]}`."
  [{:keys [key-provider blob pointer slot min-expected-seq]}]
  (let [own-pk (when key-provider (kp/normalize-pubkey-hex (kp/public-key key-provider)))
        ptr-auth (kp/normalize-pubkey-hex (:pointer/authority pointer))
        expected-slot (if (and (string? slot) (not (str/blank? slot))) slot default-backup-slot)
        expected-path (when own-pk (backup-pointer-path own-pk expected-slot))
        ptr-path (:pointer/path pointer)
        matched-path (when ptr-path (data/match-path-pattern "storage/<pubkey>/*" ptr-path))
        path-owner (kp/normalize-pubkey-hex (:owner matched-path))]
    (cond
      (nil? own-pk)
      (fail-unpack :hardware-unlock-required {})

      (not (data/verify-blob blob))
      (fail-unpack :invalid-blob-cid {:cid (:blob/cid blob)})

      (let [v-ptr (data/verify-pointer pointer)]
        (or (not (:ok? v-ptr))
            (not= ptr-auth own-pk)))
      (fail-unpack :invalid-pointer-signature {:authority ptr-auth :expected-owner own-pk})

      (not= (:pointer/target pointer) (:blob/cid blob))
      (fail-unpack :pointer-target-mismatch {:pointer-target (:pointer/target pointer) :blob-cid (:blob/cid blob)})

      (or (not (:matched? matched-path))
          (not= path-owner own-pk)
          (and slot (not= ptr-path expected-path)))
      (fail-unpack :backup-path-owner-mismatch {:path ptr-path :expected-path expected-path})

      (< (long (:pointer/seq pointer 0)) (long (or min-expected-seq 0)))
      (fail-unpack :stale-pointer-rollback {:pointer-seq (:pointer/seq pointer 0)
                                            :min-expected-seq (long (or min-expected-seq 0))})

      :else
      (let [sym-key (kp/derive-domain-key key-provider backup-domain-context)]
        (if (provider-error? sym-key)
          (fail-unpack (:error sym-key) {})
          (let [dec-res (storage/decrypt-storage-payload sym-key (:blob/bytes blob))]
            (if-not (:ok? dec-res)
              (fail-unpack :decryption-failed {:cid (:blob/cid blob)})
              (let [decoded (try
                              (fressian/decode-canonical (:plaintext dec-res))
                              (catch #?(:clj Exception :cljs :default) _ nil))]
                (if-not (map? decoded)
                  (fail-unpack :corrupt-backup-payload {:cid (:blob/cid blob)})
                  {:ok? true
                   :payload decoded
                   :seq (long (:pointer/seq pointer))
                   :cid (:blob/cid blob)
                   :path ptr-path
                   :effects []})))))))))

;; =============================================================================
;; Pure Restore Reducer (BIP-016 Grow-Only Tombstones + Lumen seq 7 Quarantine)
;; =============================================================================

(defn- merge-tombstone-entry
  [a b]
  (cond
    (nil? a) b
    (nil? b) a
    :else
    (let [seq-a (long (or (safe-map-get a :seq) 0))
          seq-b (long (or (safe-map-get b :seq) 0))
          ms-a (long (or (safe-map-get a :deleted-ms) 0))
          ms-b (long (or (safe-map-get b :deleted-ms) 0))]
      (cond-> {:seq (max seq-a seq-b)
               :deleted-ms (max ms-a ms-b)}
        (or (safe-map-get b :petname) (safe-map-get a :petname))
        (assoc :petname (or (safe-map-get b :petname) (safe-map-get a :petname)))))))

(defn- merge-petname-tombstones
  [local-tombs restored-tombs]
  (let [lt (sanitize-petname-tombstones local-tombs)
        rt (sanitize-petname-tombstones restored-tombs)]
    (reduce-kv (fn [acc pk rec]
                 (assoc acc pk (merge-tombstone-entry (safe-map-get acc pk) rec)))
               lt
               rt)))

(defn- merge-artifact-tombstones
  [local-tombs restored-tombs]
  (let [lt (sanitize-artifact-tombstones local-tombs)
        rt (sanitize-artifact-tombstones restored-tombs)]
    (reduce-kv (fn [acc k ptr]
                 (let [prev (safe-map-get acc k)
                       prev-seq (long (or (when (map? prev) (safe-map-get prev :pointer/seq)) 0))
                       next-seq (long (or (when (map? ptr) (safe-map-get ptr :pointer/seq)) 0))]
                   (if (or (nil? prev) (>= next-seq prev-seq))
                     (assoc acc k ptr)
                     acc)))
               lt
               rt)))

(defn- tombstoned-entry?
  [tombstone-set k v]
  (let [k-str (str k)
        v-str (str v)
        k-norm (kp/normalize-pubkey-hex k-str)
        v-norm (kp/normalize-pubkey-hex v-str)]
    (or (contains? tombstone-set k-str)
        (contains? tombstone-set v-str)
        (and k-norm (contains? tombstone-set k-norm))
        (and v-norm (contains? tombstone-set v-norm)))))

(defn- lookup-sid-entry
  "Looks up session-id `sid` in map `m`, accepting both string and keyword keys safely
   (CLJS `sorted-map` safe via `safe-map-get`, handling `(js->clj opts :keywordize-keys true)`)."
  [m sid]
  (when (map? m)
    (or (safe-map-get m sid)
        (when (string? sid) (safe-map-get m (keyword sid)))
        (when (keyword? sid) (safe-map-get m (name sid))))))

(defn- extract-observed-tx-seq
  "Extracts observed high-water tx-seq from an `observed-hwm` entry, accepting kebab-keyword,
   snake_keyword, string keys, or a direct numeric high-water value."
  [obs]
  (cond
    (number? obs) (long obs)
    (map? obs)
    (max (long (or (safe-map-get obs :observed-peer-high-seq)
                   (safe-map-get obs :observed_peer_high_seq)
                   (safe-map-get obs "observed-peer-high-seq")
                   (safe-map-get obs "observed_peer_high_seq")
                   0))
         (long (or (safe-map-get obs :local-tx-seq)
                   (safe-map-get obs :local_tx_seq)
                   (safe-map-get obs "local-tx-seq")
                   (safe-map-get obs "local_tx_seq")
                   0))
         (long (or (safe-map-get obs :tx-seq)
                   (safe-map-get obs :tx_seq)
                   (safe-map-get obs "tx-seq")
                   (safe-map-get obs "tx_seq")
                   0))
         (long (or (safe-map-get obs :high-water)
                   (safe-map-get obs :high_water)
                   (safe-map-get obs "high-water")
                   (safe-map-get obs "high_water")
                   0)))
    :else 0))

(defn merge-restored-state
  "Pure restore reducer shared identically across Browser, Node.js, JVM, and Full Node (`A3`, Lumen `seq 7`).
   Enforces:
     1. BIP-016 Grow-Only Deletion Tombstones (deleted petnames NEVER resurrect).
     2. Lumen `seq 7` Per-Session Auto-Quarantine (ONLY stale/tainted sessions are quarantined;
        healthy sessions and non-tombstoned petnames restore cleanly without blocking startup).
     3. Rule 4 Purity: strips all `excluded-runtime-liveness-keys`."
  [local-state restored-payload observed-hwm]
  (let [base-local (apply dissoc (or local-state {}) excluded-runtime-liveness-keys)
        payload (or restored-payload {})
        obs-hwm (let [raw (or observed-hwm {})]
                  (or (when (map? raw)
                        (or (safe-map-get raw :observed-hwm)
                            (safe-map-get raw :observed_hwm)
                            (safe-map-get raw "observed-hwm")
                            (safe-map-get raw "observed_hwm")))
                      raw))

        ;; 1. BIP-016 Grow-Only Tombstones
        merged-petname-tombs (merge-petname-tombstones
                              (safe-map-get base-local :petname-tombstones)
                              (safe-map-get payload :petname-tombstones))
        tomb-keys (set (keys merged-petname-tombs))
        merged-artifact-tombs (merge-artifact-tombstones
                               (safe-map-get base-local :artifact-tombstones)
                               (safe-map-get payload :artifact-tombstones))

        ;; Merge petnames & petname-meta, strictly excluding any tombstoned pubkey
        raw-petnames (merge (sanitize-petname-map (safe-map-get base-local :petnames))
                            (sanitize-petname-map (safe-map-get payload :petnames)))
        clean-petnames (into (sorted-map)
                             (remove (fn [[k v]] (tombstoned-entry? tomb-keys k v))
                                     raw-petnames))
        raw-meta (merge (sanitize-petname-meta (safe-map-get base-local :petname-meta))
                        (sanitize-petname-meta (safe-map-get payload :petname-meta)))
        clean-meta (into (sorted-map)
                         (remove (fn [[pk _]] (tombstoned-entry? tomb-keys pk pk))
                                 raw-meta))

        ;; Merge subscribed-subnets
        merged-subs (vec (sort (distinct (concat (map str (or (safe-map-get base-local :subscribed-subnets) []))
                                                 (map str (or (safe-map-get payload :subscribed-subnets) []))))))

        ;; 2. Lumen seq 7 Per-Session Auto-Quarantine
        local-sessions (or (safe-map-get base-local :sessions) {})
        restored-sessions (or (safe-map-get payload :sessions) {})
        local-hwm (or (safe-map-get base-local :session-high-water) {})
        payload-hwm (or (safe-map-get payload :session-high-water) {})
        all-sids (sort (distinct (concat (map str (keys local-sessions))
                                         (map str (keys restored-sessions)))))
        {:keys [sessions session-hwm effects quarantined-ids healthy-ids]}
        (reduce
         (fn [acc sid]
           (let [loc-s (lookup-sid-entry local-sessions sid)
                 res-s (lookup-sid-entry restored-sessions sid)
                 obs (lookup-sid-entry obs-hwm sid)
                 loc-h (lookup-sid-entry local-hwm sid)
                 pay-h (lookup-sid-entry payload-hwm sid)
                 r-tx (long (or (safe-map-get res-s :tx-seq) 0))
                 l-tx (long (or (safe-map-get loc-s :tx-seq) 0))
                 obs-tx (max (extract-observed-tx-seq obs)
                             (long (or (safe-map-get loc-h :tx-seq) 0))
                             l-tx)
                 merged-s (merge (or loc-s {}) (or res-s {}))
                 incoming-tainted? (or (true? (safe-map-get res-s :tx-tainted?))
                                       (true? (safe-map-get res-s :rekey-required?))
                                       (true? (safe-map-get res-s :quarantined?))
                                       (true? (safe-map-get loc-s :quarantined?)))
                 rollback? (and (some? res-s) (< r-tx obs-tx))
                 quarantine? (or rollback? incoming-tainted?)
                 fenced-tx (max r-tx obs-tx (long (or (safe-map-get pay-h :tx-seq) 0)))
                 fenced-rx (max (long (or (safe-map-get res-s :rx-high-seq) 0))
                                (long (or (safe-map-get loc-s :rx-high-seq) 0))
                                (long (or (safe-map-get loc-h :rx-high-seq) 0))
                                (long (or (safe-map-get pay-h :rx-high-seq) 0)))
                 final-s (if quarantine?
                           (assoc merged-s
                                  :quarantined? true
                                  :tx-tainted? true
                                  :rekey-required? true
                                  :reoffer-recommended? true
                                  :quarantine-reason (or (when rollback? :stale-backup-tx-seq-rollback)
                                                         (safe-map-get merged-s :quarantine-reason)
                                                         :stale-backup-tx-seq-rollback)
                                  :tx-seq fenced-tx
                                  :rx-high-seq fenced-rx)
                           (assoc merged-s
                                  :tx-seq fenced-tx
                                  :rx-high-seq fenced-rx))
                 diag (when quarantine?
                        {:effect :diagnose
                         :type :diagnose
                         :reason :session-rollback-quarantined
                         :session-id sid
                         :restored-tx-seq r-tx
                         :observed-high-water obs-tx
                         :rekey-required? true})]
             (-> acc
                 (assoc-in [:sessions sid] final-s)
                 (assoc-in [:session-hwm sid] {:tx-seq fenced-tx :rx-high-seq fenced-rx})
                 (cond->
                  quarantine? (-> (update :effects conj diag)
                                  (update :quarantined-ids conj sid))
                  (not quarantine?) (update :healthy-ids conj sid)))))
         {:sessions (sorted-map)
          :session-hwm (sorted-map)
          :effects []
          :quarantined-ids []
          :healthy-ids []}
         all-sids)

        q-count (count quarantined-ids)
        restored-seq (max (long (or (safe-map-get base-local :backup-seq) 0))
                          (long (or (safe-map-get payload :seq) 0)))
        new-state (cond-> (-> base-local
                              (assoc :petnames clean-petnames
                                     :petname-meta clean-meta
                                     :petname-tombstones merged-petname-tombs
                                     :artifact-tombstones merged-artifact-tombs
                                     :subscribed-subnets merged-subs
                                     :sessions sessions
                                     :session-high-water session-hwm
                                     :backup-seq restored-seq))
                    (pos? q-count)
                    (update-in [:diagnostics :session-rollback-quarantined] (fnil + 0) q-count)

                    (and (str/blank? (str (safe-map-get base-local :pubkey)))
                         (not (str/blank? (str (safe-map-get payload :pubkey)))))
                    (assoc :pubkey (safe-map-get payload :pubkey))

                    (and (nil? (safe-map-get base-local :subnet-id))
                         (some? (safe-map-get payload :subnet-id)))
                    (assoc :subnet-id (safe-map-get payload :subnet-id)))
        ;; 3. Rule 4 purity guarantee
        pure-state (apply dissoc new-state excluded-runtime-liveness-keys)]
    {:state pure-state
     :summary {:restored-seq restored-seq
               :petnames (count clean-petnames)
               :petname-tombstones (count merged-petname-tombs)
               :artifact-tombstones (count merged-artifact-tombs)
               :subscribed-subnets (count merged-subs)
               :healthy-sessions (count healthy-ids)
               :quarantined-sessions q-count
               :quarantined-session-ids quarantined-ids}
     :effects effects}))
