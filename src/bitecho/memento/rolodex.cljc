(ns bitecho.memento.rolodex
  "BIP-A: Signed Append-Only Rolodex & Head-Record CAS.
   Pure Sans-IO .cljc reducer: (transition rolodex event) -> [new-rolodex effects].
   Follows AGENTS.md Rules 2, 4, and 5:
   - Single-authority generation-tagged lifecycle state
   - Pointer CAS head claim BEFORE any :sign, :encrypt, :cas-put, or :emit
   - Crash-after-claim burns :seq and resumes at :seq+1 (never reuses (key, :seq))
   - Grow-only revocations that never resurrect across forward .lkg :restore
   - Counted :diagnose on every halt, stale callback, or ceiling breach."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.memento.constants :as mc]
            [clojure.set :as set]))

;; =============================================================================
;; Canonical Signing & CID Helpers
;; =============================================================================

(defn canonical-entry-payload
  "Strips :signature from an entry and returns its canonical unsigned map."
  [entry]
  (dissoc entry :signature))

(defn entry-signing-bytes
  "Returns domain-separated signing bytes: utf8(\"bitecho/rolodex/v1\") || fressian/encode-canonical(unsigned-entry)."
  [entry]
  (fressian/concat-bytes
   (fressian/utf8->bytes mc/rolodex-domain-tag)
   (fressian/encode-canonical (canonical-entry-payload entry))))

(defn entry-cid
  "Computes the 64-char hex SHA-256 CID of a signed Rolodex entry."
  [signed-entry]
  (crypto/sha256-hex (fressian/encode-canonical signed-entry)))

;; =============================================================================
;; CRDT Fold & Snapshots
;; =============================================================================

(defn- merge-revocations
  "Grow-only union of petname -> #{revoked-action ...} maps."
  [rev-a rev-b]
  (merge-with set/union (or rev-a {}) (or rev-b {})))

(defn- apply-revocations-to-state
  "Strips all globally revoked actions from every petname in state."
  [state revoked-actions]
  (reduce-kv
   (fn [acc petname entry]
     (let [rev (get revoked-actions petname #{})]
       (assoc acc petname
              (update entry :allowed-actions #(set/difference (set (or % #{})) rev)))))
   {}
   (or state {})))

(defn apply-entry-delta
  "Applies a single Rolodex entry delta onto {:state :subnets :open-sessions :revoked-actions} purely.
   Supports unified petnames, subnets, and open sessions for both :light and :infra nodes.
   Grow-only revocations ensure revoked :allowed-actions never resurrect."
  [{:keys [state subnets open-sessions revoked-actions]} entry snapshots]
  (let [op (:op entry)
        petname (:petname entry)
        rev-map (or revoked-actions {})
        subnets-map (or subnets {})
        sessions-map (or open-sessions {})]
    (case op
      (:upsert :add)
      (let [rev-for-pet (get rev-map petname #{})
            effective-actions (set/difference (set (or (:allowed-actions entry) #{})) rev-for-pet)
            record (cond-> {:petname petname
                            :pubkey (:pubkey entry)
                            :allowed-actions effective-actions}
                     (contains? entry :advisory-twin?)
                     (assoc :advisory-twin? (boolean (:advisory-twin? entry))))]
        {:state (assoc state petname record)
         :subnets subnets-map
         :open-sessions sessions-map
         :revoked-actions rev-map})

      :revoke
      (let [newly-revoked (set (or (:allowed-actions entry) #{}))
            next-rev (update rev-map petname #(set/union (or % #{}) newly-revoked))
            next-state (if (contains? state petname)
                         (update-in state [petname :allowed-actions]
                                    #(set/difference (set (or % #{})) newly-revoked))
                         state)]
        {:state next-state
         :subnets subnets-map
         :open-sessions sessions-map
         :revoked-actions next-rev})

      :remove
      {:state (dissoc state petname)
       :subnets subnets-map
       :open-sessions sessions-map
       :revoked-actions rev-map}

      :upsert-subnet
      (let [sid (:subnet-id entry)
            rec {:subnet-id sid
                 :values-cid (:values-cid entry)
                 :governance-pointer (:governance-pointer entry)
                 :members (set (or (:members entry) #{}))}]
        {:state state
         :subnets (assoc subnets-map sid rec)
         :open-sessions sessions-map
         :revoked-actions rev-map})

      :remove-subnet
      {:state state
       :subnets (dissoc subnets-map (:subnet-id entry))
       :open-sessions sessions-map
       :revoked-actions rev-map}

      (:open-session :update-session)
      (let [sess-id (:session-id entry)
            rec {:session-id sess-id
                 :peer-pubkey (:peer-pubkey entry)
                 :subnet-id (:subnet-id entry)
                 :transport (:transport entry)
                 :last-seq (long (or (:last-seq entry) 0))
                 :opened-at-ms (long (or (:opened-at-ms entry) 0))}]
        {:state state
         :subnets subnets-map
         :open-sessions (assoc sessions-map sess-id rec)
         :revoked-actions rev-map})

      :close-session
      {:state state
       :subnets subnets-map
       :open-sessions (dissoc sessions-map (:session-id entry))
       :revoked-actions rev-map}

      :burn
      {:state state
       :subnets subnets-map
       :open-sessions sessions-map
       :revoked-actions rev-map}

      :restore
      (let [snap (get snapshots (:snapshot-cid entry))
            merged-rev (merge-revocations rev-map (:revoked-actions snap))
            restored-state (apply-revocations-to-state (:state snap) merged-rev)]
        {:state restored-state
         :subnets (or (:subnets snap) subnets-map)
         :open-sessions (or (:open-sessions snap) sessions-map)
         :revoked-actions merged-rev})

      ;; Unknown op leaves state unchanged
      {:state state
       :subnets subnets-map
       :open-sessions sessions-map
       :revoked-actions rev-map})))

(defn fold-entries
  "Folds a sequence of Rolodex entries (sorted by :seq) onto initial-state and initial-revocations."
  ([initial-state initial-revocations entries]
   (fold-entries initial-state initial-revocations entries {}))
  ([initial-state initial-revocations entries snapshots]
   (reduce (fn [acc entry]
             (apply-entry-delta acc entry snapshots))
           {:state (or initial-state {})
            :subnets {}
            :open-sessions {}
            :revoked-actions (or initial-revocations {})}
           (sort-by :seq entries))))

(defn snapshot-checksum
  "Computes the canonical SHA-256 hex checksum of a Rolodex snapshot (excluding :snapshot-cid)."
  [snapshot]
  (crypto/sha256-hex (fressian/encode-canonical (dissoc snapshot :snapshot-cid))))

(defn verify-snapshot-checksum
  "Returns true iff snapshot's :snapshot-cid matches its canonical SHA-256 checksum."
  [snapshot]
  (boolean (and (map? snapshot)
                (string? (:snapshot-cid snapshot))
                (= (:snapshot-cid snapshot) (snapshot-checksum snapshot)))))

(defn make-snapshot
  "Produces a periodic Rolodex snapshot {:seq :head-cid :state :subnets :open-sessions
   :revoked-actions :total-bytes-at-rest :rotation-epoch :node-role :snapshot-cid}."
  [rolodex]
  (let [base {:seq (get-in rolodex [:head :seq])
              :head-cid (get-in rolodex [:head :head-cid])
              :state (:state rolodex)
              :subnets (or (:subnets rolodex) {})
              :open-sessions (or (:open-sessions rolodex) {})
              :revoked-actions (:revoked-actions rolodex)
              :total-bytes-at-rest (long (or (:total-bytes-at-rest rolodex) 0))
              :rotation-epoch (long (or (:rotation-epoch rolodex) 0))
              :node-role (or (:node-role rolodex) :light)}]
    (assoc base :snapshot-cid (snapshot-checksum base))))

(defn verify-snapshot-matches-fold
  "Verifies that snapshot :state, :subnets, and :open-sessions equal the fold of log deltas up to :seq."
  ([snapshot entries]
   (verify-snapshot-matches-fold snapshot entries {}))
  ([snapshot entries snapshots]
   (let [up-to-seq (filter #(<= (:seq %) (:seq snapshot)) entries)
         folded (fold-entries {} {} up-to-seq snapshots)]
     (and (= (:state snapshot) (:state folded))
          (= (or (:subnets snapshot) {}) (:subnets folded))
          (= (or (:open-sessions snapshot) {}) (:open-sessions folded))))))

;; =============================================================================
;; Single-Authority Generation-Tagged State & Diagnostics (Rules 4 & 5)
;; =============================================================================

(defn blob-gc-eligible?
  "Returns true iff current-epoch >= :gc-eligible-at-epoch of a pinned rotation record.
   Reads grace window N strictly from the pinned rotation record (never mutates N retroactively)."
  [rotation-record current-epoch]
  (boolean (and (map? rotation-record)
                (integer? (:gc-eligible-at-epoch rotation-record))
                (>= (long current-epoch) (long (:gc-eligible-at-epoch rotation-record))))))

(defn init-rolodex
  "Initializes a pure, single-authority generation-tagged Rolodex reducer state.
   Supports optional runtime config map loaded from network storage."
  ([] (init-rolodex nil))
  ([config]
   (let [cap-res (mc/resolve-effective-caps (:caps config))
         eff-caps (if (:ok? cap-res) (:effective-caps cap-res) mc/default-cap-ceilings)
         grace-res (mc/effective-grace-epochs (:rotation-grace-epochs config))]
     {:phase :idle
      :generation 0
      :node-role (or (:node-role config) :light)
      :owner-pubkeys (:owner-pubkeys config)
      :retention-policy (:retention-policy config)
      :network-config-cid (:network-config-cid config)
      :effective-caps eff-caps
      :rotation-grace-epochs (:grace-epochs grace-res)
      :rotation-history []
      :head {:seq 0
             :head-cid mc/zero-cid-hex
             :gen 0
             :memory-head-cid mc/zero-cid-hex}
      :last-committed-cid mc/zero-cid-hex
      :pending nil
      :entries {}
      :cids {}
      :burned-seqs #{}
      :snapshots {}
      :state {}
      :subnets {}
      :open-sessions {}
      :ephemeral-sockets {}
      :revoked-actions {}
      :total-bytes-at-rest 0
      :rotation-epoch 0
      :entries-since-rotation 0
      :last-error nil
      :dropped 0
      :diagnostics-count 0})))

(defn persistable-head-record
  "Returns only the persistable Pointer CAS head record (never runtime liveness)."
  [rolodex]
  (select-keys (:head rolodex) [:seq :head-cid :gen :memory-head-cid]))

(defn status-diagnostics
  "Surfaces counted diagnostics and generation-tagged lifecycle status (Rule 4 & Rule 5)."
  [rolodex]
  {:phase (:phase rolodex)
   :generation (:generation rolodex)
   :node-role (:node-role rolodex)
   :owner-pubkeys (:owner-pubkeys rolodex)
   :retention-policy (:retention-policy rolodex)
   :effective-caps (or (:effective-caps rolodex) mc/default-cap-ceilings)
   :rotation-grace-epochs (or (:rotation-grace-epochs rolodex) mc/min-rotation-grace-epochs)
   :persistent-session-count (count (:open-sessions rolodex))
   :ephemeral-socket-count (count (:ephemeral-sockets rolodex))
   :total-bytes-at-rest (:total-bytes-at-rest rolodex)
   :rotation-epoch (:rotation-epoch rolodex)
   :entries-since-rotation (:entries-since-rotation rolodex)
   :last-error (:last-error rolodex)
   :dropped (:dropped rolodex)
   :diagnostics-count (:diagnostics-count rolodex)
   :head (persistable-head-record rolodex)
   :burned-seqs (:burned-seqs rolodex)})

(defn- halt-with-diagnose
  [rolodex code detail]
  (let [next-count (inc (:diagnostics-count rolodex))
        diag (merge {:type :diagnose
                     :code code
                     :generation (:generation rolodex)
                     :count next-count}
                    detail)]
    [(assoc rolodex
            :phase :halted
            :pending nil
            :last-error diag
            :diagnostics-count next-count)
     [diag]]))

(defn- drop-stale-callback
  [rolodex cb-gen event-type]
  (let [next-dropped (inc (:dropped rolodex))
        next-count (inc (:diagnostics-count rolodex))
        diag {:type :diagnose
              :code :stale-generation-callback
              :event-type event-type
              :callback-gen cb-gen
              :current-gen (:generation rolodex)
              :dropped next-dropped
              :count next-count}]
    [(assoc rolodex
            :dropped next-dropped
            :diagnostics-count next-count)
     [diag]]))

;; =============================================================================
;; Pure Sans-IO Reducer: (transition rolodex event) -> [new-rolodex effects]
;; =============================================================================

(defn- check-bounded-caps
  "Checks effective structural caps (min constant config) before inserting a new key."
  [rolodex event]
  (let [op (:op event)
        eff-caps (or (:effective-caps rolodex) mc/default-cap-ceilings)
        pet-cap (:max-petnames eff-caps mc/max-petnames)
        sub-cap (:max-subnets eff-caps mc/max-subnets)
        ses-cap (:max-open-sessions eff-caps mc/max-open-sessions)]
    (cond
      (and (#{:upsert :add} op)
           (not (contains? (:state rolodex) (:petname event)))
           (>= (count (:state rolodex)) pet-cap))
      {:ok? false :code :bounded-cap-exceeded :detail {:table :petnames :cap pet-cap :ceiling mc/max-petnames}}

      (and (= :upsert-subnet op)
           (not (contains? (:subnets rolodex) (:subnet-id event)))
           (>= (count (:subnets rolodex)) sub-cap))
      {:ok? false :code :bounded-cap-exceeded :detail {:table :subnets :cap sub-cap :ceiling mc/max-subnets}}

      (and (#{:open-session :update-session} op)
           (not (contains? (:open-sessions rolodex) (:session-id event)))
           (>= (count (:open-sessions rolodex)) ses-cap))
      {:ok? false :code :bounded-cap-exceeded :detail {:table :open-sessions :cap ses-cap :ceiling mc/max-open-sessions}}

      :else
      {:ok? true})))

(defn transition
  "Pure Sans-IO reducer for BIP-A / BIP-016 Unified Rolodex & Head-Record CAS.
   Supports both :light and :infra node roles, petnames + subnets + persistent sessions,
   runtime-only ephemeral transport sockets, (min constant config) cap ceilings,
   N-min=4 rotation grace windows, signed owners, and bytes-at-rest accounting.
   Returns [new-rolodex effects]."
  [rolodex event]
  (case (:type event)
    :configure-pointer
    (let [role (or (:node-role event) (:node-role rolodex) :light)
          disc (mc/validate-pointer-discipline event)
          cap-res (mc/resolve-effective-caps (:caps event))
          grace-res (mc/effective-grace-epochs (:rotation-grace-epochs event))]
      (cond
        (not (contains? mc/valid-node-roles role))
        (halt-with-diagnose rolodex :invalid-node-role {:node-role role})

        (not (:ok? disc))
        (halt-with-diagnose rolodex (:code disc) (:detail disc))

        (not (:ok? cap-res))
        (halt-with-diagnose rolodex (:code cap-res) (dissoc cap-res :ok? :code))

        :else
        (let [base-count (long (or (:diagnostics-count rolodex) 0))
              clamp-diags (map-indexed
                           (fn [idx c]
                             (merge {:type :diagnose
                                     :code :cap-ceiling-clamped
                                     :generation (:generation rolodex)
                                     :count (+ base-count idx 1)}
                                    c))
                           (:clamped cap-res))
              after-clamp-count (+ base-count (count clamp-diags))
              grace-diags (if (:floored? grace-res)
                            [{:type :diagnose
                              :code :grace-window-floored
                              :generation (:generation rolodex)
                              :requested (:requested grace-res)
                              :floor (:floor grace-res)
                              :effective (:grace-epochs grace-res)
                              :count (inc after-clamp-count)}]
                            [])
              all-diags (vec (concat clamp-diags grace-diags))
              final-count (+ base-count (count all-diags))]
          [(cond-> (assoc rolodex
                          :node-role role
                          :owner-pubkeys (vec (:owner-pubkeys event))
                          :retention-policy (:retention-policy event)
                          :network-config-cid (:network-config-cid event)
                          :effective-caps (:effective-caps cap-res)
                          :rotation-grace-epochs (:grace-epochs grace-res)
                          :diagnostics-count final-count)
             (seq all-diags) (assoc :last-error (last all-diags)))
           all-diags])))

    :register-ephemeral-socket
    (let [sock-id (:socket-id event)
          rec {:socket-id sock-id
               :peer-pubkey (:peer-pubkey event)
               :transport (:transport event)
               :peer-role (or (:peer-role event) :transient-poller)
               :opened-at-ms (long (or (:opened-at-ms event) 0))}]
      [(assoc-in rolodex [:ephemeral-sockets sock-id] rec)
       []])

    :close-ephemeral-socket
    [(update rolodex :ephemeral-sockets dissoc (:socket-id event))
     []]

    :complete-rotation
    (let [retained (long (or (:retained-snapshot-bytes event) 0))
          policy (:retention-policy rolodex)]
      (if (and policy (> retained (:max-bytes policy)))
        (halt-with-diagnose rolodex :retention-bound-exceeded
                            {:retained-snapshot-bytes retained :max-bytes (:max-bytes policy)})
        (let [next-epoch (inc (long (or (:rotation-epoch rolodex) 0)))
              grace-n (long (or (:rotation-grace-epochs rolodex) mc/min-rotation-grace-epochs))
              rot-rec {:rotation-epoch next-epoch
                       :pinned-config-cid (:network-config-cid rolodex)
                       :grace-epochs grace-n
                       :gc-eligible-at-epoch (+ next-epoch grace-n)
                       :retained-head-cid (get-in rolodex [:head :head-cid])
                       :lkg-snapshot-cid (:lkg-snapshot-cid event)}]
          [(assoc rolodex
                  :rotation-epoch next-epoch
                  :entries-since-rotation 0
                  :total-bytes-at-rest retained
                  :rotation-history (conj (vec (or (:rotation-history rolodex) [])) rot-rec))
           []])))

    :propose-entry
    (let [ephemeral-poller? (and (#{:open-session :update-session} (:op event))
                                 (or (= :ephemeral (:session-scope event))
                                     (= :transient-poller (:peer-role event))))
          cap-check (check-bounded-caps rolodex event)
          acct (:storage-accounting event)
          policy (:retention-policy rolodex)
          entry-bytes (long (or (:bytes-at-rest acct) 0))
          projected-bytes (+ (long (or (:total-bytes-at-rest rolodex) 0)) entry-bytes)]
      (cond
        (not= :idle (:phase rolodex))
        (halt-with-diagnose rolodex :writer-not-idle {:current-phase (:phase rolodex)})

        ephemeral-poller?
        (halt-with-diagnose rolodex :ephemeral-poller-rejected-from-persistent-sessions
                            {:session-id (:session-id event)
                             :session-scope (:session-scope event)
                             :peer-role (:peer-role event)})

        (and (some? acct) (not (mc/valid-storage-accounting? acct)))
        (halt-with-diagnose rolodex :invalid-storage-accounting {:storage-accounting acct})

        (not (:ok? cap-check))
        (halt-with-diagnose rolodex (:code cap-check) (:detail cap-check))

        (and policy (> projected-bytes (:max-bytes policy)))
        (halt-with-diagnose rolodex :retention-bound-exceeded
                            {:projected-bytes projected-bytes :max-bytes (:max-bytes policy)})

        (and policy (>= (long (or (:entries-since-rotation rolodex) 0)) (:max-entries policy)))
        (halt-with-diagnose rolodex :retention-bound-exceeded
                            {:entries-since-rotation (:entries-since-rotation rolodex)
                             :max-entries (:max-entries policy)})

        :else
        (let [head (:head rolodex)
              next-seq (inc (:seq head))
              next-gen (inc (:generation rolodex))
              mem-head (or (:memory-head-cid event) (:memory-head-cid head))
              entry (cond-> {:seq next-seq
                             :prev-cid (:head-cid head)
                             :op (:op event)}
                      (contains? event :petname) (assoc :petname (:petname event))
                      (contains? event :pubkey) (assoc :pubkey (:pubkey event))
                      (contains? event :allowed-actions) (assoc :allowed-actions (set (:allowed-actions event)))
                      (contains? event :advisory-twin?) (assoc :advisory-twin? (boolean (:advisory-twin? event)))
                      (contains? event :subnet-id) (assoc :subnet-id (:subnet-id event))
                      (contains? event :values-cid) (assoc :values-cid (:values-cid event))
                      (contains? event :governance-pointer) (assoc :governance-pointer (:governance-pointer event))
                      (contains? event :members) (assoc :members (set (:members event)))
                      (contains? event :session-id) (assoc :session-id (:session-id event))
                      (contains? event :peer-pubkey) (assoc :peer-pubkey (:peer-pubkey event))
                      (contains? event :transport) (assoc :transport (:transport event))
                      (contains? event :last-seq) (assoc :last-seq (long (:last-seq event)))
                      (contains? event :opened-at-ms) (assoc :opened-at-ms (long (:opened-at-ms event)))
                      (some? acct) (assoc :storage-accounting acct)
                      (contains? event :reason) (assoc :reason (:reason event)))
              claimed-head {:seq next-seq
                            :head-cid nil
                            :gen next-gen
                            :memory-head-cid mem-head}]
          [(assoc rolodex
                  :phase :claiming-cas
                  :generation next-gen
                  :pending {:seq next-seq
                            :gen next-gen
                            :entry entry
                            :claimed? false
                            :memory-head-cid mem-head})
           [{:type :cas-head
             :gen next-gen
             :expected-head head
             :claimed-head claimed-head}]])))

    :propose-restore
    (let [snap-cid (:snapshot-cid event)
          snap (or (:snapshot event) (get-in rolodex [:snapshots snap-cid]))]
      (cond
        (not= :idle (:phase rolodex))
        (halt-with-diagnose rolodex :writer-not-idle {:current-phase (:phase rolodex)})

        (nil? snap)
        (halt-with-diagnose rolodex :missing-snapshot {:snapshot-cid snap-cid})

        (and (some? (:snapshot-cid snap)) (not (verify-snapshot-checksum snap)))
        (halt-with-diagnose rolodex :lkg-checksum-mismatch
                            {:snapshot-cid (:snapshot-cid snap)
                             :actual-checksum (snapshot-checksum snap)})

        :else
        (let [head (:head rolodex)
              next-seq (inc (:seq head))
              next-gen (inc (:generation rolodex))
              mem-head (or (:memory-head-cid event) (:memory-head-cid head))
              entry {:seq next-seq
                     :prev-cid (:head-cid head)
                     :op :restore
                     :snapshot-cid snap-cid}
              claimed-head {:seq next-seq
                            :head-cid nil
                            :gen next-gen
                            :memory-head-cid mem-head}]
          [(-> rolodex
               (assoc-in [:snapshots snap-cid] snap)
               (assoc :phase :claiming-cas
                      :generation next-gen
                      :pending {:seq next-seq
                                :gen next-gen
                                :entry entry
                                :claimed? false
                                :memory-head-cid mem-head}))
           [{:type :cas-head
             :gen next-gen
             :expected-head head
             :claimed-head claimed-head}]])))

    :cas-head-result
    (let [cb-gen (:gen event)]
      (cond
        (< cb-gen (:generation rolodex))
        (drop-stale-callback rolodex cb-gen :cas-head-result)

        (not= :claiming-cas (:phase rolodex))
        (halt-with-diagnose rolodex :unexpected-cas-head-result {:phase (:phase rolodex)})

        (not (:ok? event))
        (halt-with-diagnose rolodex :cas-head-lost {:reason (:reason event) :gen cb-gen})

        :else
        (let [pending (:pending rolodex)
              entry (:entry pending)
              payload-bytes (entry-signing-bytes entry)
              prev-committed (or (get-in rolodex [:head :head-cid])
                                 (:last-committed-cid rolodex)
                                 mc/zero-cid-hex)
              claimed-head {:seq (:seq pending)
                            :head-cid nil
                            :gen cb-gen
                            :memory-head-cid (:memory-head-cid pending)}]
          [(assoc rolodex
                  :phase :awaiting-sign
                  :head claimed-head
                  :last-committed-cid prev-committed
                  :pending (assoc pending :claimed? true))
           [{:type :sign
             :gen cb-gen
             :seq (:seq pending)
             :domain mc/rolodex-domain-tag
             :payload-bytes payload-bytes
             :entry entry}]])))

    :sign-result
    (let [cb-gen (:gen event)]
      (cond
        (< cb-gen (:generation rolodex))
        (drop-stale-callback rolodex cb-gen :sign-result)

        (not= :awaiting-sign (:phase rolodex))
        (halt-with-diagnose rolodex :unexpected-sign-result {:phase (:phase rolodex)})

        (or (not (:ok? event)) (nil? (:signature event)))
        (halt-with-diagnose rolodex :sign-failed {:error (:error event) :gen cb-gen})

        :else
        (let [pending (:pending rolodex)
              signed-entry (assoc (:entry pending) :signature (:signature event))
              encoded (fressian/encode-canonical signed-entry)
              declared-bytes (fressian/count-bytes encoded)
              cid (crypto/sha256-hex encoded)]
          (if (> declared-bytes mc/max-blob-bytes)
            (halt-with-diagnose rolodex :blob-ceiling-exceeded
                                {:declared-bytes declared-bytes :ceiling mc/max-blob-bytes})
            [(assoc rolodex
                    :phase :awaiting-put
                    :pending (assoc pending :signed-entry signed-entry :cid cid))
             [{:type :cas-put
               :gen cb-gen
               :seq (:seq pending)
               :cid cid
               :entry signed-entry
               :declared-bytes declared-bytes}]]))))

    :cas-put-result
    (let [cb-gen (:gen event)]
      (cond
        (< cb-gen (:generation rolodex))
        (drop-stale-callback rolodex cb-gen :cas-put-result)

        (not= :awaiting-put (:phase rolodex))
        (halt-with-diagnose rolodex :unexpected-cas-put-result {:phase (:phase rolodex)})

        (not (:ok? event))
        (halt-with-diagnose rolodex :cas-put-failed {:error (:error event) :gen cb-gen})

        :else
        (let [pending (:pending rolodex)
              signed-entry (:signed-entry pending)
              cid (:cid pending)
              seq-num (:seq pending)
              {:keys [state subnets open-sessions revoked-actions]}
              (apply-entry-delta rolodex signed-entry (:snapshots rolodex))
              entry-bytes (long (or (get-in signed-entry [:storage-accounting :bytes-at-rest]) 0))
              next-bytes (+ (long (or (:total-bytes-at-rest rolodex) 0)) entry-bytes)
              next-since-rot (inc (long (or (:entries-since-rotation rolodex) 0)))
              policy (:retention-policy rolodex)
              rotate? (and policy (>= next-since-rot (:rotate-every-entries policy)))
              new-head {:seq seq-num
                        :head-cid cid
                        :gen cb-gen
                        :memory-head-cid (:memory-head-cid pending)}
              rot-epoch (long (or (:rotation-epoch rolodex) 0))
              grace-n (long (or (:rotation-grace-epochs rolodex) mc/min-rotation-grace-epochs))
              effs (cond-> [{:type :emit
                             :gen cb-gen
                             :seq seq-num
                             :cid cid
                             :head new-head}]
                     rotate?
                     (conj {:type :rotate-log
                            :gen cb-gen
                            :seq seq-num
                            :rotation-epoch rot-epoch
                            :grace-epochs grace-n
                            :gc-eligible-at-epoch (+ rot-epoch grace-n)
                            :pinned-config-cid (:network-config-cid rolodex)
                            :entries-since-rotation next-since-rot
                            :total-bytes-at-rest next-bytes}))]
          [(assoc rolodex
                  :phase :idle
                  :pending nil
                  :head new-head
                  :last-committed-cid cid
                  :entries (assoc (:entries rolodex) seq-num signed-entry)
                  :cids (assoc (:cids rolodex) seq-num cid)
                  :state state
                  :subnets subnets
                  :open-sessions open-sessions
                  :revoked-actions revoked-actions
                  :total-bytes-at-rest next-bytes
                  :entries-since-rotation next-since-rot)
           effs])))

    :crash-and-restart
    (let [remote-head (or (:remote-head event) (:head rolodex))
          remote-seq (long (or (:seq remote-head) 0))
          remote-gen (long (or (:gen remote-head) 0))
          remote-cid (:head-cid remote-head)
          next-gen (inc (max (:generation rolodex) remote-gen))
          unclaimed-published? (and (pos? remote-seq) (nil? remote-cid))]
      (if unclaimed-published?
        ;; Burn the claimed-but-unpublished :seq so (key, :seq) is NEVER reused!
        (let [next-count (inc (:diagnostics-count rolodex))
              diag {:type :diagnose
                    :code :claimed-seq-burned
                    :burned-seq remote-seq
                    :resume-seq (inc remote-seq)
                    :generation next-gen
                    :count next-count}
              committed-cid (or (get-in rolodex [:head :head-cid])
                                (:last-committed-cid rolodex)
                                mc/zero-cid-hex)
              new-head {:seq remote-seq
                        :head-cid committed-cid
                        :gen next-gen
                        :memory-head-cid (or (:memory-head-cid remote-head)
                                             (get-in rolodex [:head :memory-head-cid]))}]
          [(assoc rolodex
                  :phase :idle
                  :pending nil
                  :generation next-gen
                  :head new-head
                  :burned-seqs (conj (:burned-seqs rolodex) remote-seq)
                  :diagnostics-count next-count
                  :last-error diag)
           [diag]])
        (let [new-head (assoc remote-head :gen next-gen)]
          [(assoc rolodex
                  :phase :idle
                  :pending nil
                  :generation next-gen
                  :head new-head)
           []])))

    :load-snapshot
    (let [declared-bytes (long (or (:declared-bytes event) 0))
          snap (:snapshot event)
          expected-cs (or (:expected-checksum event) (:snapshot-cid snap))
          actual-cs (when (map? snap) (snapshot-checksum snap))]
      (cond
        (> declared-bytes mc/max-snapshot-bytes)
        (halt-with-diagnose rolodex :snapshot-ceiling-exceeded
                            {:declared-bytes declared-bytes :ceiling mc/max-snapshot-bytes})

        (nil? snap)
        (halt-with-diagnose rolodex :missing-snapshot {})

        (and (some? expected-cs) (not= expected-cs actual-cs))
        (halt-with-diagnose rolodex :lkg-checksum-mismatch
                            {:expected-checksum expected-cs :actual-checksum actual-cs})

        :else
        (let [snap-cid (or (:snapshot-cid snap) actual-cs)]
          [(assoc-in rolodex [:snapshots snap-cid] (assoc snap :snapshot-cid snap-cid))
           []])))

    :apply-remote-entry
    (let [declared-bytes (long (or (:declared-bytes event) 0))
          entry (:entry event)
          cid (or (:cid event) (when entry (entry-cid entry)))
          entry-seq (long (or (:seq entry) 0))
          current-epoch (long (or (:rotation-epoch rolodex) 0))
          incoming-epoch (when (some? (or (:epoch entry) (:rotation-epoch entry)))
                           (long (or (:epoch entry) (:rotation-epoch entry))))
          head (:head rolodex)
          head-seq (long (:seq head))
          existing-cid (get-in rolodex [:cids entry-seq])]
      (cond
        ;; Pre-decode ceiling check BEFORE any decode/allocation
        (> declared-bytes mc/max-blob-bytes)
        (halt-with-diagnose rolodex :blob-ceiling-exceeded
                            {:declared-bytes declared-bytes :ceiling mc/max-blob-bytes})

        (false? (:sig-valid? event))
        (halt-with-diagnose rolodex :bad-signature {:seq entry-seq :cid cid})

        ;; Monotonic (epoch, seq) replay protection
        (and (some? incoming-epoch) (< incoming-epoch current-epoch))
        (halt-with-diagnose rolodex :epoch-replay-or-stale
                            {:incoming-epoch incoming-epoch :current-epoch current-epoch :seq entry-seq :cid cid})

        (and (<= entry-seq head-seq) existing-cid (not= existing-cid cid))
        (halt-with-diagnose rolodex :fork-detected
                            {:seq entry-seq :existing-cid existing-cid :incoming-cid cid})

        (<= entry-seq head-seq)
        (halt-with-diagnose rolodex :seq-replay-or-stale
                            {:seq entry-seq :head-seq head-seq :cid cid})

        (and (not= (:prev-cid entry) (:head-cid head))
             (not (contains? (:burned-seqs rolodex) (dec entry-seq))))
        (halt-with-diagnose rolodex :missing-prev-cid
                            {:seq entry-seq :expected-prev (:head-cid head) :actual-prev (:prev-cid entry)})

        (and (= :restore (:op entry))
             (nil? (get-in rolodex [:snapshots (:snapshot-cid entry)])))
        (halt-with-diagnose rolodex :missing-snapshot
                            {:seq entry-seq :snapshot-cid (:snapshot-cid entry)})

        :else
        (let [{:keys [state subnets open-sessions revoked-actions]}
              (apply-entry-delta rolodex entry (:snapshots rolodex))
              entry-bytes (long (or (get-in entry [:storage-accounting :bytes-at-rest]) 0))
              next-bytes (+ (long (or (:total-bytes-at-rest rolodex) 0)) entry-bytes)
              next-since-rot (inc (long (or (:entries-since-rotation rolodex) 0)))
              next-epoch (if (and (some? incoming-epoch) (> incoming-epoch current-epoch))
                           incoming-epoch
                           current-epoch)
              next-gen (if (= :restore (:op entry))
                         (inc (:generation rolodex))
                         (:generation rolodex))
              new-head (assoc head :seq entry-seq :head-cid cid :gen next-gen)]
          [(assoc rolodex
                  :phase :idle
                  :generation next-gen
                  :rotation-epoch next-epoch
                  :head new-head
                  :last-committed-cid cid
                  :entries (assoc (:entries rolodex) entry-seq entry)
                  :cids (assoc (:cids rolodex) entry-seq cid)
                  :state state
                  :subnets subnets
                  :open-sessions open-sessions
                  :revoked-actions revoked-actions
                  :total-bytes-at-rest next-bytes
                  :entries-since-rotation next-since-rot)
           []])))

    ;; Unknown event
    (halt-with-diagnose rolodex :unknown-event {:event-type (:type event)})))
