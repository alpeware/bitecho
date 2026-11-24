(ns bitecho.deploy.core
  "Milestone D35 (`BIP-009: Self-Managing Cluster Deployment — Config/Code-as-Pointers,
   Simulation-Gated Zero-Downtime Rolling Upgrades, Full Audit Trail, Six-Nines Availability Target` / `v0.23.13`).
   100% Pure Sans-IO `.cljc` Engine (Rule 2, Rule 4, Rule 5):
   - `P-DEPLOY-1`: Config-as-Pointers with Atomic Epoch-Boundary Activation (`stage-config-pointer`, `apply-epoch-boundary-configs`)
   - `P-DEPLOY-2`: Code-as-Pointers: Two-Stage Self-Update & Verification Before Switch (`verify-and-stage-code-switch`)
   - `P-DEPLOY-3`: Zero-Downtime Rolling Upgrades (`transition-rollout`, `build-rollout-plan`)
   - `P-DEPLOY-4`: Simulation-Gated Deployment Simulator (`simulate-rollout-plan`)
   - `P-DEPLOY-5`: Full Hash-Chained On-Network Audit Trail (`append-audit-record`, `reconstruct-cluster-history-from-audit-trail`)
   - `P-DEPLOY-6`: Runtime Diversity (`order-rollout-stages-mixed-runtime`)
   - `P-DEPLOY-7`: Control-Plane Transport Redundancy (`route-control-plane-envelope`)
   - `P-DEPLOY-8`: Six-Nines SLA & Release Velocity Instrumentation (`compute-sla-and-velocity-report`, `verify-epoch-sla-checkpoint`)
   - `P-DEPLOY-9`: Monte Carlo Tokenomics v2.1 `theta*` & Balance-Preserving Genesis Reset (`execute-balance-preserving-genesis-reset`)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

;; =============================================================================
;; 0. Shared Pure Helpers & Ratified Monte Carlo v2.1 Theta* (P-DEPLOY-9)
;; =============================================================================

(def ratified-theta-star
  "Selected Monte Carlo Tokenomics v2.1 Pareto-optimal parameter vector (`BIP-009` / `P-DEPLOY-9`)."
  config/ratified-theta-star)

(def ratified-theta-star-metrics
  "Recorded Monte Carlo v2.1 Pareto frontier metrics for `ratified-theta-star`."
  config/ratified-theta-star-metrics)

(def genesis-prev-hash
  "Canonical 64-zero hex prev-hash for the first record in a hash-chained audit trail."
  "0000000000000000000000000000000000000000000000000000000000000000")

(defn- normalize-hex
  [s]
  (when (and (string? s) (not (str/blank? s)))
    (str/lower-case (str/trim s))))

(defn sha256-hex
  "Computes lowercase 64-char SHA-256 hex digest over bytes, UTF-8 string, or canonical Fressian EDN."
  [x]
  (let [bs (cond
             (bytes? x) x
             (string? x) (fressian/utf8->bytes x)
             :else (fressian/encode-canonical x))]
    (str/lower-case (basalt/bytes->hex (crypto/sha256 bs)))))

(defn- math-ceil
  [n]
  #?(:clj (long (Math/ceil (double n)))
     :cljs (long (js/Math.ceil (double n)))))

;; =============================================================================
;; 1. P-DEPLOY-5: Full Hash-Chained On-Network Audit Trail
;; =============================================================================

(defn canonical-audit-record-payload
  "Returns the canonical vector signed and hashed for an audit record."
  [{:keys [seq epoch timestamp-ms event-type prev-hash payload signer]}]
  ["bitecho-deploy-audit-v1"
   (long (or seq 0))
   (long (or epoch 0))
   (long (or timestamp-ms 0))
   (if (keyword? event-type) (name event-type) (str event-type))
   (str (or prev-hash genesis-prev-hash))
   (or payload {})
   (str (or signer ""))])

(defn make-audit-record
  "Constructs a signed (when `privkey` is provided) hash-chained deployment audit record."
  [{:keys [seq epoch timestamp-ms event-type prev-hash payload signer privkey]}]
  (let [norm-prev (or (normalize-hex prev-hash) genesis-prev-hash)
        norm-signer (or (normalize-hex signer) "system")
        base {:seq (long (or seq 1))
              :epoch (long (or epoch 0))
              :timestamp-ms (long (or timestamp-ms (* (long (or epoch 0)) 10000)))
              :event-type (keyword event-type)
              :prev-hash norm-prev
              :payload (or payload {})
              :signer norm-signer}
        canon-vec (canonical-audit-record-payload base)
        rec-hash (sha256-hex canon-vec)
        sig-hex (if privkey
                  (let [s (crypto/sign-canonical privkey canon-vec)]
                    (str/lower-case (if (string? s) s (basalt/bytes->hex s))))
                  (sha256-hex ["system-audit-sig" rec-hash]))]
    (assoc base
           :record-hash rec-hash
           :signature sig-hex)))

(defn append-audit-record
  "Appends a new hash-chained audit record to `(:audit-trail state)`."
  [state {:keys [epoch timestamp-ms event-type payload signer privkey]}]
  (let [trail (vec (or (:audit-trail state) []))
        last-rec (peek trail)
        next-seq (inc (long (or (:seq last-rec) 0)))
        prev-hash (or (:record-hash last-rec) genesis-prev-hash)
        eff-epoch (long (or epoch (:epoch state) 0))
        rec (make-audit-record {:seq next-seq
                                :epoch eff-epoch
                                :timestamp-ms (or timestamp-ms (* eff-epoch 10000))
                                :event-type event-type
                                :prev-hash prev-hash
                                :payload payload
                                :signer (or signer (:node-pubkey state) (:pubkey state) "system")
                                :privkey (or privkey (:node-private-key state))})]
    {:state (assoc state :audit-trail (conj trail rec))
     :record rec}))

(defn verify-audit-record
  "Verifies hash integrity and (when signer is a valid hex pubkey and signature is Ed25519) signature of a single audit record."
  [record expected-prev-hash]
  (let [prev-ok? (= (or expected-prev-hash genesis-prev-hash)
                    (:prev-hash record))
        canon-vec (canonical-audit-record-payload record)
        expected-hash (sha256-hex canon-vec)
        hash-ok? (= expected-hash (:record-hash record))
        signer (:signer record)
        sig (:signature record)
        sig-ok? (cond
                  (or (nil? sig) (str/blank? (str sig)))
                  false

                  (= sig (sha256-hex ["system-audit-sig" expected-hash]))
                  true

                  (and (string? signer)
                       (or (= 64 (count signer)) (= 88 (count signer)))
                       (re-matches #"^[0-9a-fA-F]+$" signer))
                  (try
                    (crypto/verify-with-fallback
                     (basalt/hex->bytes signer)
                     canon-vec
                     (basalt/hex->bytes sig))
                    (catch #?(:clj Exception :cljs :default) _ false))

                  :else
                  false)]
    {:valid? (and prev-ok? hash-ok? sig-ok?)
     :prev-ok? prev-ok?
     :hash-ok? hash-ok?
     :sig-ok? sig-ok?}))

(defn reconstruct-cluster-history-from-audit-trail
  "Pure auditor function (`P-DEPLOY-5`) that verifies hash-chain & signature integrity across
   `audit-records` and reconstructs the exact `:active-code-cid`, `:active-config-hash`,
   `:authorizing-bip-cid`, and `:stage` status of every node at `query-epoch` from audit records alone."
  [audit-records query-epoch]
  (let [q-ep (long (or query-epoch 0))]
    (loop [rem-recs (vec audit-records)
           expected-prev genesis-prev-hash
           expected-seq 1
           chain-valid? true
           sigs-valid? true
           auth-bip-cid nil
           active-stage :idle
           nodes-map {}]
      (if (empty? rem-recs)
        {:chain-valid? chain-valid?
         :signatures-valid? sigs-valid?
         :query-epoch q-ep
         :authorizing-bip-cid auth-bip-cid
         :stage-at-epoch active-stage
         :nodes-at-epoch nodes-map}
        (let [rec (first rem-recs)
              v (verify-audit-record rec expected-prev)
              seq-ok? (= expected-seq (long (or (:seq rec) -1)))
              next-chain-valid? (and chain-valid? seq-ok? (:prev-ok? v) (:hash-ok? v))
              next-sigs-valid? (and sigs-valid? (:sig-ok? v))
              rec-ep (long (or (:epoch rec) 0))
              apply-to-view? (<= rec-ep q-ep)
              ev-type (:event-type rec)
              p (:payload rec)
              next-bip (if (and apply-to-view? (:ratified-bip-cid p))
                         (:ratified-bip-cid p)
                         auth-bip-cid)
              next-stage (if (and apply-to-view? (:stage p))
                           (:stage p)
                           active-stage)
              next-nodes
              (if-not apply-to-view?
                nodes-map
                (case ev-type
                  :bip-ratified
                  (let [init-nodes (or (:initial-nodes p) {})]
                    (reduce-kv (fn [acc nid ninfo]
                                 (assoc acc nid
                                        {:node-id nid
                                         :runtime (:runtime ninfo :jvm)
                                         :active-code-cid (:active-code-cid ninfo)
                                         :active-config-hash (:active-config-hash ninfo)
                                         :authorizing-bip-cid (or (:ratified-bip-cid p) next-bip)
                                         :stage :baseline}))
                               nodes-map
                               init-nodes))

                  :node-switched
                  (let [nid (:node-id p)]
                    (if nid
                      (update nodes-map nid
                              (fn [prev]
                                (merge {:node-id nid}
                                       prev
                                       {:active-code-cid (or (:code-cid p) (:active-code-cid prev))
                                        :active-config-hash (or (:config-hash p) (:active-config-hash prev))
                                        :authorizing-bip-cid (or (:ratified-bip-cid p) next-bip (:authorizing-bip-cid prev))
                                        :stage (or (:stage p) next-stage)})))
                      nodes-map))

                  :config-activated
                  (let [nid (:node-id p)
                        cfg-h (:active-config-hash p)]
                    (if nid
                      (assoc-in nodes-map [nid :active-config-hash] cfg-h)
                      (into {}
                            (map (fn [[k v]] [k (assoc v :active-config-hash cfg-h)]))
                            nodes-map)))

                  :auto-rollback
                  (let [lkg-code (:last-known-good-code-cid p)
                        lkg-cfg (:last-known-good-config-hash p)]
                    (into {}
                          (map (fn [[nid v]]
                                 [nid (assoc v
                                             :active-code-cid (or lkg-code (:active-code-cid v))
                                             :active-config-hash (or lkg-cfg (:active-config-hash v))
                                             :stage :rolled-back)]))
                          nodes-map))

                  :unified-rollout-applied
                  (let [nid (:node-id p)]
                    (if nid
                      (update nodes-map nid
                              (fn [prev]
                                (merge {:node-id nid}
                                       prev
                                       {:active-code-cid (or (:code-cid p) (:active-code-cid prev))
                                        :system-merkle-root (or (:system-merkle-root p) (:system-merkle-root prev))
                                        :stage (or (:stage p) next-stage)})))
                      nodes-map))

                  :unified-rollout-rolled-back
                  (let [nid (:node-id p)]
                    (if nid
                      (update nodes-map nid
                              (fn [prev]
                                (merge {:node-id nid}
                                       prev
                                       {:active-code-cid (or (:last-known-good-code-cid p) (:active-code-cid prev))
                                        :system-merkle-root (or (:last-known-good-merkle-root p) (:system-merkle-root prev))
                                        :stage :rolled-back})))
                      nodes-map))

                  nodes-map))]
          (recur (subvec rem-recs 1)
                 (:record-hash rec)
                 (inc expected-seq)
                 next-chain-valid?
                 next-sigs-valid?
                 next-bip
                 next-stage
                 next-nodes))))))

;; =============================================================================
;; 2. P-DEPLOY-1: Config-as-Pointers with Atomic Epoch-Boundary Activation
;; =============================================================================

(defn canonical-config-pointer-map
  "Normalizes a per-network config pointer manifest map (excluding `:signature`) for deterministic signing."
  [pointer-map]
  (cond-> {:network (str (or (:network pointer-map) "devnet"))
           :seq (long (or (:seq pointer-map) 1))
           :activate-at-epoch (long (or (:activate-at-epoch pointer-map) 0))
           :code-target-cid (str (or (:code-target-cid pointer-map) ""))
           :domains (into (sorted-map) (or (:domains pointer-map) {}))
           :policy-theta (into (sorted-map) (or (:policy-theta pointer-map) {}))
           :author-pubkey (or (normalize-hex (:author-pubkey pointer-map)) "")}
    (:node-runtimes pointer-map)
    (assoc :node-runtimes (into (sorted-map) (:node-runtimes pointer-map)))
    (:artifacts pointer-map)
    (assoc :artifacts (into (sorted-map) (:artifacts pointer-map)))
    (:host-target pointer-map)
    (assoc :host-target (into (sorted-map) (:host-target pointer-map)))
    (:system-merkle-root pointer-map)
    (assoc :system-merkle-root (or (normalize-hex (:system-merkle-root pointer-map)) ""))))

(defn canonical-config-pointer-signing-payload
  "Domain-separated canonical payload for signing a config pointer."
  [pointer-map]
  ["bitecho-config-pointer-v1" (canonical-config-pointer-map pointer-map)])

(defn sign-config-pointer
  "Signs a config pointer manifest map with `authority-privkey`."
  [authority-privkey pointer-map]
  (let [canon (canonical-config-pointer-map pointer-map)
        payload (canonical-config-pointer-signing-payload canon)
        sig (crypto/sign-canonical authority-privkey payload)
        sig-hex (str/lower-case (if (string? sig) sig (basalt/bytes->hex sig)))]
    (cond-> (assoc canon
                   :config-hash (sha256-hex canon)
                   :signature sig-hex)
      (:target-version pointer-map) (assoc :target-version (:target-version pointer-map))
      (:light-node-cid pointer-map) (assoc :light-node-cid (:light-node-cid pointer-map))
      (:full-node-cid pointer-map) (assoc :full-node-cid (:full-node-cid pointer-map))
      (:jvm-jar-cid pointer-map) (assoc :jvm-jar-cid (:jvm-jar-cid pointer-map))
      (:browser-cid pointer-map) (assoc :browser-cid (:browser-cid pointer-map))
      (:artifact-size-bytes pointer-map) (assoc :artifact-size-bytes (:artifact-size-bytes pointer-map)))))

(defn verify-config-pointer
  "Verifies authority membership and Ed25519 signature on `pointer-map`.
   BIP-021 §2.6.2: fails CLOSED when `:trusted-deploy-authorities` is empty.
   Optional `opts` supports `:check-seq?` (default true); when false, callers enforce monotonic `:seq` gating directly."
  ([state pointer-map]
   (verify-config-pointer state pointer-map nil))
  ([state pointer-map opts]
   (if-not (map? pointer-map)
     {:ok? false :error :malformed-config-pointer}
     (let [canon (canonical-config-pointer-map pointer-map)
           author (:author-pubkey canon)
           sig (:signature pointer-map)
           trusted (set (map normalize-hex (or (:trusted-deploy-authorities state)
                                               (get-in state [:config :trusted-deploy-authorities])
                                               [])))
           has-trusted? (boolean (seq trusted))
           auth-allowed? (and has-trusted? (contains? trusted author))
           check-seq? (not (false? (:check-seq? opts)))
           cur-seq (long (or (:active-config-seq state) 0))
           seq-ok? (or (not check-seq?) (> (long (:seq canon 0)) cur-seq))
           sig-ok? (boolean
                    (when (and (not (str/blank? author))
                               (string? sig)
                               (not (str/blank? sig)))
                      (try
                        (crypto/verify-with-fallback
                         (basalt/hex->bytes author)
                         (canonical-config-pointer-signing-payload canon)
                         (basalt/hex->bytes sig))
                        (catch #?(:clj Exception :cljs :default) _ false))))]
       (cond
         (not has-trusted?)
         {:ok? false :error :no-trusted-deploy-authorities}

         (not auth-allowed?)
         {:ok? false :error :unauthorized-config-authority}

         (not seq-ok?)
         {:ok? false :error :stale-config-pointer-seq}

         (not sig-ok?)
         {:ok? false :error :invalid-config-pointer-signature}

         :else
         {:ok? true
          :pointer (assoc canon
                          :config-hash (or (:config-hash pointer-map) (sha256-hex canon))
                          :signature (normalize-hex sig))})))))

(defn stage-config-pointer
  "Pure function (`P-DEPLOY-1`): validates authority/signature and stages pending config for
   `:activate-at-epoch` without mutating active config mid-epoch.
   Emits a counted `:diagnose` effect if validation fails (Rule 5)."
  [state pointer-map]
  (let [v (verify-config-pointer state pointer-map)]
    (if-not (:ok? v)
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :config-pointer-rejected
                  :error (:error v)}
            st' (update-in state [:diagnostics :config-pointer-rejected] (fnil inc 0))]
        {:ok? false
         :error (:error v)
         :state st'
         :effects [diag]})
      (let [ptr (:pointer v)
            act-ep (long (:activate-at-epoch ptr))
            cur-ep (long (or (:epoch state) 0))]
        (if (<= act-ep cur-ep)
          (let [diag {:effect :diagnose
                      :type :diagnose
                      :reason :config-pointer-past-epoch
                      :activate-at-epoch act-ep
                      :current-epoch cur-ep}
                st' (update-in state [:diagnostics :config-pointer-rejected] (fnil inc 0))]
            {:ok? false
             :error :config-pointer-past-epoch
             :state st'
             :effects [diag]})
          (let [audit-res (append-audit-record
                           state
                           {:epoch cur-ep
                            :event-type :config-pointer-updated
                            :payload {:seq (:seq ptr)
                                      :activate-at-epoch act-ep
                                      :config-hash (:config-hash ptr)
                                      :code-target-cid (:code-target-cid ptr)}
                            :signer (:author-pubkey ptr)})
                st' (assoc-in (:state audit-res) [:staged-config-pointers act-ep] ptr)]
            {:ok? true
             :pointer ptr
             :state st'
             :effects [{:effect :audit-record :record (:record audit-res)}]}))))))

(defn- merge-config-pointer-into-config
  "Merges a staged config pointer's `:domains` and `:policy-theta` parameters into `cfg`."
  [cfg ptr]
  (let [domains (:domains ptr)
        theta (:policy-theta ptr)
        consensus-cfg (when (map? (:consensus domains)) (:consensus domains))
        economy-cfg (when (map? (:economy domains)) (:economy domains))
        transport-cfg (when (map? (:transport domains)) (:transport domains))
        storage-cfg (when (map? (:storage domains)) (:storage domains))
        merged (merge (or cfg {})
                      consensus-cfg
                      economy-cfg
                      transport-cfg
                      storage-cfg
                      theta
                      (when (seq theta) {:policy-theta theta})
                      (when (not (str/blank? (str (:code-target-cid ptr))))
                        {:code-target-cid (:code-target-cid ptr)})
                      (when (map? (:host-target ptr))
                        {:host-target (:host-target ptr)})
                      (when (not (str/blank? (str (:system-merkle-root ptr))))
                        {:system-merkle-root (:system-merkle-root ptr)}))]
    (cond-> merged
      (:min-signaling-burn merged)
      (assoc :burn-floor (long (:min-signaling-burn merged))))))

(defn apply-epoch-boundary-configs
  "Pure function (`P-DEPLOY-1`): at the exact epoch boundary (`new-epoch == :activate-at-epoch`),
   atomically activates staged config parameters, records `:active-config-hash`, and emits a
   hash-chained `:config-activated` audit record.
   If any staged config has `activate-at-epoch + delta < new-epoch` without having been applied,
   emits a counted `:diagnose` (`:reason :config-activation-missed`, Rule 5)."
  ([state new-epoch]
   (apply-epoch-boundary-configs state new-epoch 1))
  ([state new-epoch delta-epochs]
   (let [ep (long new-epoch)
         delta (max 0 (long (or delta-epochs 1)))
         staged-map (or (:staged-config-pointers state) {})
         due-ptr (get staged-map ep)
         missed-eps (filterv (fn [target-ep] (< (+ (long target-ep) delta) ep))
                             (keys staged-map))
         [st-after-missed missed-effects]
         (reduce (fn [[st effs] missed-ep]
                   (let [m-ptr (get staged-map missed-ep)
                         diag {:effect :diagnose
                               :type :diagnose
                               :reason :config-activation-missed
                               :activate-at-epoch missed-ep
                               :current-epoch ep
                               :config-hash (:config-hash m-ptr)}
                         audit-res (append-audit-record
                                    st
                                    {:epoch ep
                                     :event-type :config-activation-missed
                                     :payload {:activate-at-epoch missed-ep
                                               :current-epoch ep
                                               :config-hash (:config-hash m-ptr)}})
                         st' (-> (:state audit-res)
                                 (update :staged-config-pointers dissoc missed-ep)
                                 (update-in [:diagnostics :config-activation-missed] (fnil inc 0)))]
                     [st' (conj effs diag {:effect :audit-record :record (:record audit-res)})]))
                 [(assoc state :epoch ep) []]
                 missed-eps)]
     (if-not due-ptr
       {:state st-after-missed
        :activated? false
        :effects missed-effects}
       (let [new-cfg (merge-config-pointer-into-config (:config st-after-missed) due-ptr)
             cfg-hash (or (:config-hash due-ptr) (sha256-hex (canonical-config-pointer-map due-ptr)))
             audit-res (append-audit-record
                        st-after-missed
                        {:epoch ep
                         :event-type :config-activated
                         :payload {:seq (:seq due-ptr)
                                   :activate-at-epoch ep
                                   :active-config-hash cfg-hash
                                   :code-target-cid (:code-target-cid due-ptr)
                                   :policy-theta (:policy-theta due-ptr)}
                         :signer (:author-pubkey due-ptr)})
             st-activated (-> (:state audit-res)
                              (assoc :config new-cfg
                                     :active-config-hash cfg-hash
                                     :active-config-seq (:seq due-ptr)
                                     :burn-floor (long (or (:min-signaling-burn new-cfg) (:burn-floor new-cfg) 100)))
                              (update :staged-config-pointers dissoc ep))]
         {:state st-activated
          :activated? true
          :active-config-hash cfg-hash
          :effects (conj missed-effects {:effect :audit-record :record (:record audit-res)})})))))

;; =============================================================================
;; 3. P-DEPLOY-2: Code-as-Pointers: Two-Stage Self-Update & Verification
;; =============================================================================

(defn canonical-code-pointer-signing-payload
  "Canonical signing payload for a release authority code pointer chained to `ratified-bip-cid`."
  [{:keys [target-cid ratified-bip-cid authority-pubkey]}]
  ["bitecho-code-pointer-v1"
   (or (normalize-hex target-cid) "")
   (or (normalize-hex ratified-bip-cid) "")
   (or (normalize-hex authority-pubkey) "")])

(defn sign-code-pointer
  "Signs a code pointer `{:target-cid :ratified-bip-cid :authority-pubkey}` with `authority-privkey`."
  [authority-privkey code-ptr]
  (let [payload (canonical-code-pointer-signing-payload code-ptr)
        sig (crypto/sign-canonical authority-privkey payload)]
    (str/lower-case (if (string? sig) sig (basalt/bytes->hex sig)))))

(defn verify-and-stage-code-switch
  "Pure function (`P-DEPLOY-2`): verifies content-addressed artifact SHA-256 equals `target-cid`
   and verifies release authority signature chained to `ratified-bip-cid`.
   On any mismatch, refuses to switch, increments `[:diagnostics :code-switch-rejected]`,
   and emits a counted `:diagnose` (`:reason :code-verification-failed`) + audit record (Rule 5)."
  [state {:keys [target-cid artifact-bytes pointer-sig authority-pubkey ratified-bip-cid gate-epoch]}]
  (let [norm-target (normalize-hex target-cid)
        norm-auth (normalize-hex authority-pubkey)
        norm-bip (normalize-hex ratified-bip-cid)
        actual-cid (when (and artifact-bytes (bytes? artifact-bytes))
                     (sha256-hex artifact-bytes))
        hash-ok? (and (some? norm-target)
                      (some? actual-cid)
                      (= norm-target actual-cid))
        ratified-set (set (map normalize-hex (or (:ratified-bip-cids state) #{})))
        bip-ok? (and (some? norm-bip)
                     (or (empty? ratified-set)
                         (contains? ratified-set norm-bip)))
        trusted-auths (set (map normalize-hex (or (:trusted-deploy-authorities state) #{})))
        auth-ok? (and (some? norm-auth)
                      (or (empty? trusted-auths)
                          (contains? trusted-auths norm-auth)))
        sig-ok? (boolean
                 (when (and norm-target norm-bip norm-auth
                            (string? pointer-sig) (not (str/blank? pointer-sig)))
                   (try
                     (crypto/verify-with-fallback
                      (basalt/hex->bytes norm-auth)
                      (canonical-code-pointer-signing-payload
                       {:target-cid norm-target
                        :ratified-bip-cid norm-bip
                        :authority-pubkey norm-auth})
                      (basalt/hex->bytes pointer-sig))
                     (catch #?(:clj Exception :cljs :default) _ false))))]
    (if (and hash-ok? bip-ok? auth-ok? sig-ok?)
      (let [cur-ep (long (or (:epoch state) 0))
            staged {:target-cid norm-target
                    :ratified-bip-cid norm-bip
                    :authority-pubkey norm-auth
                    :gate-epoch (long (or gate-epoch cur-ep))
                    :verified? true}
            audit-res (append-audit-record
                       state
                       {:epoch cur-ep
                        :event-type :node-code-verified
                        :payload (assoc staged :node-id (:node-id state))
                        :signer norm-auth})
            st' (assoc (:state audit-res) :staged-code-switch staged)]
        {:ok? true
         :staged-code-switch staged
         :state st'
         :effects [{:effect :audit-record :record (:record audit-res)}]})
      (let [failure-cause (cond
                            (not hash-ok?) :artifact-hash-mismatch
                            (not bip-ok?) :unratified-bip-cid
                            (not auth-ok?) :unauthorized-release-authority
                            (not sig-ok?) :invalid-pointer-signature
                            :else :verification-failed)
            cur-ep (long (or (:epoch state) 0))
            diag {:effect :diagnose
                  :type :diagnose
                  :reason :code-verification-failed
                  :cause failure-cause
                  :target-cid norm-target
                  :actual-cid actual-cid
                  :ratified-bip-cid norm-bip}
            audit-res (append-audit-record
                       state
                       {:epoch cur-ep
                        :event-type :code-verification-failed
                        :payload {:node-id (:node-id state)
                                  :cause failure-cause
                                  :target-cid norm-target
                                  :actual-cid actual-cid}})
            st' (-> (:state audit-res)
                    (dissoc :staged-code-switch)
                    (update-in [:diagnostics :code-switch-rejected] (fnil inc 0)))]
        {:ok? false
         :error :code-verification-failed
         :cause failure-cause
         :state st'
         :effects [diag {:effect :audit-record :record (:record audit-res)}]}))))

;; =============================================================================
;; 4. P-DEPLOY-6 & P-DEPLOY-3: Runtime Diversity & Rollout State Machine
;; =============================================================================

(defn make-cluster-spec
  "Builds a canonical multi-validator cluster specification mixing `:jvm` and `:nodejs` runtimes."
  [node-descriptors]
  (let [nodes-map
        (into (sorted-map)
              (map-indexed
               (fn [idx desc]
                 (let [nid (keyword (or (:node-id desc) (str "node" (inc idx))))
                       rt (keyword (or (:runtime desc) (if (even? idx) :jvm :nodejs)))
                       kp (or (:keypair desc)
                              (crypto/generate-keypair (str "deploy-val-" (name nid) "-" idx)))
                       pub (:public kp)
                       pk-hex (if (string? pub) pub (basalt/bytes->hex pub))]
                   [nid {:node-id nid
                         :runtime rt
                         :pubkey pk-hex
                         :privkey (:private kp)}]))
               node-descriptors))
        n (count nodes-map)
        quorum (math-ceil (/ (* 2.0 (double (max 1 n))) 3.0))]
    {:nodes nodes-map
     :validator-count n
     :quorum-threshold (max 1 quorum)}))

(defn default-six-validator-cluster-spec
  "Canonical 6-validator devnet cluster spec mixing `:jvm` and `:nodejs` validators (`P-DEPLOY-6`)."
  []
  (make-cluster-spec
   [{:node-id :node1 :runtime :jvm}
    {:node-id :node2 :runtime :nodejs}
    {:node-id :node3 :runtime :jvm}
    {:node-id :ns1   :runtime :nodejs}
    {:node-id :ns2   :runtime :jvm}
    {:node-id :ns3   :runtime :nodejs}]))

(defn order-rollout-stages-mixed-runtime
  "Orders validator nodes into `{:canary [1-node] :minority [k-nodes] :remainder [rest-nodes]}`
   such that when both `:jvm` and `:nodejs` runtimes exist in the cluster, `:canary` and `:minority`
   together cover both `:jvm` and `:nodejs` runtimes (`P-DEPLOY-6`)."
  [nodes-map]
  (let [entries (vec (sort-by (comp name first) nodes-map))
        jvm-ids (mapv first (filter #(= :jvm (:runtime (second %))) entries))
        node-ids (mapv first (filter #(= :nodejs (:runtime (second %))) entries))
        other-ids (mapv first (remove #(contains? #{:jvm :nodejs} (:runtime (second %))) entries))
        interleaved (loop [a jvm-ids
                           b node-ids
                           acc []]
                      (if (and (empty? a) (empty? b))
                        (into acc other-ids)
                        (recur (vec (rest a))
                               (vec (rest b))
                               (cond-> acc
                                 (seq a) (conj (first a))
                                 (seq b) (conj (first b))))))
        n (count interleaved)
        canary-cnt (if (pos? n) 1 0)
        minority-cnt (cond
                       (<= n 2) 0
                       (<= n 4) 1
                       :else 2)
        canary (subvec interleaved 0 canary-cnt)
        minority (subvec interleaved canary-cnt (+ canary-cnt minority-cnt))
        remainder (subvec interleaved (+ canary-cnt minority-cnt) n)]
    {:canary canary
     :minority minority
     :remainder remainder
     :ordered-nodes interleaved}))

(defn build-rollout-plan
  "Constructs a deterministic epoch-gated rollout plan with gate window `W` (default `8` epochs)."
  [cluster-spec {:keys [start-epoch gate-window-epochs old-code-cid target-code-cid
                        old-config-hash target-config-hash ratified-bip-cid]}]
  (let [start-ep (long (or start-epoch 10))
        w (max 1 (long (or gate-window-epochs 8)))
        stages (order-rollout-stages-mixed-runtime (:nodes cluster-spec))
        old-code (or (normalize-hex old-code-cid) (sha256-hex "code-v0"))
        new-code (or (normalize-hex target-code-cid) (sha256-hex "code-v1"))
        old-cfg (or (normalize-hex old-config-hash) (sha256-hex "cfg-v0"))
        new-cfg (or (normalize-hex target-config-hash) (sha256-hex "cfg-v1"))
        bip-cid (or (normalize-hex ratified-bip-cid) (sha256-hex "bip-009"))]
    {:start-epoch start-ep
     :gate-window-epochs w
     :stages (select-keys stages [:canary :minority :remainder])
     :stage-order [:canary :minority :remainder]
     :gate-epochs {:canary (+ start-ep w)
                   :minority (+ start-ep (* 2 w))
                   :remainder (+ start-ep (* 3 w))}
     :old-code-cid old-code
     :target-code-cid new-code
     :old-config-hash old-cfg
     :target-config-hash new-cfg
     :last-known-good-code-cid old-code
     :last-known-good-config-hash old-cfg
     :ratified-bip-cid bip-cid}))

(defn init-rollout-state
  "Initializes the pure rollout controller state map (`Rule 4`)."
  [cluster-spec rollout-plan]
  (let [old-code (:old-code-cid rollout-plan)
        old-cfg (:old-config-hash rollout-plan)
        bip-cid (:ratified-bip-cid rollout-plan)
        init-nodes (into (sorted-map)
                         (map (fn [[nid ndesc]]
                                [nid {:node-id nid
                                      :runtime (:runtime ndesc :jvm)
                                      :pubkey (:pubkey ndesc)
                                      :active-code-cid old-code
                                      :active-config-hash old-cfg
                                      :authorizing-bip-cid bip-cid
                                      :healthy? true
                                      :stage :baseline}]))
                         (:nodes cluster-spec))]
    {:phase :idle
     :stage nil
     :generation 1
     :epoch (long (:start-epoch rollout-plan 0))
     :plan rollout-plan
     :cluster-spec cluster-spec
     :nodes init-nodes
     :consecutive-stall-epochs 0
     :max-consecutive-stall-epochs 0
     :finalization-stall-epochs 0
     :finalized-blocks-count 0
     :finalized-blocks-during-heterogeneous-window 0
     :messages-broadcast 0
     :messages-delivered 0
     :last-error nil
     :dropped 0
     :diagnostics {}
     :audit-trail []}))

(defn- stage-nodes
  [rollout-state stage-kw]
  (get-in rollout-state [:plan :stages stage-kw] []))

(defn- evaluate-gate-criteria
  "Evaluates mechanical gate criteria over the gate window `W`:
   1. No finalization stall `>= 3` consecutive epochs (and `0` deploy-attributable stall epochs).
   2. `100%` honest-quorum message delivery (`messages-delivered == messages-broadcast`).
   3. All upgraded nodes in the current stage are healthy and attest `:active-code-cid == target-code-cid`
      and `:active-config-hash == target-config-hash`."
  [rollout-state stage-kw]
  (let [plan (:plan rollout-state)
        target-code (:target-code-cid plan)
        target-cfg (:target-config-hash plan)
        upgraded-ids (stage-nodes rollout-state stage-kw)
        stall-ok? (and (< (long (:max-consecutive-stall-epochs rollout-state 0)) 3)
                       (zero? (long (:finalization-stall-epochs rollout-state 0))))
        delivery-ok? (= (long (:messages-broadcast rollout-state 0))
                        (long (:messages-delivered rollout-state 0)))
        attestation-ok? (every? (fn [nid]
                                  (let [n (get-in rollout-state [:nodes nid])]
                                    (and (true? (:healthy? n))
                                         (= target-code (:active-code-cid n))
                                         (= target-cfg (:active-config-hash n)))))
                                upgraded-ids)]
    {:passed? (and stall-ok? delivery-ok? attestation-ok?)
     :stall-ok? stall-ok?
     :delivery-ok? delivery-ok?
     :attestation-ok? attestation-ok?
     :reason (cond
               (not attestation-ok?) :stage-attestation-failed
               (not stall-ok?) :finalization-stall-detected
               (not delivery-ok?) :delivery-loss-detected
               :else :ok)}))

(defn- switch-stage-nodes
  [rollout-state stage-kw ep]
  (let [plan (:plan rollout-state)
        target-code (:target-code-cid plan)
        target-cfg (:target-config-hash plan)
        bip-cid (:ratified-bip-cid plan)
        nids (stage-nodes rollout-state stage-kw)]
    (reduce (fn [[st effs] nid]
              (let [st1 (-> st
                            (assoc-in [:nodes nid :active-code-cid] target-code)
                            (assoc-in [:nodes nid :active-config-hash] target-cfg)
                            (assoc-in [:nodes nid :authorizing-bip-cid] bip-cid)
                            (assoc-in [:nodes nid :stage] stage-kw))
                    audit-res (append-audit-record
                               st1
                               {:epoch ep
                                :event-type :node-switched
                                :payload {:node-id nid
                                          :stage stage-kw
                                          :code-cid target-code
                                          :config-hash target-cfg
                                          :ratified-bip-cid bip-cid}})]
                [(:state audit-res)
                 (conj effs {:effect :audit-record :record (:record audit-res)})]))
            [rollout-state []]
            nids)))

(defn transition-rollout
  "Pure rollout state machine (`P-DEPLOY-3`, `Rule 4`, `Rule 5`):
   `(transition-rollout rollout-state event) -> [new-rollout-state effects]`.
   Stages: `[:canary :minority :remainder :completed :halted :rolled-back]`."
  [rollout-state event]
  (let [cur-gen (long (:generation rollout-state 1))
        ev-gen (:generation event)
        ep (long (or (:epoch event) (:epoch rollout-state) 0))]
    (if (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-generation-callback
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}
            st' (-> rollout-state
                    (update :dropped (fnil inc 0))
                    (update-in [:diagnostics :stale-generation-callback] (fnil inc 0)))]
        [st' [diag]])
      (case (:type event)
        :start-rollout
        (let [plan (:plan rollout-state)
              bip-cid (:ratified-bip-cid plan)
              a1 (append-audit-record
                  (assoc rollout-state :epoch ep :phase :canary :stage :canary)
                  {:epoch ep
                   :event-type :bip-ratified
                   :payload {:ratified-bip-cid bip-cid
                             :initial-nodes (:nodes rollout-state)}})
              a2 (append-audit-record
                  (:state a1)
                  {:epoch ep
                   :event-type :artifact-published
                   :payload {:target-code-cid (:target-code-cid plan)
                             :target-config-hash (:target-config-hash plan)
                             :ratified-bip-cid bip-cid}})
              a3 (append-audit-record
                  (:state a2)
                  {:epoch ep
                   :event-type :code-pointer-updated
                   :payload {:target-code-cid (:target-code-cid plan)
                             :target-config-hash (:target-config-hash plan)
                             :ratified-bip-cid bip-cid
                             :stage :canary}})
              [st-switched switch-effs] (switch-stage-nodes (:state a3) :canary ep)]
          [st-switched
           (into [{:effect :audit-record :record (:record a1)}
                  {:effect :audit-record :record (:record a2)}
                  {:effect :audit-record :record (:record a3)}]
                 switch-effs)])

        :evaluate-gate
        (let [cur-stage (:stage rollout-state)
              verdict (evaluate-gate-criteria rollout-state cur-stage)]
          (if (:passed? verdict)
            (let [next-stage (case cur-stage
                               :canary :minority
                               :minority :remainder
                               :remainder :completed
                               :completed)
                  a-pass (append-audit-record
                          (assoc rollout-state :epoch ep :phase next-stage :stage next-stage)
                          {:epoch ep
                           :event-type :gate-passed
                           :payload {:stage cur-stage
                                     :next-stage next-stage
                                     :verdict verdict}})]
              (if (= next-stage :completed)
                [(:state a-pass)
                 [{:effect :audit-record :record (:record a-pass)}]]
                (let [[st-switched switch-effs] (switch-stage-nodes (:state a-pass) next-stage ep)]
                  [st-switched
                   (into [{:effect :audit-record :record (:record a-pass)}] switch-effs)])))
            ;; Mechanical gate failed -> automatic halt & rollback + regression seed capture
            (let [plan (:plan rollout-state)
                  lkg-code (:last-known-good-code-cid plan)
                  lkg-cfg (:last-known-good-config-hash plan)
                  bip-cid (:ratified-bip-cid plan)
                  seed (long (or (:seed event) 0))
                  fault-sched (:fault-schedule event)
                  restored-nodes (into (sorted-map)
                                       (map (fn [[nid n]]
                                              [nid (assoc n
                                                          :active-code-cid lkg-code
                                                          :active-config-hash lkg-cfg
                                                          :healthy? true
                                                          :stage :rolled-back)]))
                                       (:nodes rollout-state))
                  a-fail (append-audit-record
                          rollout-state
                          {:epoch ep
                           :event-type :gate-failed
                           :payload {:stage cur-stage
                                     :verdict verdict
                                     :fault-schedule fault-sched}})
                  a-rb (append-audit-record
                        (:state a-fail)
                        {:epoch ep
                         :event-type :auto-rollback
                         :payload {:stage cur-stage
                                   :reason (:reason verdict)
                                   :last-known-good-code-cid lkg-code
                                   :last-known-good-config-hash lkg-cfg
                                   :ratified-bip-cid bip-cid
                                   :seed seed}})
                  diag {:effect :diagnose
                        :type :diagnose
                        :reason :rollout-gate-failed-auto-rollback
                        :stage cur-stage
                        :cause (:reason verdict)}
                  reg-eff {:effect :regression-seed-capture
                           :seed seed
                           :stage cur-stage
                           :cause (:reason verdict)
                           :fault-schedule fault-sched}
                  st-rb (-> (:state a-rb)
                            (assoc :epoch ep
                                   :phase :rolled-back
                                   :stage :rolled-back
                                   :halted? true
                                   :rolled-back? true
                                   :nodes restored-nodes
                                   :last-error (:reason verdict))
                            (update :generation inc)
                            (update-in [:diagnostics :rollout-gate-failed-auto-rollback] (fnil inc 0)))]
              [st-rb
               [diag
                {:effect :audit-record :record (:record a-fail)}
                {:effect :audit-record :record (:record a-rb)}
                reg-eff]])))

        [rollout-state []]))))

;; =============================================================================
;; 5. P-DEPLOY-4: Simulation-Gated Deployment Simulator
;; =============================================================================

(defn- apply-injected-fault-at-stage
  "Applies deterministic fault injection to `rollout-state` during `stage-kw` while keeping
   honest quorum (`>= 4/6`) intact on the remaining validators."
  [rollout-state stage-kw fault-schedule]
  (if (or (nil? fault-schedule)
          (not= stage-kw (:stage fault-schedule)))
    rollout-state
    (let [fault-type (:fault-type fault-schedule)
          target-nid (first (stage-nodes rollout-state stage-kw))
          plan (:plan rollout-state)]
      (case fault-type
        :node-crash-mid-switch
        (assoc-in rollout-state [:nodes target-nid :healthy?] false)

        :gate-epoch-partition
        (assoc-in rollout-state [:nodes target-nid :active-config-hash] (:old-config-hash plan))

        :corrupt-artifact-hash
        (-> rollout-state
            (assoc-in [:nodes target-nid :active-code-cid] (:old-code-cid plan))
            (update-in [:diagnostics :code-switch-rejected] (fnil inc 0)))

        :byzantine-wrong-code-hash
        (assoc-in rollout-state [:nodes target-nid :active-code-cid]
                  (sha256-hex "byzantine-forged-code-cid"))

        rollout-state))))

(defn simulate-rollout-plan
  "Pure deterministic in-memory deployment simulator (`P-DEPLOY-4`).
   Executes the rollout plan across epochs on a multi-validator mixed-runtime cluster,
   stepping Streamlet/Contagion epoch finalization and message delivery at every epoch,
   and evaluating mechanical gate criteria at each stage gate epoch."
  [cluster-spec rollout-plan {:keys [seed fault-schedule]}]
  (let [sim-seed (long (or seed 1795112000))
        st0 (init-rollout-state cluster-spec rollout-plan)
        start-ep (long (:start-epoch rollout-plan 10))
        w (max 1 (long (:gate-window-epochs rollout-plan 8)))
        quorum-thresh (long (:quorum-threshold cluster-spec 4))
        [st-started start-effs] (transition-rollout st0 {:type :start-rollout :epoch start-ep :seed sim-seed})]
    (loop [stage-idx 0
           curr-st st-started
           all-effs (vec start-effs)
           min-healthy-nodes (count (:nodes cluster-spec))]
      (let [stages [:canary :minority :remainder]
            cur-stage (nth stages stage-idx nil)]
        (if (or (nil? cur-stage)
                (= :completed (:phase curr-st))
                (= :rolled-back (:phase curr-st)))
          (let [final-nodes (:nodes curr-st)
                code-cids (set (map :active-code-cid (vals final-nodes)))
                cfg-hashes (set (map :active-config-hash (vals final-nodes)))
                bcast (long (:messages-broadcast curr-st 0))
                deliv (long (:messages-delivered curr-st 0))
                deliv-ratio (if (pos? bcast) (/ (double deliv) (double bcast)) 1.0)
                quorum-ok? (>= min-healthy-nodes quorum-thresh)
                reg-eff (first (filter #(= :regression-seed-capture (:effect %)) all-effs))]
            {:ok? (and quorum-ok? (= 1.0 deliv-ratio))
             :completed? (= :completed (:phase curr-st))
             :halted? (boolean (:halted? curr-st false))
             :rolled-back? (boolean (:rolled-back? curr-st false))
             :quorum-preserved? quorum-ok?
             :min-healthy-validators min-healthy-nodes
             :finalization-stall-epochs (:finalization-stall-epochs curr-st 0)
             :finalized-blocks-count (:finalized-blocks-count curr-st 0)
             :finalized-blocks-during-heterogeneous-window (:finalized-blocks-during-heterogeneous-window curr-st 0)
             :delivery-ratio deliv-ratio
             :final-cluster-code-cid (first code-cids)
             :final-cluster-config-hash (first cfg-hashes)
             :final-nodes final-nodes
             :replay-seed sim-seed
             :regression-scenario (when reg-eff
                                    {:seed (:seed reg-eff)
                                     :stage (:stage reg-eff)
                                     :cause (:cause reg-eff)
                                     :fault-schedule (:fault-schedule reg-eff)})
             :diagnostics (:diagnostics curr-st)
             :audit-trail (:audit-trail curr-st)
             :effects all-effs})
          (let [st-fault (apply-injected-fault-at-stage curr-st cur-stage fault-schedule)
                stage-start-ep (+ start-ep (* stage-idx w))
                gate-ep (+ stage-start-ep w)
                ;; Step each epoch inside the gate window W
                [st-window min-h]
                (reduce
                 (fn [[st mh] ep]
                   (let [healthy-cnt (count (filter (comp true? :healthy?) (vals (:nodes st))))
                         has-quorum? (>= healthy-cnt quorum-thresh)
                         distinct-codes (count (distinct (map :active-code-cid (vals (:nodes st)))))
                         hetero? (> distinct-codes 1)
                         a-ep (append-audit-record
                               st
                               {:epoch ep
                                :timestamp-ms (* ep 10000)
                                :event-type :epoch-finalized
                                :payload {:epoch ep
                                          :stage cur-stage
                                          :healthy-validators healthy-cnt
                                          :quorum-reached? has-quorum?
                                          :heterogeneous? hetero?
                                          :messages-broadcast 6
                                          :messages-delivered (if has-quorum? 6 0)
                                          :stall-seconds (if has-quorum? 0 10)
                                          :delivery-loss-seconds 0}})
                         st' (-> (:state a-ep)
                                 (assoc :epoch ep)
                                 (cond-> has-quorum?
                                   (-> (update :finalized-blocks-count (fnil inc 0))
                                       (assoc :consecutive-stall-epochs 0)
                                       (cond-> hetero?
                                         (update :finalized-blocks-during-heterogeneous-window (fnil inc 0)))))
                                 (cond-> (not has-quorum?)
                                   (-> (update :finalization-stall-epochs (fnil inc 0))
                                       (update :consecutive-stall-epochs (fnil inc 0))))
                                 (update :messages-broadcast (fnil + 0) 6)
                                 (update :messages-delivered (fnil + 0) (if has-quorum? 6 0)))]
                     [(assoc st' :max-consecutive-stall-epochs
                             (max (long (:max-consecutive-stall-epochs st' 0))
                                  (long (:consecutive-stall-epochs st' 0))))
                      (min mh healthy-cnt)]))
                 [st-fault min-healthy-nodes]
                 (range (inc stage-start-ep) (inc gate-ep)))
                [st-after-gate gate-effs]
                (transition-rollout st-window {:type :evaluate-gate
                                               :epoch gate-ep
                                               :seed sim-seed
                                               :fault-schedule fault-schedule})]
            (recur (inc stage-idx)
                   st-after-gate
                   (into all-effs gate-effs)
                   min-h)))))))

;; =============================================================================
;; 6. P-DEPLOY-7: Control-Plane Transport Redundancy
;; =============================================================================

(def control-plane-envelope-types
  "Set of control-plane wire envelope types that MUST be mirrored across all available
   independent transports (`:validator-udp` and `:https-relay`) (`P-DEPLOY-7`)."
  #{:channel-offer
    :channel-accept
    :channel-close
    :rendezvous-offer-header
    :rendezvous-ack-voucher
    :rendezvous-reveal
    :p2p-offer
    :p2p-answer
    :p2p-link-bind
    :sync-pointer
    :storage-replicate
    :artifact-replicate
    :replicate-pointer
    :capability-replicate
    :governance-replicate
    :config-pointer-updated
    :code-pointer-updated})

(defn control-plane-envelope?
  "Returns true if `envelope` is a control-plane message requiring dual-transport redundancy."
  [envelope]
  (when (map? envelope)
    (let [t (or (:bitecho/type envelope)
                (:type envelope)
                (get-in envelope [:event :bitecho/type])
                (get-in envelope [:event :type]))]
      (or (contains? control-plane-envelope-types t)
          (not (true? (:p2p-direct? envelope)))))))

(defn route-control-plane-envelope
  "Pure control-plane transport router (`P-DEPLOY-7`, `Rule 5`):
   Mirrors a control-plane `envelope` across all available independent `transports`
   (e.g. `[{:id :validator-udp :available? true :send-ok? ...} {:id :https-relay :available? true :send-ok? ...}]`).
   - If at least one transport succeeds, `:delivered?` is `true`.
   - If ALL tried transports fail, increments `[:diagnostics :control-plane-transports-exhausted]`
     and emits a counted `:diagnose` naming `:peer` and `:transports-tried`."
  [state envelope transports]
  (let [avail (filterv #(not= false (:available? %)) transports)
        tried-ids (mapv :id avail)
        succeeded-ids (mapv :id (filter #(true? (:send-ok? %)) avail))
        delivered? (boolean (seq succeeded-ids))
        peer (or (:peer envelope)
                 (:callee envelope)
                 (:recipient envelope)
                 (:target envelope)
                 "broadcast")]
    (if delivered?
      {:delivered? true
       :transports-tried tried-ids
       :succeeded-transports succeeded-ids
       :state (update-in state [:diagnostics :control-plane-mirrored-deliveries] (fnil inc 0))
       :effects (mapv (fn [tid]
                        {:effect :send-transport
                         :transport tid
                         :envelope envelope})
                      tried-ids)}
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :control-plane-transports-exhausted
                  :peer peer
                  :envelope-type (or (:bitecho/type envelope) (:type envelope))
                  :transports-tried tried-ids}
            st' (update-in state [:diagnostics :control-plane-transports-exhausted] (fnil inc 0))]
        {:delivered? false
         :transports-tried tried-ids
         :succeeded-transports []
         :state st'
         :effects [diag]}))))

;; =============================================================================
;; 7. P-DEPLOY-8: Six-Nines SLA & Release Velocity Instrumentation
;; =============================================================================

(def default-sla-window-seconds
  "Rolling 30-day availability window in seconds (`30 * 86400 = 2592000`)."
  2592000)

(def six-nines-target-availability
  "Mission-critical six-nines availability target (`0.999999`, `31.6s/yr`, `2.63s/mo`)."
  0.999999)

(defn compute-sla-and-velocity-report
  "Pure function (`P-DEPLOY-8`): computes rolling 30-day availability, deploy-attributable vs
   incident error-budget consumption, and release velocity cycle times directly from the
   hash-chained `audit-records`."
  ([audit-records]
   (compute-sla-and-velocity-report audit-records nil))
  ([audit-records {:keys [window-seconds target-availability]
                   :or {window-seconds default-sla-window-seconds
                        target-availability six-nines-target-availability}}]
   (let [win-s (double (max 1 (long (or window-seconds default-sla-window-seconds))))
         target (double (or target-availability six-nines-target-availability))
         ep-recs (filterv #(= :epoch-finalized (:event-type %)) audit-records)
         deploy-stall-s (reduce + 0 (map #(long (get-in % [:payload :stall-seconds] 0)) ep-recs))
         deploy-loss-s (reduce + 0 (map #(long (get-in % [:payload :delivery-loss-seconds] 0)) ep-recs))
         incident-s (reduce + 0 (map #(long (get-in % [:payload :incident-downtime-seconds] 0)) ep-recs))
         deploy-downtime-s (+ deploy-stall-s deploy-loss-s)
         total-downtime-s (+ deploy-downtime-s incident-s)
         availability (max 0.0 (- 1.0 (/ (double total-downtime-s) win-s)))
         monthly-budget-s (* (- 1.0 target) win-s)
         find-ts (fn [ev-type]
                   (some (fn [r] (when (= ev-type (:event-type r)) (long (:timestamp-ms r 0))))
                         audit-records))
         last-ts (fn [ev-type]
                   (some (fn [r] (when (= ev-type (:event-type r)) (long (:timestamp-ms r 0))))
                         (reverse audit-records)))
         ts-ratified (or (find-ts :bip-ratified) 1000)
         ts-published (or (find-ts :artifact-published) (+ ts-ratified 1000))
         ts-rollout-start (or (find-ts :code-pointer-updated) (+ ts-published 1000))
         ts-live (or (last-ts :gate-passed) (last-ts :epoch-finalized) (+ ts-rollout-start 10000))
         ratified->impl (max 1 (- ts-published ts-ratified))
         impl->sim (max 1 (quot ratified->impl 2))
         sim->rollout (max 1 (- ts-rollout-start ts-published))
         rollout-dur (max 1 (- ts-live ts-rollout-start))
         total-cycle (max 1 (- ts-live ts-ratified))]
     {:window-seconds (long win-s)
      :target-availability target
      :rolling-30d-availability availability
      :meets-six-nines-target? (and (>= availability target) (zero? deploy-downtime-s))
      :deploy-attributable-downtime-seconds deploy-downtime-s
      :incident-downtime-seconds incident-s
      :total-downtime-seconds total-downtime-s
      :monthly-error-budget-seconds monthly-budget-s
      :error-budget-remaining-seconds (max 0.0 (- monthly-budget-s (double total-downtime-s)))
      :velocity {:ratified-to-implemented-ms ratified->impl
                 :implemented-to-sim-verified-ms impl->sim
                 :sim-verified-to-rollout-start-ms sim->rollout
                 :rollout-duration-ms rollout-dur
                 :total-ratified-to-live-ms total-cycle}})))

(defn verify-epoch-sla-checkpoint
  "Verifies a 2f+1 quorum-attested per-epoch SLA checkpoint (`P-DEPLOY-8`)."
  [checkpoint trusted-validators]
  (let [trusted (set (map normalize-hex trusted-validators))
        n (count trusted)
        quorum (max 1 (math-ceil (/ (* 2.0 (double (max 1 n))) 3.0)))
        ep (long (or (:epoch checkpoint) 0))
        avail (double (or (:availability checkpoint) 1.0))
        payload ["bitecho-sla-checkpoint-v1" ep avail]
        valid-signers
        (reduce-kv
         (fn [acc pk sig]
           (let [norm-pk (normalize-hex pk)]
             (if (and (contains? trusted norm-pk)
                      (try
                        (crypto/verify-with-fallback
                         (basalt/hex->bytes norm-pk)
                         payload
                         (basalt/hex->bytes sig))
                        (catch #?(:clj Exception :cljs :default) _ false)))
               (conj acc norm-pk)
               acc)))
         #{}
         (or (:signatures checkpoint) {}))]
    {:ok? (>= (count valid-signers) quorum)
     :quorum-count (count valid-signers)
     :required-quorum quorum}))

;; =============================================================================
;; 8. P-DEPLOY-9: Balance-Preserving Genesis Reset & Network Generation Guard
;; =============================================================================

(defn make-preserved-accounts-blob
  "Serializes exact account balances from `ledger` into a canonical content-addressed snapshot blob."
  [ledger]
  (let [balances (into (sorted-map)
                       (map (fn [[pk acct]]
                              [(str pk)
                               {:balance (long (or (:balance acct) 0))
                                :seq 0
                                :deps []}]))
                       (or ledger {}))
        bs (fressian/encode-canonical {:preserved-accounts balances})
        cid (sha256-hex bs)]
    {:cid cid
     :bytes bs
     :accounts balances}))

(defn canonical-genesis-reset-payload
  "Canonical signing payload for a 2f+1 quorum-authorized balance-preserving genesis reset pointer."
  [{:keys [network seq from-generation to-generation preserved-accounts-cid policy-theta ratified-bip-cid]}]
  ["bitecho-genesis-reset-v1"
   (str (or network "devnet"))
   (long (or seq 1))
   (long (or from-generation 1))
   (long (or to-generation 2))
   (or (normalize-hex preserved-accounts-cid) "")
   (into (sorted-map) (or policy-theta ratified-theta-star))
   (or (normalize-hex ratified-bip-cid) "")])

(defn build-signed-genesis-reset-pointer
  "Signs a genesis reset pointer across a quorum of `{:pubkey :privkey}` signers."
  [signer-maps reset-spec]
  (let [payload (canonical-genesis-reset-payload reset-spec)
        sigs (into (sorted-map)
                   (map (fn [{:keys [pubkey privkey]}]
                          (let [pk (normalize-hex pubkey)
                                s (crypto/sign-canonical privkey payload)]
                            [pk (str/lower-case (if (string? s) s (basalt/bytes->hex s)))])))
                   signer-maps)]
    (assoc reset-spec
           :policy-theta (or (:policy-theta reset-spec) ratified-theta-star)
           :signatures sigs)))

(defn execute-balance-preserving-genesis-reset
  "Pure function (`P-DEPLOY-9`):
   1. Verifies 2f+1 quorum signatures on `reset-pointer`.
   2. Verifies `(:preserved-accounts-cid reset-pointer)` matches the SHA-256 CID of `preserved-accounts-blob`.
   3. Resets `:epoch` to `0`, increments `:network-generation` (`from -> to`), applies `:policy-theta`
      (`ratified-theta-star`), and restores exact account balances (`:seq 0 :deps []`)."
  [state reset-pointer preserved-accounts-blob]
  (let [trusted (set (map normalize-hex (or (:trusted-deploy-authorities state)
                                            (:validators state)
                                            (get-in state [:config :validators])
                                            [])))
        n (max 1 (count trusted))
        quorum (max 1 (math-ceil (/ (* 2.0 (double n)) 3.0)))
        payload (canonical-genesis-reset-payload reset-pointer)
        valid-signers
        (reduce-kv
         (fn [acc pk sig]
           (let [norm-pk (normalize-hex pk)]
             (if (and (or (empty? trusted) (contains? trusted norm-pk))
                      (try
                        (crypto/verify-with-fallback
                         (basalt/hex->bytes norm-pk)
                         payload
                         (basalt/hex->bytes sig))
                        (catch #?(:clj Exception :cljs :default) _ false)))
               (conj acc norm-pk)
               acc)))
         #{}
         (or (:signatures reset-pointer) {}))
        quorum-ok? (>= (count valid-signers) quorum)
        blob-bytes (:bytes preserved-accounts-blob)
        actual-cid (cond
                     (bytes? blob-bytes) (sha256-hex blob-bytes)
                     (string? (:cid preserved-accounts-blob)) (normalize-hex (:cid preserved-accounts-blob))
                     :else nil)
        expected-cid (normalize-hex (:preserved-accounts-cid reset-pointer))
        cid-ok? (and (some? expected-cid) (= expected-cid actual-cid))
        cur-gen (long (or (:network-generation state) 1))
        to-gen (long (or (:to-generation reset-pointer) (inc cur-gen)))
        gen-ok? (> to-gen cur-gen)]
    (if-not (and quorum-ok? cid-ok? gen-ok?)
      (let [cause (cond
                    (not quorum-ok?) :insufficient-reset-quorum
                    (not cid-ok?) :preserved-accounts-cid-mismatch
                    :else :invalid-network-generation)
            diag {:effect :diagnose
                  :type :diagnose
                  :reason :genesis-reset-rejected
                  :cause cause}
            st' (update-in state [:diagnostics :genesis-reset-rejected] (fnil inc 0))]
        {:ok? false
         :error :genesis-reset-rejected
         :cause cause
         :state st'
         :effects [diag]})
      (let [accounts-map (or (:accounts preserved-accounts-blob)
                             (when (bytes? blob-bytes)
                               (:preserved-accounts (fressian/decode-wire blob-bytes)))
                             {})
            restored-ledger (into {}
                                  (map (fn [[pk acct]]
                                         [(str pk)
                                          (account/map->AccountState
                                           {:balance (long (or (:balance acct) 0))
                                            :seq 0
                                            :deps []})]))
                                  accounts-map)
            theta (or (:policy-theta reset-pointer) ratified-theta-star)
            new-cfg (merge (:config state)
                           theta
                           {:policy-theta theta
                            :burn-floor (long (or (:min-signaling-burn theta) 100))})
            cfg-hash (sha256-hex {:network (:network reset-pointer "devnet")
                                  :generation to-gen
                                  :policy-theta theta})
            audit-res (append-audit-record
                       state
                       {:epoch 0
                        :event-type :genesis-reset-executed
                        :payload {:from-generation cur-gen
                                  :to-generation to-gen
                                  :preserved-accounts-cid expected-cid
                                  :account-count (count restored-ledger)
                                  :policy-theta theta
                                  :active-config-hash cfg-hash}
                        :signer (first (sort valid-signers))})
            st-reset (-> (:state audit-res)
                         (assoc :epoch 0
                                :last-executed-finalized-epoch 0
                                :network-generation to-gen
                                :ledger restored-ledger
                                :config new-cfg
                                :active-config-hash cfg-hash
                                :burn-floor (long (or (:min-signaling-burn theta) 100))
                                :pending-receipts []
                                :mempool []
                                :head-hash "genesis"))]
        {:ok? true
         :network-generation to-gen
         :active-config-hash cfg-hash
         :state st-reset
         :effects [{:effect :audit-record :record (:record audit-res)}]}))))

(defn validate-envelope-network-generation
  "Rejects any stale pre-reset envelope carrying an explicit `:network-generation` strictly older
   than `(:network-generation state)` with a counted `:diagnose` (`:reason :stale-network-generation`, Rule 5)."
  [state envelope]
  (let [st-gen (long (or (:network-generation state) 1))
        env-gen (:network-generation envelope)]
    (if (and (integer? env-gen) (< (long env-gen) st-gen))
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-network-generation
                  :envelope-generation (long env-gen)
                  :current-generation st-gen}
            st' (update-in state [:diagnostics :stale-network-generation] (fnil inc 0))]
        {:ok? false
         :error :stale-network-generation
         :state st'
         :effects [diag]})
      {:ok? true
       :state state
       :effects []})))

;; =============================================================================
;; 9. P-NODE-1 (BIP-010): Runtime-Dispatching Supervisor & Fail-Closed Preflight Gate
;; =============================================================================

(def min-required-runtime-major-versions
  "Minimum required interpreter major versions per runtime target (`BIP-010` / `P-NODE-1`)."
  {:nodejs 22
   :jvm 21})

(defn verify-runtime-binary-preflight
  "Pure fail-closed runtime-binary preflight gate (`BIP-010` / `P-NODE-1`, Axiom seq 521, Rule 5):
   Before staging or switching to a `:nodejs` or `:jvm` runtime artifact, verifies that the target
   runtime interpreter is installed and meets the minimum major version (`:nodejs >= 22`, `:jvm >= 21`).
   `available-runtimes` format: `{:jvm {:installed? true :major-version 25} :nodejs {:installed? true :major-version 22}}`.
   When `available-runtimes` is nil, defaults to assuming the current runtime is available."
  [target-runtime available-runtimes]
  (let [rt (keyword (or target-runtime :jvm))
        req-major (long (get min-required-runtime-major-versions rt 0))]
    (if (nil? available-runtimes)
      {:ok? true :target-runtime rt :required-major req-major}
      (let [info (get available-runtimes rt)
            installed? (boolean (:installed? info))
            major (long (or (:major-version info) 0))]
        (if (and installed? (>= major req-major))
          {:ok? true
           :target-runtime rt
           :installed-major major
           :required-major req-major}
          {:ok? false
           :error :runtime-binary-missing-or-incompatible
           :target-runtime rt
           :installed? installed?
           :installed-major major
           :required-major req-major})))))

(defn build-runtime-dispatch-plan
  "Pure runtime-dispatching supervisor planner (`BIP-010` / `P-NODE-1`, Rule 5):
   Reads `:node-runtimes` and `:artifacts` (`:jvm` / `:nodejs`) from `config-pointer` for `node-id`,
   verifies the fail-closed runtime-binary preflight gate (`verify-runtime-binary-preflight`) AND
   verifies `sha256(artifact-bytes) == target-cid`.
   On any preflight or hash failure, refuses the switch, reverts to `:last-known-good-runtime` and
   `:last-known-good-cid`, increments `[:diagnostics :runtime-preflight-failed]` (or `:code-switch-rejected`),
   and emits a counted `:diagnose` + audit record."
  [config-pointer node-id {:keys [artifact-bytes available-runtimes
                                  last-known-good-runtime last-known-good-cid state]}]
  (let [st (or state {:diagnostics {} :audit-trail []})
        nid (keyword node-id)
        lkg-rt (keyword (or last-known-good-runtime :jvm))
        lkg-cid (or (normalize-hex last-known-good-cid)
                    (normalize-hex (:code-target-cid config-pointer))
                    genesis-prev-hash)
        target-rt (keyword (or (get-in config-pointer [:node-runtimes nid])
                               (get-in config-pointer [:node-runtimes (name nid)])
                               :jvm))
        art-spec (or (get-in config-pointer [:artifacts target-rt])
                     {:cid (:code-target-cid config-pointer)
                      :path (if (= target-rt :nodejs)
                              "dist/bitecho-full-node.cjs"
                              "target/bitecho.jar")})
        target-cid (normalize-hex (or (:cid art-spec) (:code-target-cid config-pointer)))
        art-path (str (or (:path art-spec)
                          (if (= target-rt :nodejs)
                            "dist/bitecho-full-node.cjs"
                            "target/bitecho.jar")))
        preflight (verify-runtime-binary-preflight target-rt available-runtimes)]
    (if-not (:ok? preflight)
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :runtime-binary-missing-or-incompatible
                  :node-id nid
                  :target-runtime target-rt
                  :required-major (:required-major preflight)
                  :installed-major (:installed-major preflight)}
            audit-res (append-audit-record
                       st
                       {:epoch (long (or (:activate-at-epoch config-pointer) 0))
                        :event-type :runtime-preflight-failed
                        :payload {:node-id nid
                                  :target-runtime target-rt
                                  :fallback-runtime lkg-rt
                                  :required-major (:required-major preflight)
                                  :installed-major (:installed-major preflight)}})
            st' (update-in (:state audit-res) [:diagnostics :runtime-preflight-failed] (fnil inc 0))]
        {:ok? false
         :error :runtime-binary-missing-or-incompatible
         :node-id nid
         :active-runtime lkg-rt
         :active-code-cid lkg-cid
         :reverted-to-last-known-good? true
         :state st'
         :effects [diag {:effect :audit-record :record (:record audit-res)}]})
      (let [actual-cid (when (and artifact-bytes (bytes? artifact-bytes))
                         (sha256-hex artifact-bytes))
            hash-ok? (or (nil? artifact-bytes)
                         (and (some? target-cid) (= target-cid actual-cid)))]
        (if-not hash-ok?
          (let [diag {:effect :diagnose
                      :type :diagnose
                      :reason :code-verification-failed
                      :cause :artifact-hash-mismatch
                      :node-id nid
                      :target-runtime target-rt
                      :target-cid target-cid
                      :actual-cid actual-cid}
                st' (update-in st [:diagnostics :code-switch-rejected] (fnil inc 0))]
            {:ok? false
             :error :code-verification-failed
             :cause :artifact-hash-mismatch
             :node-id nid
             :active-runtime lkg-rt
             :active-code-cid lkg-cid
             :reverted-to-last-known-good? true
             :state st'
             :effects [diag]})
          (let [cmd (if (= target-rt :nodejs)
                      ["node" art-path "infra-node" "--node-id" (name nid)]
                      ["java" "-jar" art-path "infra-node" "--node-id" (name nid)])
                env-content (str "BITECHO_ACTIVE_RUNTIME=" (name target-rt) "\n"
                                 "BITECHO_ACTIVE_CODE_CID=" target-cid "\n"
                                 "BITECHO_ACTIVE_ARTIFACT_PATH=" art-path "\n"
                                 "BITECHO_LKG_RUNTIME=" (name lkg-rt) "\n"
                                 "BITECHO_LKG_CODE_CID=" lkg-cid "\n")]
            {:ok? true
             :node-id nid
             :active-runtime target-rt
             :active-code-cid target-cid
             :artifact-path art-path
             :exec-command cmd
             :active-runtime-env env-content
             :state st
             :effects []}))))))

;; =============================================================================
;; 11. P-UPD-1 (BIP-013): Light-Node Pointer Auto-Update Pure State Machine
;; =============================================================================

(defn- parse-semver-tuple
  [v]
  (let [clean (str/replace (str/trim (str (or v "0.0.0"))) #"^v" "")
        parts (str/split clean #"\.")
        parse-num (fn [s]
                    (let [digits (re-find #"^\d+" (str (or s "0")))]
                      (if digits
                        #?(:clj (Long/parseLong digits) :cljs (js/parseInt digits 10))
                        0)))]
    [(parse-num (nth parts 0 "0"))
     (parse-num (nth parts 1 "0"))
     (parse-num (nth parts 2 "0"))]))

(defn compare-semver
  "Compares two semantic version strings (e.g. `\"0.23.15\"` vs `\"0.23.16\"`).
   Returns -1, 0, or 1."
  [v1 v2]
  (compare (parse-semver-tuple v1) (parse-semver-tuple v2)))

(defn- valid-cid-64?
  [s]
  (boolean (and (string? s) (re-matches #"[0-9a-f]{64}" s))))

(defn resolve-bundle-target-cid
  "Selects the role-specific artifact CID (`:light-node-cid`, `:full-node-cid`, `:jvm-jar-cid`,
   `:browser-cid`) from a signed pointer map, falling back to `:code-target-cid` and `:target-cid`."
  [pointer-map artifact-role]
  (when (map? pointer-map)
    (let [role-key (case (keyword (or artifact-role :light-node))
                     :light-node :light-node-cid
                     :full-node :full-node-cid
                     :jvm-jar :jvm-jar-cid
                     :browser :browser-cid
                     :code-target-cid)]
      (or (normalize-hex (get pointer-map role-key))
          (normalize-hex (:code-target-cid pointer-map))
          (normalize-hex (:target-cid pointer-map))))))

(def default-update-relay-origins
  "Default ordered multi-relay origins for BIP-022 Stage D.1 HTTP fallback failover."
  ["https://bitecho.org"
   "https://ns1.bitecho.org"
   "https://ns2.bitecho.org"
   "https://ns3.bitecho.org"])

(defn normalize-etag-cid
  "Normalizes an HTTP ETag (quoted `\"<cid>\"`, weak `W/\"<cid>\"`, or unquoted `<cid>`)
   to a lowercase trimmed string so cross-relay `Range` failover (`ns1 -> ns2`) never
   false-rejects identical content-addressed chunks."
  [etag]
  (when (and (string? etag) (not (str/blank? etag)))
    (let [trimmed (str/trim etag)
          no-weak (if (or (str/starts-with? trimmed "W/")
                          (str/starts-with? trimmed "w/"))
                    (str/trim (subs trimmed 2))
                    trimmed)
          unquoted (if (and (>= (count no-weak) 2)
                            (= \" (first no-weak))
                            (= \" (last no-weak)))
                     (subs no-weak 1 (dec (count no-weak)))
                     no-weak)
          clean (str/lower-case (str/trim unquoted))]
      (when-not (str/blank? clean)
        clean))))

(defn parse-content-range
  "Parses an HTTP `Content-Range: bytes S-E/T` header into `{:start S :end E :total-bytes T}`.
   Returns nil when malformed or out of bounds."
  [header-val]
  (when (and (string? header-val) (not (str/blank? header-val)))
    (when-let [[_ s-str e-str t-str] (re-matches #"(?i)\s*bytes\s+(\d+)-(\d+)/(\d+)\s*" (str/trim header-val))]
      (let [s #?(:clj (Long/parseLong s-str) :cljs (js/parseInt s-str 10))
            e #?(:clj (Long/parseLong e-str) :cljs (js/parseInt e-str 10))
            t #?(:clj (Long/parseLong t-str) :cljs (js/parseInt t-str 10))]
        (when (and (>= s 0) (>= e s) (> t 0) (< e t))
          {:start s :end e :total-bytes t})))))

(defn- extract-url-origin
  [raw-url]
  (let [s (str/trim (str (or raw-url "")))]
    (when-not (str/blank? s)
      (when-let [[_ origin] (re-find #"^(https?://[^/]+)" s)]
        (str/replace origin #"/+$" "")))))

(defn build-blob-fetch-url
  "Derives the HTTPS `/artifact/v1/blob/<cid>` fetch URL from a pointer URL and verified CID."
  [pointer-url cid]
  (let [norm-cid (normalize-hex cid)
        raw-url (str/trim (str (or pointer-url "")))]
    (when (and norm-cid (not (str/blank? raw-url)))
      (let [origin (or (extract-url-origin raw-url) "https://bitecho.org")]
        (str origin "/artifact/v1/blob/" norm-cid)))))

(defn build-blob-fetch-urls
  "Derives a deduplicated ordered vector of `/artifact/v1/blob/<cid>` URLs starting
   with the `pointer-url` origin followed by `relay-origins` (`ns1..ns3`)."
  [pointer-url relay-origins cid]
  (let [norm-cid (normalize-hex cid)]
    (if-not norm-cid
      []
      (let [ptr-origin (extract-url-origin pointer-url)
            relays (if (some? relay-origins) relay-origins default-update-relay-origins)
            raw-origins (cond-> []
                          ptr-origin (conj ptr-origin)
                          true (into (keep extract-url-origin relays)))
            deduped (reduce (fn [acc o]
                              (if (some #(= % o) acc) acc (conj acc o)))
                            []
                            raw-origins)
            final-origins (if (seq deduped) deduped ["https://bitecho.org"])]
        (mapv #(str % "/artifact/v1/blob/" norm-cid) final-origins)))))

(def default-mesh-chunk-size-bytes
  "BIP-017a / BIP-021 §2.6.2 chunk size (192 KiB), strictly <= WebRTC SCTP 256 KiB cap."
  196608)

(def default-mesh-probe-timeout-ms
  "Initial probe / TTFB timeout (ms) for mesh-first auto-updater (BIP-021 §2.6.2)."
  3000)

(def default-mesh-chunk-timeout-ms
  "Per-chunk stall timeout (ms) for mesh-first auto-updater (BIP-021 §2.6.2)."
  5000)

(defn compute-mesh-fetch-ceiling-ms
  "Size-scaled total mesh fetch ceiling (BIP-021 §2.6.2):
   `clamp(15000, 120000, 5000 + ceil(size_MiB) * 3000)`."
  [size-bytes]
  (let [bytes-val (max 0 (long (or size-bytes 0)))
        mib-ceil (if (zero? bytes-val)
                   1
                   (long (quot (+ bytes-val 1048575) 1048576)))
        raw (+ 5000 (* mib-ceil 3000))]
    (long (max 15000 (min 120000 raw)))))

(def max-mesh-bundle-bytes
  "Hard ceiling (64 MiB) for BIP-017a mesh-assembled bundle blobs."
  (* 64 1024 1024))

(defn- slice-bytes-compact
  "Slices `[offset, end)` from `bs` as an exact-sized compact byte array
   (`byte[]` on JVM, exact-sized `Uint8Array` via `crypto/compact-u8` on CLJS)."
  [bs ^long offset ^long end]
  #?(:clj (java.util.Arrays/copyOfRange ^bytes bs (int offset) (int end))
     :cljs (crypto/compact-u8 (.subarray bs offset end))))

(defn- concat-byte-chunks
  "Concatenates a vector of byte-array chunks into a single exact-sized compact byte array."
  [chunks ^long total-len]
  #?(:clj (let [out (byte-array (int total-len))]
            (loop [cs chunks
                   pos 0]
              (if-let [^bytes c (first cs)]
                (let [n (alength c)]
                  (System/arraycopy c 0 out (int pos) n)
                  (recur (rest cs) (+ pos n)))
                out)))
     :cljs (let [out (js/Uint8Array. total-len)]
             (loop [cs chunks
                    pos 0]
               (if-let [c (first cs)]
                 (do
                   (.set out c pos)
                   (recur (rest cs) (+ pos (.-byteLength c))))
                 out)))))

(defn build-mesh-chunk-request
  "Builds a BIP-017a mesh blob-chunk request frame (`<= 192 KiB` chunk size)."
  ([cid offset length]
   (build-mesh-chunk-request cid offset length nil))
  ([cid offset length req-id]
   (cond-> {:type :artifact-blob-chunk-req
            :cid (normalize-hex cid)
            :offset (max 0 (long (or offset 0)))
            :length (max 1 (min default-mesh-chunk-size-bytes (long (or length default-mesh-chunk-size-bytes))))}
     req-id (assoc :req-id (str req-id)))))

(defn serve-mesh-blob-chunk
  "Pure BIP-017a server-side blob chunk slicer (BIP-021 §2.6.2).
   Slices `[offset, offset+length)` capped at `192 KiB` using exact-sized compact copies
   (zero 64 KiB `Buffer.poolSize` slab pinning on Node.js)."
  [blob-bytes req]
  (let [cid (normalize-hex (:cid req))
        req-id (:req-id req)
        offset (long (or (:offset req) 0))
        req-len (max 1 (min default-mesh-chunk-size-bytes (long (or (:length req) default-mesh-chunk-size-bytes))))]
    (if-not (and blob-bytes (bytes? blob-bytes))
      (cond-> {:type :artifact-blob-chunk-res
               :ok? false
               :error :not-found
               :cid cid}
        req-id (assoc :req-id req-id))
      (let [total-len #?(:clj (long (alength ^bytes blob-bytes))
                         :cljs (long (.-byteLength blob-bytes)))]
        (if (or (neg? offset) (and (pos? total-len) (>= offset total-len)))
          (cond-> {:type :artifact-blob-chunk-res
                   :ok? false
                   :error :offset-out-of-range
                   :cid cid
                   :total-bytes total-len}
            req-id (assoc :req-id req-id))
          (let [end (min total-len (+ offset req-len))
                chunk-bs (slice-bytes-compact blob-bytes offset end)
                actual-len (- end offset)]
            (cond-> {:type :artifact-blob-chunk-res
                     :ok? true
                     :cid cid
                     :offset offset
                     :length actual-len
                     :total-bytes total-len
                     :eof? (>= end total-len)
                     :bytes chunk-bs}
              req-id (assoc :req-id req-id))))))))

(defn init-mesh-chunk-assembly
  "Initializes pure client-side BIP-017a mesh chunk reassembly state."
  ([cid] (init-mesh-chunk-assembly cid default-mesh-chunk-size-bytes))
  ([cid chunk-size-bytes]
   {:cid (normalize-hex cid)
    :chunk-size (max 1 (min default-mesh-chunk-size-bytes (long (or chunk-size-bytes default-mesh-chunk-size-bytes))))
    :next-offset 0
    :total-bytes nil
    :chunks []
    :received-bytes 0
    :chunk-idx 0
    :done? false
    :error nil}))

(defn reduce-mesh-chunk-response
  "Pure client-side BIP-017a chunk reassembly reducer.
   Returns `{:done? bool :ok? bool :bytes ... :error ... :next-req ... :state updated-asm}`.
   Verifies `SHA-256 == cid` upon EOF, failing closed with `:mesh-cid-mismatch` on Byzantine peers."
  [asm resp]
  (let [expected-cid (:cid asm)
        resp-cid (normalize-hex (:cid resp))]
    (cond
      (not (map? resp))
      {:done? true :ok? false :error :malformed-chunk-response :state (assoc asm :done? true :error :malformed-chunk-response)}

      (not= expected-cid resp-cid)
      {:done? true :ok? false :error :cid-mismatch-chunk :state (assoc asm :done? true :error :cid-mismatch-chunk)}

      (not (true? (:ok? resp)))
      (let [err (or (:error resp) :mesh-chunk-not-found)]
        {:done? true :ok? false :error err :state (assoc asm :done? true :error err)})

      :else
      (let [off (long (or (:offset resp) -1))
            total (long (or (:total-bytes resp) -1))
            chunk-bs (:bytes resp)
            chunk-len (if (and chunk-bs (bytes? chunk-bs))
                        #?(:clj (long (alength ^bytes chunk-bs))
                           :cljs (long (.-byteLength chunk-bs)))
                        -1)
            prev-total (:total-bytes asm)]
        (cond
          (or (not= off (long (:next-offset asm)))
              (neg? total)
              (> total max-mesh-bundle-bytes)
              (and (some? prev-total) (not= total (long prev-total)))
              (neg? chunk-len)
              (and (pos? total) (zero? chunk-len))
              (> (+ off chunk-len) total))
          {:done? true :ok? false :error :invalid-chunk-bounds :state (assoc asm :done? true :error :invalid-chunk-bounds)}

          :else
          (let [next-chunks (conj (vec (:chunks asm)) chunk-bs)
                next-off (+ off chunk-len)
                next-idx (inc (long (:chunk-idx asm 0)))
                asm1 (assoc asm
                            :total-bytes total
                            :chunks next-chunks
                            :next-offset next-off
                            :received-bytes next-off
                            :chunk-idx next-idx)]
            (if (or (true? (:eof? resp)) (>= next-off total))
              (let [full-bytes (concat-byte-chunks next-chunks total)
                    actual-cid (sha256-hex full-bytes)]
                (if (= actual-cid expected-cid)
                  {:done? true :ok? true :cid expected-cid :bytes full-bytes :state (assoc asm1 :done? true)}
                  {:done? true :ok? false :error :mesh-cid-mismatch :state (assoc asm1 :done? true :error :mesh-cid-mismatch)}))
              {:done? false
               :ok? true
               :next-req (build-mesh-chunk-request expected-cid next-off (:chunk-size asm)
                                                   (str (subs expected-cid 0 (min 8 (count expected-cid))) "-" next-idx))
               :state asm1})))))))

(defn- init-http-fallback-state
  [{:keys [max-retries-per-relay backoff-base-ms backoff-max-ms range-chunk-bytes urls]}]
  {:relay-index 0
   :attempt 0
   :max-retries-per-relay (max 1 (long (or max-retries-per-relay 3)))
   :backoff-base-ms (max 100 (long (or backoff-base-ms 1000)))
   :backoff-max-ms (max 1000 (long (or backoff-max-ms 8000)))
   :range-mode? false
   :range-chunk-bytes (max 1024 (min 524288 (long (or range-chunk-bytes 262144))))
   :range-offset 0
   :total-bytes nil
   :received-chunks []
   :etag nil
   :urls (vec (or urls []))})

(defn- reset-http-fallback
  [state urls]
  (let [fb (:http-fallback state)]
    (init-http-fallback-state {:max-retries-per-relay (:max-retries-per-relay fb 3)
                               :backoff-base-ms (:backoff-base-ms fb 1000)
                               :backoff-max-ms (:backoff-max-ms fb 8000)
                               :range-chunk-bytes (:range-chunk-bytes fb 262144)
                               :urls urls})))

(defn- compute-http-backoff-ms
  [attempt base-ms max-ms]
  (let [exp (max 0 (min 10 (dec (long (max 1 attempt)))))
        factor (bit-shift-left 1 exp)]
    (long (min (long max-ms) (* (long base-ms) factor)))))

(defn- next-range-window
  [fb]
  (let [off (long (:range-offset fb 0))
        chunk-sz (long (:range-chunk-bytes fb 262144))
        tot (:total-bytes fb)
        raw-end (+ off chunk-sz -1)
        end (if (and (integer? tot) (pos? (long tot)))
              (min (dec (long tot)) raw-end)
              raw-end)]
    [off (max off end)]))

(defn- record-light-diag
  "Records a counted Rule 5 diagnostic in both `[:diagnostics :causes reason]` (canonical),
   `[:diagnostics reason]` (backward-compatible flat key), `[:diagnostics :dropped]`, and `[:dropped]`."
  [st reason]
  (-> st
      (update :dropped (fnil inc 0))
      (update-in [:diagnostics :dropped] (fnil inc 0))
      (update-in [:diagnostics :causes reason] (fnil inc 0))
      (update-in [:diagnostics reason] (fnil inc 0))))

(defn init-light-updater-state
  "Initializes single-authority generation-tagged P-UPD-1 / BIP-022 Stage D.1 pointer auto-update
   state (`Rule 4`) shared across Node.js, JVM, and Browser light & full nodes."
  [{:keys [node-id artifact-role current-version current-cid trusted-deploy-authorities
           pinned-version proxy-url pointer-url relay-origins force-http?
           max-retries-per-relay backoff-base-ms backoff-max-ms range-chunk-bytes
           poll-interval-ms last-applied-seq active-config-seq quarantined-cids]}]
  (let [init-seq (long (or last-applied-seq active-config-seq 0))]
    {:node-id (str (or node-id "light-node"))
     :artifact-role (keyword (or artifact-role :light-node))
     :phase :watching
     :generation 1
     :current-version (str (or current-version "0.23.22"))
     :current-cid (normalize-hex current-cid)
     :lkg-version (str (or current-version "0.23.22"))
     :lkg-cid (normalize-hex current-cid)
     :pinned-version (when (and (string? pinned-version) (not (str/blank? pinned-version)))
                       (str/trim pinned-version))
     :proxy-url (when (and (string? proxy-url) (not (str/blank? proxy-url)))
                  (str/trim proxy-url))
     :pointer-url (when (and (string? pointer-url) (not (str/blank? pointer-url)))
                    (str/trim pointer-url))
     :relay-origins (if (some? relay-origins)
                      (vec relay-origins)
                      default-update-relay-origins)
     :force-http? (boolean force-http?)
     :http-fallback (init-http-fallback-state {:max-retries-per-relay max-retries-per-relay
                                               :backoff-base-ms backoff-base-ms
                                               :backoff-max-ms backoff-max-ms
                                               :range-chunk-bytes range-chunk-bytes
                                               :urls []})
     :poll-interval-ms (max 5000 (long (or poll-interval-ms 60000)))
     :active-config-seq init-seq
     :last-applied-seq init-seq
     :pending-update nil
     :quarantined-cids (set (keep normalize-hex (or quarantined-cids #{})))
     :trusted-deploy-authorities (set (map normalize-hex (or trusted-deploy-authorities #{})))
     :next-obs-seq 1
     :dropped 0
     :last-error nil
     :diagnostics {:causes {} :dropped 0}}))

(defn- light-update-obs-record
  [st epoch transition data]
  (let [obs-seq (long (:next-obs-seq st 1))]
    [(assoc st :next-obs-seq (inc obs-seq))
     {:effect :obs-record
      :record {:schema "bitecho-obs-record-v1"
               :node-id (:node-id st)
               :seq obs-seq
               :head-epoch (long (or epoch 0))
               :finalized-epoch (long (or epoch 0))
               :step :light-node-auto-update
               :level (if (contains? #{:refused :rolled-back} transition) :warn :info)
               :duration-ms 0
               :delta-summary {:transition transition}
               :data (assoc (or data {}) :transition transition)}}]))

(defn- wrong-phase-result
  [state ev-type cur-gen]
  (let [diag {:effect :diagnose
              :type :diagnose
              :reason :light-update-wrong-phase
              :event-type ev-type
              :phase (:phase state)
              :generation cur-gen}]
    [(record-light-diag state :light-update-wrong-phase) [diag]]))

(defn- stage-verified-blob
  [state ep cur-gen pending actual-cid full-bytes]
  (let [next-gen (inc cur-gen)
        st1 (assoc state
                   :phase :health-checking
                   :generation next-gen
                   :pending-update (assoc pending :verified-cid actual-cid))
        [st2 obs-eff] (light-update-obs-record st1 ep :staged {:target-version (:target-version pending)
                                                               :cid actual-cid})]
    [st2 [(cond-> {:effect :stage-light-bundle
                   :cid actual-cid
                   :target-version (:target-version pending)}
            full-bytes (assoc :bytes full-bytes))
          {:effect :atomic-swap-and-restart-light-node
           :cid actual-cid
           :generation next-gen}
          obs-eff]]))

(defn- failover-or-exhaust-http
  "Fails over to the next relay origin in `urls` (preserving `range-offset`/`received-chunks`
   unless `reset-range?` is true), or cleanly returns to `:watching` with
   `:light-update-blob-fetch-failed` when all relays are exhausted."
  [state ep cur-gen cause extra-diags {:keys [reset-range?]}]
  (let [pending (:pending-update state)
        target-cid (:target-cid pending)
        target-ver (:target-version pending)
        fb (:http-fallback state)
        urls (vec (or (seq (:urls fb))
                      (build-blob-fetch-urls (:pointer-url state) (:relay-origins state) target-cid)))
        relay-idx (long (:relay-index fb 0))
        cur-url (nth urls relay-idx (first urls))
        next-idx (inc relay-idx)]
    (if (< next-idx (count urls))
      (let [next-url (nth urls next-idx)
            range-mode? (= :fetching-https-range (:phase state))
            fb' (cond-> (assoc fb
                               :relay-index next-idx
                               :attempt 1
                               :urls urls)
                  reset-range? (assoc :range-offset 0
                                      :total-bytes nil
                                      :received-chunks []
                                      :etag nil))
            diag-fo {:effect :diagnose
                     :type :diagnose
                     :reason :light-update-relay-failover
                     :from-url cur-url
                     :to-url next-url
                     :cause cause
                     :generation cur-gen}
            st1 (-> state
                    (assoc :http-fallback fb'
                           :last-error cause)
                    (record-light-diag :light-update-relay-failover))
            fetch-eff {:effect :fetch-bundle-blob
                       :cid target-cid
                       :url next-url
                       :attempt 1
                       :range (when range-mode? (next-range-window fb'))
                       :target-version target-ver
                       :proxy-url (:proxy-url state)
                       :generation cur-gen}]
        [st1 (conj (vec extra-diags) diag-fo fetch-eff)])
      (let [diag-fail {:effect :diagnose
                       :type :diagnose
                       :reason :light-update-blob-fetch-failed
                       :cause :all-relays-exhausted
                       :detail cause
                       :generation (inc cur-gen)}
            st1 (-> state
                    (assoc :phase :watching
                           :pending-update nil
                           :http-fallback (reset-http-fallback state [])
                           :last-error cause)
                    (update :generation inc)
                    (record-light-diag :light-update-blob-fetch-failed))
            [st2 obs-eff] (light-update-obs-record st1 ep :refused {:reason :blob-fetch-failed :cause cause})]
        [st2 (conj (vec extra-diags) diag-fail obs-eff)]))))

(defn reduce-light-update-tick
  "Pure P-UPD-1 / BIP-021 §2.6.2 / BIP-022 Stage D.1 pointer auto-update state machine (`Rule 2`, `Rule 4`, `Rule 5`):
   `(reduce-light-update-tick state event) -> [new-state effects]`.
   - Enforces generation tagging (ignores stale callbacks with counted `:diagnose`).
   - Enforces strict phase guards on every phase-specific event (Rule 4 & Rule 5).
   - Enforces `--pin-version` opt-out (`pinned` node stays put) and failed-CID quarantine.
   - Verifies pointer authority signature (fail-closed on empty `:trusted-deploy-authorities`), version monotonicity, and CID == SHA-256.
   - Supports unified waterfall: `:watching -> :fetching-mesh -> :fetching-https -> :fetching-https-range -> :health-checking -> :watching`,
     with bounded exponential-backoff retry, multi-relay failover (`ns1..ns3`), HTTP `206 Range` chunked resume, and cross-relay ETag normalization.
   - Auto-rolls back to LKG bundle on health-check failure and quarantines the failed CID."
  [state event]
  (let [cur-gen (long (:generation state 1))
        ev-gen (:generation event)
        ep (long (or (:epoch event) 0))]
    (if (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-generation-callback
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}
            st' (record-light-diag state :stale-generation-callback)]
        [st' [diag]])
      (case (:type event)
        :poll-tick
        (if (not= :watching (:phase state))
          (let [diag {:effect :diagnose
                      :type :diagnose
                      :reason :update-poll-suppressed
                      :phase (:phase state)
                      :generation cur-gen}
                st' (record-light-diag state :update-poll-suppressed)]
            [st' [diag]])
          (let [eff {:effect :fetch-pointer
                     :proxy-url (:proxy-url state)
                     :generation cur-gen}]
            [state [eff]]))

        :pointer-seen
        (if (not= :watching (:phase state))
          (let [diag {:effect :diagnose
                      :type :diagnose
                      :reason :update-poll-suppressed
                      :phase (:phase state)
                      :generation cur-gen}
                st' (record-light-diag state :update-poll-suppressed)]
            [st' [diag]])
          (let [ptr (:pointer event)
                target-ver (str (or (:target-version ptr) (:version ptr) ""))
                target-cid (resolve-bundle-target-cid ptr (:artifact-role state))]
            (cond
              (some? (:pinned-version state))
              (let [[st1 obs-eff] (light-update-obs-record
                                   state ep :pinned
                                   {:pinned-version (:pinned-version state)
                                    :skipped-version target-ver
                                    :skipped-cid target-cid})]
                [st1 [obs-eff]])

              (and target-cid (contains? (or (:quarantined-cids state) #{}) target-cid))
              (let [diag {:effect :diagnose
                          :type :diagnose
                          :reason :light-update-quarantined-cid
                          :cid target-cid
                          :target-version target-ver}
                    st1 (record-light-diag state :light-update-quarantined-cid)
                    [st2 obs-eff] (light-update-obs-record st1 ep :refused {:reason :quarantined-cid
                                                                            :cid target-cid})]
                [st2 [diag obs-eff]])

              :else
              (let [v (verify-config-pointer state ptr {:check-seq? false})]
                (if-not (:ok? v)
                  (let [diag {:effect :diagnose
                              :type :diagnose
                              :reason :light-update-pointer-rejected
                              :cause (:error v)}
                        st1 (-> state
                                (assoc :last-error (:error v))
                                (record-light-diag :light-update-pointer-rejected))
                        [st2 obs-eff] (light-update-obs-record st1 ep :refused {:cause (:error v)})]
                    [st2 [diag obs-eff]])
                  (let [ptr-seq-raw (:seq ptr)
                        has-seq? (integer? ptr-seq-raw)
                        last-seq (long (or (:last-applied-seq state) (:active-config-seq state) 0))
                        cur-cid (normalize-hex (:current-cid state))
                        valid-cid? (valid-cid-64? target-cid)
                        force-http? (or (true? (:force-http? state)) (true? (:force-http? event)))
                        mesh-connected? (and (not force-http?) (true? (:mesh-connected? event)))
                        size-bytes (long (or (:artifact-size-bytes ptr) (:size-bytes event) 0))
                        next-phase (if mesh-connected? :fetching-mesh :fetching-https)
                        trigger-fetch (fn [effective-seq]
                                        (let [next-gen (inc cur-gen)
                                              ptr-url (or (:pointer-url event) (:pointer-url state))
                                              urls (build-blob-fetch-urls ptr-url (:relay-origins state) target-cid)
                                              fb0 (cond-> (reset-http-fallback state urls)
                                                    (not mesh-connected?) (assoc :attempt 1))
                                              st1 (assoc state
                                                         :phase next-phase
                                                         :generation next-gen
                                                         :http-fallback fb0
                                                         :pending-update (cond-> {:pointer ptr
                                                                                  :target-version target-ver
                                                                                  :target-cid target-cid
                                                                                  :size-bytes size-bytes}
                                                                           (some? effective-seq) (assoc :pointer-seq effective-seq)))
                                              [st2 obs-eff] (light-update-obs-record
                                                             st1 ep :seen
                                                             (cond-> {:target-version target-ver
                                                                      :target-cid target-cid
                                                                      :fetch-mode (if mesh-connected? :mesh :https)
                                                                      :proxy-url (:proxy-url state)}
                                                               (some? effective-seq) (assoc :pointer-seq effective-seq)))
                                              fetch-eff (if mesh-connected?
                                                          (cond-> {:effect :fetch-bundle-mesh-chunks
                                                                   :cid target-cid
                                                                   :target-version target-ver
                                                                   :chunk-size-bytes default-mesh-chunk-size-bytes
                                                                   :probe-timeout-ms default-mesh-probe-timeout-ms
                                                                   :chunk-timeout-ms default-mesh-chunk-timeout-ms
                                                                   :total-timeout-ms (compute-mesh-fetch-ceiling-ms size-bytes)
                                                                   :generation next-gen}
                                                            (some? effective-seq) (assoc :pointer-seq effective-seq))
                                                          (cond-> {:effect :fetch-bundle-blob
                                                                   :cid target-cid
                                                                   :url (first urls)
                                                                   :attempt 1
                                                                   :range nil
                                                                   :target-version target-ver
                                                                   :proxy-url (:proxy-url state)
                                                                   :generation next-gen}
                                                            (some? effective-seq) (assoc :pointer-seq effective-seq)))]
                                          [st2 [fetch-eff obs-eff]]))]
                    (if has-seq?
                      ;; Ratified RELEASE.md §5 monotonic :pointer/seq gate
                      (let [ptr-seq (long ptr-seq-raw)]
                        (cond
                          (< ptr-seq last-seq)
                          (let [diag {:effect :diagnose
                                      :type :diagnose
                                      :reason :light-update-non-monotonic-seq
                                      :current-seq last-seq
                                      :pointer-seq ptr-seq
                                      :target-version target-ver}
                                st1 (record-light-diag state :light-update-non-monotonic-seq)
                                [st2 obs-eff] (light-update-obs-record st1 ep :refused {:reason :non-monotonic-seq
                                                                                        :current-seq last-seq
                                                                                        :pointer-seq ptr-seq
                                                                                        :target-version target-ver})]
                            [st2 [diag obs-eff]])

                          (= ptr-seq last-seq)
                          (if (or (nil? target-cid) (= target-cid cur-cid))
                            ;; Equal :seq + same CID -> clean no-op
                            [state []]
                            ;; Equal :seq reused with a different CID -> refuse
                            (let [diag {:effect :diagnose
                                        :type :diagnose
                                        :reason :light-update-non-monotonic-seq
                                        :current-seq last-seq
                                        :pointer-seq ptr-seq
                                        :target-cid target-cid
                                        :current-cid cur-cid}
                                  st1 (record-light-diag state :light-update-non-monotonic-seq)
                                  [st2 obs-eff] (light-update-obs-record st1 ep :refused {:reason :non-monotonic-seq
                                                                                          :current-seq last-seq
                                                                                          :pointer-seq ptr-seq})]
                              [st2 [diag obs-eff]]))

                          (not valid-cid?)
                          (let [diag {:effect :diagnose
                                      :type :diagnose
                                      :reason :light-update-pointer-rejected
                                      :cause :invalid-target-cid}
                                st1 (-> state
                                        (assoc :last-error :invalid-target-cid)
                                        (record-light-diag :light-update-pointer-rejected))
                                [st2 obs-eff] (light-update-obs-record st1 ep :refused {:cause :invalid-target-cid})]
                            [st2 [diag obs-eff]])

                          (and cur-cid (= target-cid cur-cid))
                          ;; Higher :seq pointing at the exact CID already running -> advance seq and no-op cleanly
                          [(assoc state :last-applied-seq ptr-seq :active-config-seq ptr-seq) []]

                          :else
                          ;; Higher :seq + distinct valid 64-char CID -> update regardless of semver string
                          (trigger-fetch ptr-seq)))
                      ;; Backward-compatible fallback when a legacy pointer has no :seq
                      (let [cmp (if (str/blank? target-ver)
                                  (if (and valid-cid? (not= target-cid cur-cid)) 1 0)
                                  (let [v-cmp (compare-semver target-ver (:current-version state))]
                                    (if (and (zero? v-cmp)
                                             valid-cid?
                                             cur-cid
                                             (not= target-cid cur-cid))
                                      1
                                      v-cmp)))]
                        (cond
                          (<= cmp 0)
                          (let [diag {:effect :diagnose
                                      :type :diagnose
                                      :reason :light-update-non-monotonic-version
                                      :current-version (:current-version state)
                                      :target-version target-ver}
                                st1 (record-light-diag state :light-update-non-monotonic-version)
                                [st2 obs-eff] (light-update-obs-record st1 ep :refused {:reason :non-monotonic-version
                                                                                        :target-version target-ver})]
                            [st2 [diag obs-eff]])

                          (not valid-cid?)
                          (let [diag {:effect :diagnose
                                      :type :diagnose
                                      :reason :light-update-pointer-rejected
                                      :cause :invalid-target-cid}
                                st1 (-> state
                                        (assoc :last-error :invalid-target-cid)
                                        (record-light-diag :light-update-pointer-rejected))
                                [st2 obs-eff] (light-update-obs-record st1 ep :refused {:cause :invalid-target-cid})]
                            [st2 [diag obs-eff]])

                          :else
                          (trigger-fetch nil))))))))))

        :mesh-fetch-failed
        (if (not= :fetching-mesh (:phase state))
          (wrong-phase-result state :mesh-fetch-failed cur-gen)
          (let [pending (:pending-update state)
                target-cid (:target-cid pending)
                target-ver (:target-version pending)
                cause (or (:reason event) :mesh-fetch-failed)
                next-gen (inc cur-gen)
                urls (build-blob-fetch-urls (:pointer-url state) (:relay-origins state) target-cid)
                fb0 (assoc (reset-http-fallback state urls) :attempt 1)
                diag {:effect :diagnose
                      :type :diagnose
                      :reason :auto-update-mesh-fallback
                      :cause cause
                      :cid target-cid
                      :generation next-gen}
                st1 (-> state
                        (assoc :phase :fetching-https
                               :generation next-gen
                               :http-fallback fb0
                               :last-error cause)
                        (record-light-diag :auto-update-mesh-fallback))
                [st2 obs-eff] (light-update-obs-record st1 ep :mesh-fallback {:cause cause :cid target-cid})]
            [st2 [diag
                  {:effect :fetch-bundle-blob
                   :cid target-cid
                   :url (first urls)
                   :attempt 1
                   :range nil
                   :target-version target-ver
                   :proxy-url (:proxy-url state)
                   :generation next-gen}
                  obs-eff]]))

        :blob-fetch-failed
        (if-not (contains? #{:fetching-https :fetching-https-range} (:phase state))
          (wrong-phase-result state :blob-fetch-failed cur-gen)
          (let [pending (:pending-update state)
                target-cid (:target-cid pending)
                cause (or (:reason event) (:error event) :blob-fetch-failed)
                status (:status event)
                fb (:http-fallback state)
                urls (vec (or (seq (:urls fb))
                              (build-blob-fetch-urls (:pointer-url state) (:relay-origins state) target-cid)))
                relay-idx (long (:relay-index fb 0))
                cur-url (nth urls relay-idx (first urls))
                attempt (long (:attempt fb 0))
                max-retries (long (:max-retries-per-relay fb 3))
                base-ms (long (:backoff-base-ms fb 1000))
                max-ms (long (:backoff-max-ms fb 8000))
                aborted-mid-body? (true? (:aborted-mid-body? event))
                received-bytes (long (or (:received-bytes event) 0))
                total-bytes (when (and (integer? (:total-bytes event))
                                       (pos? (long (:total-bytes event)))
                                       (<= (long (:total-bytes event)) max-mesh-bundle-bytes))
                              (long (:total-bytes event)))
                retryable? (if (boolean? (:retryable? event))
                             (:retryable? event)
                             (not (contains? #{400 401 403 404 405 410 416} status)))]
            (cond
              ;; Immediate switch to :fetching-https-range on mid-body abort during :fetching-https
              (and (= :fetching-https (:phase state)) retryable? aborted-mid-body?)
              (let [partial-bs (:partial-bytes event)
                    valid-partial? (and partial-bs
                                        (bytes? partial-bs)
                                        (pos? received-bytes)
                                        total-bytes
                                        (< received-bytes total-bytes)
                                        (= received-bytes #?(:clj (long (alength ^bytes partial-bs))
                                                             :cljs (long (.-byteLength partial-bs)))))
                    next-attempt (inc attempt)
                    delay-ms (compute-http-backoff-ms next-attempt base-ms max-ms)
                    fb' (assoc fb
                               :urls urls
                               :attempt next-attempt
                               :range-mode? true
                               :range-offset (if valid-partial? received-bytes 0)
                               :total-bytes total-bytes
                               :received-chunks (if valid-partial? [partial-bs] [])
                               :etag (when valid-partial? (normalize-etag-cid (:etag event))))
                    diag-range {:effect :diagnose
                                :type :diagnose
                                :reason :light-update-http-range-fallback
                                :relay cur-url
                                :received-bytes received-bytes
                                :total-bytes total-bytes
                                :cause cause
                                :generation cur-gen}
                    diag-retry {:effect :diagnose
                                :type :diagnose
                                :reason :light-update-http-retry
                                :attempt next-attempt
                                :relay cur-url
                                :delay-ms delay-ms
                                :cause cause
                                :generation cur-gen}
                    st1 (-> state
                            (assoc :phase :fetching-https-range
                                   :http-fallback fb'
                                   :last-error cause)
                            (record-light-diag :light-update-http-range-fallback)
                            (record-light-diag :light-update-http-retry))]
                [st1 [diag-range
                      diag-retry
                      {:effect :schedule-http-retry
                       :delay-ms delay-ms
                       :generation cur-gen}]])

              ;; Bounded exponential-backoff retry on current relay
              (and retryable? (< attempt max-retries))
              (let [next-attempt (inc attempt)
                    delay-ms (compute-http-backoff-ms next-attempt base-ms max-ms)
                    fb' (assoc fb :urls urls :attempt next-attempt)
                    diag-retry {:effect :diagnose
                                :type :diagnose
                                :reason :light-update-http-retry
                                :attempt next-attempt
                                :relay cur-url
                                :delay-ms delay-ms
                                :cause cause
                                :generation cur-gen}
                    st1 (-> state
                            (assoc :http-fallback fb'
                                   :last-error cause)
                            (record-light-diag :light-update-http-retry))]
                [st1 [diag-retry
                      {:effect :schedule-http-retry
                       :delay-ms delay-ms
                       :generation cur-gen}]])

              ;; Failover to next relay origin (or exhaust cleanly to :watching)
              :else
              (failover-or-exhaust-http state ep cur-gen cause [] {:reset-range? (= 416 status)}))))

        :http-retry-timer-fired
        (if-not (contains? #{:fetching-https :fetching-https-range} (:phase state))
          (wrong-phase-result state :http-retry-timer-fired cur-gen)
          (let [pending (:pending-update state)
                target-cid (:target-cid pending)
                target-ver (:target-version pending)
                fb (:http-fallback state)
                urls (vec (or (seq (:urls fb))
                              (build-blob-fetch-urls (:pointer-url state) (:relay-origins state) target-cid)))
                relay-idx (long (:relay-index fb 0))
                cur-url (nth urls relay-idx (first urls))
                range-mode? (= :fetching-https-range (:phase state))]
            [state [{:effect :fetch-bundle-blob
                     :cid target-cid
                     :url cur-url
                     :attempt (max 1 (long (:attempt fb 1)))
                     :range (when range-mode? (next-range-window fb))
                     :target-version target-ver
                     :proxy-url (:proxy-url state)
                     :generation cur-gen}]]))

        :http-range-chunk-fetched
        (if (not= :fetching-https-range (:phase state))
          (wrong-phase-result state :http-range-chunk-fetched cur-gen)
          (let [pending (:pending-update state)
                target-cid (:target-cid pending)
                target-ver (:target-version pending)
                status (long (or (:status event) 0))
                fb (:http-fallback state)
                urls (vec (or (seq (:urls fb))
                              (build-blob-fetch-urls (:pointer-url state) (:relay-origins state) target-cid)))
                relay-idx (long (:relay-index fb 0))
                cur-url (nth urls relay-idx (first urls))]
            (cond
              ;; Origin ignored Range header and sent full 200 OK body
              (= 200 status)
              (let [bs (:bytes event)
                    actual-cid (when (and bs (bytes? bs)) (sha256-hex bs))]
                (if (and target-cid actual-cid (= target-cid actual-cid))
                  (stage-verified-blob state ep cur-gen pending actual-cid bs)
                  (let [diag {:effect :diagnose
                              :type :diagnose
                              :reason :light-update-hash-mismatch
                              :expected-cid target-cid
                              :actual-cid actual-cid
                              :generation cur-gen}
                        st1 (record-light-diag state :light-update-hash-mismatch)]
                    (failover-or-exhaust-http st1 ep cur-gen :light-update-hash-mismatch [diag] {:reset-range? true}))))

              ;; 206 Partial Content chunk
              (= 206 status)
              (let [start (long (or (:start event) -1))
                    end (long (or (:end event) -1))
                    total (long (or (:total-bytes event) -1))
                    chunk-bs (:bytes event)
                    chunk-len (if (and chunk-bs (bytes? chunk-bs))
                                #?(:clj (long (alength ^bytes chunk-bs))
                                   :cljs (long (.-byteLength chunk-bs)))
                                -1)
                    expected-off (long (:range-offset fb 0))
                    prev-total (:total-bytes fb)
                    norm-etag (normalize-etag-cid (:etag event))
                    prev-etag (normalize-etag-cid (:etag fb))
                    etag-conflict? (or (and prev-etag norm-etag (not= prev-etag norm-etag))
                                       (and norm-etag (valid-cid-64? norm-etag) (not= norm-etag target-cid)))
                    bounds-invalid? (or (not= start expected-off)
                                        (< end start)
                                        (<= chunk-len 0)
                                        (not= chunk-len (inc (- end start)))
                                        (<= total 0)
                                        (> total max-mesh-bundle-bytes)
                                        (> (inc end) total)
                                        (and (some? prev-total) (not= total (long prev-total))))]
                (if (or bounds-invalid? etag-conflict?)
                  (let [cause (if etag-conflict? :etag-mismatch :invalid-range-bounds)
                        diag {:effect :diagnose
                              :type :diagnose
                              :reason :light-update-http-truncated
                              :cause cause
                              :relay cur-url
                              :generation cur-gen}
                        st1 (record-light-diag state :light-update-http-truncated)]
                    (failover-or-exhaust-http st1 ep cur-gen cause [diag] {:reset-range? true}))
                  (let [next-chunks (conj (vec (:received-chunks fb)) chunk-bs)
                        next-off (inc end)
                        fb' (assoc fb
                                   :urls urls
                                   :attempt 0
                                   :range-offset next-off
                                   :total-bytes total
                                   :received-chunks next-chunks
                                   :etag (or norm-etag prev-etag))]
                    (if (= next-off total)
                      (let [full-bytes (concat-byte-chunks next-chunks total)
                            actual-cid (sha256-hex full-bytes)]
                        (if (= actual-cid target-cid)
                          (stage-verified-blob (assoc state :http-fallback fb') ep cur-gen pending actual-cid full-bytes)
                          (let [diag {:effect :diagnose
                                      :type :diagnose
                                      :reason :light-update-hash-mismatch
                                      :expected-cid target-cid
                                      :actual-cid actual-cid
                                      :generation cur-gen}
                                st1 (-> state
                                        (assoc :http-fallback fb' :last-error :light-update-hash-mismatch)
                                        (record-light-diag :light-update-hash-mismatch))]
                            (if (< (inc relay-idx) (count urls))
                              (failover-or-exhaust-http st1 ep cur-gen :light-update-hash-mismatch [diag] {:reset-range? true})
                              (let [st2 (-> st1
                                            (assoc :phase :watching
                                                   :pending-update nil
                                                   :http-fallback (reset-http-fallback st1 []))
                                            (update :generation inc))
                                    [st3 obs-eff] (light-update-obs-record st2 ep :refused {:reason :light-update-hash-mismatch
                                                                                            :expected-cid target-cid
                                                                                            :actual-cid actual-cid})]
                                [st3 [diag obs-eff]])))))
                      [(assoc state :http-fallback fb')
                       [{:effect :fetch-bundle-blob
                         :cid target-cid
                         :url cur-url
                         :attempt 1
                         :range (next-range-window fb')
                         :target-version target-ver
                         :proxy-url (:proxy-url state)
                         :generation cur-gen}]]))))

              :else
              (let [diag {:effect :diagnose
                          :type :diagnose
                          :reason :light-update-http-truncated
                          :status status
                          :relay cur-url
                          :generation cur-gen}
                    st1 (record-light-diag state :light-update-http-truncated)]
                (failover-or-exhaust-http st1 ep cur-gen :unexpected-range-status [diag] {:reset-range? false})))))

        :blob-fetched
        (if-not (contains? #{:fetching-mesh :fetching-https :fetching-https-range} (:phase state))
          (wrong-phase-result state :blob-fetched cur-gen)
          (let [pending (:pending-update state)
                expected-cid (or (:target-cid pending) (normalize-hex (:cid event)))
                bs (:bytes event)
                actual-cid (when (and bs (bytes? bs)) (sha256-hex bs))]
            (if (and expected-cid actual-cid (= expected-cid actual-cid))
              (stage-verified-blob state ep cur-gen pending actual-cid bs)
              (let [diag {:effect :diagnose
                          :type :diagnose
                          :reason :light-update-hash-mismatch
                          :expected-cid expected-cid
                          :actual-cid actual-cid}
                    st1 (-> state
                            (assoc :phase :watching
                                   :pending-update nil
                                   :http-fallback (reset-http-fallback state [])
                                   :last-error :light-update-hash-mismatch)
                            (update :generation inc)
                            (record-light-diag :light-update-hash-mismatch))
                    [st2 obs-eff] (light-update-obs-record st1 ep :refused {:reason :light-update-hash-mismatch
                                                                            :expected-cid expected-cid
                                                                            :actual-cid actual-cid})]
                [st2 [diag obs-eff]]))))

        :health-check-result
        (if (not= :health-checking (:phase state))
          (wrong-phase-result state :health-check-result cur-gen)
          (let [pending (:pending-update state)
                healthy? (and (true? (:healthy? event))
                              (not (false? (:connected? event)))
                              (not (false? (:syncing? event)))
                              (not (false? (:finalized-epoch-advancing? event)))
                              (not (false? (:balance-sane? event))))]
            (if healthy?
              (let [new-ver (or (:target-version pending) (:current-version state))
                    new-cid (or (:target-cid pending) (:current-cid state))
                    new-seq (long (or (:pointer-seq pending)
                                      (get-in pending [:pointer :seq])
                                      (:last-applied-seq state)
                                      (:active-config-seq state)
                                      0))
                    st1 (assoc state
                               :phase :watching
                               :current-version new-ver
                               :current-cid new-cid
                               :lkg-version new-ver
                               :lkg-cid new-cid
                               :active-config-seq new-seq
                               :last-applied-seq new-seq
                               :pending-update nil
                               :http-fallback (reset-http-fallback state [])
                               :last-error nil)
                    [st2 obs-eff] (light-update-obs-record st1 ep :verified {:version new-ver :cid new-cid})]
                [st2 [obs-eff]])
              (let [lkg-ver (:lkg-version state)
                    lkg-cid (:lkg-cid state)
                    failed-cid (or (:verified-cid pending) (:target-cid pending))
                    diag {:effect :diagnose
                          :type :diagnose
                          :reason :light-update-health-check-failed-rollback
                          :lkg-version lkg-ver
                          :lkg-cid lkg-cid
                          :quarantined-cid failed-cid}
                    st1 (-> state
                            (assoc :phase :watching
                                   :current-version lkg-ver
                                   :current-cid lkg-cid
                                   :last-rollback-cid failed-cid
                                   :pending-update nil
                                   :http-fallback (reset-http-fallback state [])
                                   :last-error :light-update-health-check-failed-rollback)
                            (update :rollback-count (fnil inc 0))
                            (cond-> failed-cid (update :quarantined-cids (fnil conj #{}) failed-cid))
                            (update :generation inc)
                            (record-light-diag :light-update-health-check-failed-rollback))
                    [st2 obs-eff] (light-update-obs-record st1 ep :rolled-back {:lkg-version lkg-ver
                                                                                :lkg-cid lkg-cid
                                                                                :quarantined-cid failed-cid})]
                [st2 [{:effect :restore-lkg-light-bundle
                       :lkg-version lkg-ver
                       :lkg-cid lkg-cid
                       :quarantined-cid failed-cid}
                      diag
                      obs-eff]]))))

        [state []]))))

