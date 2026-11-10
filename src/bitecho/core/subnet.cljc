(ns bitecho.core.subnet
  "Unified Sans-IO Subnet Policy, Relocated Bully `:leader-election` Engine,
   `reduce-subnet` Reducer, and Thin Pointer Adapters (UNIFICATION.md §§5-8):
   - Validates constrained policy axes (`:subnet/gate`, `:subnet/economy`, `:subnet/replication`)
     and explicit `:subnet/genesis-policy-cid` pinning fail-closed with counted `:diagnose` effects.
   - Relocates `web.cluster.protocol`'s pure Bully + `2s`/`6s` liveness reducer as the `:leader-election`
     replication engine with split-brain quorum (`>= 2`) and clock-free monotonic `:term`.
   - Enforces `subnet/policy` governance (Cold Root Key or `k-of-n` `:trust-anchors` quorum,
     blocking unilateral hot-leader mutations).
   - Provides thin Pointer/Blob adapters for Directory descriptors, Bootstrap descriptors, DACs,
     and Home-Set registrations over `bitecho.core.data`.
   100% pure `.cljc` portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [clojure.string :as str]))

(defn- normalize-hex
  [s]
  (when (and (string? s) (not (str/blank? s)))
    (str/lower-case (str/trim s))))

;; =============================================================================
;; 1. Subnet Policy Hashing & Constrained-Axis Validation (Gaps G5 & G10)
;; =============================================================================

(defn policy-cid
  "Computes the deterministic lowercase SHA-256 hex CID of a Subnet policy map
   (excluding `:subnet/genesis-policy-cid` itself)."
  [policy]
  (let [clean (dissoc policy :subnet/genesis-policy-cid)
        encoded (fressian/encode-canonical clean)]
    (data/compute-cid encoded)))

(defn validate-subnet-policy
  "Validates a Subnet policy map against UNIFICATION.md §2.1 & §5 axis constraints:
   - `:streamlet-bft` and `:leader-election` require `:gate/mode :permissioned`
   - `:gate/admission :min-stake` requires `:economy/mode` in `#{:burn-only :full-settlement}`
   - `:economy/mode :full-settlement` requires a settlement anchor (`:subnet/parent-id` or root `global`/`validator-core`)
   - When `:subnet/genesis-policy-cid` is present, it must match `(policy-cid policy)`.
   Returns `{:ok? true :policy policy}` or `{:ok? false :error <kw> :effects [diagnose]}`."
  [policy]
  (if-not (and (map? policy)
               (string? (:subnet/id policy))
               (not (str/blank? (:subnet/id policy))))
    {:ok? false
     :error :malformed-subnet-policy
     :effects [{:effect :diagnose :reason :malformed-subnet-policy}]}
    (let [sid (:subnet/id policy)
          parent-id (:subnet/parent-id policy)
          gate (:subnet/gate policy)
          gate-mode (:gate/mode gate)
          admission (:gate/admission gate)
          econ (:subnet/economy policy)
          econ-mode (:economy/mode econ)
          rep (:subnet/replication policy)
          ptr-rep (:replication/pointers rep)
          blob-rep (:replication/blobs rep)
          gen-cid (:subnet/genesis-policy-cid policy)]
      (cond
        (not (contains? #{:permissionless :permissioned} gate-mode))
        {:ok? false
         :error :invalid-gate-mode
         :effects [{:effect :diagnose :reason :invalid-gate-mode :subnet sid}]}

        (not (contains? #{:open :allowlist :dac :mtls-cert :min-stake} admission))
        {:ok? false
         :error :invalid-gate-admission
         :effects [{:effect :diagnose :reason :invalid-gate-admission :subnet sid}]}

        (and (= gate-mode :permissioned) (= admission :open))
        {:ok? false
         :error :permissioned-cannot-use-open-admission
         :effects [{:effect :diagnose :reason :permissioned-cannot-use-open-admission :subnet sid}]}

        (not (contains? #{:none :burn-only :full-settlement} econ-mode))
        {:ok? false
         :error :invalid-economy-mode
         :effects [{:effect :diagnose :reason :invalid-economy-mode :subnet sid}]}

        (not (contains? #{:gossip-crdt :streamlet-bft :leader-election} ptr-rep))
        {:ok? false
         :error :invalid-pointer-replication
         :effects [{:effect :diagnose :reason :invalid-pointer-replication :subnet sid}]}

        (not (contains? #{:eager-push :pull-on-demand} blob-rep))
        {:ok? false
         :error :invalid-blob-replication
         :effects [{:effect :diagnose :reason :invalid-blob-replication :subnet sid}]}

        (and (contains? #{:streamlet-bft :leader-election} ptr-rep)
             (not= gate-mode :permissioned))
        {:ok? false
         :error :consensus-requires-permissioned-gate
         :effects [{:effect :diagnose :reason :consensus-requires-permissioned-gate :subnet sid}]}

        (and (= admission :min-stake)
             (not (contains? #{:burn-only :full-settlement} econ-mode)))
        {:ok? false
         :error :min-stake-requires-economy
         :effects [{:effect :diagnose :reason :min-stake-requires-economy :subnet sid}]}

        (and (= econ-mode :full-settlement)
             (nil? parent-id)
             (not (contains? #{"global" "validator-core"} sid)))
        {:ok? false
         :error :full-settlement-requires-anchor
         :effects [{:effect :diagnose :reason :full-settlement-requires-anchor :subnet sid}]}

        (and (some? gen-cid)
             (not= (normalize-hex gen-cid) (policy-cid policy)))
        {:ok? false
         :error :genesis-policy-cid-mismatch
         :effects [{:effect :diagnose :reason :genesis-policy-cid-mismatch :subnet sid}]}

        :else
        {:ok? true :policy policy :effects []}))))

;; =============================================================================
;; 2. Relocated Pure Bully `:leader-election` Engine (Decision D1 & Gap G8)
;; =============================================================================

(defn- node-sort-key
  [nid]
  (cond
    (keyword? nid) (name nid)
    (symbol? nid) (name nid)
    :else (str nid)))

(defn init-leader-election
  "Initializes pure Bully leader-election & peer liveness state (`2s` heartbeat / `6s` timeout defaults)."
  [opts]
  (let [node-id (:node-id opts)
        raw-all (or (:all-nodes opts) (when node-id #{node-id}) #{})
        all-nodes (set raw-all)
        peer-ids (disj all-nodes node-id)
        hb-interval (long (or (:heartbeat-interval-ms opts) 2000))
        hb-timeout (long (or (:heartbeat-timeout-ms opts) 6000))
        peers (into {} (map (fn [pid] [pid {:last-seen-ms nil :connected? false}]) peer-ids))
        healthy (if node-id #{node-id} #{})
        leader (when (and (= 1 (count all-nodes)) node-id) node-id)]
    {:node-id node-id
     :all-nodes all-nodes
     :heartbeat-interval-ms hb-interval
     :heartbeat-timeout-ms hb-timeout
     :peers peers
     :healthy-nodes healthy
     :leader-id leader
     :role (if (and leader (= leader node-id)) :leader :follower)
     :term (if leader 1 0)}))

(defn compute-healthy-nodes
  "Returns reachable nodes (local `:node-id` + peers seen within `:heartbeat-timeout-ms`)."
  [le-state now-ms]
  (let [node-id (:node-id le-state)
        hb-timeout (long (:heartbeat-timeout-ms le-state 6000))
        healthy-peers (keep (fn [[pid info]]
                              (let [seen (:last-seen-ms info)]
                                (when (and seen (< (- (long now-ms) (long seen)) hb-timeout))
                                  pid)))
                            (:peers le-state))]
    (cond-> (set healthy-peers)
      node-id (conj node-id))))

(defn elect-leader
  "Determines leader from `healthy-nodes` and `total-configured-nodes`.
   Enforces split-brain quorum (`>= 2` healthy nodes required when `total > 1`)."
  [healthy-nodes total-configured-nodes]
  (cond
    (empty? healthy-nodes) nil
    (<= (long total-configured-nodes) 1) (first healthy-nodes)
    (< (count healthy-nodes) 2) nil
    :else (first (sort-by node-sort-key healthy-nodes))))

(defn step-leader-election
  "Pure reducer advancing leader-election state on `:tick`, `:heartbeat`, `:peer-connected`, or `:peer-disconnected`.
   Maintains clock-free monotonic `:term` across leader elections and peer heartbeats, converging to the
   peer's `:term` when adopting an already-elected leader rather than leapfrogging terms."
  [le-state event now-ms]
  (let [t (long (or now-ms 0))
        etype (:type event)
        local-term (long (:term le-state 0))
        remote-term (if (= etype :heartbeat) (long (or (:term event) 0)) 0)
        remote-leader (when (= etype :heartbeat) (:leader-id event))
        base-term (max local-term remote-term)
        st1 (case etype
              :heartbeat
              (let [from (:from event)]
                (cond-> (assoc le-state :term base-term)
                  from (assoc-in [:peers from] {:last-seen-ms t :connected? true})))

              :peer-connected
              (let [pid (:peer-id event)]
                (cond-> le-state
                  pid (assoc-in [:peers pid] {:last-seen-ms t :connected? true})))

              :peer-disconnected
              (let [pid (:peer-id event)]
                (cond-> le-state
                  pid (-> (assoc-in [:peers pid :connected?] false)
                          (assoc-in [:peers pid :last-seen-ms] nil))))

              le-state)
        healthy (compute-healthy-nodes st1 t)
        prev-leader (:leader-id st1)
        leader (elect-leader healthy (count (:all-nodes st1)))
        leader-changed? (and (some? leader) (not= leader prev-leader))
        adopted-remote-term? (and (= etype :heartbeat)
                                  (> remote-term local-term)
                                  (or (nil? remote-leader) (= remote-leader leader)))
        new-role (if (and leader (= leader (:node-id st1))) :leader :follower)
        new-term (if (and leader-changed? (not adopted-remote-term?))
                   (inc base-term)
                   base-term)
        effects (cond-> []
                  leader-changed?
                  (conj {:effect :leader-elected :leader-id leader :term new-term})
                  (= etype :tick)
                  (conj {:effect :broadcast-heartbeat
                         :from (:node-id st1)
                         :term new-term
                         :leader-id leader}))]
    {:state (assoc st1
                   :healthy-nodes healthy
                   :leader-id leader
                   :role new-role
                   :term new-term)
     :effects effects}))

;; =============================================================================
;; 3. Gate Admission & `reduce-subnet` Unified Reducer
;; =============================================================================

(defn- verify-dac-credential
  "Verifies a DAC map against `:gate/trust-anchors` and expected `sender-pubkey`."
  [dac sender-pubkey trust-anchors current-epoch]
  (if-not (and (map? dac)
               (string? (:anchor-pubkey dac))
               (string? (:agent-pubkey dac))
               (string? (:signature dac)))
    false
    (let [norm-anchor (normalize-hex (:anchor-pubkey dac))
          norm-agent (normalize-hex (:agent-pubkey dac))
          norm-sender (normalize-hex sender-pubkey)
          anchors (set (map normalize-hex trust-anchors))
          iss-ep (long (or (:issued-epoch dac) 0))
          exp-ep (long (or (:expires-epoch dac) 0))
          max-spend (long (or (:max-spend-per-epoch dac) 0))
          sorted-scopes (vec (sort (distinct (map #(str/lower-case (name %)) (or (:scopes dac) [])))))
          canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," sorted-scopes))
          pub-bytes (try (basalt/hex->bytes norm-anchor) (catch #?(:clj Exception :cljs :default) _ nil))
          sig-bytes (try (basalt/hex->bytes (:signature dac)) (catch #?(:clj Exception :cljs :default) _ nil))]
      (boolean
       (and (= norm-agent norm-sender)
            (contains? anchors norm-anchor)
            (integer? current-epoch)
            (<= iss-ep (long current-epoch))
            (>= exp-ep (long current-epoch))
            pub-bytes
            sig-bytes
            (crypto/verify pub-bytes (fressian/utf8->bytes canonical-str) sig-bytes))))))

(defn check-gate-admission
  "Purely evaluates whether `event` satisfies `(:subnet/gate policy)`."
  [policy state event]
  (let [gate (:subnet/gate policy)
        mode (:gate/mode gate)
        admission (:gate/admission gate)
        anchors (set (map normalize-hex (or (:gate/trust-anchors gate) #{})))
        gov (:gate/governance gate)
        cold-pk (normalize-hex (:cold-pubkey gov))
        sender (normalize-hex (or (:sender event)
                                  (get-in event [:pointer :pointer/authority])
                                  (:from event)))]
    (cond
      ;; Cold governance key is always admitted for policy administration
      (and cold-pk sender (= sender cold-pk))
      {:admitted? true :member sender}

      (= mode :permissionless)
      (if (= admission :min-stake)
        (let [stake (long (get-in state [:stakes sender] (or (:stake event) 0)))
              min-s (long (or (:gate/min-stake gate) 1))]
          (if (>= stake min-s)
            {:admitted? true :member sender}
            {:admitted? false :error :insufficient-stake}))
        {:admitted? true :member sender})

      :else
      (case admission
        :allowlist
        (if (and sender (contains? anchors sender))
          {:admitted? true :member sender}
          {:admitted? false :error :not-in-allowlist})

        :dac
        (if (and sender (or (contains? anchors sender)
                            (verify-dac-credential (:dac event) sender anchors (:epoch event))))
          {:admitted? true :member sender}
          {:admitted? false :error :invalid-or-missing-dac})

        :mtls-cert
        (let [cert-pub (normalize-hex (or (:mtls-client-pubkey event) sender))]
          (if (and cert-pub (or (contains? anchors cert-pub)
                                (verify-dac-credential (:dac event) cert-pub anchors (:epoch event))))
            {:admitted? true :member cert-pub}
            {:admitted? false :error :mtls-admission-denied}))

        :min-stake
        (let [stake (long (get-in state [:stakes sender] (or (:stake event) 0)))
              min-s (long (or (:gate/min-stake gate) 1))]
          (if (and sender (>= stake min-s))
            {:admitted? true :member sender}
            {:admitted? false :error :insufficient-stake}))

        {:admitted? false :error :unsupported-admission-mode}))))

(defn init-subnet-instance
  "Validates `policy` and initializes a unified Subnet state map (`:bitecho.subnet/unified? true`)."
  ([policy]
   (init-subnet-instance policy nil))
  ([policy opts]
   (let [v-res (validate-subnet-policy policy)]
     (if-not (:ok? v-res)
       v-res
       (let [sid (:subnet/id policy)
             anchors (set (map normalize-hex (get-in policy [:subnet/gate :gate/trust-anchors] #{})))
             ptr-rep (get-in policy [:subnet/replication :replication/pointers])
             all-nodes (or (:all-nodes opts) anchors)
             node-id (or (normalize-hex (:node-id opts)) (:node-id opts))
             le-state (when (= ptr-rep :leader-election)
                        (init-leader-election (assoc opts :node-id node-id :all-nodes all-nodes)))]
         {:ok? true
          :effects []
          :instance {:bitecho.subnet/unified? true
                     :subnet-id sid
                     :policy policy
                     :data (data/init-data-state opts)
                     :admitted-members anchors
                     :leader-election le-state
                     :burned-ech 0
                     :diagnostics {:gate-rejected 0
                                   :insufficient-burn 0
                                   :policy-rejected 0}}})))))

(defn- pointer-verify-ctx
  [instance admitted-member now-ms]
  (let [policy (:policy instance)
        le (:leader-election instance)
        anchors (set (map normalize-hex (get-in policy [:subnet/gate :gate/trust-anchors] #{})))
        event-admitted (cond-> (set (:admitted-members instance anchors))
                         admitted-member (conj admitted-member))]
    (cond-> {:subnet (:subnet/id policy)
             :path-acl (or (:subnet/path-acl policy) [])
             :trust-anchors anchors
             :admitted-members event-admitted
             :governance (get-in policy [:subnet/gate :gate/governance])
             :leader-pubkeys anchors
             :current-leader (when le (:leader-id le))
             :min-leader-term (when le (:term le))
             :blobs (get-in instance [:data :blobs])
             :now-ms now-ms}
      (get-in policy [:subnet/gate :gate/acme-thumbprint])
      (assoc :acme-thumbprint (get-in policy [:subnet/gate :gate/acme-thumbprint]))
      (get-in policy [:subnet/gate :gate/allowed-dac-capabilities])
      (assoc :allowed-dac-capabilities (get-in policy [:subnet/gate :gate/allowed-dac-capabilities])))))

(defn reduce-subnet
  "Pure Sans-IO unified Subnet reducer (`Gate -> Economy -> Replication`):
   Accepts an initialized `instance` (or `[policy state]`) and `event`, returning
   `{:state updated-instance :applied? boolean :effects [...]}`."
  [instance event]
  (let [now-ms (long (or (:now-ms event) 0))
        etype (:type event)
        policy (:policy instance)
        sid (:subnet/id policy)]
    (case etype
      (:leader-tick :leader-heartbeat :peer-connected :peer-disconnected)
      (if-let [le (:leader-election instance)]
        (let [le-ev (case etype
                      :leader-tick {:type :tick}
                      :leader-heartbeat (assoc event :type :heartbeat :from (or (normalize-hex (:from event)) (:from event)))
                      event)
              le-res (step-leader-election le le-ev now-ms)]
          {:state (assoc instance :leader-election (:state le-res))
           :applied? true
           :effects (:effects le-res)})
        {:state instance :applied? false :effects []})

      ;; Data / Pointer operations go through Gate -> Economy -> Replication
      (let [adm (check-gate-admission policy instance event)]
        (if-not (:admitted? adm)
          (let [diag {:effect :diagnose
                      :reason :subnet-gate-rejected
                      :error (:error adm)
                      :subnet sid}]
            {:state (update-in instance [:diagnostics :gate-rejected] (fnil inc 0))
             :applied? false
             :error (:error adm)
             :effects [diag]})
          (let [econ (:subnet/economy policy)
                econ-mode (:economy/mode econ :none)
                burn-floor (long (:economy/burn-floor econ 0))
                provided-burn (long (or (:burn event) 0))]
            (if (and (not= econ-mode :none)
                     (contains? #{:put-blob :publish-pointer} etype)
                     (< provided-burn burn-floor))
              (let [diag {:effect :diagnose
                          :reason :insufficient-subnet-burn
                          :subnet sid
                          :required burn-floor
                          :provided provided-burn}]
                {:state (update-in instance [:diagnostics :insufficient-burn] (fnil inc 0))
                 :applied? false
                 :error :insufficient-burn
                 :effects [diag]})
              (let [admitted-member (:member adm)
                    inst1 (cond-> instance
                            (and (not= econ-mode :none) (pos? provided-burn))
                            (update :burned-ech (fnil + 0) provided-burn))]
                (case etype
                  :put-blob
                  (let [res (data/put-data-blob (:data inst1) (:blob event) now-ms)
                        eager? (= :eager-push (get-in policy [:subnet/replication :replication/blobs]))
                        rep-effs (if (and (:ok? res) eager?)
                                   [{:effect :eager-push-blob
                                     :subnet sid
                                     :cid (:cid res)
                                     :blob (:blob event)}]
                                   [])]
                    {:state (assoc inst1 :data (:state res))
                     :applied? (boolean (:ok? res))
                     :effects (into (vec (:effects res)) rep-effs)})

                  :get-blob
                  (let [res (data/get-blob (get-in inst1 [:data :blobs])
                                           (:cid event)
                                           {:subnet sid :now-ms now-ms})]
                    {:state (assoc-in inst1 [:data :blobs] (:store res))
                     :applied? (:hit? res)
                     :blob (:blob res)
                     :effects (:effects res)})

                  :publish-pointer
                  (let [ptr (:pointer event)
                        ptype (get-in ptr [:pointer/proof :proof/type])
                        target-cid (:pointer/target ptr)
                        requires-target-blob? (and (some? target-cid)
                                                   (contains? #{:cert :acme-key-auth :dac} ptype))
                        pre-blob-read (when requires-target-blob?
                                        (data/get-blob (get-in inst1 [:data :blobs])
                                                       target-cid
                                                       {:subnet sid :now-ms now-ms}))]
                    (if (and requires-target-blob? (not (:hit? pre-blob-read)))
                      {:state (assoc-in inst1 [:data :blobs] (:store pre-blob-read))
                       :applied? false
                       :error :missing-target-blob
                       :effects (:effects pre-blob-read)}
                      (let [ctx (pointer-verify-ctx inst1 admitted-member now-ms)
                            res (data/apply-pointer (:data inst1) ptr ctx)]
                        (if-not (:applied? res)
                          {:state (assoc inst1 :data (:state res))
                           :applied? false
                           :error (:error res)
                           :effects (:effects res)}
                          (let [valid-ptr (:pointer res)
                                is-policy-path? (= "subnet/policy" (:pointer/path valid-ptr))
                                inst2 (assoc inst1 :data (:state res))]
                            (if-not is-policy-path?
                              (let [ptr-rep (get-in policy [:subnet/replication :replication/pointers])
                                    rep-eff {:effect :replicate-pointer
                                             :engine ptr-rep
                                             :subnet sid
                                             :pointer valid-ptr}]
                                {:state inst2
                                 :applied? true
                                 :effects (conj (vec (:effects res)) rep-eff)})
                              ;; "subnet/policy" cannot be tombstoned and must have its target Blob present & valid BEFORE recording Pointer!
                              (if (nil? (:pointer/target valid-ptr))
                                (let [diag {:effect :diagnose :reason :invalid-policy-update :subnet sid}]
                                  {:state (update-in inst1 [:diagnostics :policy-rejected] (fnil inc 0))
                                   :applied? false
                                   :error :invalid-policy-update
                                   :effects [diag]})
                                (let [blob-read (data/get-blob (get-in inst1 [:data :blobs])
                                                               (:pointer/target valid-ptr)
                                                               {:subnet sid :now-ms now-ms})]
                                  (if-not (:hit? blob-read)
                                    {:state (assoc-in inst1 [:data :blobs] (:store blob-read))
                                     :applied? false
                                     :error :missing-policy-blob
                                     :effects (:effects blob-read)}
                                    (let [decoded (try (fressian/decode-wire (get-in blob-read [:blob :blob/bytes]))
                                                       (catch #?(:clj Exception :cljs :default) _ nil))
                                          merged-pol (when (map? decoded)
                                                       (cond-> decoded
                                                         (:subnet/genesis-policy-cid policy)
                                                         (dissoc :subnet/genesis-policy-cid)))
                                          v-pol (validate-subnet-policy merged-pol)]
                                      (if-not (and (:ok? v-pol) (= sid (:subnet/id merged-pol)))
                                        (let [diag {:effect :diagnose :reason :invalid-policy-update :subnet sid}]
                                          {:state (update-in inst1 [:diagnostics :policy-rejected] (fnil inc 0))
                                           :applied? false
                                           :error :invalid-policy-update
                                           :effects [diag]})
                                        (let [new-anchors (set (map normalize-hex (get-in merged-pol [:subnet/gate :gate/trust-anchors] #{})))
                                              final-pol (cond-> merged-pol
                                                          (:subnet/genesis-policy-cid policy)
                                                          (assoc :subnet/genesis-policy-cid (:subnet/genesis-policy-cid policy)))]
                                          {:state (-> inst2
                                                      (assoc :policy final-pol)
                                                      (update :admitted-members into new-anchors))
                                           :applied? true
                                           :effects [{:effect :policy-updated :subnet sid :seq (:pointer/seq valid-ptr)}]}))))))))))))

                  (let [diag {:effect :diagnose :reason :unknown-subnet-event :subnet sid :event-type etype}]
                    {:state inst1 :applied? false :error :unknown-subnet-event :effects [diag]}))))))))))

;; =============================================================================
;; 4. Thin Pointer Adapters (Directory, Bootstrap, DAC, Home-Set — UNIFICATION.md §4)
;; =============================================================================

(defn- verify-directory-pop-payload
  "Cryptographically verifies the agent Proof-of-Possession signature (and optional rotation signature)
   on a directory descriptor/PoP map."
  [pop-m]
  (try
    (let [domain (str/lower-case (str/trim (str (or (:domain pop-m) "bitecho.org"))))
          nick (str/lower-case (str/trim (str (:nickname pop-m))))
          agent-pub (normalize-hex (:pubkey pop-m))
          hs (vec (sort (distinct (keep rendezvous/normalize-home-node (:home-set pop-m)))))
          ep (long (or (:epoch pop-m) 0))
          prev-pub (normalize-hex (:prev-pubkey pop-m))
          rot-sig (:rotation-signature pop-m)
          suites (:crypto-suites pop-m)
          suites-str (when (seq suites)
                       (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))
          base-canonical (str "bitecho-directory-pop-v1|" domain "|" nick "|" agent-pub "|"
                              (str/join "," hs) "|" ep "|" (or prev-pub ""))
          canonical-str (if (seq suites-str)
                          (str base-canonical "|" suites-str)
                          base-canonical)
          pub-bytes (when agent-pub (basalt/hex->bytes agent-pub))
          sig-bytes (when (string? (:pop-signature pop-m)) (basalt/hex->bytes (:pop-signature pop-m)))
          pop-ok? (boolean (and pub-bytes sig-bytes
                                (crypto/verify pub-bytes (fressian/utf8->bytes canonical-str) sig-bytes)))]
      (if-not pop-ok?
        false
        (if (or prev-pub rot-sig)
          (let [prev-bytes (when prev-pub (basalt/hex->bytes prev-pub))
                rot-bytes (when (string? rot-sig) (basalt/hex->bytes rot-sig))]
            (boolean (and prev-bytes rot-bytes
                          (not= prev-pub agent-pub)
                          (crypto/verify prev-bytes (fressian/utf8->bytes canonical-str) rot-bytes))))
          true)))
    (catch #?(:clj Exception :cljs :default) _ false)))

(defn sign-directory-pointer
  "Wraps a directory attestation into a Canonical Fressian `Blob` + signed `Pointer` after verifying PoP."
  [directory-privkey directory-pubkey pop-map {:keys [subnet issued-epoch expires-epoch mailbox] seq-num :seq}]
  (when (verify-directory-pop-payload pop-map)
    (let [norm-dir (normalize-hex directory-pubkey)
          domain (str/lower-case (str/trim (or (:domain pop-map) "bitecho.org")))
          nick (str/lower-case (str/trim (str (:nickname pop-map))))
          agent-pub (normalize-hex (:pubkey pop-map))
          hs (vec (sort (distinct (keep rendezvous/normalize-home-node (:home-set pop-map)))))
          desc (cond-> {:bitecho/type :directory-descriptor
                        :domain domain
                        :nickname nick
                        :uri (str domain "/" nick)
                        :pubkey agent-pub
                        :home-set hs
                        :epoch (long (or (:epoch pop-map) issued-epoch 0))
                        :issued-epoch (long (or issued-epoch 0))
                        :expires-epoch (long (or expires-epoch 0))
                        :pop-signature (:pop-signature pop-map)
                        :directory-pubkey norm-dir}
                 mailbox (assoc :mailbox mailbox)
                 (seq (:crypto-suites pop-map)) (assoc :crypto-suites (vec (map #(if (keyword? %) (name %) (str %)) (:crypto-suites pop-map))))
                 (:prev-pubkey pop-map) (assoc :prev-pubkey (normalize-hex (:prev-pubkey pop-map)))
                 (:rotation-signature pop-map) (assoc :rotation-signature (:rotation-signature pop-map)))
          blob (data/make-blob (fressian/encode-canonical desc) "application/fressian")
          sub-id (str (or subnet "global"))
          path (str "dir/" nick)
          ptr (data/sign-pointer directory-privkey
                                 {:pointer/authority norm-dir
                                  :pointer/subnet sub-id
                                  :pointer/path path
                                  :pointer/seq (long (or seq-num 1))
                                  :pointer/target (:blob/cid blob)
                                  :pointer/proof {:proof/type :self}})]
      {:blob blob :pointer ptr :descriptor desc})))

(defn verify-directory-pointer
  "Verifies a directory `Pointer` + target `Blob` (including agent PoP signature) against `trusted-directory-pubkey` and `current-epoch`."
  [pointer blob trusted-directory-pubkey current-epoch]
  (let [norm-dir (normalize-hex trusted-directory-pubkey)
        put-res (data/put-blob (data/init-blob-store) blob)
        ctx {:subnet (:pointer/subnet pointer)
             :path-acl [{:pattern "dir/*" :principal {:type :pubkey :pubkey norm-dir}}]}]
    (cond
      (not (:ok? put-res))
      {:ok? false :error :blob-cid-mismatch}

      (not= (:blob/cid blob) (:pointer/target pointer))
      {:ok? false :error :pointer-target-mismatch}

      :else
      (let [v-ptr (data/verify-pointer pointer ctx)]
        (if-not (:ok? v-ptr)
          v-ptr
          (let [desc (try (fressian/decode-wire (:blob/bytes blob))
                          (catch #?(:clj Exception :cljs :default) _ nil))]
            (cond
              (not (map? desc))
              {:ok? false :error :malformed-descriptor}

              (not (verify-directory-pop-payload desc))
              {:ok? false :error :invalid-pop-signature}

              (and (integer? current-epoch)
                   (< (long (:expires-epoch desc 0)) (long current-epoch)))
              {:ok? false :error :descriptor-expired}

              :else
              {:ok? true :valid? true :descriptor desc :pointer (:pointer v-ptr)})))))))

(defn sign-bootstrap-pointer
  "Wraps a bootstrap descriptor map into a Canonical Fressian `Blob` + signed `Pointer` at `\"bootstrap\"`."
  [authority-privkey descriptor {:keys [subnet] seq-num :seq}]
  (let [auth-pub (normalize-hex (:authority-pubkey descriptor))
        blob (data/make-blob (fressian/encode-canonical descriptor) "application/fressian")
        sub-id (str (or subnet "global"))
        ptr (data/sign-pointer authority-privkey
                               {:pointer/authority auth-pub
                                :pointer/subnet sub-id
                                :pointer/path "bootstrap"
                                :pointer/seq (long (or seq-num 1))
                                :pointer/target (:blob/cid blob)
                                :pointer/proof {:proof/type :self}})]
    {:blob blob :pointer ptr :descriptor descriptor}))

(defn verify-bootstrap-pointer
  "Verifies a `\"bootstrap\"` `Pointer` + `Blob` against `expected-authority-pubkey` and `current-epoch`."
  [pointer blob expected-authority-pubkey current-epoch]
  (let [norm-auth (normalize-hex expected-authority-pubkey)
        put-res (data/put-blob (data/init-blob-store) blob)
        ctx {:subnet (:pointer/subnet pointer)
             :path-acl [{:pattern "bootstrap" :principal {:type :pubkey :pubkey norm-auth}}]}]
    (cond
      (not (:ok? put-res))
      {:ok? false :error :blob-cid-mismatch}

      (not= (:blob/cid blob) (:pointer/target pointer))
      {:ok? false :error :pointer-target-mismatch}

      :else
      (let [v-ptr (data/verify-pointer pointer ctx)]
        (if-not (:ok? v-ptr)
          v-ptr
          (let [desc (try (fressian/decode-wire (:blob/bytes blob))
                          (catch #?(:clj Exception :cljs :default) _ nil))]
            (cond
              (not (map? desc))
              {:ok? false :error :malformed-descriptor}

              (and (integer? current-epoch)
                   (integer? (:expires-epoch desc))
                   (> (long current-epoch) (long (:expires-epoch desc))))
              {:ok? false :error :descriptor-expired}

              :else
              {:ok? true :valid? true :descriptor desc :pointer (:pointer v-ptr)})))))))

(defn sign-dac-pointer
  "Wraps a Cold-Anchor-signed DAC into a Canonical Fressian `Blob` + `:dac`-proven `Pointer` at `\"dac/<agent-pubkey>\"`."
  [anchor-privkey anchor-pubkey agent-pubkey capabilities {:keys [subnet issued-epoch expires-epoch max-spend-per-epoch] seq-num :seq}]
  (let [norm-anchor (normalize-hex anchor-pubkey)
        norm-agent (normalize-hex agent-pubkey)
        caps (vec (sort (distinct (map #(str/lower-case (name %)) capabilities))))
        iss-ep (long (or issued-epoch 0))
        exp-ep (long (or expires-epoch 0))
        max-spend (long (or max-spend-per-epoch 0))
        canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," caps))
        dac-sig (basalt/bytes->hex (crypto/sign anchor-privkey (fressian/utf8->bytes canonical-str)))
        dac-map {:bitecho/type :dac
                 :dac-id (data/compute-cid (fressian/utf8->bytes canonical-str))
                 :anchor-pubkey norm-anchor
                 :agent-pubkey norm-agent
                 :issued-epoch iss-ep
                 :expires-epoch exp-ep
                 :max-spend-per-epoch max-spend
                 :capabilities caps
                 :scopes caps
                 :signature (str/lower-case dac-sig)}
        blob (data/make-blob (fressian/encode-canonical dac-map) "application/fressian")
        sub-id (str (or subnet "global"))
        ptr (data/sign-pointer anchor-privkey
                               {:pointer/authority norm-anchor
                                :pointer/subnet sub-id
                                :pointer/path (str "dac/" norm-agent)
                                :pointer/seq (long (or seq-num 1))
                                :pointer/target (:blob/cid blob)
                                :pointer/proof {:proof/type :dac
                                                :agent-pubkey norm-agent
                                                :capabilities caps}})]
    {:blob blob :pointer ptr :dac dac-map}))

(defn verify-dac-pointer
  "Verifies a `\"dac/<agent>\"` `Pointer` + `Blob` against `expected-anchor-pubkey` and `current-epoch`."
  [pointer blob expected-anchor-pubkey current-epoch]
  (let [norm-anchor (normalize-hex expected-anchor-pubkey)
        put-res (data/put-blob (data/init-blob-store) blob)
        ctx {:subnet (:pointer/subnet pointer)
             :path-acl [{:pattern "dac/*" :principal {:type :pubkey :pubkey norm-anchor}}]}]
    (cond
      (not (:ok? put-res))
      {:ok? false :error :blob-cid-mismatch}

      (not= (:blob/cid blob) (:pointer/target pointer))
      {:ok? false :error :pointer-target-mismatch}

      :else
      (let [v-ptr (data/verify-pointer pointer ctx)]
        (if-not (:ok? v-ptr)
          v-ptr
          (let [dac (try (fressian/decode-wire (:blob/bytes blob))
                         (catch #?(:clj Exception :cljs :default) _ nil))]
            (if (and (map? dac)
                     (verify-dac-credential dac (:agent-pubkey dac) #{norm-anchor} current-epoch))
              {:ok? true :valid? true :dac dac :pointer (:pointer v-ptr)}
              {:ok? false :error :invalid-dac})))))))

(defn sign-home-set-pointer
  "Wraps an agent's Home-Set registration into a Canonical Fressian `Blob` + `:home-set`-proven `Pointer`
   at `\"homeset/<agent-pubkey>\"`."
  [agent-privkey agent-pubkey candidates {:keys [subnet price epoch ice-ufrag ice-pwd] seq-num :seq}]
  (let [norm-agent (normalize-hex agent-pubkey)
        norm-cands (mapv (fn [c]
                           (if (map? c)
                             (update c :node-id rendezvous/normalize-home-node)
                             {:node-id (rendezvous/normalize-home-node c)
                              :price (long (or price 10))}))
                         candidates)
        hs-map (cond-> {:bitecho/type :home-set
                        :callee norm-agent
                        :candidates norm-cands
                        :price (long (or price 10))
                        :epoch (long (or epoch 0))}
                 ice-ufrag (assoc :ice-ufrag ice-ufrag)
                 ice-pwd (assoc :ice-pwd ice-pwd))
        blob (data/make-blob (fressian/encode-canonical hs-map) "application/fressian")
        sub-id (str (or subnet "global"))
        ptr (data/sign-pointer agent-privkey
                               {:pointer/authority norm-agent
                                :pointer/subnet sub-id
                                :pointer/path (str "homeset/" norm-agent)
                                :pointer/seq (long (or seq-num 1))
                                :pointer/target (:blob/cid blob)
                                :pointer/proof {:proof/type :home-set
                                                :candidates norm-cands}})]
    {:blob blob :pointer ptr :home-set hs-map}))

(defn verify-home-set-pointer
  "Verifies a `\"homeset/<agent>\"` `Pointer` + `Blob` under `:self-path-owner` ACL."
  [pointer blob]
  (let [put-res (data/put-blob (data/init-blob-store) blob)
        ctx {:subnet (:pointer/subnet pointer)
             :path-acl [{:pattern "homeset/<pubkey>" :principal {:type :self-path-owner}}]}]
    (cond
      (not (:ok? put-res))
      {:ok? false :error :blob-cid-mismatch}

      (not= (:blob/cid blob) (:pointer/target pointer))
      {:ok? false :error :pointer-target-mismatch}

      :else
      (let [v-ptr (data/verify-pointer pointer ctx)]
        (if-not (:ok? v-ptr)
          v-ptr
          (let [hs (try (fressian/decode-wire (:blob/bytes blob))
                        (catch #?(:clj Exception :cljs :default) _ nil))]
            (if (and (map? hs) (= (:callee hs) (:pointer/authority (:pointer v-ptr))))
              {:ok? true :valid? true :home-set hs :pointer (:pointer v-ptr)}
              {:ok? false :error :invalid-home-set})))))))
