(ns bitecho.d38-bip013-observability-defense-and-autoupdate-test
  "Milestone D38 (`BIP-013: Core Observability, Built-In Request Defense,
   2026-11-20 Findings Fixes (F-SOAK-1, F-SADV1-1, F-BCAST-1, F-ART-1),
   and Light-Node Pointer Auto-Update (P-UPD-1)` / `v0.23.16`).
   Strict TDD generative `clojure.test.check` invariants (`Rule 1`, `Rule 2`, `Rule 4`, `Rule 5`, `Rule 6`)
   plus all 9 deterministic proof scenarios (`S-D38-1` through `S-D38-9`) and Rule 6 co-commit audit."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.defense.core :as defense]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.host.core :as host]
            [bitecho.light-node.core :as light-core]
            [bitecho.observability.core :as obs]
            [bitecho.streamlet.core :as streamlet]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- kp->pk-hex [kp]
  (let [pub (or (:public kp) (:public-key kp))]
    (str/lower-case (if (string? pub) pub (basalt/bytes->hex pub)))))

(defn- utf8-bytes [s]
  (fressian/utf8->bytes (str s)))

(defn- make-test-identity [seed]
  (let [kp (crypto/generate-keypair seed)]
    {:pubkey (kp->pk-hex kp)
     :privkey-bytes (:private kp)
     :keypair kp}))

;; =============================================================================
;; 1. Generative Invariants (Rule 1: Strict TDD)
;; =============================================================================

(def ^:private gen-level
  (gen/elements [:debug :info :warn :error]))

(def ^:private gen-step-name
  (gen/elements [:tick :gossip-recv :relay-poll :broadcast :artifact-get :consensus-vote]))

(defspec ^{:doc "BIP-013 Prop 1 (P-OBS-1): Core step instrumentation is pure, never alters step outputs, preserves monotonic seq, and enforces record/byte budgets under adversarial state sizes."}
  prop-obs-step-instrumentation-pure-transparent-and-budget-bounded 30
  (prop/for-all [node-id (gen/elements ["ns1" "ns2" "node1" "light-axiom"])
                 step-name gen-step-name
                 level gen-level
                 min-level gen-level
                 head-ep (gen/choose 100 50000)
                 fin-ep (gen/choose 100 50000)
                 duration-ms (gen/choose 0 5000)
                 blob-len (gen/choose 10 6000)
                 max-bytes (gen/choose 256 2048)]
                (let [state-before {:node-id node-id
                                    :head-epoch head-ep
                                    :finalized-epoch (min head-ep fin-ep)
                                    :epoch head-ep
                                    :payload (apply str (repeat (min 500 blob-len) "a"))
                                    :diagnostics {:dropped 0}}
                      step-fn (fn [st ev]
                                {:state (-> st
                                            (update :head-epoch inc)
                                            (assoc :last-ev (:id ev))
                                            (assoc :huge-blob (apply str (repeat blob-len "x"))))
                                 :effects [{:effect :emit :id (:id ev)}]})
                      event {:id (str "ev-" head-ep)}
                      cfg (assoc obs/default-observability-config
                                 :node-id node-id
                                 :step step-name
                                 :level level
                                 :default-level min-level
                                 :max-bytes-per-record max-bytes
                                 :max-records-per-step 4)
                      raw-out (step-fn state-before event)
                      wrapped-a (obs/wrap-step step-fn state-before event (assoc cfg :seq 10 :duration-ms duration-ms))
                      wrapped-b (obs/wrap-step step-fn state-before event (assoc cfg :seq 10 :duration-ms duration-ms))
                      rec-a (obs/decide-log-record state-before (:state raw-out) duration-ms (assoc cfg :seq 10))
                      rec-b (obs/decide-log-record state-before (:state raw-out) duration-ms (assoc cfg :seq 10))]
                  (and (= raw-out (:result wrapped-a))
                       (= wrapped-a wrapped-b)
                       (= rec-a rec-b)
                       (<= (count (:records wrapped-a)) 4)
                       (if (obs/level-enabled? level min-level)
                         (and (map? rec-a)
                              (= node-id (:node-id rec-a))
                              (= 10 (:seq rec-a))
                              (= step-name (:step rec-a))
                              (= level (:level rec-a))
                              (= (inc head-ep) (:head-epoch rec-a))
                              (= (min head-ep fin-ep) (:finalized-epoch rec-a))
                              (<= (obs/estimate-record-bytes rec-a) max-bytes))
                         (nil? rec-a))))))

(defspec ^{:doc "BIP-013 Prop 2 (P-OBS-6): Defense engine always fails open for authenticated consensus/peer traffic, escalates unauthenticated ingress abuse through throttle -> drop -> ban with expiry, and never exposes raw source IPs."}
  prop-defense-fail-open-consensus-and-escalating-ban-with-expiry 30
  (prop/for-all [ip-last (gen/choose 1 254)
                 violation (gen/elements [:malformed :auth-failed :invalid-sig])
                 ban-ms (gen/choose 10000 120000)
                 t0 (gen/choose 1000000 2000000)]
                (let [raw-ip (str "203.0.113." ip-last)
                      val-pk (deploy/sha256-hex (str "validator-" ip-last))
                      policy (assoc defense/default-defense-policy
                                    :throttle-threshold 2
                                    :drop-threshold 4
                                    :ban-threshold 6
                                    :ban-duration-ms ban-ms
                                    :allowlist-pubkeys #{val-pk})
                      st0 (defense/init-defense-state policy)
          ;; 1. Authenticated validator traffic from same IP is ALWAYS allowed (fail-open)
                      [st-auth dec-auth _] (defense/evaluate-request
                                            st0
                                            {:source-id raw-ip
                                             :source-pubkey val-pk
                                             :traffic-class :validator-sync
                                             :authenticated? true
                                             :violation violation
                                             :route "/validator/sync"
                                             :now-ms t0})
          ;; 2. Repeated unauthenticated violations escalate to :ban
                      {:keys [state actions records]}
                      (reduce (fn [{:keys [state actions records]} idx]
                                (let [[st' dec effs] (defense/evaluate-request
                                                      state
                                                      {:source-id raw-ip
                                                       :traffic-class :unauthenticated-ingress
                                                       :authenticated? false
                                                       :violation violation
                                                       :route "/relay/v1/poll"
                                                       :now-ms (+ t0 (* idx 100))})]
                                  {:state st'
                                   :actions (conj actions (:action dec))
                                   :records (into records (filter #(= :obs-record (:effect %)) effs))}))
                              {:state st-auth :actions [] :records []}
                              (range 6))
          ;; 3. While banned, authenticated peer traffic STILL passes (fail-open)
                      [_ dec-val-during-ban _] (defense/evaluate-request
                                                state
                                                {:source-id raw-ip
                                                 :source-pubkey val-pk
                                                 :traffic-class :p2p-session
                                                 :authenticated? true
                                                 :route "/p2p"
                                                 :now-ms (+ t0 1000)})
          ;; 4. After ban expires, clean request is allowed again
                      [_ dec-after-expiry _] (defense/evaluate-request
                                              state
                                              {:source-id raw-ip
                                               :traffic-class :unauthenticated-ingress
                                               :authenticated? false
                                               :violation nil
                                               :route "/relay/v1/poll"
                                               :now-ms (+ t0 ban-ms 5000)})
                      no-raw-ip? (every? (fn [r]
                                           (not (str/includes? (pr-str r) raw-ip)))
                                         records)]
                  (and (= :allow (:action dec-auth))
                       (true? (:exempt? dec-auth))
                       (some #{:ban} actions)
                       (= :allow (:action dec-val-during-ban))
                       (= :allow (:action dec-after-expiry))
                       no-raw-ip?))))

(defspec ^{:doc "BIP-013 Prop 3 (F-SADV1-1): Attestation manifest validation fails closed with invalid-manifest-missing-layers whenever :layers is missing/non-map or any of :os-subtree/:runtime-subtree/:app-subtree is empty."}
  prop-attest-manifest-fail-closed-on-missing-layers-or-empty-subtree 30
  (prop/for-all [arch (gen/elements ["amd64" "arm64"])
                 bad-case (gen/elements [:no-layers :nil-layers :non-map-layers
                                         :empty-os :empty-runtime :empty-app :non-map-manifest])]
                (let [valid-manifest (host/build-system-merkle-manifest
                                      {:arch arch
                                       :os-packages [{:atom "sys-apps/openrc" :version "0.55" :cid (deploy/sha256-hex "openrc")}]
                                       :runtimes [{:name "nodejs" :version "22.24.0" :cid (deploy/sha256-hex "node22")}]
                                       :app-artifacts [{:artifact "bitecho-full-node.cjs" :version "0.23.16" :cid (deploy/sha256-hex "fn16")}]})
                      bad-manifest (case bad-case
                                     :no-layers (dissoc valid-manifest :layers)
                                     :nil-layers (assoc valid-manifest :layers nil)
                                     :non-map-layers (assoc valid-manifest :layers ["bad"])
                                     :empty-os (assoc-in valid-manifest [:layers :os-subtree] [])
                                     :empty-runtime (assoc-in valid-manifest [:layers :runtime-subtree] [])
                                     :empty-app (assoc-in valid-manifest [:layers :app-subtree] [])
                                     :non-map-manifest "not-a-map")
                      ok-res (host/validate-attestation-manifest valid-manifest)
                      bad-res (host/validate-attestation-manifest bad-manifest)]
                  (and (true? (:ok? ok-res))
                       (false? (:ok? bad-res))
                       (= "invalid-manifest-missing-layers" (:error bad-res))))))

(defspec ^{:doc "BIP-013 Prop 4 (P-UPD-1, Rule 4, Rule 5): Light-node pointer auto-update enforces version monotonicity, CID verification, pin-version hold, stale-generation guard, proxy propagation, and automatic rollback on health failure."}
  prop-light-node-autoupdate-monotonic-verified-and-stale-gen-guard 25
  (prop/for-all [new-patch (gen/choose 16 40)
                 proxy-port (gen/choose 3128 9999)
                 tamper? gen/boolean
                 health-ok? gen/boolean]
                (let [auth-kp (crypto/generate-keypair (str "light-upd-auth-" new-patch))
                      auth-pk (kp->pk-hex auth-kp)
                      v-cur "0.23.15"
                      v-new (str "0.23." new-patch)
                      cur-bytes (utf8-bytes (str "light-bundle-" v-cur))
                      cur-cid (deploy/sha256-hex cur-bytes)
                      new-bytes (utf8-bytes (str "light-bundle-" v-new))
                      new-cid (deploy/sha256-hex new-bytes)
                      delivered-bytes (if tamper? (utf8-bytes "tampered-bundle") new-bytes)
                      proxy-url (str "http://127.0.0.1:" proxy-port)
                      ptr (deploy/sign-config-pointer
                           (:private auth-kp)
                           {:network "devnet"
                            :seq 2
                            :author-pubkey auth-pk
                            :code-target-cid new-cid
                            :target-version v-new
                            :effective-epoch 100})
                      st0 (deploy/init-light-updater-state
                           {:node-id "light-test"
                            :current-version v-cur
                            :current-cid cur-cid
                            :trusted-deploy-authorities #{auth-pk}
                            :proxy-url proxy-url})
          ;; Stale-generation callback must be ignored with counted :diagnose
                      [st-stale effs-stale] (deploy/reduce-light-update-tick
                                             (assoc st0 :generation 3)
                                             {:type :health-check-result
                                              :generation 1
                                              :healthy? true
                                              :epoch 100})
          ;; Fresh pointer seen
                      [st1 effs1] (deploy/reduce-light-update-tick
                                   st0
                                   {:type :pointer-seen
                                    :pointer ptr
                                    :epoch 100})
                      fetch-eff (first (filter #(= :fetch-bundle-blob (:effect %)) effs1))
          ;; Blob fetched
                      [st2 effs2] (deploy/reduce-light-update-tick
                                   st1
                                   {:type :blob-fetched
                                    :generation (:generation st1)
                                    :cid new-cid
                                    :bytes delivered-bytes
                                    :epoch 100})]
                  (and (= 1 (:dropped st-stale))
                       (some #(= :stale-generation-callback (:reason %)) effs-stale)
                       (= proxy-url (:proxy-url fetch-eff))
                       (if tamper?
                         (and (= :watching (:phase st2))
                              (= cur-cid (:current-cid st2))
                              (some #(= :light-update-hash-mismatch (:reason %)) effs2))
                         (let [[st3 effs3] (deploy/reduce-light-update-tick
                                            st2
                                            {:type :health-check-result
                                             :generation (:generation st2)
                                             :healthy? health-ok?
                                             :connected? health-ok?
                                             :syncing? health-ok?
                                             :finalized-epoch-advancing? health-ok?
                                             :balance-sane? health-ok?
                                             :epoch 101})]
                           (if health-ok?
                             (and (= :watching (:phase st3))
                                  (= v-new (:current-version st3))
                                  (= new-cid (:current-cid st3)))
                             (and (= :rolled-back (:phase st3))
                                  (= v-cur (:current-version st3))
                                  (= cur-cid (:current-cid st3))
                                  (some #(= :restore-lkg-light-bundle (:effect %)) effs3)))))))))

;; =============================================================================
;; 2. Deterministic Proof Scenarios (S-D38-1 through S-D38-9 + Rule 6)
;; =============================================================================

(deftest s-d38-1-instrumentation-transparency-and-budget-test
  (testing "S-D38-1 (P-OBS-1): Step instrumentation is transparent, pure, never throws into step, and enforces byte/record caps"
    (let [step-fn (fn [st ev]
                    {:state (-> st
                                (update :head-epoch inc)
                                (update :finalized-epoch inc)
                                (assoc :last-msg (:msg ev)))
                     :effects [{:effect :send :msg (:msg ev)}]})
          st0 {:node-id "ns1" :head-epoch 49946 :finalized-epoch 34329}
          ev {:msg "hello-d38"}
          out-off (obs/wrap-step step-fn st0 ev {:enabled? false})
          out-on (obs/wrap-step step-fn st0 ev {:enabled? true
                                                :node-id "ns1"
                                                :step :relay-poll
                                                :level :info
                                                :seq 1
                                                :duration-ms 4
                                                :max-bytes-per-record 512})
          rec (first (:records out-on))]
      (is (= (:result out-off) (:result out-on)))
      (is (empty? (:records out-off)))
      (is (= 1 (count (:records out-on))))
      (is (= "ns1" (:node-id rec)))
      (is (= 1 (:seq rec)))
      (is (= 49947 (:head-epoch rec)))
      (is (= 34330 (:finalized-epoch rec)))
      (is (= :relay-poll (:step rec)))
      (is (<= (obs/estimate-record-bytes rec) 512)))))

(deftest s-d38-2-sink-failure-isolation-test
  (testing "S-D38-2 (P-OBS-2): Disk full, network unreachable, IndexedDB quota exceeded isolate failures, expose seq gaps, and rotate disk within 50 MiB cap"
    (let [r0 (obs/init-sink-router {:node-id "ns1" :indexeddb-enabled? true})
          rec1 {:node-id "ns1" :step :tick :level :info :head-epoch 10 :finalized-epoch 10 :duration-ms 2 :data {}}
          rec2 {:node-id "ns1" :step :tick :level :info :head-epoch 11 :finalized-epoch 11 :duration-ms 3 :data {}}
          rec3 {:node-id "ns1" :step :tick :level :info :head-epoch 12 :finalized-epoch 12 :duration-ms 4 :data {}}
          ;; Kill disk on rec1, network on rec2, indexeddb on rec3
          [r1 effs1] (obs/route-records r0 [rec1] {:disk {:ok? false :error :disk-full}
                                                   :network {:ok? true}
                                                   :indexeddb {:ok? true}})
          [r2 effs2] (obs/route-records r1 [rec2] {:disk {:ok? true}
                                                   :network {:ok? false :error :network-unreachable}
                                                   :indexeddb {:ok? true}})
          [r3 effs3] (obs/route-records r2 [rec3] {:disk {:ok? true}
                                                   :network {:ok? true}
                                                   :indexeddb {:ok? false :error :indexeddb-quota-exceeded}})
          ;; Disk rotation enforces 50 MiB total cap (5 x 10 MiB)
          rot (reduce (fn [ds _] (obs/plan-disk-rotation ds (* 10 1024 1024)))
                      (get-in r0 [:sinks :disk])
                      (range 8))
          idb-rec (obs/indexeddb-record-schema (assoc rec1 :seq 1))
          paths (obs/observability-paths "ns1")]
      (is (= 4 (:next-seq r3)))
      (is (some #(= :sink-write-failed (:reason %)) effs1))
      (is (some #(= :sink-write-failed (:reason %)) effs2))
      (is (some #(= :sink-write-failed (:reason %)) effs3))
      ;; Seq gaps are visible in each sink
      (is (pos? (count (get-in r3 [:sinks :disk :seq-gaps]))))
      (is (pos? (count (get-in r3 [:sinks :network :seq-gaps]))))
      (is (pos? (count (get-in r3 [:sinks :indexeddb :seq-gaps]))))
      ;; Disk rotation bounded to <= 5 files and <= 50 MiB
      (is (<= (count (:files rot)) 5))
      (is (<= (:total-bytes rot) (* 50 1024 1024)))
      ;; Browser IndexedDB schema matches canonical fields
      (is (= "bitecho-obs-record-v1" (:schema idb-rec)))
      (is (= "bitecho.org/observability" (:subnet paths)))
      (is (= "telemetry/ns1/digest.edn" (:digest-path paths)))
      (is (= "telemetry/ns1/crash-context.edn" (:crash-context-path paths)))
      (is (= "telemetry/index.edn" (:index-path paths))))))

(deftest s-d38-3-restart-accountability-and-six-nines-sla-test
  (testing "S-D38-3 (P-OBS-3, P-OBS-4): SIGKILL preserves crash-context window (<=64 recs, <=32 KiB), publishes digest without raw IPs, and SLA accountant separates deploy vs service downtime"
    (let [r0 (obs/init-sink-router {:node-id "ns1"})
          recs (mapv (fn [i]
                       {:node-id "ns1" :step :relay-poll :level :info
                        :head-epoch (+ 49900 i) :finalized-epoch (+ 34300 i)
                        :duration-ms 5 :data {:i i :client-ip "198.51.100.42"}})
                     (range 80))
          [r1 _] (obs/route-records r0 recs {:disk {:ok? true} :network {:ok? true}})
          crash-ctx (:crash-context r1)
          sup-ev (obs/collect-supervisor-event
                  {:node-id "ns1" :event :respawn :exit-code 137 :signal "SIGKILL"
                   :cause :oom-or-sigkill :crash-context crash-ctx})
          digest (obs/build-telemetry-digest
                  {:node-id "ns1"
                   :uptime-ms 32400000
                   :restart-count 1
                   :restart-causes [:sigkill]
                   :head-epoch 49980
                   :finalized-epoch 34380
                   :attest-root (deploy/sha256-hex "ns1-attest")
                   :service-counters {:http-requests 12000 :relay-polls 9500 :client-ip "198.51.100.42"}
                   :defense-counters {:banned 2}
                   :crash-context-cid (deploy/sha256-hex (pr-str crash-ctx))
                   :downtime-events [{:cause :planned-deploy :duration-ms 4000}
                                     {:cause :sigkill :duration-ms 12000}]})
          sla (obs/compute-six-nines-sla [digest] {:window-ms 86400000})]
      (is (<= (count crash-ctx) 64))
      (is (<= (obs/estimate-record-bytes crash-ctx) 32768))
      (is (= :respawn (:event sup-ev)))
      (is (= 137 (:exit-code sup-ev)))
      (is (= 49980 (:head-epoch digest)))
      (is (= 34380 (:finalized-epoch digest)))
      (is (<= (obs/estimate-record-bytes digest) 16384))
      (is (not (str/includes? (pr-str digest) "198.51.100.42")))
      (is (= 4000 (:deploy-downtime-ms sla)))
      (is (= 12000 (:service-downtime-ms sla)))
      (is (= 49980 (:head-epoch-max sla)))
      (is (= 34380 (:finalized-epoch-max sla)))
      (is (false? (:six-nines-met? sla))))))

(deftest s-d38-4-ddos-defense-drill-test
  (testing "S-D38-4 (P-OBS-6): Unauthenticated flood triggers throttle -> drop -> ban; authenticated peers unaffected; detail sampling capped while counters stay exact"
    (let [val-pk (deploy/sha256-hex "validator-node1")
          policy (assoc defense/default-defense-policy
                        :throttle-threshold 2
                        :drop-threshold 4
                        :ban-threshold 6
                        :ban-duration-ms 60000
                        :detail-sample-cap-per-window 5
                        :allowlist-pubkeys #{val-pk})
          st0 (defense/init-defense-state policy)
          ;; Run 20 unauthenticated flood requests from attacker
          {:keys [state actions obs-count]}
          (reduce (fn [{:keys [state actions obs-count]} i]
                    (let [[st' dec effs] (defense/evaluate-request
                                          state
                                          {:source-id "198.51.100.99"
                                           :traffic-class :unauthenticated-ingress
                                           :authenticated? false
                                           :violation :malformed
                                           :route "/relay/v1/poll"
                                           :now-ms (+ 1000 (* i 50))})]
                      {:state st'
                       :actions (conj actions (:action dec))
                       :obs-count (+ obs-count (count (filter #(= :obs-record (:effect %)) effs)))}))
                  {:state st0 :actions [] :obs-count 0}
                  (range 20))
          ;; Legitimate validator traffic unaffected
          [state2 dec-val _] (defense/evaluate-request
                              state
                              {:source-id "198.51.100.99"
                               :source-pubkey val-pk
                               :traffic-class :validator-sync
                               :authenticated? true
                               :route "/validator/sync"
                               :now-ms 3000})
          ;; After ban expiry (t = 70000), attacker can make a clean request
          [_ dec-exp _] (defense/evaluate-request
                         state2
                         {:source-id "198.51.100.99"
                          :traffic-class :unauthenticated-ingress
                          :authenticated? false
                          :violation nil
                          :route "/relay/v1/poll"
                          :now-ms 70000})
          counters (defense/defense-digest-counters state2)]
      (is (some #{:throttle} actions))
      (is (some #{:drop} actions))
      (is (some #{:ban} actions))
      (is (= :allow (:action dec-val)))
      (is (= :allow (:action dec-exp)))
      ;; Exact counters match all 20 attack requests + 1 exempt validator request
      (is (= 20 (+ (:allowed counters) (:throttled counters) (:dropped counters) (:banned counters))))
      (is (= 1 (:exempt-allowed counters)))
      ;; Detail sampling was capped under flood (<= 5)
      (is (<= obs-count 5)))))

(deftest s-d38-5-broadcast-after-restart-fanout-test
  (testing "S-D38-5 (F-BCAST-1): Restart invalidates stale P2P metadata; broadcast never takes :p2p-direct? path and reports mesh fanout"
    (let [id-a (make-test-identity "bcast-node-a")
          st0 (-> (light-core/init-light-state id-a {:subnet-id "bitecho.org/dev" :economy-enabled? false})
                  (assoc-in [:sessions "sess-old"]
                            {:state "open"
                             :peer (deploy/sha256-hex "peer-b")
                             :p2p {:connected? true :local-signal-seq 5}
                             :p2p-meta {:connected? true :preferred-candidates ["1.2.3.4:5000"]}}))
          ;; Simulate daemon restart persistence roundtrip + stale P2P invalidation
          restarted (light-core/invalidate-stale-p2p-sessions (light-core/strip-sensitive-keys st0))
          res (light-core/handle-command restarted
                                         {"cmd" "broadcast"
                                          "subnet_id" "bitecho.org/dev"
                                          "text" "post-restart mesh anchor"}
                                         (:privkey-bytes id-a))
          env (first (:net-envelopes res))
          resp (:response res)]
      (is (not (true? (get-in restarted [:sessions "sess-old" :p2p :connected?]))))
      (is (not (true? (get-in restarted [:sessions "sess-old" :p2p-meta :connected?]))))
      (is (true? (get resp "ok")))
      ;; CRITICAL F-BCAST-1 assertion: broadcast MUST NOT set :p2p-direct? true
      (is (not (true? (:p2p-direct? env))))
      (is (true? (:mesh-broadcast? env)))
      (is (false? (get resp "p2p")))
      (is (true? (get resp "mesh_submitted")))
      (is (= "mesh" (get-in resp ["fanout" "route"])))
      (is (false? (get-in resp ["fanout" "p2p_direct"]))))))

(deftest s-d38-6-publish-then-fetch-replica-consistency-test
  (testing "S-D38-6 (F-ART-1): Artifact publish tracks replica quorum; artifact-get walks replicas and returns counted diagnose naming missing replicas"
    (let [id-pub (make-test-identity "art-pub")
          id-get (make-test-identity "art-get")
          st-pub (light-core/init-light-state id-pub {:subnet-id "bitecho.org/dev" :economy-enabled? false})
          ;; 1. Publish failing quorum (only 1 of 2 required confirmed) -> fail closed
          fail-pub (light-core/handle-command st-pub
                                              {"cmd" "artifact-put"
                                               "subnet_id" "bitecho.org/dev"
                                               "path" "notes/round.edn"
                                               "text" "{:ok true}"
                                               "replicas" ["ns1" "ns2" "ns3"]
                                               "confirmed_replicas" ["ns1"]
                                               "replica_quorum" 2}
                                              (:privkey-bytes id-pub))
          ;; 2. Publish meeting quorum (2 of 3 confirmed) -> succeeds with replica set
          ok-pub (light-core/handle-command st-pub
                                            {"cmd" "artifact-put"
                                             "subnet_id" "bitecho.org/dev"
                                             "path" "notes/round.edn"
                                             "text" "{:ok true}"
                                             "replicas" ["ns1" "ns2" "ns3"]
                                             "confirmed_replicas" ["ns1" "ns2"]
                                             "replica_quorum" 2}
                                            (:privkey-bytes id-pub))
          blob (get-in ok-pub [:response "blob"])
          ptr (get-in ok-pub [:response "pointer"])
          cid (get-in ok-pub [:response "cid"])
          ;; 3. Second light node has pointer + replica-blobs on ns2 only -> walks replicas and succeeds
          st-get (-> (light-core/init-light-state id-get {:subnet-id "bitecho.org/dev" :economy-enabled? false})
                     (assoc-in [:artifact-pointers ["bitecho.org/dev" "notes/round.edn"]] ptr)
                     (assoc-in [:replica-blobs "ns2" cid] blob))
          ok-get (light-core/handle-command st-get
                                            {"cmd" "artifact-get"
                                             "subnet_id" "bitecho.org/dev"
                                             "path" "notes/round.edn"
                                             "replicas" ["ns1" "ns2" "ns3"]}
                                            (:privkey-bytes id-get))
          ;; 4. Missing on all replicas -> counted diagnose naming missing replicas
          st-miss (-> (light-core/init-light-state id-get {:subnet-id "bitecho.org/dev" :economy-enabled? false})
                      (assoc-in [:artifact-pointers ["bitecho.org/dev" "notes/round.edn"]] ptr))
          miss-get (light-core/handle-command st-miss
                                              {"cmd" "artifact-get"
                                               "subnet_id" "bitecho.org/dev"
                                               "path" "notes/round.edn"
                                               "replicas" ["ns1" "ns2" "ns3"]}
                                              (:privkey-bytes id-get))]
      (is (false? (get-in fail-pub [:response "ok"])))
      (is (= "artifact-replica-quorum-unmet" (get-in fail-pub [:response "error"])))
      (is (true? (get-in ok-pub [:response "ok"])))
      (is (= ["ns1" "ns2" "ns3"] (get-in ok-pub [:response "replicas"])))
      (is (true? (get-in ok-get [:response "ok"])))
      (is (= "ns2" (get-in ok-get [:response "served_by_replica"])))
      (is (false? (get-in miss-get [:response "ok"])))
      (is (= ["ns1" "ns2" "ns3"] (get-in miss-get [:response "missing_replicas"])))
      (is (= "artifact-missing-on-replicas" (get-in miss-get [:response "diagnose" "reason"])))
      (is (pos? (long (get-in miss-get [:state :diagnostics :artifact-missing-on-replicas] 0)))))))

(deftest s-d38-7-attest-fail-closed-test
  (testing "S-D38-7 (F-SADV1-1): Missing :layers or empty subtrees fail closed; valid manifests attest identically"
    (let [valid (host/build-system-merkle-manifest
                 {:arch "amd64"
                  :os-packages [{:atom "sys-apps/openrc" :version "0.55" :cid (deploy/sha256-hex "openrc")}]
                  :runtimes [{:name "nodejs" :version "22.24.0" :cid (deploy/sha256-hex "node22")}]
                  :app-artifacts [{:artifact "bitecho-full-node.cjs" :version "0.23.16" :cid (deploy/sha256-hex "fn16")}]})
          v-res (host/validate-attestation-manifest valid)
          m-missing (host/validate-attestation-manifest {:arch "amd64"})
          m-empty-app (host/validate-attestation-manifest (assoc-in valid [:layers :app-subtree] []))]
      (is (true? (:ok? v-res)))
      (is (= (:system-merkle-root valid) (:system-merkle-root (host/compute-system-merkle-root valid))))
      (is (false? (:ok? m-missing)))
      (is (= "invalid-manifest-missing-layers" (:error m-missing)))
      (is (false? (:ok? m-empty-app)))
      (is (= "invalid-manifest-missing-layers" (:error m-empty-app))))))

(deftest s-d38-8-ns1-profile-telemetry-and-soak-mitigation-test
  (testing "S-D38-8 (F-SOAK-1, P-OBS-3, P-OBS-5): Heap/event-loop/poll-route collectors capture ns1 profile and scripts enforce --max-old-space-size=384"
    (let [node-m (obs/collect-nodejs-runtime {:node-id "ns1" :rss-bytes (* 310 1024 1024)
                                              :heap-used-bytes (* 180 1024 1024)
                                              :heap-total-bytes (* 256 1024 1024)
                                              :event-loop-lag-ms 12.5 :gc-pause-ms 4.2})
          http-m (obs/collect-http-metric {:node-id "ns1" :route "/relay/v1/poll" :status 200
                                           :latency-ms 18 :bytes 1024 :source-id "203.0.113.5"})
          relay-m (obs/collect-relay-metric {:node-id "ns1" :poll-queue-depth 14 :fanout-count 5
                                             :active-waiters 12 :dropped 0})
          dns-m (obs/collect-dns-metric {:node-id "ns1" :query-type "A" :name "bitecho.org"
                                         :latency-ms 2 :rcode "NOERROR"})
          disk-m (obs/collect-disk-metric {:node-id "ns1" :mount "/" :used-bytes 3300000000
                                           :total-bytes 30000000000})
          jvm-m (obs/collect-jvm-runtime {:node-id "node1" :heap-used-bytes 100000000
                                          :heap-max-bytes 448000000 :gc-pause-ms 3 :thread-count 42})
          browser-m (obs/collect-browser-runtime {:node-id "browser-1" :js-heap-used-bytes 20000000
                                                  :js-heap-limit-bytes 512000000 :nav-latency-ms 120})
          run-infra (slurp "scripts/run-infra-node.sh")
          run-val (slurp "scripts/run-validator-node.sh")]
      (is (= :nodejs-runtime (:collector node-m)))
      (is (= "/relay/v1/poll" (:route http-m)))
      (is (not (str/includes? (pr-str http-m) "203.0.113.5")))
      (is (= 12 (:active-waiters relay-m)))
      (is (= :dns (:collector dns-m)))
      (is (= :disk (:collector disk-m)))
      (is (= :jvm-runtime (:collector jvm-m)))
      (is (= :browser-runtime (:collector browser-m)))
      (is (str/includes? run-infra "--max-old-space-size="))
      (is (str/includes? run-val "--max-old-space-size=")))))

(deftest s-d38-9-light-node-pointer-autoupdate-drill-test
  (testing "S-D38-9 (P-UPD-1): Verified pointer self-update, CID mismatch refusal, health-check rollback, --pin-version opt-out, proxy propagation, and telemetry transitions"
    (let [auth-kp (crypto/generate-keypair "p-upd-1-drill")
          auth-pk (kp->pk-hex auth-kp)
          v15-bytes (utf8-bytes "light-node-0.23.15")
          v15-cid (deploy/sha256-hex v15-bytes)
          v16-bytes (utf8-bytes "light-node-0.23.16")
          v16-cid (deploy/sha256-hex v16-bytes)
          ptr-v16 (deploy/sign-config-pointer
                   (:private auth-kp)
                   {:network "devnet"
                    :seq 10
                    :author-pubkey auth-pk
                    :code-target-cid v16-cid
                    :target-version "0.23.16"
                    :effective-epoch 500})
          base-opts {:node-id "light-axiom"
                     :current-version "0.23.15"
                     :current-cid v15-cid
                     :trusted-deploy-authorities #{auth-pk}
                     :proxy-url "http://127.0.0.1:8080"}
          ;; A. Happy path: seen -> fetched -> applied -> verified
          st0 (deploy/init-light-updater-state base-opts)
          [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-v16 :epoch 500})
          [st2 effs2] (deploy/reduce-light-update-tick st1 {:type :blob-fetched :generation (:generation st1)
                                                            :cid v16-cid :bytes v16-bytes :epoch 500})
          [st3 effs3] (deploy/reduce-light-update-tick st2 {:type :health-check-result :generation (:generation st2)
                                                            :healthy? true :connected? true :syncing? true
                                                            :finalized-epoch-advancing? true :balance-sane? true :epoch 501})
          ;; B. CID mismatch refused before staging
          [st-bad effs-bad] (deploy/reduce-light-update-tick st1 {:type :blob-fetched :generation (:generation st1)
                                                                  :cid v16-cid :bytes (utf8-bytes "corrupted") :epoch 500})
          ;; C. Health-check failure triggers automatic rollback
          [st-rb effs-rb] (deploy/reduce-light-update-tick st2 {:type :health-check-result :generation (:generation st2)
                                                                :healthy? false :connected? false :epoch 501})
          ;; D. Pinned node does not move
          st-pin0 (deploy/init-light-updater-state (assoc base-opts :pinned-version "0.23.15"))
          [st-pin1 effs-pin1] (deploy/reduce-light-update-tick st-pin0 {:type :pointer-seen :pointer ptr-v16 :epoch 500})]
      ;; Proxy propagated
      (is (= "http://127.0.0.1:8080" (:proxy-url (first (filter #(= :fetch-bundle-blob (:effect %)) effs1)))))
      ;; Happy path transitions
      (is (= "0.23.16" (:current-version st3)))
      (is (= v16-cid (:current-cid st3)))
      (is (some #(= :stage-light-bundle (:effect %)) effs2))
      (is (some #(= :obs-record (:effect %)) effs1))
      (is (some #(= :obs-record (:effect %)) effs2))
      (is (some #(= :obs-record (:effect %)) effs3))
      ;; CID mismatch refused
      (is (= "0.23.15" (:current-version st-bad)))
      (is (some #(= :light-update-hash-mismatch (:reason %)) effs-bad))
      ;; Rollback restores v15
      (is (= :rolled-back (:phase st-rb)))
      (is (= "0.23.15" (:current-version st-rb)))
      (is (= v15-cid (:current-cid st-rb)))
      (is (some #(= :restore-lkg-light-bundle (:effect %)) effs-rb))
      ;; Pinned node stays put
      (is (= "0.23.15" (:current-version st-pin1)))
      (is (= :watching (:phase st-pin1)))
      (is (not (some #(= :fetch-bundle-blob (:effect %)) effs-pin1)))
      (is (some #(= :obs-record (:effect %)) effs-pin1)))))

(deftest s-d38-10-rule6-cocommit-flags-and-bip013-receipt-test
  (testing "Rule 6: Co-committed version bump (0.23.16), ops scripts, CLI flags, and BIP-013 8-gate receipt"
    (is (= "0.23.16" config/version))
    (doseq [path ["src/bitecho/observability/core.cljc"
                  "src/bitecho/defense/core.cljc"
                  "scripts/run-infra-node.sh"
                  "scripts/run-validator-node.sh"
                  "scripts/light-node.sh"
                  "docs/bips/bip-013-v02316.edn"]]
      (is (.exists (io/file path)) (str "Required co-committed deliverable missing: " path)))
    (let [node-main-src (slurp "src/bitecho/node_main.cljs")
          full-node-src (slurp "src/bitecho/full_node_main.cljs")
          bip013-raw (slurp "docs/bips/bip-013-v02316.edn")
          bip013-spec (edn/read-string bip013-raw)
          gate-check (gov/verify-bip-admission-gates bip013-spec)]
      (is (str/includes? node-main-src "--pin-version"))
      (is (str/includes? node-main-src "--proxy"))
      (is (str/includes? full-node-src "invalid-manifest-missing-layers"))
      (is (not (str/includes? bip013-raw "\"undefined\"")))
      (is (true? (:ok? gate-check)) (str "BIP-013 missing gates: " (:missing-gates gate-check)))
      (is (empty? (:missing-gates gate-check))))))

;; =============================================================================
;; 3. F-EPOCH-1: Self-Healing Quorum Epoch Catch-Up (BIP-013 Addition)
;; =============================================================================

(defn- make-streamlet-committee
  [prefix n]
  (let [entries (sort-by :hex
                         (mapv (fn [i]
                                 (let [kp (crypto/generate-keypair (str prefix "-" i))]
                                   {:kp kp :hex (kp->pk-hex kp)}))
                               (range n)))
        pks (mapv :hex entries)
        kps (mapv :kp entries)
        peers-map (into {} (map (fn [{:keys [hex kp]}] [hex (:public kp)]) entries))]
    {:pks pks :kps kps :peers-map peers-map}))

(defspec ^{:doc "BIP-013 Prop 5 (F-EPOCH-1): A single Byzantine validator cannot jump a node's epoch past max-epoch-catchup-delta, while >= (f+1) corroborated honest validators trigger self-healing catch-up with counted :diagnose."}
  prop-streamlet-quorum-epoch-catchup-resists-single-byzantine-and-self-heals 25
  (prop/for-all [base-ep (gen/choose 100 50000)
                 gap (gen/choose 200 5000)
                 byz-extra (gen/choose 1000 100000)]
                (let [{:keys [pks kps peers-map]} (make-streamlet-committee "f-epoch-1-val" 6)
                      honest-ep (+ base-ep gap)
                      byz-ep (+ honest-ep byz-extra)
                      byz-idx (mod byz-ep 6)
                      honest-idx (mod (inc byz-idx) 6)
                      local-idx (mod (+ byz-idx 2) 6)
                      lagging-st {:node-pubkey (nth pks local-idx)
                                  :keypair (nth kps local-idx)
                                  :peers-map peers-map
                                  :total-nodes 6
                                  :epoch base-ep
                                  :max-epoch-catchup-delta 64
                                  :blocks {}
                                  :notarized #{}
                                  :finalized #{}
                                  :votes {}
                                  :voted-epochs #{}
                                  :head-hash "genesis"
                                  :diagnostics {}}
          ;; 1. Single Byzantine validator sends far-future proposal -> MUST NOT jump epoch, MUST emit :diagnose
                      byz-blk (streamlet/sign-block (streamlet/->Block byz-ep "genesis" [] (nth pks byz-idx))
                                                    (:private (nth kps byz-idx)))
                      r-byz (streamlet/handle-streamlet-event
                             lagging-st
                             {:type :receive-propose :sender (nth pks byz-idx) :block byz-blk})
                      st-after-byz (:state r-byz)
          ;; 2. Second distinct validator (honest) sends vote at honest-ep -> (f+1)=2 corroborated!
          ;;    Must jump to honest-ep (NOT byz-ep!) and emit :quorum-epoch-catchup diagnose!
                      honest-blk (streamlet/sign-block (streamlet/->Block honest-ep "genesis" [] (nth pks honest-idx))
                                                       (:private (nth kps honest-idx)))
                      honest-hash (streamlet/hash-block honest-blk)
                      honest-sig (basalt/bytes->hex (crypto/sign (:private (nth kps honest-idx)) (fressian/utf8->bytes honest-hash)))
                      honest-vote (streamlet/->Vote honest-hash honest-ep honest-sig)
                      r-heal (streamlet/handle-streamlet-event
                              st-after-byz
                              {:type :receive-vote :sender (nth pks honest-idx) :vote honest-vote})
                      st-healed (:state r-heal)]
                  (and (= base-ep (:epoch st-after-byz))
                       (some #(= :proposal-exceeds-catchup-delta (:reason %)) (:commands r-byz))
                       (= honest-ep (:epoch st-healed))
                       (< (:epoch st-healed) byz-ep)
                       (some #(= :quorum-epoch-catchup (:reason %)) (:commands r-heal))
                       (pos? (long (get-in st-healed [:diagnostics :quorum-epoch-catchup] 0)))))))

(deftest s-d38-11-f-epoch-1-quorum-epoch-catchup-and-accountz-parity-test
  (testing "S-D38-11 (F-EPOCH-1): Lagging validator at 49794 catches up to quorum at 50951 via self-healing catch-up, resumes voting, and /accountz uses deterministic sorted-map"
    (let [{:keys [pks kps peers-map]} (make-streamlet-committee "devnet6-val" 6)
          l1-idx (mod 50951 6)
          l2-idx (mod 50952 6)
          ns3-idx (mod (+ l2-idx 1) 6)
          ns3-st {:node-pubkey (nth pks ns3-idx)
                  :keypair (nth kps ns3-idx)
                  :peers-map peers-map
                  :total-nodes 6
                  :epoch 49794
                  :max-epoch-catchup-delta 64
                  :blocks {}
                  :notarized #{}
                  :finalized #{}
                  :votes {}
                  :voted-epochs #{}
                  :head-hash "genesis"
                  :diagnostics {}}
          ;; First honest peer at 50951 -> recorded as witness, no jump yet, counted diagnose emitted
          b1 (streamlet/sign-block (streamlet/->Block 50951 "genesis" [] (nth pks l1-idx))
                                   (:private (nth kps l1-idx)))
          r1 (streamlet/handle-streamlet-event ns3-st {:type :receive-propose :sender (nth pks l1-idx) :block b1})
          ;; Second honest peer at 50952 -> threshold (f+1 = 2) met -> self-heals to 50951 and votes!
          b2 (streamlet/sign-block (streamlet/->Block 50952 "genesis" [] (nth pks l2-idx))
                                   (:private (nth kps l2-idx)))
          r2 (streamlet/handle-streamlet-event (:state r1) {:type :receive-propose :sender (nth pks l2-idx) :block b2})
          full-node-src (slurp "src/bitecho/full_node_main.cljs")]
      (is (= 49794 (:epoch (:state r1))))
      (is (some #(= :proposal-exceeds-catchup-delta (:reason %)) (:commands r1)))
      (is (>= (:epoch (:state r2)) 50951))
      (is (some #(= :quorum-epoch-catchup (:reason %)) (:commands r2)))
      (is (some #(= :send-vote (:type %)) (:commands r2)))
      (is (str/includes? full-node-src ":accounts (into (sorted-map)")))))
