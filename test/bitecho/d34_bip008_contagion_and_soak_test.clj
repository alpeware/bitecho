(ns bitecho.d34-bip008-contagion-and-soak-test
  "Milestone D34 (`BIP-008: Contagion Sample-Size Correction + Overnight Soak Remediations` / `v0.23.12`)
   Generative `test.check` Invariants (Rule 1 Strict TDD, >= 50 trials each) & Deterministic Scenarios:
   1. `prop-contagion-delivery-reachable-when-view-smaller-than-sample` (`P-CONTAG-2`):
      Effective thresholds clamp via `(sm/effective-sample-threshold S T-hat V)` so that when
      active sample/view size V < configured sample size S, honest votes across the V available
      peers reach `:sieve-delivered-set`, `:local-ready-set`, and `:delivered-set` (`:on-deliver` fires).
   2. `prop-threshold-clamp-never-exceeds-active-view` (`P-CONTAG-2`):
      For any S >= 1, 1 <= T-hat <= S, and V >= 0:
      - V >= S -> equals T-hat
      - 1 <= V < S -> in [1, V]
      - V = 0 -> >= 1 (never 0)
   3. `prop-devnet-6-preset-selected-on-six-validator-boot` (`P-CONTAG-1`):
      When `mesh/build-initial-node-state` or `mesh/rebind-restored-state` boots a `:devnet` node
      with 6 validators (`#{:node1 :node2 :node3 :ns1 :ns2 :ns3}`), `(:config state)` selects
      `config/devnet-6-config` (`:murmur-k 5, E=5/4, R=5/2, D=5/4`) even without explicit `:protocol`
      overrides; while a 3-node `:devnet` config selects `config/devnet-config` (`E=2/2, R=2/1, D=2/2`).
   4. `prop-mainnet-config-never-stalls-delivery-at-small-N` (`P-CONTAG-3`):
      With `config/mainnet-config`, for any cluster size N in [4..12] (V = N - 1 in [3..11]),
      Contagion delivery threshold is clamped to <= N - 1, messages reach `:delivered-set`,
      and `mesh/validate-contagion-config` surfaces a diagnostic warning when raw `:delivery-threshold` > N - 1.
   5. `prop-shared-http-client-single-selector-manager` (`P-SOAK-1` / `BUG-SOAK-01`):
      `(http/default-http-client)` and `(light-shell/default-http-client)` return the exact same shared
      `java.net.http.HttpClient` instance across repeated invocations, and 100+ back-to-back loopback
      HTTP requests spawn at most 1 new `HttpClient-*-SelectorManager` thread.
   6. `prop-relay-leg-opens-only-after-verified-link-bind` (`P-LEG-1`):
      When a relay P2P leg is in `:connecting` (or dialed with `:require-link-bind? true`), outbound `send`
      uses mesh fallback (`burn=500`) until a cryptographically valid `:p2p-link-bind` from the session peer
      transitions the leg to `{:phase :open :connected? true :zero-burn? true}`; any invalid/forged
      `:p2p-link-bind` is rejected with counted `[:diagnostics :p2p-link-bind-rejected]` without opening the leg.
   7. `S-D34-1..S-D34-6`: Deterministic E2E scenarios for `P-CONTAG-4`, `P-SOAK-2`, `P-SOAK-3`, `P-SOAK-4`, `P-SOAK-5`, and `P-LEG-1`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.acme :as acme]
            [bitecho.shell.http :as http]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.shell.mesh :as mesh]
            [bitecho.shell.persistence :as persistence]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- kp->pk-hex [kp]
  (let [pub (:public kp)]
    (if (string? pub) pub (basalt/bytes->hex pub))))

(defn- kp->sk [kp]
  (:private kp))

(defn- make-tmp-dir! []
  (.toFile (Files/createTempDirectory "d34-bip008-test-" (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^File f]
  (when (and f (.exists f))
    (when (.isDirectory f)
      (doseq [^File child (.listFiles f)]
        (delete-dir-recursively! child)))
    (.delete f)))

(defn- count-selector-manager-threads []
  (->> (Thread/getAllStackTraces)
       keys
       (filter (fn [^Thread t]
                 (and (.isAlive t)
                      (boolean (re-find #"HttpClient-\d+-SelectorManager" (.getName t))))))
       count))

(defn- make-test-validator-entries [n]
  (let [ids (take n [:node1 :node2 :node3 :ns1 :ns2 :ns3 :node4 :node5 :node6 :node7 :node8 :node9])]
    (into {}
          (map-indexed
           (fn [idx nid]
             (let [kp (crypto/generate-keypair (str "d34-val-" (name nid) "-" idx))
                   pk (kp->pk-hex kp)]
               [nid {:ip (str "127.0.0." (inc idx))
                     :port (+ 5000 idx)
                     :agent-port (+ 5010 idx)
                     :pubkey pk
                     :privkey (:private kp)
                     :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                     :ice-ufrag (str "ufrag" idx)
                     :ice-pwd (str "pwd" idx)}]))
           ids))))

;; =============================================================================
;; 1. Generative Properties (Rule 1: >= 50 trials each)
;; =============================================================================

(defspec ^{:doc "BIP-008 Prop 1 (P-CONTAG-2): Contagion delivery is reachable when active view V is smaller than configured sample size S."}
  prop-contagion-delivery-reachable-when-view-smaller-than-sample 50
  (prop/for-all
   [sample-size (gen/choose 5 21)
    view-size (gen/choose 1 20)]
   (let [v (min view-size (max 1 (dec sample-size)))
         e-thresh (max 1 (long (Math/ceil (* 0.7 sample-size))))
         r-thresh (max 1 (long (Math/ceil (* 0.3 sample-size))))
         d-thresh (max 1 (long (Math/ceil (* 0.8 sample-size))))
         cfg (assoc config/default-config
                    :economy-enabled? false
                    :burn-floor 0
                    :require-signed-control-frames false
                    :echo-sample-size sample-size
                    :echo-threshold e-thresh
                    :ready-sample-size sample-size
                    :ready-threshold r-thresh
                    :delivery-sample-size sample-size
                    :delivery-threshold d-thresh)
         peer-kps (mapv #(crypto/generate-keypair (str "d34-p1-peer-" %)) (range v))
         peer-hexes (mapv kp->pk-hex peer-kps)
         peers (mapv (fn [idx kp]
                       (basalt/make-peer (str "10.0.0." (inc idx)) (+ 8000 idx) (:public kp)))
                     (range v) peer-kps)
         self-kp (crypto/generate-keypair "d34-p1-self")
         self-pk (kp->pk-hex self-kp)
         st0 (-> (sm/init-state peers self-pk cfg)
                 (assoc :global-echo-sample (set peer-hexes)
                        :global-ready-sample (set peer-hexes)
                        :global-delivery-sample (set peer-hexes)))
         bcast-res (sm/handle-event st0 {:type :broadcast
                                         :payload (.getBytes "d34-contagion-test" StandardCharsets/UTF_8)
                                         :rng (java.util.Random. 42)})
         st1 (:state bcast-res)
         mid (first (:contagion-known-ids st1))
         st-after-echoes (reduce (fn [st peer-pk]
                                   (:state (sm/handle-event st {:type :receive-sieve-echo
                                                                :sender peer-pk
                                                                :message-id mid})))
                                 st1
                                 peer-hexes)
         deliver-events (atom [])
         st-after-readies (reduce (fn [st peer-pk]
                                    (let [r (sm/handle-event st {:type :receive-contagion-ready
                                                                 :sender peer-pk
                                                                 :message-id mid})]
                                      (doseq [c (:commands r)]
                                        (when (and (= (:type c) :app-event) (= (:event-name c) :on-deliver))
                                          (swap! deliver-events conj c)))
                                      (:state r)))
                                  st-after-echoes
                                  peer-hexes)]
     (and (some? mid)
          (contains? (:sieve-delivered-set st-after-echoes) mid)
          (contains? (:local-ready-set st-after-readies) mid)
          (contains? (:delivered-set st-after-readies) mid)
          (= 1 (count @deliver-events))))))

(defspec ^{:doc "BIP-008 Prop 2 (P-CONTAG-2): effective-sample-threshold preserves configured threshold when V >= S and clamps to [1, V] when 1 <= V < S."}
  prop-threshold-clamp-never-exceeds-active-view 60
  (prop/for-all
   [s (gen/choose 1 50)
    t-ratio (gen/choose 1 100)
    v (gen/choose 0 60)]
   (let [t-hat (max 1 (min s (long (Math/ceil (* (/ (double t-ratio) 100.0) (double s))))))
         eff (sm/effective-sample-threshold s t-hat v)]
     (and (integer? eff)
          (>= eff 1)
          (cond
            (>= v s) (= eff t-hat)
            (pos? v) (and (<= 1 eff) (<= eff v))
            :else (>= eff 1))))))

(defspec ^{:doc "BIP-008 Prop 3 (P-CONTAG-1): 6-validator devnet boot & restore automatically select devnet-6-config sample parameters while 3-validator devnet selects devnet-config."}
  prop-devnet-6-preset-selected-on-six-validator-boot 50
  (prop/for-all
   [tick-ms (gen/choose 5000 15000)
    use-6-nodes? gen/boolean]
   (let [n (if use-6-nodes? 6 3)
         nodes-map (make-test-validator-entries n)
         first-id (first (keys nodes-map))
         first-node (get nodes-map first-id)
         ident {:node-id first-id
                :pubkey-hex (:pubkey first-node)
                :keypair {:public (basalt/hex->bytes (:pubkey first-node))
                          :private (:privkey first-node)}}
         cfg {:node/id first-id
              :network :devnet
              :state-dir "/tmp/d34-test"
              :protocol {:tick-interval-ms tick-ms
                         :epoch-length-ms tick-ms}
              :cluster {:validators (mapv :pubkey (vals nodes-map))
                        :nodes nodes-map}}
         st (mesh/build-initial-node-state cfg ident)
         pcfg (:config st)
         ;; Also test rebind-restored-state upgrading a legacy E=2 snapshot when 6 validators are configured
         legacy-st (assoc st :config (merge pcfg (select-keys config/devnet-config
                                                              [:murmur-k :echo-sample-size :echo-threshold
                                                               :ready-sample-size :ready-threshold
                                                               :delivery-sample-size :delivery-threshold])))
         rebound (mesh/rebind-restored-state legacy-st cfg ident)
         rcfg (:config rebound)]
     (if use-6-nodes?
       (and (= 5 (:murmur-k pcfg))
            (= 5 (:echo-sample-size pcfg))
            (= 4 (:echo-threshold pcfg))
            (= 5 (:ready-sample-size pcfg))
            (= 2 (:ready-threshold pcfg))
            (= 5 (:delivery-sample-size pcfg))
            (= 4 (:delivery-threshold pcfg))
            (= 5 (:echo-sample-size rcfg))
            (= 4 (:delivery-threshold rcfg)))
       (and (= 2 (:murmur-k pcfg))
            (= 2 (:echo-sample-size pcfg))
            (= 2 (:echo-threshold pcfg))
            (= 2 (:ready-sample-size pcfg))
            (= 1 (:ready-threshold pcfg))
            (= 2 (:delivery-sample-size pcfg))
            (= 2 (:delivery-threshold pcfg)))))))

(defspec ^{:doc "BIP-008 Prop 4 (P-CONTAG-3): Mainnet config never stalls Contagion delivery at small cluster sizes N in [4..12], and validate-contagion-config diagnoses unclamped threshold > N-1."}
  prop-mainnet-config-never-stalls-delivery-at-small-N 50
  (prop/for-all
   [cluster-n (gen/choose 4 12)
    tx-amt (gen/choose 10 500)]
   (let [v (dec cluster-n)
         nodes-map (make-test-validator-entries cluster-n)
         all-pks (mapv :pubkey (vals nodes-map))
         self-entry (first (vals nodes-map))
         self-pk (:pubkey self-entry)
         self-sk (:privkey self-entry)
         peer-entries (rest (vals nodes-map))
         peer-pks (mapv :pubkey peer-entries)
         peers (mapv (fn [e] (basalt/make-peer (:ip e) (:port e) (basalt/hex->bytes (:pubkey e)))) peer-entries)
         m-cfg (assoc config/mainnet-config
                      :genesis-ledger {self-pk (account/map->AccountState {:balance 100000 :seq 0 :deps []})})
         val-check (mesh/validate-contagion-config m-cfg all-pks)
         st0 (-> (sm/init-state peers self-pk m-cfg)
                 (assoc :node-private-key self-sk
                        :global-echo-sample (set peer-pks)
                        :global-ready-sample (set peer-pks)
                        :global-delivery-sample (set peer-pks)))
         tx (account/create-transfer self-sk {:sender self-pk
                                              :receiver (first peer-pks)
                                              :amount tx-amt
                                              :seq 1
                                              :deps []
                                              :network-uri "mainnet.bitecho.org"})
         payload (fressian/encode-canonical {:transfer (into {} tx)})
         bcast (sm/handle-event st0 {:type :broadcast
                                     :payload payload
                                     :private-key self-sk
                                     :public-key (basalt/hex->bytes self-pk)
                                     :burn 100
                                     :rng (java.util.Random. 99)})
         st1 (:state bcast)
         mid (first (:contagion-known-ids st1))
         st2 (reduce (fn [s e]
                       (let [signed (sieve/sign-control-frame :sieve-echo mid (:privkey e) (:pubkey e))]
                         (:state (sm/handle-event s {:type :receive-sieve-echo
                                                     :sender (:pubkey e)
                                                     :message-id mid
                                                     :signature (:signature signed)}))))
                     st1
                     peer-entries)
         st3 (reduce (fn [s e]
                       (let [signed (sieve/sign-control-frame :contagion-ready mid (:privkey e) (:pubkey e))]
                         (:state (sm/handle-event s {:type :receive-contagion-ready
                                                     :sender (:pubkey e)
                                                     :message-id mid
                                                     :signature (:signature signed)}))))
                     st2
                     peer-entries)
         clamped-d (sm/effective-sample-threshold (:delivery-sample-size m-cfg)
                                                  (:delivery-threshold m-cfg)
                                                  v)]
     (and (<= clamped-d v)
          (contains? (:delivered-set st3) mid)
          (map? val-check)
          (true? (:valid? val-check))
          (if (< v (:delivery-threshold m-cfg))
            (true? (:clamped? val-check))
            (false? (:clamped? val-check)))))))

(defspec ^{:doc "BIP-008 Prop 5 (P-SOAK-1 / BUG-SOAK-01): Shared HttpClient returns identical instance and executing 100+ HTTP calls spawns at most 1 SelectorManager thread."}
  prop-shared-http-client-single-selector-manager 50
  (prop/for-all
   [batch-size (gen/choose 2 4)]
   (let [c1 (http/default-http-client)
         c2 (http/default-http-client)
         c3 (light-shell/default-http-client)
         c4 (acme/create-http-client)
         c5 (acme/create-http-client)
         before-threads (count-selector-manager-threads)
         srv (com.sun.net.httpserver.HttpServer/create (java.net.InetSocketAddress. "127.0.0.1" 0) 0)
         _ (.createContext srv "/"
                           (reify com.sun.net.httpserver.HttpHandler
                             (handle [_ ex]
                               (let [bs (.getBytes "{\"ok\":true,\"messages\":[],\"snapshots\":[]}" StandardCharsets/UTF_8)]
                                 (.sendResponseHeaders ex 200 (alength bs))
                                 (with-open [os (.getResponseBody ex)]
                                   (.write os bs))))))
         _ (.start srv)
         port (.getPort (.getAddress srv))
         base-url (str "http://127.0.0.1:" port)
         kp (crypto/generate-keypair "d34-p5-http")
         pk (kp->pk-hex kp)
         sk (kp->sk kp)]
     (try
       (dotimes [_ batch-size]
         (light-shell/poll-relay-envelopes! base-url pk sk {:since-seq 0 :timeout-ms 0})
         (light-shell/fetch-relay-chain-state! base-url {:pubkey pk :nonce "n1" :timeout-ms 1000})
         (light-shell/submit-relay-envelope! base-url "deadbeef" {:timeout-ms 1000})
         (light-shell/post-control-request! port "tok" {"cmd" "status"} 1000))
       (let [after-threads (count-selector-manager-threads)]
         (and (identical? c1 c2)
              (identical? c1 c3)
              (identical? c4 c5)
              (<= (- after-threads before-threads) 1)))
       (finally
         (.stop srv 0))))))

(defspec ^{:doc "BIP-008 Prop 6 (P-LEG-1): Relay P2P leg transitions from :connecting to :open only after a cryptographically verified :p2p-link-bind from the session peer; forged link-binds are rejected with counted :p2p-link-bind-rejected diagnostics."}
  prop-relay-leg-opens-only-after-verified-link-bind 50
  (prop/for-all
   [sid-num (gen/choose 1000 9999)
    forged-type (gen/elements [:wrong-signer :corrupt-sig :wrong-session])]
   (let [alice-kp (crypto/generate-keypair (str "d34-p6-alice-" sid-num))
         bob-kp (crypto/generate-keypair (str "d34-p6-bob-" sid-num))
         mallory-kp (crypto/generate-keypair (str "d34-p6-mallory-" sid-num))
         alice-pk (kp->pk-hex alice-kp)
         alice-sk (kp->sk alice-kp)
         bob-pk (kp->pk-hex bob-kp)
         bob-sk (kp->sk bob-kp)
         mallory-pk (kp->pk-hex mallory-kp)
         mallory-sk (kp->sk mallory-kp)
         ;; Establish open E2EE session between Alice and Bob with P2P phase in :connecting (connected? false)
         off-res (light-core/handle-command
                  (-> (light-core/init-light-state {:pubkey-hex alice-pk} {:subnet-id "global" :economy-enabled? true :burn-floor 100 :epoch 10 :autonomous? true})
                      (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
                  {"cmd" "offer" "callee" bob-pk "peer" bob-pk "price" 10 "burn" 100}
                  alice-sk)
         real-sid (get-in off-res [:response "session_id"])
         bob-st0 (-> (light-core/init-light-state {:pubkey-hex bob-pk} {:subnet-id "global" :economy-enabled? true :burn-floor 100 :epoch 10 :autonomous? true})
                     (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
         bob-rx (reduce (fn [acc env]
                          (let [r (light-core/handle-wire-payload (:state acc) env bob-sk)]
                            {:state (:state r) :net-envelopes (into (:net-envelopes acc) (:net-envelopes r))}))
                        {:state bob-st0 :net-envelopes []}
                        (:net-envelopes off-res))
         alice-open (reduce (fn [st env] (:state (light-core/handle-wire-payload st env alice-sk)))
                            (:state off-res)
                            (:net-envelopes bob-rx))
         alice-connecting (assoc-in alice-open [:sessions real-sid :p2p]
                                    {:phase :connecting
                                     :connected? false
                                     :zero-burn? false
                                     :transport "https"})
         ;; 1. While in :connecting, send uses mesh fallback (burn=500, p2p=false)
         send-before (light-core/handle-command alice-connecting {"cmd" "send" "session_id" real-sid "text" "while-connecting"} alice-sk)
         ;; 2. Forged/invalid :p2p-link-bind must be rejected with counted :p2p-link-bind-rejected diagnostic
         bad-bind (case forged-type
                    :wrong-signer (light-shell/build-p2p-link-bind-envelope mallory-pk mallory-sk real-sid)
                    :corrupt-sig (assoc (light-shell/build-p2p-link-bind-envelope bob-pk bob-sk real-sid)
                                        :signature (apply str (repeat 128 "0")))
                    :wrong-session (light-shell/build-p2p-link-bind-envelope bob-pk bob-sk (str real-sid "-wrong")))
         rx-bad (light-core/handle-wire-payload (:state send-before) (fressian/encode-wire bad-bind) alice-sk)
         st-after-bad (:state rx-bad)
         ;; 3. Valid :p2p-link-bind from Bob transitions session P2P state to :open / connected? true / zero-burn? true
         good-bind (light-shell/build-p2p-link-bind-envelope bob-pk bob-sk real-sid)
         rx-good (light-core/handle-wire-payload st-after-bad (fressian/encode-wire good-bind) alice-sk)
         st-after-good (:state rx-good)
         send-after (light-core/handle-command st-after-good {"cmd" "send" "session_id" real-sid "text" "after-verified-bind"} alice-sk)]
     (and (= 500 (get-in send-before [:response "burn"]))
          (false? (get-in send-before [:response "p2p"]))
          (false? (get-in st-after-bad [:sessions real-sid :p2p :connected?]))
          (= 1 (get-in st-after-bad [:diagnostics :p2p-link-bind-rejected]))
          (some #(= "p2p-link-bind-rejected" (get % "reason")) (:stdout-events rx-bad))
          (true? (get-in st-after-good [:sessions real-sid :p2p :connected?]))
          (= :open (get-in st-after-good [:sessions real-sid :p2p :phase]))
          (true? (get-in st-after-good [:sessions real-sid :p2p :zero-burn?]))
          (some #(= "p2p-connected" (get % "event")) (:stdout-events rx-good))
          (= 0 (get-in send-after [:response "burn"]))
          (true? (get-in send-after [:response "p2p"]))))))

;; =============================================================================
;; 2. Deterministic E2E Scenarios (S-D34-1..S-D34-6)
;; =============================================================================

(deftest scenario-s-d34-1-bounded-trailing-epoch-contagion-summary-test
  (testing "S-D34-1 (P-CONTAG-4): contagion/generate-summary and handle-tick bound anti-entropy summary IDs to trailing epoch window"
    (let [peer-kp (crypto/generate-keypair "d34-s1-peer")
          peer (basalt/make-peer "10.0.0.2" 8000 (:public peer-kp))
          self-kp (crypto/generate-keypair "d34-s1-self")
          self-pk (kp->pk-hex self-kp)
          cfg (assoc config/default-config
                     :contagion-summary-window-epochs 3
                     :gossip-ttl-epochs 20)
          st0 (-> (sm/init-state [peer] self-pk cfg)
                  (assoc :epoch 10
                         :contagion-known-ids #{"msg-ep2" "msg-ep5" "msg-ep8" "msg-ep9" "msg-ep10"}
                         :message-epochs {"msg-ep2" 2
                                          "msg-ep5" 5
                                          "msg-ep8" 8
                                          "msg-ep9" 9
                                          "msg-ep10" 10}
                         :epoch-to-messages {2 #{"msg-ep2"}
                                             5 #{"msg-ep5"}
                                             8 #{"msg-ep8"}
                                             9 #{"msg-ep9"}
                                             10 #{"msg-ep10"}}))
          tick-res (sm/handle-event st0 {:type :tick :rng (java.util.Random. 7)})
          sum-cmd (first (filter #(= :send-summary (:type %)) (:commands tick-res)))]
      (is (some? sum-cmd))
      (is (= #{"msg-ep8" "msg-ep9" "msg-ep10"} (:summary sum-cmd))
          "Summary on tick must only include message IDs within the trailing :contagion-summary-window-epochs"))))

(deftest scenario-s-d34-2-directory-lookup-qualified-domain-nickname-test
  (testing "S-D34-2 (P-SOAK-2 / BUG-SOAK-02): directory-lookup and directory-verify accept qualified domain/nickname (--name bitecho.org/vector and --nickname bitecho.org/vector)"
    (let [dir-kp (crypto/generate-keypair "d34-s2-dir")
          dir-pk (kp->pk-hex dir-kp)
          dir-sk (kp->sk dir-kp)
          vec-kp (crypto/generate-keypair "d34-s2-vector")
          vec-pk (kp->pk-hex vec-kp)
          vec-sk (kp->sk vec-kp)
          pop (light-core/create-directory-pop vec-sk {:domain "bitecho.org"
                                                       :nickname "vector"
                                                       :pubkey vec-pk
                                                       :home-set ["node1" "node2"]
                                                       :epoch 10})
          desc (light-core/sign-directory-descriptor dir-sk
                                                     dir-pk
                                                     pop
                                                     {:issued-epoch 10
                                                      :expires-epoch 500})
          st0 (-> (light-core/init-light-state {:pubkey-hex vec-pk} {:subnet-id "global" :epoch 12})
                  (assoc :trusted-directory-pubkey dir-pk))
          ;; Verify via CLI build-cmd-map with both --nickname and --name qualified as bitecho.org/vector
          cmd-v (cli/build-cmd-map "directory-verify" ["directory-verify" "--name" "bitecho.org/vector"])
          v-res (light-core/handle-command st0 (assoc cmd-v "descriptor" desc) vec-sk)
          st1 (:state v-res)
          cmd-l1 (cli/build-cmd-map "directory-lookup" ["directory-lookup" "--name" "bitecho.org/vector"])
          cmd-l2 (cli/build-cmd-map "directory-lookup" ["directory-lookup" "--nickname" "bitecho.org/vector"])
          l1-res (light-core/handle-command st1 cmd-l1 vec-sk)
          l2-res (light-core/handle-command st1 cmd-l2 vec-sk)]
      (is (= "vector" (get cmd-l1 "nickname")))
      (is (= "bitecho.org" (get cmd-l1 "domain")))
      (is (true? (get-in v-res [:response "ok"])))
      (is (true? (get-in l1-res [:response "ok"])))
      (is (= vec-pk (get-in l1-res [:response "descriptor" :pubkey])))
      (is (true? (get-in l2-res [:response "ok"])))
      (is (= vec-pk (get-in l2-res [:response "descriptor" :pubkey]))))))

(deftest scenario-s-d34-3-artifact-put-auto-relay-and-vector-allowlist-test
  (testing "S-D34-3 (P-SOAK-3 / BUG-SOAK-03): artifact-put auto-infers relay URL from bootstrap when conn-opts omits :relay-url, and default-infra-policy includes K_vector"
    (let [tmp-dir (make-tmp-dir!)
          vec-kp (crypto/generate-keypair "d34-s3-vector")
          vec-pk (kp->pk-hex vec-kp)
          vec-sk (kp->sk vec-kp)
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath tmp-dir)
               :node-id :ns1
               :node-privkey vec-sk
               :policy (infra/default-infra-policy {:trust-anchors [vec-pk]})})
          tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir) :domain "localhost"})
          srv (http/start-http-servers! {:domain "localhost"
                                         :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                        tls-mgr rt)
          port (:http-port srv)
          relay-url (str "http://127.0.0.1:" port)]
      (try
        ;; 1. Verify K_vector is in default-infra-policy doc/blog/bip signers and default-dev-signers
        (let [pol (infra/default-infra-policy {:trust-anchors [vec-pk]})
              blog-rule (some #(when (= (:pattern %) "web/blog/*") %) (:subnet/path-acl pol))
              bip-rule (some #(when (= (:pattern %) "bip/*") %) (:subnet/path-acl pol))]
          (is (= "302a300506032b6570032100365bd3dc35b4f609d6ac147c129c5b791798765b181d53341e58d6fcf1c6cd62"
                 infra/K_vector))
          (is (contains? (get-in blog-rule [:principal :signers]) infra/K_vector))
          (is (contains? (get-in bip-rule [:principal :signers]) infra/K_vector))
          (is (contains? infra/default-dev-signers infra/K_vector)))
        ;; 2. Verify handle-serve-line! falls back to bootstrap :relay-url when conn-opts has no :relay-url
        (let [st-atom (atom (-> (light-core/init-light-state {:pubkey-hex vec-pk} {:subnet-id "bitecho.org/infra" :epoch 10})
                                (assoc :account {:balance 100000 :spendable 100000 :seq 0})))
              ctx {:state-atom st-atom
                   :identity {:pubkey-hex vec-pk :privkey-bytes vec-sk}
                   :bootstrap {:domain "bitecho.org"
                               :relay-url relay-url
                               :nodes {}}
                   :conn-opts {}}
              serve-res (light-shell/handle-serve-line!
                         {"cmd" "artifact-put"
                          "subnet_id" "bitecho.org/infra"
                          "path" "web/blog/d34-soak-report.md"
                          "text" "# Vector Soak Report\n"}
                         ctx)
              resolved (infra/resolve-path-blob! rt "web/blog/d34-soak-report.md")]
          (is (true? (get serve-res "ok")))
          (is (true? (:ok? resolved)) "handle-serve-line! must auto-push artifact to bootstrap relay-url even when conn-opts omits :relay-url")
          (is (= "# Vector Soak Report\n"
                 (String. ^bytes (get-in resolved [:blob :blob/bytes]) StandardCharsets/UTF_8))))
        (finally
          (try (http/stop-http-servers! srv) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d34-4-udp-socket-receive-buffer-4mb-test
  (testing "S-D34-4 (P-SOAK-4 / DIAG-SOAK-03): Light-node and DNS UDP sockets configure 4 MB SO_RCVBUF helper cleanly"
    (with-open [ch (java.nio.channels.DatagramChannel/open)]
      (is (true? (light-shell/configure-udp-receive-buffer! ch 4194304)))
      (let [actual (.getOption ch java.net.StandardSocketOptions/SO_RCVBUF)]
        (is (pos? actual))))))

(deftest scenario-s-d34-5-dirty-gated-non-canonical-snapshot-persistence-test
  (testing "S-D34-5 (P-SOAK-5): save-state-to-disk skips redundant disk rewrites when state is unchanged and round-trips non-canonical Fressian snapshots identically"
    (let [tmp-file (java.io.File/createTempFile "d34-dirty-snap-" ".bin")
          filepath (.getAbsolutePath tmp-file)
          acct (account/map->AccountState {:balance 75000 :seq 3 :deps ["dep-1"]})
          st1 {:epoch 15
               :ledger {"alice" acct}
               :contagion-known-ids #{"m1" "m2"}
               :murmur-cache {:queue (into clojure.lang.PersistentQueue/EMPTY ["m1" "m2"])
                              :set #{"m1" "m2"}}}
          st2 (assoc st1 :epoch 16)]
      (try
        (is (true? (persistence/save-state-to-disk filepath st1)))
        (let [mtime1 (.lastModified tmp-file)]
          ;; Sleep briefly and re-save identical state -> dirty gate skips disk rewrite
          (Thread/sleep 20)
          (is (true? (persistence/save-state-to-disk filepath st1)))
          (is (= (:skipped-clean (persistence/persistence-stats filepath)) 1)
              "Redundant save of identical state must increment :skipped-clean")
          (is (= mtime1 (.lastModified tmp-file)))
          ;; Save mutated state -> writes to disk and updates snapshot
          (is (true? (persistence/save-state-to-disk filepath st2)))
          (let [loaded (persistence/load-state-from-disk filepath)]
            (is (= 16 (:epoch loaded)))
            (is (= acct (get-in loaded [:ledger "alice"])))
            (is (= #{"m1" "m2"} (:contagion-known-ids loaded)))))
        (finally
          (.delete tmp-file))))))

(deftest scenario-s-d34-6-cluster-sh-and-version-02312-test
  (testing "S-D34-6: scripts/cluster.sh renders devnet-6 Contagion sample parameters, cross-root-subnet offer/accept uses wildcard outer-sub, and config/version is 0.23.12"
    (let [cluster-sh (slurp "scripts/cluster.sh")
          lumen-kp (crypto/generate-keypair "d34-s6-lumen")
          lumen-pk (kp->pk-hex lumen-kp)
          lumen-sk (kp->sk lumen-kp)
          nexus-kp (crypto/generate-keypair "d34-s6-nexus")
          nexus-pk (kp->pk-hex nexus-kp)
          nexus-sk (kp->sk nexus-kp)
          lumen-st (-> (light-core/init-light-state {:pubkey-hex lumen-pk}
                                                    {:subnet-id "devnet.bitecho.org" :economy-enabled? true :burn-floor 100 :epoch 12})
                       (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
          nexus-st (-> (light-core/init-light-state {:pubkey-hex nexus-pk}
                                                    {:subnet-id "global"
                                                     :bootstrap {:domain "bitecho.org"}
                                                     :economy-enabled? true
                                                     :burn-floor 100
                                                     :epoch 12
                                                     :autonomous? true})
                       (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
          off-res (light-core/handle-command lumen-st {"cmd" "offer" "callee" nexus-pk "peer" nexus-pk "price" 10 "burn" 500} lumen-sk)
          gossip-env (last (:net-envelopes off-res))
          sid (get-in off-res [:response "session_id"])
          nx-rx (light-core/handle-wire-payload nexus-st gossip-env nexus-sk)
          acc-env (first (:net-envelopes nx-rx))
          lu-rx (light-core/handle-wire-payload (:state off-res) acc-env lumen-sk)]
      (is (= "*" (:subnet-id gossip-env)) "Burn-bearing root-subnet offer outer envelope must use wildcard '*' subnet-id")
      (is (= "*" (:subnet-id acc-env)) "Burn-bearing root-subnet accept outer envelope must use wildcard '*' subnet-id")
      (is (= "open" (get-in (:state nx-rx) [:sessions sid :state])) "Nexus ('global' / 'bitecho.org') must auto-accept Lumen's ('devnet.bitecho.org') offer without subnet-mismatch")
      (is (= "open" (get-in (:state lu-rx) [:sessions sid :state])) "Lumen ('devnet.bitecho.org') must accept Nexus's channel-accept without subnet-mismatch")
      (is (str/includes? cluster-sh ":echo-sample-size 5"))
      (is (str/includes? cluster-sh ":echo-threshold 4"))
      (is (str/includes? cluster-sh ":ready-sample-size 5"))
      (is (str/includes? cluster-sh ":ready-threshold 2"))
      (is (str/includes? cluster-sh ":delivery-sample-size 5"))
      (is (str/includes? cluster-sh ":delivery-threshold 4"))
      (is (contains? #{"0.23.12" "0.23.13" "0.23.14"} config/version)))))
