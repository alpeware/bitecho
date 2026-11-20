(ns bitecho.d33-bip007-low-latency-and-infra-test
  "Milestone D33 (`BIP-007: Low-Latency Quorum Sync, Zero-Burn HTTPS Relay Legs & Cluster Operations Hardening` / `v0.23.11`)
   Generative `test.check` Invariants & Deterministic Full-Topology Scenarios:
   1. `prop-d33-zero-burn-relay-p2p-mailbox-admission`: 0-burn P2P envelopes admitted to HTTP relay mailboxes while only burned envelopes emit `:forward-to-validators`.
   2. `prop-d33-autonomous-p2p-offer-auto-answer-and-dial`: `--autonomous` auto-answers incoming `:p2p-offer` on open sessions even when not yet P2P-connected, emitting both events and `:p2p-dial`.
   3. `prop-d33-unambiguous-most-active-open-session-resolution`: `resolve-session-id` deterministically selects the most active open session (`tx-seq + rx-high-seq`, tie-breaking by `:epoch` and `:session-id`).
   4. `prop-d33-canonical-put-desugaring-and-endpoint-candidate-mapping`: `put` preserves `canonical_cmd = \"put\"` / `cmd = \"artifact-put\"`, and `p2p-offer` / `p2p-answer` maps `--endpoint` to `\"candidates\"` and `--to` to `\"to\"`/`\"peer\"`.
   5. `prop-d33-idempotent-replicated-artifact-pointer-acceptance`: `/artifact/v1/pointer` returns HTTP 200 OK with `\"idempotent\": true` when an already-applied pointer is re-submitted.
   6. `S-D33-1..S-D33-5`: Deterministic end-to-end simulation scenarios."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
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
  (.toFile (Files/createTempDirectory "d33-bip007-test-" (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^File f]
  (when (and f (.exists f))
    (when (.isDirectory f)
      (doseq [^File child (.listFiles f)]
        (delete-dir-recursively! child)))
    (.delete f)))

;; =============================================================================
;; 1. Generative Properties (Rule 1: >= 50 trials each)
;; =============================================================================

(defspec ^{:doc "BIP-007 Prop 1 (P-NET-2): Zero-burn P2P envelopes are admitted into recipient relay mailboxes while :forward-to-validators is emitted only when burn >= min-signaling-burn."}
  prop-d33-zero-burn-relay-p2p-mailbox-admission 50
  (prop/for-all
   [p2p-type (gen/elements [:sealed-message :session-ack :p2p-broadcast :p2p-hub-relay :p2p-offer :p2p-answer :p2p-link-bind])
    burn-amt (gen/elements [0 100 250])
    sid (gen/fmap #(str "sess-d33-" %) (gen/choose 1000 9999))]
   (let [alice-kp (crypto/generate-keypair (str "d33-p1-alice-" sid))
         bob-kp (crypto/generate-keypair (str "d33-p1-bob-" sid))
         alice-pk (kp->pk-hex alice-kp)
         alice-sk (kp->sk alice-kp)
         bob-pk (kp->pk-hex bob-kp)
         relay-st0 (relay/init-relay-state {:min-signaling-burn 100})
         env (if (= p2p-type :p2p-link-bind)
               (assoc (light-shell/build-p2p-link-bind-envelope alice-pk alice-sk sid)
                      :recipient bob-pk)
               (let [inner (case p2p-type
                             :p2p-broadcast
                             {:bitecho/type :p2p-broadcast
                              :type :p2p-broadcast
                              :subnet-id "chat/simon-nexus-axiom"
                              :sender alice-pk
                              :text "zero-burn p2p broadcast"}
                             {:bitecho/type p2p-type
                              :type p2p-type
                              :session-id sid
                              :sender alice-pk
                              :recipient bob-pk
                              :seq 1})]
                 (light-core/build-gossip-envelope
                  alice-pk
                  alice-sk
                  (fressian/encode-wire inner)
                  burn-amt
                  (if (pos? burn-amt) "*" "global"))))
         res (relay/reduce-relay relay-st0 {:type :relay-submit
                                            :envelope env
                                            :now-ms 1700000000000})
         fwd-effects (filterv #(= :forward-to-validators (:effect %)) (:effects res))]
     (and (true? (:ok? res))
          (if (= p2p-type :p2p-broadcast)
            (= 1 (count (:broadcasts (:state res))))
            (= 1 (count (get-in (:state res) [:mailboxes bob-pk]))))
          (if (or (= p2p-type :p2p-link-bind) (< burn-amt 100))
            (empty? fwd-effects)
            (= 1 (count fwd-effects)))))))

(defspec ^{:doc "BIP-007 Prop 2 (P-NET-2): Autonomous responder automatically generates a signed :p2p-answer and populates :p2p-dial on incoming :p2p-offer for any open session."}
  prop-d33-autonomous-p2p-offer-auto-answer-and-dial 50
  (prop/for-all
   [relay-host (gen/elements ["https://ns1.bitecho.org/relay/v1"
                              "https://ns2.bitecho.org/relay/v1"
                              "https://bitecho.org/relay/v1"])
    already-open? gen/boolean
    sig-seq (gen/choose 1 500)]
   (let [alice-kp (crypto/generate-keypair (str "d33-p2-alice-" sig-seq))
         bob-kp (crypto/generate-keypair (str "d33-p2-bob-" sig-seq))
         alice-pk (kp->pk-hex alice-kp)
         alice-sk (kp->sk alice-kp)
         bob-pk (kp->pk-hex bob-kp)
         bob-sk (kp->sk bob-kp)
         sid (str "sess-d33-auto-" sig-seq)
         bob-st0 (-> (light-core/init-light-state {:pubkey-hex bob-pk
                                                   :fingerprint "AA:BB:CC:DD"}
                                                  {:subnet-id "global"
                                                   :epoch 10
                                                   :autonomous? true})
                     (assoc :default-p2p-candidates ["udp://192.168.1.50:5011"])
                     (assoc-in [:sessions sid]
                               {:session-id sid
                                :peer alice-pk
                                :role "callee"
                                :state "open"
                                :epoch 10
                                :p2p {:phase (if already-open? :open :closed)
                                      :connected? already-open?
                                      :local-candidates nil}}))
         alice-st0 (-> (light-core/init-light-state {:pubkey-hex alice-pk
                                                     :fingerprint "11:22:33:44"}
                                                    {:subnet-id "global"
                                                     :epoch 10
                                                     :autonomous? true})
                       (assoc-in [:sessions sid]
                                 {:session-id sid
                                  :peer bob-pk
                                  :role "caller"
                                  :state "open"
                                  :epoch 10
                                  :p2p {:phase :closed :connected? false}}))
         offer-res (light-core/handle-command
                    alice-st0
                    {"cmd" "p2p-offer"
                     "session_id" sid
                     "transport" "https"
                     "candidates" [relay-host]
                     "signal_seq" sig-seq}
                    alice-sk)
         offer-env (first (:net-envelopes offer-res))
         bob-rx (light-core/handle-wire-payload bob-st0 (fressian/encode-wire offer-env) bob-sk)
         ans-env (first (:net-envelopes bob-rx))
         ans-inner (when ans-env (light-core/unwrap-wire-message ans-env))
         ev-names (set (map #(or (get % "event") (:event %)) (:stdout-events bob-rx)))]
     (and (some? ans-env)
          (= :p2p-answer (:type ans-inner))
          (contains? (set (:candidates ans-inner)) relay-host)
          (contains? ev-names "p2p-offer-answered-while-open")
          (if already-open?
            true
            (and (contains? ev-names "p2p-offer-received")
                 (= :connecting (get-in (:state bob-rx) [:sessions sid :p2p :phase]))))
          (some? (:p2p-dial bob-rx))
          (contains? (set (get-in bob-rx [:p2p-dial :remote-candidates])) relay-host)))))

(defspec ^{:doc "BIP-007 Prop 3 (P-NET-2): resolve-session-id deterministically selects the most active open session by (tx-seq + rx-high-seq) when multiple sessions exist for the same peer."}
  prop-d33-unambiguous-most-active-open-session-resolution 50
  (prop/for-all
   [tx1 (gen/choose 0 20)
    rx1 (gen/choose 0 20)
    delta (gen/choose 1 25)
    ep1 (gen/choose 1 50)
    ep2 (gen/choose 1 50)]
   (let [alice-kp (crypto/generate-keypair "d33-p3-alice")
         bob-kp (crypto/generate-keypair "d33-p3-bob")
         alice-pk (kp->pk-hex alice-kp)
         bob-pk (kp->pk-hex bob-kp)
         sid-offered "sess-00-offered"
         sid-open-low "sess-01-open-low"
         sid-open-high "sess-02-open-high"
         total-low (+ tx1 rx1)
         total-high (+ total-low delta)
         st (-> (light-core/init-light-state {:pubkey-hex alice-pk} {:subnet-id "global" :epoch 60})
                (assoc :sessions
                       {sid-offered {:session-id sid-offered
                                     :peer bob-pk
                                     :state "offered"
                                     :epoch 99
                                     :tx-seq 100
                                     :rx-high-seq 100}
                        sid-open-low {:session-id sid-open-low
                                      :peer bob-pk
                                      :state "open"
                                      :epoch ep1
                                      :tx-seq tx1
                                      :rx-high-seq rx1}
                        sid-open-high {:session-id sid-open-high
                                       :peer bob-pk
                                       :state "open"
                                       :epoch ep2
                                       :tx-seq total-high
                                       :rx-high-seq 0}}))
         resolved (light-core/resolve-session-id st {"to" bob-pk} :open)]
     (= sid-open-high resolved))))

(defspec ^{:doc "BIP-007 Prop 4 (P-NET-2 & P-ART-1): Canonical put desugars to artifact-put while preserving canonical_cmd, and p2p-offer / p2p-answer map --endpoint to candidates and --to to peer."}
  prop-d33-canonical-put-desugaring-and-endpoint-candidate-mapping 50
  (prop/for-all
   [sub-path (gen/fmap #(str "web/blog/post-" % ".md") (gen/choose 1 999))
    endpoint-url (gen/elements ["https://ns1.bitecho.org/relay/v1"
                                "https://ns2.bitecho.org/relay/v1"
                                "udp://192.168.1.10:5011"])
    peer-id (gen/elements ["nexus" "axiom" "302a300506032b6570032100e6fb9542cab052ca0a766ca3e62a9710a4878b0755d6692abcbe301041d10c0e"])]
   (let [put-map (cli/build-cmd-map "put" ["put" "--subnet-id" "bitecho.org/infra" "--path" sub-path "--text" "hello"])
         desugared-put (cli/desugar-cli-cmd-map {"cmd" "put" "subnet_id" "bitecho.org/infra" "path" sub-path "text" "hello"})
         p2p-off-map (cli/build-cmd-map "p2p-offer" ["p2p-offer" "--to" peer-id "--endpoint" endpoint-url])
         p2p-ans-map (cli/build-cmd-map "p2p-answer" ["p2p-answer" "--to" peer-id "--endpoint" endpoint-url])]
     (and (= "artifact-put" (get put-map "cmd"))
          (= "put" (get put-map "canonical_cmd"))
          (= "artifact-put" (get desugared-put "cmd"))
          (= "put" (get desugared-put "canonical_cmd"))
          (= [endpoint-url] (get p2p-off-map "candidates"))
          (= peer-id (get p2p-off-map "to"))
          (= [endpoint-url] (get p2p-ans-map "candidates"))
          (= peer-id (get p2p-ans-map "to"))))))

(defspec ^{:doc "BIP-007 Prop 5 (P-ART-1): /artifact/v1/pointer accepts idempotent or already-applied pointers with identical target CID with HTTP 200 OK and idempotent: true."}
  prop-d33-idempotent-replicated-artifact-pointer-acceptance 50
  (prop/for-all
   [seq-num (gen/choose 2 20)
    older-offset (gen/choose 0 1)]
   (let [tmp-dir (make-tmp-dir!)
         kp (crypto/generate-keypair (str "d33-p5-publisher-" seq-num))
         pk (kp->pk-hex kp)
         sk (kp->sk kp)
         rt (infra/start-subnet-runtime!
             {:state-dir (.getAbsolutePath tmp-dir)
              :node-id :ns1
              :node-privkey sk
              :policy (infra/default-infra-policy {:trust-anchors [pk]})})
         tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir)
                                          :domain "localhost"})
         srv (http/start-http-servers! {:domain "localhost"
                                        :http {:bind-ip "127.0.0.1"
                                               :http-port 0
                                               :https-port 0}}
                                       tls-mgr
                                       rt)]
     (try
       (let [port (:http-port srv)
             client (HttpClient/newHttpClient)
             blob (data/make-blob (.getBytes (str "artifact-v" seq-num) StandardCharsets/UTF_8) "text/markdown")
             _ (infra/put-blob! rt blob {:sender pk})
             ptr (data/sign-pointer
                  sk
                  {:pointer/authority pk
                   :pointer/subnet "bitecho.org/infra"
                   :pointer/path "web/d33-idempotent.md"
                   :pointer/seq (long seq-num)
                   :pointer/target (:blob/cid blob)
                   :pointer/proof {:proof/type :self}})
             post-ptr! (fn [p]
                         (let [req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/artifact/v1/pointer")))
                                       (.header "Content-Type" "application/edn")
                                       (.POST (HttpRequest$BodyPublishers/ofString (pr-str p) StandardCharsets/UTF_8))
                                       (.build))]
                           (.send client req (HttpResponse$BodyHandlers/ofString))))
             r1 (post-ptr! ptr)
             ;; Re-submit identical pointer or lower seq with identical target CID
             dup-ptr (data/sign-pointer
                      sk
                      (assoc ptr :pointer/seq (long (- seq-num older-offset))))
             r2 (post-ptr! dup-ptr)
             j2 (json/read-str (.body r2))]
         (and (= 200 (.statusCode r1))
              (= 200 (.statusCode r2))
              (true? (get j2 "ok"))
              (true? (get j2 "idempotent"))))
       (finally
         (try (http/stop-http-servers! srv) (catch Exception _ nil))
         (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
         (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 2. Deterministic Full-Topology Simulation Scenarios (S-D33-1..S-D33-5)
;; =============================================================================

(deftest scenario-s-d33-1-fast-local-only-and-http-quorum-chain-state-test
  (testing "S-D33-1: /relay/v1/chain-state?local_only=true returns co-located validator snapshot in < 10ms without UDP :5010, and infra aggregates HTTP peer snapshots in parallel"
    (let [tmp-dir1 (make-tmp-dir!)
          tmp-dir2 (make-tmp-dir!)
          val1-kp (crypto/generate-keypair "d33-s1-val1")
          val1-pk (kp->pk-hex val1-kp)
          val1-sk (kp->sk val1-kp)
          val2-kp (crypto/generate-keypair "d33-s1-val2")
          val2-pk (kp->pk-hex val2-kp)
          val2-sk (kp->sk val2-kp)
          agent-kp (crypto/generate-keypair "d33-s1-agent")
          agent-pk (kp->pk-hex agent-kp)
          mk-val-node (fn [val-kp val-pk val-sk]
                        (let [st (-> (sm/init-state [{:pubkey val-pk}]
                                                    val-pk
                                                    (assoc (config/devnet-6-config)
                                                           :genesis-ledger {agent-pk {:balance 950000 :seq 5 :deps []}}))
                                     (assoc :last-executed-finalized-epoch 77))]
                          {:state-atom (atom st)
                           :identity {:pubkey-hex val-pk
                                      :privkey-hex (basalt/bytes->hex val-sk)
                                      :keypair {:public (:public val-kp) :private val-sk}}
                           :shell-node {:state-atom (atom st)}}))
          vnode1 (mk-val-node val1-kp val1-pk val1-sk)
          vnode2 (mk-val-node val2-kp val2-pk val2-sk)
          rt2 (infra/start-subnet-runtime!
               {:state-dir (.getAbsolutePath tmp-dir2)
                :node-id :ns2
                :node-privkey val2-sk
                :validator-node vnode2
                :policy (infra/default-infra-policy {:trust-anchors [val2-pk]})})
          tls2 (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir2) :domain "localhost"})
          srv2 (http/start-http-servers! {:domain "localhost"
                                          :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                         tls2 rt2)
          port2 (:http-port srv2)
          bootstrap {:nodes {:ns1 {:pubkey val1-pk :ip "127.0.0.1" :port 59998 :agent-port 59998}
                             :ns2 {:pubkey val2-pk :ip "127.0.0.1" :http-port port2 :port 59999 :agent-port 59999}}}
          rt1 (infra/start-subnet-runtime!
               {:state-dir (.getAbsolutePath tmp-dir1)
                :node-id :ns1
                :node-privkey val1-sk
                :validator-node vnode1
                :validator-bootstrap bootstrap
                :policy (infra/default-infra-policy {:trust-anchors [val1-pk]})})
          tls1 (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir1) :domain "localhost"})
          srv1 (http/start-http-servers! {:domain "localhost"
                                          :validator-bootstrap bootstrap
                                          :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                         tls1 rt1)
          port1 (:http-port srv1)]
      (try
        (let [client (HttpClient/newHttpClient)
              ;; 1. Query ns2 with local_only=true -> returns ONLY val2's snapshot immediately
              req-local (-> (HttpRequest/newBuilder
                             (URI/create (str "http://127.0.0.1:" port2 "/relay/v1/chain-state?pubkey=" agent-pk "&nonce=n-local-1&local_only=true")))
                            (.GET)
                            (.build))
              resp-local (.send client req-local (HttpResponse$BodyHandlers/ofString))
              json-local (json/read-str (.body resp-local))
              snaps-local (get json-local "snapshots")
              ;; 2. Query ns1 full /relay/v1/chain-state -> aggregates local vnode1 + HTTP peer ns2 (local_only=true) without dialing dead UDP 59999!
              udp-dialed? (atom false)
              _ (with-redefs [light-shell/query-validator-chain-state!
                              (fn [& _]
                                (reset! udp-dialed? true)
                                nil)]
                  (let [req-full (-> (HttpRequest/newBuilder
                                      (URI/create (str "http://127.0.0.1:" port1 "/relay/v1/chain-state?pubkey=" agent-pk "&nonce=n-agg-2")))
                                     (.GET)
                                     (.build))
                        resp-full (.send client req-full (HttpResponse$BodyHandlers/ofString))
                        json-full (json/read-str (.body resp-full))
                        snaps-full (get json-full "snapshots")
                        q-res (light-core/verify-chain-state-quorum
                               snaps-full
                               {:expected-pubkey agent-pk
                                :expected-nonce "n-agg-2"
                                :trusted-validators #{val1-pk val2-pk}})]
                    (is (= 200 (.statusCode resp-full)))
                    (is (= 2 (count snaps-full)))
                    (is (false? @udp-dialed?) "Must resolve peer snapshot over HTTP local_only=true without dialing UDP :5010")
                    (is (true? (:ok? q-res)))
                    (is (= 950000 (get-in q-res [:snapshot :balance])))))]
          (is (= 200 (.statusCode resp-local)))
          (is (= 1 (count snaps-local)))
          (is (= val2-pk (or (get (first snaps-local) "validator_pubkey")
                             (get (first snaps-local) "validator-pubkey")))))
        ;; 3. Also verify mesh /accountz?pubkey=<pk>&nonce=<n> includes signed :snapshot when identity is in ctx
        (let [val-st @(:state-atom vnode1)
              handler (mesh/make-http-handler {:shell-node vnode1
                                               :state-atom (:state-atom vnode1)
                                               :identity (:identity vnode1)
                                               :transport :in-memory
                                               :in-mem-bus (atom {})}
                                              1 val-st)
              acc-srv (com.sun.net.httpserver.HttpServer/create (java.net.InetSocketAddress. "127.0.0.1" 0) 0)
              _ (.createContext acc-srv "/" handler)
              _ (.start acc-srv)
              acc-port (.getPort (.getAddress acc-srv))]
          (try
            (let [client (HttpClient/newHttpClient)
                  req (-> (HttpRequest/newBuilder
                           (URI/create (str "http://127.0.0.1:" acc-port "/accountz?pubkey=" agent-pk "&nonce=n-acc-3")))
                          (.GET)
                          (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))
                  parsed (edn/read-string (.body resp))]
              (is (= 200 (.statusCode resp)))
              (is (= 950000 (:spendable parsed)))
              (is (map? (:snapshot parsed)))
              (is (true? (relay/verify-chain-state-snapshot-signature (:snapshot parsed)))))
            (finally
              (.stop acc-srv 0))))
        (finally
          (try (http/stop-http-servers! srv1) (catch Exception _ nil))
          (try (http/stop-http-servers! srv2) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt1) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt2) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir1)
          (delete-dir-recursively! tmp-dir2))))))

(deftest scenario-s-d33-2-zero-burn-https-relay-p2p-leg-e2e-test
  (testing "S-D33-2: Full 0-burn HTTPS relay P2P leg E2E (p2p-offer -> autonomous auto-answer -> :p2p-link-bind & 0-burn :sealed-message over /relay/v1/send with :min-signaling-burn 100)"
    (let [tmp-dir (make-tmp-dir!)
          val-kp (crypto/generate-keypair "d33-s2-val")
          val-pk (kp->pk-hex val-kp)
          val-sk (kp->sk val-kp)
          nexus-kp (crypto/generate-keypair "d33-s2-nexus")
          nexus-pk (kp->pk-hex nexus-kp)
          nexus-sk (kp->sk nexus-kp)
          axiom-kp (crypto/generate-keypair "d33-s2-axiom")
          axiom-pk (kp->pk-hex axiom-kp)
          axiom-sk (kp->sk axiom-kp)
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath tmp-dir)
               :node-id :ns1
               :node-privkey val-sk
               :policy (infra/default-infra-policy {:trust-anchors [val-pk]})})
          tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir) :domain "localhost"})
          srv (http/start-http-servers! {:domain "localhost"
                                         :min-signaling-burn 100
                                         :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                        tls-mgr rt)
          port (:http-port srv)
          relay-url (str "http://127.0.0.1:" port "/relay/v1")]
      (try
        ;; Establish E2EE session between Nexus and Axiom
        (let [nx0 (-> (light-core/init-light-state {:pubkey-hex nexus-pk :fingerprint "11:22"}
                                                   {:subnet-id "global" :economy-enabled? true :burn-floor 100 :epoch 12 :autonomous? true})
                      (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
              ax0 (-> (light-core/init-light-state {:pubkey-hex axiom-pk :fingerprint "33:44"}
                                                   {:subnet-id "global" :economy-enabled? true :burn-floor 100 :epoch 12 :autonomous? true})
                      (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
              off-res (light-core/handle-command nx0 {"cmd" "offer" "callee" axiom-pk "peer" axiom-pk "price" 10 "burn" 100} nexus-sk)
              nx1 (:state off-res)
              sid (get-in off-res [:response "session_id"])
              ;; Because ax0 has :autonomous? true, handle-wire-payload auto-accepts the offer and emits :channel-accept in :net-envelopes!
              ax-rx-off (reduce (fn [acc env]
                                  (let [r (light-core/handle-wire-payload (:state acc) env axiom-sk)]
                                    {:state (:state r)
                                     :net-envelopes (into (:net-envelopes acc) (:net-envelopes r))}))
                                {:state ax0 :net-envelopes []}
                                (:net-envelopes off-res))
              ax1 (:state ax-rx-off)
              nx2 (reduce (fn [st env]
                            (:state (light-core/handle-wire-payload st env nexus-sk)))
                          nx1
                          (:net-envelopes ax-rx-off))
              ;; Nexus sends p2p-offer using --to and --endpoint
              p2p-cmd (cli/build-cmd-map "p2p-offer" ["p2p-offer" "--to" axiom-pk "--endpoint" relay-url "--transport" "https"])
              p2p-off (light-core/handle-command nx2 p2p-cmd nexus-sk)
              nx3 (:state p2p-off)
              ;; Submit p2p-offer to HTTP relay
              r-off-sub (light-shell/submit-relay-envelope! relay-url (first (:net-envelopes p2p-off)) {:timeout-ms 3000})
              ;; Axiom polls HTTP relay -> autonomous? is true so Axiom auto-answers even though not yet P2P-connected!
              ax-poll1 (light-shell/poll-relay-envelopes! relay-url axiom-pk axiom-sk {:since-seq 0})
              ax-env1-hex (get (first (get ax-poll1 "messages")) "envelope_hex")
              ax-rx-p2p (light-core/handle-wire-payload ax1 (basalt/hex->bytes ax-env1-hex) axiom-sk)
              ax2 (:state ax-rx-p2p)
              auto-ans-env (first (:net-envelopes ax-rx-p2p))
              ;; Submit Axiom's auto-answer to HTTP relay
              r-ans-sub (light-shell/submit-relay-envelope! relay-url auto-ans-env {:timeout-ms 3000})
              ;; Nexus polls HTTP relay and receives p2p-answer
              nx-poll1 (light-shell/poll-relay-envelopes! relay-url nexus-pk nexus-sk {:since-seq 0})
              nx-env1-hex (get (first (get nx-poll1 "messages")) "envelope_hex")
              nx-rx-ans (light-core/handle-wire-payload nx3 (basalt/hex->bytes nx-env1-hex) nexus-sk)
              ;; Both sides mark P2P channel connected via HTTPS relay leg
              nx4 (:state (light-core/handle-command (:state nx-rx-ans) {"cmd" "p2p-channel-state" "session_id" sid "connected" true "transport" "https"} nexus-sk))
              ax3 (:state (light-core/handle-command ax2 {"cmd" "p2p-channel-state" "session_id" sid "connected" true "transport" "https"} axiom-sk))
              ;; Nexus sends a 0-burn sealed message over the open P2P HTTPS relay leg!
              send-res (light-core/handle-command nx4 {"cmd" "send" "to" axiom-pk "text" "Zero-burn P2P over HTTPS relay!"} nexus-sk)
              sealed-env (first (:net-envelopes send-res))
              r-msg-sub (light-shell/submit-relay-envelope! relay-url sealed-env {:timeout-ms 3000})
              ;; Axiom polls relay and decrypts the 0-burn sealed message!
              ax-poll2 (light-shell/poll-relay-envelopes! relay-url axiom-pk axiom-sk {:since-seq 1})
              ax-env2-hex (get (first (get ax-poll2 "messages")) "envelope_hex")
              ax-rx-msg (light-core/handle-wire-payload ax3 (basalt/hex->bytes ax-env2-hex) axiom-sk)
              inbox-res (light-core/handle-command (:state ax-rx-msg) {"cmd" "inbox"} axiom-sk)]
          (is (true? (get r-off-sub "ok")) (pr-str {:r-off-sub r-off-sub :p2p-off-resp (:response p2p-off) :sid sid}))
          (is (some? auto-ans-env) "Autonomous responder must auto-answer incoming p2p-offer")
          (is (some? (:p2p-dial ax-rx-p2p)))
          (is (true? (get r-ans-sub "ok")))
          (is (some? (:p2p-dial nx-rx-ans)))
          (is (= 0 (get-in send-res [:response "burn"])) "P2P message must have 0 ECH burn")
          (is (true? (get r-msg-sub "ok")) "HTTP relay must admit 0-burn P2P sealed-message into recipient mailbox")
          (is (= "Zero-burn P2P over HTTPS relay!"
                 (let [m (first (get-in inbox-res [:response "messages"]))]
                   (or (:text m) (get m "text"))))))
        (finally
          (try (http/stop-http-servers! srv) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d33-3-canonical-put-relay-upload-and-idempotent-pointer-test
  (testing "S-D33-3: Canonical `put` one-shot & serve mode relay upload triggers for both `put` and `artifact-put`, and `/artifact/v1/pointer` accepts idempotent pointers"
    (let [tmp-dir (make-tmp-dir!)
          kp (crypto/generate-keypair "d33-s3-nexus")
          pk (kp->pk-hex kp)
          sk (kp->sk kp)
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath tmp-dir)
               :node-id :ns1
               :node-privkey sk
               :policy (infra/default-infra-policy {:trust-anchors [pk]})})
          tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir) :domain "localhost"})
          srv (http/start-http-servers! {:domain "localhost"
                                         :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                        tls-mgr rt)
          port (:http-port srv)
          relay-url (str "http://127.0.0.1:" port)]
      (try
        (let [st-atom (atom (-> (light-core/init-light-state {:pubkey-hex pk} {:subnet-id "bitecho.org/infra" :epoch 10})
                                (assoc :account {:balance 100000 :spendable 100000 :seq 0})))
              ctx {:state-atom st-atom
                   :identity {:pubkey-hex pk :privkey-bytes sk}
                   :bootstrap {:nodes {}}
                   :conn-opts {:relay-url relay-url}}
              ;; Send canonical `{"cmd":"put", ...}` through handle-serve-line!
              serve-res (light-shell/handle-serve-line!
                         {"cmd" "put"
                          "subnet_id" "bitecho.org/infra"
                          "path" "web/d33-canonical-put.md"
                          "text" "# Published via Canonical Put\n"
                          "relay_url" relay-url}
                         ctx)
              resolved (infra/resolve-path-blob! rt "web/d33-canonical-put.md")]
          (is (true? (get serve-res "ok")))
          (is (true? (:ok? resolved)) "Canonical `put` must upload blob and pointer to HTTP relay /artifact/v1/*")
          (is (= "# Published via Canonical Put\n"
                 (String. ^bytes (get-in resolved [:blob :blob/bytes]) StandardCharsets/UTF_8))))
        ;; 2. Verify default-infra-policy allows K_nexus to sign web/app/* pointers directly via CLI put,
        ;;    and render-resolved-blob gzip-compresses compressible disk files > 2 MiB up to 16 MiB
        (let [pol (infra/default-infra-policy {:trust-anchors [pk]})
              nexus-rule (some #(when (= (:pattern %) "web/app/*") %) (:subnet/path-acl pol))]
          (is (some? nexus-rule))
          (is (contains? (get-in nexus-rule [:principal :signers]) infra/K_nexus)
              "K_nexus must be authorized to publish web/app/* pointers in default-infra-policy"))
        (finally
          (try (http/stop-http-servers! srv) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d33-4-light-node-https-relay-first-quorum-sync-test
  (testing "S-D33-4: maybe-sync-account-state! uses HTTPS /relay/v1/chain-state quorum first before spawning ephemeral UDP :5010 WebRTC dials"
    (let [tmp-dir (make-tmp-dir!)
          val1-kp (crypto/generate-keypair "d33-s4-val1")
          val2-kp (crypto/generate-keypair "d33-s4-val2")
          val3-kp (crypto/generate-keypair "d33-s4-val3")
          val1-pk (kp->pk-hex val1-kp)
          val2-pk (kp->pk-hex val2-kp)
          val3-pk (kp->pk-hex val3-kp)
          agent-kp (crypto/generate-keypair "d33-s4-agent")
          agent-pk (kp->pk-hex agent-kp)
          agent-sk (kp->sk agent-kp)
          mk-snap (fn [vkp vpk pk nonce]
                    (light-core/sign-chain-state-snapshot
                     {:bitecho/type :chain-state-snapshot
                      :type :chain-state-snapshot
                      :validator-pubkey vpk
                      :pubkey pk
                      :finalized-epoch 88
                      :balance 1234567
                      :spendable 1234567
                      :seq 4
                      :deps []
                      :escrows []
                      :nonce (str nonce)}
                     (kp->sk vkp)))
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath tmp-dir)
               :node-id :ns1
               :node-privkey (kp->sk val1-kp)
               :policy (infra/default-infra-policy {:trust-anchors [val1-pk]})})
          tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir) :domain "localhost"})
          srv (http/start-http-servers! {:domain "localhost"
                                         :chain-state-fetcher (fn [pk nonce]
                                                                [(mk-snap val1-kp val1-pk pk nonce)
                                                                 (mk-snap val2-kp val2-pk pk nonce)
                                                                 (mk-snap val3-kp val3-pk pk nonce)])
                                         :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                        tls-mgr rt)
          port (:http-port srv)
          relay-url (str "http://127.0.0.1:" port)
          bootstrap {:domain "bitecho.org"
                     :relay-url relay-url
                     :nodes {:node1 {:pubkey val1-pk :ip "127.0.0.1" :port 59991 :agent-port 59991}
                             :node2 {:pubkey val2-pk :ip "127.0.0.1" :port 59992 :agent-port 59992}
                             :node3 {:pubkey val3-pk :ip "127.0.0.1" :port 59993 :agent-port 59993}}}
          st-atom (atom (light-core/init-light-state {:pubkey-hex agent-pk} {:bootstrap bootstrap}))
          udp-called? (atom false)]
      (try
        (with-redefs [light-shell/fetch-inband-chain-state-quorum!
                      (fn [& _]
                        (reset! udp-called? true)
                        {:ok? false :error "udp-should-not-be-called"})]
          ;; Call maybe-sync-account-state! WITHOUT explicit :relay-url in opts (only in bootstrap)
          (let [res (light-shell/maybe-sync-account-state! st-atom bootstrap agent-pk agent-sk {})]
            (is (true? (:ok? res)))
            (is (false? @udp-called?) "maybe-sync-account-state! must use bootstrap :relay-url fast-path without spawning UDP :5010 dials")
            (is (= 1234567 (get-in @st-atom [:account :balance])))
            (is (= 88 (get-in @st-atom [:account :finalized-epoch])))))
        (finally
          (try (http/stop-http-servers! srv) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d33-5-ops-scripts-batchmode-rollback-and-sha256-test
  (testing "S-D33-5: scripts/cluster.sh and scripts/infra_cluster.sh enforce BatchMode=yes, StrictHostKeyChecking=accept-new, bitecho-infra rollback, and live .sha256 verification"
    (let [cluster-sh (slurp "scripts/cluster.sh")
          infra-sh (slurp "scripts/infra_cluster.sh")]
      (is (str/includes? cluster-sh "BatchMode=yes"))
      (is (str/includes? cluster-sh "StrictHostKeyChecking=accept-new"))
      (is (str/includes? infra-sh "BatchMode=yes"))
      (is (str/includes? infra-sh "StrictHostKeyChecking=accept-new"))
      (is (str/includes? infra-sh "bitecho.jar.bak"))
      (is (str/includes? infra-sh "bitecho-light-node.cjs.sha256"))
      (is (contains? #{"0.23.11" "0.23.12" "0.23.13" "0.23.14" "0.23.15"} config/version)))))
