(ns bitecho.fractal-federation-test
  "Cross-platform test suite for Fractal Composition & Federation (Milestone 12):
   - Step 12A: Subnet identity, isolation, zero-burn team topologies, and multi-subnet multiplexing.
   - Step 12B: Domain-anchored discovery, authority-signed bootstrap descriptors, and federated rendezvous.
   - Rule 4: Single-authority lifecycle state over shared connection pools.
   - Rule 5: Zero silent failures on unroutable or mismatched subnets."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser-shell]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [clojure.string :as str]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            #?(:clj [clojure.test.check.properties :refer [for-all]]
               :cljs [clojure.test.check.properties :refer-macros [for-all]])))

;; -----------------------------------------------------------------------------
;; Step 12A Tests: Subnets & Multi-Subnet Multiplexer
;; -----------------------------------------------------------------------------

(def gen-subnet-id
  "Generator for valid distinct subnet IDs."
  (gen/such-that #(and (not= % "*") (not= % "global") (not (str/blank? %)))
                 (gen/fmap #(str "subnet-" %) (gen/not-empty gen/string-alphanumeric))))

(defspec ^{:doc "Generative property test verifying strict isolation between multiplexed subnets and unroutable drop semantics (Rule 5)."}
  prop-multi-subnet-multiplexer-isolation 50
  (for-all [[sub-a sub-b] (gen/such-that (fn [[a b]] (not= a b))
                                         (gen/tuple gen-subnet-id gen-subnet-id))
            _payload-text (gen/not-empty gen/string-ascii)]
           (let [kp-a (crypto/generate-keypair)
                 kp-b (crypto/generate-keypair)
                 pub-a (basalt/bytes->hex (:public kp-a))
                 pub-b (basalt/bytes->hex (:public kp-b))
                 node-a (light-core/init-light-state {:pubkey-hex pub-a} {:subnet-id sub-a})
                 node-b (light-core/init-light-state {:pubkey-hex pub-b} {:subnet-id sub-b})
                 mux (-> (light-core/init-multi-subnet-multiplexer {})
                         (light-core/register-subnet-instance sub-a node-a)
                         (light-core/register-subnet-instance sub-b node-b))
          ;; 1. Inbound envelope targeting sub-a routes to sub-a and does NOT affect sub-b
                 env-a {:protocol-version 1
                        :wire-format "fressian-v1"
                        :subnet-id sub-a
                        :event {:type :tick :epoch 1}}
                 routed-a (light-core/route-multiplexed-envelope mux env-a (:private kp-a))
                 st-a (get-in (:mux routed-a) [:subnets sub-a])
                 st-b (get-in (:mux routed-a) [:subnets sub-b])

          ;; 2. Inbound envelope targeting unknown subnet drops fail-closed (Rule 5)
                 unknown-sub (str "unregistered-" sub-a "-999")
                 env-unknown {:protocol-version 1
                              :wire-format "fressian-v1"
                              :subnet-id unknown-sub
                              :event {:type :tick}}
                 unroutable-res (light-core/route-multiplexed-envelope (:mux routed-a) env-unknown (:private kp-a))

          ;; 3. Dispatch command to sub-b tags outbound envelopes with sub-b
                 cmd-res (light-core/dispatch-multiplexed-command
                          (:mux unroutable-res)
                          sub-b
                          {"cmd" "offer" "peer" pub-a "price" 10 "burn" 500}
                          (:private kp-b))
                 out-envs (:net-envelopes cmd-res)]
             (and (= 1 (:epoch st-a))
                  (= 0 (:epoch st-b))
                  (= 1 (get-in unroutable-res [:mux :diagnostics :unroutable-dropped]))
                  (= 1 (count (:stdout-events unroutable-res)))
                  (= "unroutable-subnet-dropped" (get (first (:stdout-events unroutable-res)) "event"))
                  (if (seq out-envs)
                    (every? #(= sub-b (:subnet-id %)) out-envs)
                    true)))))

(deftest test-per-instance-economy-and-zero-burn-team-subnet
  (testing "Zero-burn team subnet processes offers and messaging without ECH balance or fees"
    (let [res (light-core/run-zero-burn-team-subnet-demo)]
      (is (= true (:ok? res)))
      (is (= true (:verified? res)))
      (is (= "team-subnet-engineering" (:subnet-id res)))
      (is (= false (:economy-enabled? res)))
      (is (= 0 (:alice-burned res)))
      (is (= 0 (:bob-burned res)))
      (is (= 1 (:messages-received res)))
      (is (= "Deploying v2.4 to staging..." (get-in res [:last-message :text]))))))

(deftest test-rendezvous-subnet-advertisement-signing-and-verification
  (testing "Subnet rendezvous advertisement signs and verifies deterministically"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          ad (light-core/build-subnet-advertisement pub (:private kp)
                                                    {:subnet-id "ai-compute-subnet"
                                                     :topic "subnet/ai-compute-subnet"
                                                     :economy-enabled? false
                                                     :burn-floor 0
                                                     :crypto-suites ["suite-v1-aes256gcm"]})
          parsed (light-core/parse-subnet-advertisement ad)]
      (is (= true (:ok? parsed)))
      (is (= "ai-compute-subnet" (get-in parsed [:advertisement :subnet-id])))
      (is (= false (get-in parsed [:advertisement :economy-enabled?])))
      (is (= 0 (get-in parsed [:advertisement :burn-floor])))
      (is (string? (get-in parsed [:advertisement :signature]))))

    (testing "Tampered subnet advertisement fails verification"
      (let [kp (crypto/generate-keypair)
            pub (basalt/bytes->hex (:public kp))
            ad (light-core/build-subnet-advertisement pub (:private kp)
                                                      {:subnet-id "sub-valid"
                                                       :topic "subnet/sub-valid"})
            tampered (assoc ad :burn-floor 99999)
            parsed (light-core/parse-subnet-advertisement tampered)]
        (is (= false (:ok? parsed)))
        (is (= "invalid-signature" (:error parsed)))))))

;; -----------------------------------------------------------------------------
;; Step 12B Tests: Domain-Anchored Discovery & Federation
;; -----------------------------------------------------------------------------

(def gen-domain
  "Generator for valid test domain names."
  (gen/fmap #(str % ".bitecho.local") (gen/not-empty gen/string-alphanumeric)))

(defspec ^{:doc "Generative property test verifying authority-signed bootstrap descriptors and tamper rejection."}
  prop-signed-bootstrap-descriptor-verification 50
  (for-all [domain gen-domain
            issued (gen/choose 10 100)
            ttl (gen/choose 10 50)]
           (let [kp (crypto/generate-keypair)
                 pub (basalt/bytes->hex (:public kp))
                 expires (+ issued ttl)
                 desc {:domain domain
                       :authority-pubkey pub
                       :issued-epoch issued
                       :expires-epoch expires
                       :nodes [{:node-id "val-1"
                                :ip "10.0.0.1"
                                :port 9000
                                :agent-port 9001
                                :pubkey pub
                                :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                                :ice-ufrag "ufrag"
                                :ice-pwd "pwd"}]}
                 signed (light-core/sign-bootstrap-descriptor (:private kp) desc)
                 txt-rendered (light-core/format-bootstrap-txt-pure signed)
                 edn-rendered (pr-str signed)
          ;; 1. Valid before expiration (map, EDN string, and bootstrap.txt string)
                 v-valid (light-core/verify-bootstrap-descriptor pub signed (+ issued 1))
                 fed-valid (light-core/verify-federated-domain-bootstrap domain signed (+ issued 1) pub)
                 fed-edn-valid (light-core/verify-federated-domain-bootstrap domain edn-rendered (+ issued 1) pub)
                 fed-txt-valid (light-core/verify-federated-domain-bootstrap domain txt-rendered (+ issued 1) pub)

          ;; 2. Invalid after expiration
                 v-expired (light-core/verify-bootstrap-descriptor pub signed (+ expires 1))

          ;; 3. Tampered payload fails verification
                 tampered (assoc signed :domain "malicious.domain.com")
                 v-tampered (light-core/verify-bootstrap-descriptor pub tampered (+ issued 1))]
             (and (= true (:ok? v-valid))
                  (= true (:valid? v-valid))
                  (= true (:ok? fed-valid))
                  (= true (:valid? fed-valid))
                  (= true (:ok? fed-edn-valid))
                  (= true (:ok? fed-txt-valid))
                  (= false (:valid? v-expired))
                  (= "descriptor-expired" (:error v-expired))
                  (= false (:valid? v-tampered))))))

(deftest test-two-domain-federation-demo
  (testing "Two-domain federation simulation with cross-domain verification and relay"
    (let [res (light-core/run-two-domain-federation-demo)]
      (is (= true (:ok? res)))
      (is (= true (:verified? res)))
      (is (= "alpha.bitecho.local" (:domain-a res)))
      (is (= "beta.bitecho.local" (:domain-b res)))
      (is (= true (:domain-a-verified? res)))
      (is (= true (:domain-b-verified? res)))
      (is (= true (:advertisement-verified? res)))
      (is (= true (:inter-subnet-routed? res)))
      (is (= 1 (:unroutable-dropped res))))))

(deftest test-subnet-retagging-prevention-and-mismatch-diagnostics
  (testing "Retagged zero-burn offer envelope (team-alpha rewritten to global) drops fail-closed"
    (let [kp-alice (crypto/generate-keypair)
          kp-bob (crypto/generate-keypair)
          pub-alice (basalt/bytes->hex (:public kp-alice))
          pub-bob (basalt/bytes->hex (:public kp-bob))
          alice-st (light-core/init-light-state {:pubkey-hex pub-alice}
                                                {:subnet-id "team-alpha"
                                                 :economy-enabled? false
                                                 :burn-floor 0})
          offer-res (light-core/handle-command alice-st
                                               {"cmd" "offer" "callee" pub-bob "price" 0 "burn" 0}
                                               (:private kp-alice))
          orig-env (first (:net-envelopes offer-res))
          _ (is (some? orig-env))
          _ (is (= "team-alpha" (:subnet-id orig-env)))
          tampered-outer-env (assoc orig-env :subnet-id "global")
          bob-global-st (light-core/init-light-state {:pubkey-hex pub-bob}
                                                     {:subnet-id "global"
                                                      :economy-enabled? true
                                                      :burn-floor 100})
          receive-res (light-core/handle-wire-payload bob-global-st tampered-outer-env (:private kp-bob))
          new-bob-st (:state receive-res)
          _ (is (empty? (:pending-offers new-bob-st)))
          _ (is (>= (long (or (:subnet-mismatch-dropped new-bob-st) 0)) 1))
          mux (-> (light-core/init-multi-subnet-multiplexer {})
                  (light-core/register-subnet-instance "global" bob-global-st))
          mux-res (light-core/route-multiplexed-envelope mux tampered-outer-env (:private kp-bob))
          mux-bob-st (get-in (:mux mux-res) [:subnets "global"])]
      (is (empty? (:pending-offers mux-bob-st)))
      (is (>= (long (or (get-in mux-res [:mux :diagnostics :subnet-mismatch-dropped]) 0)) 1)))))

(deftest test-bootstrap-verification-fail-closed
  (testing "verify-bootstrap-descriptor fails closed on nil, blank, or mismatched authority pubkey"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          other-kp (crypto/generate-keypair)
          other-pub (basalt/bytes->hex (:public other-kp))
          desc {:domain "test.bitecho.local"
                :authority-pubkey pub
                :issued-epoch 10
                :expires-epoch 100
                :nodes [{:node-id "val-1" :ip "10.0.0.1" :port 9000 :agent-port 9001 :pubkey pub
                         :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                         :ice-ufrag "ufrag" :ice-pwd "pwd"}]}
          signed (light-core/sign-bootstrap-descriptor (:private kp) desc)]
      (is (= :missing-expected-authority-pubkey (:error (light-core/verify-bootstrap-descriptor nil signed 20))))
      (is (= :missing-expected-authority-pubkey (:error (light-core/verify-bootstrap-descriptor "" signed 20))))
      (is (= :missing-expected-authority-pubkey (:error (light-core/verify-federated-domain-bootstrap "test.bitecho.local" signed 20))))
      (is (= :missing-expected-authority-pubkey (:error (light-core/verify-federated-domain-bootstrap "test.bitecho.local" signed 20 nil))))
      (is (= :authority-pubkey-mismatch (:error (light-core/verify-bootstrap-descriptor other-pub signed 20))))
      (is (= :authority-pubkey-mismatch (:error (light-core/verify-federated-domain-bootstrap "test.bitecho.local" signed 20 other-pub)))))))

;; -----------------------------------------------------------------------------
;; Milestone 16 (Phase 4 M4): P2P ICE Handshake, Hub Relay, & 3-Way Broadcast
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Generative property test verifying in-session p2p-offer/p2p-answer negotiation, automatic 0-ECH burn 1:1 P2P routing, and opaque Nexus hub relay."}
  prop-p2p-offer-answer-and-zero-burn-1to1-routing 30
  (for-all [msg-text (gen/such-that #(not (str/blank? %)) (gen/not-empty gen/string-ascii))
            mdns-uuid (gen/not-empty gen/string-alphanumeric)]
           (let [kp-browser (crypto/generate-keypair)
                 kp-nexus (crypto/generate-keypair)
                 kp-axiom (crypto/generate-keypair)
                 pub-browser (basalt/bytes->hex (:public kp-browser))
                 pub-nexus (basalt/bytes->hex (:public kp-nexus))
                 pub-axiom (basalt/bytes->hex (:public kp-axiom))
                 browser-0 (light-core/init-light-state {:pubkey-hex pub-browser} {:epoch 10})
                 nexus-0 (light-core/init-light-state {:pubkey-hex pub-nexus} {:epoch 10})
                 axiom-0 (light-core/init-light-state {:pubkey-hex pub-axiom} {:epoch 10})
                 ;; 1. Establish Browser <-> Axiom E2E sealed session
                 off-res (light-core/handle-command browser-0
                                                    {"cmd" "offer" "callee" pub-axiom "price" 10 "burn" 500}
                                                    (:private kp-browser))
                 sid (get-in off-res [:response "session_id"])
                 axiom-1 (reduce (fn [st env]
                                   (:state (light-core/handle-wire-payload st env (:private kp-axiom))))
                                 axiom-0
                                 (:net-envelopes off-res))
                 acc-res (light-core/handle-command axiom-1
                                                    {"cmd" "accept" "session_id" sid}
                                                    (:private kp-axiom))
                 browser-1 (reduce (fn [st env]
                                     (:state (light-core/handle-wire-payload st env (:private kp-browser))))
                                   (:state off-res)
                                   (:net-envelopes acc-res))
                 burned-before-p2p (get-in browser-1 [:local-accounting :burned-ech] 0)
                 ;; 2. Negotiate p2p-offer -> p2p-answer with mDNS & HTTP CONNECT candidates
                 mdns-cand (str (str/lower-case mdns-uuid) ".local:54321")
                 p2p-off (light-core/handle-command browser-1
                                                    {"cmd" "p2p-offer"
                                                     "session_id" sid
                                                     "transport" "mdns"
                                                     "candidates" [mdns-cand]
                                                     "ice_ufrag" "ufragB"
                                                     "ice_pwd" "pwdBrowser12345678901234"}
                                                    (:private kp-browser))
                 axiom-2-res (reduce (fn [acc env]
                                       (let [r (light-core/handle-wire-payload (:state acc) env (:private kp-axiom))]
                                         {:state (:state r)
                                          :stdout-events (into (:stdout-events acc) (:stdout-events r))}))
                                     {:state (:state acc-res) :stdout-events []}
                                     (:net-envelopes p2p-off))
                 p2p-ans (light-core/handle-command (:state axiom-2-res)
                                                    {"cmd" "p2p-answer"
                                                     "session_id" sid
                                                     "transport" "connect"
                                                     "candidates" ["nexus.ingress.bitecho.org:443"]
                                                     "ice_ufrag" "ufragA"
                                                     "ice_pwd" "pwdAxiom1234567890123456"}
                                                    (:private kp-axiom))
                 browser-2-res (reduce (fn [acc env]
                                         (let [r (light-core/handle-wire-payload (:state acc) env (:private kp-browser))]
                                           {:state (:state r)
                                            :stdout-events (into (:stdout-events acc) (:stdout-events r))}))
                                       {:state (:state p2p-off) :stdout-events []}
                                       (:net-envelopes p2p-ans))
                 ;; Direct P2P transport connection completes -> p2p-channel-state connected: true
                 browser-2-conn (light-core/handle-command (:state browser-2-res)
                                                           {"cmd" "p2p-channel-state" "session_id" sid "connected" true}
                                                           (:private kp-browser))
                 axiom-2-conn (light-core/handle-command (:state p2p-ans)
                                                         {"cmd" "p2p-channel-state" "session_id" sid "connected" true}
                                                         (:private kp-axiom))
                 browser-2 (:state browser-2-conn)
                 axiom-2 (:state axiom-2-conn)
                 ;; 3. Send 1:1 message over P2P at 0 ECH burn, routed via Nexus opaque hub relay
                 send-res (light-core/handle-command browser-2
                                                     {"cmd" "send" "session_id" sid "text" msg-text}
                                                     (:private kp-browser))
                 burned-after-p2p (get-in (:state send-res) [:local-accounting :burned-ech] 0)
                 relay-env (light-core/build-p2p-hub-relay-envelope
                            pub-browser
                            (:private kp-browser)
                            {:target-pubkey pub-axiom
                             :session-id sid
                             :sealed-envelope (first (:net-envelopes send-res))})
                 nexus-relay-res (light-core/handle-wire-payload nexus-0 relay-env (:private kp-nexus))
                 axiom-final (reduce (fn [st env]
                                       (:state (light-core/handle-wire-payload st env (:private kp-axiom))))
                                     axiom-2
                                     (:net-envelopes nexus-relay-res))]
             (and (= :connecting (get-in (:state p2p-ans) [:sessions sid :p2p :phase]))
                  (false? (get-in (:state p2p-ans) [:sessions sid :p2p :connected?]))
                  (some? (:p2p-dial p2p-ans))
                  (some #(= "p2p-answer-received" (get % "event")) (:stdout-events browser-2-res))
                  (true? (get-in browser-2 [:sessions sid :p2p :connected?]))
                  (true? (get-in axiom-2 [:sessions sid :p2p :connected?]))
                  (some #(= "p2p-connected" (get % "event")) (:stdout-events browser-2-conn))
                  (= 0 (get-in send-res [:response "burn"]))
                  (true? (get-in send-res [:response "p2p"]))
                  (= burned-before-p2p burned-after-p2p)
                  (= 1 (get-in (:state nexus-relay-res) [:diagnostics :p2p-relayed]))
                  (empty? (:sessions (:state nexus-relay-res)))
                  (= 1 (count (:inbox axiom-final)))
                  (= msg-text (:text (first (:inbox axiom-final))))))))

(defspec ^{:doc "Generative property test verifying 3-way zero-burn broadcast deduplication by (sender-pubkey, sender-seq, msg-id) and DAC admission in chat/simon-nexus-axiom."}
  prop-three-way-broadcast-dedup-and-dac-gate 30
  (for-all [msg-1 (gen/such-that #(not (str/blank? %)) (gen/not-empty gen/string-ascii))
            msg-2 (gen/such-that #(not (str/blank? %)) (gen/not-empty gen/string-ascii))]
           (let [kp-anchor (crypto/generate-keypair)
                 pub-anchor (basalt/bytes->hex (:public kp-anchor))
                 kp-simon (crypto/generate-keypair)
                 kp-nexus (crypto/generate-keypair)
                 kp-axiom (crypto/generate-keypair)
                 kp-intruder (crypto/generate-keypair)
                 pub-simon (basalt/bytes->hex (:public kp-simon))
                 pub-nexus (basalt/bytes->hex (:public kp-nexus))
                 pub-axiom (basalt/bytes->hex (:public kp-axiom))
                 pub-intruder (basalt/bytes->hex (:public kp-intruder))
                 subnet-id light-core/simon-nexus-axiom-subnet-id
                 dac-simon (light-core/create-dac (:private kp-anchor)
                                                  {:anchor-pubkey pub-anchor
                                                   :agent-pubkey pub-simon
                                                   :issued-epoch 0
                                                   :expires-epoch 1000
                                                   :max-spend-per-epoch 0
                                                   :scopes ["broadcast" "gossip" "offer"]})
                 simon-0 (-> (light-core/init-light-state {:pubkey-hex pub-simon}
                                                          {:subnet-id subnet-id
                                                           :economy-enabled? false
                                                           :burn-floor 0
                                                           :epoch 10
                                                           :trusted-dac-anchors #{pub-anchor}})
                             (assoc :dac dac-simon))
                 nexus-0 (light-core/init-light-state {:pubkey-hex pub-nexus}
                                                      {:subnet-id subnet-id
                                                       :economy-enabled? false
                                                       :burn-floor 0
                                                       :epoch 10
                                                       :trusted-dac-anchors #{pub-anchor}})
                 axiom-0 (light-core/init-light-state {:pubkey-hex pub-axiom}
                                                      {:subnet-id subnet-id
                                                       :economy-enabled? false
                                                       :burn-floor 0
                                                       :epoch 10
                                                       :trusted-dac-anchors #{pub-anchor}})
                 intruder-0 (light-core/init-light-state {:pubkey-hex pub-intruder}
                                                         {:subnet-id subnet-id
                                                          :economy-enabled? false
                                                          :burn-floor 0
                                                          :epoch 10
                                                          :trusted-dac-anchors #{pub-anchor}})
                 ;; 1. Simon broadcasts msg-1 and msg-2
                 b1 (light-core/handle-command simon-0
                                               {"cmd" "broadcast" "text" msg-1 "subnet_id" subnet-id}
                                               (:private kp-simon))
                 b2 (light-core/handle-command (:state b1)
                                               {"cmd" "broadcast" "text" msg-2 "subnet_id" subnet-id}
                                               (:private kp-simon))
                 env-1 (first (:net-envelopes b1))
                 env-2 (first (:net-envelopes b2))
                 ;; 2. Deliver env-1 twice + env-2 to Nexus and Axiom
                 nexus-r1 (light-core/handle-wire-payload nexus-0 env-1 (:private kp-nexus))
                 nexus-r1-dup (light-core/handle-wire-payload (:state nexus-r1) env-1 (:private kp-nexus))
                 nexus-r2 (light-core/handle-wire-payload (:state nexus-r1-dup) env-2 (:private kp-nexus))
                 axiom-r1 (light-core/handle-wire-payload axiom-0 env-1 (:private kp-axiom))
                 axiom-r2 (light-core/handle-wire-payload (:state axiom-r1) env-2 (:private kp-axiom))
                 ;; 3. Intruder without valid DAC attempts broadcast on DAC-gated subnet
                 b-bad (light-core/handle-command intruder-0
                                                  {"cmd" "broadcast" "text" "spoof" "subnet_id" subnet-id}
                                                  (:private kp-intruder))
                 nexus-r-bad (light-core/handle-wire-payload (:state nexus-r2)
                                                             (first (:net-envelopes b-bad))
                                                             (:private kp-nexus))]
             (and (= 1 (get-in b1 [:response "seq"]))
                  (= 2 (get-in b2 [:response "seq"]))
                  (= 0 (get-in b1 [:response "burn"]))
                  (= 0 (get-in (:state b2) [:local-accounting :burned-ech] 0))
                  (= 2 (count (:broadcast-inbox (:state nexus-r2))))
                  (= 2 (count (:broadcast-inbox (:state axiom-r2))))
                  (= 1 (get-in (:state nexus-r1-dup) [:diagnostics :broadcast-duplicates-dropped]))
                  (= [msg-1 msg-2] (mapv :text (:broadcast-inbox (:state nexus-r2))))
                  (= [msg-1 msg-2] (mapv :text (:broadcast-inbox (:state axiom-r2))))
                  (= "broadcast-received" (get (first (:stdout-events nexus-r1)) "event"))
                  (= 1 (get-in (:state nexus-r-bad) [:diagnostics :broadcast-rejected]))
                  (= 2 (count (:broadcast-inbox (:state nexus-r-bad))))))))

(deftest test-three-way-p2p-broadcast-demo
  (testing "Milestone 16 3-way zero-burn P2P & broadcast demo (Browser <-> Nexus <-> Axiom)"
    (let [res (light-core/run-three-way-p2p-broadcast-demo)]
      (is (true? (:ok? res)))
      (is (true? (:verified? res)))
      (is (= "chat/simon-nexus-axiom" (:subnet-id res)))
      (is (= 0 (:total-ech-burned res)))
      (is (= 3 (:broadcast-count res)))
      (is (= 1 (:duplicates-dropped res))))))

(deftest test-p2p-transient-liveness-rule-4
  (testing "Rule 4: Derived runtime :p2p liveness is never persisted and cleared on close/prune"
    (let [kp-a (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          kp-b (crypto/generate-keypair)
          pub-b (basalt/bytes->hex (:public kp-b))
          node-0 (light-core/init-light-state {:pubkey-hex pub-a} {:epoch 10})
          sid "test-sess-rule4"
          node-with-p2p (assoc-in node-0 [:sessions sid]
                                  {:session-id sid
                                   :peer pub-b
                                   :state "open"
                                   :role :initiator
                                   :p2p {:phase :open
                                         :connected? true
                                         :zero-burn? true
                                         :local-transport "udp"
                                         :remote-transport "udp"}})]
      ;; 1. strip-sensitive-keys strips :p2p from all sessions
      (let [stripped (light-core/strip-sensitive-keys node-with-p2p)]
        (is (nil? (get-in stripped [:sessions sid :p2p]))
            "strip-sensitive-keys must strip :p2p map from sessions"))
      ;; 2. exec-close removes :p2p from closed session
      (let [closed-res (light-core/handle-command node-with-p2p
                                                  {"cmd" "close" "session_id" sid}
                                                  (:private kp-a))]
        (is (= "closed" (get-in (:state closed-res) [:sessions sid :state])))
        (is (nil? (get-in (:state closed-res) [:sessions sid :p2p]))
            "exec-close must dissoc :p2p from closed session"))
      ;; 3. browser prune-ghost-sessions strips :p2p
      (let [pruned (browser-shell/prune-ghost-sessions (:sessions node-with-p2p))]
        (is (nil? (get-in pruned [sid :p2p]))
            "browser prune-ghost-sessions must strip :p2p from active sessions")))))

(deftest test-p2p-signaling-replay-protection-and-epoch-skew
  (testing "Monotonic signal-seq anti-replay, epoch skew, and invalid signature rejection (Rule 5)"
    (let [kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          node-a-0 (light-core/init-light-state {:pubkey-hex pub-a} {:epoch 10})
          node-b-0 (light-core/init-light-state {:pubkey-hex pub-b} {:epoch 10})
          ;; Setup open session between A and B
          off-res (light-core/handle-command node-a-0
                                             {"cmd" "offer" "callee" pub-b "price" 10 "burn" 500}
                                             (:private kp-a))
          sid (get-in off-res [:response "session_id"])
          node-b-1 (reduce (fn [st env]
                             (:state (light-core/handle-wire-payload st env (:private kp-b))))
                           node-b-0
                           (:net-envelopes off-res))
          acc-res (light-core/handle-command node-b-1
                                             {"cmd" "accept" "session_id" sid}
                                             (:private kp-b))
          node-b-open (:state acc-res)
          node-a-1 (reduce (fn [st env]
                             (:state (light-core/handle-wire-payload st env (:private kp-a))))
                           (:state off-res)
                           (:net-envelopes acc-res))
          ;; Node A sends p2p-offer (signal-seq = 1)
          p2p-off (light-core/handle-command node-a-1
                                             {"cmd" "p2p-offer" "session_id" sid "transport" "udp" "candidates" ["udp://127.0.0.1:9001"]}
                                             (:private kp-a))
          env-off (first (:net-envelopes p2p-off))
          ;; 1. First offer with signal-seq 1 succeeds
          b-recv-1 (light-core/handle-wire-payload node-b-open env-off (:private kp-b))]
      (is (= :offer-received (get-in (:state b-recv-1) [:sessions sid :p2p :phase])))
      (is (= 1 (get-in (:state b-recv-1) [:sessions sid :p2p :remote-offer-seq])))
      (is (= 0 (get-in (:state b-recv-1) [:diagnostics :p2p-signaling-rejected] 0)))

        ;; 2. Replay of same p2p-offer (signal-seq <= 1) is rejected
      (let [b-replay (light-core/handle-wire-payload (:state b-recv-1) env-off (:private kp-b))]
        (is (= 1 (get-in (:state b-replay) [:diagnostics :p2p-signaling-rejected]))
            "Replay of p2p-offer must increment :p2p-signaling-rejected")
        (is (some #(= "p2p-signaling-rejected" (get % "event")) (:stdout-events b-replay))))

        ;; 3. Tampered signature on p2p-offer is rejected
      (let [tampered-payload (assoc (light-core/thaw-payload (:payload env-off)) :signature "302a00")
            tampered-env (assoc env-off :payload (light-core/freeze-payload tampered-payload))
            b-bad-sig (light-core/handle-wire-payload (:state b-recv-1) tampered-env (:private kp-b))]
        (is (= 1 (get-in (:state b-bad-sig) [:diagnostics :p2p-signaling-rejected])))
        (is (some #(= "p2p-signaling-rejected" (get % "event")) (:stdout-events b-bad-sig))))

        ;; 4. Epoch skew > 2 on p2p-offer is dropped with :p2p-signaling-rejected
      (let [skewed-payload (assoc (light-core/thaw-payload (:payload env-off)) :epoch 100)
            skewed-env (assoc env-off :payload (light-core/freeze-payload skewed-payload))
            b-skew (light-core/handle-wire-payload (:state b-recv-1) skewed-env (:private kp-b))]
        (is (= 1 (get-in (:state b-skew) [:diagnostics :p2p-signaling-rejected]))
            "Epoch skew > 2 must increment :p2p-signaling-rejected")
        (is (some #(= "p2p-signaling-rejected" (get % "event")) (:stdout-events b-skew)))))))

(deftest test-hub-broadcast-automatic-fan-out
  (testing "Automatic Hub broadcast fan-out (Browser -> Nexus -> Axiom) increments :p2p-relayed"
    (let [kp-browser (crypto/generate-keypair)
          kp-nexus (crypto/generate-keypair)
          kp-axiom (crypto/generate-keypair)
          pub-browser (basalt/bytes->hex (:public kp-browser))
          pub-nexus (basalt/bytes->hex (:public kp-nexus))
          pub-axiom (basalt/bytes->hex (:public kp-axiom))
          subnet-id "chat/simon-nexus-axiom"
          sid-bn "sess-browser-nexus"
          sid-an "sess-axiom-nexus"
          nexus-0 (-> (light-core/init-light-state {:pubkey-hex pub-nexus}
                                                   {:subnet-id subnet-id :epoch 10})
                      (assoc-in [:sessions sid-bn]
                                {:session-id sid-bn
                                 :peer pub-browser
                                 :state "open"
                                 :p2p {:phase :open :connected? true :zero-burn? true}})
                      (assoc-in [:sessions sid-an]
                                {:session-id sid-an
                                 :peer pub-axiom
                                 :state "open"
                                 :p2p {:phase :open :connected? true :zero-burn? true}}))
          browser-0 (-> (light-core/init-light-state {:pubkey-hex pub-browser}
                                                     {:subnet-id subnet-id :epoch 10})
                        (assoc-in [:sessions sid-bn]
                                  {:session-id sid-bn
                                   :peer pub-nexus
                                   :state "open"
                                   :p2p {:phase :open :connected? true :zero-burn? true}}))
          axiom-0 (-> (light-core/init-light-state {:pubkey-hex pub-axiom}
                                                   {:subnet-id subnet-id :epoch 10})
                      (assoc-in [:sessions sid-an]
                                {:session-id sid-an
                                 :peer pub-nexus
                                 :state "open"
                                 :p2p {:phase :open :connected? true :zero-burn? true}}))
          ;; Browser broadcasts a message
          b-res (light-core/handle-command browser-0
                                           {"cmd" "broadcast" "text" "fan-out-hello" "subnet_id" subnet-id}
                                           (:private kp-browser))
          b-env (first (:net-envelopes b-res))
          ;; Nexus receives Browser's broadcast over wire
          nexus-res (light-core/handle-wire-payload nexus-0 b-env (:private kp-nexus))]
      ;; Nexus should record the broadcast, increment :p2p-relayed, and emit fan-out envelope to Axiom
      (is (= 1 (count (:broadcast-inbox (:state nexus-res)))))
      (is (= 1 (get-in (:state nexus-res) [:diagnostics :p2p-relayed]))
          "Nexus must increment :p2p-relayed upon fanning out broadcast")
      (is (= 1 (count (:net-envelopes nexus-res)))
          "Nexus must fan out exactly 1 envelope to Axiom (excluding sender Browser)")
      (let [relay-env (first (:net-envelopes nexus-res))]
        (is (true? (:p2p-direct? relay-env)))
        (is (= pub-axiom (:p2p-peer relay-env)))
        (is (= sid-an (:p2p-session-id relay-env)))
        ;; Deliver fan-out envelope to Axiom
        (let [axiom-res (light-core/handle-wire-payload axiom-0 relay-env (:private kp-axiom))]
          (is (= 1 (count (:broadcast-inbox (:state axiom-res)))))
          (is (= "fan-out-hello" (:text (first (:broadcast-inbox (:state axiom-res))))))
          (is (= pub-browser (:from (first (:broadcast-inbox (:state axiom-res)))))))))))

(deftest test-p2p-offer-answer-signaling-burn
  (testing "exec-p2p-offer and exec-p2p-answer apply :min-signaling-burn floor when closed, and 0 burn when direct P2P is open"
    (let [kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          sid "sess-signaling-burn-test"
          base-a (-> (light-core/init-light-state {:pubkey-hex pub-a} {:subnet-id "test/burn" :epoch 10})
                     (assoc :default-p2p-candidates ["udp://127.0.0.1:7777"])
                     (assoc-in [:sessions sid]
                               {:session-id sid
                                :peer pub-b
                                :state "open"
                                :p2p {:phase :none :connected? false}}))
          ;; 1. Omitted candidates falls back to :default-p2p-candidates, burn defaults to 100
          off-res-1 (light-core/handle-command base-a {"cmd" "p2p-offer" "session_id" sid} (:private kp-a))]
      (is (= true (get-in off-res-1 [:response "ok"])))
      (is (= 100 (get-in off-res-1 [:response "burn"])))
      (is (= ["udp://127.0.0.1:7777"] (get-in off-res-1 [:response "candidates"])))
      (let [env-1 (first (:net-envelopes off-res-1))]
        (is (nil? (:p2p-direct? env-1)))
        (is (= 100 (get-in env-1 [:event :message :burn-amount]))))

      ;; 2. When p2p-open? is true, burn is 0 and :p2p-direct? is true
      (let [open-a (assoc-in base-a [:sessions sid :p2p :connected?] true)
            off-res-2 (light-core/handle-command open-a {"cmd" "p2p-offer" "session_id" sid} (:private kp-a))]
        (is (= true (get-in off-res-2 [:response "ok"])))
        (is (= 0 (get-in off-res-2 [:response "burn"])))
        (let [env-2 (first (:net-envelopes off-res-2))]
          (is (true? (:p2p-direct? env-2)))
          (is (= 0 (get-in env-2 [:event :message :burn-amount])))))

      ;; 3. Custom burn parameter
      (let [off-res-3 (light-core/handle-command base-a {"cmd" "p2p-offer" "session_id" sid "burn" 250} (:private kp-a))]
        (is (= true (get-in off-res-3 [:response "ok"])))
        (is (= 250 (get-in off-res-3 [:response "burn"])))
        (is (= 250 (get-in (first (:net-envelopes off-res-3)) [:event :message :burn-amount]))))

      ;; 4. Negative burn rejected
      (let [off-res-4 (light-core/handle-command base-a {"cmd" "p2p-offer" "session_id" sid "burn" -50} (:private kp-a))]
        (is (= false (get-in off-res-4 [:response "ok"])))
        (is (= "invalid-numeric-parameter" (get-in off-res-4 [:response "error"]))))

      ;; 5. p2p-answer behaves identically
      (let [ans-res-1 (light-core/handle-command base-a {"cmd" "p2p-answer" "session_id" sid} (:private kp-a))]
        (is (= true (get-in ans-res-1 [:response "ok"])))
        (is (= 100 (get-in ans-res-1 [:response "burn"])))
        (is (= ["udp://127.0.0.1:7777"] (get-in ans-res-1 [:response "candidates"])))
        (is (= 100 (get-in (first (:net-envelopes ans-res-1)) [:event :message :burn-amount])))))))

(deftest test-state-machine-min-signaling-burn-floor
  (testing "state_machine/handle-receive-gossip respects custom :min-signaling-burn and :burn-floor in state config, and allows 0-burn when economy-enabled? is false"
    (let [kp1 (crypto/generate-keypair)
          kp2 (crypto/generate-keypair)
          pub1 (basalt/bytes->hex (:public kp1))
          pub2 (basalt/bytes->hex (:public kp2))
          cfg-min-burn (assoc config/default-config
                              :economy-enabled? true
                              :min-signaling-burn 200
                              :genesis-ledger {pub1 {:balance 100000 :seq 0 :deps []}
                                               pub2 {:balance 100000 :seq 0 :deps []}})
          s0 (sm/init-state [] pub1 (assoc cfg-min-burn :keypair kp1))
          ;; Gossip with burn 150 (< 200) should be dropped
          msg-low (sieve/wrap-message (fressian/utf8->bytes "low burn") (:private kp2) (:public kp2) 150)
          res-low (sm/handle-event s0 {:type :receive-gossip :sender pub2 :message msg-low})
          ;; Gossip with burn 200 (>= 200) should be accepted
          msg-ok (sieve/wrap-message (fressian/utf8->bytes "ok burn") (:private kp2) (:public kp2) 200)
          res-ok (sm/handle-event s0 {:type :receive-gossip :sender pub2 :message msg-ok})]
      (is (empty? (get-in (:state res-low) [:murmur-cache :set])))
      (is (contains? (get-in (:state res-ok) [:murmur-cache :set])
                     (basalt/bytes->hex (crypto/sha256 (:payload msg-ok)))))

      ;; Test :burn-floor 200 on default-config (without :min-signaling-burn)
      (let [cfg-burn-floor (assoc config/default-config
                                  :economy-enabled? true
                                  :burn-floor 200
                                  :genesis-ledger {pub1 {:balance 100000 :seq 0 :deps []}
                                                   pub2 {:balance 100000 :seq 0 :deps []}})
            s-bf (sm/init-state [] pub1 (assoc cfg-burn-floor :keypair kp1))
            res-bf-low (sm/handle-event s-bf {:type :receive-gossip :sender pub2 :message msg-low})
            res-bf-ok (sm/handle-event s-bf {:type :receive-gossip :sender pub2 :message msg-ok})]
        (is (empty? (get-in (:state res-bf-low) [:murmur-cache :set]))
            ":burn-floor 200 must reject burn 150 on default-config")
        (is (contains? (get-in (:state res-bf-ok) [:murmur-cache :set])
                       (basalt/bytes->hex (crypto/sha256 (:payload msg-ok))))
            ":burn-floor 200 must accept burn 200 on default-config"))

      ;; Test :economy-enabled? false allows 0-burn
      (let [cfg-no-econ (assoc config/default-config
                               :economy-enabled? false
                               :genesis-ledger {})
            s-no-econ (sm/init-state [] pub1 (assoc cfg-no-econ :keypair kp1))
            msg-zero (sieve/wrap-message (fressian/utf8->bytes "zero burn") (:private kp2) (:public kp2) 0)
            res-zero (sm/handle-event s-no-econ {:type :receive-gossip :sender pub2 :message msg-zero})]
        (is (contains? (get-in (:state res-zero) [:murmur-cache :set])
                       (basalt/bytes->hex (crypto/sha256 (:payload msg-zero))))
            ":economy-enabled? false must accept 0-burn gossip without deduction")))))
