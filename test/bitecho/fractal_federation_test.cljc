(ns bitecho.fractal-federation-test
  "Cross-platform test suite for Fractal Composition & Federation (Milestone 12):
   - Step 12A: Subnet identity, isolation, zero-burn team topologies, and multi-subnet multiplexing.
   - Step 12B: Domain-anchored discovery, authority-signed bootstrap descriptors, and federated rendezvous.
   - Rule 4: Single-authority lifecycle state over shared connection pools.
   - Rule 5: Zero silent failures on unroutable or mismatched subnets."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.light-node.core :as light-core]
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
