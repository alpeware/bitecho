(ns bitecho.state-machine-portability-test
  "Cross-runtime portability tests verifying that Bitecho's pure state machine
   initializes, transitions, and preserves invariants identically on both JVM and Node/CLJS."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- make-peer [i]
  (let [kp (crypto/generate-keypair)
        pub-hex (basalt/bytes->hex (:public kp))]
    {:ip (str "127.0.0." i)
     :port (+ 8000 i)
     :pubkey (:public kp)
     :hash (str "hash-" i)
     :node-id pub-hex}))

(deftest state-machine-init-portability-test
  (testing "State machine initializes identically across runtimes"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          peers [(make-peer 1) (make-peer 2) (make-peer 3)]
          cfg (assoc config/default-config
                     :genesis-ledger {pub-hex {:balance 1000 :seq 0 :deps []}}
                     :epoch-entropy "genesis-entropy-test")
          state (sm/init-state peers pub-hex cfg)]
      (is (some? state))
      (is (= pub-hex (:node-pubkey state)))
      (is (= 0 (:epoch state)))
      (is (= "genesis-entropy-test" (:epoch-entropy state)))
      (is (= 1000 (:balance (get-in state [:ledger pub-hex]))))
      (is (record? (get-in state [:ledger pub-hex])))
      (is (vector? (:basalt-view state)))
      (is (map? (:murmur-cache state)))
      (is (set? (:contagion-known-ids state))))))

(deftest state-machine-tick-portability-test
  (testing "handle-tick executes deterministic transitions and command generation"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          state (sm/init-state [] pub-hex config/default-config)
          res (sm/handle-event state {:type :tick})]
      (is (map? res))
      (is (contains? res :state))
      (is (contains? res :commands))
      (is (vector? (:commands res)))
      (is (= 1 (:epoch (:state res)))))))

(deftest state-machine-transfer-event-portability-test
  (testing "Pure state machine validates and applies canonical transfers"
    (let [alice-kp (crypto/generate-keypair)
          bob-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          bob-pub (basalt/bytes->hex (:public bob-kp))
          alice-priv (:private alice-kp)
          cfg (assoc config/default-config
                     :genesis-ledger {alice-pub {:balance 500 :seq 0 :deps []}
                                      bob-pub   {:balance 100 :seq 0 :deps []}})
          state (sm/init-state [] alice-pub cfg)
          unsigned-tx {:sender alice-pub
                       :receiver bob-pub
                       :amount 150
                       :seq 1
                       :deps []}
          tx (account/create-transfer alice-priv unsigned-tx)
          expected-hash (account/transfer-hash tx)
          transfer-event {:type :on-deliver
                          :sender alice-pub
                          :payload (fressian/encode-canonical {:transfer (into {} tx)})}
          res (sm/handle-event state transfer-event)
          new-state (:state res)]
      (is (some? new-state))
      (is (= 350 (:balance (get-in new-state [:ledger alice-pub]))))
      (is (= 250 (:balance (get-in new-state [:ledger bob-pub]))))
      (is (= 1 (:seq (get-in new-state [:ledger alice-pub]))))
      (is (= [expected-hash] (:deps (get-in new-state [:ledger alice-pub])))))))

(defspec ^{:doc "Property: State machine balance conservation under arbitrary sequence of valid transfers"}
  prop-state-machine-transfer-balance-conservation 50
  (prop/for-all [amount-1 (gen/choose 1 100)
                 amount-2 (gen/choose 1 100)]
                (let [alice-kp (crypto/generate-keypair)
                      bob-kp (crypto/generate-keypair)
                      alice-pub (basalt/bytes->hex (:public alice-kp))
                      bob-pub (basalt/bytes->hex (:public bob-kp))
                      alice-priv (:private alice-kp)
                      initial-alice 500
                      initial-bob 200
                      total-initial (+ initial-alice initial-bob)
                      cfg (assoc config/default-config
                                 :genesis-ledger {alice-pub {:balance initial-alice :seq 0 :deps []}
                                                  bob-pub   {:balance initial-bob :seq 0 :deps []}})
                      state0 (sm/init-state [] alice-pub cfg)
                      ;; Transfer 1: Alice -> Bob
                      tx1 (account/create-transfer alice-priv {:sender alice-pub :receiver bob-pub :amount amount-1 :seq 1 :deps []})
                      p1 (fressian/encode-canonical {:transfer (into {} tx1)})
                      res1 (sm/handle-event state0 {:type :on-deliver :sender alice-pub :payload p1})
                      state1 (:state res1)
                      ;; Transfer 2: Alice -> Bob
                      tx2 (account/create-transfer alice-priv {:sender alice-pub :receiver bob-pub :amount amount-2 :seq 2 :deps [(account/transfer-hash tx1)]})
                      p2 (fressian/encode-canonical {:transfer (into {} tx2)})
                      res2 (sm/handle-event state1 {:type :on-deliver :sender alice-pub :payload p2})
                      state2 (:state res2)
                      final-alice (:balance (get-in state2 [:ledger alice-pub]))
                      final-bob   (:balance (get-in state2 [:ledger bob-pub]))]
                  (and (= total-initial (+ final-alice final-bob))
                       (= (- initial-alice amount-1 amount-2) final-alice)
                       (= (+ initial-bob amount-1 amount-2) final-bob)
                       (= 2 (:seq (get-in state2 [:ledger alice-pub])))
                       (= 0 (:seq (get-in state2 [:ledger bob-pub])))))))

(deftest shell-boundary-crypto-portability-test
  (testing "Decision A(i): shell-boundary pre-verify-envelope, sign-and-emit, and seal-and-emit work across JVM and CLJS"
    (let [boundary (crypto/make-crypto-boundary)
          kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          priv (:private kp)
          ;; 1. Deferred signing from light-node.core (no private key inside reducer)
          deferred-env (light-core/build-chain-state-query-envelope pub-hex :defer-crypto {:epoch 7 :nonce "n-7"})
          _ (is (= :sign-and-emit (get-in deferred-env [:crypto-effect :effect])))
          _ (is (nil? (:signature deferred-env)))
          ;; Fulfill :sign-and-emit at the shell boundary
          signed-env (crypto/sign-and-emit boundary (assoc deferred-env :private-key priv))
          _ (is (string? (:signature signed-env)))
          _ (is (nil? (:crypto-effect signed-env)))
          ;; 2. Pre-verify at the shell boundary before passing to pure reducer
          verified-env (crypto/pre-verify-envelope boundary signed-env)
          _ (is (true? (:crypto/verified? verified-env)))
          ;; 3. Sieve message pre-verification + validation
          sieve-msg (sieve/wrap-message (fressian/utf8->bytes "hello-boundary") priv (:public kp) 100)
          pre-verified-sieve (crypto/pre-verify-envelope boundary sieve-msg)
          _ (is (true? (:crypto/verified? pre-verified-sieve)))
          _ (is (some? (sieve/validate-message pre-verified-sieve)))
          ;; 4. seal-and-emit boundary effect
          sealed-atom (atom nil)
          sealed-out (crypto/seal-and-emit boundary {:plaintext "secret-data"
                                                     :seal-fn #(str "sealed:" %)
                                                     :on-sealed #(reset! sealed-atom %)})]
      (is (= "sealed:secret-data" sealed-out))
      (is (= "sealed:secret-data" @sealed-atom)))))
