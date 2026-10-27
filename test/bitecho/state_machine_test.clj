(ns bitecho.state-machine-test
  "Tests for the pure state machine integrating Basalt, Murmur, Sieve, and Contagion."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.state-machine :as sm]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest ^{:doc "Tests that init-state returns a correctly shaped state map."} init-state-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "A"}
                       {:ip "127.0.0.1" :port 8001 :pubkey (byte-array 32) :hash "B"}]
        state (sm/init-state initial-peers "node-pubkey-stub")]
    (is (vector? (:basalt-view state)))
    (is (= 20 (count (:basalt-view state))))
    (is (map? (:murmur-cache state)))
    (is (set? (:set (:murmur-cache state))))
    (is (= clojure.lang.PersistentQueue/EMPTY (:queue (:murmur-cache state))))
    (is (set? (:contagion-known-ids state)))
    (is (set? (:global-echo-sample state)))
    (is (set? (:global-ready-sample state)))
    (is (set? (:global-delivery-sample state)))
    (is (set? (:echo-subscribers state)))
    (is (set? (:ready-subscribers state)))
    (is (set? (:delivery-subscribers state)))
    (is (map? (:echo-vote-counts state)))
    (is (map? (:ready-vote-counts state)))
    (is (map? (:delivery-vote-counts state)))
    (is (map? (:epoch-to-messages state)))
    (is (not (contains? state :echo-samples)))
    (is (not (contains? state :ready-samples)))
    (is (not (contains? state :delivery-samples)))
    (is (map? (:config state)) "State should contain the protocol config map")))

(deftest unknown-sender-rejected-test
  (testing "Transfer from unknown sender with zero genesis balance is rejected and leaves ledger unchanged"
    (let [state (sm/init-state [] "node-pubkey-1")
          initial-ledger (:ledger state)
          kp (crypto/generate-keypair)
          unknown-sender (basalt/bytes->hex (:public kp))
          unsigned-tx {:sender unknown-sender
                       :receiver "node-pubkey-1"
                       :amount 100
                       :seq 1
                       :deps []}
          tx (account/create-transfer (:private kp) unsigned-tx)
          payload (.getBytes (pr-str {:id "msg-1" :transfer tx}) "UTF-8")
          event {:type :on-deliver :payload payload :message-id "msg-1"}
          result (sm/handle-event state event)]
      (is (= initial-ledger (:ledger (:state result))))
      (is (nil? (get-in result [:state :ledger unknown-sender]))))))

(deftest genesis-ledger-transfer-success-test
  (testing "Transfer from account seeded via (:genesis-ledger cfg) succeeds"
    (let [kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public kp))
          genesis-ledger {sender-pub (account/map->AccountState {:balance 500 :seq 0 :deps []})}
          cfg (merge config/default-config {:genesis-ledger genesis-ledger})
          state (sm/init-state [] "node-pubkey-1" cfg)
          unsigned-tx {:sender sender-pub
                       :receiver "node-pubkey-1"
                       :amount 200
                       :seq 1
                       :deps []}
          tx (account/create-transfer (:private kp) unsigned-tx)
          payload (.getBytes (pr-str {:id "msg-2" :transfer tx}) "UTF-8")
          event {:type :on-deliver :payload payload :message-id "msg-2"}
          result (sm/handle-event state event)
          updated-ledger (:ledger (:state result))]
      (testing "Sender balance is decremented and seq is updated"
        (is (= 300 (:balance (get updated-ledger sender-pub))))
        (is (= 1 (:seq (get updated-ledger sender-pub)))))
      (testing "Receiver balance is incremented"
        (is (= 1200 (:balance (get updated-ledger "node-pubkey-1"))))))))

(defspec ^{:doc "Property: Transfers from unseeded accounts cannot create money or alter ledger, while transfers from genesis-seeded accounts conserve total supply."}
  prop-no-unauthorized-money-creation 100
  (prop/for-all [genesis-bal (gen/choose 100 5000)
                 transfer-amt (gen/choose 1 100)
                 attempt-unauthorized? gen/boolean]
                (let [node-pub "local-node-pubkey"
                      genesis-kp (crypto/generate-keypair)
                      genesis-pub (basalt/bytes->hex (:public genesis-kp))
                      cfg (merge config/default-config {:genesis-ledger {genesis-pub (account/map->AccountState {:balance genesis-bal :seq 0 :deps []})}})
                      state (sm/init-state [] node-pub cfg)
                      initial-ledger (:ledger state)
                      initial-total-supply (reduce + (map :balance (vals initial-ledger)))]
                  (if attempt-unauthorized?
        ;; Unauthorized transfer from unknown, unseeded key
                    (let [unauth-kp (crypto/generate-keypair)
                          unauth-pub (basalt/bytes->hex (:public unauth-kp))
                          unsigned-tx {:sender unauth-pub
                                       :receiver node-pub
                                       :amount transfer-amt
                                       :seq 1
                                       :deps []}
                          tx (account/create-transfer (:private unauth-kp) unsigned-tx)
                          payload (.getBytes (pr-str {:id "unauth" :transfer tx}) "UTF-8")
                          result (sm/handle-event state {:type :on-deliver :payload payload :message-id "unauth"})
                          final-ledger (:ledger (:state result))]
          ;; Invariant: ledger is completely unchanged
                      (and (= initial-ledger final-ledger)
                           (= initial-total-supply (reduce + (map :balance (vals final-ledger))))
                           (nil? (get final-ledger unauth-pub))))
        ;; Authorized transfer from genesis-seeded key
                    (let [unsigned-tx {:sender genesis-pub
                                       :receiver node-pub
                                       :amount transfer-amt
                                       :seq 1
                                       :deps []}
                          tx (account/create-transfer (:private genesis-kp) unsigned-tx)
                          payload (.getBytes (pr-str {:id "auth" :transfer tx}) "UTF-8")
                          result (sm/handle-event state {:type :on-deliver :payload payload :message-id "auth"})
                          final-ledger (:ledger (:state result))
                          final-total-supply (reduce + (map :balance (vals final-ledger)))]
          ;; Invariant: total supply conserved, sender decremented, receiver incremented
                      (and (= initial-total-supply final-total-supply)
                           (= (- genesis-bal transfer-amt) (:balance (get final-ledger genesis-pub)))
                           (= (+ 1000 transfer-amt) (:balance (get final-ledger node-pub)))))))))

(deftest init-state-epoch-entropy-test
  (testing "init-state initializes default :epoch-entropy to genesis and seeds basalt-view deterministically"
    (let [state (sm/init-state [] "my-node-pubkey")
          expected-seed-0 (basalt/derive-slot-seed "genesis" "my-node-pubkey" 0)]
      (is (= "genesis" (:epoch-entropy state)))
      (is (= expected-seed-0 (:seed (first (:basalt-view state)))))))

  (testing "init-state uses custom :epoch-entropy from cfg if provided"
    (let [cfg (assoc config/default-config :epoch-entropy "custom-entropy-123")
          state (sm/init-state [] "my-node-pubkey" cfg)
          expected-seed-0 (basalt/derive-slot-seed "custom-entropy-123" "my-node-pubkey" 0)]
      (is (= "custom-entropy-123" (:epoch-entropy state)))
      (is (= expected-seed-0 (:seed (first (:basalt-view state))))))))

(deftest handle-tick-deterministic-slot-reset-test
  (testing "handle-tick threads epoch-entropy into basalt/reset-slots deterministically"
    (let [state (sm/init-state [] "my-node-pubkey")
          idx (:basalt-index state)
          expected-seed (basalt/derive-slot-seed "genesis" "my-node-pubkey" idx)
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)
          new-view (:basalt-view new-state)]
      (is (= "genesis" (:epoch-entropy new-state)))
      (is (= expected-seed (:seed (nth new-view idx))))))

  (testing "handle-tick updates epoch-entropy when new finalized block is present"
    (let [state (assoc (sm/init-state [] "my-node-pubkey")
                       :finalized-blocks ["block-final-hash-99"])
          idx (:basalt-index state)
          expected-seed (basalt/derive-slot-seed "block-final-hash-99" "my-node-pubkey" idx)
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)
          new-view (:basalt-view new-state)]
      (is (= "block-final-hash-99" (:epoch-entropy new-state)))
      (is (= expected-seed (:seed (nth new-view idx)))))))

(defspec ^{:doc "Property: State machine basalt slot seeds are deterministic across differing RNG instances."}
  prop-state-machine-deterministic-entropy 50
  (prop/for-all [node-pub (gen/not-empty gen/string-alphanumeric)
                 entropy (gen/not-empty gen/string-alphanumeric)]
                (let [cfg (assoc config/default-config :epoch-entropy entropy)
                      state (sm/init-state [] node-pub cfg)
                      res1 (sm/handle-event state {:type :tick :rng (java.util.Random. 1111)})
                      res2 (sm/handle-event state {:type :tick :rng (java.util.Random. 9999)})
                      view1 (:basalt-view (:state res1))
                      view2 (:basalt-view (:state res2))
                      seeds1 (mapv :seed view1)
                      seeds2 (mapv :seed view2)]
                  ;; The slot seeds must be 100% identical regardless of different RNG seeds!
                  (= seeds1 seeds2))))
