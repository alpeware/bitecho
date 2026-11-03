(ns bitecho.state-machine-test
  "Tests for the pure state machine integrating Basalt, Murmur, Sieve, and Contagion."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.treasury :as treasury]
            [bitecho.rendezvous.core :as rdv]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.set :as set]
            [clojure.string :as string]
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
    (is (= {} (:epoch-burns state)) "State should initialize :epoch-burns to empty map")
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

(deftest init-state-default-ledger-empty-test
  (testing "init-state with default config yields an empty ledger {}"
    (let [state (sm/init-state [] "node-pub-1")]
      (is (= {} (:ledger state))))))

(deftest init-state-genesis-ledger-authoritative-test
  (testing "init-state with a :genesis-ledger entry yields only that entry, not granting 1000 ECHO to node-pubkey"
    (let [kp (crypto/generate-keypair)
          genesis-pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/default-config :genesis-ledger {genesis-pub (account/map->AccountState {:balance 500 :seq 0 :deps []})})
          state (sm/init-state [] "node-pub-1" cfg)]
      (is (= {genesis-pub (account/map->AccountState {:balance 500 :seq 0 :deps []})}
             (:ledger state)))
      (is (nil? (get-in state [:ledger "node-pub-1"]))))))

(deftest un-funded-node-transfer-rejected-test
  (testing "A transfer from node-pubkey itself when absent from genesis-ledger is rejected and changes nothing"
    (let [node-kp (crypto/generate-keypair)
          node-pub (basalt/bytes->hex (:public node-kp))
          state (sm/init-state [] node-pub)
          receiver-kp (crypto/generate-keypair)
          receiver-pub (basalt/bytes->hex (:public receiver-kp))
          unsigned-tx {:sender node-pub
                       :receiver receiver-pub
                       :amount 100
                       :seq 1
                       :deps []}
          tx (account/create-transfer (:private node-kp) unsigned-tx)
          payload (.getBytes (pr-str {:id "msg-unfunded" :transfer tx}) "UTF-8")
          res (sm/handle-event state {:type :on-deliver :payload payload :message-id "msg-unfunded"})]
      (is (= (:ledger state) (:ledger (:state res))))
      (is (= {} (:ledger (:state res))))
      (is (nil? (get-in res [:state :ledger node-pub])))
      (is (nil? (get-in res [:state :ledger receiver-pub]))))))

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
        (is (= 200 (:balance (get updated-ledger "node-pubkey-1"))))))))

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
                           (= transfer-amt (:balance (get final-ledger node-pub)))))))))

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

(deftest handle-tick-deterministic-peer-selection-test
  (testing "handle-tick uses basalt/select-peers-deterministic for push targets and background sampling"
    (let [node-pub "node-pub-test"
          entropy "entropy-test-123"
          cfg (assoc config/default-config :epoch-entropy entropy)
          peers (mapv (fn [i] {:address (str "10.0.0." i)
                               :port (+ 8000 i)
                               :pubkey (str "peer-pubkey-" i)
                               :hash (str "peer-hash-" i)})
                      (range 1 15))
          state (sm/init-state peers node-pub cfg)
          res1 (sm/handle-event state {:type :tick :rng (java.util.Random. 12345)})
          res2 (sm/handle-event state {:type :tick :rng (java.util.Random. 67890)})
          s1 (:state res1)
          s2 (:state res2)
          push1 (first (filter #(= :send-push-view (:type %)) (:commands res1)))
          push2 (first (filter #(= :send-push-view (:type %)) (:commands res2)))]
      ;; Slot seeds are identical across differing RNGs
      (is (= (mapv :seed (:basalt-view s1))
             (mapv :seed (:basalt-view s2))))
      ;; Push targets are identical across differing RNGs
      (is (some? (:targets push1)))
      (is (= (:targets push1) (:targets push2)))
      ;; Global role samples are non-empty and identical across differing RNGs
      (is (seq (:global-echo-sample s1)))
      (is (= (:global-echo-sample s1) (:global-echo-sample s2)))
      (is (seq (:global-ready-sample s1)))
      (is (= (:global-ready-sample s1) (:global-ready-sample s2)))
      (is (seq (:global-delivery-sample s1)))
      (is (= (:global-delivery-sample s1) (:global-delivery-sample s2))))))

(defspec ^{:doc "Property: State machine basalt slot seeds, push targets, and background role samples are deterministic across differing RNG instances."}
  prop-state-machine-deterministic-entropy 50
  (prop/for-all [node-pub (gen/not-empty gen/string-alphanumeric)
                 entropy (gen/not-empty gen/string-alphanumeric)]
                (let [cfg (assoc config/default-config :epoch-entropy entropy)
                      peers (mapv (fn [i] {:address (str "10.0.0." i)
                                           :port (+ 8000 i)
                                           :pubkey (str "peer-pubkey-" i)
                                           :hash (str "peer-hash-" i)})
                                  (range 1 12))
                      state (sm/init-state peers node-pub cfg)
                      res1 (sm/handle-event state {:type :tick :rng (java.util.Random. 1111)})
                      res2 (sm/handle-event state {:type :tick :rng (java.util.Random. 9999)})
                      s1 (:state res1)
                      s2 (:state res2)
                      seeds1 (mapv :seed (:basalt-view s1))
                      seeds2 (mapv :seed (:basalt-view s2))
                      push-targets1 (:targets (first (filter #(= :send-push-view (:type %)) (:commands res1))))
                      push-targets2 (:targets (first (filter #(= :send-push-view (:type %)) (:commands res2))))]
                  (and (= seeds1 seeds2)
                       (= push-targets1 push-targets2)
                       (= (:global-echo-sample s1) (:global-echo-sample s2))
                       (= (:global-ready-sample s1) (:global-ready-sample s2))
                       (= (:global-delivery-sample s1) (:global-delivery-sample s2))))))

(deftest signaling-burn-state-machine-test
  (testing "Direct :signaling-burn event decrements sender ledger balance and increments [:epoch-burns current-epoch]"
    (let [sender "sender-pub-1"
          cfg (assoc config/default-config :genesis-ledger {sender (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          state (sm/init-state [] "node-pub-1" cfg)
          res (sm/handle-event state {:type :signaling-burn :sender sender :burn 250})
          new-state (:state res)]
      (is (= 750 (:balance (get-in new-state [:ledger sender]))))
      (is (= 250 (get-in new-state [:epoch-burns 0])))
      (is (empty? (:commands res)))
      (is (nil? (get-in new-state [:ledger "node-pub-1"]))
          "No receiver account was credited with the burned amount")))

  (testing "Direct :signaling-burn with default burn amount when not specified"
    (let [sender "sender-pub-2"
          cfg (assoc config/default-config :genesis-ledger {sender (account/map->AccountState {:balance 500 :seq 0 :deps []})})
          state (sm/init-state [] "node-pub-1" cfg)
          res (sm/handle-event state {:type :signaling-burn :sender sender})
          new-state (:state res)]
      (is (= 400 (:balance (get-in new-state [:ledger sender]))))
      (is (= burn/min-signaling-burn (get-in new-state [:epoch-burns 0])))))

  (testing "Direct :signaling-burn rejects when burn is below min-signaling-burn or sender has insufficient funds"
    (let [sender "sender-pub-3"
          cfg (assoc config/default-config :genesis-ledger {sender (account/map->AccountState {:balance 80 :seq 0 :deps []})})
          state (sm/init-state [] "node-pub-1" cfg)]
      (testing "Below minimum burn"
        (let [res (sm/handle-event state {:type :signaling-burn :sender sender :burn (dec burn/min-signaling-burn)})]
          (is (= state (:state res)))))
      (testing "Insufficient funds"
        (let [res (sm/handle-event state {:type :signaling-burn :sender sender :burn 100})]
          (is (= state (:state res)))))
      (testing "Unknown sender"
        (let [res (sm/handle-event state {:type :signaling-burn :sender "unknown-pub" :burn 100})]
          (is (= state (:state res))))))))

(deftest broadcast-signaling-burn-test
  (testing "Broadcast event with custom :burn deducts signaling burn from sender and increments [:epoch-burns epoch]"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          state (sm/init-state [peer] "node-pub-1" cfg)
          res (sm/handle-event state {:type :broadcast
                                      :sender sender-pub
                                      :payload (.getBytes "hello" "UTF-8")
                                      :rng (java.util.Random. 42)
                                      :burn 150})
          new-state (:state res)]
      (is (= 850 (:balance (get-in new-state [:ledger sender-pub]))))
      (is (= 150 (get-in new-state [:epoch-burns 0])))
      (is (seq (:commands res)))))

  (testing "Broadcast event with :signaling-burn true deducts min-signaling-burn"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          state (sm/init-state [peer] "node-pub-1" cfg)
          res (sm/handle-event state {:type :broadcast
                                      :sender sender-pub
                                      :payload (.getBytes "hello" "UTF-8")
                                      :rng (java.util.Random. 42)
                                      :signaling-burn true})
          new-state (:state res)]
      (is (= 900 (:balance (get-in new-state [:ledger sender-pub]))))
      (is (= 100 (get-in new-state [:epoch-burns 0])))
      (is (seq (:commands res)))))

  (testing "Broadcast event rejects when sender balance is insufficient for requested burn"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          sender-pub "poor-sender"
          cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 50 :seq 0 :deps []})})
          state (sm/init-state [peer] "node-pub-1" cfg)
          res (sm/handle-event state {:type :broadcast
                                      :sender sender-pub
                                      :payload (.getBytes "hello" "UTF-8")
                                      :rng (java.util.Random. 42)
                                      :burn 100})]
      (is (empty? (:commands res)) "Broadcast should not emit send commands when burn cannot be deducted")
      (is (= 50 (:balance (get-in (:state res) [:ledger sender-pub]))))
      (is (empty? (:epoch-burns (:state res))))))

  (testing "Broadcast event from un-funded node is dropped with ledger and epoch-burns untouched"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          state (sm/init-state [peer] "node-pub-1")
          res (sm/handle-event state {:type :broadcast
                                      :payload (.getBytes "hello" "UTF-8")
                                      :rng (java.util.Random. 42)})]
      (is (= state (:state res)))
      (is (empty? (:commands res)))))

  (testing "Broadcast event without explicit :burn from funded node automatically deducts min-signaling-burn (100)"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          state (sm/init-state [peer] "node-pub-1" cfg)
          res (sm/handle-event state {:type :broadcast
                                      :sender sender-pub
                                      :payload (.getBytes "hello" "UTF-8")
                                      :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 900 (:balance (get-in new-state [:ledger sender-pub]))))
      (is (= 100 (get-in new-state [:epoch-burns 0])))
      (is (seq (:commands res)))))

  (testing "Broadcast event with :burn false or < min-signaling-burn is dropped"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          state (sm/init-state [peer] "node-pub-1" cfg)
          res-false (sm/handle-event state {:type :broadcast
                                            :sender sender-pub
                                            :burn false
                                            :payload (.getBytes "hello" "UTF-8")
                                            :rng (java.util.Random. 42)})
          res-low (sm/handle-event state {:type :broadcast
                                          :sender sender-pub
                                          :burn 50
                                          :payload (.getBytes "hello" "UTF-8")
                                          :rng (java.util.Random. 42)})]
      (is (empty? (:commands res-false)))
      (is (= 1000 (:balance (get-in (:state res-false) [:ledger sender-pub]))))
      (is (empty? (:commands res-low)))
      (is (= 1000 (:balance (get-in (:state res-low) [:ledger sender-pub]))))))

  (testing "Outbound gossip message cryptographically binds :burn-amount when keys provided"
    (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
          kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public kp))
          sender-priv (:private kp)
          cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          state (assoc (sm/init-state [peer] "node-pub-1" cfg) :epoch 0)
          res (sm/handle-event state {:type :broadcast
                                      :sender sender-pub
                                      :private-key sender-priv
                                      :public-key (:public kp)
                                      :burn 150
                                      :payload (.getBytes "hello" "UTF-8")
                                      :rng (java.util.Random. 42)})
          cmd (first (:commands res))
          msg (:message cmd)]
      (is (= 150 (:burn-amount msg)))
      (is (some? (sieve/validate-message msg)))

      (testing "Inbound gossip rejects when :burn-amount is missing (nil or omitted)"
        (let [no-burn-msg (dissoc msg :burn-amount)
              inbound-res (sm/handle-event state {:type :receive-gossip :message no-burn-msg :rng (java.util.Random. 42)})]
          (is (= state (:state inbound-res)))
          (is (empty? (:commands inbound-res)))))

      (testing "Inbound gossip rejects when :burn-amount is < 100"
        (let [low-burn-msg (assoc msg :burn-amount 50)
              inbound-res (sm/handle-event state {:type :receive-gossip :message low-burn-msg :rng (java.util.Random. 42)})]
          (is (= state (:state inbound-res)))
          (is (empty? (:commands inbound-res)))))

      (testing "Inbound gossip rejects when :burn-amount was tampered with after signing"
        (let [tampered-msg (assoc msg :burn-amount 200)
              inbound-res (sm/handle-event state {:type :receive-gossip :message tampered-msg :rng (java.util.Random. 42)})]
          (is (= state (:state inbound-res)))
          (is (empty? (:commands inbound-res)))))

      (testing "Inbound gossip from known ledger account deducts :burn-amount and records in :epoch-burns"
        (let [inbound-res (sm/handle-event state {:type :receive-gossip :message msg :rng (java.util.Random. 42)})
              new-state (:state inbound-res)]
          (is (= 850 (:balance (get-in new-state [:ledger sender-pub]))))
          (is (= 150 (get-in new-state [:epoch-burns 0])))
          (is (contains? (:contagion-known-ids new-state) (:message-id msg)))
          (is (seq (:commands inbound-res)))))

      (testing "Inbound gossip from known ledger account with balance < :burn-amount is rejected"
        (let [poor-cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 50 :seq 0 :deps []})})
              poor-state (assoc (sm/init-state [peer] "node-pub-1" poor-cfg) :epoch 0)
              inbound-res (sm/handle-event poor-state {:type :receive-gossip :message msg :rng (java.util.Random. 42)})]
          (is (= poor-state (:state inbound-res)))
          (is (empty? (:commands inbound-res)))))

      (testing "Inbound gossip from unknown sender absent from :ledger is rejected"
        (let [unknown-kp (crypto/generate-keypair)
              unknown-pub (basalt/bytes->hex (:public unknown-kp))
              unknown-priv (:private unknown-kp)
              unknown-raw (sieve/wrap-message (.getBytes "hello unknown" "UTF-8")
                                              unknown-priv
                                              (:public unknown-kp)
                                              150)
              unknown-msg (assoc unknown-raw :message-id "msg-unknown-1")
              inbound-res (sm/handle-event state {:type :receive-gossip
                                                  :message unknown-msg
                                                  :rng (java.util.Random. 42)})]
          (is (= state (:state inbound-res)))
          (is (empty? (:commands inbound-res)))
          (is (nil? (get-in (:state inbound-res) [:ledger unknown-pub])))
          (is (nil? (get-in (:state inbound-res) [:epoch-burns 0])))
          (is (not (contains? (:contagion-known-ids (:state inbound-res)) "msg-unknown-1")))))

      (testing "Inbound gossip where sender is local node (node-pubkey) does not deduct again"
        (let [self-cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
              self-state (assoc (sm/init-state [peer] sender-pub self-cfg) :epoch 0)
              inbound-res (sm/handle-event self-state {:type :receive-gossip :message msg :rng (java.util.Random. 42)})
              new-state (:state inbound-res)]
          (is (= 1000 (:balance (get-in new-state [:ledger sender-pub]))))
          (is (nil? (get-in new-state [:epoch-burns 0])))
          (is (contains? (:contagion-known-ids new-state) (:message-id msg))))))))

(defspec ^{:doc "Property: Inbound gossip enforces burn deduction and conservation for funded senders, and drops underfunded, unseeded, or tampered gossip"}
  prop-inbound-gossip-burn-enforcement 50
  (prop/for-all [initial-balance (gen/choose 0 500)
                 burn-amt (gen/choose 100 300)
                 tamper-burn? gen/boolean
                 unseeded-sender? gen/boolean]
                (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
                      kp (crypto/generate-keypair)
                      sender-pub (basalt/bytes->hex (:public kp))
                      sender-priv (:private kp)
                      payload (.getBytes "prop-gossip-payload" "UTF-8")
                      raw-msg (sieve/wrap-message payload sender-priv (:public kp) burn-amt)
                      msg (assoc raw-msg :message-id "msg-prop-1")
                      final-msg (if tamper-burn? (assoc msg :burn-amount (+ burn-amt 50)) msg)
                      genesis-ledger (if unseeded-sender?
                                       {}
                                       {sender-pub (account/map->AccountState {:balance initial-balance :seq 0 :deps []})})
                      cfg (assoc config/default-config :genesis-ledger genesis-ledger)
                      state (assoc (sm/init-state [peer] "node-local" cfg) :epoch 0)
                      res (sm/handle-event state {:type :receive-gossip :message final-msg :rng (java.util.Random. 42)})
                      new-state (:state res)
                      sender-bal (or (:balance (get-in new-state [:ledger sender-pub])) 0)
                      epoch-burns (or (get-in new-state [:epoch-burns 0]) 0)]
                  (if (and (not unseeded-sender?) (not tamper-burn?) (>= initial-balance burn-amt))
                    (and (= (- initial-balance burn-amt) sender-bal)
                         (= burn-amt epoch-burns)
                         (contains? (:contagion-known-ids new-state) (basalt/bytes->hex (crypto/sha256 payload)))
                         (seq (:commands res)))
                    (and (= (if unseeded-sender? 0 initial-balance) sender-bal)
                         (zero? epoch-burns)
                         (= state new-state)
                         (empty? (:commands res))
                         (if unseeded-sender?
                           (nil? (get-in new-state [:ledger sender-pub]))
                           true))))))

(defspec ^{:doc "Property: Total initial supply equals final ledger supply plus total accumulated epoch burns."}
  prop-state-machine-burn-accounting 50
  (prop/for-all [initial-balance (gen/choose 500 5000)
                 burn-amount (gen/choose 100 500)]
                (let [sender "burning-node"
                      cfg (assoc config/default-config :genesis-ledger {sender (account/map->AccountState {:balance initial-balance :seq 0 :deps []})})
                      state (sm/init-state [] "local-node" cfg)
                      initial-ledger (:ledger state)
                      initial-total-supply (reduce + (map :balance (vals initial-ledger)))
                      res (sm/handle-event state {:type :signaling-burn :sender sender :burn burn-amount})
                      final-state (:state res)
                      final-ledger (:ledger final-state)
                      final-ledger-supply (reduce + (map :balance (vals final-ledger)))
                      total-burned (reduce + (vals (:epoch-burns final-state)))]
                  (and (= initial-total-supply (+ final-ledger-supply total-burned))
                       (= (- initial-balance burn-amount) (:balance (get final-ledger sender)))
                       (= burn-amount (get-in final-state [:epoch-burns 0]))))))

(defspec ^{:doc "Property: init-state ledger strictly mirrors genesis-ledger with no un-allocated balances"}
  prop-genesis-ledger-authoritative 50
  (prop/for-all [balances (gen/vector (gen/choose 10 1000) 1 5)
                 node-id (gen/elements ["node-alpha" "node-beta" "node-gamma"])]
                (let [entries (into {} (map-indexed (fn [i b]
                                                      [(str "genesis-pub-" i)
                                                       (account/map->AccountState {:balance b :seq 0 :deps []})])
                                                    balances))
                      cfg (assoc config/default-config :genesis-ledger entries)
                      state (sm/init-state [] node-id cfg)]
                  (and (= entries (:ledger state))
                       (if (contains? entries node-id)
                         (some? (get (:ledger state) node-id))
                         (nil? (get (:ledger state) node-id)))))))

(deftest test-state-machine-mint-and-custody
  (testing "init-state initializes :total-minted to 0 and :minted-epochs to #{}"
    (let [state (sm/init-state [] "my-node")]
      (is (= 0 (:total-minted state)))
      (is (= #{} (:minted-epochs state)))))

  (testing "State machine processes signed :epoch-mint event and credits receivers"
    (let [t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          allocs {"node1" 600 "node2" 400}
          sig (treasury/sign-epoch-mint t-priv 1 allocs)
          state (assoc (sm/init-state [] "my-node") :treasury-pubkey t-pub)
          event {:type :epoch-mint
                 :epoch 1
                 :epoch-gate 1000
                 :allocations allocs
                 :treasury-pubkey t-pub
                 :signature sig}
          res (sm/handle-event state event)
          new-state (:state res)]
      (is (= 1000 (:total-minted new-state)))
      (is (= #{1} (:minted-epochs new-state)))
      (is (= 600 (:balance (get-in new-state [:ledger "node1"]))))
      (is (= 400 (:balance (get-in new-state [:ledger "node2"]))))))

  (testing "State machine rejects unsigned or invalidly signed :epoch-mint event"
    (let [t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          allocs {"node1" 600 "node2" 400}
          state (assoc (sm/init-state [] "my-node") :treasury-pubkey t-pub)
          ;; Unsigned
          unsigned-event {:type :epoch-mint
                          :epoch 1
                          :epoch-gate 1000
                          :allocations allocs}
          res-unsigned (sm/handle-event state unsigned-event)
          ;; Tampered signature
          sig (treasury/sign-epoch-mint t-priv 1 allocs)
          tampered-sig (str "ff" (subs sig 2))
          tampered-event {:type :epoch-mint
                          :epoch 1
                          :epoch-gate 1000
                          :allocations allocs
                          :treasury-pubkey t-pub
                          :signature tampered-sig}
          res-tampered (sm/handle-event state tampered-event)]
      (is (= state (:state res-unsigned)))
      (is (= state (:state res-tampered)))))

  (testing "State machine rejects duplicate :epoch-mint event for same epoch"
    (let [t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          allocs {"node1" 500}
          sig (treasury/sign-epoch-mint t-priv 1 allocs)
          state (assoc (sm/init-state [] "my-node")
                       :treasury-pubkey t-pub
                       :total-minted 1000
                       :minted-epochs #{1})
          event {:type :epoch-mint
                 :epoch 1
                 :epoch-gate 1000
                 :allocations allocs
                 :treasury-pubkey t-pub
                 :signature sig}
          res (sm/handle-event state event)]
      (is (= state (:state res)))))

  (testing "State machine on-deliver ignores gossip mint payloads and never mints"
    (let [t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          allocs {"attacker-node" 1000000}
          sig (treasury/sign-epoch-mint t-priv 1 allocs)
          state (assoc (sm/init-state [] "my-node") :treasury-pubkey t-pub)
          ;; 1. Payload carrying {:type :epoch-mint ...}
          p1 (.getBytes (pr-str {:type :epoch-mint :epoch 1 :allocations allocs :treasury-pubkey t-pub :signature sig}) "UTF-8")
          res1 (sm/handle-event state {:type :on-deliver :payload p1 :message-id "gossip-mint-1"})
          ;; 2. Payload carrying {:mint {...}}
          p2 (.getBytes (pr-str {:mint {:epoch 1 :allocations allocs :treasury-pubkey t-pub :signature sig}}) "UTF-8")
          res2 (sm/handle-event state {:type :on-deliver :payload p2 :message-id "gossip-mint-2"})]
      (is (= state (:state res1)))
      (is (= 0 (:total-minted (:state res1))))
      (is (= #{} (:minted-epochs (:state res1))))
      (is (nil? (get-in (:state res1) [:ledger "attacker-node"])))
      (is (= state (:state res2)))
      (is (= 0 (:total-minted (:state res2))))
      (is (= #{} (:minted-epochs (:state res2))))
      (is (nil? (get-in (:state res2) [:ledger "attacker-node"])))))

  (testing "Custody drawdown via transfer debits custody balance and never increments :total-minted"
    (let [custody-kp (crypto/generate-keypair)
          custody-pub (basalt/bytes->hex (:public custody-kp))
          receiver-pub "partner-pub"
          genesis-ledger {custody-pub (account/map->AccountState {:balance 5000 :seq 0 :deps []})}
          cfg (assoc config/default-config :genesis-ledger genesis-ledger)
          state (sm/init-state [] "my-node" cfg)
          unsigned-tx {:sender custody-pub
                       :receiver receiver-pub
                       :amount 1500
                       :seq 1
                       :deps []}
          tx (account/create-transfer (:private custody-kp) unsigned-tx)
          payload (.getBytes (pr-str {:id "custody-tx" :transfer tx}) "UTF-8")
          res (sm/handle-event state {:type :on-deliver :payload payload :message-id "custody-tx"})
          new-state (:state res)]
      (is (= 3500 (:balance (get-in new-state [:ledger custody-pub]))))
      (is (= 1500 (:balance (get-in new-state [:ledger receiver-pub]))))
      (is (= 0 (:total-minted new-state)))
      (is (= #{} (:minted-epochs new-state))))))

(defspec ^{:doc "Property: Custody drawdowns never increment :total-minted while valid mints increment :total-minted by exact distributed sum"}
  prop-mint-and-custody-conservation 50
  (prop/for-all [custody-bal (gen/choose 1000 50000)
                 drawdown-amt (gen/choose 100 1000)
                 mint-amt (gen/choose 100 2000)]
                (let [custody-kp (crypto/generate-keypair)
                      custody-pub (basalt/bytes->hex (:public custody-kp))
                      t-kp (crypto/generate-keypair)
                      t-pub (basalt/bytes->hex (:public t-kp))
                      t-priv (:private t-kp)
                      receiver-pub "partner-node"
                      cfg (assoc config/default-config
                                 :treasury-pubkey t-pub
                                 :genesis-ledger {custody-pub (account/map->AccountState {:balance custody-bal :seq 0 :deps []})})
                      state (sm/init-state [] "my-node" cfg)
                      unsigned-tx {:sender custody-pub
                                   :receiver receiver-pub
                                   :amount drawdown-amt
                                   :seq 1
                                   :deps []}
                      tx (account/create-transfer (:private custody-kp) unsigned-tx)
                      payload (.getBytes (pr-str {:id "tx-drawdown" :transfer tx}) "UTF-8")
                      res-drawdown (sm/handle-event state {:type :on-deliver :payload payload :message-id "tx-drawdown"})
                      state-after-drawdown (:state res-drawdown)
                      allocs {"mesh-node" mint-amt}
                      sig (treasury/sign-epoch-mint t-priv 1 allocs)
                      mint-event {:type :epoch-mint
                                  :epoch 1
                                  :epoch-gate (* mint-amt 2)
                                  :allocations allocs
                                  :treasury-pubkey t-pub
                                  :signature sig}
                      res-mint (sm/handle-event state-after-drawdown mint-event)
                      final-state (:state res-mint)]
                  (and (= 0 (:total-minted state-after-drawdown))
                       (= (- custody-bal drawdown-amt) (:balance (get-in state-after-drawdown [:ledger custody-pub])))
                       (= mint-amt (:total-minted final-state))
                       (= mint-amt (:balance (get-in final-state [:ledger "mesh-node"])))
                       (contains? (:minted-epochs final-state) 1)))))

(deftest test-state-machine-tick-treasury-epoch
  (testing "init-state initializes :epoch-settlement-takes to {}"
    (let [state (sm/init-state [] "my-node")]
      (is (= {} (:epoch-settlement-takes state)))))

  (testing "init-state initializes :mint-dust to 0 and :epoch-mint-dust to {}"
    (let [state (sm/init-state [] "my-node")]
      (is (= 0 (:mint-dust state)))
      (is (= {} (:epoch-mint-dust state)))))

  (testing "default-config has :bootstrap-sunset-epoch 26280"
    (is (= 26280 (:bootstrap-sunset-epoch config/default-config))))

  (testing "handle-tick processes epoch boundary: calculates trailing revenue with zero-padding, mints 20/80 split"
    (let [val-pub "validator-node-1"
          mesh-pub "mesh-routing-node-1"
          t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          cfg (assoc config/default-config
                     :treasury-pubkey t-pub
                     :treasury-privkey t-priv
                     :treasury-trailing-epochs 168
                     :validators [val-pub]
                     :mesh-nodes {mesh-pub 1.0})
          state (assoc (sm/init-state [] "my-node" cfg)
                       :epoch 0
                       :epoch-burns {0 16800}
                       :epoch-settlement-takes {})
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 1 (:epoch new-state)))
      ;; Trailing revenue over 168 epochs with zero-padding is 16800 / 168 = 100.
      ;; Demand-gated mint M_t = 100 * 50% = 50.
      ;; Split: 20% Streamlet (10), 80% Mesh (40).
      (is (= 50 (:total-minted new-state)))
      (is (contains? (:minted-epochs new-state) 1))
      (is (= 10 (:balance (get-in new-state [:ledger val-pub]))))
      (is (= 40 (:balance (get-in new-state [:ledger mesh-pub]))))))

  (testing "handle-tick does not mint if treasury keys are missing from config"
    (let [val-pub "validator-node-1"
          mesh-pub "mesh-routing-node-1"
          cfg (assoc config/default-config
                     :treasury-trailing-epochs 168
                     :validators [val-pub]
                     :mesh-nodes {mesh-pub 1.0})
          state (assoc (sm/init-state [] "my-node" cfg)
                       :epoch 0
                       :epoch-burns {0 16800}
                       :epoch-settlement-takes {})
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 1 (:epoch new-state)))
      (is (= 0 (:total-minted new-state)))
      (is (= #{} (:minted-epochs new-state)))
      (is (nil? (get-in new-state [:ledger val-pub])))
      (is (nil? (get-in new-state [:ledger mesh-pub])))))

  (testing "handle-tick executes custody drawdowns from :ledger without increasing :total-minted"
    (let [custody-kp (crypto/generate-keypair)
          custody-pub (basalt/bytes->hex (:public custody-kp))
          custody-priv (:private custody-kp)
          cfg (assoc config/default-config
                     :genesis-ledger {custody-pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})}
                     :custody-pubkey custody-pub
                     :custody-privkey custody-priv
                     :custody-allocations [{:receiver "grantee-x" :amount 2500}])
          state (sm/init-state [] "my-node" cfg)
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 7500 (:balance (get-in new-state [:ledger custody-pub]))))
      (is (= 2500 (:balance (get-in new-state [:ledger "grantee-x"]))))
      (is (= 0 (:total-minted new-state)))))

  (testing "handle-tick executes bootstrap sunset burn when reaching bootstrap-sunset-epoch"
    (let [custody-pub "sunset-custody-pub"
          cfg (assoc config/default-config
                     :genesis-ledger {custody-pub (account/map->AccountState {:balance 5000 :seq 0 :deps []})}
                     :custody-pubkey custody-pub
                     :bootstrap-sunset-epoch 3)
          state (assoc (sm/init-state [] "my-node" cfg) :epoch 2)
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 3 (:epoch new-state)))
      (is (= 0 (:balance (get-in new-state [:ledger custody-pub]))))
      (is (= 0 (:total-minted new-state))))))

(defspec ^{:doc "Property: Across state machine ticks and burns, total-minted is bounded by max-conditional-mint-supply and custody releases never increase total-minted"}
  prop-state-machine-epoch-tick-invariants 50
  (prop/for-all [burn-amt (gen/choose 1000 50000)
                 custody-amt (gen/choose 500 5000)]
                (let [custody-kp (crypto/generate-keypair)
                      custody-pub (basalt/bytes->hex (:public custody-kp))
                      custody-priv (:private custody-kp)
                      t-kp (crypto/generate-keypair)
                      t-pub (basalt/bytes->hex (:public t-kp))
                      t-priv (:private t-kp)
                      cfg (assoc config/default-config
                                 :treasury-pubkey t-pub
                                 :treasury-privkey t-priv
                                 :treasury-trailing-epochs 10
                                 :validators ["v-node"]
                                 :mesh-nodes {"m-node" 1.0}
                                 :genesis-ledger {custody-pub (account/map->AccountState {:balance 20000 :seq 0 :deps []})}
                                 :custody-pubkey custody-pub
                                 :custody-privkey custody-priv
                                 :custody-allocations [{:receiver "grantee-y" :amount custody-amt}])
                      state (assoc (sm/init-state [] "my-node" cfg)
                                   :epoch 0
                                   :epoch-burns {0 burn-amt})
                      res (sm/handle-event state {:type :tick :rng (java.util.Random. 123)})
                      new-state (:state res)
                      r-trailing (quot burn-amt 10)
                      expected-mint (quot (* r-trailing 5000) 10000)]
                  (and (= 1 (:epoch new-state))
                       (contains? (:minted-epochs new-state) 1)
                       (<= (:total-minted new-state) expected-mint)
                       (<= (:total-minted new-state) treasury/max-conditional-mint-supply)
                       (= (- 20000 custody-amt) (:balance (get-in new-state [:ledger custody-pub])))
                       (= custody-amt (:balance (get-in new-state [:ledger "grantee-y"])))))))

(deftest test-state-machine-settle-intent
  (let [payer "payer-node"
        receiver "receiver-node"
        cfg (assoc config/default-config
                   :genesis-ledger {payer (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
        state (assoc (sm/init-state [] "my-node" cfg) :epoch 0)]
    (testing "Valid settle-intent deducts amount from payer, credits net to receiver, and records take in epoch-settlement-takes"
      ;; Amount 1000 with default 50 bps take: take = 5, net = 995
      (let [res (sm/handle-event state {:type :settle-intent
                                        :payer payer
                                        :receiver receiver
                                        :amount 1000})
            new-state (:state res)]
        (is (= 9000 (:balance (get-in new-state [:ledger payer]))))
        (is (= 995 (:balance (get-in new-state [:ledger receiver]))))
        (is (= 5 (get-in new-state [:epoch-settlement-takes 0])))
        (is (empty? (:commands res)))
        ;; Net ledger balance decreased by exactly the burned protocol take (5)
        (is (= (- 10000 5)
               (+ (:balance (get-in new-state [:ledger payer]))
                  (:balance (get-in new-state [:ledger receiver])))))))

    (testing "Event :take-bps is ignored: passing :take-bps 0 does not waive take, configured 50 bps is deducted"
      (let [res (sm/handle-event state {:type :settle-intent
                                        :payer payer
                                        :receiver receiver
                                        :amount 1000
                                        :take-bps 0})
            new-state (:state res)]
        (is (= 9000 (:balance (get-in new-state [:ledger payer]))))
        (is (= 995 (:balance (get-in new-state [:ledger receiver]))))
        (is (= 5 (get-in new-state [:epoch-settlement-takes 0])))))

    (testing "Configured settlement-take-bps in state/config is used (event :take-bps ignored)"
      (let [cfg-100 (assoc cfg :settlement-take-bps 100)
            st-100 (assoc (sm/init-state [] "my-node" cfg-100) :epoch 0)
            res (sm/handle-event st-100 {:type :settle-intent
                                         :payer payer
                                         :receiver receiver
                                         :amount 1000
                                         :take-bps 0})
            new-state (:state res)]
        (is (= 9000 (:balance (get-in new-state [:ledger payer]))))
        (is (= 990 (:balance (get-in new-state [:ledger receiver]))))
        (is (= 10 (get-in new-state [:epoch-settlement-takes 0])))))

    (testing "Fails closed on unknown payer"
      (let [res (sm/handle-event state {:type :settle-intent
                                        :payer "unknown-node"
                                        :receiver receiver
                                        :amount 1000})]
        (is (= state (:state res)))
        (is (empty? (:commands res)))))

    (testing "Fails closed on insufficient payer balance"
      (let [res (sm/handle-event state {:type :settle-intent
                                        :payer payer
                                        :receiver receiver
                                        :amount 20000})]
        (is (= state (:state res)))
        (is (empty? (:commands res)))))

    (testing "Fails closed on non-positive or non-integer amount"
      (let [res-zero (sm/handle-event state {:type :settle-intent :payer payer :receiver receiver :amount 0})
            res-neg (sm/handle-event state {:type :settle-intent :payer payer :receiver receiver :amount -500})
            res-float (sm/handle-event state {:type :settle-intent :payer payer :receiver receiver :amount 100.5})]
        (is (= state (:state res-zero)))
        (is (= state (:state res-neg)))
        (is (= state (:state res-float)))))

    (testing "Fails closed on missing receiver"
      (let [res (sm/handle-event state {:type :settle-intent :payer payer :amount 1000})]
        (is (= state (:state res)))))))

(deftest test-settle-intent-drives-demand-gated-mint-on-tick
  (testing "Settlement takes in epoch 0 feed trailing revenue on epoch 1 tick and drive demand-gated mint"
    (let [val-pub "validator-node-1"
          mesh-pub "mesh-routing-node-1"
          payer "payer-node"
          receiver "receiver-node"
          t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          cfg (assoc config/default-config
                     :treasury-pubkey t-pub
                     :treasury-privkey t-priv
                     :treasury-trailing-epochs 1
                     :validators [val-pub]
                     :mesh-nodes {mesh-pub 1.0}
                     :genesis-ledger {payer (account/map->AccountState {:balance 100000 :seq 0 :deps []})})
          state (assoc (sm/init-state [] "my-node" cfg) :epoch 0)
          ;; Settle intent for 40,000 with 50 bps take: take = 200, net = 39,800
          settle-res (sm/handle-event state {:type :settle-intent
                                             :payer payer
                                             :receiver receiver
                                             :amount 40000})
          s-settled (:state settle-res)
          ;; Advance to epoch 1 via :tick
          tick-res (sm/handle-event s-settled {:type :tick :rng (java.util.Random. 42)})
          s-tick (:state tick-res)]
      (is (= 200 (get-in s-settled [:epoch-settlement-takes 0])))
      (is (= 1 (:epoch s-tick)))
      ;; Trailing revenue for n=1 is 200 (from epoch 0 settlement take)
      ;; Demand-gated mint M_t = 200 * 50% = 100
      ;; Split: 20% Streamlet (20), 80% Mesh (80)
      (is (= 100 (:total-minted s-tick)))
      (is (= 20 (:balance (get-in s-tick [:ledger val-pub]))))
      (is (= 80 (:balance (get-in s-tick [:ledger mesh-pub])))))))

(deftest test-tick-persists-mint-dust
  (testing "handle-tick persists :mint-dust in state and :epoch-mint-dust across epochs"
    (let [val-pub1 "v1"
          val-pub2 "v2"
          val-pub3 "v3"
          mesh-pub "m1"
          t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          cfg (assoc config/default-config
                     :treasury-pubkey t-pub
                     :treasury-privkey t-priv
                     :treasury-trailing-epochs 1
                     :validators [val-pub1 val-pub2 val-pub3]
                     :mesh-nodes {mesh-pub 1.0})
          ;; Trailing burn 1000 -> M_t = 500. Split: Streamlet 100, Mesh 400.
          ;; 3 validators share 100 -> 33 each = 99. 1 dust!
          state (assoc (sm/init-state [] "my-node" cfg)
                       :epoch 0
                       :epoch-burns {0 1000})
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 1 (:epoch new-state)))
      (is (= 499 (:total-minted new-state)))
      (is (= 1 (:mint-dust new-state)))
      (is (= 1 (get-in new-state [:epoch-mint-dust 1]))))))

(defspec ^{:doc "Property: Settle intent strictly conserves ledger supply minus protocol take and records protocol take"}
  prop-settle-intent-conservation 50
  (prop/for-all [extra-bal (gen/choose 0 50000)
                 settle-amt (gen/choose 100 2000)
                 event-take-bps (gen/choose 0 200)
                 configured-take-bps (gen/choose 0 200)]
                (let [initial-payer-bal (+ settle-amt extra-bal)
                      payer "payer-node"
                      receiver "receiver-node"
                      cfg (assoc config/default-config
                                 :settlement-take-bps configured-take-bps
                                 :genesis-ledger {payer (account/map->AccountState {:balance initial-payer-bal :seq 0 :deps []})})
                      state (assoc (sm/init-state [] "local-node" cfg) :epoch 2)
                      res (sm/handle-event state {:type :settle-intent
                                                  :payer payer
                                                  :receiver receiver
                                                  :amount settle-amt
                                                  :take-bps event-take-bps})
                      new-state (:state res)
                      new-ledger (:ledger new-state)
                      effective-bps (max 1 (or configured-take-bps 50))
                      take-amt (burn/calculate-settlement-take settle-amt effective-bps)
                      net-amt (- settle-amt take-amt)]
                  (and (= (- initial-payer-bal settle-amt) (:balance (get new-ledger payer)))
                       (= net-amt (:balance (get new-ledger receiver)))
                       (= take-amt (get-in new-state [:epoch-settlement-takes 2]))
                       (= (- initial-payer-bal take-amt)
                          (+ (:balance (get new-ledger payer))
                             (:balance (get new-ledger receiver))))))))

(deftest test-tick-carries-forward-mint-dust-conserved
  (testing "handle-tick carries forward mint-dust into future epoch gate and satisfies conservation identity"
    (let [val-pub1 "v1"
          val-pub2 "v2"
          val-pub3 "v3"
          mesh-pub "m1"
          t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          cfg (assoc config/default-config
                     :treasury-pubkey t-pub
                     :treasury-privkey t-priv
                     :treasury-trailing-epochs 1
                     :validators [val-pub1 val-pub2 val-pub3]
                     :mesh-nodes {mesh-pub 1.0})
          ;; Epoch 0 burns 1000 -> gate 500. Split: Streamlet 100 (33 each = 99), Mesh 400.
          ;; Actual minted = 499, dust = 1.
          s0 (assoc (sm/init-state [] "my-node" cfg)
                    :epoch 0
                    :epoch-burns {0 1000})
          t1-res (sm/handle-event s0 {:type :tick :rng (java.util.Random. 42)})
          s1 (:state t1-res)]
      (is (= 1 (:epoch s1)))
      (is (= 499 (:total-minted s1)))
      (is (= 1 (:mint-dust s1)))
      (is (= (+ (:total-minted s1) (:mint-dust s1)) 500))

      ;; In Epoch 1, burn 1000 again -> demand gate 500.
      ;; With carry-dust 1, m-t becomes 501.
      ;; Split 501: Streamlet floor(0.20 * 501) = 100 (33 each = 99), Mesh 501 - 100 = 401.
      ;; Actual minted = 99 + 401 = 500.
      ;; New dust = 501 - 500 = 1.
      (let [s1-with-burn (assoc-in s1 [:epoch-burns 1] 1000)
            t2-res (sm/handle-event s1-with-burn {:type :tick :rng (java.util.Random. 42)})
            s2 (:state t2-res)]
        (is (= 2 (:epoch s2)))
        (is (= (+ 499 500) (:total-minted s2)))
        (is (= 1 (:mint-dust s2)))
        ;; Conservation identity across epochs:
        ;; (+ total-minted mint-dust) == sum of demand gates (500 + 500 = 1000)
        (is (= 1000 (+ (:total-minted s2) (:mint-dust s2))))))))

(deftest test-state-machine-skipped-custody-allocations
  (testing "init-state initializes :skipped-custody-allocations to []"
    (let [state (sm/init-state [] "my-node")]
      (is (= [] (:skipped-custody-allocations state)))))

  (testing "handle-tick populates :skipped-custody-allocations when custody allocations exceed balance"
    (let [c-kp (crypto/generate-keypair)
          c-pub (basalt/bytes->hex (:public c-kp))
          c-priv (:private c-kp)
          cfg (assoc config/default-config
                     :custody-pubkey c-pub
                     :custody-privkey c-priv
                     :custody-allocations [{:receiver "p1" :amount 300}
                                           {:receiver "p2" :amount 400}]
                     :genesis-ledger {c-pub (account/map->AccountState {:balance 500 :seq 0 :deps []})})
          state (assoc (sm/init-state [] "my-node" cfg) :epoch 0)
          res (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          new-state (:state res)]
      (is (= 1 (:epoch new-state)))
      ;; 300 succeeded, 400 exceeded remaining 200 balance and was skipped
      (is (= 200 (:balance (get-in new-state [:ledger c-pub]))))
      (is (= 300 (:balance (get-in new-state [:ledger "p1"]))))
      (is (= [{:receiver "p2" :amount 400 :reason :insufficient-custody-balance}]
             (:skipped-custody-allocations new-state))))))

(deftest test-state-machine-frozen-messages-and-strikes
  (testing "init-state initializes :frozen-epoch-messages to {} and :fault-strikes to {}"
    (let [state (sm/init-state [] "my-node")]
      (is (= {} (:frozen-epoch-messages state)))
      (is (= {} (:fault-strikes state)))))

  (testing "handle-tick snapshots closing epoch messages before TTL pruning, immune to later pruning"
    (let [cfg (assoc config/default-config :gossip-ttl-epochs 2)
          state (assoc (sm/init-state [] "my-node" cfg)
                       :epoch 0
                       :epoch-to-messages {0 #{"msg-a" "msg-b"}})
          res-ep1 (sm/handle-event state {:type :tick :rng (java.util.Random. 42)})
          state-ep1 (:state res-ep1)]
      (is (= 1 (:epoch state-ep1)))
      (is (= #{"msg-a" "msg-b"} (get-in state-ep1 [:frozen-epoch-messages 0])))

      ;; Advance multiple epochs past TTL (cutoff-epoch = new-epoch - 2)
      (let [state-ep5 (loop [s state-ep1
                             step 1]
                        (if (>= step 5)
                          s
                          (recur (:state (sm/handle-event s {:type :tick :rng (java.util.Random. 42)}))
                                 (inc step))))]
        (is (= 5 (:epoch state-ep5)))
        (is (nil? (get-in state-ep5 [:epoch-to-messages 0])) "Epoch 0 was pruned from active message store")
        (is (= #{"msg-a" "msg-b"} (get-in state-ep5 [:frozen-epoch-messages 0]))
            "Frozen snapshot is permanently retained and immune to TTL pruning!"))))

  (testing "handle-event :submit-transcript protects honest peers from fabricated unilateral strikes"
    (let [kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          honest-roles [["m1" :echo]]
          valid-half (attestation/create-transcript 0 pub-a pub-b honest-roles (:private kp-a))
          fabricated-half (attestation/create-transcript 0 pub-a pub-b [["invented-fake" :seen]] (:private kp-a))
          state (assoc (sm/init-state [] "my-node")
                       :frozen-epoch-messages {0 #{"m1"}}
                       :frozen-epoch-message-roles {0 {"m1" :echo}})]
      (testing "Fabricated unilateral report is rejected and does NOT strike peer B"
        (let [res (sm/handle-event state {:type :submit-transcript :transcript fabricated-half})
              new-state (:state res)]
          (is (= {} (:fault-strikes new-state)) "Honest peer B was NOT struck")))

      (testing "Log-verified half-signed transcript credits peer A and records a strike on peer B"
        (let [res (sm/handle-event state {:type :submit-transcript
                                          :transcript valid-half})
              new-state (:state res)]
          (is (= 1 (get-in new-state [:fault-strikes pub-b])) "Peer B was struck for withholding signature"))))))

(defspec ^{:doc "Property: Frozen epoch message snapshots remain immutable across arbitrary subsequent ticks"}
  prop-state-machine-frozen-messages-ttl-immunity 50
  (prop/for-all [extra-ticks (gen/choose 3 15)]
                (let [cfg (assoc config/default-config :gossip-ttl-epochs 2)
                      init-msgs #{"snapshot-m1" "snapshot-m2"}
                      state (assoc (sm/init-state [] "my-node" cfg)
                                   :epoch 0
                                   :epoch-to-messages {0 init-msgs})
                      ;; First tick closes epoch 0
                      res-1 (sm/handle-event state {:type :tick :rng (java.util.Random. 11)})
                      state-after-ep0 (:state res-1)
                      ;; Advance extra ticks
                      final-state (loop [s state-after-ep0
                                         t 0]
                                    (if (>= t extra-ticks)
                                      s
                                      (recur (:state (sm/handle-event s {:type :tick :rng (java.util.Random. 22)}))
                                             (inc t))))]
                  (and (= init-msgs (get-in state-after-ep0 [:frozen-epoch-messages 0]))
                       (= init-msgs (get-in final-state [:frozen-epoch-messages 0]))))))

(deftest rendezvous-state-machine-integration-test
  (testing "init-state initializes rendezvous and voucher maps/sets"
    (let [state (sm/init-state [] "my-node")]
      (is (= {} (:home-sets state)))
      (is (= {} (:voucher-seqs state)))
      (is (= [] (:pending-vouchers state)))
      (is (= #{} (:settled-voucher-tuples state)))
      (is (= [] (:failed-vouchers state)))))

  (testing "handle-event :register-home-set registers home set at fixed price per epoch"
    (let [callee "callee-b"
          candidates [{:node-id "n1" :price 10}
                      {:node-id "n2" :price 10}
                      {:node-id "n3" :price 10}
                      {:node-id "n4" :price 20}]
          state (assoc (sm/init-state [] "my-node") :epoch 0)
          reg-res (sm/handle-event state {:type :register-home-set
                                          :callee callee
                                          :candidates candidates
                                          :price 10
                                          :price-max 20})
          st1 (:state reg-res)
          registered (get-in st1 [:home-sets [callee 0]])]
      (is (= :ok (:status registered)))
      (is (= 10 (:price registered)))
      (is (= 3 (count (:home-nodes registered))))

      ;; Re-registration in the SAME epoch at a DIFFERENT price is rejected
      (let [bad-rereg (sm/handle-event st1 {:type :register-home-set
                                            :callee callee
                                            :candidates candidates
                                            :price 25
                                            :price-max 30})
            st-bad (:state bad-rereg)]
        (is (= 10 (:price (get-in st-bad [:home-sets [callee 0]]))) "Retains initial registration price"))

      ;; Registration for a NEW epoch at a different price succeeds
      (let [next-epoch-reg (sm/handle-event st1 {:type :register-home-set
                                                 :callee callee
                                                 :epoch 1
                                                 :candidates candidates
                                                 :price 15
                                                 :price-max 25})
            st-next (:state next-epoch-reg)]
        (is (= 15 (:price (get-in st-next [:home-sets [callee 1]])))))))

  (testing "handle-event :receive-offer-header validates home-node membership, monotonicity, and records voucher"
    (let [callee-kp (crypto/generate-keypair)
          callee-pub (basalt/bytes->hex (:public callee-kp))
          callee-priv (:private callee-kp)
          home-node "home-node-1"
          candidates [{:node-id home-node :price 10}
                      {:node-id "home-node-2" :price 10}
                      {:node-id "home-node-3" :price 10}]
          base-state (-> (sm/init-state [] "my-node")
                         (assoc :epoch 0)
                         (assoc-in [:ledger callee-pub]
                                   (account/map->AccountState {:balance 100 :seq 0 :deps []}))
                         (assoc-in [:home-sets [callee-pub 0]]
                                   {:status :ok :home-nodes candidates :price 10 :degraded? false}))]

      (testing "Rejects offer header if callee is absent from :ledger (or has 0 balance) when price > 0"
        (let [unfunded-state (assoc base-state :ledger {})
              unfunded-event {:type :receive-offer-header
                              :caller "caller-a"
                              :callee callee-pub
                              :callee-privkey callee-priv
                              :home-node home-node
                              :offer-hash "hash-unfunded"
                              :seq 1}
              res (sm/handle-event unfunded-state unfunded-event)]
          (is (= unfunded-state (:state res)))
          (is (empty? (:commands res)))
          (is (empty? (:pending-vouchers (:state res))))))

      (testing "Rejects offer header if home-node is not in callee's registered home set"
        (let [unregistered-event {:type :receive-offer-header
                                  :caller "caller-a"
                                  :callee callee-pub
                                  :callee-privkey callee-priv
                                  :home-node "rogue-home-node"
                                  :offer-hash "hash-1"
                                  :seq 1}
              res (sm/handle-event base-state unregistered-event)]
          (is (= base-state (:state res)))))

      (testing "Accepts initial valid offer header at seq = 1 and appends DeliveryAck"
        (let [valid-event-1 {:type :receive-offer-header
                             :caller "caller-a"
                             :callee callee-pub
                             :callee-privkey callee-priv
                             :home-node home-node
                             :offer-hash "hash-1"
                             :seq 1}
              res-1 (sm/handle-event base-state valid-event-1)
              st-1 (:state res-1)]
          (is (= 1 (get-in st-1 [:voucher-seqs [callee-pub home-node 0]])))
          (is (= 1 (count (:pending-vouchers st-1))))
          (let [ack (first (:pending-vouchers st-1))]
            (is (= 1 (:seq ack)))
            (is (= 10 (:cumulative-debit ack)))
            (is (true? (rdv/verify-delivery-ack ack))))

          (testing "Rejects seq gap (e.g. seq = 3 when last-seq = 1) and seq rollback (seq = 1)"
            (let [gap-event (assoc valid-event-1 :seq 3)
                  rollback-event (assoc valid-event-1 :seq 1)]
              (is (= st-1 (:state (sm/handle-event st-1 gap-event))))
              (is (= st-1 (:state (sm/handle-event st-1 rollback-event))))))

          (testing "Accepts strictly monotonic seq = 2 and accumulates voucher"
            (let [valid-event-2 (assoc valid-event-1 :seq 2 :offer-hash "hash-2")
                  res-2 (sm/handle-event st-1 valid-event-2)
                  st-2 (:state res-2)]
              (is (= 2 (get-in st-2 [:voucher-seqs [callee-pub home-node 0]])))
              (is (= 2 (count (:pending-vouchers st-2))))
              (let [ack2 (second (:pending-vouchers st-2))]
                (is (= 2 (:seq ack2)))
                (is (= 20 (:cumulative-debit ack2)))
                (is (true? (rdv/verify-delivery-ack ack2))))))))))

  (testing "handle-tick at epoch boundary compacts vouchers, settles against ledger, and protects against replay"
    (let [callee-kp (crypto/generate-keypair)
          callee-pub (basalt/bytes->hex (:public callee-kp))
          callee-priv (:private callee-kp)
          home-node "home-node-settle"
          price 15
          candidates [{:node-id home-node :price price}
                      {:node-id "h2" :price price}
                      {:node-id "h3" :price price}]
          ;; Setup ledger: callee has 100, home-node has 10
          ledger {callee-pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                  home-node (account/map->AccountState {:balance 10 :seq 0 :deps []})}
          init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                     (assoc :epoch 0)
                     (assoc-in [:home-sets [callee-pub 0]]
                               {:status :ok :home-nodes candidates :price price :degraded? false}))
          ;; Receive seq 1 (debit 15) and seq 2 (debit 30)
          ev1 {:type :receive-offer-header
               :caller "caller"
               :callee callee-pub
               :callee-privkey callee-priv
               :home-node home-node
               :offer-hash "hash-a"
               :seq 1}
          ev2 (assoc ev1 :seq 2 :offer-hash "hash-b")
          s1 (:state (sm/handle-event init-s ev1))
          s2 (:state (sm/handle-event s1 ev2))]
      (is (= 2 (count (:pending-vouchers s2))))

      ;; Trigger epoch boundary tick
      (let [tick-res (sm/handle-event s2 {:type :tick :rng (java.util.Random. 42)})
            new-state (:state tick-res)
            new-ledger (:ledger new-state)]
        (is (= 1 (:epoch new-state)))
        ;; Vouchers for epoch 0 were cleared
        (is (empty? (:pending-vouchers new-state)))
        ;; Compacted voucher (seq 2, cum-debit 30) settled:
        ;; callee balance 100 - 30 = 70; home-node balance 10 + 30 = 40
        (is (= 70 (:balance (get new-ledger callee-pub))))
        (is (= 40 (:balance (get new-ledger home-node))))
        ;; Tuple recorded in settled-tuples
        (is (contains? (:settled-voucher-tuples new-state) [callee-pub home-node 0]))

        ;; Replay safety: a repeated settlement with an ack for [callee-pub home-node 0] does nothing
        (let [stale-ack (first (:pending-vouchers s2))
              replayed-state (assoc new-state :pending-vouchers [stale-ack])
              re-tick (:state (sm/handle-event replayed-state {:type :tick :rng (java.util.Random. 42)}))]
          (is (= 70 (:balance (get (:ledger re-tick) callee-pub))))
          (is (= 40 (:balance (get (:ledger re-tick) home-node)))))))))

(defspec ^{:doc "Property: State machine voucher settlement strictly conserves balance between callee and home-node"}
  prop-state-machine-voucher-settlement-conservation 50
  (prop/for-all [callee-init-bal (gen/choose 0 1000)
                 home-init-bal (gen/choose 0 1000)
                 seq-num (gen/choose 1 20)
                 price (gen/choose 1 50)]
                (let [callee-kp (crypto/generate-keypair)
                      callee-pub (basalt/bytes->hex (:public callee-kp))
                      callee-priv (:private callee-kp)
                      home-node "home-prop-node"
                      ledger {callee-pub (account/map->AccountState {:balance callee-init-bal :seq 0 :deps []})
                              home-node (account/map->AccountState {:balance home-init-bal :seq 0 :deps []})}
                      candidates [{:node-id home-node :price price}
                                  {:node-id "h2" :price price}
                                  {:node-id "h3" :price price}]
                      init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                                 (assoc :epoch 0)
                                 (assoc-in [:home-sets [callee-pub 0]]
                                           {:status :ok :home-nodes candidates :price price :degraded? false}))
                      ev {:type :receive-offer-header
                          :caller "caller"
                          :callee callee-pub
                          :callee-privkey callee-priv
                          :home-node home-node
                          :offer-hash "hash-prop"
                          :seq 1}
                      ;; Receive sequence of vouchers up to seq-num
                      final-received (reduce (fn [st s]
                                               (:state (sm/handle-event st (assoc ev :seq s :offer-hash (str "hash-" s)))))
                                             init-s
                                             (range 1 (inc seq-num)))
                      ;; Tick epoch boundary
                      tick-res (sm/handle-event final-received {:type :tick :rng (java.util.Random. 99)})
                      post-state (:state tick-res)
                      post-ledger (:ledger post-state)
                      final-callee-bal (:balance (get post-ledger callee-pub))
                      final-home-bal (:balance (get post-ledger home-node))
                      total-before (+ callee-init-bal home-init-bal)
                      total-after (+ final-callee-bal final-home-bal)
                      actual-transfer (* (min seq-num (quot callee-init-bal price)) price)]
                  (and (= total-before total-after)
                       (= final-callee-bal (- callee-init-bal actual-transfer))
                       (= final-home-bal (+ home-init-bal actual-transfer))))))

(defspec ^{:doc "Property: receive-offer-header fails closed when callee is absent or has balance < cum-debit"}
  prop-receive-offer-header-callee-balance-invariants 50
  (prop/for-all [callee-bal (gen/choose 0 500)
                 price (gen/choose 1 50)
                 seq-num (gen/choose 1 10)
                 absent? gen/boolean]
                (let [callee-kp (crypto/generate-keypair)
                      callee-pub (basalt/bytes->hex (:public callee-kp))
                      callee-priv (:private callee-kp)
                      home-node "home-node"
                      candidates [{:node-id home-node :price price}]
                      cum-debit (* seq-num price)
                      ledger (if absent?
                               {}
                               {callee-pub (account/map->AccountState {:balance callee-bal :seq 0 :deps []})})
                      state (-> (sm/init-state [] "my-node")
                                (assoc :epoch 0)
                                (assoc :ledger ledger)
                                (assoc-in [:home-sets [callee-pub 0]]
                                          {:status :ok :home-nodes candidates :price price :degraded? false})
                                (assoc-in [:voucher-seqs [callee-pub home-node 0]] (dec seq-num)))
                      event {:type :receive-offer-header
                             :caller "caller"
                             :callee callee-pub
                             :callee-privkey callee-priv
                             :home-node home-node
                             :offer-hash "hash-prop"
                             :seq seq-num}
                      res (sm/handle-event state event)
                      effective-bal (if absent? 0 callee-bal)]
                  (if (< effective-bal cum-debit)
                    (and (= state (:state res))
                         (empty? (:commands res))
                         (empty? (:pending-vouchers (:state res))))
                    (and (= 1 (count (:pending-vouchers (:state res))))
                         (= seq-num (get-in (:state res) [:voucher-seqs [callee-pub home-node 0]])))))))

(deftest signed-control-frames-test
  (let [kp-echo (crypto/generate-keypair)
        echo-sender (basalt/bytes->hex (:public kp-echo))
        kp-ready (crypto/generate-keypair)
        ready-sender (basalt/bytes->hex (:public kp-ready))
        message-id "msg-test-control-1"
        valid-echo-frame (sieve/sign-control-frame :sieve-echo message-id (:private kp-echo) (:public kp-echo))
        valid-ready-frame (sieve/sign-control-frame :contagion-ready message-id (:private kp-ready) (:public kp-ready))
        base-cfg (assoc config/default-config
                        :echo-threshold 1
                        :ready-threshold 1
                        :delivery-threshold 1
                        :require-signed-control-frames true)
        state (-> (sm/init-state [] "my-node" base-cfg)
                  (assoc :global-echo-sample #{echo-sender}
                         :global-ready-sample #{ready-sender}
                         :global-delivery-sample #{ready-sender}))]

    (testing "sieve/validate-control-frame validates authentic signatures and rejects forged frames"
      (is (true? (sieve/validate-control-frame valid-echo-frame :sieve-echo true)))
      (is (true? (sieve/validate-control-frame valid-ready-frame :contagion-ready true)))
      (testing "Mismatched frame-type is rejected"
        (is (false? (sieve/validate-control-frame valid-echo-frame :contagion-ready true))))
      (testing "Mismatched message-id is rejected"
        (is (false? (sieve/validate-control-frame (assoc valid-echo-frame :message-id "wrong-id") :sieve-echo true))))
      (testing "Corrupted signature is rejected"
        (let [corrupt (assoc valid-echo-frame :signature (basalt/bytes->hex (byte-array 64)))]
          (is (false? (sieve/validate-control-frame corrupt :sieve-echo true)))))
      (testing "Unsigned frame is rejected when require-signed is true"
        (let [unsigned-frame (dissoc valid-echo-frame :signature)]
          (is (false? (sieve/validate-control-frame unsigned-frame :sieve-echo true)))
          (is (true? (sieve/validate-control-frame unsigned-frame :sieve-echo false))))))

    (testing "Forged :receive-sieve-echo is rejected and does not increment votes"
      (let [forged-event {:type :receive-sieve-echo
                          :sender echo-sender
                          :message-id message-id
                          :signature (basalt/bytes->hex (byte-array 64))}
            res (sm/handle-event state forged-event)]
        (is (= state (:state res)))
        (is (empty? (:commands res)))))

    (testing "Unsigned :receive-sieve-echo is rejected when require-signed-control-frames is true"
      (let [unsigned-event {:type :receive-sieve-echo
                            :sender echo-sender
                            :message-id message-id}
            res (sm/handle-event state unsigned-event)]
        (is (= state (:state res)))
        (is (empty? (:commands res)))))

    (testing "Authentic signed :receive-sieve-echo is accepted and increments votes"
      (let [valid-event (assoc valid-echo-frame :type :receive-sieve-echo)
            res (sm/handle-event state valid-event)
            new-state (:state res)]
        (is (= 1 (get-in new-state [:echo-vote-counts message-id])))
        (is (contains? (:sieve-delivered-set new-state) message-id))))

    (testing "Forged :receive-contagion-ready is rejected and does not increment votes"
      (let [forged-event {:type :receive-contagion-ready
                          :sender ready-sender
                          :message-id message-id
                          :signature (basalt/bytes->hex (byte-array 64))}
            res (sm/handle-event state forged-event)]
        (is (= state (:state res)))
        (is (empty? (:commands res)))))

    (testing "Authentic signed :receive-contagion-ready is accepted and increments votes"
      (let [valid-event (assoc valid-ready-frame :type :receive-contagion-ready)
            res (sm/handle-event state valid-event)
            new-state (:state res)]
        (is (= 1 (get-in new-state [:ready-vote-counts message-id])))
        (is (= 1 (get-in new-state [:delivery-vote-counts message-id])))))))

(defspec ^{:doc "Property: Signed control frames are authentic; corrupted signatures are always rejected"}
  prop-signed-control-frame-authenticity 50
  (prop/for-all [frame-type (gen/elements [:sieve-echo :contagion-ready])
                 message-id gen/string-alphanumeric
                 corrupt? gen/boolean]
                (let [kp (crypto/generate-keypair)
                      pub (:public kp)
                      priv (:private kp)
                      signed (sieve/sign-control-frame frame-type message-id priv pub)
                      test-frame (if corrupt?
                                   (assoc signed :signature (basalt/bytes->hex (byte-array 64)))
                                   signed)
                      valid? (sieve/validate-control-frame test-frame frame-type true)]
                  (if corrupt?
                    (false? valid?)
                    (true? valid?)))))

(defspec ^{:doc "Property: Mandatory broadcast burn is deducted or broadcast is dropped; balance is strictly conserved"}
  prop-state-machine-mandatory-burn-conservation 50
  (prop/for-all [initial-balance (gen/choose 0 500)
                 burn-amount (gen/choose 50 300)]
                (let [sender "broadcasting-node"
                      peer {:ip "127.0.0.1" :port 8001 :pubkey "peer-pubkey" :hash "peer-hash"}
                      cfg (assoc config/default-config :genesis-ledger {sender (account/map->AccountState {:balance initial-balance :seq 0 :deps []})})
                      state (sm/init-state [peer] "local-node" cfg)
                      res (sm/handle-event state {:type :broadcast
                                                  :sender sender
                                                  :burn burn-amount
                                                  :payload (.getBytes "test-payload" "UTF-8")
                                                  :rng (java.util.Random. 42)})
                      new-state (:state res)
                      final-bal (or (:balance (get-in new-state [:ledger sender])) 0)
                      total-burned (reduce + (vals (or (:epoch-burns new-state) {})))]
                  (if (and (>= burn-amount burn/min-signaling-burn)
                           (>= initial-balance burn-amount))
                    (and (= (- initial-balance burn-amount) final-bal)
                         (= burn-amount total-burned)
                         (= 1 (count (:messages new-state)))
                         (seq (:commands res)))
                    (and (= initial-balance final-bal)
                         (zero? total-burned)
                         (empty? (:messages new-state))
                         (empty? (:commands res)))))))

(deftest ^{:doc "Tests derive-epoch-entropy strictly derives hash strings and never stringifies maps"}
  derive-epoch-entropy-test
  (testing "extracts :latest-finalized-block-hash directly"
    (let [state {:latest-finalized-block-hash "deadbeef0123456789abcdef"}
          entropy (sm/derive-epoch-entropy state {})]
      (is (= "deadbeef0123456789abcdef" entropy))))

  (testing "extracts :latest-finalized-block when string hash"
    (let [state {:latest-finalized-block "cafebabe0123456789abcdef"}
          entropy (sm/derive-epoch-entropy state {})]
      (is (= "cafebabe0123456789abcdef" entropy))))

  (testing "hashes Block map/record when present in :latest-finalized-block"
    (let [block (streamlet/->Block 5 "genesis" [] "proposer-pubkey")
          state {:latest-finalized-block block}
          entropy (sm/derive-epoch-entropy state {})]
      (is (string? entropy))
      (is (= 64 (count entropy)))
      (is (not (.contains entropy "{")))
      (is (not (.contains entropy ":epoch")))
      (is (= (streamlet/hash-block block) entropy))))

  (testing "hashes latest Block from :finalized-blocks collection"
    (let [b1 (streamlet/->Block 1 "genesis" [] "p1")
          b2 (streamlet/->Block 2 (streamlet/hash-block b1) [] "p2")
          state {:finalized-blocks [b1 b2]}
          entropy (sm/derive-epoch-entropy state {})]
      (is (string? entropy))
      (is (= 64 (count entropy)))
      (is (= (streamlet/hash-block b2) entropy))))

  (testing "falls back to :epoch-entropy in state, cfg, or genesis"
    (is (= "state-entropy" (sm/derive-epoch-entropy {:epoch-entropy "state-entropy"} {})))
    (is (= "cfg-entropy" (sm/derive-epoch-entropy {} {:epoch-entropy "cfg-entropy"})))
    (is (= "genesis" (sm/derive-epoch-entropy {} {})))))

(defspec ^{:doc "Property: derive-epoch-entropy strictly outputs non-empty hash string, never a stringified Clojure map"}
  prop-derive-epoch-entropy-never-stringifies-maps 50
  (prop/for-all [epoch (gen/choose 1 1000)
                 proposer gen/string-alphanumeric]
                (let [block (streamlet/->Block epoch "genesis" [] proposer)
                      state {:finalized-blocks #{block}
                             :latest-finalized-block block}
                      entropy (sm/derive-epoch-entropy state {})]
                  (and (string? entropy)
                       (not (string/blank? entropy))
                       (= 64 (count entropy))
                       (not (.contains entropy "{"))
                       (not (.contains entropy "}"))
                       (not (.contains entropy ":epoch"))
                       (= (streamlet/hash-block block) entropy)))))

(deftest fail-closed-voucher-settlement-test
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        home-node "home-node-1"
        price 20
        candidates [{:node-id home-node :price price}
                    {:node-id "h2" :price price}
                    {:node-id "h3" :price price}]]

    (testing "handle-receive-offer-header rejects offer header when callee is in ledger and underfunded"
      (let [ledger {callee-pub (account/map->AccountState {:balance 15 :seq 0 :deps []})}
            init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                       (assoc :epoch 0)
                       (assoc-in [:home-sets [callee-pub 0]]
                                 {:status :ok :home-nodes candidates :price price :degraded? false}))
            ev {:type :receive-offer-header
                :caller "caller"
                :callee callee-pub
                :callee-privkey callee-priv
                :home-node home-node
                :offer-hash "hash-underfunded"
                :seq 1}
            res (sm/handle-event init-s ev)]
        ;; 15 < cum-debit 20 -> rejected
        (is (= init-s (:state res)))
        (is (empty? (:commands res)))
        (is (empty? (:pending-vouchers (:state res))))))

    (testing "handle-receive-offer-header accepts offer header when callee balance >= cum-debit"
      (let [ledger {callee-pub (account/map->AccountState {:balance 20 :seq 0 :deps []})}
            init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                       (assoc :epoch 0)
                       (assoc-in [:home-sets [callee-pub 0]]
                                 {:status :ok :home-nodes candidates :price price :degraded? false}))
            ev {:type :receive-offer-header
                :caller "caller"
                :callee callee-pub
                :callee-privkey callee-priv
                :home-node home-node
                :offer-hash "hash-funded"
                :seq 1}
            res (sm/handle-event init-s ev)]
        (is (= 1 (count (:pending-vouchers (:state res)))))))

    (testing "voucher settlement fails closed when callee balance is less than voucher debit at tick"
      (let [ledger {callee-pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                    home-node (account/map->AccountState {:balance 50 :seq 0 :deps []})}
            init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                       (assoc :epoch 0)
                       (assoc-in [:home-sets [callee-pub 0]]
                                 {:status :ok :home-nodes candidates :price price :degraded? false}))
            ev {:type :receive-offer-header
                :caller "caller"
                :callee callee-pub
                :callee-privkey callee-priv
                :home-node home-node
                :offer-hash "hash-drain"
                :seq 1}
            s1 (:state (sm/handle-event init-s ev))]
        (is (= 1 (count (:pending-vouchers s1))))
        ;; Drain callee balance: callee now has only 10, but voucher debit is 20
        (let [drained-s (assoc-in s1 [:ledger callee-pub :balance] 10)
              tick-res (sm/handle-event drained-s {:type :tick :rng (java.util.Random. 42)})
              post-state (:state tick-res)
              post-ledger (:ledger post-state)]
          ;; Fail-closed: 0 transferred, tuple not added to settled-voucher-tuples
          (is (= 10 (:balance (get post-ledger callee-pub))))
          (is (= 50 (:balance (get post-ledger home-node))))
          (is (not (contains? (:settled-voucher-tuples post-state) [callee-pub home-node 0]))))))))

(deftest role-preserving-frozen-epoch-logs-test
  (testing "init-state initializes role tracking maps"
    (let [st (sm/init-state [] "my-node")]
      (is (= {} (:epoch-to-message-roles st)))
      (is (= {} (:frozen-epoch-message-roles st)))))

  (testing "message handlers track observed roles :gossip, :echo, and :ready"
    (let [sender-kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public sender-kp))
          sender-priv (:private sender-kp)
          ledger {sender-pub (account/map->AccountState {:balance 100000 :seq 0 :deps []})}
          st (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                 (assoc :epoch 0)
                 (assoc :global-echo-sample #{sender-pub})
                 (assoc :global-ready-sample #{sender-pub}))]

      (testing "handle-broadcast records :gossip role"
        (let [res (sm/handle-event st {:type :broadcast
                                       :payload (.getBytes "hello broadcast" "UTF-8")
                                       :sender sender-pub
                                       :private-key sender-priv
                                       :public-key (:public sender-kp)
                                       :rng (java.util.Random. 1)})
              new-st (:state res)
              m-id (first (keys (:messages new-st)))]
          (is (some? m-id))
          (is (= :gossip (get-in new-st [:epoch-to-message-roles 0 m-id])))))

      (testing "receive-gossip records :gossip role"
        (let [payload (.getBytes "hello gossip" "UTF-8")
              wrapped (sieve/wrap-message payload sender-priv (:public sender-kp) 1000)
              res (sm/handle-event st {:type :receive-gossip :message wrapped})
              new-st (:state res)
              expected-id (basalt/bytes->hex (crypto/sha256 payload))]
          (is (= :gossip (get-in new-st [:epoch-to-message-roles 0 expected-id])))))

      (testing "receive-sieve-echo records :echo role"
        (let [echo-frame (sieve/sign-control-frame :sieve-echo "msg-echo-1" sender-priv sender-pub)
              res (sm/handle-event st (assoc echo-frame :type :receive-sieve-echo))
              new-st (:state res)]
          (is (= :echo (get-in new-st [:epoch-to-message-roles 0 "msg-echo-1"])))))

      (testing "receive-contagion-ready records :ready role"
        (let [ready-frame (sieve/sign-control-frame :contagion-ready "msg-ready-1" sender-priv sender-pub)
              res (sm/handle-event st (assoc ready-frame :type :receive-contagion-ready))
              new-st (:state res)]
          (is (= :ready (get-in new-st [:epoch-to-message-roles 0 "msg-ready-1"])))))))

  (testing "frozen-epoch-message-roles snapshotting and TTL immunity"
    (let [cfg (assoc config/default-config :gossip-ttl-epochs 2)
          st (assoc (sm/init-state [] "my-node" cfg)
                    :epoch 0
                    :epoch-to-messages {0 #{"m-gossip" "m-echo"}}
                    :epoch-to-message-roles {0 {"m-gossip" :gossip "m-echo" :echo}})
          tick-1 (sm/handle-event st {:type :tick :rng (java.util.Random. 42)})
          st-ep1 (:state tick-1)]
      (is (= 1 (:epoch st-ep1)))
      (is (= {"m-gossip" :gossip "m-echo" :echo} (get-in st-ep1 [:frozen-epoch-message-roles 0])))

      ;; Advance ticks past TTL (cutoff-epoch = new-epoch - 2)
      (let [st-ep5 (loop [s st-ep1
                          step 1]
                     (if (>= step 5)
                       s
                       (recur (:state (sm/handle-event s {:type :tick :rng (java.util.Random. 42)}))
                              (inc step))))]
        (is (= 5 (:epoch st-ep5)))
        (is (nil? (get-in st-ep5 [:epoch-to-message-roles 0])) "Epoch 0 roles pruned from active store")
        (is (= {"m-gossip" :gossip "m-echo" :echo} (get-in st-ep5 [:frozen-epoch-message-roles 0]))
            "Frozen role snapshot is permanently retained past TTL pruning"))))

  (testing "handle-submit-transcript role preservation and bilateral intersection"
    (let [kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          state (assoc (sm/init-state [] pub-a)
                       :frozen-epoch-messages {0 #{"m1" "m2"}}
                       :frozen-epoch-message-roles {0 {"m1" :gossip "m2" :ready}})]

      (testing "rejects transcript with falsified role without striking counterparty"
        (let [falsified-roles [["m1" :echo]]
              falsified-half (attestation/create-transcript 0 pub-a pub-b falsified-roles (:private kp-a))
              res (sm/handle-event state {:type :submit-transcript :transcript falsified-half})
              new-state (:state res)]
          (is (= {} (:fault-strikes new-state)) "Counterparty B was NOT struck because role mismatch invalidated transcript")))

      (testing "accepts transcript matching authoritative local frozen roles"
        (let [honest-roles [["m1" :gossip] ["m2" :ready]]
              honest-half (attestation/create-transcript 0 pub-a pub-b honest-roles (:private kp-a))
              res (sm/handle-event state {:type :submit-transcript :transcript honest-half})
              new-state (:state res)]
          (is (= 1 (get-in new-state [:fault-strikes pub-b])) "Counterparty B was struck for withholding on valid transcript")))

      (testing "uses bilateral intersection with cryptographically signed :counterparty-frozen-log"
        (let [roles-both [["m1" :gossip] ["m2" :ready]]
              transcript-both (attestation/create-transcript 0 pub-a pub-b roles-both (:private kp-a))
              roles-m2 [["m2" :ready]]
              transcript-m2 (attestation/create-transcript 0 pub-a pub-b roles-m2 (:private kp-a))
              valid-cp-log (attestation/sign-frozen-log 0 pub-b ["m2"] (:private kp-b))
              forged-key-log (attestation/sign-frozen-log 0 pub-b ["m2"] (:private (crypto/generate-keypair)))
              wrong-epoch-log (attestation/sign-frozen-log 1 pub-b ["m2"] (:private kp-b))
              wrong-peer-log (attestation/sign-frozen-log 0 pub-a ["m2"] (:private kp-a))
              event-valid {:type :submit-transcript
                           :counterparty-frozen-log valid-cp-log}
              res-both (sm/handle-event state (assoc event-valid :transcript transcript-both))
              res-m2 (sm/handle-event state (assoc event-valid :transcript transcript-m2))]

          (testing "Rejects unauthenticated raw counterparty IDs without signed log"
            (let [raw-res (sm/handle-event state {:type :submit-transcript
                                                  :transcript transcript-m2
                                                  :counterparty-frozen-ids #{"m2"}})]
              (is (= {} (:fault-strikes (:state raw-res)))
                  "Unauthenticated raw counterparty IDs must fail closed without striking")))

          (testing "Rejects forged or mismatched counterparty frozen log"
            (is (= {} (:fault-strikes (:state (sm/handle-event state {:type :submit-transcript
                                                                      :transcript transcript-m2
                                                                      :counterparty-frozen-log forged-key-log})))))
            (is (= {} (:fault-strikes (:state (sm/handle-event state {:type :submit-transcript
                                                                      :transcript transcript-m2
                                                                      :counterparty-frozen-log wrong-epoch-log})))))
            (is (= {} (:fault-strikes (:state (sm/handle-event state {:type :submit-transcript
                                                                      :transcript transcript-m2
                                                                      :counterparty-frozen-log wrong-peer-log}))))))

          (testing "Reconciles with valid signed counterparty log"
            (is (= {} (:fault-strikes (:state res-both)))
                "Transcript including non-intersected message m1 is rejected")
            (is (= 1 (get-in (:state res-m2) [:fault-strikes pub-b]))
                "Transcript matching bilateral intersection is accepted and strikes withholding peer")))))))

(deftest test-voucher-settlement-failed-vouchers-tracking
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        home-node "home-node-settle"
        price 15
        candidates [{:node-id home-node :price price}]
        ledger {callee-pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                home-node (account/map->AccountState {:balance 10 :seq 0 :deps []})}
        init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                   (assoc :epoch 0)
                   (assoc-in [:home-sets [callee-pub 0]]
                             {:status :ok :home-nodes candidates :price price :degraded? false}))
        ev1 {:type :receive-offer-header
             :caller "caller"
             :callee callee-pub
             :callee-privkey callee-priv
             :home-node home-node
             :offer-hash "hash-a"
             :seq 1}
        ev2 (assoc ev1 :seq 2 :offer-hash "hash-b")
        s1 (:state (sm/handle-event init-s ev1))
        s2 (:state (sm/handle-event s1 ev2))]

    (testing "Depleted callee balance mid-epoch fails closed and records unpaid voucher in :failed-vouchers"
      (let [depleted-state (assoc-in s2 [:ledger callee-pub :balance] 10)
            tick-res (sm/handle-event depleted-state {:type :tick :rng (java.util.Random. 42)})
            new-state (:state tick-res)
            new-ledger (:ledger new-state)]
        (is (= 1 (:epoch new-state)))
        (is (= 10 (:balance (get new-ledger callee-pub))))
        (is (= 10 (:balance (get new-ledger home-node))))
        (is (not (contains? (:settled-voucher-tuples new-state) [callee-pub home-node 0])))
        (is (= 1 (count (:failed-vouchers new-state))))
        (let [failed (first (:failed-vouchers new-state))]
          (is (= :insufficient-callee-balance (:reason failed)))
          (is (= 30 (:debit failed)))
          (is (= 10 (:callee-balance failed)))
          (is (= 0 (:epoch failed))))))

    (testing "Invalid voucher failing cryptographic verification records failure in :failed-vouchers"
      (let [stale-ack (first (:pending-vouchers s2))
            corrupted-ack (assoc stale-ack :signature (byte-array 64) :epoch 0)
            corrupted-state (assoc init-s :pending-vouchers [corrupted-ack])
            tick-res (sm/handle-event corrupted-state {:type :tick :rng (java.util.Random. 42)})
            new-state (:state tick-res)]
        (is (= 1 (count (:failed-vouchers new-state))))
        (let [failed (first (:failed-vouchers new-state))]
          (is (contains? #{:invalid-voucher :signature-verification-failed :invalid-signature} (:reason failed)))
          (is (= 0 (:epoch failed))))))))

(deftest test-state-machine-bounded-frozen-retention
  (testing "handle-tick bounds frozen epoch message retention to :frozen-log-retention-epochs"
    (let [cfg (assoc config/default-config :gossip-ttl-epochs 2 :frozen-log-retention-epochs 4)
          state (assoc (sm/init-state [] "my-node" cfg)
                       :epoch 0
                       :epoch-to-messages {0 #{"msg-ep0"}}
                       :epoch-to-message-roles {0 {"msg-ep0" :gossip}})
          s3 (loop [s state step 0]
               (if (>= step 3) s
                   (recur (:state (sm/handle-event s {:type :tick :rng (java.util.Random. 42)})) (inc step))))]
      (is (= 3 (:epoch s3)))
      (is (nil? (get-in s3 [:epoch-to-messages 0])) "Epoch 0 active messages pruned past TTL")
      (is (= #{"msg-ep0"} (get-in s3 [:frozen-epoch-messages 0])) "Epoch 0 frozen messages retained within retention window (4)")
      (is (= {"msg-ep0" :gossip} (get-in s3 [:frozen-epoch-message-roles 0])) "Epoch 0 frozen roles retained within retention window (4)")
      (let [s5 (loop [s s3 step 3]
                 (if (>= step 5) s
                     (recur (:state (sm/handle-event s {:type :tick :rng (java.util.Random. 42)})) (inc step))))]
        (is (= 5 (:epoch s5)))
        (is (nil? (get-in s5 [:frozen-epoch-messages 0])) "Epoch 0 frozen messages evicted past retention window (4)")
        (is (nil? (get-in s5 [:frozen-epoch-message-roles 0])) "Epoch 0 frozen roles evicted past retention window (4)")))))

(deftest test-tick-empty-recipient-pools-do-not-accumulate-mint-dust
  (testing "Empty validator and mesh pools produce zero mint-dust and do not bank emission reservoir"
    (let [t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          cfg (assoc config/default-config
                     :treasury-pubkey t-pub
                     :treasury-privkey t-priv
                     :treasury-trailing-epochs 1
                     :validators []
                     :mesh-nodes {})
          s0 (assoc (sm/init-state [] "my-node" cfg)
                    :epoch 0
                    :epoch-burns {0 1000})
          t1-res (sm/handle-event s0 {:type :tick :rng (java.util.Random. 42)})
          s1 (:state t1-res)]
      (is (= 1 (:epoch s1)))
      (is (= 0 (:total-minted s1)))
      (is (= 0 (:mint-dust s1)))
      (is (= 0 (get-in s1 [:epoch-mint-dust 1])))

      (let [val-pub1 "v1"
            mesh-pub "m1"
            s1-active (-> s1
                          (assoc :validators [val-pub1])
                          (assoc :mesh-nodes {mesh-pub 1.0})
                          (assoc-in [:epoch-burns 1] 1000))
            t2-res (sm/handle-event s1-active {:type :tick :rng (java.util.Random. 42)})
            s2 (:state t2-res)]
        (is (= 2 (:epoch s2)))
        (is (= 500 (:total-minted s2)) "Total minted reflects ONLY epoch 1 demand gate (500), not banked epoch 0 (1000)!")
        (is (= 0 (:mint-dust s2)))))))

(defspec ^{:doc "Property: Failed vouchers are strictly tracked in :failed-vouchers when callee balance is depleted mid-epoch, and settlement fails closed"}
  prop-failed-voucher-tracking-and-isolation 50
  (prop/for-all [price (gen/choose 1 50)
                 seq-num (gen/choose 1 10)
                 callee-bal (gen/choose 0 500)]
                (let [cum-debit (* seq-num price)
                      callee-kp (crypto/generate-keypair)
                      callee-pub (basalt/bytes->hex (:public callee-kp))
                      callee-priv (:private callee-kp)
                      home-node "home-node"
                      candidates [{:node-id home-node :price price}]
                      funded-ledger {callee-pub (account/map->AccountState {:balance (+ cum-debit 1000) :seq 0 :deps []})
                                     home-node (account/map->AccountState {:balance 50 :seq 0 :deps []})}
                      init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger funded-ledger))
                                 (assoc :epoch 0)
                                 (assoc-in [:home-sets [callee-pub 0]]
                                           {:status :ok :home-nodes candidates :price price :degraded? false}))
                      ev {:type :receive-offer-header
                          :caller "caller"
                          :callee callee-pub
                          :callee-privkey callee-priv
                          :home-node home-node}
                      s1 (reduce (fn [st s]
                                   (:state (sm/handle-event st (assoc ev :seq s :offer-hash (str "hash-failed-v-" s)))))
                                 init-s
                                 (range 1 (inc seq-num)))
                      mid-state (assoc-in s1 [:ledger callee-pub :balance] callee-bal)
                      post-state (:state (sm/handle-event mid-state {:type :tick :rng (java.util.Random. 17)}))
                      post-ledger (:ledger post-state)]
                  (if (< callee-bal cum-debit)
                    (and (= callee-bal (:balance (get post-ledger callee-pub)))
                         (= 50 (:balance (get post-ledger home-node)))
                         (not (contains? (:settled-voucher-tuples post-state) [callee-pub home-node 0]))
                         (= 1 (count (:failed-vouchers post-state)))
                         (= :insufficient-callee-balance (:reason (first (:failed-vouchers post-state)))))
                    (and (= (- callee-bal cum-debit) (:balance (get post-ledger callee-pub)))
                         (= (+ 50 cum-debit) (:balance (get post-ledger home-node)))
                         (contains? (:settled-voucher-tuples post-state) [callee-pub home-node 0])
                         (= 0 (count (:failed-vouchers post-state))))))))

(defspec ^{:doc "Property: Frozen epoch logs are strictly bounded by :frozen-log-retention-epochs"}
  prop-bounded-frozen-log-retention 50
  (prop/for-all [retention (gen/choose 2 6)
                 ticks (gen/choose 5 15)]
                (let [cfg (assoc config/default-config
                                 :gossip-ttl-epochs 1
                                 :frozen-log-retention-epochs retention)
                      init-s (assoc (sm/init-state [] "my-node" cfg)
                                    :epoch 0
                                    :epoch-to-messages {0 #{"m0"}}
                                    :epoch-to-message-roles {0 {"m0" :gossip}})
                      final-s (loop [s init-s step 0]
                                (if (>= step ticks) s
                                    (let [curr-ep (:epoch s)
                                          s-with-msg (-> s
                                                         (assoc-in [:epoch-to-messages curr-ep] #{(str "m" curr-ep)})
                                                         (assoc-in [:epoch-to-message-roles curr-ep] {(str "m" curr-ep) :gossip}))]
                                      (recur (:state (sm/handle-event s-with-msg {:type :tick :rng (java.util.Random. step)}))
                                             (inc step)))))
                      final-ep (:epoch final-s)
                      cutoff (- final-ep retention)
                      frozen-eps (keys (:frozen-epoch-messages final-s))
                      frozen-role-eps (keys (:frozen-epoch-message-roles final-s))]
                  (and (every? #(>= % cutoff) frozen-eps)
                       (every? #(>= % cutoff) frozen-role-eps)
                       (<= (count frozen-eps) (inc retention))
                       (<= (count frozen-role-eps) (inc retention))))))

(deftest test-submit-transcript-ignores-event-supplied-roles
  (testing "handle-submit-transcript completely ignores event-supplied roles and uses local frozen roles"
    (let [kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          honest-roles [["m1" :echo]]
          valid-half (attestation/create-transcript 0 pub-a pub-b honest-roles (:private kp-a))
          state (assoc (sm/init-state [] pub-a)
                       :frozen-epoch-messages {0 #{"m1"}}
                       :frozen-epoch-message-roles {0 {"m1" :echo}})]
      ;; 1. Adversary passes forged :frozen-log-roles, :message-roles, and :roles trying to force :gossip
      (let [res (sm/handle-event state {:type :submit-transcript
                                        :transcript valid-half
                                        :frozen-log-roles [["m1" :gossip]]
                                        :message-roles [["m1" :gossip]]
                                        :roles [["m1" :gossip]]})
            new-state (:state res)]
        (is (= 1 (get-in new-state [:fault-strikes pub-b]))
            "Counterparty B is struck because authoritative role is :echo from local state, ignoring forged event roles"))
      ;; 2. Transcript with forged role matching event-supplied role is rejected
      (let [forged-half (attestation/create-transcript 0 pub-a pub-b [["m1" :gossip]] (:private kp-a))
            res (sm/handle-event state {:type :submit-transcript
                                        :transcript forged-half
                                        :frozen-log-roles [["m1" :gossip]]})
            new-state (:state res)]
        (is (= {} (:fault-strikes new-state))
            "Forged transcript is rejected against local authoritative :echo role despite matching forged event roles"))
      ;; 3. Message in local-frozen-ids without entry in local-frozen-roles defaults to :gossip
      (let [state-unmapped (assoc (sm/init-state [] pub-a)
                                  :frozen-epoch-messages {0 #{"m2"}})
            gossip-half (attestation/create-transcript 0 pub-a pub-b [["m2" :gossip]] (:private kp-a))
            res (sm/handle-event state-unmapped {:type :submit-transcript
                                                 :transcript gossip-half
                                                 :frozen-log-roles [["m2" :ready]]})
            new-state (:state res)]
        (is (= 1 (get-in new-state [:fault-strikes pub-b]))
            "Unmapped message defaults to :gossip, striking B on honest gossip transcript despite event :ready")))))

(defspec ^{:doc "Property: Event-supplied roles are completely ignored in handle-submit-transcript"}
  prop-submit-transcript-forged-event-roles-ignored 50
  (prop/for-all [role-idx (gen/choose 0 2)
                 forged-role-idx (gen/choose 0 2)]
                (let [roles-pool [:gossip :echo :ready]
                      honest-role (nth roles-pool role-idx)
                      forged-role (nth roles-pool forged-role-idx)
                      kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      honest-roles [["m1" honest-role]]
                      valid-half (attestation/create-transcript 0 pub-a pub-b honest-roles (:private kp-a))
                      state (assoc (sm/init-state [] pub-a)
                                   :frozen-epoch-messages {0 #{"m1"}}
                                   :frozen-epoch-message-roles {0 {"m1" honest-role}})
                      res-clean (sm/handle-event state {:type :submit-transcript :transcript valid-half})
                      res-forged (sm/handle-event state {:type :submit-transcript
                                                         :transcript valid-half
                                                         :frozen-log-roles [["m1" forged-role]]
                                                         :message-roles [["m1" forged-role]]
                                                         :roles [["m1" forged-role]]})]
                  (= (:fault-strikes (:state res-clean))
                     (:fault-strikes (:state res-forged))))))

(deftest test-state-machine-unclaimed-mint-initialization-and-accumulation
  (testing "init-state initializes :unclaimed-mint to 0 and :epoch-unclaimed-mint to {}"
    (let [st (sm/init-state [] "my-node")]
      (is (= 0 (:unclaimed-mint st)))
      (is (= {} (:epoch-unclaimed-mint st)))))

  (testing "handle-tick with empty recipient pools accumulates :unclaimed-mint and records :epoch-unclaimed-mint"
    (let [cfg (assoc config/default-config
                     :treasury-trailing-epochs 1)
          t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          s0 (assoc (sm/init-state [] "my-node" cfg)
                    :epoch 0
                    :treasury-pubkey t-pub
                    :treasury-privkey t-priv
                    :epoch-burns {0 1000})
          ;; Tick from 0 to 1 with empty recipient pools
          t1-res (sm/handle-event s0 {:type :tick :rng (java.util.Random. 1)})
          s1 (:state t1-res)]
      (is (= 1 (:epoch s1)))
      (is (= 500 (:unclaimed-mint s1)))
      (is (= 500 (get-in s1 [:epoch-unclaimed-mint 1])))
      (is (= 0 (:mint-dust s1)))
      (is (= 0 (:total-minted s1)))
      ;; Tick from 1 to 2 with empty recipient pools and 1000 burn in epoch 1
      (let [s1-with-burn (assoc-in s1 [:epoch-burns 1] 1000)
            t2-res (sm/handle-event s1-with-burn {:type :tick :rng (java.util.Random. 2)})
            s2 (:state t2-res)]
        (is (= 2 (:epoch s2)))
        (is (= 1000 (:unclaimed-mint s2)))
        (is (= 500 (get-in s2 [:epoch-unclaimed-mint 2])))
        (is (= 0 (:mint-dust s2)))))))

(defspec ^{:doc "Property: State machine :unclaimed-mint strictly equals the sum of :epoch-unclaimed-mint"}
  prop-state-machine-unclaimed-mint-persistence 50
  (prop/for-all [burn (gen/choose 100 5000)
                 ticks (gen/choose 2 5)]
                (let [t-kp (crypto/generate-keypair)
                      t-pub (basalt/bytes->hex (:public t-kp))
                      t-priv (:private t-kp)
                      cfg (assoc config/default-config :treasury-trailing-epochs 1)
                      init-s (assoc (sm/init-state [] "my-node" cfg)
                                    :epoch 0
                                    :treasury-pubkey t-pub
                                    :treasury-privkey t-priv)
                      final-s (loop [s init-s step 0]
                                (if (>= step ticks) s
                                    (let [curr-ep (:epoch s)
                                          s-burned (assoc-in s [:epoch-burns curr-ep] burn)
                                          t-res (sm/handle-event s-burned {:type :tick :rng (java.util.Random. step)})]
                                      (recur (:state t-res) (inc step)))))]
                  (and (= (:unclaimed-mint final-s)
                          (reduce + 0 (vals (:epoch-unclaimed-mint final-s))))
                       (every? #(integer? %) (vals (:epoch-unclaimed-mint final-s)))))))

(deftest test-voucher-settlement-unpaid-retry-mechanism
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        home-node "home-node"
        candidates [{:node-id home-node :price 20}]
        price 20
        ;; Callee funded with 100 initially, then drained to 10 mid-epoch
        ledger {callee-pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                home-node (account/map->AccountState {:balance 50 :seq 0 :deps []})}
        init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                   (assoc :epoch 0)
                   (assoc-in [:home-sets [callee-pub 0]]
                             {:status :ok :home-nodes candidates :price price :degraded? false}))
        ev {:type :receive-offer-header
            :caller "caller"
            :callee callee-pub
            :callee-privkey callee-priv
            :home-node home-node
            :offer-hash "hash-retry-1"
            :seq 1}
        s1 (:state (sm/handle-event init-s ev))
        underfunded-s1 (assoc-in s1 [:ledger callee-pub :balance] 10)]
    (is (= 1 (count (:pending-vouchers s1))))

    (testing "Tick 0 -> 1 fails closed, records failed voucher, and retains unpaid voucher in :pending-vouchers"
      (let [t1-res (sm/handle-event underfunded-s1 {:type :tick :rng (java.util.Random. 42)})
            s-ep1 (:state t1-res)
            ledger-ep1 (:ledger s-ep1)]
        (is (= 1 (:epoch s-ep1)))
        (is (= 10 (:balance (get ledger-ep1 callee-pub))))
        (is (= 50 (:balance (get ledger-ep1 home-node))))
        (is (not (contains? (:settled-voucher-tuples s-ep1) [callee-pub home-node 0])))
        (is (= 1 (count (:failed-vouchers s-ep1))))
        (let [failed (first (:failed-vouchers s-ep1))]
          (is (= :insufficient-callee-balance (:reason failed)))
          (is (= 0 (:epoch failed)))
          (is (= 20 (:debit failed))))
        (is (= 1 (count (:pending-vouchers s-ep1))))
        (is (= 0 (:epoch (first (:pending-vouchers s-ep1)))))

        (testing "Tick 1 -> 2 retries and settles epoch 0 voucher when callee is topped up in epoch 1"
          (let [topped-s (assoc-in s-ep1 [:ledger callee-pub :balance] 100)
                t2-res (sm/handle-event topped-s {:type :tick :rng (java.util.Random. 43)})
                s-ep2 (:state t2-res)
                ledger-ep2 (:ledger s-ep2)]
            (is (= 2 (:epoch s-ep2)))
            (is (= 80 (:balance (get ledger-ep2 callee-pub))))
            (is (= 70 (:balance (get ledger-ep2 home-node))))
            (is (contains? (:settled-voucher-tuples s-ep2) [callee-pub home-node 0]))
            (is (empty? (:pending-vouchers s-ep2)))
            (is (empty? (:failed-vouchers s-ep2)))))))))

(deftest test-voucher-settlement-corrupted-voucher-not-retried
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        home-node "home-node"
        ledger {callee-pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                home-node (account/map->AccountState {:balance 50 :seq 0 :deps []})}
        init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger ledger))
                   (assoc :epoch 0)
                   (assoc-in [:home-sets [callee-pub 0]]
                             {:status :ok :home-nodes [{:node-id home-node :price 20}] :price 20 :degraded? false}))
        corrupted-ack {:callee callee-pub
                       :home-node home-node
                       :epoch 0
                       :seq 1
                       :cumulative-debit 20
                       :offer-hash "corrupted-hash"
                       :signature (basalt/bytes->hex (byte-array 64))}
        s-with-corrupted (assoc init-s :pending-vouchers [corrupted-ack])
        t1-res (sm/handle-event s-with-corrupted {:type :tick :rng (java.util.Random. 42)})
        s-ep1 (:state t1-res)]
    (testing "Corrupted voucher records failure in :failed-vouchers and is NOT retained in :pending-vouchers"
      (is (= 1 (count (:failed-vouchers s-ep1))))
      (is (= 0 (:epoch (first (:failed-vouchers s-ep1)))))
      (is (= :invalid-signature (:reason (first (:failed-vouchers s-ep1)))))
      (is (empty? (:pending-vouchers s-ep1))))))

(deftest test-voucher-settlement-expired-voucher-evicted
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        home-node "home-node"
        candidates [{:node-id home-node :price 20}]
        cfg (assoc config/default-config :frozen-log-retention-epochs 2)
        ledger {callee-pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                home-node (account/map->AccountState {:balance 50 :seq 0 :deps []})}
        init-s (-> (sm/init-state [] "my-node" (assoc cfg :genesis-ledger ledger))
                   (assoc :epoch 0)
                   (assoc-in [:home-sets [callee-pub 0]]
                             {:status :ok :home-nodes candidates :price 20 :degraded? false}))
        ev {:type :receive-offer-header
            :caller "caller"
            :callee callee-pub
            :callee-privkey callee-priv
            :home-node home-node
            :offer-hash "hash-exp-1"
            :seq 1}
        s1 (:state (sm/handle-event init-s ev))
        underfunded-s1 (assoc-in s1 [:ledger callee-pub :balance] 10)
        ;; Tick 0 -> 1: closing-epoch 0, min-epoch 0. Retained.
        s-ep1 (:state (sm/handle-event underfunded-s1 {:type :tick :rng (java.util.Random. 1)}))
        ;; Tick 1 -> 2: closing-epoch 1, min-epoch 0. Retained.
        s-ep2 (:state (sm/handle-event s-ep1 {:type :tick :rng (java.util.Random. 2)}))
        ;; Tick 2 -> 3: closing-epoch 2, min-epoch 0. Retained.
        s-ep3 (:state (sm/handle-event s-ep2 {:type :tick :rng (java.util.Random. 3)}))
        ;; Tick 3 -> 4: closing-epoch 3, min-epoch 1. Epoch 0 is now older than min-epoch 1: evicted!
        s-ep4 (:state (sm/handle-event s-ep3 {:type :tick :rng (java.util.Random. 4)}))
        ;; Tick 4 -> 5: closing-epoch 4, min-epoch 2. Evicted voucher was already removed.
        s-ep5 (:state (sm/handle-event s-ep4 {:type :tick :rng (java.util.Random. 5)}))]
    (testing "Underfunded voucher retained within retention window"
      (is (= 1 (count (:pending-vouchers s-ep1))))
      (is (= 1 (count (:pending-vouchers s-ep2))))
      (is (= 1 (count (:pending-vouchers s-ep3)))))
    (testing "Underfunded voucher evicted once older than retention epochs and recorded in :failed-vouchers"
      (is (empty? (:pending-vouchers s-ep4)))
      (is (= 1 (count (:failed-vouchers s-ep4))))
      (is (= 0 (:epoch (first (:failed-vouchers s-ep4)))))
      (is (= :expired-epoch (:reason (first (:failed-vouchers s-ep4))))))
    (testing "Evicted voucher is not re-processed on subsequent ticks"
      (is (empty? (:pending-vouchers s-ep5)))
      (is (empty? (:failed-vouchers s-ep5))))))

(deftest test-bounded-rendezvous-state-retention
  (let [cfg (assoc config/default-config :frozen-log-retention-epochs 2)
        init-s (assoc (sm/init-state [] "my-node" cfg)
                      :epoch 3
                      :home-sets {["callee" 0] {:price 10}
                                  ["callee" 1] {:price 10}
                                  ["callee" 2] {:price 10}
                                  ["callee" 3] {:price 10}}
                      :voucher-seqs {["callee" "home" 0] 1
                                     ["callee" "home" 1] 2
                                     ["callee" "home" 2] 3
                                     ["callee" "home" 3] 4})
        ;; On tick from epoch 3 -> 4: closing-epoch = 3, retention = 2, rdv-cutoff = (- 3 2) = 1.
        ;; Epoch 0 is < 1, so it should be pruned. Epochs 1, 2, 3 should remain.
        res (sm/handle-event init-s {:type :tick :rng (java.util.Random. 42)})
        s (:state res)]
    (testing "Prunes :home-sets and :voucher-seqs strictly older than rdv-cutoff (- closing-epoch retention)"
      (is (nil? (get-in s [:home-sets ["callee" 0]])))
      (is (some? (get-in s [:home-sets ["callee" 1]])))
      (is (some? (get-in s [:home-sets ["callee" 2]])))
      (is (some? (get-in s [:home-sets ["callee" 3]])))
      (is (nil? (get-in s [:voucher-seqs ["callee" "home" 0]])))
      (is (= 2 (get-in s [:voucher-seqs ["callee" "home" 1]])))
      (is (= 3 (get-in s [:voucher-seqs ["callee" "home" 2]])))
      (is (= 4 (get-in s [:voucher-seqs ["callee" "home" 3]]))))))

(defspec ^{:doc "Property: :home-sets and :voucher-seqs are strictly bounded by :frozen-log-retention-epochs"}
  prop-bounded-rendezvous-state-retention 50
  (prop/for-all [retention (gen/choose 2 5)
                 ticks (gen/choose 5 12)]
                (let [cfg (assoc config/default-config
                                 :frozen-log-retention-epochs retention)
                      init-s (sm/init-state [] "my-node" cfg)
                      final-s (loop [s (assoc init-s :epoch 0) step 0]
                                (if (>= step ticks)
                                  s
                                  (let [curr-ep (:epoch s)
                                        s-with-rdv (-> s
                                                       (assoc-in [:home-sets [(str "c-" curr-ep) curr-ep]] {:price 10})
                                                       (assoc-in [:voucher-seqs [(str "c-" curr-ep) "home" curr-ep]] 1))]
                                    (recur (:state (sm/handle-event s-with-rdv {:type :tick :rng (java.util.Random. step)}))
                                           (inc step)))))
                      final-ep (:epoch final-s)
                      closing-ep (dec final-ep)
                      cutoff (- closing-ep retention)
                      hs-eps (map second (keys (:home-sets final-s)))
                      vs-eps (map #(nth % 2) (keys (:voucher-seqs final-s)))]
                  (and (every? #(>= % cutoff) hs-eps)
                       (every? #(>= % cutoff) vs-eps)
                       (<= (count (:home-sets final-s)) (+ retention 2))
                       (<= (count (:voucher-seqs final-s)) (+ retention 2))))))

(defspec ^{:doc "Property: Valid underfunded voucher is retained across ticks and settled upon funding"}
  prop-unpaid-voucher-retry-settlement 50
  (prop/for-all [price (gen/choose 1 50)
                 seq-num (gen/choose 1 5)]
                (let [cum-debit (* seq-num price)
                      callee-kp (crypto/generate-keypair)
                      callee-pub (basalt/bytes->hex (:public callee-kp))
                      callee-priv (:private callee-kp)
                      home-node "home-node"
                      candidates [{:node-id home-node :price price}]
                      underfunded-bal (max 0 (- cum-debit 1))
                      funded-ledger {callee-pub (account/map->AccountState {:balance (+ cum-debit 1000) :seq 0 :deps []})
                                     home-node (account/map->AccountState {:balance 50 :seq 0 :deps []})}
                      init-s (-> (sm/init-state [] "my-node" (assoc config/default-config :genesis-ledger funded-ledger))
                                 (assoc :epoch 0)
                                 (assoc-in [:home-sets [callee-pub 0]]
                                           {:status :ok :home-nodes candidates :price price :degraded? false}))
                      ev {:type :receive-offer-header
                          :caller "caller"
                          :callee callee-pub
                          :callee-privkey callee-priv
                          :home-node home-node}
                      s1 (reduce (fn [st s]
                                   (:state (sm/handle-event st (assoc ev :seq s :offer-hash (str "hash-retry-" s)))))
                                 init-s
                                 (range 1 (inc seq-num)))
                      underfunded-s (assoc-in s1 [:ledger callee-pub :balance] underfunded-bal)
                      s-ep1 (:state (sm/handle-event underfunded-s {:type :tick :rng (java.util.Random. 17)}))
                      topped-s (assoc-in s-ep1 [:ledger callee-pub :balance] (+ cum-debit 200))
                      s-ep2 (:state (sm/handle-event topped-s {:type :tick :rng (java.util.Random. 18)}))
                      ledger-ep2 (:ledger s-ep2)]
                  (and (= 1 (count (:pending-vouchers s-ep1)))
                       (= underfunded-bal (:balance (get-in s-ep1 [:ledger callee-pub])))
                       (not (contains? (:settled-voucher-tuples s-ep1) [callee-pub home-node 0]))
                       (= 200 (:balance (get ledger-ep2 callee-pub)))
                       (= (+ 50 cum-debit) (:balance (get ledger-ep2 home-node)))
                       (contains? (:settled-voucher-tuples s-ep2) [callee-pub home-node 0])
                       (empty? (:pending-vouchers s-ep2))
                       (empty? (:failed-vouchers s-ep2))))))

(deftest test-devnet-config-and-unified-3node-cluster
  (testing "devnet-config parameters are tuned for 3-node Genesis Devnet cluster"
    (is (= 10000 (:epoch-length-ms config/devnet-config)))
    (is (= 10000 (:tick-interval-ms config/devnet-config)))
    (is (= 2 (:murmur-k config/devnet-config)))
    (is (= 10 (:basalt-max-view-size config/devnet-config)))
    (is (= 2 (:echo-sample-size config/devnet-config)))
    (is (= 2 (:echo-threshold config/devnet-config)))
    (is (= 2 (:ready-sample-size config/devnet-config)))
    (is (= 1 (:ready-threshold config/devnet-config)))
    (is (= 2 (:delivery-sample-size config/devnet-config)))
    (is (= 2 (:delivery-threshold config/devnet-config))))

  (testing "3-node unified state machine cluster drives Streamlet block proposals, quorum, and finalization"
    (let [kp0 (crypto/generate-keypair)
          kp1 (crypto/generate-keypair)
          kp2 (crypto/generate-keypair)
          raw-nodes [{:kp kp0 :pub (basalt/bytes->hex (:public kp0))}
                     {:kp kp1 :pub (basalt/bytes->hex (:public kp1))}
                     {:kp kp2 :pub (basalt/bytes->hex (:public kp2))}]
          sorted-nodes (vec (sort-by :pub raw-nodes))
          node0 (nth sorted-nodes 0)
          node1 (nth sorted-nodes 1)
          node2 (nth sorted-nodes 2)
          pub0 (:pub node0)
          pub1 (:pub node1)
          pub2 (:pub node2)
          peers-map {pub0 (:public (:kp node0))
                     pub1 (:public (:kp node1))
                     pub2 (:public (:kp node2))}
          cfg (assoc config/devnet-config :peers-map peers-map)
          init-s0 (sm/init-state [] pub0 (assoc cfg :keypair (:kp node0)))
          init-s1 (sm/init-state [] pub1 (assoc cfg :keypair (:kp node1)))
          init-s2 (sm/init-state [] pub2 (assoc cfg :keypair (:kp node2)))]

      (testing "init-state sets Streamlet BFT fields"
        (is (= {} (:blocks init-s0)))
        (is (= #{} (:notarized-blocks init-s0)))
        (is (= #{} (:finalized-blocks init-s0)))
        (is (= {} (:block-votes init-s0)))
        (is (= #{} (:voted-epochs init-s0)))
        (is (= "genesis" (:head-hash init-s0)))
        (is (= [] (:mempool init-s0)))
        (is (= peers-map (:peers-map init-s0)))
        (is (= (:kp node0) (:keypair init-s0))))

      ;; Epoch 1: Proposer is index (mod 1 3) = 1 -> node1
      (let [t1-res1 (sm/handle-event init-s1 {:type :tick :rng (java.util.Random. 1)})
            s1-ep1 (:state t1-res1)
            cmds1-ep1 (:commands t1-res1)
            t1-res0 (sm/handle-event init-s0 {:type :tick :rng (java.util.Random. 1)})
            s0-ep1 (:state t1-res0)
            t1-res2 (sm/handle-event init-s2 {:type :tick :rng (java.util.Random. 1)})
            s2-ep1 (:state t1-res2)
            prop1-cmd (first (filter #(= :send-propose (:type %)) cmds1-ep1))
            vote1-cmd (first (filter #(= :send-vote (:type %)) cmds1-ep1))
            b1 (:block prop1-cmd)
            h1 (streamlet/hash-block b1)
            v1 (:vote vote1-cmd)]
        (is (some? prop1-cmd))
        (is (some? vote1-cmd))
        (is (= 1 (:epoch b1)))
        (is (= "genesis" (:parent-hash b1)))
        (is (= pub1 (:proposer b1)))

        ;; Peers receive proposal and vote
        (let [p0-res (sm/handle-event s0-ep1 {:type :receive-propose :block b1 :sender pub1})
              v0 (:vote (first (filter #(= :send-vote (:type %)) (:commands p0-res))))
              s0-notarized (:state (sm/handle-event (:state p0-res) {:type :receive-vote :vote v1 :sender pub1}))
              s1-notarized (:state (sm/handle-event s1-ep1 {:type :receive-vote :vote v0 :sender pub0}))
              p2-res (sm/handle-event s2-ep1 {:type :receive-propose :block b1 :sender pub1})
              s2-notarized (:state (sm/handle-event (:state p2-res) {:type :receive-vote :vote v1 :sender pub1}))]
          (is (contains? (:notarized-blocks s0-notarized) h1))
          (is (contains? (:notarized-blocks s1-notarized) h1))
          (is (contains? (:notarized-blocks s2-notarized) h1))

          ;; Epoch 2: Proposer is index (mod 2 3) = 2 -> node2
          (let [t2-res2 (sm/handle-event s2-notarized {:type :tick :rng (java.util.Random. 2)})
                s2-ep2 (:state t2-res2)
                b2-prop (first (filter #(= :send-propose (:type %)) (:commands t2-res2)))
                b2-vote (first (filter #(= :send-vote (:type %)) (:commands t2-res2)))
                b2 (:block b2-prop)
                h2 (streamlet/hash-block b2)
                v2 (:vote b2-vote)
                s0-ep2 (:state (sm/handle-event s0-notarized {:type :tick :rng (java.util.Random. 2)}))
                s1-ep2 (:state (sm/handle-event s1-notarized {:type :tick :rng (java.util.Random. 2)}))
                p0-res2 (sm/handle-event s0-ep2 {:type :receive-propose :block b2 :sender pub2})
                v0-ep2 (:vote (first (filter #(= :send-vote (:type %)) (:commands p0-res2))))
                s0-notarized2 (:state (sm/handle-event (:state p0-res2) {:type :receive-vote :vote v2 :sender pub2}))
                s2-notarized2 (:state (sm/handle-event s2-ep2 {:type :receive-vote :vote v0-ep2 :sender pub0}))
                p1-res2 (sm/handle-event s1-ep2 {:type :receive-propose :block b2 :sender pub2})
                s1-notarized2 (:state (sm/handle-event (:state p1-res2) {:type :receive-vote :vote v2 :sender pub2}))]
            (is (some? b2-prop))
            (is (= 2 (:epoch b2)))
            (is (= h1 (:parent-hash b2)))
            (is (contains? (:notarized-blocks s0-notarized2) h2))
            (is (contains? (:notarized-blocks s1-notarized2) h2))
            (is (contains? (:notarized-blocks s2-notarized2) h2))

            ;; Epoch 3: Proposer is index (mod 3 3) = 0 -> node0
            (let [t3-res0 (sm/handle-event s0-notarized2 {:type :tick :rng (java.util.Random. 3)})
                  s0-ep3 (:state t3-res0)
                  b3-prop (first (filter #(= :send-propose (:type %)) (:commands t3-res0)))
                  b3-vote (first (filter #(= :send-vote (:type %)) (:commands t3-res0)))
                  b3 (:block b3-prop)
                  h3 (streamlet/hash-block b3)
                  v0-ep3 (:vote b3-vote)
                  s1-ep3 (:state (sm/handle-event s1-notarized2 {:type :tick :rng (java.util.Random. 3)}))
                  p1-res3 (sm/handle-event s1-ep3 {:type :receive-propose :block b3 :sender pub0})
                  v1-ep3 (:vote (first (filter #(= :send-vote (:type %)) (:commands p1-res3))))
                  s0-notarized3 (:state (sm/handle-event s0-ep3 {:type :receive-vote :vote v1-ep3 :sender pub1}))
                  s1-notarized3 (:state (sm/handle-event (:state p1-res3) {:type :receive-vote :vote v0-ep3 :sender pub0}))]
              (is (some? b3-prop))
              (is (= 3 (:epoch b3)))
              (is (= h2 (:parent-hash b3)))
              (is (contains? (:notarized-blocks s0-notarized3) h3))

              ;; Finalization: 3 consecutive epochs (1, 2, 3) finalizes middle block h2 and ancestors h1
              (is (contains? (:finalized-blocks s0-notarized3) h2))
              (is (contains? (:finalized-blocks s0-notarized3) h1))
              (is (contains? (:finalized-blocks s1-notarized3) h2))
              (is (contains? (:finalized-blocks s1-notarized3) h1))

              ;; Epoch entropy is derived from finalized blocks
              (let [entropy0 (sm/derive-epoch-entropy s0-notarized3 cfg)
                    entropy1 (sm/derive-epoch-entropy s1-notarized3 cfg)]
                (is (not= "genesis" entropy0))
                (is (= entropy0 entropy1))
                (is (contains? (:finalized-blocks s0-notarized3) entropy0))))))))))

(defspec ^{:doc "Property: Unified state machine deterministically notarizes proposed blocks upon 2n/3 quorum and never with < 2 votes"}
  prop-unified-streamlet-state-machine-quorum 50
  (prop/for-all [epoch-num (gen/choose 1 20)
                 proposer-offset (gen/choose 0 2)]
                (let [kp0 (crypto/generate-keypair)
                      kp1 (crypto/generate-keypair)
                      kp2 (crypto/generate-keypair)
                      kps [kp0 kp1 kp2]
                      pubs (mapv #(basalt/bytes->hex (:public %)) kps)
                      sorted-indices (sort-by #(nth pubs %) (range 3))
                      sorted-kps (mapv #(nth kps %) sorted-indices)
                      sorted-pubs (mapv #(nth pubs %) sorted-indices)
                      peers-map (into {} (map (fn [i] [(nth sorted-pubs i) (:public (nth sorted-kps i))]) (range 3)))
                      cfg (assoc config/devnet-config :peers-map peers-map)
                      proposer-idx (mod epoch-num 3)
                      proposer-pub (nth sorted-pubs proposer-idx)
                      proposer-kp (nth sorted-kps proposer-idx)
                      obs-idx (mod (+ proposer-idx 1 proposer-offset) 3)
                      obs-pub (nth sorted-pubs obs-idx)
                      obs-kp (nth sorted-kps obs-idx)
                      other-idx (first (filter #(and (not= % proposer-idx) (not= % obs-idx)) (range 3)))
                      other-pub (nth sorted-pubs other-idx)
                      other-kp (nth sorted-kps other-idx)
                      obs-state (assoc (sm/init-state [] obs-pub (assoc cfg :keypair obs-kp))
                                       :epoch epoch-num)
                      raw-block (streamlet/->Block epoch-num "genesis" [] proposer-pub)
                      block (streamlet/sign-block raw-block (:private proposer-kp))
                      b-hash (streamlet/hash-block block)
                      s-unsigned (:state (sm/handle-event obs-state {:type :receive-propose :block raw-block :sender proposer-pub}))
                      wrong-proposer-raw (streamlet/->Block epoch-num "genesis" [] other-pub)
                      wrong-proposer-block (streamlet/sign-block wrong-proposer-raw (:private other-kp))
                      s-wrong (:state (sm/handle-event obs-state {:type :receive-propose :block wrong-proposer-block :sender other-pub}))
                      res-prop (sm/handle-event obs-state {:type :receive-propose :block block :sender proposer-pub})
                      s1 (:state res-prop)
                      sybil-kp (crypto/generate-keypair)
                      sybil-pub (basalt/bytes->hex (:public sybil-kp))
                      sybil-sig (streamlet/bytes->hex (crypto/sign (:private sybil-kp) (.getBytes ^String b-hash "UTF-8")))
                      sybil-vote (streamlet/->Vote b-hash epoch-num sybil-sig)
                      s-sybil (:state (sm/handle-event s1 {:type :receive-vote :vote sybil-vote :sender sybil-pub}))
                      corrupted-vote (streamlet/->Vote b-hash epoch-num (streamlet/bytes->hex (byte-array 64)))
                      s-corrupt (:state (sm/handle-event s1 {:type :receive-vote :vote corrupted-vote :sender other-pub}))
                      valid-sig (streamlet/bytes->hex (crypto/sign (:private other-kp) (.getBytes ^String b-hash "UTF-8")))
                      valid-vote (streamlet/->Vote b-hash epoch-num valid-sig)
                      s2 (:state (sm/handle-event s1 {:type :receive-vote :vote valid-vote :sender other-pub}))]
                  (and (= obs-state s-unsigned)
                       (= obs-state s-wrong)
                       (= s1 s-sybil)
                       (if (= obs-idx proposer-idx)
                         (and (not (contains? (:notarized-blocks s1) b-hash))
                              (not (contains? (:notarized-blocks s-corrupt) b-hash))
                              (contains? (:notarized-blocks s2) b-hash))
                         (and (= 1 (count (get-in s1 [:block-votes b-hash])))
                              (not (contains? (:notarized-blocks s1) b-hash))
                              (= 1 (count (get-in s-corrupt [:block-votes b-hash])))
                              (not (contains? (:notarized-blocks s-corrupt) b-hash))
                              (= 2 (count (get-in s2 [:block-votes b-hash])))
                              (contains? (:notarized-blocks s2) b-hash)))))))

(deftest test-tick-with-empty-peers-map-skips-streamlet-propose
  (testing "when :peers-map is empty, :tick advances :epoch without proposing or voting"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          cfg (assoc config/devnet-config :peers-map {} :keypair kp)
          state (assoc (sm/init-state [] pub-hex cfg) :epoch 5)
          res (sm/handle-event state {:type :tick})
          new-state (:state res)
          commands (:commands res)]
      (is (= 6 (:epoch new-state)))
      (is (empty? (filter #(#{:send-propose :send-vote} (:type %)) commands)))
      (is (empty? (:blocks new-state))))))

(deftest test-receive-gossip-ignores-claimed-message-id
  (testing "State machine ignores any claimed or spoofed message-id and derives true id from sha256 of payload"
    (let [kp-a (crypto/generate-keypair)
          sender-a (basalt/bytes->hex (:public kp-a))
          kp-b (crypto/generate-keypair)
          sender-b (basalt/bytes->hex (:public kp-b))
          payload-a (.getBytes "payload-A-data" "UTF-8")
          payload-b (.getBytes "payload-B-data" "UTF-8")
          hash-a (basalt/bytes->hex (crypto/sha256 payload-a))
          hash-b (basalt/bytes->hex (crypto/sha256 payload-b))
          burn 500
          cfg (assoc config/default-config
                     :genesis-ledger {sender-a (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      sender-b (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
          state (assoc (sm/init-state [] "node-local" cfg) :epoch 0)
          ;; Sender A sends payload-a with spoofed message-id = hash-b
          sieve-a (sieve/wrap-message payload-a (:private kp-a) (:public kp-a) burn)
          spoofed-a (assoc sieve-a :message-id hash-b)
          res-a (sm/handle-event state {:type :receive-gossip :message spoofed-a})
          st-a (:state res-a)]
      ;; The state machine records it under hash-a, NOT hash-b
      (is (contains? (:contagion-known-ids st-a) hash-a))
      (is (not (contains? (:contagion-known-ids st-a) hash-b)))
      (is (= burn (get-in st-a [:epoch-burns 0])))
      ;; Sender B subsequently sends payload-b
      (let [sieve-b (sieve/wrap-message payload-b (:private kp-b) (:public kp-b) burn)
            res-b (sm/handle-event st-a {:type :receive-gossip :message sieve-b})
            st-b (:state res-b)]
        ;; Sender B's message is accepted under hash-b and not dropped as duplicate!
        (is (contains? (:contagion-known-ids st-b) hash-b))
        (is (= (* 2 burn) (get-in st-b [:epoch-burns 0])))))))

(deftest test-ttl-pruned-gossip-prevents-pull-and-reburn
  (testing "Gossip message that is TTL-pruned from :messages and :contagion-known-ids is retained in :murmur-cache, preventing re-burn and duplicate pull request"
    (let [kp (crypto/generate-keypair)
          sender (basalt/bytes->hex (:public kp))
          payload (.getBytes "test-ttl-pruned-payload" "UTF-8")
          msg-id (basalt/bytes->hex (crypto/sha256 payload))
          burn 500
          cfg (assoc config/default-config
                     :gossip-ttl-epochs 2
                     :genesis-ledger {sender (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
          state (assoc (sm/init-state [] "node-local" cfg) :epoch 0)
          sieve-msg (sieve/wrap-message payload (:private kp) (:public kp) burn)
          res1 (sm/handle-event state {:type :receive-gossip :message sieve-msg})
          st1 (:state res1)]
      (is (= 9500 (get-in st1 [:ledger sender :balance])))
      (is (contains? (:contagion-known-ids st1) msg-id))
      (is (contains? (get-in st1 [:murmur-cache :set]) msg-id))
      (is (contains? (:messages st1) msg-id))
      (let [st-pruned (reduce (fn [s _] (:state (sm/handle-event s {:type :tick}))) st1 (range 3))]
        (is (> (:epoch st-pruned) 2))
        (is (not (contains? (:messages st-pruned) msg-id)))
        (is (not (contains? (:contagion-known-ids st-pruned) msg-id)))
        (is (not (contains? (get-in st-pruned [:murmur-cache :set]) msg-id)))
        (let [res-summary (sm/handle-event st-pruned {:type :receive-summary :sender "peer-remote" :summary #{msg-id}})]
          (is (empty? (filter (fn [cmd]
                                (and (= :send-pull-request (:type cmd))
                                     (contains? (:missing-ids cmd) msg-id)))
                              (:commands res-summary)))))
        (let [res2 (sm/handle-event st-pruned {:type :receive-gossip :message sieve-msg})
              st2 (:state res2)]
          (is (= 9500 (get-in st2 [:ledger sender :balance])))
          (is (nil? (get-in st2 [:epoch-burns (:epoch st2)]))))))))

(defspec ^{:doc "Property: TTL-pruned gossip messages retained in murmur cache prevent redundant lazy pulls and double burn deduction across subsequent epochs"}
  prop-ttl-pruned-gossip-no-reburn-or-pull 25
  (prop/for-all [initial-balance (gen/choose 1000 5000)
                 burn-amt (gen/choose 100 500)
                 ticks (gen/choose 3 6)]
                (let [kp (crypto/generate-keypair)
                      sender-pub (basalt/bytes->hex (:public kp))
                      payload (.getBytes "prop-ttl-payload" "UTF-8")
                      msg-id (basalt/bytes->hex (crypto/sha256 payload))
                      cfg (assoc config/default-config
                                 :gossip-ttl-epochs 2
                                 :genesis-ledger {sender-pub (account/map->AccountState {:balance initial-balance :seq 0 :deps []})})
                      state (assoc (sm/init-state [] "node-local" cfg) :epoch 0)
                      sieve-msg (sieve/wrap-message payload (:private kp) (:public kp) burn-amt)
                      res1 (sm/handle-event state {:type :receive-gossip :message sieve-msg :rng (java.util.Random. 42)})
                      st1 (:state res1)
                      bal-after-1 (get-in st1 [:ledger sender-pub :balance])
                      st-pruned (reduce (fn [s _] (:state (sm/handle-event s {:type :tick}))) st1 (range ticks))
                      res-summary (sm/handle-event st-pruned {:type :receive-summary :sender "peer-remote" :summary #{msg-id}})
                      res-gossip2 (sm/handle-event st-pruned {:type :receive-gossip :message sieve-msg :rng (java.util.Random. 43)})
                      st2 (:state res-gossip2)
                      bal-after-2 (get-in st2 [:ledger sender-pub :balance])
                      pull-commands (filter (fn [cmd]
                                              (and (= :send-pull-request (:type cmd))
                                                   (contains? (:missing-ids cmd) msg-id)))
                                            (:commands res-summary))]
                  (and (= (- initial-balance burn-amt) bal-after-1)
                       (not (contains? (:messages st-pruned) msg-id))
                       (not (contains? (:contagion-known-ids st-pruned) msg-id))
                       (not (contains? (get-in st-pruned [:murmur-cache :set]) msg-id))
                       (empty? pull-commands)
                       (= bal-after-1 bal-after-2)))))

(defn- exchange-block-and-votes
  "Given current 3-node states [s0 s1 s2], sorted pubs [pub0 pub1 pub2], epoch ep,
   ticks all nodes, distributes proposer's proposal to peers, and exchanges votes."
  [[s0 s1 s2] [pub0 pub1 pub2] ep]
  (let [states [s0 s1 s2]
        proposer-idx (mod ep 3)
        proposer-pub (nth [pub0 pub1 pub2] proposer-idx)
        ;; 1. Tick on all nodes
        tick-results (mapv (fn [st] (sm/handle-event st {:type :tick :rng (java.util.Random. ep)})) states)
        states-after-tick (mapv :state tick-results)
        proposer-res (nth tick-results proposer-idx)
        prop-cmd (first (filter #(= :send-propose (:type %)) (:commands proposer-res)))
        proposer-vote (first (filter #(= :send-vote (:type %)) (:commands proposer-res)))
        block (:block prop-cmd)
        v-prop (:vote proposer-vote)
        ;; 2. Proposer sends proposal to other 2 peers, which vote
        peer-indices (filter #(not= % proposer-idx) [0 1 2])
        prop-deliver-results (reduce (fn [acc idx]
                                       (assoc acc idx (sm/handle-event (nth states-after-tick idx)
                                                                       {:type :receive-propose :block block :sender proposer-pub})))
                                     {}
                                     peer-indices)
        peer-votes (into {} (map (fn [idx]
                                   (let [res (get prop-deliver-results idx)
                                         vote-cmd (first (filter #(= :send-vote (:type %)) (:commands res)))]
                                     [idx (:vote vote-cmd)]))
                                 peer-indices))
        ;; States after receive-propose
        states-with-props (mapv (fn [idx]
                                  (if (= idx proposer-idx)
                                    (nth states-after-tick idx)
                                    (:state (get prop-deliver-results idx))))
                                [0 1 2])
        ;; 3. Distribute votes to everyone
        all-votes (into [[proposer-idx proposer-pub v-prop]]
                        (map (fn [idx] [idx (nth [pub0 pub1 pub2] idx) (get peer-votes idx)]) peer-indices))
        final-states (reduce (fn [curr-states [from-idx from-pub v]]
                               (if-not v
                                 curr-states
                                 (mapv (fn [to-idx]
                                         (if (= to-idx from-idx)
                                           (nth curr-states to-idx)
                                           (:state (sm/handle-event (nth curr-states to-idx)
                                                                    {:type :receive-vote :vote v :sender from-pub}))))
                                       [0 1 2])))
                             states-with-props
                             all-votes)]
    final-states))

(defspec ^{:doc "Property: Simulates a 3-node Streamlet cluster with treasury keys, validators, and funded accounts across skewed events and ticks; verifies all 3 nodes converge to identical ledger, supply, burns, takes, finalized epoch, and burn-map digest upon block finalization."}
  prop-finalized-block-ledger-convergence 50
  (prop/for-all [burn-amt (gen/choose 10 100)
                 intent-amt (gen/choose 10 500)
                 transfer-amt (gen/choose 10 500)]
                (let [kp0 (crypto/generate-keypair)
                      kp1 (crypto/generate-keypair)
                      kp2 (crypto/generate-keypair)
                      kps [kp0 kp1 kp2]
                      pubs (mapv #(basalt/bytes->hex (:public %)) kps)
                      sorted-indices (sort-by #(nth pubs %) (range 3))
                      sorted-kps (mapv #(nth kps %) sorted-indices)
                      sorted-pubs (mapv #(nth pubs %) sorted-indices)
                      pub0 (nth sorted-pubs 0)
                      pub1 (nth sorted-pubs 1)
                      pub2 (nth sorted-pubs 2)
                      peers-map {pub0 (:public (nth sorted-kps 0))
                                 pub1 (:public (nth sorted-kps 1))
                                 pub2 (:public (nth sorted-kps 2))}
                      t-kp (crypto/generate-keypair)
                      t-pub (basalt/bytes->hex (:public t-kp))
                      t-priv (basalt/bytes->hex (:private t-kp))
                      client-kp (crypto/generate-keypair)
                      client-pub (basalt/bytes->hex (:public client-kp))
                      receiver-kp (crypto/generate-keypair)
                      receiver-pub (basalt/bytes->hex (:public receiver-kp))
                      genesis-ledger {pub0 (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                                      pub1 (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                                      pub2 (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                                      client-pub (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                                      receiver-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                      cfg (assoc config/devnet-config
                                 :genesis-ledger genesis-ledger
                                 :peers-map peers-map
                                 :validators sorted-pubs
                                 :mesh-nodes sorted-pubs
                                 :treasury-pubkey t-pub
                                 :treasury-privkey t-priv)
                      init-s0 (sm/init-state [] pub0 (assoc cfg :keypair (nth sorted-kps 0)))
                      init-s1 (sm/init-state [] pub1 (assoc cfg :keypair (nth sorted-kps 1)))
                      init-s2 (sm/init-state [] pub2 (assoc cfg :keypair (nth sorted-kps 2)))
                      unsigned-tx {:sender client-pub
                                   :receiver receiver-pub
                                   :amount transfer-amt
                                   :seq 1
                                   :deps []}
                      tx (account/create-transfer (:private client-kp) unsigned-tx)
                      transfer-payload (.getBytes (pr-str {:transfer tx}) "UTF-8")
          ;; Epoch 1: Proposer is node1 (pub1). Inject signaling burn and intent into node1.
                      s1-burned (:state (sm/handle-event init-s1 {:type :signaling-burn :sender client-pub :burn burn-amt}))
                      s1-intent (:state (sm/handle-event s1-burned {:type :settle-intent :payer client-pub :receiver receiver-pub :amount intent-amt}))
                      states-ep1 (exchange-block-and-votes [init-s0 s1-intent init-s2] sorted-pubs 1)
          ;; Epoch 2: Proposer is node2 (pub2). Inject transfer on-deliver into node2.
                      s2-delivered (:state (sm/handle-event (nth states-ep1 2) {:type :on-deliver :payload transfer-payload :message-id "msg-tx-1"}))
                      states-ep2 (exchange-block-and-votes [(nth states-ep1 0) (nth states-ep1 1) s2-delivered] sorted-pubs 2)
          ;; Epoch 3: Proposer is node0 (pub0). Block 3 notarized -> 3-chain finalizes block 2 and block 1!
                      states-ep3 (exchange-block-and-votes states-ep2 sorted-pubs 3)
          ;; Epoch 4: Proposer is node1 (pub1). Block 4 notarized -> finalizes block 3!
                      states-ep4 (exchange-block-and-votes states-ep3 sorted-pubs 4)
                      s0-final (nth states-ep4 0)
                      s1-final (nth states-ep4 1)
                      s2-final (nth states-ep4 2)]
                  (and (= (:ledger s0-final) (:ledger s1-final) (:ledger s2-final))
                       (= (:total-minted s0-final) (:total-minted s1-final) (:total-minted s2-final))
                       (= (:mint-dust s0-final) (:mint-dust s1-final) (:mint-dust s2-final))
                       (= (:epoch-burns s0-final) (:epoch-burns s1-final) (:epoch-burns s2-final))
                       (= (:epoch-settlement-takes s0-final) (:epoch-settlement-takes s1-final) (:epoch-settlement-takes s2-final))
                       (= (:last-executed-finalized-epoch s0-final)
                          (:last-executed-finalized-epoch s1-final)
                          (:last-executed-finalized-epoch s2-final))
                       (> (:last-executed-finalized-epoch s0-final) 0)
                       (= (sm/compute-burn-map-digest s0-final)
                          (sm/compute-burn-map-digest s1-final)
                          (sm/compute-burn-map-digest s2-final))
                       (string? (sm/compute-burn-map-digest s0-final))
                       (= 16 (count (sm/compute-burn-map-digest s0-final)))))))

(deftest test-finality-stall-queues-receipts-and-heals-on-finalization
  (testing "receipts are queued during finality stall without mutating ledger or mint, overspending rejected, and executed in order on finality"
    (let [kp0 (crypto/generate-keypair)
          kp1 (crypto/generate-keypair)
          kp2 (crypto/generate-keypair)
          kps [kp0 kp1 kp2]
          pubs (mapv #(basalt/bytes->hex (:public %)) kps)
          sorted-indices (sort-by #(nth pubs %) (range 3))
          sorted-kps (mapv #(nth kps %) sorted-indices)
          sorted-pubs (mapv #(nth pubs %) sorted-indices)
          pub0 (nth sorted-pubs 0)
          pub1 (nth sorted-pubs 1)
          pub2 (nth sorted-pubs 2)
          peers-map {pub0 (:public (nth sorted-kps 0))
                     pub1 (:public (nth sorted-kps 1))
                     pub2 (:public (nth sorted-kps 2))}
          t-kp (crypto/generate-keypair)
          t-pub (basalt/bytes->hex (:public t-kp))
          t-priv (basalt/bytes->hex (:private t-kp))
          client-kp (crypto/generate-keypair)
          client-pub (basalt/bytes->hex (:public client-kp))
          receiver-kp (crypto/generate-keypair)
          receiver-pub (basalt/bytes->hex (:public receiver-kp))
          genesis-ledger {pub0 (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                          pub1 (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                          pub2 (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                          client-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                          receiver-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
          cfg (assoc config/devnet-config
                     :genesis-ledger genesis-ledger
                     :peers-map peers-map
                     :validators sorted-pubs
                     :treasury-pubkey t-pub
                     :treasury-privkey t-priv)
          s0 (sm/init-state [] pub0 (assoc cfg :keypair (nth sorted-kps 0)))
          ;; 1. Stage an intent for 600
          res1 (sm/handle-event s0 {:type :settle-intent :payer client-pub :receiver receiver-pub :amount 600})
          s1 (:state res1)
          _ (do
              (is (= 1 (count (:pending-receipts s1))))
              ;; Authoritative ledger must NOT be mutated!
              (is (= 1000 (:balance (get-in s1 [:ledger client-pub]))))
              (is (empty? (:epoch-settlement-takes s1)))
              ;; Spendable balance reflects pending debit
              (is (= 400 (sm/spendable-balance s1 client-pub))))
          ;; 2. Overspending beyond spendable balance (400) is rejected fail-closed
          res-fail (sm/handle-event s1 {:type :settle-intent :payer client-pub :receiver receiver-pub :amount 500})
          _ (do
              (is (= (count (:pending-receipts s1)) (count (:pending-receipts (:state res-fail)))))
              (is (= 400 (sm/spendable-balance (:state res-fail) client-pub))))
          ;; 3. Stage a signaling burn within spendable balance (100 <= 400)
          res2 (sm/handle-event s1 {:type :signaling-burn :sender client-pub :burn 100})
          s2 (:state res2)]
      (is (= 2 (count (:pending-receipts s2))))
      (is (= 1000 (:balance (get-in s2 [:ledger client-pub]))))
      (is (= 300 (sm/spendable-balance s2 client-pub)))
      (is (empty? (:epoch-burns s2)))
      ;; 4. Stall Phase (Epochs 1 and 2): Drive all 3 nodes through :tick without delivering proposals or votes
      (let [init-s1 (sm/init-state [] pub1 (assoc cfg :keypair (nth sorted-kps 1)))
            init-s2 (sm/init-state [] pub2 (assoc cfg :keypair (nth sorted-kps 2)))
            ;; Epoch 1 ticks
            s0-ep1 (:state (sm/handle-event s2 {:type :tick :rng (java.util.Random. 1)}))
            s1-ep1 (:state (sm/handle-event init-s1 {:type :tick :rng (java.util.Random. 1)}))
            s2-ep1 (:state (sm/handle-event init-s2 {:type :tick :rng (java.util.Random. 1)}))
            ;; Epoch 2 ticks
            s0-stalled (:state (sm/handle-event s0-ep1 {:type :tick :rng (java.util.Random. 2)}))
            s1-stalled (:state (sm/handle-event s1-ep1 {:type :tick :rng (java.util.Random. 2)}))
            s2-stalled (:state (sm/handle-event s2-ep1 {:type :tick :rng (java.util.Random. 2)}))]
        ;; Assert stall state:
        (is (= 2 (:epoch s0-stalled)))
        (is (empty? (:finalized-blocks s0-stalled)))
        (is (= 0 (:last-executed-finalized-epoch s0-stalled)))
        (is (= 2 (count (:pending-receipts s0-stalled))))
        (is (= 1000 (:balance (get-in s0-stalled [:ledger client-pub]))))

        ;; 5. Recovery Phase (Epochs 3, 4, 5, 6, 7): Propose and vote across consecutive epochs
        (let [states-ep3 (exchange-block-and-votes [s0-stalled s1-stalled s2-stalled] sorted-pubs 3)
              states-ep4 (exchange-block-and-votes states-ep3 sorted-pubs 4)
              states-ep5 (exchange-block-and-votes states-ep4 sorted-pubs 5)
              states-ep6 (exchange-block-and-votes states-ep5 sorted-pubs 6)
              states-ep7 (exchange-block-and-votes states-ep6 sorted-pubs 7)
              s0-rec (nth states-ep7 0)
              s1-rec (nth states-ep7 1)
              s2-rec (nth states-ep7 2)]
          (is (= 0 (count (:pending-receipts s0-rec))))
          (is (seq (:finalized-blocks s0-rec)))
          (is (>= (:last-executed-finalized-epoch s0-rec) 4))
          (is (= (:last-executed-finalized-epoch s0-rec)
                 (:last-executed-finalized-epoch s1-rec)
                 (:last-executed-finalized-epoch s2-rec)))
          (is (= 300 (:balance (get-in s0-rec [:ledger client-pub]))))
          (is (= (:ledger s0-rec) (:ledger s1-rec) (:ledger s2-rec)))
          (is (pos? (:balance (get-in s0-rec [:ledger receiver-pub]))))
          (is (pos? (get-in s0-rec [:epoch-burns 2] 0)))
          (is (pos? (get-in s0-rec [:epoch-settlement-takes 2] 0))))))))

(deftest test-fifo-receipt-tracking-eviction
  (testing "at max-tracked-receipts 5, staging 7 distinct receipts evicts oldest 2 (r0, r1) and retains newest 5 (r2..r6)"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 100000 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)}
                     :max-tracked-receipts 5)
          s0 (sm/init-state [] pub (assoc cfg :keypair kp))
          ;; Stage 7 distinct receipts (r0 .. r6)
          receipts (mapv (fn [i] {:receipt-id (str "burn:r" i)
                                  :type :burn
                                  :sender pub
                                  :amount 100})
                         (range 7))
          s-staged (reduce (fn [st r] (:state (sm/stage-receipt st r))) s0 receipts)]
      ;; :known-receipt-ids must only contain r2..r6
      (is (= 5 (count (:known-receipt-ids s-staged))))
      (is (= (mapv #(str "burn:r" %) (range 2 7)) (:known-receipt-order s-staged)))
      (is (not (contains? (:known-receipt-ids s-staged) "burn:r0")))
      (is (not (contains? (:known-receipt-ids s-staged) "burn:r1")))
      (doseq [i (range 2 7)]
        (is (contains? (:known-receipt-ids s-staged) (str "burn:r" i))))
      ;; Now execute a block containing the receipts
      (let [block {:epoch 1
                   :parent-hash "genesis"
                   :payload (:pending-receipts s-staged)}
            block-hash (streamlet/hash-block block)
            s-executed (-> s-staged
                           (assoc-in [:blocks block-hash] block)
                           (assoc :latest-finalized-block-hash block-hash
                                  :finalized-blocks #{block-hash})
                           sm/execute-finalized-blocks)]
        (is (= 5 (count (:executed-receipt-ids s-executed))))
        (is (= (mapv #(str "burn:r" %) (range 2 7)) (:executed-receipt-order s-executed)))
        (is (not (contains? (:executed-receipt-ids s-executed) "burn:r0")))
        (is (not (contains? (:executed-receipt-ids s-executed) "burn:r1")))
        (doseq [i (range 2 7)]
          (is (contains? (:executed-receipt-ids s-executed) (str "burn:r" i))))))))

(deftest test-unrooted-finalized-chain-waits-for-missing-ancestor
  (testing "execute-finalized-blocks holds unrooted finalized suffix when an intermediate ancestor block is missing, then executes in order once ancestor arrives"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)})
          s0 (sm/init-state [] pub (assoc cfg :keypair kp))
          ;; 1. Block 0 at epoch 0 with genesis parent, executed
          b0 {:epoch 0 :parent-hash "genesis" :payload []}
          b0-hash (streamlet/hash-block b0)
          s-init (-> s0
                     (assoc-in [:blocks b0-hash] b0)
                     (assoc :latest-finalized-block-hash b0-hash
                            :finalized-blocks #{b0-hash})
                     sm/execute-finalized-blocks)]
      (is (= 0 (:last-executed-finalized-epoch s-init)))
      (is (contains? (:executed-finalized-blocks s-init) b0-hash))
      (is (= 10000 (:balance (get-in s-init [:ledger pub]))))

      ;; 2. Block 1 at epoch 1 containing a signaling burn of 500
      (let [burn-receipt {:receipt-id "burn:node:1:1"
                          :type :burn
                          :sender pub
                          :amount 500}
            b1 {:epoch 1 :parent-hash b0-hash :payload [burn-receipt]}
            b1-hash (streamlet/hash-block b1)
            b2 {:epoch 2 :parent-hash b1-hash :payload []}
            b2-hash (streamlet/hash-block b2)
            b3 {:epoch 3 :parent-hash b2-hash :payload []}
            b3-hash (streamlet/hash-block b3)
            ;; 3. Node receives finalization for b3, has b2 and b3 in :blocks, but b1 is missing!
            s-missing-b1 (-> s-init
                             (assoc-in [:blocks b2-hash] b2)
                             (assoc-in [:blocks b3-hash] b3)
                             (assoc :latest-finalized-block-hash b3-hash
                                    :finalized-blocks #{b0-hash b1-hash b2-hash b3-hash})
                             sm/execute-finalized-blocks)]
        ;; MUST NOT execute b2/b3 and MUST NOT skip b1!
        (is (= 0 (:last-executed-finalized-epoch s-missing-b1)))
        (is (not (contains? (:executed-finalized-blocks s-missing-b1) b2-hash)))
        (is (not (contains? (:executed-finalized-blocks s-missing-b1) b3-hash)))
        (is (= 10000 (:balance (get-in s-missing-b1 [:ledger pub]))))
        (is (zero? (get-in s-missing-b1 [:epoch-burns 1] 0)))

        ;; 4. Now b1 is synced and added to :blocks
        (let [s-recovered (-> s-missing-b1
                              (assoc-in [:blocks b1-hash] b1)
                              sm/execute-finalized-blocks)]
          ;; Now b1, b2, b3 execute in order!
          (is (= 3 (:last-executed-finalized-epoch s-recovered)))
          (is (contains? (:executed-finalized-blocks s-recovered) b1-hash))
          (is (contains? (:executed-finalized-blocks s-recovered) b2-hash))
          (is (contains? (:executed-finalized-blocks s-recovered) b3-hash))
          ;; Burn from b1 was properly executed, not skipped!
          (is (= 9500 (:balance (get-in s-recovered [:ledger pub]))))
          (is (= 500 (get-in s-recovered [:epoch-burns 0]))))))))

(deftest test-unrooted-finalized-chain-fallback-and-fresh-genesis
  (let [kp (crypto/generate-keypair)
        pub (basalt/bytes->hex (:public kp))
        cfg (assoc config/devnet-config
                   :genesis-ledger {pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})}
                   :peers-map {pub (:public kp)})
        s0 (sm/init-state [] pub (assoc cfg :keypair kp))
        burn-receipt {:receipt-id "burn:node:1:1"
                      :type :burn
                      :sender pub
                      :amount 500}]

    (testing "Fallback path (nil :latest-finalized-block-hash) at fresh genesis holds unrooted b2 until b1 arrives"
      (let [b1 {:epoch 1 :parent-hash "genesis" :payload [burn-receipt]}
            b1-hash (streamlet/hash-block b1)
            b2 {:epoch 2 :parent-hash b1-hash :payload []}
            b2-hash (streamlet/hash-block b2)
            ;; b1 missing from :blocks, but both hashes in :finalized-blocks
            s-missing (-> s0
                          (assoc-in [:blocks b2-hash] b2)
                          (assoc :latest-finalized-block-hash nil
                                 :finalized-blocks #{b1-hash b2-hash})
                          sm/execute-finalized-blocks)]
        (is (= 0 (:last-executed-finalized-epoch s-missing)))
        (is (not (contains? (:executed-finalized-blocks s-missing) b2-hash)))
        (is (= 10000 (:balance (get-in s-missing [:ledger pub]))))
        (is (zero? (get-in s-missing [:epoch-burns 0] 0)))

        ;; Once b1 arrives in :blocks, b1 and b2 execute in order
        (let [s-recovered (-> s-missing
                              (assoc-in [:blocks b1-hash] b1)
                              sm/execute-finalized-blocks)]
          (is (= 2 (:last-executed-finalized-epoch s-recovered)))
          (is (contains? (:executed-finalized-blocks s-recovered) b1-hash))
          (is (contains? (:executed-finalized-blocks s-recovered) b2-hash))
          (is (= 9500 (:balance (get-in s-recovered [:ledger pub]))))
          (is (= 500 (get-in s-recovered [:epoch-burns 0]))))))

    (testing "Fallback path (nil :latest-finalized-block-hash) after b0 executed holds unrooted b2 until b1 arrives"
      (let [b0 {:epoch 0 :parent-hash "genesis" :payload []}
            b0-hash (streamlet/hash-block b0)
            s-init (-> s0
                       (assoc-in [:blocks b0-hash] b0)
                       (assoc :latest-finalized-block-hash b0-hash
                              :finalized-blocks #{b0-hash})
                       sm/execute-finalized-blocks)
            b1 {:epoch 1 :parent-hash b0-hash :payload [burn-receipt]}
            b1-hash (streamlet/hash-block b1)
            b2 {:epoch 2 :parent-hash b1-hash :payload []}
            b2-hash (streamlet/hash-block b2)
            ;; b1 missing from :blocks, b0 executed, :latest-finalized-block-hash nil
            s-missing (-> s-init
                          (assoc-in [:blocks b2-hash] b2)
                          (assoc :latest-finalized-block-hash nil
                                 :finalized-blocks #{b0-hash b1-hash b2-hash})
                          sm/execute-finalized-blocks)]
        (is (= 0 (:last-executed-finalized-epoch s-missing)))
        (is (not (contains? (:executed-finalized-blocks s-missing) b2-hash)))
        (is (= 10000 (:balance (get-in s-missing [:ledger pub]))))
        (is (zero? (get-in s-missing [:epoch-burns 0] 0)))

        ;; Once b1 arrives in :blocks, b1 and b2 execute in order
        (let [s-recovered (-> s-missing
                              (assoc-in [:blocks b1-hash] b1)
                              sm/execute-finalized-blocks)]
          (is (= 2 (:last-executed-finalized-epoch s-recovered)))
          (is (contains? (:executed-finalized-blocks s-recovered) b1-hash))
          (is (contains? (:executed-finalized-blocks s-recovered) b2-hash))
          (is (= 9500 (:balance (get-in s-recovered [:ledger pub]))))
          (is (= 500 (get-in s-recovered [:epoch-burns 0]))))))

    (testing "Fresh genesis with :latest-finalized-block-hash set to b2-hash holds b2 until b1 arrives"
      (let [b1 {:epoch 1 :parent-hash "genesis" :payload [burn-receipt]}
            b1-hash (streamlet/hash-block b1)
            b2 {:epoch 2 :parent-hash b1-hash :payload []}
            b2-hash (streamlet/hash-block b2)
            s-missing (-> s0
                          (assoc-in [:blocks b2-hash] b2)
                          (assoc :latest-finalized-block-hash b2-hash
                                 :finalized-blocks #{b1-hash b2-hash})
                          sm/execute-finalized-blocks)]
        (is (= 0 (:last-executed-finalized-epoch s-missing)))
        (is (not (contains? (:executed-finalized-blocks s-missing) b2-hash)))
        (is (= 10000 (:balance (get-in s-missing [:ledger pub]))))
        (is (zero? (get-in s-missing [:epoch-burns 0] 0)))

        ;; Once b1 arrives in :blocks, b1 and b2 execute in order
        (let [s-recovered (-> s-missing
                              (assoc-in [:blocks b1-hash] b1)
                              sm/execute-finalized-blocks)]
          (is (= 2 (:last-executed-finalized-epoch s-recovered)))
          (is (contains? (:executed-finalized-blocks s-recovered) b1-hash))
          (is (contains? (:executed-finalized-blocks s-recovered) b2-hash))
          (is (= 9500 (:balance (get-in s-recovered [:ledger pub]))))
          (is (= 500 (get-in s-recovered [:epoch-burns 0]))))))))

(deftest test-monotonic-fallback-receipt-ids-across-drains
  (testing "two burns and two settle-intents in same epoch separated by block execution do not collide on fallback receipt-id"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          receiver-kp (crypto/generate-keypair)
          receiver-pub (basalt/bytes->hex (:public receiver-kp))
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      receiver-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)})
          s0 (sm/init-state [] pub (assoc cfg :keypair kp))
          ;; 1. Stage first burn and first settle intent in epoch 0
          s1 (:state (sm/handle-event s0 {:type :signaling-burn :sender pub :burn 100}))
          s2 (:state (sm/handle-event s1 {:type :settle-intent :payer pub :receiver receiver-pub :amount 200}))
          rids-1 (mapv :receipt-id (:pending-receipts s2))]
      (is (= 2 (count rids-1)))
      (is (distinct? (set rids-1)))
      ;; Simulate block finalization draining pending-receipts
      (let [block {:epoch 1
                   :parent-hash "genesis"
                   :payload (:pending-receipts s2)}
            block-hash (streamlet/hash-block block)
            s-finalized (-> s2
                            (assoc-in [:blocks block-hash] block)
                            (assoc :latest-finalized-block-hash block-hash
                                   :finalized-blocks #{block-hash})
                            sm/execute-finalized-blocks)]
        (is (empty? (:pending-receipts s-finalized)))
        (is (= 9700 (:balance (get-in s-finalized [:ledger pub]))))
        ;; 2. In same epoch 0 (or before tick), stage a second burn and second settle-intent
        (let [s3 (:state (sm/handle-event s-finalized {:type :signaling-burn :sender pub :burn 100}))
              s4 (:state (sm/handle-event s3 {:type :settle-intent :payer pub :receiver receiver-pub :amount 150}))
              rids-2 (mapv :receipt-id (:pending-receipts s4))]
          (is (= 2 (count rids-2)))
          ;; Must not collide with rids-1!
          (is (empty? (set/intersection (set rids-1) (set rids-2))))
          ;; Execute second block
          (let [block2 {:epoch 2
                        :parent-hash block-hash
                        :payload (:pending-receipts s4)}
                block2-hash (streamlet/hash-block block2)
                s-finalized2 (-> s4
                                 (assoc-in [:blocks block2-hash] block2)
                                 (assoc :latest-finalized-block-hash block2-hash
                                        :finalized-blocks #{block-hash block2-hash})
                                 sm/execute-finalized-blocks)]
            (is (empty? (:pending-receipts s-finalized2)))
            (is (= 9450 (:balance (get-in s-finalized2 [:ledger pub]))))))))))

(deftest test-fail-closed-staging-at-capacity
  (testing "at max-pending-receipts 0, handle-register-home-set does not mutate :home-sets and handle-receive-offer-header does not burn :voucher-seqs"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          home-kp (crypto/generate-keypair)
          home-pub (basalt/bytes->hex (:public home-kp))
          candidates [{:node-id home-pub :price 10}
                      {:node-id "n2" :price 10}
                      {:node-id "n3" :price 10}]
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      home-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)}
                     :max-pending-receipts 0)
          s0 (sm/init-state [] pub (assoc cfg :keypair kp))
          tuple-hs [pub 0]
          ;; 1. Register home set at capacity 0 fails closed without mutating :home-sets
          res-hs (sm/handle-event s0 {:type :register-home-set
                                      :callee pub
                                      :candidates candidates
                                      :price 10})
          s-hs (:state res-hs)]
      (is (nil? (get-in s-hs [:home-sets tuple-hs])))
      (is (empty? (:pending-receipts s-hs)))

      ;; Now with capacity 10, register home set succeeds
      (let [s-hs-ok (:state (sm/handle-event (assoc-in s0 [:config :max-pending-receipts] 10)
                                             {:type :register-home-set
                                              :callee pub
                                              :candidates candidates
                                              :price 10}))
            tuple-vs [pub home-pub 0]]
        (is (some? (get-in s-hs-ok [:home-sets tuple-hs])))
        ;; 2. Offer header at capacity 0 fails closed without mutating :voucher-seqs
        (let [s-full (assoc-in s-hs-ok [:config :max-pending-receipts] 0)
              res-oh (sm/handle-event s-full {:type :receive-offer-header
                                              :callee pub
                                              :callee-privkey (:private kp)
                                              :home-node home-pub
                                              :seq 1})
              s-oh (:state res-oh)]
          (is (nil? (get-in s-oh [:voucher-seqs tuple-vs])))
          ;; Retry at normal capacity succeeds with seq 1
          (let [s-retry (:state (sm/handle-event (assoc-in s-oh [:config :max-pending-receipts] 10)
                                                 {:type :receive-offer-header
                                                  :callee pub
                                                  :callee-privkey (:private kp)
                                                  :home-node home-pub
                                                  :seq 1}))]
            (is (= 1 (get-in s-retry [:voucher-seqs tuple-vs])))))))))

(deftest test-failed-receipts-count-increments-on-overspend
  (testing "failed-receipts-count increments when overspent receipt in finalized block is executed"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          receiver-kp (crypto/generate-keypair)
          receiver-pub (basalt/bytes->hex (:public receiver-kp))
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 100 :seq 0 :deps []})
                                      receiver-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)})
          s0 (sm/init-state [] pub (assoc cfg :keypair kp))
          ;; Block with overspending settle-intent (amount 500 > balance 100) and overspending burn (200 > 100)
          bad-receipt1 {:receipt-id "intent:bad:1" :type :settle-intent :payer pub :receiver receiver-pub :amount 500}
          bad-receipt2 {:receipt-id "burn:bad:2" :type :burn :sender pub :amount 200}
          block {:epoch 1
                 :parent-hash "genesis"
                 :payload [bad-receipt1 bad-receipt2]}
          block-hash (streamlet/hash-block block)
          s1 (-> s0
                 (assoc-in [:blocks block-hash] block)
                 (assoc :latest-finalized-block-hash block-hash
                        :finalized-blocks #{block-hash})
                 sm/execute-finalized-blocks)]
      (is (= 2 (:failed-receipts-count s1)))
      (is (= 100 (:balance (get-in s1 [:ledger pub]))))
      (is (contains? (:executed-receipt-ids s1) "intent:bad:1"))
      (is (contains? (:executed-receipt-ids s1) "burn:bad:2")))))

(deftest test-pipelined-transfers-validate-sequential-seq-and-deps
  (testing "pipelined transfers from same sender in same epoch validate against projected seq and deps"
    (let [sender-kp (crypto/generate-keypair)
          sender-pub (basalt/bytes->hex (:public sender-kp))
          receiver-kp (crypto/generate-keypair)
          receiver-pub (basalt/bytes->hex (:public receiver-kp))
          node-kp (crypto/generate-keypair)
          node-pub (basalt/bytes->hex (:public node-kp))
          cfg (assoc config/devnet-config
                     :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                      receiver-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})
                                      node-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})}
                     :peers-map {node-pub (:public node-kp)})
          s0 (sm/init-state [] node-pub (assoc cfg :keypair node-kp))
          ;; Transfer 1: seq 1, deps []
          tx1 (account/create-transfer (:private sender-kp)
                                       {:sender sender-pub
                                        :receiver receiver-pub
                                        :amount 100
                                        :seq 1
                                        :deps []})
          payload1 (.getBytes (pr-str {:transfer tx1}) "UTF-8")
          res1 (sm/handle-event s0 {:type :on-deliver :payload payload1 :message-id "tx1"})
          s1 (:state res1)
          _ (is (= 1 (count (:pending-receipts s1))))
          ;; Sender's projected deps after tx1:
          tx1-hash (account/transfer-hash tx1)
          ;; Transfer 2: seq 2, deps [tx1-hash]
          tx2 (account/create-transfer (:private sender-kp)
                                       {:sender sender-pub
                                        :receiver receiver-pub
                                        :amount 200
                                        :seq 2
                                        :deps [tx1-hash]})
          payload2 (.getBytes (pr-str {:transfer tx2}) "UTF-8")
          res2 (sm/handle-event s1 {:type :on-deliver :payload payload2 :message-id "tx2"})
          s2 (:state res2)]
      (is (= 2 (count (:pending-receipts s2))))
      (is (= 700 (sm/spendable-balance s2 sender-pub)))
      ;; Both transfers execute upon block finalization
      (let [block {:epoch 1
                   :parent-hash "genesis"
                   :payload (:pending-receipts s2)}
            block-hash (streamlet/hash-block block)
            s-final (-> s2
                        (assoc-in [:blocks block-hash] block)
                        (assoc :latest-finalized-block-hash block-hash
                               :finalized-blocks #{block-hash})
                        sm/execute-finalized-blocks)]
        (is (empty? (:pending-receipts s-final)))
        (is (= 700 (:balance (get-in s-final [:ledger sender-pub]))))
        (is (= 2 (:seq (get-in s-final [:ledger sender-pub]))))
        (is (= 300 (:balance (get-in s-final [:ledger receiver-pub]))))))))

(deftest test-submit-vouchers-consensus-staging-and-finalization
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        node-kp (crypto/generate-keypair)
        node-pub (basalt/bytes->hex (:public node-kp))
        cfg (config/make-config
             {:mode :consensus
              :genesis-ledger {callee-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                               node-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
              :peers-map {node-pub (:public node-kp)}})
        s0 (sm/init-state [] node-pub (assoc cfg :keypair node-kp))
        ;; Register home set for callee with keyword :node1 at price 10
        s1 (assoc-in s0 [:home-sets [callee-pub 1]]
                     {:status :active
                      :callee callee-pub
                      :epoch 1
                      :nodes [:node1 :node2 :node3]
                      :price 10})
        ;; Create a valid DeliveryAck signed by callee, using string "node1" to verify normalization
        ack (rdv/create-delivery-ack callee-priv callee-pub "node1" 1 "offer-hash" 2 20)
        res (sm/handle-event s1 {:type :submit-vouchers :vouchers [ack]})
        s2 (:state res)]
    (testing "Stages voucher receipt into :pending-receipts and updates voucher-seqs"
      (is (= 1 (count (:pending-receipts s2))))
      (let [r (first (:pending-receipts s2))]
        (is (= :voucher (:type r)))
        (is (= callee-pub (:callee r)))
        (is (= 20 (:cumulative-debit r)))
        (is (= 2 (:seq r)))))
    (testing "Spendable balance reflects staged voucher debit"
      (is (= 980 (sm/spendable-balance s2 callee-pub))))
    (testing "Finalized block execution executes voucher debit and credit"
      (let [b1 {:epoch 1
                :parent-hash "genesis"
                :payload (:pending-receipts s2)}
            b1-hash (streamlet/hash-block b1)
            b2 {:epoch 2
                :parent-hash b1-hash
                :payload []}
            b2-hash (streamlet/hash-block b2)
            s-final (-> s2
                        (assoc-in [:blocks b1-hash] b1)
                        (assoc-in [:blocks b2-hash] b2)
                        (assoc :latest-finalized-block-hash b2-hash
                               :finalized-blocks #{b1-hash b2-hash})
                        sm/execute-finalized-blocks)]
        (is (empty? (:pending-receipts s-final)))
        (is (= 980 (:balance (get-in s-final [:ledger callee-pub]))))
        (is (= 20 (:balance (get-in s-final [:ledger "node1"] 0))))))))

(deftest test-mixed-keyword-string-home-node-state-machine
  (testing "Mixed keyword (:node1) and string (\"node1\") home-node representations coalesce and settle cleanly"
    (let [callee-kp (crypto/generate-keypair)
          callee-pub (basalt/bytes->hex (:public callee-kp))
          callee-priv (:private callee-kp)
          node-kp (crypto/generate-keypair)
          node-pub (basalt/bytes->hex (:public node-kp))
          cfg (config/make-config
               {:mode :consensus
                :genesis-ledger {callee-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                 node-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                :peers-map {node-pub (:public node-kp)}})
          s0 (sm/init-state [] node-pub (assoc cfg :keypair node-kp))
          ;; 1. Register home set with mixed keyword candidates [:node1 :node2]
          s1 (assoc-in s0 [:home-sets [callee-pub 1]]
                       {:status :ok
                        :callee callee-pub
                        :epoch 1
                        :home-nodes [{:node-id :node1 :price 10}
                                     {:node-id "node2" :price 10}
                                     {:node-id :node3 :price 10}]
                        :price 10})
          ;; 2. Submit voucher signed with keyword :node1 and string "node1" in submit-vouchers
          ack1 (rdv/create-delivery-ack callee-priv callee-pub :node1 1 "offer-hash" 2 20)
          ack2 (rdv/create-delivery-ack callee-priv callee-pub "node1" 1 "offer-hash" 3 30)
          res (sm/handle-event s1 {:type :submit-vouchers :vouchers [ack1 ack2]})
          s2 (:state res)]
      ;; Compacted and staged into [callee-pub "node1" 1] with seq 3
      (is (= 1 (count (:pending-receipts s2))))
      (let [r (first (:pending-receipts s2))]
        (is (= "node1" (:home-node r)))
        (is (= 30 (:cumulative-debit r)))
        (is (= 3 (:seq r))))
      ;; 3. Finalize block and verify settlement credits "node1"
      (let [b1 {:epoch 1
                :parent-hash "genesis"
                :payload (:pending-receipts s2)}
            b1-hash (streamlet/hash-block b1)
            b2 {:epoch 2
                :parent-hash b1-hash
                :payload []}
            b2-hash (streamlet/hash-block b2)
            s-final (-> s2
                        (assoc-in [:blocks b1-hash] b1)
                        (assoc-in [:blocks b2-hash] b2)
                        (assoc :latest-finalized-block-hash b2-hash
                               :finalized-blocks #{b1-hash b2-hash})
                        sm/execute-finalized-blocks)]
        (is (empty? (:pending-receipts s-final)))
        (is (= 970 (:balance (get-in s-final [:ledger callee-pub]))))
        (is (= 30 (:balance (get-in s-final [:ledger "node1"] 0))))
        (is (= 3 (get-in s-final [:voucher-seqs [callee-pub "node1" 1]])))))))

(deftest test-unregistered-epoch-voucher-fails-closed
  (testing "Unregistered-epoch 999-debit voucher probe fails closed across all layers with 0 debit to callee"
    (let [callee-kp (crypto/generate-keypair)
          callee-pub (basalt/bytes->hex (:public callee-kp))
          callee-priv (:private callee-kp)
          node-kp (crypto/generate-keypair)
          node-pub (basalt/bytes->hex (:public node-kp))
          cfg (config/make-config
               {:mode :consensus
                :genesis-ledger {callee-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                 node-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                :peers-map {node-pub (:public node-kp)}})
          s0 (sm/init-state [] node-pub (assoc cfg :keypair node-kp))
          ;; Notice: NO home set is registered for callee for epoch 1
          ;; Create a 999-debit signed voucher for unregistered epoch 1
          ack (rdv/create-delivery-ack callee-priv callee-pub "node1" 1 "offer-hash" 1 999)]

      ;; Layer 1: handle-submit-vouchers fails closed
      (testing "Layer 1: handle-submit-vouchers fails closed on missing registration"
        (let [res (sm/handle-event s0 {:type :submit-vouchers :vouchers [ack]})
              s1 (:state res)]
          (is (empty? (:pending-receipts s1)))
          (is (empty? (:pending-vouchers s1)))
          (is (= 1000 (:balance (get-in s1 [:ledger callee-pub]))))
          (is (= 1000 (sm/spendable-balance s1 callee-pub)))))

      ;; Layer 2: execute-finalized-blocks fails closed when voucher is injected directly into finalized block payload
      (testing "Layer 2: execute-finalized-blocks fails closed on unregistered voucher in block payload"
        (let [raw-receipt {:receipt-id "voucher:probe:999"
                           :type :voucher
                           :callee callee-pub
                           :home-node "node1"
                           :epoch 1
                           :seq 1
                           :cumulative-debit 999
                           :ack ack}
              b1 {:epoch 1
                  :parent-hash "genesis"
                  :payload [raw-receipt]}
              b1-hash (streamlet/hash-block b1)
              b2 {:epoch 2
                  :parent-hash b1-hash
                  :payload []}
              b2-hash (streamlet/hash-block b2)
              b3 {:epoch 3
                  :parent-hash b2-hash
                  :payload []}
              b3-hash (streamlet/hash-block b3)
              s-final (-> s0
                          (assoc-in [:blocks b1-hash] b1)
                          (assoc-in [:blocks b2-hash] b2)
                          (assoc-in [:blocks b3-hash] b3)
                          (assoc :latest-finalized-block-hash b3-hash
                                 :finalized-blocks #{b1-hash b2-hash b3-hash})
                          sm/execute-finalized-blocks)]
          (is (= 1 (long (or (:failed-receipts-count s-final) 0))))
          (is (empty? (:pending-vouchers s-final)))
          (is (= 1000 (:balance (get-in s-final [:ledger callee-pub]))))
          (is (= 0 (or (:balance (get-in s-final [:ledger "node1"])) 0)))))

      ;; Layer 3: settle-single-voucher fails closed with :reason :unregistered-home-set
      (testing "Layer 3: settle-single-voucher fails closed on missing registration"
        (let [s-settled (#'sm/settle-single-voucher s0 ack 1 0)]
          (is (= 1000 (:balance (get-in s-settled [:ledger callee-pub]))))
          (is (= 0 (or (:balance (get-in s-settled [:ledger "node1"])) 0)))
          (is (= 1 (count (:failed-vouchers s-settled))))
          (let [fv (first (:failed-vouchers s-settled))]
            (is (= :unregistered-home-set (:reason fv)))))))))

(deftest test-settle-intent-and-register-home-set-reject-sender-spoofing
  (testing "handle-settle-intent and handle-register-home-set fail closed when :sender is spoofed"
    (let [alice-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          attacker-kp (crypto/generate-keypair)
          attacker-pub (basalt/bytes->hex (:public attacker-kp))
          bob-kp (crypto/generate-keypair)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          peers-map {alice-pub (:public alice-kp)
                     bob-pub (:public bob-kp)}
          cfg (assoc config/default-config
                     :peers-map peers-map
                     :genesis-ledger {alice-pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      attacker-pub (account/map->AccountState {:balance 500 :seq 0 :deps []})
                                      bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})})
          consensus-state (sm/init-state [] alice-pub (assoc cfg :keypair alice-kp))
          standalone-state (sm/init-state [] alice-pub (dissoc cfg :peers-map))]

      (testing "Consensus mode: :settle-intent with sender != payer fails closed"
        (let [res (sm/handle-event consensus-state
                                   {:type :settle-intent
                                    :payer alice-pub
                                    :receiver attacker-pub
                                    :amount 1000
                                    :sender attacker-pub})]
          (is (= (:state res) consensus-state))
          (is (empty? (:commands res)))
          (is (empty? (:pending-receipts (:state res))))))

      (testing "Consensus mode: :settle-intent with sender == payer or sender nil succeeds"
        (let [res1 (sm/handle-event consensus-state
                                    {:type :settle-intent
                                     :payer alice-pub
                                     :receiver bob-pub
                                     :amount 500
                                     :sender alice-pub})
              res2 (sm/handle-event consensus-state
                                    {:type :settle-intent
                                     :payer alice-pub
                                     :receiver bob-pub
                                     :amount 500})]
          (is (= 1 (count (:pending-receipts (:state res1)))))
          (is (= 1 (count (:pending-receipts (:state res2)))))))

      (testing "Standalone mode: :settle-intent with sender != payer fails closed"
        (let [res (sm/handle-event standalone-state
                                   {:type :settle-intent
                                    :payer alice-pub
                                    :receiver attacker-pub
                                    :amount 1000
                                    :sender attacker-pub})]
          (is (= (:state res) standalone-state))
          (is (= 10000 (:balance (get-in (:state res) [:ledger alice-pub]))))
          (is (= 500 (:balance (get-in (:state res) [:ledger attacker-pub]))))))

      (testing "Standalone mode: :settle-intent with sender == payer or sender nil succeeds"
        (let [res1 (sm/handle-event standalone-state
                                    {:type :settle-intent
                                     :payer alice-pub
                                     :receiver bob-pub
                                     :amount 1000
                                     :sender alice-pub})]
          (is (< (:balance (get-in (:state res1) [:ledger alice-pub])) 10000))
          (is (pos? (:balance (get-in (:state res1) [:ledger bob-pub]))))))

      (testing "Consensus mode: :register-home-set with sender != callee fails closed"
        (let [res (sm/handle-event consensus-state
                                   {:type :register-home-set
                                    :callee alice-pub
                                    :candidates [{:node-id "node-1" :price 10 :latency-ms 10}]
                                    :price 10
                                    :price-max 15
                                    :sender attacker-pub})]
          (is (= (:state res) consensus-state))
          (is (empty? (:commands res)))
          (is (empty? (:pending-receipts (:state res))))))

      (testing "Consensus mode: :register-home-set with sender == callee or sender nil succeeds"
        (let [res1 (sm/handle-event consensus-state
                                    {:type :register-home-set
                                     :callee alice-pub
                                     :candidates [{:node-id "node-1" :price 10 :latency-ms 10}]
                                     :price 10
                                     :price-max 15
                                     :sender alice-pub})
              res2 (sm/handle-event consensus-state
                                    {:type :register-home-set
                                     :callee alice-pub
                                     :candidates [{:node-id "node-1" :price 10 :latency-ms 10}]
                                     :price 10
                                     :price-max 15})]
          (is (= 1 (count (:pending-receipts (:state res1)))))
          (is (= 1 (count (:pending-receipts (:state res2)))))))

      (testing "Standalone mode: :register-home-set with sender != callee fails closed"
        (let [res (sm/handle-event standalone-state
                                   {:type :register-home-set
                                    :callee alice-pub
                                    :candidates [{:node-id "node-1" :price 10 :latency-ms 10}]
                                    :price 10
                                    :price-max 15
                                    :sender attacker-pub})]
          (is (= (:state res) standalone-state))
          (is (empty? (:home-sets (:state res))))))

      (testing "Standalone mode: :register-home-set with sender == callee or sender nil succeeds"
        (let [res1 (sm/handle-event standalone-state
                                    {:type :register-home-set
                                     :callee alice-pub
                                     :candidates [{:node-id "node-1" :price 10 :latency-ms 10}]
                                     :price 10
                                     :price-max 15
                                     :sender alice-pub})]
          (is (some? (get-in (:state res1) [:home-sets [alice-pub 0]]))))))))

(deftest test-transcript-adversarial-hardening-rejects-self-dealing-empty-roles-and-sender-spoofing
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        kp-attacker (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public kp-a))
        pub-b (basalt/bytes->hex (:public kp-b))
        attacker-pub (basalt/bytes->hex (:public kp-attacker))
        roles [["m1" :echo]]
        valid-half (attestation/create-transcript 0 pub-a pub-b roles (:private kp-a))
        valid-mut (attestation/cosign-transcript valid-half (:private kp-b))
        self-tx (attestation/create-transcript 0 pub-a pub-a roles (:private kp-a))
        self-mut (attestation/cosign-transcript self-tx (:private kp-a))
        empty-tx (attestation/create-transcript 0 pub-a pub-b [] (:private kp-a))
        empty-mut (attestation/cosign-transcript empty-tx (:private kp-b))
        st-standalone (assoc (sm/init-state [] pub-a)
                             :frozen-epoch-messages {0 #{"m1"}}
                             :frozen-epoch-message-roles {0 {"m1" :echo}})
        st-consensus (sm/init-state [] pub-a (assoc config/devnet-config
                                                    :peers-map {pub-a (:public kp-a) pub-b (:public kp-b)}
                                                    :validators [pub-a pub-b]
                                                    :mesh-nodes [pub-a pub-b]
                                                    :keypair kp-a))]
    (testing "1. Self-dealing transcripts (peer-a == peer-b) are strictly rejected"
      ;; Standalone mode handle-submit-transcript
      (let [res (sm/handle-event st-standalone {:type :submit-transcript :transcript self-mut})]
        (is (= (:state res) st-standalone))
        (is (empty? (:settled-transcript-pairs (:state res))))
        (is (empty? (:epoch-participation (:state res)))))
      ;; Consensus mode handle-submit-transcript
      (let [res (sm/handle-event st-consensus {:type :submit-transcript :transcript self-mut})]
        (is (= (:state res) st-consensus))
        (is (empty? (:pending-receipts (:state res)))))
      ;; handle-receive-transcript-sig
      (let [res (sm/handle-event st-consensus {:type :receive-transcript-sig
                                               :sender pub-a
                                               :transcript self-mut})]
        (is (empty? (:commands res)))
        (is (empty? (:pending-receipts (:state res)))))
      ;; execute-finalized-blocks with self-dealing receipt
      (let [bad-receipt {:receipt-id "rcpt-self"
                         :type :transcript
                         :epoch 0
                         :peer-a pub-a
                         :peer-b pub-a
                         :transcript (into {} self-mut)}
            b1 {:hash "b1" :parent-hash "genesis" :epoch 1 :payload [bad-receipt]}
            st-with-block (assoc st-consensus
                                 :blocks {"b1" b1}
                                 :finalized-blocks #{"b1"}
                                 :latest-finalized-block-hash "b1")
            executed (sm/execute-finalized-blocks st-with-block)]
        (is (= 1 (:failed-receipts-count executed)))
        (is (empty? (:settled-transcript-pairs executed)))))

    (testing "2. Empty-role transcripts are strictly rejected"
      ;; Standalone mode handle-submit-transcript
      (let [res (sm/handle-event st-standalone {:type :submit-transcript :transcript empty-mut})]
        (is (= (:state res) st-standalone))
        (is (empty? (:settled-transcript-pairs (:state res)))))
      ;; Consensus mode handle-submit-transcript
      (let [res (sm/handle-event st-consensus {:type :submit-transcript :transcript empty-mut})]
        (is (= (:state res) st-consensus))
        (is (empty? (:pending-receipts (:state res)))))
      ;; handle-receive-transcript-sig
      (let [res (sm/handle-event st-consensus {:type :receive-transcript-sig
                                               :sender pub-a
                                               :transcript empty-mut})]
        (is (empty? (:commands res))))
      ;; execute-finalized-blocks with empty-roles receipt
      (let [bad-receipt {:receipt-id "rcpt-empty"
                         :type :transcript
                         :epoch 0
                         :peer-a pub-a
                         :peer-b pub-b
                         :transcript (into {} empty-mut)}
            b1 {:hash "b1" :parent-hash "genesis" :epoch 1 :payload [bad-receipt]}
            st-with-block (assoc st-consensus
                                 :blocks {"b1" b1}
                                 :finalized-blocks #{"b1"}
                                 :latest-finalized-block-hash "b1")
            executed (sm/execute-finalized-blocks st-with-block)]
        (is (= 1 (:failed-receipts-count executed)))
        (is (empty? (:settled-transcript-pairs executed)))))

    (testing "3. :submit-transcript rejects spoofed :sender from unrelated third parties"
      ;; Spoofed sender attacker-pub (neither peer-a nor peer-b)
      (let [res-spoofed (sm/handle-event st-consensus {:type :submit-transcript
                                                       :transcript valid-mut
                                                       :sender attacker-pub})]
        (is (= (:state res-spoofed) st-consensus))
        (is (empty? (:pending-receipts (:state res-spoofed)))))
      ;; Legitimate sender pub-a succeeds
      (let [res-legit-a (sm/handle-event st-consensus {:type :submit-transcript
                                                       :transcript valid-mut
                                                       :sender pub-a})]
        (is (= 1 (count (:pending-receipts (:state res-legit-a))))))
      ;; Legitimate sender pub-b succeeds
      (let [res-legit-b (sm/handle-event st-consensus {:type :submit-transcript
                                                       :transcript valid-mut
                                                       :sender pub-b})]
        (is (= 1 (count (:pending-receipts (:state res-legit-b))))))
      ;; Sender nil succeeds (local invocation)
      (let [res-nil (sm/handle-event st-consensus {:type :submit-transcript
                                                   :transcript valid-mut
                                                   :sender nil})]
        (is (= 1 (count (:pending-receipts (:state res-nil)))))))))

(defspec ^{:doc "Property: Simulates 3-node Streamlet cluster with bilateral transcript exchange (:send-transcript-sig / :receive-transcript-sig), partial-overlap reconciliation, half-signed dispute against signed frozen logs, and finalized-block receipt execution; asserts convergence on identical settled pairs, weights, balances, supply, and withholding strikes."}
  prop-bilateral-transcript-mesh-reward-convergence 50
  (prop/for-all [burn-amt (gen/choose 5000 50000)
                 msg-count (gen/choose 2 4)]
                (let [kp0 (crypto/generate-keypair)
                      kp1 (crypto/generate-keypair)
                      kp2 (crypto/generate-keypair)
                      kps [kp0 kp1 kp2]
                      pubs (mapv #(basalt/bytes->hex (:public %)) kps)
                      sorted-indices (sort-by #(nth pubs %) (range 3))
                      sorted-kps (mapv #(nth kps %) sorted-indices)
                      sorted-pubs (mapv #(nth pubs %) sorted-indices)
                      pub0 (nth sorted-pubs 0)
                      pub1 (nth sorted-pubs 1)
                      pub2 (nth sorted-pubs 2)
                      peers-map {pub0 (:public (nth sorted-kps 0))
                                 pub1 (:public (nth sorted-kps 1))
                                 pub2 (:public (nth sorted-kps 2))}
                      t-kp (crypto/generate-keypair)
                      t-pub (basalt/bytes->hex (:public t-kp))
                      t-priv (basalt/bytes->hex (:private t-kp))
                      client-kp (crypto/generate-keypair)
                      client-pub (basalt/bytes->hex (:public client-kp))
                      faulty-kp (crypto/generate-keypair)
                      faulty-pub (basalt/bytes->hex (:public faulty-kp))
                      genesis-ledger {pub0 (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      pub1 (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      pub2 (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      client-pub (account/map->AccountState {:balance 1000000 :seq 0 :deps []})}
                      cfg (assoc config/devnet-config
                                 :genesis-ledger genesis-ledger
                                 :peers-map peers-map
                                 :validators sorted-pubs
                                 :mesh-nodes sorted-pubs
                                 :treasury-pubkey t-pub
                                 :treasury-privkey t-priv
                                 :min-stake 1000)
                      s0 (sm/init-state [] pub0 (assoc cfg :keypair (nth sorted-kps 0)))
                      s1 (sm/init-state [] pub1 (assoc cfg :keypair (nth sorted-kps 1)))
                      s2 (sm/init-state [] pub2 (assoc cfg :keypair (nth sorted-kps 2)))
                      mids (mapv #(str "msg-ep0-" %) (range msg-count))
                      inject-msgs (fn [st ms]
                                    (reduce (fn [acc mid]
                                              (-> acc
                                                  (update :contagion-known-ids conj mid)
                                                  (assoc-in [:messages mid] {:payload (.getBytes (str mid) "UTF-8")})
                                                  (update-in [:epoch-to-messages 0] (fnil conj #{}) mid)
                                                  (assoc-in [:epoch-to-message-roles 0 mid] :gossip)))
                                            st
                                            ms))
                      s0-burned (:state (sm/handle-event s0 {:type :signaling-burn :sender client-pub :burn burn-amt}))
                      s0-msgs (inject-msgs s0-burned mids)
                      s1-msgs (inject-msgs s1 mids)
                      s2-msgs (inject-msgs s2 (subvec mids 0 (max 1 (dec msg-count))))
                      ;; 1. Tick epoch 0 -> epoch 1 on all nodes
                      tick-res0 (sm/handle-event s0-msgs {:type :tick :rng (java.util.Random. 0)})
                      tick-res1 (sm/handle-event s1-msgs {:type :tick :rng (java.util.Random. 1)})
                      tick-res2 (sm/handle-event s2-msgs {:type :tick :rng (java.util.Random. 2)})
                      states-after-tick [(:state tick-res0) (:state tick-res1) (:state tick-res2)]
                      sig-cmds0 (filterv #(= :send-transcript-sig (:type %)) (:commands tick-res0))
                      cmd0-to-1 (first (filter #(= pub1 (:target %)) sig-cmds0))
                      cmd0-to-2 (first (filter #(= pub2 (:target %)) sig-cmds0))
                      ;; 2. Deliver node0 -> node1 (exact match: node1 cosigns and replies)
                      r1 (sm/handle-event (nth states-after-tick 1)
                                          {:type :receive-transcript-sig
                                           :sender pub0
                                           :target pub1
                                           :epoch (:epoch cmd0-to-1)
                                           :transcript (:transcript cmd0-to-1)
                                           :frozen-log (:frozen-log cmd0-to-1)})
                      reply1 (first (filter #(= :send-transcript-sig (:type %)) (:commands r1)))
                      ;; Deliver node1's cosigned reply back to node0
                      r0 (sm/handle-event (nth states-after-tick 0)
                                          {:type :receive-transcript-sig
                                           :sender pub1
                                           :target pub0
                                           :epoch (:epoch reply1)
                                           :transcript (:transcript reply1)})
                      ;; 3. Deliver node0 -> node2 (partial overlap: node2 responds with reconciled half-tx)
                      r2 (sm/handle-event (nth states-after-tick 2)
                                          {:type :receive-transcript-sig
                                           :sender pub0
                                           :target pub2
                                           :epoch (:epoch cmd0-to-2)
                                           :transcript (:transcript cmd0-to-2)
                                           :frozen-log (:frozen-log cmd0-to-2)})
                      reply2 (first (filter #(= :send-transcript-sig (:type %)) (:commands r2)))
                      ;; Node0 receives reconciled half-tx, cosigns and replies
                      r0-reconciled (sm/handle-event (:state r0)
                                                     {:type :receive-transcript-sig
                                                      :sender pub2
                                                      :target pub0
                                                      :epoch (:epoch reply2)
                                                      :transcript (:transcript reply2)
                                                      :frozen-log (:frozen-log reply2)
                                                      :reconciled? true})
                      reply0-cosigned (first (filter #(= :send-transcript-sig (:type %)) (:commands r0-reconciled)))
                      ;; Node2 receives cosigned transcript and stages it
                      r2-final (sm/handle-event (:state r2)
                                                {:type :receive-transcript-sig
                                                 :sender pub0
                                                 :target pub2
                                                 :epoch (:epoch reply0-cosigned)
                                                 :transcript (:transcript reply0-cosigned)})
                      ;; 4. Case B: Node1 submits half-signed dispute against withholding peer faulty-pub with signed frozen logs
                      frozen-log-faulty (attestation/sign-frozen-log 0 faulty-pub mids (:private faulty-kp))
                      half-tx-faulty (attestation/create-transcript 0 pub1 faulty-pub (mapv #(vector % :gossip) mids) (:private (nth sorted-kps 1)))
                      s1-dispute (:state (sm/handle-event (:state r1)
                                                          {:type :submit-transcript
                                                           :transcript half-tx-faulty
                                                           :counterparty-frozen-log frozen-log-faulty}))
                      ;; 5. Progress Streamlet rounds to finalize blocks 2 & 3
                      st0 (:state r0-reconciled)
                      st1 s1-dispute
                      st2 (:state r2-final)
                      states-ep2 (exchange-block-and-votes [st0 st1 st2] sorted-pubs 2)
                      states-ep3 (exchange-block-and-votes states-ep2 sorted-pubs 3)
                      states-ep4 (exchange-block-and-votes states-ep3 sorted-pubs 4)
                      states-ep5 (exchange-block-and-votes states-ep4 sorted-pubs 5)
                      states-ep6 (exchange-block-and-votes states-ep5 sorted-pubs 6)
                      final-s0 (nth states-ep6 0)
                      final-s1 (nth states-ep6 1)
                      final-s2 (nth states-ep6 2)]
                  (and (= (:settled-transcript-pairs final-s0)
                          (:settled-transcript-pairs final-s1)
                          (:settled-transcript-pairs final-s2))
                       (= (:attested-participation final-s0)
                          (:attested-participation final-s1)
                          (:attested-participation final-s2))
                       (= (:mesh-nodes final-s0)
                          (:mesh-nodes final-s1)
                          (:mesh-nodes final-s2))
                       (pos? (double (get-in final-s0 [:mesh-nodes pub0] 0.0)))
                       (pos? (double (get-in final-s0 [:mesh-nodes pub1] 0.0)))
                       (pos? (double (get-in final-s0 [:mesh-nodes pub2] 0.0)))
                       (= (:ledger final-s0)
                          (:ledger final-s1)
                          (:ledger final-s2))
                       (= (:total-minted final-s0)
                          (:total-minted final-s1)
                          (:total-minted final-s2))
                       (pos? (:total-minted final-s0))
                       (= 1 (get-in final-s0 [:fault-strikes faulty-pub]))
                       (= 1 (get-in final-s1 [:fault-strikes faulty-pub]))
                       (= 1 (get-in final-s2 [:fault-strikes faulty-pub]))))))

(defspec ^{:doc "Property: Escrow operations strictly conserve supply (initial_supply - released_takes = balances + locked_escrows) across arbitrary command sequences and prevent double-settlement."}
  prop-escrow-conservation-and-no-double-settlement 50
  (prop/for-all [initial-alice-bal (gen/choose 10000 50000)
                 take-bps (gen/choose 10 100)
                 ops (gen/vector
                      (gen/one-of
                       [(gen/tuple (gen/return :lock) (gen/choose 0 2) (gen/choose 100 2000) (gen/choose 5 50))
                        (gen/tuple (gen/return :release-preimage) (gen/choose 0 2))
                        (gen/tuple (gen/return :release-sig) (gen/choose 0 2))
                        (gen/tuple (gen/return :release-bad-preimage) (gen/choose 0 2))
                        (gen/tuple (gen/return :refund-voluntary) (gen/choose 0 2))
                        (gen/tuple (gen/return :refund-timeout) (gen/choose 0 2))
                        (gen/tuple (gen/return :advance-epoch) (gen/choose 1 10))])
                      1 25)]
                (let [alice-kp (crypto/generate-keypair)
                      alice-pub (basalt/bytes->hex (:public alice-kp))
                      bob-kp (crypto/generate-keypair)
                      bob-pub (basalt/bytes->hex (:public bob-kp))
                      secrets (mapv #(str "secret-val-" %) (range 3))
                      hashes (mapv (fn [s] (basalt/bytes->hex (crypto/sha256 (.getBytes (str s) "UTF-8")))) secrets)
                      cfg (assoc config/default-config
                                 :settlement-take-bps take-bps
                                 :genesis-ledger {alice-pub (account/map->AccountState {:balance initial-alice-bal :seq 0 :deps []})
                                                  bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})})
                      init-st (assoc (sm/init-state [] alice-pub cfg) :epoch 1)
                      final-st (first
                                (reduce
                                 (fn [[st active-eids] [op-type arg1 arg2 arg3]]
                                   (case op-type
                                     :advance-epoch
                                     [(update st :epoch (fnil + 1) arg1) active-eids]

                                     :lock
                                     (let [idx arg1
                                           amt arg2
                                           dur arg3
                                           ep (long (or (:epoch st) 1))
                                           exp-ep (+ ep dur)
                                           d-hash (nth hashes idx)
                                           eid (escrow/compute-escrow-id alice-pub bob-pub amt d-hash ep exp-ep (str "gen-" ep "-" idx))
                                           res (sm/handle-event st {:type :lock-intent
                                                                    :escrow-id eid
                                                                    :payer alice-pub
                                                                    :receiver bob-pub
                                                                    :amount amt
                                                                    :deliverable-hash d-hash
                                                                    :created-epoch ep
                                                                    :expires-epoch exp-ep
                                                                    :sender alice-pub})
                                           new-st (:state res)]
                                       (if (= :locked (get-in new-st [:escrows eid :status]))
                                         [new-st (assoc active-eids idx eid)]
                                         [new-st active-eids]))

                                     :release-preimage
                                     (let [idx arg1
                                           eid (get active-eids idx)
                                           preimage (nth secrets idx)
                                           res (if eid
                                                 (sm/handle-event st {:type :release-intent
                                                                      :escrow-id eid
                                                                      :preimage preimage
                                                                      :sender bob-pub
                                                                      :epoch (:epoch st)})
                                                 {:state st})]
                                       [(:state res) active-eids])

                                     :release-sig
                                     (let [idx arg1
                                           eid (get active-eids idx)
                                           d-hash (nth hashes idx)
                                           payer-sig (when eid (escrow/sign-escrow-release (:private alice-kp) eid d-hash))
                                           res (if eid
                                                 (sm/handle-event st {:type :release-intent
                                                                      :escrow-id eid
                                                                      :payer-signature payer-sig
                                                                      :sender bob-pub
                                                                      :epoch (:epoch st)})
                                                 {:state st})]
                                       [(:state res) active-eids])

                                     :release-bad-preimage
                                     (let [idx arg1
                                           eid (get active-eids idx)
                                           res (if eid
                                                 (sm/handle-event st {:type :release-intent
                                                                      :escrow-id eid
                                                                      :preimage "corrupted-preimage"
                                                                      :sender bob-pub
                                                                      :epoch (:epoch st)})
                                                 {:state st})]
                                       [(:state res) active-eids])

                                     :refund-voluntary
                                     (let [idx arg1
                                           eid (get active-eids idx)
                                           res (if eid
                                                 (sm/handle-event st {:type :refund-intent
                                                                      :escrow-id eid
                                                                      :sender bob-pub
                                                                      :epoch (:epoch st)})
                                                 {:state st})]
                                       [(:state res) active-eids])

                                     :refund-timeout
                                     (let [idx arg1
                                           eid (get active-eids idx)
                                           res (if eid
                                                 (sm/handle-event st {:type :refund-intent
                                                                      :escrow-id eid
                                                                      :sender alice-pub
                                                                      :epoch (:epoch st)})
                                                 {:state st})]
                                       [(:state res) active-eids])))
                                 [init-st {}]
                                 ops))
                      final-alice (or (:balance (get-in final-st [:ledger alice-pub])) 0)
                      final-bob (or (:balance (get-in final-st [:ledger bob-pub])) 0)
                      final-takes (reduce + 0 (vals (:epoch-settlement-takes final-st)))
                      locked-sum (reduce + 0 (map :amount (filter #(= :locked (:status %)) (vals (:escrows final-st)))))]
                  (and
                   (= initial-alice-bal (+ final-alice final-bob final-takes locked-sum))
                   (every? (fn [[_ esc]] (contains? #{:locked :released :refunded} (:status esc)))
                           (:escrows final-st))))))

(deftest test-escrow-unit-fail-closed-guards
  (testing "Escrow fail-closed guards on sender spoofing, self-dealing, invalid hashes, amounts, and dates"
    (let [alice-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          bob-kp (crypto/generate-keypair)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          cfg (assoc config/default-config
                     :genesis-ledger {alice-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                      bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})})
          st (assoc (sm/init-state [] alice-pub cfg) :epoch 1)]

      ;; 1. Sender spoofing on lock-intent fails closed
      (let [res (sm/handle-event st {:type :lock-intent
                                     :payer alice-pub
                                     :receiver bob-pub
                                     :amount 500
                                     :deliverable-hash d-hash
                                     :expires-epoch 10
                                     :sender bob-pub})]
        (is (= st (:state res))))

      ;; 2. Self-dealing (payer == receiver) fails closed
      (let [res (sm/handle-event st {:type :lock-intent
                                     :payer alice-pub
                                     :receiver alice-pub
                                     :amount 500
                                     :deliverable-hash d-hash
                                     :expires-epoch 10
                                     :sender alice-pub})]
        (is (= st (:state res))))

      ;; 3. Invalid deliverable-hash fails closed
      (let [res (sm/handle-event st {:type :lock-intent
                                     :payer alice-pub
                                     :receiver bob-pub
                                     :amount 500
                                     :deliverable-hash "not-hex-64"
                                     :expires-epoch 10
                                     :sender alice-pub})]
        (is (= st (:state res))))

      ;; 4. Non-positive or non-integer amount fails closed
      (let [res-zero (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 0 :deliverable-hash d-hash :expires-epoch 10})
            res-neg (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount -100 :deliverable-hash d-hash :expires-epoch 10})
            res-float (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 50.5 :deliverable-hash d-hash :expires-epoch 10})]
        (is (= st (:state res-zero)))
        (is (= st (:state res-neg)))
        (is (= st (:state res-float))))

      ;; 5. Insufficient balance fails closed
      (let [res (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 5000 :deliverable-hash d-hash :expires-epoch 10})]
        (is (= st (:state res))))

      ;; 6. Voluntary receiver early refund succeeds before timeout
      (let [eid (escrow/compute-escrow-id alice-pub bob-pub 500 d-hash 1 10 "1")
            locked-st (:state (sm/handle-event st {:type :lock-intent
                                                   :escrow-id eid
                                                   :payer alice-pub
                                                   :receiver bob-pub
                                                   :amount 500
                                                   :deliverable-hash d-hash
                                                   :expires-epoch 10
                                                   :sender alice-pub}))
            refund-res (sm/handle-event locked-st {:type :refund-intent
                                                   :escrow-id eid
                                                   :sender bob-pub
                                                   :epoch 2})]
        (is (= :refunded (get-in (:state refund-res) [:escrows eid :status])))
        (is (= 1000 (:balance (get-in (:state refund-res) [:ledger alice-pub])))))

      ;; 7. Payer outcome signature release succeeds
      (let [eid (escrow/compute-escrow-id alice-pub bob-pub 500 d-hash 1 10 "2")
            locked-st (:state (sm/handle-event st {:type :lock-intent
                                                   :escrow-id eid
                                                   :payer alice-pub
                                                   :receiver bob-pub
                                                   :amount 500
                                                   :deliverable-hash d-hash
                                                   :expires-epoch 10
                                                   :sender alice-pub}))
            payer-sig (escrow/sign-escrow-release (:private alice-kp) eid d-hash)
            release-res (sm/handle-event locked-st {:type :release-intent
                                                    :escrow-id eid
                                                    :payer-signature payer-sig
                                                    :sender bob-pub
                                                    :epoch 2})]
        (is (= :released (get-in (:state release-res) [:escrows eid :status])))
        (is (pos? (:balance (get-in (:state release-res) [:ledger bob-pub]))))))))

(deftest test-consensus-escrow-streamlet-finalization-and-spendable-balance
  (testing "Consensus mode: spendable-balance is deducted by pending lock-intent, and finalized blocks apply escrows"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          bob-kp (crypto/generate-keypair)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                      bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)})
          s0 (assoc (sm/init-state [] pub (assoc cfg :keypair kp)) :epoch 1)
          eid (escrow/compute-escrow-id pub bob-pub 400 d-hash 1 10 "c1")
          lock-res (sm/handle-event s0 {:type :lock-intent
                                        :escrow-id eid
                                        :payer pub
                                        :receiver bob-pub
                                        :amount 400
                                        :deliverable-hash d-hash
                                        :expires-epoch 10
                                        :sender pub})
          s1 (:state lock-res)]
      ;; 1. Pending receipt stages cleanly and spendable-balance is reduced
      (is (= 1 (count (:pending-receipts s1))))
      (is (= 600 (sm/spendable-balance s1 pub)))
      ;; 2. Attempting to lock another 700 fails closed because spendable is only 600
      (let [bad-lock (sm/handle-event s1 {:type :lock-intent
                                          :payer pub
                                          :receiver bob-pub
                                          :amount 700
                                          :deliverable-hash d-hash
                                          :expires-epoch 10
                                          :sender pub})]
        (is (= 1 (count (:pending-receipts (:state bad-lock))))))
      ;; 3. Execute block with lock receipt
      (let [lock-receipt (first (:pending-receipts s1))
            block {:epoch 2 :parent-hash "genesis" :payload [lock-receipt]}
            s-after-block (sm/execute-finalized-blocks (assoc s1 :finalized-blocks #{(streamlet/hash-block block)}
                                                              :blocks {(streamlet/hash-block block) block}
                                                              :head-hash (streamlet/hash-block block)))]
        (is (= 600 (:balance (get-in s-after-block [:ledger pub]))))
        (is (= :locked (get-in s-after-block [:escrows eid :status])))
        ;; 4. Execute block with release receipt
        (let [payer-sig (escrow/sign-escrow-release (:private kp) eid d-hash)
              release-receipt {:receipt-id (str "release:" eid)
                               :type :release-intent
                               :escrow-id eid
                               :payer-signature payer-sig
                               :sender bob-pub}
              block2 {:epoch 3 :parent-hash (streamlet/hash-block block) :payload [release-receipt]}
              s-after-rel (sm/execute-finalized-blocks (assoc s-after-block
                                                              :finalized-blocks #{(streamlet/hash-block block)
                                                                                  (streamlet/hash-block block2)}
                                                              :blocks {(streamlet/hash-block block) block
                                                                       (streamlet/hash-block block2) block2}
                                                              :head-hash (streamlet/hash-block block2)))]
          (is (= :released (get-in s-after-rel [:escrows eid :status])))
          (is (= 398 (:balance (get-in s-after-rel [:ledger bob-pub])))) ;; 400 - 2 (50 bps take) = 398
          (is (= 2 (get-in s-after-rel [:epoch-settlement-takes 2]))))))))

(deftest test-escrow-epoch-integer-guards
  (testing "handle-event fails closed without ClassCastException when epochs are strings or booleans"
    (let [alice-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          bob-kp (crypto/generate-keypair)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          cfg (assoc config/default-config
                     :genesis-ledger {alice-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                      bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})})
          st (assoc (sm/init-state [] alice-pub cfg) :epoch 1)]
      ;; string epoch on lock-intent
      (is (= st (:state (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 100 :deliverable-hash d-hash :epoch "1" :expires-epoch 5}))))
      ;; string created-epoch on lock-intent
      (is (= st (:state (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 100 :deliverable-hash d-hash :created-epoch "1" :expires-epoch 5}))))
      ;; string expires-epoch on lock-intent
      (is (= st (:state (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 100 :deliverable-hash d-hash :created-epoch 1 :expires-epoch "5"}))))
      ;; boolean epoch on lock-intent
      (is (= st (:state (sm/handle-event st {:type :lock-intent :payer alice-pub :receiver bob-pub :amount 100 :deliverable-hash d-hash :epoch true :expires-epoch 5}))))
      ;; string/boolean epoch on release-intent
      (is (= st (:state (sm/handle-event st {:type :release-intent :escrow-id "eid" :epoch "2"}))))
      (is (= st (:state (sm/handle-event st {:type :release-intent :escrow-id "eid" :epoch true}))))
      ;; string/boolean epoch on refund-intent
      (is (= st (:state (sm/handle-event st {:type :refund-intent :escrow-id "eid" :epoch "10"}))))
      (is (= st (:state (sm/handle-event st {:type :refund-intent :escrow-id "eid" :epoch false})))))))

(deftest test-escrow-epoch-horizon-and-pruning
  (testing "168-epoch horizon rejects stale locks and prunes settled escrows past horizon while keeping active ones"
    (let [alice-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          bob-kp (crypto/generate-keypair)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          charlie-kp (crypto/generate-keypair)
          charlie-pub (basalt/bytes->hex (:public charlie-kp))
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          cfg (assoc config/default-config
                     :genesis-ledger {alice-pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})
                                      charlie-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})})
          s0 (assoc (sm/init-state [] alice-pub cfg) :epoch 200)]
      ;; 1. Rejects lock with created-epoch < current-epoch - 168 (created-epoch 30 < 200 - 168 = 32)
      (let [res-stale (sm/handle-event s0 {:type :lock-intent
                                           :payer alice-pub
                                           :receiver bob-pub
                                           :amount 100
                                           :deliverable-hash d-hash
                                           :created-epoch 30
                                           :expires-epoch 40
                                           :sender alice-pub})]
        (is (= s0 (:state res-stale))))

      ;; 2. Rejects lock with horizon duration > 168 epochs (expires-epoch - created-epoch > 168)
      (let [res-too-long (sm/handle-event s0 {:type :lock-intent
                                              :payer alice-pub
                                              :receiver bob-pub
                                              :amount 100
                                              :deliverable-hash d-hash
                                              :created-epoch 200
                                              :expires-epoch 400
                                              :sender alice-pub})]
        (is (= s0 (:state res-too-long))))

      ;; 3. Lock valid escrow 1 (to be released at epoch 201) and escrow 2 (remains locked)
      (let [eid1 (escrow/compute-escrow-id alice-pub bob-pub 200 d-hash 200 250 "h1")
            eid2 (escrow/compute-escrow-id alice-pub bob-pub 300 d-hash 200 350 "h2")
            s1 (:state (sm/handle-event s0 {:type :lock-intent :escrow-id eid1 :payer alice-pub :receiver bob-pub :amount 200 :deliverable-hash d-hash :created-epoch 200 :expires-epoch 250 :sender alice-pub}))
            s2 (:state (sm/handle-event s1 {:type :lock-intent :escrow-id eid2 :payer alice-pub :receiver bob-pub :amount 300 :deliverable-hash d-hash :created-epoch 200 :expires-epoch 350 :sender alice-pub}))
            payer-sig (escrow/sign-escrow-release (:private alice-kp) eid1 d-hash)
            s3 (:state (sm/handle-event s2 {:type :release-intent :escrow-id eid1 :payer-signature payer-sig :sender bob-pub :epoch 201}))]
        (is (= :released (get-in s3 [:escrows eid1 :status])))
        (is (= 201 (get-in s3 [:escrows eid1 :settled-epoch])))
        (is (= :locked (get-in s3 [:escrows eid2 :status])))
        (is (contains? (:settled-escrow-ids s3) eid1))

        ;; 4. Verify timeout refund authorization (Note 3):
        ;; Try refunding eid1 (already released) -> fails closed
        (is (= s3 (:state (sm/handle-event s3 {:type :refund-intent :escrow-id eid1 :sender alice-pub :epoch 260}))))
        ;; At epoch 360 (> expires-epoch 350 of eid2), third-party charlie attempts timeout refund -> fails closed
        (let [s-timeout (assoc s3 :epoch 360)
              charlie-res (sm/handle-event s-timeout {:type :refund-intent :escrow-id eid2 :sender charlie-pub :epoch 360})]
          (is (= s-timeout (:state charlie-res)))
          ;; Payer can trigger timeout refund
          (let [payer-res (sm/handle-event s-timeout {:type :refund-intent :escrow-id eid2 :sender alice-pub :epoch 360})]
            (is (= :refunded (get-in (:state payer-res) [:escrows eid2 :status])))))

        ;; 5. Test pruning: advance tick to epoch 400 (escrow-cutoff = 400 - 168 = 232).
        ;; Settled eid1 (settled at 201 <= 232) is pruned from :escrows!
        ;; Active eid2 (unsettled) remains!
        (let [s-pruned (#'sm/prune-expired-tick-state s3 400 168)]
          (is (nil? (get-in s-pruned [:escrows eid1])))
          (is (some? (get-in s-pruned [:escrows eid2])))
          (is (= :locked (get-in s-pruned [:escrows eid2 :status]))))))))

(deftest test-consensus-lock-intent-rejects-stale-created-epoch
  (testing "In consensus mode (with :peers-map), lock-intent with created-epoch < current-epoch - 168 is rejected without clamping"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          bob-kp (crypto/generate-keypair)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          cfg (assoc config/devnet-config
                     :genesis-ledger {pub (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                     :peers-map {pub (:public kp)})
          s0 (assoc (sm/init-state [] pub (assoc cfg :keypair kp)) :epoch 200)
          ;; created-epoch 30 is < 200 - 168 = 32 -> stale!
          res-stale (sm/handle-event s0 {:type :lock-intent
                                         :payer pub
                                         :receiver bob-pub
                                         :amount 100
                                         :deliverable-hash d-hash
                                         :created-epoch 30
                                         :expires-epoch 40
                                         :sender pub})]
      (is (= s0 (:state res-stale)))
      (is (empty? (:pending-receipts (:state res-stale)))))))

(deftest test-three-node-streamlet-escrow-finalization-convergence
  (testing "3-node Streamlet cluster converges on lock, release, and refund finalized block execution"
    (let [kps (take 3 (repeatedly crypto/generate-keypair))
          pubs (mapv #(basalt/bytes->hex (:public %)) kps)
          sorted-indices (sort-by #(nth pubs %) (range 3))
          sorted-kps (mapv #(nth kps %) sorted-indices)
          sorted-pubs (mapv #(nth pubs %) sorted-indices)
          pub0 (nth sorted-pubs 0)
          pub1 (nth sorted-pubs 1)
          pub2 (nth sorted-pubs 2)
          peers-map {pub0 (:public (nth sorted-kps 0))
                     pub1 (:public (nth sorted-kps 1))
                     pub2 (:public (nth sorted-kps 2))}
          client-kp (crypto/generate-keypair)
          client-pub (basalt/bytes->hex (:public client-kp))
          receiver-kp (crypto/generate-keypair)
          receiver-pub (basalt/bytes->hex (:public receiver-kp))
          secret1 "deliverable-alpha"
          d-hash1 (basalt/bytes->hex (crypto/sha256 (.getBytes secret1 "UTF-8")))
          d-hash2 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          genesis-ledger {pub0 (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                          pub1 (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                          pub2 (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                          client-pub (account/map->AccountState {:balance 1000000 :seq 0 :deps []})
                          receiver-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
          cfg (assoc config/devnet-config
                     :genesis-ledger genesis-ledger
                     :peers-map peers-map
                     :validators sorted-pubs
                     :mesh-nodes sorted-pubs
                     :settlement-take-bps 50)
          init-s0 (sm/init-state [] pub0 (assoc cfg :keypair (nth sorted-kps 0)))
          init-s1 (sm/init-state [] pub1 (assoc cfg :keypair (nth sorted-kps 1)))
          init-s2 (sm/init-state [] pub2 (assoc cfg :keypair (nth sorted-kps 2)))
          eid1 (escrow/compute-escrow-id client-pub receiver-pub 400 d-hash1 0 10 "streamlet-1")
          eid2 (escrow/compute-escrow-id client-pub receiver-pub 600 d-hash2 0 2 "streamlet-2")
          ;; Epoch 1: Proposer is node1 (pub1). Stage lock-intent for eid1 and eid2 on node1
          s1-l1 (:state (sm/handle-event init-s1 {:type :lock-intent :escrow-id eid1 :payer client-pub :receiver receiver-pub :amount 400 :deliverable-hash d-hash1 :created-epoch 0 :expires-epoch 10 :sender client-pub}))
          s1-l2 (:state (sm/handle-event s1-l1 {:type :lock-intent :escrow-id eid2 :payer client-pub :receiver receiver-pub :amount 600 :deliverable-hash d-hash2 :created-epoch 0 :expires-epoch 2 :sender client-pub}))
          states-ep1 (exchange-block-and-votes [init-s0 s1-l2 init-s2] sorted-pubs 1)
          ;; Epoch 2: Proposer is node2 (pub2)
          states-ep2 (exchange-block-and-votes states-ep1 sorted-pubs 2)
          ;; Epoch 3: Proposer is node0 (pub0). Block 3 notarized -> 3-chain finalizes Block 1!
          states-ep3 (exchange-block-and-votes states-ep2 sorted-pubs 3)
          ;; Epoch 4: Proposer is node1 (pub1). Now eid1 is locked in :escrows! Stage release-intent on node1.
          s1-rel (:state (sm/handle-event (nth states-ep3 1) {:type :release-intent :escrow-id eid1 :preimage secret1 :sender receiver-pub :epoch 4}))
          states-ep4 (exchange-block-and-votes [(nth states-ep3 0) s1-rel (nth states-ep3 2)] sorted-pubs 4)
          ;; Epoch 5: Proposer is node2 (pub2). Stage refund-intent for eid2 on node2 (epoch 5 > expires-epoch 2)
          s2-ref (:state (sm/handle-event (nth states-ep4 2) {:type :refund-intent :escrow-id eid2 :sender client-pub :epoch 5}))
          states-ep5 (exchange-block-and-votes [(nth states-ep4 0) (nth states-ep4 1) s2-ref] sorted-pubs 5)
          ;; Epoch 6: Proposer is node0 (pub0). Finalizes Block 4 (release-intent)!
          states-ep6 (exchange-block-and-votes states-ep5 sorted-pubs 6)
          ;; Epoch 7: Proposer is node1 (pub1). Finalizes Block 5 (refund-intent)!
          states-ep7 (exchange-block-and-votes states-ep6 sorted-pubs 7)
          s0-final (nth states-ep7 0)
          s1-final (nth states-ep7 1)
          s2-final (nth states-ep7 2)]
      ;; All 3 nodes converged to identical ledger, escrows, and settlement takes
      (is (= (:ledger s0-final) (:ledger s1-final) (:ledger s2-final)))
      (is (= (:escrows s0-final) (:escrows s1-final) (:escrows s2-final)))
      (is (= (:epoch-settlement-takes s0-final) (:epoch-settlement-takes s1-final) (:epoch-settlement-takes s2-final)))
      (is (= :released (get-in s0-final [:escrows eid1 :status])))
      (is (= :refunded (get-in s0-final [:escrows eid2 :status])))
      ;; Take on 400 at 50 bps (0.5%) = 2
      ;; Receiver net = 398
      (is (= 398 (:balance (get-in s0-final [:ledger receiver-pub]))))
      ;; Client: 1000000 - 400 (eid1) - 600 (eid2) + 600 (refund) = 999600
      (is (= 999600 (:balance (get-in s0-final [:ledger client-pub])))))))

(defspec ^{:doc "Property: Basalt view exchange and Murmur gossip fanout never include local node pubkey or gossip sender when remote peers exist"}
  prop-basalt-push-view-and-murmur-exclude-self-and-sender 25
  (prop/for-all [seed (gen/choose 1 10000)
                 payload-str (gen/not-empty gen/string-alphanumeric)]
                (let [kp1 (crypto/generate-keypair)
                      kp2 (crypto/generate-keypair)
                      kp3 (crypto/generate-keypair)
                      pub1 (basalt/bytes->hex (:public kp1))
                      pub2 (basalt/bytes->hex (:public kp2))
                      pub3 (basalt/bytes->hex (:public kp3))
                      peer1 (basalt/make-peer "10.0.0.1" 5000 (:public kp1))
                      peer2 (basalt/make-peer "10.0.0.2" 5000 (:public kp2))
                      peer3 (basalt/make-peer "10.0.0.3" 5000 (:public kp3))
                      cfg (assoc config/devnet-config
                                 :murmur-k 2
                                 :genesis-ledger {pub1 (account/map->AccountState {:balance 100000 :seq 0 :deps []})
                                                  pub2 (account/map->AccountState {:balance 100000 :seq 0 :deps []})
                                                  pub3 (account/map->AccountState {:balance 100000 :seq 0 :deps []})}
                                 :peers-map {pub1 (:public kp1) pub2 (:public kp2) pub3 (:public kp3)}
                                 :validators [pub1 pub2 pub3]
                                 :mesh-nodes [pub1 pub2 pub3])
                      s0 (sm/init-state [peer2 peer3] pub1 (assoc cfg :keypair kp1))
                      ;; Peer 2 pushes its Basalt view (which includes peer1 = self!) to node 1
                      s1 (:state (sm/handle-event s0 {:type :receive-push-view
                                                      :sender pub2
                                                      :view [peer1 peer3]}))
                      view-pubs (set (map #(let [pk (:pubkey %)] (if (string? pk) pk (basalt/bytes->hex pk)))
                                          (basalt/extract-peers (:basalt-view s1))))
                      ;; Peer 2 sends a gossip message to node 1; with murmur-k=2 and only peer3 remaining, node 1 must forward to peer3 (never peer1 or peer2)
                      gossip-msg (sieve/wrap-message (.getBytes payload-str "UTF-8") (:private kp2) (:public kp2) 500)
                      res-gossip (sm/handle-event s1 {:type :receive-gossip
                                                      :sender pub2
                                                      :message gossip-msg
                                                      :rng (java.util.Random. (long seed))})
                      gossip-cmd (first (filter #(= :send-gossip (:type %)) (:commands res-gossip)))
                      target-pubs (set (map #(let [pk (:pubkey %)] (if (string? pk) pk (basalt/bytes->hex pk)))
                                            (:targets gossip-cmd)))]
                  (and (not (contains? view-pubs pub1))
                       (= #{pub2 pub3} view-pubs)
                       (= #{pub3} target-pubs)))))

(deftest test-murmur-two-peer-view-never-echoes-back-to-sender
  (testing "In a 2-peer network (self + hop-sender), handle-receive-gossip accepts message into cache and receipts but emits zero :send-gossip commands back to sender"
    (let [kp1 (crypto/generate-keypair)
          pub1 (basalt/bytes->hex (:public kp1))
          kp2 (crypto/generate-keypair)
          pub2 (basalt/bytes->hex (:public kp2))
          peer2 {:pubkey pub2 :ip "127.0.0.1" :port 5002}
          cfg (assoc config/devnet-config
                     :murmur-k 2
                     :genesis-ledger {pub1 (account/map->AccountState {:balance 100000 :seq 0 :deps []})
                                      pub2 (account/map->AccountState {:balance 100000 :seq 0 :deps []})}
                     :peers-map {pub1 (:public kp1) pub2 (:public kp2)}
                     :validators [pub1 pub2]
                     :mesh-nodes [pub1 pub2])
          s0 (sm/init-state [peer2] pub1 (assoc cfg :keypair kp1))
          gossip-msg (sieve/wrap-message (.getBytes "two-peer test payload" "UTF-8") (:private kp2) (:public kp2) 500)
          msg-id (basalt/bytes->hex (crypto/sha256 (:payload gossip-msg)))
          res (sm/handle-event s0 {:type :receive-gossip
                                   :sender pub2
                                   :message gossip-msg
                                   :rng (java.util.Random. 42)})]
      ;; 1. Accepted into cache and receipts
      (is (contains? (:contagion-known-ids (:state res)) msg-id))
      (is (contains? (get-in (:state res) [:murmur-cache :set]) msg-id))
      (is (= 1 (count (:pending-receipts (:state res)))))
      (is (= (str "gossip-burn:" msg-id) (:receipt-id (first (:pending-receipts (:state res))))))
      ;; 2. Never echoes back to sender: zero :send-gossip commands
      (is (empty? (filter #(= :send-gossip (:type %)) (:commands res)))))))


