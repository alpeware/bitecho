(ns bitecho.state-machine-test
  "Tests for the pure state machine integrating Basalt, Murmur, Sieve, and Contagion."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.treasury :as treasury]
            [bitecho.rendezvous.core :as rdv]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
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

      (testing "Inbound gossip where sender is local node (node-pubkey) does not deduct again"
        (let [self-cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
              self-state (assoc (sm/init-state [peer] sender-pub self-cfg) :epoch 0)
              inbound-res (sm/handle-event self-state {:type :receive-gossip :message msg :rng (java.util.Random. 42)})
              new-state (:state inbound-res)]
          (is (= 1000 (:balance (get-in new-state [:ledger sender-pub]))))
          (is (nil? (get-in new-state [:epoch-burns 0])))
          (is (contains? (:contagion-known-ids new-state) (:message-id msg))))))))

(defspec ^{:doc "Property: Inbound gossip enforces burn deduction and conservation for funded senders, and drops underfunded or tampered gossip"}
  prop-inbound-gossip-burn-enforcement 50
  (prop/for-all [initial-balance (gen/choose 0 500)
                 burn-amt (gen/choose 100 300)
                 tamper-burn? gen/boolean]
                (let [peer {:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "peer-a"}
                      kp (crypto/generate-keypair)
                      sender-pub (basalt/bytes->hex (:public kp))
                      sender-priv (:private kp)
                      payload (.getBytes "prop-gossip-payload" "UTF-8")
                      raw-msg (sieve/wrap-message payload sender-priv (:public kp) burn-amt)
                      msg (assoc raw-msg :message-id "msg-prop-1")
                      final-msg (if tamper-burn? (assoc msg :burn-amount (+ burn-amt 50)) msg)
                      cfg (assoc config/default-config :genesis-ledger {sender-pub (account/map->AccountState {:balance initial-balance :seq 0 :deps []})})
                      state (assoc (sm/init-state [peer] "node-local" cfg) :epoch 0)
                      res (sm/handle-event state {:type :receive-gossip :message final-msg :rng (java.util.Random. 42)})
                      new-state (:state res)
                      sender-bal (or (:balance (get-in new-state [:ledger sender-pub])) 0)
                      epoch-burns (or (get-in new-state [:epoch-burns 0]) 0)]
                  (if (and (not tamper-burn?) (>= initial-balance burn-amt))
                    (and (= (- initial-balance burn-amt) sender-bal)
                         (= burn-amt epoch-burns)
                         (contains? (:contagion-known-ids new-state) "msg-prop-1")
                         (seq (:commands res)))
                    (and (= initial-balance sender-bal)
                         (zero? epoch-burns)
                         (= state new-state)
                         (empty? (:commands res)))))))

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
                       :frozen-epoch-messages {0 #{"m1"}})]
      (testing "Fabricated unilateral report is rejected and does NOT strike peer B"
        (let [res (sm/handle-event state {:type :submit-transcript :transcript fabricated-half})
              new-state (:state res)]
          (is (= {} (:fault-strikes new-state)) "Honest peer B was NOT struck")))

      (testing "Log-verified half-signed transcript credits peer A and records a strike on peer B"
        (let [res (sm/handle-event state {:type :submit-transcript
                                          :transcript valid-half
                                          :frozen-log-roles honest-roles})
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
      (is (= #{} (:settled-voucher-tuples state)))))

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
                         (assoc-in [:home-sets [callee-pub 0]]
                                   {:status :ok :home-nodes candidates :price 10 :degraded? false}))]

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
                      expected-debit (* seq-num price)
                      actual-transfer (min callee-init-bal expected-debit)]
                  (and (= total-before total-after)
                       (= final-callee-bal (- callee-init-bal actual-transfer))
                       (= final-home-bal (+ home-init-bal actual-transfer))))))

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



