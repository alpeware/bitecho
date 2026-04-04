(ns bitecho.economy.account-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [clojure.test :refer [deftest is testing]]))

(deftest account-records-test
  (testing "AccountState record creation"
    (let [state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})]
      (is (= 100 (:balance state)))
      (is (= 5 (:seq state)))
      (is (= ["hash1" "hash2"] (:deps state)))))

  (testing "Transfer record creation"
    (let [transfer (account/map->Transfer {:sender "pubkey1"
                                           :receiver "pubkey2"
                                           :amount 50
                                           :seq 6
                                           :deps ["hash3"]
                                           :signature "sig123"})]
      (is (= "pubkey1" (:sender transfer)))
      (is (= "pubkey2" (:receiver transfer)))
      (is (= 50 (:amount transfer)))
      (is (= 6 (:seq transfer)))
      (is (= ["hash3"] (:deps transfer)))
      (is (= "sig123" (:signature transfer))))))

(deftest validate-transfer-test
  (testing "Valid transfer"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          privkey (:private keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          unsigned-transfer {:sender pubkey
                             :receiver "pubkey2"
                             :amount 50
                             :seq 6
                             :deps ["hash1" "hash2"]}
          payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature)))]
      (is (true? (account/validate-transfer state transfer)))))

  (testing "Invalid seq - not incremented by 1"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          privkey (:private keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          unsigned-transfer {:sender pubkey
                             :receiver "pubkey2"
                             :amount 50
                             :seq 7
                             :deps ["hash1" "hash2"]}
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature signature))]
      (is (false? (account/validate-transfer state transfer)))))

  (testing "Invalid seq - same sequence"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          privkey (:private keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          unsigned-transfer {:sender pubkey
                             :receiver "pubkey2"
                             :amount 50
                             :seq 5
                             :deps ["hash1" "hash2"]}
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature signature))]
      (is (false? (account/validate-transfer state transfer)))))

  (testing "Invalid deps - mismatch"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          privkey (:private keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          unsigned-transfer {:sender pubkey
                             :receiver "pubkey2"
                             :amount 50
                             :seq 6
                             :deps ["hash1" "hash3"]}
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature signature))]
      (is (false? (account/validate-transfer state transfer)))))

  (testing "Invalid balance - not enough funds"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          privkey (:private keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          unsigned-transfer {:sender pubkey
                             :receiver "pubkey2"
                             :amount 150
                             :seq 6
                             :deps ["hash1" "hash2"]}
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature signature))]
      (is (false? (account/validate-transfer state transfer)))))

  (testing "Invalid signature - tampered amount"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          privkey (:private keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          unsigned-transfer {:sender pubkey
                             :receiver "pubkey2"
                             :amount 50
                             :seq 6
                             :deps ["hash1" "hash2"]}
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          tampered-transfer (account/map->Transfer (assoc unsigned-transfer :amount 60 :signature signature))]
      (is (false? (account/validate-transfer state tampered-transfer)))))

  (testing "Invalid signature - completely invalid signature bytes"
    (let [keys (crypto/generate-keypair)
          pubkey (:public keys)
          state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})
          transfer (account/map->Transfer {:sender pubkey
                                           :receiver "pubkey2"
                                           :amount 50
                                           :seq 6
                                           :deps ["hash1" "hash2"]
                                           :signature (byte-array 64)})]
      (is (false? (account/validate-transfer state transfer))))))

(deftest apply-transfer-test
  (testing "Valid apply-transfer"
    (let [keys1 (crypto/generate-keypair)
          sender-pubkey (:public keys1)
          sender-privkey (:private keys1)
          receiver-pubkey "pubkey2"
          initial-sender-state (account/map->AccountState {:balance 100 :seq 5 :deps ["hash1"]})
          ledger {sender-pubkey initial-sender-state}
          unsigned-transfer {:sender sender-pubkey
                             :receiver receiver-pubkey
                             :amount 40
                             :seq 6
                             :deps ["hash1"]}
          payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
          signature (crypto/sign sender-privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature)))
          updated-ledger (account/apply-transfer ledger transfer)
          safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (byte-array (map byte (:signature transfer)))))
          transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))]
      (is (= 60 (:balance (get updated-ledger sender-pubkey))))
      (is (= 6 (:seq (get updated-ledger sender-pubkey))))
      (is (= [transfer-hash] (:deps (get updated-ledger sender-pubkey))))
      (is (= 40 (:balance (get updated-ledger receiver-pubkey))))
      (is (= 0 (:seq (get updated-ledger receiver-pubkey))))
      (is (= [] (:deps (get updated-ledger receiver-pubkey))))))

  (testing "Invalid apply-transfer (bad signature)"
    (let [keys1 (crypto/generate-keypair)
          sender-pubkey (:public keys1)
          receiver-pubkey "pubkey2"
          initial-sender-state (account/map->AccountState {:balance 100 :seq 5 :deps ["hash1"]})
          ledger {sender-pubkey initial-sender-state}
          unsigned-transfer {:sender sender-pubkey
                             :receiver receiver-pubkey
                             :amount 40
                             :seq 6
                             :deps ["hash1"]}
          transfer (account/map->Transfer (assoc unsigned-transfer :signature (byte-array 64)))
          updated-ledger (account/apply-transfer ledger transfer)]
      (is (= ledger updated-ledger))))

  (testing "Valid apply-transfer with existing receiver"
    (let [keys1 (crypto/generate-keypair)
          sender-pubkey (:public keys1)
          sender-privkey (:private keys1)
          receiver-pubkey "pubkey2"
          initial-sender-state (account/map->AccountState {:balance 100 :seq 5 :deps ["hash1"]})
          initial-receiver-state (account/map->AccountState {:balance 50 :seq 2 :deps ["hash2"]})
          ledger {sender-pubkey initial-sender-state
                  receiver-pubkey initial-receiver-state}
          unsigned-transfer {:sender sender-pubkey
                             :receiver receiver-pubkey
                             :amount 40
                             :seq 6
                             :deps ["hash1"]}
          payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
          signature (crypto/sign sender-privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature)))
          updated-ledger (account/apply-transfer ledger transfer)]
      (is (= 60 (:balance (get updated-ledger sender-pubkey))))
      (is (= 90 (:balance (get updated-ledger receiver-pubkey))))
      (is (= 2 (:seq (get updated-ledger receiver-pubkey))))
      (is (= ["hash2"] (:deps (get updated-ledger receiver-pubkey))))))

  (testing "Valid apply-transfer to self (self-transfer)"
    (let [keys1 (crypto/generate-keypair)
          sender-pubkey (:public keys1)
          receiver-pubkey sender-pubkey
          initial-sender-state (account/map->AccountState {:balance 100 :seq 5 :deps ["hash1"]})
          ledger {sender-pubkey initial-sender-state}
          unsigned-transfer {:sender sender-pubkey
                             :receiver receiver-pubkey
                             :amount 40
                             :seq 6
                             :deps ["hash1"]}
          payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
          signature (crypto/sign (:private keys1) payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature signature))
          updated-ledger (account/apply-transfer ledger transfer)
          safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex signature))
          transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))]
      ;; The balance should be (100 - 40) + 40 = 100
      (is (= 100 (:balance (get updated-ledger sender-pubkey))))
      ;; Seq and deps should update
      (is (= 6 (:seq (get updated-ledger sender-pubkey))))
      (is (= [transfer-hash] (:deps (get updated-ledger sender-pubkey)))))))
