(ns bitecho.economy.account-test
  (:require [bitecho.crypto :as crypto]
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
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          signature (crypto/sign privkey payload-bytes)
          transfer (account/map->Transfer (assoc unsigned-transfer :signature signature))]
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
