(ns bitecho.economy.account-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

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

(deftest hex-sender-ed25519-lifecycle-test
  (testing "Transfer created with real Ed25519 keypair and hex public key validates and applies"
    (let [sender-kp (crypto/generate-keypair)
          receiver-kp (crypto/generate-keypair)
          sender-pubhex (basalt/bytes->hex (:public sender-kp))
          receiver-pubhex (basalt/bytes->hex (:public receiver-kp))
          sender-priv (:private sender-kp)
          initial-sender (account/map->AccountState {:balance 500 :seq 10 :deps ["prev-hash"]})
          initial-receiver (account/map->AccountState {:balance 100 :seq 3 :deps []})
          ledger {sender-pubhex initial-sender
                  receiver-pubhex initial-receiver}
          unsigned-tx {:sender sender-pubhex
                       :receiver receiver-pubhex
                       :amount 150
                       :seq 11
                       :deps ["prev-hash"]}
          tx (account/create-transfer sender-priv unsigned-tx)
          expected-hash (account/transfer-hash tx)]
      (testing "validate-transfer succeeds for valid transfer with hex sender"
        (is (true? (account/validate-transfer initial-sender tx))))

      (testing "apply-transfer applies transfer with hex sender correctly"
        (let [updated-ledger (account/apply-transfer ledger tx)]
          (is (= 350 (:balance (get updated-ledger sender-pubhex))))
          (is (= 250 (:balance (get updated-ledger receiver-pubhex))))
          (is (= 11 (:seq (get updated-ledger sender-pubhex))))
          (is (= [expected-hash] (:deps (get updated-ledger sender-pubhex))))))

      (testing "validate-transfer rejects tampered amounts"
        (let [tampered (assoc tx :amount 151)]
          (is (false? (account/validate-transfer initial-sender tampered)))
          (is (= ledger (account/apply-transfer ledger tampered)))))

      (testing "validate-transfer rejects invalid signature bytes"
        (let [tampered (assoc tx :signature (vec (byte-array 64)))]
          (is (false? (account/validate-transfer initial-sender tampered)))
          (is (= ledger (account/apply-transfer ledger tampered))))))))

(defspec ^{:doc "Generative property test verifying that transfers created with real Ed25519 keys and hex public keys preserve balance invariants, update causal sequence and dependencies, and reject tampered signatures or amounts."} transfer-lifecycle-property-test 100
  (prop/for-all [initial-balance (gen/choose 100 10000)
                 transfer-amount (gen/choose 1 100)
                 initial-seq (gen/choose 0 100)
                 deps-count (gen/choose 0 3)]
                (let [sender-kp (crypto/generate-keypair)
                      receiver-kp (crypto/generate-keypair)
                      sender-pubhex (basalt/bytes->hex (:public sender-kp))
                      receiver-pubhex (basalt/bytes->hex (:public receiver-kp))
                      initial-deps (vec (repeatedly deps-count #(str "dep-" (java.util.UUID/randomUUID))))
                      sender-state (account/map->AccountState {:balance initial-balance
                                                               :seq initial-seq
                                                               :deps initial-deps})
                      receiver-state (account/map->AccountState {:balance 50 :seq 0 :deps []})
                      ledger {sender-pubhex sender-state
                              receiver-pubhex receiver-state}
                      unsigned-tx {:sender sender-pubhex
                                   :receiver receiver-pubhex
                                   :amount transfer-amount
                                   :seq (inc initial-seq)
                                   :deps initial-deps}
                      tx (account/create-transfer (:private sender-kp) unsigned-tx)
                      expected-hash (account/transfer-hash tx)]
                  (and
       ;; Invariant 1: Valid transfer validates successfully with hex sender
                   (true? (account/validate-transfer sender-state tx))

       ;; Invariant 2: Applying transfer updates ledger accurately
                   (let [updated-ledger (account/apply-transfer ledger tx)
                         updated-sender (get updated-ledger sender-pubhex)
                         updated-receiver (get updated-ledger receiver-pubhex)]
                     (and
          ;; Balance conservation
                      (= (+ initial-balance 50)
                         (+ (:balance updated-sender) (:balance updated-receiver)))
                      (= (- initial-balance transfer-amount) (:balance updated-sender))
                      (= (+ 50 transfer-amount) (:balance updated-receiver))
          ;; Sequence progression
                      (= (inc initial-seq) (:seq updated-sender))
          ;; Causal dependencies updated to transfer-hash
                      (= [expected-hash] (:deps updated-sender))))

       ;; Invariant 3: Tampered signature fails validation and apply-transfer rejects it
                   (let [bad-sig (byte-array 64)
                         tampered-sig-tx (assoc tx :signature (vec bad-sig))]
                     (and (false? (account/validate-transfer sender-state tampered-sig-tx))
                          (= ledger (account/apply-transfer ledger tampered-sig-tx))))

       ;; Invariant 4: Tampered amount fails validation (signature mismatch)
                   (let [tampered-amount-tx (assoc tx :amount (inc transfer-amount))]
                     (and (false? (account/validate-transfer sender-state tampered-amount-tx))
                          (= ledger (account/apply-transfer ledger tampered-amount-tx))))))))

(deftest apply-mint-test
  (testing "apply-mint credits receiver without requiring a funded sender"
    (let [ledger {}
          res (account/apply-mint ledger "recv1" 500)]
      (is (= 500 (:balance (get res "recv1"))))
      (is (= 0 (:seq (get res "recv1"))))
      (is (= [] (:deps (get res "recv1"))))))

  (testing "apply-mint increments existing account balance without altering seq or deps"
    (let [ledger {"recv1" (account/map->AccountState {:balance 300 :seq 2 :deps ["tx-1"]})}
          res (account/apply-mint ledger "recv1" 200)]
      (is (= 500 (:balance (get res "recv1"))))
      (is (= 2 (:seq (get res "recv1"))))
      (is (= ["tx-1"] (:deps (get res "recv1"))))))

  (testing "apply-mint accepts multi-recipient allocation map"
    (let [ledger {"recv1" (account/map->AccountState {:balance 100 :seq 0 :deps []})}
          res (account/apply-mint ledger {"recv1" 50 "recv2" 200})]
      (is (= 150 (:balance (get res "recv1"))))
      (is (= 200 (:balance (get res "recv2"))))))

  (testing "apply-mint rejects negative or non-integer amounts and leaves ledger unchanged"
    (let [ledger {"recv1" (account/map->AccountState {:balance 100 :seq 0 :deps []})}]
      (is (= ledger (account/apply-mint ledger "recv1" -50)))
      (is (= ledger (account/apply-mint ledger {"recv1" 50 "recv2" -10}))))))

(defspec ^{:doc "Property: apply-mint strictly increases ledger balances by exact allocation amounts without creating or destroying funds elsewhere"}
  prop-apply-mint-invariants 50
  (prop/for-all [initial-bal (gen/choose 0 5000)
                 mint-amt-1 (gen/choose 1 1000)
                 mint-amt-2 (gen/choose 1 1000)]
                (let [ledger {"recv1" (account/map->AccountState {:balance initial-bal :seq 1 :deps ["dep1"]})}
                      allocs {"recv1" mint-amt-1 "recv2" mint-amt-2}
                      updated (account/apply-mint ledger allocs)]
                  (and (= (+ initial-bal mint-amt-1) (:balance (get updated "recv1")))
                       (= mint-amt-2 (:balance (get updated "recv2")))
                       (= (+ initial-bal mint-amt-1 mint-amt-2)
                          (reduce + 0 (map :balance (vals updated))))
                       (= 1 (:seq (get updated "recv1")))
                       (= ["dep1"] (:deps (get updated "recv1")))
                       (= 0 (:seq (get updated "recv2")))
                       (= [] (:deps (get updated "recv2")))))))

