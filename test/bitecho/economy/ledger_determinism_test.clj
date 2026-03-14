(ns bitecho.economy.ledger-determinism-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.ledger :as ledger]
            [clojure.test :refer [deftest is testing]]))

(deftest transaction-hash-determinism-test
  (testing "HIGH-05: Transaction hashes must be deterministic independent of map key ordering"
    ;; In Clojure, maps up to 8 keys created with literal syntax or array-map
    ;; retain insertion order. Maps > 8 keys become PersistentHashMaps and lose insertion order.
    ;; We use array-maps here to explicitly force different iteration orders for structurally identical maps.
    (let [tx1 (array-map :inputs ["utxo1"]
                         :outputs [{:amount 100 :puzzle-hash "hash2"}]
                         :puzzles ["true"]
                         :solutions ["true"])
          tx2 (array-map :solutions ["true"]
                         :puzzles ["true"]
                         :outputs [{:amount 100 :puzzle-hash "hash2"}]
                         :inputs ["utxo1"])]

      ;; The maps should be strictly equal by value.
      (is (= tx1 tx2))

      ;; Prove that raw serialization (pr-str) without canonicalization is order-dependent
      ;; and therefore yields non-deterministic hashes.
      (let [raw-hash1 (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str tx1) "UTF-8")))
            raw-hash2 (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str tx2) "UTF-8")))]
        (is (not= raw-hash1 raw-hash2)))

      ;; Prove that our canonicalization logic works.
      (let [canonical-hash1 (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str (into (sorted-map) tx1)) "UTF-8")))
            canonical-hash2 (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str (into (sorted-map) tx2)) "UTF-8")))]
        (is (= canonical-hash1 canonical-hash2)))

      ;; Prove that ledger/process-transaction uses the canonicalization correctly
      (let [initial-ledger {:utxos {"utxo1" {:amount 100 :puzzle-hash "hash1"}}
                            :claimed-tickets #{}}
            ledger1 (ledger/process-transaction initial-ledger tx1)
            ledger2 (ledger/process-transaction initial-ledger tx2)
            ;; Both transactions should produce exactly the same new UTXO IDs since their deterministic hashes match
            keys1 (keys (:utxos ledger1))
            keys2 (keys (:utxos ledger2))]
        (is (= keys1 keys2))))))
