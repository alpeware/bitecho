(ns bitecho.economy.burn-test
  (:require [bitecho.economy.account :as account]
            [bitecho.economy.burn :as burn]
            [clojure.test :refer [deftest is testing]]))

(deftest deduct-routing-fee-test
  (testing "Deducts fee from sender's balance in the ledger"
    (let [sender "pubkey1"
          initial-ledger {sender (account/map->AccountState {:balance 100 :seq 1 :deps []})}
          transfer {:sender sender :receiver "pubkey2" :amount 10}
          updated-ledger (burn/deduct-routing-fee initial-ledger transfer)]
      (is (= (- 100 burn/routing-fee) (:balance (get updated-ledger sender))))))

  (testing "Does not deduct if insufficient balance for fee"
    (let [sender "pubkey1"
          initial-ledger {sender (account/map->AccountState {:balance 0 :seq 1 :deps []})}
          transfer {:sender sender :receiver "pubkey2" :amount 10}
          updated-ledger (burn/deduct-routing-fee initial-ledger transfer)]
      (is (= 0 (:balance (get updated-ledger sender))))
      (is (= initial-ledger updated-ledger)))))
