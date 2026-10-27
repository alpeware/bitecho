(ns bitecho.economy.burn-test
  (:require [bitecho.economy.account :as account]
            [bitecho.economy.burn :as burn]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest constants-test
  (testing "Burn constants match 42B-scale fee parameters"
    (is (= 100 burn/min-signaling-burn))
    (is (= 50 burn/default-settlement-take-bps))
    (is (= 0 burn/min-settlement-take-bps))
    (is (= 200 burn/max-settlement-take-bps))
    (is (= burn/min-signaling-burn burn/routing-fee)
        "routing-fee is an alias for min-signaling-burn for backward compatibility")))

(deftest deduct-signaling-burn-account-state-test
  (testing "Deducts default min-signaling-burn from account state"
    (let [acct (account/map->AccountState {:balance 300 :seq 1 :deps []})
          res (burn/deduct-signaling-burn acct)]
      (is (some? res))
      (is (= 100 (:burn-amount res)))
      (is (= 200 (:balance res)))
      (is (= 200 (:balance (:account-state res))))
      (is (= 1 (:seq (:account-state res))))))

  (testing "Deducts custom signaling burn from account state"
    (let [acct (account/map->AccountState {:balance 500 :seq 2 :deps []})
          res (burn/deduct-signaling-burn acct 250)]
      (is (some? res))
      (is (= 250 (:burn-amount res)))
      (is (= 250 (:balance res)))
      (is (= 250 (:balance (:account-state res))))))

  (testing "Rejects burn below min-signaling-burn"
    (let [acct (account/map->AccountState {:balance 500 :seq 1 :deps []})]
      (is (nil? (burn/deduct-signaling-burn acct 99)))
      (is (nil? (burn/deduct-signaling-burn acct 0)))
      (is (nil? (burn/deduct-signaling-burn acct -10)))))

  (testing "Rejects burn exceeding account balance"
    (let [acct (account/map->AccountState {:balance 90 :seq 1 :deps []})]
      (is (nil? (burn/deduct-signaling-burn acct)))
      (is (nil? (burn/deduct-signaling-burn acct 100)))
      (is (nil? (burn/deduct-signaling-burn acct 150))))))

(deftest deduct-signaling-burn-ledger-test
  (testing "Deducts default burn from ledger sender"
    (let [sender "pubkey1"
          ledger {sender (account/map->AccountState {:balance 300 :seq 1 :deps []})}
          res (burn/deduct-signaling-burn ledger sender)]
      (is (some? res))
      (is (= 100 (:burn-amount res)))
      (is (= 200 (:balance res)))
      (is (= 200 (:balance (get-in res [:ledger sender]))))))

  (testing "Deducts custom burn from ledger sender"
    (let [sender "pubkey1"
          ledger {sender (account/map->AccountState {:balance 1000 :seq 1 :deps []})}
          res (burn/deduct-signaling-burn ledger sender 400)]
      (is (some? res))
      (is (= 400 (:burn-amount res)))
      (is (= 600 (:balance res)))
      (is (= 600 (:balance (get-in res [:ledger sender]))))))

  (testing "Returns nil when sender not found in ledger"
    (let [ledger {"known" (account/map->AccountState {:balance 500 :seq 1 :deps []})}]
      (is (nil? (burn/deduct-signaling-burn ledger "unknown")))
      (is (nil? (burn/deduct-signaling-burn ledger "unknown" 200)))))

  (testing "Returns nil when sender has insufficient funds in ledger"
    (let [sender "poor"
          ledger {sender (account/map->AccountState {:balance 50 :seq 1 :deps []})}]
      (is (nil? (burn/deduct-signaling-burn ledger sender)))
      (is (nil? (burn/deduct-signaling-burn ledger sender 100))))))

(deftest calculate-settlement-take-test
  (testing "Calculates settlement take with default 50 bps"
    (is (= 50 (burn/calculate-settlement-take 10000)))
    (is (= 5 (burn/calculate-settlement-take 1000)))
    (is (= 0 (burn/calculate-settlement-take 100)))
    (is (= 0 (burn/calculate-settlement-take 0)))
    (is (= 0 (burn/calculate-settlement-take -1000))))

  (testing "Calculates settlement take with custom bps within [0, 200]"
    (is (= 0 (burn/calculate-settlement-take 10000 0)))
    (is (= 100 (burn/calculate-settlement-take 10000 100)))
    (is (= 200 (burn/calculate-settlement-take 10000 200))))

  (testing "Clamps bps below 0 to 0 and above 200 to 200"
    (is (= 0 (burn/calculate-settlement-take 10000 -50)))
    (is (= 200 (burn/calculate-settlement-take 10000 350)))))

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

(defspec ^{:doc "Property: Deduct signaling burn satisfies balance conservation and boundary invariants."}
  prop-signaling-burn-invariants 50
  (prop/for-all [initial-bal (gen/choose 0 5000)
                 burn-amt (gen/choose -50 5000)]
                (let [acct (account/map->AccountState {:balance initial-bal :seq 1 :deps []})
                      res (burn/deduct-signaling-burn acct burn-amt)]
                  (if (or (< burn-amt burn/min-signaling-burn)
                          (< initial-bal burn-amt))
                    (nil? res)
                    (and (some? res)
                         (= burn-amt (:burn-amount res))
                         (= (- initial-bal burn-amt) (:balance res))
                         (= (- initial-bal burn-amt) (:balance (:account-state res)))
                         (= (+ (:balance (:account-state res)) (:burn-amount res)) initial-bal)
                         (= 1 (:seq (:account-state res))))))))

(defspec ^{:doc "Property: Settlement take calculation satisfies clamping and truncation invariants."}
  prop-settlement-take-invariants 50
  (prop/for-all [amount (gen/choose -500 500000)
                 bps (gen/choose -100 500)]
                (let [take (burn/calculate-settlement-take amount bps)
                      effective-bps (max burn/min-settlement-take-bps
                                         (min burn/max-settlement-take-bps bps))
                      expected (quot (* (max 0 amount) effective-bps) 10000)]
                  (and (integer? take)
                       (>= take 0)
                       (= take expected)
                       (<= take (max 0 amount))))))
