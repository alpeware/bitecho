(ns bitecho.economy.treasury-test
  "Tests for demand-gated treasury minting, 20/80 split, and Genesis Bootstrap custody."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.treasury :as treasury]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest constants-test
  (testing "Treasury constants match V2 demand-gated specification"
    (is (= 5000 treasury/default-k-bps))
    (is (= 5000 treasury/max-k-bps))
    (is (= 20 treasury/streamlet-share-pct))
    (is (= 80 treasury/mesh-share-pct))))

(deftest calculate-trailing-revenue-test
  (testing "Calculates average trailing burn over N epochs"
    (is (= 2000 (treasury/calculate-trailing-revenue [1000 2000 3000] 3)))
    (is (= 66 (treasury/calculate-trailing-revenue [100 100] 3)))
    (is (= 150 (treasury/calculate-trailing-revenue [100 200]))))

  (testing "Safe boundary handling"
    (is (= 0 (treasury/calculate-trailing-revenue [] 5)))
    (is (= 0 (treasury/calculate-trailing-revenue [100 200] 0)))
    (is (= 0 (treasury/calculate-trailing-revenue [100 200] -1)))
    (is (= 0 (treasury/calculate-trailing-revenue nil 5)))))

(deftest calculate-demand-gated-mint-test
  (testing "Demand-gated mint defaults to 50% of trailing revenue"
    (is (= 5000 (treasury/calculate-demand-gated-mint 10000)))
    (is (= 50 (treasury/calculate-demand-gated-mint 100)))
    (is (= 0 (treasury/calculate-demand-gated-mint 1))))

  (testing "Configurable k-bps within [0, 5000]"
    (is (= 2500 (treasury/calculate-demand-gated-mint 10000 2500)))
    (is (= 0 (treasury/calculate-demand-gated-mint 10000 0))))

  (testing "Caps k-bps at 5000 (50%) to guarantee net-deflationary invariant"
    (is (= 5000 (treasury/calculate-demand-gated-mint 10000 8000))))

  (testing "Zero and negative handling"
    (is (= 0 (treasury/calculate-demand-gated-mint 0)))
    (is (= 0 (treasury/calculate-demand-gated-mint -100)))))

(deftest split-mint-test
  (testing "Exact 20/80 split conserving total mint"
    (let [split (treasury/split-mint 100)]
      (is (= 20 (:streamlet split)))
      (is (= 80 (:mesh split)))
      (is (= 100 (+ (:streamlet split) (:mesh split))))))

  (testing "Conserves total mint under integer truncation"
    (doseq [m [1 2 5 11 99 101 105 1007 100000]]
      (let [split (treasury/split-mint m)]
        (is (= m (+ (:streamlet split) (:mesh split))))))))

(deftest distribute-shares-test
  (testing "Equal distribution among recipient collection"
    (let [recipients ["node-1" "node-2" "node-3"]
          shares (treasury/distribute-shares 100 recipients)]
      (is (= 33 (get shares "node-1")))
      (is (= 33 (get shares "node-2")))
      (is (= 33 (get shares "node-3")))))

  (testing "Proportional distribution among weighted recipients"
    (let [weights {"node-1" 10.0 "node-2" 30.0}
          shares (treasury/distribute-shares 100 weights)]
      (is (= 25 (get shares "node-1")))
      (is (= 75 (get shares "node-2")))))

  (testing "Safe handling of empty or zero-weight recipients"
    (is (= {} (treasury/distribute-shares 100 [])))
    (is (= {} (treasury/distribute-shares 100 {"node-1" 0.0})))))

(deftest process-bootstrap-custody-test
  (let [custody-kp (crypto/generate-keypair)
        custody-pub (:public custody-kp)
        custody-priv (:private custody-kp)
        allocations [{:receiver "partner-1" :amount 200}
                     {:receiver "partner-2" :amount 300}]
        ctx {:custody-pubkey custody-pub
             :custody-privkey custody-priv
             :custody-balance 1000
             :allocations allocations
             :start-seq 10
             :start-deps ["hash-0"]}
        res (treasury/process-bootstrap-custody ctx)]
    (testing "Draws down custody balance without creating new supply"
      (is (= 500 (:remaining-balance res)))
      (is (= 2 (count (:commands res))))
      (is (= 12 (:seq res))))

    (testing "Rejects or caps allocations exceeding available custody balance"
      (let [over-ctx (assoc ctx :custody-balance 400)
            over-res (treasury/process-bootstrap-custody over-ctx)]
        (is (>= (:remaining-balance over-res) 0))
        (is (<= (reduce + (map :amount (:commands over-res))) 400))))))

(deftest process-treasury-epoch-test
  (let [treasury-kp (crypto/generate-keypair)
        t-pub (:public treasury-kp)
        t-priv (:private treasury-kp)
        custody-kp (crypto/generate-keypair)
        c-pub (:public custody-kp)
        c-priv (:private custody-kp)
        ctx {:treasury-pubkey t-pub
             :treasury-privkey t-priv
             :trailing-burns [10000 20000 30000]
             :n-epochs 3
             :validators ["val-1" "val-2"]
             :mesh-nodes {"mesh-1" (attestation/calculate-node-weight 100 2000 1000)
                          "mesh-2" (attestation/calculate-node-weight 100 1000 1000)}
             :custody-pubkey c-pub
             :custody-privkey c-priv
             :custody-balance 50000
             :custody-allocations [{:receiver "grantee-1" :amount 500}]
             :start-seq 0
             :start-deps ["genesis"]}
        res (treasury/process-treasury-epoch ctx)]
    (testing "Demand-gated mint matches 50% of trailing revenue"
      (is (= 20000 (:r-trailing res)))
      (is (= 10000 (:epoch-mint res)))
      (is (= 2000 (:m-streamlet res)))
      (is (= 8000 (:m-mesh res)))
      (is (= 10000 (+ (:m-streamlet res) (:m-mesh res)))))

    (testing "Commands include signed mint transfers and custody transfers"
      (is (= 5 (count (:commands res))))
      (is (= 4 (count (:mint-commands res))))
      (is (= 1 (count (:custody-commands res))))
      (is (= 49500 (:remaining-custody-balance res))))))

(defspec ^{:doc "Property: In every epoch M_t <= 0.5 * R_trailing and M_streamlet + M_mesh == M_t"}
  prop-epoch-mint-and-split-invariants 50
  (prop/for-all [r-trailing (gen/choose 0 1000000)
                 k-bps (gen/choose 0 10000)]
                (let [m-t (treasury/calculate-demand-gated-mint r-trailing k-bps)
                      split (treasury/split-mint m-t)]
                  (and (<= m-t (quot r-trailing 2))
                       (<= m-t (* 0.5 (double r-trailing)))
                       (= m-t (+ (:streamlet split) (:mesh split)))
                       (>= (:streamlet split) 0)
                       (>= (:mesh split) 0)))))

(defspec ^{:doc "Property: Over multi-cycle horizon T = 5 * N, cumulative demand-gated mint <= 0.5 * cumulative burns"}
  prop-multi-cycle-net-deflationary 50
  (prop/for-all [n (gen/choose 3 10)
                 burns (gen/vector (gen/choose 0 5000) 25)]
                (let [t-horizon (count burns)
          ;; Simulate sliding window trailing burns across horizon
                      mints (loop [step 0
                                   history []
                                   acc-mints []]
                              (if (= step t-horizon)
                                acc-mints
                                (let [current-burn (nth burns step)
                                      new-history (vec (take-last n (conj history current-burn)))
                                      r-trailing (treasury/calculate-trailing-revenue new-history n)
                                      m-t (treasury/calculate-demand-gated-mint r-trailing)]
                                  (recur (inc step) new-history (conj acc-mints m-t)))))
                      total-burns (reduce + burns)
                      total-mints (reduce + mints)]
                  (<= total-mints (Math/ceil (* 0.5 (double total-burns)))))))

(defspec ^{:doc "Property: Bootstrap custody distributions only debit custody balance and never increase M_t"}
  prop-bootstrap-custody-invariants 50
  (prop/for-all [custody-bal (gen/choose 1000 50000)
                 alloc-amt (gen/choose 10 2000)
                 r-trailing (gen/choose 100 10000)]
                (let [custody-kp (crypto/generate-keypair)
                      ctx {:custody-pubkey (:public custody-kp)
                           :custody-privkey (:private custody-kp)
                           :custody-balance custody-bal
                           :allocations [{:receiver "partner-x" :amount alloc-amt}]
                           :start-seq 1
                           :start-deps ["dep-0"]}
                      res (treasury/process-bootstrap-custody ctx)
                      m-t-before (treasury/calculate-demand-gated-mint r-trailing)
                      drawn-amt (reduce + (map :amount (:commands res)))
                      m-t-after (treasury/calculate-demand-gated-mint r-trailing)]
                  (and (= m-t-before m-t-after)
                       (= (:remaining-balance res) (- custody-bal drawn-amt))
                       (<= drawn-amt alloc-amt)
                       (<= drawn-amt custody-bal)))))

(deftest default-genesis-ledger-test
  (testing "default-genesis-ledger builds exact 45% Genesis custody ledger (18,900,000,000 ECHO total)"
    (let [custody-keys {:bootstrap "custody-bootstrap-pub"
                        :team "custody-team-pub"
                        :partners "custody-partners-pub"
                        :ecosystem "custody-ecosystem-pub"}
          ledger (treasury/default-genesis-ledger custody-keys)]
      (is (= 4 (count ledger)))
      (is (= 4200000000 (:balance (get ledger "custody-bootstrap-pub"))))
      (is (= 6300000000 (:balance (get ledger "custody-team-pub"))))
      (is (= 4200000000 (:balance (get ledger "custody-partners-pub"))))
      (is (= 4200000000 (:balance (get ledger "custody-ecosystem-pub"))))
      (is (= 18900000000 (reduce + (map :balance (vals ledger)))))
      (is (every? #(instance? bitecho.economy.account.AccountState %) (vals ledger)))
      (is (every? #(= 0 (:seq %)) (vals ledger)))
      (is (every? #(= [] (:deps %)) (vals ledger)))))

  (testing "Handles byte-array pubkeys and subsets of custody keys"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          custody-keys {:bootstrap (:public kp)
                        :team "team-hex"}
          ledger (treasury/default-genesis-ledger custody-keys)]
      (is (= 2 (count ledger)))
      (is (= 4200000000 (:balance (get ledger pub-hex))))
      (is (= 6300000000 (:balance (get ledger "team-hex"))))
      (is (= 10500000000 (reduce + (map :balance (vals ledger))))))))

(defspec ^{:doc "Property: default-genesis-ledger conserves 45% 18.9B total when all 4 roles are provided"}
  prop-default-genesis-ledger-invariants 50
  (prop/for-all [b-suffix (gen/choose 1 1000)
                 t-suffix (gen/choose 1001 2000)
                 p-suffix (gen/choose 2001 3000)
                 e-suffix (gen/choose 3001 4000)]
                (let [custody-keys {:bootstrap (str "bootstrap-" b-suffix)
                                    :team (str "team-" t-suffix)
                                    :partners (str "partners-" p-suffix)
                                    :ecosystem (str "ecosystem-" e-suffix)}
                      ledger (treasury/default-genesis-ledger custody-keys)]
                  (and (= 4 (count ledger))
                       (= 18900000000 (reduce + (map :balance (vals ledger))))
                       (= 4200000000 (:balance (get ledger (str "bootstrap-" b-suffix))))
                       (= 6300000000 (:balance (get ledger (str "team-" t-suffix))))
                       (= 4200000000 (:balance (get ledger (str "partners-" p-suffix))))
                       (= 4200000000 (:balance (get ledger (str "ecosystem-" e-suffix))))
                       (every? #(and (= 0 (:seq %)) (= [] (:deps %))) (vals ledger))))))

(deftest supply-constants-test
  (testing "Canonical v2.1 supply constants match hard cap and split"
    (is (= 42000000000 treasury/hard-cap))
    (is (= 18900000000 treasury/genesis-custody-supply))
    (is (= 23100000000 treasury/max-conditional-mint-supply))
    (is (= treasury/hard-cap (+ treasury/genesis-custody-supply treasury/max-conditional-mint-supply)))))

(deftest apply-epoch-mint-test
  (let [t-kp (crypto/generate-keypair)
        t-pub (basalt/bytes->hex (:public t-kp))
        t-priv (:private t-kp)
        base-state {:ledger {}
                    :total-minted 0
                    :minted-epochs #{}}]
    (testing "Applies valid epoch mint and increments :total-minted by exact distributed sum"
      (let [allocs {"node1" 500 "node2" 300}
            res (treasury/apply-epoch-mint base-state {:epoch 1
                                                       :epoch-gate 1000
                                                       :allocations allocs})]
        (is (= 800 (:total-minted res)))
        (is (contains? (:minted-epochs res) 1))
        (is (= 500 (:balance (get-in res [:ledger "node1"]))))
        (is (= 300 (:balance (get-in res [:ledger "node2"]))))))

    (testing "Rounding dust: only actual distributed sum is minted, never phantom gate amount"
      (let [allocs {"node1" 499 "node2" 499}
            res (treasury/apply-epoch-mint base-state {:epoch 2
                                                       :epoch-gate 1000
                                                       :allocations allocs})]
        (is (= 998 (:total-minted res)))
        (is (= 998 (reduce + 0 (map :balance (vals (:ledger res))))))))

    (testing "Double-mint of same epoch is rejected in full"
      (let [state-epoch-1 (assoc base-state :minted-epochs #{1} :total-minted 500)
            res (treasury/apply-epoch-mint state-epoch-1 {:epoch 1
                                                          :epoch-gate 1000
                                                          :allocations {"node1" 100}})]
        (is (= state-epoch-1 res))))

    (testing "Rejects mint exceeding epoch demand gate M_t"
      (let [res (treasury/apply-epoch-mint base-state {:epoch 3
                                                       :epoch-gate 500
                                                       :allocations {"node1" 600}})]
        (is (= base-state res))))

    (testing "Rejects mint exceeding max-conditional-mint-supply (23.1B hard cap limit)"
      (let [state-near-cap (assoc base-state :total-minted (- treasury/max-conditional-mint-supply 100))
            res (treasury/apply-epoch-mint state-near-cap {:epoch 4
                                                           :epoch-gate 200
                                                           :allocations {"node1" 150}})]
        (is (= state-near-cap res))))

    (testing "Rejects when any allocation amount is negative"
      (let [res (treasury/apply-epoch-mint base-state {:epoch 5
                                                       :epoch-gate 1000
                                                       :allocations {"node1" 500 "node2" -50}})]
        (is (= base-state res))))

    (testing "Verifies cryptographic signature when treasury-pubkey and signature are provided"
      (let [allocs {"node1" 400}
            sig (treasury/sign-epoch-mint t-priv 6 allocs)
            valid-ctx {:epoch 6
                       :epoch-gate 500
                       :allocations allocs
                       :treasury-pubkey t-pub
                       :signature sig}
            valid-res (treasury/apply-epoch-mint base-state valid-ctx)]
        (is (= 400 (:total-minted valid-res)))
        (is (contains? (:minted-epochs valid-res) 6))
        (is (= 400 (:balance (get-in valid-res [:ledger "node1"])))))

      (testing "Rejects when signature is tampered"
        (let [allocs {"node1" 400}
              sig (treasury/sign-epoch-mint t-priv 6 allocs)
              tampered-sig (str "ff" (subs sig 2))
              invalid-ctx {:epoch 6
                           :epoch-gate 500
                           :allocations allocs
                           :treasury-pubkey t-pub
                           :signature tampered-sig}
              invalid-res (treasury/apply-epoch-mint base-state invalid-ctx)]
          (is (= base-state invalid-res)))))))

(defspec ^{:doc "Property: apply-epoch-mint strictly respects demand gate, hard cap, and never phantom-mints rounding dust"}
  prop-apply-epoch-mint-invariants 50
  (prop/for-all [epoch (gen/choose 1 1000)
                 gate (gen/choose 100 5000)
                 alloc-pct-1 (gen/choose 10 40)
                 alloc-pct-2 (gen/choose 10 40)
                 attempt-overflow? gen/boolean]
                (let [base-state {:ledger {}
                                  :total-minted 0
                                  :minted-epochs #{}}
                      amt-1 (quot (* gate alloc-pct-1) 100)
                      amt-2 (quot (* gate alloc-pct-2) 100)
                      allocs (if attempt-overflow?
                               {"n1" (+ gate 100)}
                               {"n1" amt-1 "n2" amt-2})
                      ctx {:epoch epoch
                           :epoch-gate gate
                           :allocations allocs}
                      res (treasury/apply-epoch-mint base-state ctx)]
                  (if attempt-overflow?
                    (= base-state res)
                    (let [actual-sum (+ amt-1 amt-2)]
                      (and (<= (:total-minted res) gate)
                           (<= (:total-minted res) treasury/max-conditional-mint-supply)
                           (= actual-sum (:total-minted res))
                           (= actual-sum (reduce + 0 (map :balance (vals (:ledger res)))))
                           (contains? (:minted-epochs res) epoch)))))))


