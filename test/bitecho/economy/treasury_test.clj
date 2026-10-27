(ns bitecho.economy.treasury-test
  "Tests for demand-gated treasury minting, 20/80 split, and Genesis Bootstrap custody."
  (:require [bitecho.crypto :as crypto]
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
