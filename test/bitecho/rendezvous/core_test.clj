(ns bitecho.rendezvous.core-test
  "Tests for pure multi-homed Callee registration, home node selection, and DeliveryAck vouchers."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.rendezvous.core :as rdv]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest register-home-set-test
  (testing "Successfully registers >= 3 nodes at initial price p_B"
    (let [candidates [{:node-id "n1" :price 10}
                      {:node-id "n2" :price 10}
                      {:node-id "n3" :price 10}
                      {:node-id "n4" :price 20}]
          res (rdv/register-home-set candidates 10 25)]
      (is (= :ok (:status res)))
      (is (= 10 (:price res)))
      (is (false? (:degraded? res)))
      (is (= 3 (count (:home-nodes res))))))

  (testing "Steps p_B up to p_B_max when fewer than 3 nodes accept at initial price"
    (let [candidates [{:node-id "n1" :price 10}
                      {:node-id "n2" :price 15}
                      {:node-id "n3" :price 18}
                      {:node-id "n4" :price 30}]
          res (rdv/register-home-set candidates 10 20)]
      (is (= :ok (:status res)))
      (is (= 18 (:price res)))
      (is (false? (:degraded? res)))
      (is (= 3 (count (:home-nodes res))))))

  (testing "Flags :degraded when 1 <= m < 3 at p_B_max"
    (let [candidates [{:node-id "n1" :price 10}
                      {:node-id "n2" :price 15}
                      {:node-id "n3" :price 35}
                      {:node-id "n4" :price 40}]
          res (rdv/register-home-set candidates 10 20)]
      (is (= :degraded (:status res)))
      (is (= 20 (:price res)))
      (is (true? (:degraded? res)))
      (is (= 2 (count (:home-nodes res))))))

  (testing "Rejects when m = 0 at p_B_max"
    (let [candidates [{:node-id "n1" :price 50}
                      {:node-id "n2" :price 60}]
          res (rdv/register-home-set candidates 10 20)]
      (is (= :rejected (:status res)))
      (is (empty? (:home-nodes res)))
      (is (false? (:degraded? res))))))

(deftest select-home-node-test
  (testing "Selects responsive node with lowest latency"
    (let [home-set [{:node-id "n1" :latency 80 :responsive? true}
                    {:node-id "n2" :latency 25 :responsive? true}
                    {:node-id "n3" :latency 60 :responsive? true}]
          selected (rdv/select-home-node home-set)]
      (is (= "n2" (:node-id selected)))))

  (testing "Skips unresponsive nodes regardless of latency"
    (let [home-set [{:node-id "n1" :latency 10 :responsive? false}
                    {:node-id "n2" :latency 40 :responsive? true}]
          selected (rdv/select-home-node home-set)]
      (is (= "n2" (:node-id selected)))))

  (testing "Returns nil when no nodes are responsive or home set is empty"
    (is (nil? (rdv/select-home-node [])))
    (is (nil? (rdv/select-home-node [{:node-id "n1" :latency 10 :responsive? false}])))))

(deftest process-offer-header-test
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        home-node "home-node-pub-h"
        caller "caller-pub-a"
        offer-hash "hash-offer-123"
        base-ctx {:caller caller
                  :callee callee-pub
                  :callee-privkey callee-priv
                  :home-node home-node
                  :epoch 5
                  :offer-hash offer-hash
                  :seq 1
                  :p-b 100
                  :burn 150
                  :allowlist #{caller "other-caller"}
                  :min-burn 100}]
    (testing "Produces valid signed DeliveryAck bound to epoch when caller passes allowlist and min-burn (signed by callee)"
      (let [res (rdv/process-offer-header base-ctx)
            ack (:delivery-ack res)]
        (is (= :ok (:status res)))
        (is (some? ack))
        (is (= callee-pub (:callee ack)))
        (is (= home-node (:home-node ack)))
        (is (= 5 (:epoch ack)))
        (is (= offer-hash (:offer-hash ack)))
        (is (= 1 (:seq ack)))
        (is (= 100 (:cumulative-debit ack)))
        (is (true? (rdv/verify-delivery-ack ack)))))

    (testing "Falls back to :home-node-privkey if :callee-privkey is absent"
      (let [fallback-ctx (-> base-ctx
                             (dissoc :callee-privkey)
                             (assoc :home-node-privkey callee-priv))
            res (rdv/process-offer-header fallback-ctx)
            ack (:delivery-ack res)]
        (is (= :ok (:status res)))
        (is (some? ack))
        (is (true? (rdv/verify-delivery-ack ack)))))

    (testing "Rejects offer when caller is not in callee's allowlist"
      (let [disallowed-ctx (assoc base-ctx :caller "unauthorized-caller")
            res (rdv/process-offer-header disallowed-ctx)]
        (is (nil? (:delivery-ack res)))
        (is (= :rejected-allowlist (:error res)))))

    (testing "Rejects offer when burn is below min-burn requirement"
      (let [low-burn-ctx (assoc base-ctx :burn 50)
            res (rdv/process-offer-header low-burn-ctx)]
        (is (nil? (:delivery-ack res)))
        (is (= :insufficient-burn (:error res)))))

    (testing "Rejects offer when seq < 1"
      (let [zero-seq-ctx (assoc base-ctx :seq 0)
            res (rdv/process-offer-header zero-seq-ctx)]
        (is (nil? (:delivery-ack res)))
        (is (= :invalid-seq (:error res)))))

    (testing "Rejects offer when seq is not strictly (inc last-seq)"
      (let [gap-ctx (assoc base-ctx :seq 3 :last-seq 1)
            rollback-ctx (assoc base-ctx :seq 1 :last-seq 1)
            valid-ctx (assoc base-ctx :seq 2 :last-seq 1)]
        (is (= :invalid-seq (:error (rdv/process-offer-header gap-ctx))))
        (is (= :invalid-seq (:error (rdv/process-offer-header rollback-ctx))))
        (is (= :ok (:status (rdv/process-offer-header valid-ctx))))))

    (testing "Calculates cumulative-debit strictly as (* seq p-b) and rejects mismatched debit"
      (let [calc-res (rdv/process-offer-header (assoc base-ctx :seq 3 :p-b 50))
            ack (:delivery-ack calc-res)
            inflated-ctx (assoc base-ctx :seq 3 :p-b 50 :cumulative-debit 999)]
        (is (= :ok (:status calc-res)))
        (is (= 150 (:cumulative-debit ack)))
        (is (= :invalid-debit (:error (rdv/process-offer-header inflated-ctx))))))))

(deftest verify-ack-for-settlement-test
  (let [callee-kp (crypto/generate-keypair)
        callee-pub (basalt/bytes->hex (:public callee-kp))
        callee-priv (:private callee-kp)
        home-node "home-node-1"
        epoch 5
        seq-num 3
        p-b 20
        cum-debit (* seq-num p-b)
        offer-ctx {:caller "caller-1"
                   :callee callee-pub
                   :callee-privkey callee-priv
                   :home-node home-node
                   :epoch epoch
                   :offer-hash "hash-settle-1"
                   :seq seq-num
                   :p-b p-b
                   :burn 100
                   :allowlist #{"caller-1"}}
        valid-ack (:delivery-ack (rdv/process-offer-header offer-ctx))
        settlement-ctx {:settlement-epoch epoch
                        :registered-price p-b
                        :settled-tuples #{}}]
    (testing "Accepts valid DeliveryAck matching epoch, seq * price, and unplayed tuple"
      (let [res (rdv/verify-ack-for-settlement valid-ack settlement-ctx)]
        (is (true? (:valid? res)))
        (is (= cum-debit (:debit res)))
        (is (= [callee-pub home-node epoch] (:tuple res)))))

    (testing "Rejects replayed voucher tuple"
      (let [replayed-ctx (assoc settlement-ctx :settled-tuples #{[callee-pub home-node epoch]})
            res (rdv/verify-ack-for-settlement valid-ack replayed-ctx)]
        (is (false? (:valid? res)))
        (is (= :replayed-tuple (:error res)))))

    (testing "Rejects voucher from expired / mismatched epoch"
      (let [mismatched-ctx (assoc settlement-ctx :settlement-epoch 6)
            res (rdv/verify-ack-for-settlement valid-ack mismatched-ctx)]
        (is (false? (:valid? res)))
        (is (= :expired-epoch (:error res)))))

    (testing "Rejects invalid sequence number (seq <= 0)"
      (let [zero-seq-ack (assoc valid-ack :seq 0)
            res (rdv/verify-ack-for-settlement zero-seq-ack settlement-ctx)]
        (is (false? (:valid? res)))
        (is (contains? #{:invalid-debit :invalid-seq} (:error res)))))

    (testing "Rejects mismatched / inflated cumulative-debit"
      (let [bad-debit-ack (assoc valid-ack :cumulative-debit 9999)
            res (rdv/verify-ack-for-settlement bad-debit-ack settlement-ctx)]
        (is (false? (:valid? res)))
        (is (= :invalid-debit (:error res)))))

    (testing "Rejects corrupted / invalid signature"
      (let [corrupted-ack (assoc valid-ack :signature (basalt/bytes->hex (byte-array 64)))
            res (rdv/verify-ack-for-settlement corrupted-ack settlement-ctx)]
        (is (false? (:valid? res)))
        (is (= :invalid-signature (:error res)))))))

(defspec ^{:doc "Property: register-home-set preserves price bounds and node selection thresholds"}
  prop-register-home-set-invariants 50
  (prop/for-all [p-b (gen/choose 1 50)
                 delta (gen/choose 0 50)
                 prices (gen/vector (gen/choose 1 100) 10)]
                (let [p-b-max (+ p-b delta)
                      candidates (map-indexed (fn [i p] {:node-id (str "node-" i) :price p}) prices)
                      res (rdv/register-home-set candidates p-b p-b-max)
                      m (count (:home-nodes res))]
                  (cond
                    (>= m 3)
                    (and (= :ok (:status res))
                         (false? (:degraded? res))
                         (<= (:price res) p-b-max)
                         (>= (:price res) p-b)
                         (every? #(<= (:price %) (:price res)) (:home-nodes res)))

                    (and (>= m 1) (< m 3))
                    (and (= :degraded (:status res))
                         (true? (:degraded? res))
                         (= (:price res) p-b-max)
                         (every? #(<= (:price %) p-b-max) (:home-nodes res)))

                    (= m 0)
                    (and (= :rejected (:status res))
                         (empty? (:home-nodes res)))))))

(defspec ^{:doc "Property: select-home-node always picks a responsive node with minimum latency"}
  prop-select-home-node-lowest-latency 50
  (prop/for-all [nodes (gen/vector (gen/tuple gen/string-alphanumeric (gen/choose 1 500) gen/boolean) 1 10)]
                (let [home-set (mapv (fn [[id lat resp]] {:node-id id :latency lat :responsive? resp}) nodes)
                      selected (rdv/select-home-node home-set)
                      responsive-nodes (filter :responsive? home-set)]
                  (if (empty? responsive-nodes)
                    (nil? selected)
                    (and (some? selected)
                         (:responsive? selected)
                         (every? #(<= (:latency selected) (:latency %)) responsive-nodes))))))

(defspec ^{:doc "Property: DeliveryAck settlement verification safety and replay protection"}
  prop-delivery-ack-settlement-safety 50
  (prop/for-all [seq-num (gen/choose 1 50)
                 p-b (gen/choose 1 100)
                 epoch (gen/choose 1 20)
                 mutate-debit? gen/boolean]
                (let [callee-kp (crypto/generate-keypair)
                      callee-pub (basalt/bytes->hex (:public callee-kp))
                      callee-priv (:private callee-kp)
                      home-node "home-node-sim"
                      offer-ctx {:caller "caller-sim"
                                 :callee callee-pub
                                 :callee-privkey callee-priv
                                 :home-node home-node
                                 :epoch epoch
                                 :offer-hash "hash-gen-test"
                                 :seq seq-num
                                 :p-b p-b
                                 :burn 100
                                 :allowlist #{"caller-sim"}}
                      ack (:delivery-ack (rdv/process-offer-header offer-ctx))
                      test-ack (if mutate-debit?
                                 (assoc ack :cumulative-debit (+ (:cumulative-debit ack) 1))
                                 ack)
                      settlement-ctx {:settlement-epoch epoch
                                      :registered-price p-b
                                      :settled-tuples #{}}
                      res (rdv/verify-ack-for-settlement test-ack settlement-ctx)]
                  (if mutate-debit?
                    (and (false? (:valid? res))
                         (= :invalid-debit (:error res)))
                    (and (true? (:valid? res))
                         (= (* seq-num p-b) (:debit res))
                         (= [callee-pub home-node epoch] (:tuple res))
                         (let [replayed-res (rdv/verify-ack-for-settlement
                                             ack
                                             (assoc settlement-ctx :settled-tuples #{(:tuple res)}))]
                           (and (false? (:valid? replayed-res))
                                (= :replayed-tuple (:error replayed-res)))))))))
