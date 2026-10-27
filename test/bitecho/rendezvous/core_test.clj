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
  (let [home-kp (crypto/generate-keypair)
        home-pub (basalt/bytes->hex (:public home-kp))
        home-priv (:private home-kp)
        callee "callee-pub-b"
        caller "caller-pub-a"
        offer-hash "hash-offer-123"
        base-ctx {:caller caller
                  :callee callee
                  :home-node home-pub
                  :home-node-privkey home-priv
                  :epoch 5
                  :offer-hash offer-hash
                  :seq 1
                  :cumulative-debit 100
                  :burn 150
                  :allowlist #{caller "other-caller"}
                  :min-burn 100}]
    (testing "Produces valid signed DeliveryAck bound to epoch when caller passes allowlist and min-burn"
      (let [res (rdv/process-offer-header base-ctx)
            ack (:delivery-ack res)]
        (is (some? ack))
        (is (= callee (:callee ack)))
        (is (= home-pub (:home-node ack)))
        (is (= 5 (:epoch ack)))
        (is (= offer-hash (:offer-hash ack)))
        (is (= 1 (:seq ack)))
        (is (= 100 (:cumulative-debit ack)))
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
        (is (= :insufficient-burn (:error res)))))))

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
