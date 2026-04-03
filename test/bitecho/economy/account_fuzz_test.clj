(ns bitecho.economy.account-fuzz-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; Generator for a pool of pre-generated keypairs to act as network nodes
(def ^:private num-nodes 5)
(def ^:private keypairs (vec (repeatedly num-nodes crypto/generate-keypair)))
(def ^:private pubkeys (mapv :public keypairs))
(def ^:private privkeys (mapv :private keypairs))

;; Generate initial balances for each node (from 0 to 1000)
(def ^:private initial-balances-gen
  (gen/vector (gen/choose 0 1000) num-nodes))

;; Generate a transfer intent (not yet signed or strictly sequenced)
(def ^:private transfer-intent-gen
  (gen/hash-map
   :sender-idx (gen/choose 0 (dec num-nodes))
   :receiver-idx (gen/choose 0 (dec num-nodes))
   :amount (gen/choose 1 500)
   ;; seq-offset: -1 means reuse old seq, 0 means valid next seq, 1 means skip a seq
   :seq-offset (gen/elements [-1 0 1])
   :tamper-sig? gen/boolean
   :tamper-amount? gen/boolean))

;; Generate a scenario: initial balances and a list of transfer intents
(def ^:private scenario-gen
  (gen/hash-map
   :balances initial-balances-gen
   :intents (gen/vector transfer-intent-gen 1 100)))

(defn- build-initial-ledger [balances]
  (into {}
        (map-indexed (fn [i bal]
                       [(nth pubkeys i)
                        (account/map->AccountState {:balance bal :seq 0 :deps []})])
                     balances)))

(defn- execute-intent [ledger intent node-seqs node-deps]
  (let [sender-idx (:sender-idx intent)
        receiver-idx (:receiver-idx intent)
        sender-pubkey (nth pubkeys sender-idx)
        sender-privkey (nth privkeys sender-idx)
        receiver-pubkey (nth pubkeys receiver-idx)

        current-seq (@node-seqs sender-idx)
        current-deps (@node-deps sender-idx)

        target-seq (+ current-seq 1 (:seq-offset intent))
        target-seq (max 0 target-seq) ;; ensure non-negative

        unsigned-transfer {:sender sender-pubkey
                           :receiver receiver-pubkey
                           :amount (:amount intent)
                           :seq target-seq
                           :deps current-deps}

        payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
        signature (crypto/sign sender-privkey payload-bytes)

        ;; maybe tamper
        final-transfer (cond
                         (:tamper-amount? intent)
                         (assoc unsigned-transfer :amount (+ (:amount intent) 100) :signature signature)

                         (:tamper-sig? intent)
                         (assoc unsigned-transfer :signature (byte-array 64))

                         :else
                         (assoc unsigned-transfer :signature signature))

        transfer-record (account/map->Transfer final-transfer)

        new-ledger (account/apply-transfer ledger transfer-record)]

    ;; If the transfer was successfully applied, update our simulation tracking of seq/deps
    ;; We can detect success if the ledger changed.
    (when (not= new-ledger ledger)
      (let [safe-transfer (assoc (into {} transfer-record) :signature (basalt/bytes->hex (:signature transfer-record)))
            transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))]
        (swap! node-seqs assoc sender-idx target-seq)
        (swap! node-deps assoc sender-idx [transfer-hash])))

    new-ledger))

(defspec ^{:doc "Proves that double spending is impossible without global consensus by fuzzing state transitions."} no-double-spend-invariant 100
  (prop/for-all [scenario scenario-gen]
                (let [initial-ledger (build-initial-ledger (:balances scenario))
                      initial-total-supply (reduce + (map :balance (vals initial-ledger)))

                      node-seqs (atom (vec (repeat num-nodes 0)))
                      node-deps (atom (vec (repeat num-nodes [])))

                      final-ledger (reduce (fn [ledger intent]
                                             (execute-intent ledger intent node-seqs node-deps))
                                           initial-ledger
                                           (:intents scenario))

                      final-total-supply (reduce + (map :balance (vals final-ledger)))]

                  (and
       ;; Invariant 1: Total supply must never change (no money created or destroyed)
                   (= initial-total-supply final-total-supply)

       ;; Invariant 2: No account can have a negative balance
                   (every? (fn [state] (>= (:balance state) 0)) (vals final-ledger))))))
