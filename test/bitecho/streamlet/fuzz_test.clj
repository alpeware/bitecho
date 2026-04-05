(ns bitecho.streamlet.fuzz-test
  "Generative state-machine fuzzer for Streamlet BFT consensus."
  (:require [bitecho.crypto :as crypto]
            [bitecho.streamlet.core :as core]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- chain-length [blocks block-hash]
  (loop [curr block-hash len 0]
    (let [block (get blocks curr)]
      (if (or (nil? block) (= "genesis" (:parent-hash block)))
        len
        (recur (:parent-hash block) (inc len))))))

(defn- update-head [state]
  (let [notarized (:notarized-blocks state)
        blocks (:blocks state)
        best-hash (if (empty? notarized)
                    "genesis"
                    (first (sort-by (juxt #(- (chain-length blocks %)) identity) notarized)))]
    (assoc state :head-hash best-hash)))

(defn- handle-block [state block]
  (let [b-hash (core/hash-block block)
        state (update state :blocks assoc b-hash block)
        vote (core/cast-vote state block)]
    (if vote
      {:state (update state :voted-epochs conj (:epoch block))
       :out-votes [vote]}
      {:state state :out-votes []})))

(defn- handle-vote [state vote voter-pubkey n]
  (let [state (core/accumulate-vote state vote voter-pubkey n)
        state (core/finalize-prefix state)
        state (update-head state)]
    {:state state}))

(defn- init-sim [n]
  (let [keypairs (repeatedly n crypto/generate-keypair)
        nodes (into {} (map-indexed
                        (fn [i kp]
                          [i {:node-pubkey (#'core/bytes->hex (:public kp))
                              :keypair kp
                              :mempool []
                              :head-hash "genesis"
                              :voted-epochs #{}
                              :blocks {}
                              :block-votes {}
                              :notarized-blocks #{}
                              :finalized-blocks #{}}])
                        keypairs))]
    {:nodes nodes
     :messages []
     :n n
     :pubkeys (into {} (map-indexed (fn [i kp] [i (:public kp)]) keypairs))}))

(defn- dispatch-propose [sim node-id epoch]
  (let [node (get-in sim [:nodes node-id])
        block (core/propose-block node epoch)
        msgs (for [i (range (:n sim))]
               {:target i :type :block :block block})]
    (update sim :messages into msgs)))

(defn- dispatch-deliver [sim raw-idx]
  (if (empty? (:messages sim))
    sim
    (let [idx (mod raw-idx (count (:messages sim)))
          msg (nth (:messages sim) idx)
          msgs (vec (concat (subvec (:messages sim) 0 idx)
                            (subvec (:messages sim) (inc idx))))
          sim (assoc sim :messages msgs)
          target (:target msg)
          node (get-in sim [:nodes target])]
      (case (:type msg)
        :block
        (let [{:keys [state out-votes]} (handle-block node (:block msg))
              sim (assoc-in sim [:nodes target] state)
              vote-msgs (when (seq out-votes)
                          (let [v (first out-votes)
                                pubkey (get-in sim [:pubkeys target])]
                            (for [i (range (:n sim))]
                              {:target i :type :vote :vote v :voter-pubkey pubkey})))]
          (if vote-msgs
            (update sim :messages into vote-msgs)
            sim))

        :vote
        (let [{:keys [state]} (handle-vote node (:vote msg) (:voter-pubkey msg) (:n sim))]
          (assoc-in sim [:nodes target] state))))))

(defn- dispatch-drop [sim raw-idx]
  (if (empty? (:messages sim))
    sim
    (let [idx (mod raw-idx (count (:messages sim)))
          msgs (vec (concat (subvec (:messages sim) 0 idx)
                            (subvec (:messages sim) (inc idx))))]
      (assoc sim :messages msgs))))

(defn- run-sim [sim actions]
  (reduce (fn [s [op arg1 arg2]]
            (case op
              :propose (dispatch-propose s arg1 arg2)
              :deliver (dispatch-deliver s arg1)
              :drop (dispatch-drop s arg1)))
          sim
          actions))

(defn- check-safety [nodes]
  (let [all-finalized (set (mapcat :finalized-blocks (vals nodes)))
        all-blocks (apply merge (map :blocks (vals nodes)))
        is-ancestor? (fn [b1 b2]
                       (loop [curr b2]
                         (cond
                           (= curr b1) true
                           (or (nil? curr) (= "genesis" curr)) false
                           :else (let [parent (:parent-hash (get all-blocks curr))]
                                   (recur parent)))))]
    (every? (fn [b1]
              (every? (fn [b2]
                        (or (= b1 b2)
                            (is-ancestor? b1 b2)
                            (is-ancestor? b2 b1)))
                      all-finalized))
            all-finalized)))

(defn- flush-messages [sim]
  (loop [s sim]
    (if (empty? (:messages s))
      s
      (recur (dispatch-deliver s 0)))))

(defn- run-synchronous-epoch [sim epoch leader-id]
  (let [sim (dispatch-propose sim leader-id epoch)
        sim (flush-messages sim)]
    sim))

(defn- test-liveness [sim]
  (let [sim (flush-messages sim)
        max-epoch (reduce max 0 (mapcat :voted-epochs (vals (:nodes sim))))
        e1 (inc max-epoch)
        e2 (+ 2 max-epoch)
        e3 (+ 3 max-epoch)
        leader 0
        sim (run-synchronous-epoch sim e1 leader)
        sim (run-synchronous-epoch sim e2 leader)
        sim (run-synchronous-epoch sim e3 leader)
        nodes (:nodes sim)]
    (every? (fn [node]
              (let [finalized (:finalized-blocks node)
                    blocks (:blocks node)
                    has-e2? (some #(= e2 (:epoch (get blocks %))) finalized)]
                has-e2?))
            (vals nodes))))

(def gen-node-id
  "Generates a node ID."
  (gen/fmap #(mod % 4) gen/nat))
(def gen-epoch
  "Generates an epoch."
  (gen/choose 1 10))
(def gen-idx
  "Generates a random message index."
  gen/large-integer)

(def gen-action
  "Generates a simulator action."
  (gen/frequency
   [[2 (gen/tuple (gen/return :propose) gen-node-id gen-epoch)]
    [7 (gen/tuple (gen/return :deliver) gen-idx)]
    [1 (gen/tuple (gen/return :drop) gen-idx)]]))

(def gen-actions
  "Generates a list of simulator actions."
  (gen/vector gen-action 10 100))

(defspec ^{:doc "Property: Streamlet maintains safety and liveness under asynchronous fuzzing."}
  prop-streamlet-fuzz 20
  (prop/for-all [actions gen-actions]
                (let [sim (init-sim 4)
                      fuzzed-sim (run-sim sim actions)
                      safety-ok? (check-safety (:nodes fuzzed-sim))
                      liveness-ok? (test-liveness fuzzed-sim)]
                  (and safety-ok? liveness-ok?))))
