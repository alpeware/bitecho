(ns bitecho.streamlet.core-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.streamlet.core :as core]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest test-streamlet-records
  (testing "Block record can be instantiated"
    (let [block (core/->Block 1 "parent-hash-xyz" {:some "payload"} "proposer-xyz")]
      (is (= 1 (:epoch block)))
      (is (= "parent-hash-xyz" (:parent-hash block)))
      (is (= {:some "payload"} (:payload block)))
      (is (= "proposer-xyz" (:proposer block)))))

  (testing "Vote record can be instantiated"
    (let [vote (core/->Vote "block-hash-abc" 2 "signature-123")]
      (is (= "block-hash-abc" (:block-hash vote)))
      (is (= 2 (:epoch vote)))
      (is (= "signature-123" (:voter-signature vote))))))

(deftest test-propose-block
  (testing "propose-block uses correct state defaults"
    (let [state {:node-pubkey "pub1" :mempool ["tx1"] :head-hash "hash0"}
          block (core/propose-block state 5)]
      (is (= 5 (:epoch block)))
      (is (= "hash0" (:parent-hash block)))
      (is (= ["tx1"] (:payload block)))
      (is (= "pub1" (:proposer block)))))

  (testing "propose-block falls back to genesis and empty mempool"
    (let [state {:node-pubkey "pub2"}
          block (core/propose-block state 6)]
      (is (= 6 (:epoch block)))
      (is (= "genesis" (:parent-hash block)))
      (is (= [] (:payload block)))
      (is (= "pub2" (:proposer block))))))

(deftest test-cast-vote
  (testing "cast-vote prevents duplicate voting per epoch"
    (let [state {:voted-epochs #{7}}
          block (core/->Block 7 "genesis" [] "proposer1")
          vote (core/cast-vote state block)]
      (is (nil? vote))))

  (testing "cast-vote generates valid signed vote"
    (let [keypair (crypto/generate-keypair)
          state {:voted-epochs #{} :keypair keypair}
          block (core/->Block 8 "genesis" [] "proposer2")
          vote (core/cast-vote state block)]
      (is (not (nil? vote)))
      (is (= 8 (:epoch vote)))
      (is (string? (:block-hash vote)))
      (is (string? (:voter-signature vote)))
      ;; Verify signature
      (is (true? (crypto/verify
                  (:public keypair)
                  (.getBytes ^String (:block-hash vote) "UTF-8")
                  (core/hex->bytes (:voter-signature vote))))))))

(deftest test-longest-notarized-parent-vote
  (let [keypair (crypto/generate-keypair)
        ;; Create a chain: b1 -> b2 -> b3
        b1 (core/->Block 1 "genesis" [] "p1")
        h1 (core/hash-block b1)
        b2 (core/->Block 2 h1 [] "p2")
        h2 (core/hash-block b2)
        b3 (core/->Block 3 h2 [] "p3")
        h3 (core/hash-block b3)
        ;; And an alternative shorter branch: b1-alt
        b1-alt (core/->Block 1 "genesis" ["alt"] "p-alt")
        h1-alt (core/hash-block b1-alt)
        blocks {h1 b1, h2 b2, h3 b3, h1-alt b1-alt}]

    (testing "when no blocks are notarized, extending 'genesis' succeeds"
      (let [state {:voted-epochs #{} :keypair keypair :blocks {} :notarized-blocks #{}}
            block (core/->Block 1 "genesis" [] "p")
            vote (core/cast-vote state block)]
        (is (not (nil? vote)))
        (is (= 1 (:epoch vote)))
        (is (true? (core/longest-notarized-parent? state "genesis")))))

    (testing "when no blocks are notarized, extending a non-genesis block fails"
      (let [state {:voted-epochs #{} :keypair keypair :blocks {} :notarized-blocks #{}}
            block (core/->Block 1 "non-genesis-hash" [] "p")
            vote (core/cast-vote state block)]
        (is (nil? vote))
        (is (false? (core/longest-notarized-parent? state "non-genesis-hash")))))

    (testing "when b1 and b2 are notarized, extending genesis fails (shorter than longest notarized)"
      (let [state {:voted-epochs #{} :keypair keypair :blocks blocks :notarized-blocks #{h1 h2}}
            block (core/->Block 3 "genesis" [] "p")
            vote (core/cast-vote state block)]
        (is (nil? vote))
        (is (false? (core/longest-notarized-parent? state "genesis")))))

    (testing "when b1 and b2 are notarized, extending shorter branch h1 fails"
      (let [state {:voted-epochs #{} :keypair keypair :blocks blocks :notarized-blocks #{h1 h2}}
            block (core/->Block 3 h1 [] "p")
            vote (core/cast-vote state block)]
        (is (nil? vote))
        (is (false? (core/longest-notarized-parent? state h1)))))

    (testing "when b1 and b2 are notarized, extending longest notarized head h2 succeeds"
      (let [state {:voted-epochs #{} :keypair keypair :blocks blocks :notarized-blocks #{h1 h2}}
            block (core/->Block 3 h2 [] "p")
            vote (core/cast-vote state block)]
        (is (not (nil? vote)))
        (is (= 3 (:epoch vote)))
        (is (true? (core/longest-notarized-parent? state h2)))))

    (testing "when there are two notarized chains of equal length (fork), extending either head succeeds"
      (let [state {:voted-epochs #{} :keypair keypair :blocks blocks :notarized-blocks #{h1 h1-alt}}
            block-a (core/->Block 2 h1 [] "p")
            block-b (core/->Block 2 h1-alt [] "p")
            vote-a (core/cast-vote state block-a)
            vote-b (core/cast-vote state block-b)]
        (is (true? (core/longest-notarized-parent? state h1)))
        (is (true? (core/longest-notarized-parent? state h1-alt)))
        (is (not (nil? vote-a)))
        (is (not (nil? vote-b)))))))

(deftest test-quorum-threshold
  (testing "quorum-threshold calculates 2n/3 properly"
    (is (= 1 (core/quorum-threshold 1)))
    (is (= 2 (core/quorum-threshold 2)))
    (is (= 2 (core/quorum-threshold 3)))
    (is (= 3 (core/quorum-threshold 4)))
    (is (= 4 (core/quorum-threshold 5)))
    (is (= 4 (core/quorum-threshold 6)))
    (is (= 7 (core/quorum-threshold 10)))))

(deftest test-accumulate-vote
  (let [keypair1 (crypto/generate-keypair)
        pub1 (:public keypair1)
        priv1 (:private keypair1)

        keypair2 (crypto/generate-keypair)
        pub2 (:public keypair2)
        priv2 (:private keypair2)

        block-hash "test-block-hash"

        ;; valid vote from pub1
        sig1 (crypto/sign priv1 (.getBytes block-hash "UTF-8"))
        vote1 (core/->Vote block-hash 1 (#'core/bytes->hex sig1))

        ;; valid vote from pub2
        sig2 (crypto/sign priv2 (.getBytes block-hash "UTF-8"))
        vote2 (core/->Vote block-hash 1 (#'core/bytes->hex sig2))

        ;; invalid vote (wrong signature)
        invalid-sig (crypto/sign priv2 (.getBytes "wrong-hash" "UTF-8"))
        invalid-vote (core/->Vote block-hash 1 (#'core/bytes->hex invalid-sig))]

    (testing "accumulate-vote rejects invalid signatures"
      (let [state {:block-votes {} :notarized-blocks #{}}
            new-state (core/accumulate-vote state invalid-vote pub1 3)]
        (is (= state new-state))))

    (testing "accumulate-vote accepts valid signature but no notarization below threshold"
      (let [state {:block-votes {} :notarized-blocks #{}}
            new-state (core/accumulate-vote state vote1 pub1 3)]
        (is (= #{(#'core/bytes->hex pub1)} (get-in new-state [:block-votes block-hash])))
        (is (= #{} (:notarized-blocks new-state)))))

    (testing "accumulate-vote notarizes block when threshold is reached"
      (let [state {:block-votes {block-hash #{(#'core/bytes->hex pub1)}}
                   :notarized-blocks #{}}
            ;; threshold for n=3 is 2
            new-state (core/accumulate-vote state vote2 pub2 3)]
        (is (= #{(#'core/bytes->hex pub1) (#'core/bytes->hex pub2)} (get-in new-state [:block-votes block-hash])))
        (is (= #{block-hash} (:notarized-blocks new-state)))))))

(defn- build-test-chain
  "Builds a chain of blocks from a list of epochs."
  [epochs]
  (reduce (fn [acc epoch]
            (let [parent-hash (if (empty? acc) "genesis" (:hash (last acc)))
                  block (core/->Block epoch parent-hash [] "proposer")
                  b-hash (core/hash-block block)]
              (conj acc (assoc block :hash b-hash))))
          []
          epochs))

(deftest test-finalize-prefix-unit
  (testing "finalize-prefix finalizes nothing if no consecutive epochs"
    (let [chain (build-test-chain [1 3 5])
          blocks-map (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) chain))
          notarized (set (keys blocks-map))
          state {:blocks blocks-map
                 :notarized-blocks notarized
                 :finalized-blocks #{}}
          new-state (core/finalize-prefix state)]
      (is (= #{} (:finalized-blocks new-state)))))

  (testing "finalize-prefix finalizes middle block and ancestors on 3 consecutive epochs"
    (let [chain (build-test-chain [1 2 4 5 6 8])
          blocks-map (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) chain))
          notarized (set (keys blocks-map))
          state {:blocks blocks-map
                 :notarized-blocks notarized
                 :finalized-blocks #{}}
          new-state (core/finalize-prefix state)
          b1 (:hash (nth chain 0))
          b2 (:hash (nth chain 1))
          b4 (:hash (nth chain 2))
          b5 (:hash (nth chain 3))]
      ;; chain of 4, 5, 6 means 5 and its ancestors (4, 2, 1) should be finalized
      (is (contains? (:finalized-blocks new-state) b1))
      (is (contains? (:finalized-blocks new-state) b2))
      (is (contains? (:finalized-blocks new-state) b4))
      (is (contains? (:finalized-blocks new-state) b5))
      (is (not (contains? (:finalized-blocks new-state) (:hash (nth chain 4))))))))

(defspec ^{:doc "Property: any chain with a 3-consecutive epoch sequence finalizes up to the middle block."}
  prop-finalize-prefix 100
  (prop/for-all [epochs (gen/not-empty (gen/vector (gen/choose 1 100)))]
                (let [sorted-epochs (vec (distinct (sort epochs)))
                      chain (build-test-chain sorted-epochs)
                      blocks-map (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) chain))
                      notarized (set (keys blocks-map))
                      state {:blocks blocks-map
                             :notarized-blocks notarized
                             :finalized-blocks #{}}
                      new-state (core/finalize-prefix state)
                      finalized (:finalized-blocks new-state)

                      triplets (partition 3 1 chain)
                      consecutive-triplets (filter (fn [[b1 b2 b3]]
                                                     (and (= (:epoch b2) (inc (:epoch b1)))
                                                          (= (:epoch b3) (inc (:epoch b2)))))
                                                   triplets)
                      expected-finalized (set (mapcat (fn [[_ b2 _]]
                                                        (map :hash (take-while #(not= (:hash %) (:hash b2)) chain)))
                                                      consecutive-triplets))
                      expected-finalized (into expected-finalized (map (comp :hash second) consecutive-triplets))]
                  (= finalized expected-finalized))))

(defspec ^{:doc "Property: cast-vote only votes on blocks extending a longest notarized chain head."}
  prop-longest-notarized-chain-vote 100
  (prop/for-all [chain-len (gen/choose 1 10)]
                (let [keypair (crypto/generate-keypair)
                      epochs (range 1 (inc chain-len))
                      main-chain (build-test-chain epochs)
                      main-blocks (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) main-chain))
                      main-head-hash (:hash (last main-chain))
                      state {:voted-epochs #{}
                             :keypair keypair
                             :blocks main-blocks
                             :notarized-blocks (set (keys main-blocks))}

          ;; 1. Block extending longest notarized head should be voted on
                      valid-block (core/->Block (+ chain-len 1) main-head-hash [] "proposer")
                      valid-vote (core/cast-vote state valid-block)

          ;; 2. Block extending 'genesis' when chain-len >= 1 should be REJECTED (vote is nil)
                      stale-genesis-block (core/->Block (+ chain-len 2) "genesis" [] "proposer")
                      stale-genesis-vote (core/cast-vote state stale-genesis-block)

          ;; 3. Block extending a shorter ancestor (if chain-len > 1) should be REJECTED
                      shorter-ancestor-ok?
                      (if (> chain-len 1)
                        (let [shorter-hash (:hash (first main-chain))
                              shorter-block (core/->Block (+ chain-len 3) shorter-hash [] "proposer")]
                          (nil? (core/cast-vote state shorter-block)))
                        true)]
                  (and (not (nil? valid-vote))
                       (= (+ chain-len 1) (:epoch valid-vote))
                       (nil? stale-genesis-vote)
                       shorter-ancestor-ok?))))

(defn- test-bytes->hex [^bytes ba]
  (apply str (map #(format "%02x" %) ba)))

(defn- setup-test-nodes [n]
  (let [pairs (repeatedly n crypto/generate-keypair)
        sorted-pairs (vec (sort-by (fn [kp] (test-bytes->hex (:public kp))) pairs))
        peer-hexes (mapv #(test-bytes->hex (:public %)) sorted-pairs)
        peers-map (into {} (map (fn [kp] [(test-bytes->hex (:public kp)) (:public kp)]) sorted-pairs))]
    {:pairs sorted-pairs
     :peer-hexes peer-hexes
     :peers-map peers-map}))

(deftest test-handle-streamlet-event-tick-proposer
  (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
        proposer-idx (mod 1 3)
        proposer-kp (nth pairs proposer-idx)
        proposer-hex (nth peer-hexes proposer-idx)
        state {:epoch 0
               :node-pubkey proposer-hex
               :keypair proposer-kp
               :peers-map peers-map
               :total-nodes 3
               :blocks {}
               :notarized-blocks #{}
               :head-hash "genesis"}
        event {:type :tick}
        result (core/handle-streamlet-event state event)
        new-state (:state result)
        commands (:commands result)]
    (testing "proposer node increments epoch and updates head-hash"
      (is (= 1 (:epoch new-state)))
      (is (= "genesis" (:head-hash new-state))))
    (testing "proposer creates block and adds to :blocks"
      (let [block-hashes (keys (:blocks new-state))]
        (is (= 1 (count block-hashes)))
        (let [b (first (vals (:blocks new-state)))]
          (is (= 1 (:epoch b)))
          (is (= "genesis" (:parent-hash b)))
          (is (= proposer-hex (:proposer b))))))
    (testing "proposer votes for own block and accumulates its vote"
      (is (contains? (:voted-epochs new-state) 1))
      (let [b-hash (first (keys (:blocks new-state)))]
        (is (contains? (get-in new-state [:block-votes b-hash]) proposer-hex))))
    (testing "proposer emits send-propose and send-vote commands"
      (is (= 2 (count commands)))
      (let [cmd-types (set (map :type commands))]
        (is (contains? cmd-types :send-propose))
        (is (contains? cmd-types :send-vote))
        (let [vote-cmd (first (filter #(= (:type %) :send-vote) commands))
              vote (:vote vote-cmd)]
          (is (= 1 (:epoch vote)))
          (is (true? (crypto/verify (:public proposer-kp)
                                    (.getBytes ^String (:block-hash vote) "UTF-8")
                                    (core/hex->bytes (:voter-signature vote))))))))))

(deftest test-handle-streamlet-event-tick-non-proposer
  (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
        proposer-idx (mod 1 3)
        non-proposer-idx (if (zero? proposer-idx) 1 0)
        kp (nth pairs non-proposer-idx)
        hex-pk (nth peer-hexes non-proposer-idx)
        state {:epoch 0
               :node-pubkey hex-pk
               :keypair kp
               :peers-map peers-map
               :total-nodes 3
               :blocks {}
               :notarized-blocks #{}
               :head-hash "genesis"}
        event {:type :tick}
        result (core/handle-streamlet-event state event)
        new-state (:state result)
        commands (:commands result)]
    (testing "non-proposer increments epoch but proposes nothing"
      (is (= 1 (:epoch new-state)))
      (is (empty? (:blocks new-state)))
      (is (empty? (:voted-epochs new-state)))
      (is (empty? commands)))))

(deftest test-handle-streamlet-event-receive-propose
  (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
        kp0 (first pairs)
        hex0 (first peer-hexes)
        hex1 (second peer-hexes)
        state {:epoch 1
               :node-pubkey hex0
               :keypair kp0
               :peers-map peers-map
               :total-nodes 3
               :blocks {}
               :notarized-blocks #{}
               :head-hash "genesis"}
        block (core/->Block 1 "genesis" ["tx1"] hex1)
        b-hash (core/hash-block block)]

    (testing "valid proposal with known parent triggers vote"
      (let [event {:type :receive-propose :block block :sender hex1}
            result (core/handle-streamlet-event state event)
            new-state (:state result)
            commands (:commands result)]
        (is (contains? (:blocks new-state) b-hash))
        (is (contains? (:voted-epochs new-state) 1))
        (is (contains? (get-in new-state [:block-votes b-hash]) hex0))
        (is (= 1 (count commands)))
        (let [cmd (first commands)]
          (is (= :send-vote (:type cmd)))
          (is (= b-hash (:block-hash (:vote cmd))))
          (is (true? (crypto/verify (:public kp0)
                                    (.getBytes ^String b-hash "UTF-8")
                                    (core/hex->bytes (:voter-signature (:vote cmd)))))))))

    (testing "proposal with unknown parent buffers into future-blocks"
      (let [orphan-block (core/->Block 2 "unknown-parent-hash" ["tx2"] hex1)
            event {:type :receive-propose :block orphan-block :sender hex1}
            result (core/handle-streamlet-event state event)
            new-state (:state result)
            commands (:commands result)]
        (is (empty? commands))
        (is (= 1 (count (:future-blocks new-state))))
        (is (= orphan-block (:block (first (:future-blocks new-state)))))))

    (testing "duplicate proposal for already voted epoch does not vote again"
      (let [already-voted-state (assoc state :voted-epochs #{1})
            event {:type :receive-propose :block block :sender hex1}
            result (core/handle-streamlet-event already-voted-state event)
            commands (:commands result)]
        (is (empty? commands))))))

(deftest test-handle-streamlet-event-receive-vote
  (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
        kp0 (nth pairs 0)
        hex0 (nth peer-hexes 0)
        kp1 (nth pairs 1)
        hex1 (nth peer-hexes 1)
        kp2 (nth pairs 2)
        hex2 (nth peer-hexes 2)
        block (core/->Block 1 "genesis" [] hex0)
        b-hash (core/hash-block block)
        state {:epoch 1
               :node-pubkey hex0
               :keypair kp0
               :peers-map peers-map
               :total-nodes 3
               :blocks {b-hash block}
               :block-votes {b-hash #{hex0}}
               :notarized-blocks #{}
               :voted-epochs #{1}}]

    (testing "receiving valid vote accumulates and notarizes at quorum (2 of 3)"
      (let [sig1 (core/bytes->hex (crypto/sign (:private kp1) (.getBytes ^String b-hash "UTF-8")))
            vote1 (core/->Vote b-hash 1 sig1)
            event {:type :receive-vote :vote vote1 :sender hex1}
            result (core/handle-streamlet-event state event)
            new-state (:state result)]
        (is (contains? (get-in new-state [:block-votes b-hash]) hex1))
        (is (contains? (:notarized-blocks new-state) b-hash))))

    (testing "receiving vote for unknown block buffers into future-votes"
      (let [unknown-hash "some-unseen-block-hash"
            sig2 (core/bytes->hex (crypto/sign (:private kp2) (.getBytes ^String unknown-hash "UTF-8")))
            vote2 (core/->Vote unknown-hash 1 sig2)
            event {:type :receive-vote :vote vote2 :sender hex2}
            result (core/handle-streamlet-event state event)
            new-state (:state result)]
        (is (= 1 (count (get-in new-state [:future-votes unknown-hash]))))
        (is (empty? (:commands result)))))))

(deftest test-handle-streamlet-event-unknown-type
  (let [state {:epoch 0 :blocks {}}
        event {:type :unknown-foo}
        result (core/handle-streamlet-event state event)]
    (is (= state (:state result)))
    (is (= [] (:commands result)))))

(defspec ^{:doc "Property: Streamlet reducer achieves consensus and notarization across honest nodes without double-voting."}
  prop-streamlet-reducer-lifecycle 50
  (prop/for-all [node-count (gen/choose 3 6)]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes node-count)
                      init-nodes (into {} (map-indexed
                                           (fn [idx hex-pk]
                                             [hex-pk {:epoch 0
                                                      :node-pubkey hex-pk
                                                      :keypair (nth pairs idx)
                                                      :peers-map peers-map
                                                      :total-nodes node-count
                                                      :blocks {}
                                                      :block-votes {}
                                                      :notarized-blocks #{}
                                                      :voted-epochs #{}
                                                      :head-hash "genesis"}])
                                           peer-hexes))
                      proposer-idx (mod 1 node-count)
                      proposer-hex (nth peer-hexes proposer-idx)

                      proposer-res (core/handle-streamlet-event (get init-nodes proposer-hex) {:type :tick})
                      proposer-state (:state proposer-res)
                      proposer-cmds (:commands proposer-res)
                      prop-cmd (first (filter #(= (:type %) :send-propose) proposer-cmds))
                      proposed-block (:block prop-cmd)
                      b-hash (core/hash-block proposed-block)
                      proposer-vote-cmd (first (filter #(= (:type %) :send-vote) proposer-cmds))
                      proposer-vote (:vote proposer-vote-cmd)

                      ;; 2. Deliver proposal to all other nodes and collect their emitted votes
                      proposals-and-votes
                      (mapv (fn [[pk st]]
                              (if (= pk proposer-hex)
                                {:pk pk :state proposer-state :vote proposer-vote}
                                (let [res (core/handle-streamlet-event st {:type :receive-propose :block proposed-block :sender proposer-hex})
                                      vote-cmd (first (filter #(= (:type %) :send-vote) (:commands res)))]
                                  {:pk pk :state (:state res) :vote (:vote vote-cmd)})))
                            init-nodes)

                      nodes-after-propose
                      (into {} (map (fn [item] [(:pk item) (:state item)]) proposals-and-votes))

                      all-votes
                      (vec (keep :vote proposals-and-votes))

                      ;; 3. Deliver enough votes to reach quorum to every node
                      quorum (core/quorum-threshold node-count)
                      quorum-votes (take quorum all-votes)
                      final-nodes
                      (into {}
                            (map (fn [[pk st]]
                                   (let [final-st (reduce (fn [s v]
                                                            (let [sender-pk (first (filter (fn [hex]
                                                                                             (crypto/verify (get peers-map hex)
                                                                                                            (.getBytes ^String b-hash "UTF-8")
                                                                                                            (core/hex->bytes (:voter-signature v))))
                                                                                           peer-hexes))]
                                                              (:state (core/handle-streamlet-event s {:type :receive-vote :vote v :sender sender-pk}))))
                                                          st quorum-votes)]
                                     [pk final-st]))
                                 nodes-after-propose))

                      ;; 4. Invariant check:
                      ;; - Every node notarized the proposed block
                      ;; - Every node voted in epoch 1 exactly once
                      ;; - A duplicate proposal for epoch 1 yields NO votes
                      all-notarized? (every? (fn [[_ st]] (contains? (:notarized-blocks st) b-hash)) final-nodes)
                      single-vote? (every? (fn [[_ st]] (= #{1} (:voted-epochs st))) final-nodes)
                      no-double-vote? (every? (fn [[_ st]]
                                                (let [dup-block (core/->Block 1 "genesis" ["rogue"] proposer-hex)
                                                      dup-res (core/handle-streamlet-event st {:type :receive-propose :block dup-block :sender proposer-hex})]
                                                  (empty? (:commands dup-res))))
                                              final-nodes)]
                  (and (not (nil? prop-cmd))
                       (not (nil? proposer-vote))
                       (= 1 (:epoch proposed-block))
                       all-notarized?
                       single-vote?
                       no-double-vote?))))
