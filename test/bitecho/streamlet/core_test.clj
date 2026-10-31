(ns bitecho.streamlet.core-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.streamlet.core :as core]
            [clojure.set :as set]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest test-streamlet-records
  (testing "Block record can be instantiated with 4-arity (signature nil)"
    (let [block (core/->Block 1 "parent-hash-xyz" {:some "payload"} "proposer-xyz")]
      (is (= 1 (:epoch block)))
      (is (= "parent-hash-xyz" (:parent-hash block)))
      (is (= {:some "payload"} (:payload block)))
      (is (= "proposer-xyz" (:proposer block)))
      (is (nil? (:signature block)))))

  (testing "Block record can be instantiated with 5-arity"
    (let [block (core/->Block 1 "parent-hash-xyz" {:some "payload"} "proposer-xyz" "sig-xyz")]
      (is (= 1 (:epoch block)))
      (is (= "parent-hash-xyz" (:parent-hash block)))
      (is (= {:some "payload"} (:payload block)))
      (is (= "proposer-xyz" (:proposer block)))
      (is (= "sig-xyz" (:signature block)))))

  (testing "Vote record can be instantiated"
    (let [vote (core/->Vote "block-hash-abc" 2 "signature-123")]
      (is (= "block-hash-abc" (:block-hash vote)))
      (is (= 2 (:epoch vote)))
      (is (= "signature-123" (:voter-signature vote))))))

(deftest test-propose-block
  (testing "propose-block uses correct state defaults and leaves signature nil without private key"
    (let [state {:node-pubkey "pub1" :mempool ["tx1"] :head-hash "hash0"}
          block (core/propose-block state 5)]
      (is (= 5 (:epoch block)))
      (is (= "hash0" (:parent-hash block)))
      (is (= ["tx1"] (:payload block)))
      (is (= "pub1" (:proposer block)))
      (is (nil? (:signature block)))))

  (testing "propose-block falls back to genesis and empty mempool"
    (let [state {:node-pubkey "pub2"}
          block (core/propose-block state 6)]
      (is (= 6 (:epoch block)))
      (is (= "genesis" (:parent-hash block)))
      (is (= [] (:payload block)))
      (is (= "pub2" (:proposer block)))
      (is (nil? (:signature block)))))

  (testing "propose-block signs block when private key is present in state"
    (let [keypair (crypto/generate-keypair)
          pub-hex (core/bytes->hex (:public keypair))
          state {:node-pubkey pub-hex
                 :keypair keypair
                 :mempool ["tx1"]
                 :head-hash "hash0"}
          block (core/propose-block state 5)]
      (is (string? (:signature block)))
      (is (true? (core/verify-block-signature block (:public keypair))))
      (let [tampered (assoc block :payload ["tampered"])]
        (is (false? (core/verify-block-signature tampered (:public keypair))))))))

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
        kp1 (second pairs)
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
        raw-block (core/->Block 1 "genesis" ["tx1"] hex1)
        block (core/sign-block raw-block (:private kp1))
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
      (let [raw-orphan (core/->Block 1 "unknown-parent-hash" ["tx2"] hex1)
            orphan-block (core/sign-block raw-orphan (:private kp1))
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
        (is (empty? commands))))

    (testing "unsigned proposal is rejected fail-closed"
      (let [event {:type :receive-propose :block raw-block :sender hex1}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (empty? (:commands result)))))

    (testing "proposal with corrupted signature is rejected fail-closed"
      (let [corrupted (assoc block :signature (core/bytes->hex (byte-array 64)))
            event {:type :receive-propose :block corrupted :sender hex1}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (empty? (:commands result)))))

    (testing "proposal from wrong leader for epoch is rejected fail-closed"
      (let [wrong-raw (core/->Block 1 "genesis" ["tx1"] hex0)
            wrong-block (core/sign-block wrong-raw (:private kp0))
            event {:type :receive-propose :block wrong-block :sender hex0}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (empty? (:commands result)))))

    (testing "proposal with mismatched sender is rejected fail-closed"
      (let [event {:type :receive-propose :block block :sender hex0}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (empty? (:commands result)))))

    (testing "proposal from Sybil peer outside peers-map is rejected fail-closed"
      (let [sybil-kp (crypto/generate-keypair)
            sybil-hex (core/bytes->hex (:public sybil-kp))
            sybil-raw (core/->Block 1 "genesis" ["tx1"] sybil-hex)
            sybil-block (core/sign-block sybil-raw (:private sybil-kp))
            event {:type :receive-propose :block sybil-block :sender sybil-hex}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (empty? (:commands result)))))))

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
        (is (empty? (:commands result)))))

    (testing "receiving Sybil vote for known block is rejected fail-closed without modifying state"
      (let [sybil-kp (crypto/generate-keypair)
            sybil-hex (core/bytes->hex (:public sybil-kp))
            sybil-sig (core/bytes->hex (crypto/sign (:private sybil-kp) (.getBytes ^String b-hash "UTF-8")))
            sybil-vote (core/->Vote b-hash 1 sybil-sig)
            event {:type :receive-vote
                   :vote sybil-vote
                   :sender sybil-hex
                   :sender-pubkey-bytes (:public sybil-kp)}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (empty? (:commands result)))))

    (testing "receiving Sybil vote for unknown block is rejected fail-closed without buffering"
      (let [sybil-kp (crypto/generate-keypair)
            sybil-hex (core/bytes->hex (:public sybil-kp))
            unknown-hash "unknown-hash-xyz"
            sybil-sig (core/bytes->hex (crypto/sign (:private sybil-kp) (.getBytes ^String unknown-hash "UTF-8")))
            sybil-vote (core/->Vote unknown-hash 1 sybil-sig)
            event {:type :receive-vote :vote sybil-vote :sender sybil-hex}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
        (is (nil? (get-in (:state result) [:future-votes unknown-hash])))
        (is (empty? (:commands result)))))

    (testing "receiving malformed vote (missing voter-signature or block-hash) is rejected fail-closed"
      (let [malformed-vote {:epoch 1}
            event {:type :receive-vote :vote malformed-vote :sender hex1}
            result (core/handle-streamlet-event state event)]
        (is (= state (:state result)))
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
                                                (let [proposer-kp (nth pairs proposer-idx)
                                                      dup-raw (core/->Block 1 "genesis" ["rogue"] proposer-hex)
                                                      dup-block (core/sign-block dup-raw (:private proposer-kp))
                                                      dup-res (core/handle-streamlet-event st {:type :receive-propose :block dup-block :sender proposer-hex})]
                                                  (empty? (:commands dup-res))))
                                              final-nodes)]
                  (and (not (nil? prop-cmd))
                       (not (nil? proposer-vote))
                       (= 1 (:epoch proposed-block))
                       all-notarized?
                       single-vote?
                       no-double-vote?))))

(defspec ^{:doc "Property: Streamlet only accepts block proposals from the designated round-robin leader with valid Ed25519 signature."}
  prop-block-proposal-authentication 50
  (prop/for-all [node-count (gen/choose 3 6)
                 epoch (gen/choose 1 50)]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes node-count)
                      leader-idx (mod epoch node-count)
                      leader-hex (nth peer-hexes leader-idx)
                      leader-kp (nth pairs leader-idx)
                      non-leader-idx (mod (inc leader-idx) node-count)
                      non-leader-hex (nth peer-hexes non-leader-idx)
                      non-leader-kp (nth pairs non-leader-idx)
                      sybil-kp (crypto/generate-keypair)
                      sybil-hex (core/bytes->hex (:public sybil-kp))
                      state {:epoch epoch
                             :node-pubkey (first peer-hexes)
                             :keypair (first pairs)
                             :peers-map peers-map
                             :total-nodes node-count
                             :blocks {}
                             :notarized-blocks #{}
                             :head-hash "genesis"}
                      valid-raw (core/->Block epoch "genesis" ["tx"] leader-hex)
                      valid-block (core/sign-block valid-raw (:private leader-kp))
                      valid-res (core/handle-streamlet-event state {:type :receive-propose :block valid-block :sender leader-hex})
                      unsigned-res (core/handle-streamlet-event state {:type :receive-propose :block valid-raw :sender leader-hex})
                      tampered-block (assoc valid-block :payload ["tampered"])
                      tampered-res (core/handle-streamlet-event state {:type :receive-propose :block tampered-block :sender leader-hex})
                      wrong-leader-raw (core/->Block epoch "genesis" ["tx"] non-leader-hex)
                      wrong-leader-block (core/sign-block wrong-leader-raw (:private non-leader-kp))
                      wrong-leader-res (core/handle-streamlet-event state {:type :receive-propose :block wrong-leader-block :sender non-leader-hex})
                      mismatched-res (core/handle-streamlet-event state {:type :receive-propose :block valid-block :sender non-leader-hex})
                      sybil-raw (core/->Block epoch "genesis" ["tx"] sybil-hex)
                      sybil-block (core/sign-block sybil-raw (:private sybil-kp))
                      sybil-res (core/handle-streamlet-event state {:type :receive-propose :block sybil-block :sender sybil-hex})]
                  (and (contains? (:blocks (:state valid-res)) (core/hash-block valid-block))
                       (= state (:state unsigned-res))
                       (= state (:state tampered-res))
                       (= state (:state wrong-leader-res))
                       (= state (:state mismatched-res))
                       (= state (:state sybil-res))))))

(defspec ^{:doc "Property: Streamlet reducer rejects votes from Sybil senders (absent from peers-map) for both known and unknown blocks fail-closed."}
  prop-vote-sybil-sender-rejection 50
  (prop/for-all [node-count (gen/choose 3 6)
                 epoch (gen/choose 1 50)
                 unknown-block? gen/boolean]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes node-count)
                      honest-idx 1
                      honest-hex (nth peer-hexes honest-idx)
                      honest-kp (nth pairs honest-idx)
                      sybil-kp (crypto/generate-keypair)
                      sybil-hex (core/bytes->hex (:public sybil-kp))
                      block (core/->Block epoch "genesis" [] (first peer-hexes))
                      b-hash (if unknown-block? "unseen-block-hash" (core/hash-block block))
                      base-state {:epoch epoch
                                  :node-pubkey (first peer-hexes)
                                  :keypair (first pairs)
                                  :peers-map peers-map
                                  :total-nodes node-count
                                  :blocks (if unknown-block? {} {b-hash block})
                                  :block-votes (if unknown-block? {} {b-hash #{(first peer-hexes)}})
                                  :notarized-blocks #{}
                                  :voted-epochs #{epoch}}
                      honest-sig (core/bytes->hex (crypto/sign (:private honest-kp) (.getBytes ^String b-hash "UTF-8")))
                      honest-vote (core/->Vote b-hash epoch honest-sig)
                      honest-res (core/handle-streamlet-event base-state {:type :receive-vote :vote honest-vote :sender honest-hex})
                      sybil-sig (core/bytes->hex (crypto/sign (:private sybil-kp) (.getBytes ^String b-hash "UTF-8")))
                      sybil-vote (core/->Vote b-hash epoch sybil-sig)
                      sybil-res (core/handle-streamlet-event base-state {:type :receive-vote :vote sybil-vote :sender sybil-hex})]
                  (and (not= base-state (:state honest-res))
                       (= base-state (:state sybil-res))
                       (empty? (:commands sybil-res))))))

(deftest adversarial-cycle-guard-test
  (let [kp (crypto/generate-keypair)
        self-loop-blocks {"block-self" (core/->Block 1 "block-self" [] "p1")}
        cycle-2-blocks {"block-a" (core/->Block 1 "block-b" [] "p1")
                        "block-b" (core/->Block 2 "block-a" [] "p2")}
        multi-cycle-blocks {"block-1" (core/->Block 1 "block-3" [] "p1")
                            "block-2" (core/->Block 2 "block-1" [] "p2")
                            "block-3" (core/->Block 3 "block-2" [] "p3")
                            "block-leaf" (core/->Block 4 "block-3" [] "p4")}]
    (testing "chain-length detects cycles and returns -1"
      (is (= -1 (core/chain-length self-loop-blocks "block-self")))
      (is (= -1 (core/chain-length cycle-2-blocks "block-a")))
      (is (= -1 (core/chain-length cycle-2-blocks "block-b")))
      (is (= -1 (core/chain-length multi-cycle-blocks "block-leaf"))))

    (testing "get-ancestors terminates safely on cyclic chains"
      (is (= [] (core/get-ancestors self-loop-blocks "block-self")))
      (is (= ["block-b"] (core/get-ancestors cycle-2-blocks "block-a")))
      (is (= ["block-3" "block-2" "block-1"] (core/get-ancestors multi-cycle-blocks "block-leaf"))))

    (testing "longest-notarized-parent? rejects cyclic parents"
      (let [state-self {:notarized-blocks #{"block-self"}
                        :blocks self-loop-blocks}
            state-2cycle {:notarized-blocks #{"block-a" "block-b"}
                          :blocks cycle-2-blocks}]
        (is (false? (core/longest-notarized-parent? state-self "block-self")))
        (is (false? (core/longest-notarized-parent? state-2cycle "block-a")))
        (is (false? (core/longest-notarized-parent? state-2cycle "block-b")))))

    (testing "cast-vote refuses to vote for blocks with cyclic parents"
      (let [state {:voted-epochs #{}
                   :keypair kp
                   :notarized-blocks #{"block-a"}
                   :blocks cycle-2-blocks}
            block-voting-cyclic (core/->Block 3 "block-a" [] "proposer")]
        (is (nil? (core/cast-vote state block-voting-cyclic)))))

    (testing "update-head-hash falls back to genesis when all notarized blocks are cyclic"
      (let [state {:notarized-blocks #{"block-self"}
                   :blocks self-loop-blocks
                   :head-hash "old-head"}
            updated (#'core/update-head-hash state)]
        (is (= "genesis" (:head-hash updated)))))

    (testing "finalize-prefix terminates safely without hanging on cyclic block graph"
      (let [state {:notarized-blocks #{"block-a" "block-b"}
                   :blocks cycle-2-blocks
                   :finalized-blocks []}
            finalized (core/finalize-prefix state)]
        (is (= state finalized))))))

(defspec ^{:doc "Property: Traversal functions strictly terminate and reject arbitrary adversarial cycle topologies"}
  prop-adversarial-cycle-guard-termination 50
  (prop/for-all [cycle-len (gen/choose 1 10)
                 extra-hops (gen/choose 0 5)]
                (let [kp (crypto/generate-keypair)
                      cycle-hashes (mapv #(str "cycle-" %) (range cycle-len))
                      cycle-map (into {}
                                      (map-indexed
                                       (fn [i h]
                                         [h (core/->Block (inc i)
                                                          (nth cycle-hashes (mod (inc i) cycle-len))
                                                          []
                                                          "proposer")])
                                       cycle-hashes))
                      leaf-hashes (mapv #(str "leaf-" %) (range extra-hops))
                      leaf-map (into {}
                                     (map-indexed
                                      (fn [i h]
                                        (let [parent (if (zero? i)
                                                       (first cycle-hashes)
                                                       (nth leaf-hashes (dec i)))]
                                          [h (core/->Block (+ 100 i) parent [] "proposer")]))
                                      leaf-hashes))
                      all-blocks (merge cycle-map leaf-map)
                      target-hash (if (seq leaf-hashes) (last leaf-hashes) (first cycle-hashes))
                      state {:voted-epochs #{}
                             :keypair kp
                             :notarized-blocks (set (keys all-blocks))
                             :blocks all-blocks
                             :head-hash "genesis"}
                      prop-block (core/->Block 200 target-hash [] "proposer")]
                  (and (= -1 (core/chain-length all-blocks target-hash))
                       (vector? (core/get-ancestors all-blocks target-hash))
                       (<= (count (core/get-ancestors all-blocks target-hash)) (+ cycle-len extra-hops))
                       (false? (core/longest-notarized-parent? state target-hash))
                       (nil? (core/cast-vote state prop-block))
                       (= "genesis" (:head-hash (#'core/update-head-hash state)))
                       (map? (core/finalize-prefix state))))))

(def gen-malformed-vote
  "Generates malformed vote payloads to test exception-safety and fail-closed validation."
  (gen/one-of
   [(gen/elements [nil "not-a-map" 12345 :vote-kw ["vec" "vote"]])
    (gen/let [b-hash (gen/elements [123 :bad-hash ["vec"] nil {} true])
              sig (gen/elements ["112233" "aabbcc" 123 :sig nil])]
      {:block-hash b-hash :epoch 1 :voter-signature sig})
    (gen/let [b-hash (gen/elements ["known-block-hash" "unknown-block-hash"])
              sig (gen/elements [123 :sig-kw ["not" "hex"] (byte-array [1 2 3]) "abc" "zzzzzzzz" "xyz123" "1" "" nil])]
      {:block-hash b-hash :epoch 1 :voter-signature sig})]))

(defspec ^{:doc "Property: Streamlet reducer drops all malformed vote events fail-closed without throwing or altering state"}
  prop-malformed-vote-resilience 50
  (prop/for-all [node-count (gen/choose 3 6)
                 epoch (gen/choose 1 50)
                 unknown-block? gen/boolean
                 malformed-vote gen-malformed-vote]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes node-count)
                      sender-hex (nth peer-hexes 1)
                      block (core/->Block epoch "genesis" [] (first peer-hexes))
                      known-hash (core/hash-block block)
                      vote (if (and (map? malformed-vote) (contains? malformed-vote :block-hash))
                             (if unknown-block?
                               (assoc malformed-vote :block-hash (if (string? (:block-hash malformed-vote))
                                                                   "unknown-block-hash"
                                                                   (:block-hash malformed-vote)))
                               (assoc malformed-vote :block-hash (if (string? (:block-hash malformed-vote))
                                                                   known-hash
                                                                   (:block-hash malformed-vote))))
                             malformed-vote)
                      base-state {:epoch epoch
                                  :node-pubkey (first peer-hexes)
                                  :keypair (first pairs)
                                  :peers-map peers-map
                                  :total-nodes node-count
                                  :blocks {known-hash block}
                                  :block-votes {known-hash #{(first peer-hexes)}}
                                  :notarized-blocks #{}
                                  :voted-epochs #{epoch}}
                      event {:type :receive-vote :vote vote :sender sender-hex}
                      res (try (core/handle-streamlet-event base-state event)
                               (catch Throwable e {:error e}))]
                  (and (not (contains? res :error))
                       (= base-state (:state res))
                       (= [] (:commands res))))))

(deftest test-malformed-vote-resilience-unit
  (testing "accumulate-vote and handle-streamlet-event are exception-safe against malformed votes"
    (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
          voter-pk (:public (second pairs))
          voter-hex (second peer-hexes)
          block (core/->Block 1 "genesis" [] (first peer-hexes))
          b-hash (core/hash-block block)
          state {:epoch 1
                 :node-pubkey (first peer-hexes)
                 :keypair (first pairs)
                 :peers-map peers-map
                 :total-nodes 3
                 :blocks {b-hash block}
                 :block-votes {b-hash #{(first peer-hexes)}}
                 :notarized-blocks #{}
                 :voted-epochs #{1}}
          bad-votes [{:block-hash 123 :voter-signature "abcd"}
                     {:block-hash b-hash :voter-signature 123}
                     {:block-hash b-hash :voter-signature "abc"}
                     {:block-hash b-hash :voter-signature "zzzzzzzz"}
                     {:block-hash nil :voter-signature "abcd"}
                     {:block-hash b-hash :voter-signature nil}
                     "not-a-map"
                     nil]]
      (doseq [bv bad-votes]
        (testing (str "malformed vote: " (pr-str bv))
          ;; accumulate-vote should safely return state unchanged without throwing
          (is (= state (core/accumulate-vote state bv voter-pk 3)))
          ;; handle-streamlet-event should safely drop vote and return state unchanged
          (let [res (core/handle-streamlet-event state {:type :receive-vote :vote bv :sender voter-hex})]
            (is (= state (:state res)))
            (is (= [] (:commands res)))))))))

(defn- step-consensus-round
  "Executes one full consensus round for epoch e across nodes-map:
   proposer ticks, broadcasts proposal w/ ancestors, peers vote, votes are delivered to all nodes."
  [nodes-map peer-hexes e]
  (let [node-count (count peer-hexes)
        proposer-idx (mod e node-count)
        proposer-hex (nth peer-hexes proposer-idx)
        proposer-st (get nodes-map proposer-hex)
        proposer-res (core/handle-streamlet-event proposer-st {:type :tick})
        prop-cmd (first (filter #(= (:type %) :send-propose) (:commands proposer-res)))
        prop-vote-cmd (first (filter #(= (:type %) :send-vote) (:commands proposer-res)))
        proposed-block (:block prop-cmd)
        ancestors (:ancestors prop-cmd)
        proposer-vote (when prop-vote-cmd (:vote prop-vote-cmd))
        proposer-st-after (:state proposer-res)

        ;; Deliver proposal to peers
        nodes-and-votes
        (mapv (fn [hex]
                (if (= hex proposer-hex)
                  {:hex hex :state proposer-st-after :vote proposer-vote}
                  (let [st (get nodes-map hex)
                        res (core/handle-streamlet-event st {:type :receive-propose
                                                             :block proposed-block
                                                             :ancestors ancestors
                                                             :sender proposer-hex})
                        vote-cmd (first (filter #(= (:type %) :send-vote) (:commands res)))]
                    {:hex hex :state (:state res) :vote (when vote-cmd (:vote vote-cmd))})))
              peer-hexes)

        nodes-after-proposal (into {} (map (fn [item] [(:hex item) (:state item)]) nodes-and-votes))
        all-votes (vec (keep :vote nodes-and-votes))

        ;; Deliver all votes to all nodes
        final-nodes
        (into {}
              (map (fn [[hex st]]
                     (let [final-st (reduce (fn [s v]
                                              (let [voter-hex (first (filter (fn [h]
                                                                               (let [pk (get-in s [:peers-map h])]
                                                                                 (and pk
                                                                                      (crypto/verify pk
                                                                                                     (.getBytes ^String (:block-hash v) "UTF-8")
                                                                                                     (core/hex->bytes (:voter-signature v))))))
                                                                             peer-hexes))]
                                                (:state (core/handle-streamlet-event s {:type :receive-vote :vote v :sender voter-hex}))))
                                            st
                                            all-votes)]
                       [hex final-st]))
                   nodes-after-proposal))]
    final-nodes))

(deftest test-longest-notarized-parent-epoch-monotonicity
  (let [b1 (core/->Block 5 "genesis" [] "p1")
        h1 (core/hash-block b1)
        b2 (core/->Block 6 h1 [] "p2")
        h2 (core/hash-block b2)
        state {:blocks {h1 b1, h2 b2}
               :notarized-blocks #{h1 h2}}]
    (testing "child epoch > parent epoch is allowed"
      (is (true? (core/longest-notarized-parent? state h2 7))))
    (testing "child epoch <= parent epoch is rejected"
      (is (false? (core/longest-notarized-parent? state h2 6)))
      (is (false? (core/longest-notarized-parent? state h2 5)))
      (is (false? (core/longest-notarized-parent? state h2 4))))
    (testing "genesis parent allows any positive child epoch"
      (is (true? (core/longest-notarized-parent? {:notarized-blocks #{}} "genesis" 1))))))

(defn- make-quorum-votes-for-block
  "Generates a quorum of signed votes for b-hash at epoch using keypairs from pairs."
  [b-hash epoch pairs peer-hexes]
  (let [threshold (core/quorum-threshold (count peer-hexes))
        voters (take threshold (map vector pairs peer-hexes))
        votes (into {}
                    (map (fn [[kp hex]]
                           (let [sig-bytes (crypto/sign (:private kp) (.getBytes ^String b-hash "UTF-8"))
                                 vote (core/->Vote b-hash epoch (core/bytes->hex sig-bytes))]
                             [hex vote]))
                         voters))]
    {:voter-set (set (keys votes))
     :vote-proofs votes}))

(deftest test-staggered-epoch-catchup-and-finalization
  (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
        [hex1 hex2 hex3] peer-hexes
        [kp1 kp2 kp3] pairs
        blocks-seq (reduce (fn [acc e]
                             (let [parent-hash (if (empty? acc) "genesis" (:hash (last acc)))
                                   leader-idx (mod e 3)
                                   leader-hex (nth peer-hexes leader-idx)
                                   leader-kp (nth pairs leader-idx)
                                   raw-b (core/->Block e parent-hash [] leader-hex)
                                   b (core/sign-block raw-b (:private leader-kp))
                                   h (core/hash-block b)]
                               (conj acc (assoc b :hash h))))
                           []
                           (range 1 6))
        all-blocks (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) blocks-seq))
        all-block-votes (into {}
                              (map (fn [b]
                                     [(:hash b)
                                      (:voter-set (make-quorum-votes-for-block (:hash b) (:epoch b) pairs peer-hexes))])
                                   blocks-seq))
        all-block-proofs (into {}
                               (map (fn [b]
                                      [(:hash b)
                                       (:vote-proofs (make-quorum-votes-for-block (:hash b) (:epoch b) pairs peer-hexes))])
                                    blocks-seq))
        h1-h5 (mapv :hash blocks-seq)
        h5 (nth h1-h5 4)
        h2 (nth h1-h5 1)
        n1 {:epoch 5
            :node-pubkey hex1
            :keypair kp1
            :peers-map peers-map
            :total-nodes 3
            :blocks all-blocks
            :block-votes all-block-votes
            :block-vote-proofs all-block-proofs
            :notarized-blocks (set h1-h5)
            :head-hash h5}
        n2 {:epoch 2
            :node-pubkey hex2
            :keypair kp2
            :peers-map peers-map
            :total-nodes 3
            :blocks (select-keys all-blocks (take 2 h1-h5))
            :block-votes (select-keys all-block-votes (take 2 h1-h5))
            :block-vote-proofs (select-keys all-block-proofs (take 2 h1-h5))
            :notarized-blocks (set (take 2 h1-h5))
            :head-hash h2}
        n3 {:epoch 0
            :node-pubkey hex3
            :keypair kp3
            :peers-map peers-map
            :total-nodes 3
            :blocks {}
            :notarized-blocks #{}
            :head-hash "genesis"}
        nodes {hex1 n1, hex2 n2, hex3 n3}
        nodes-6 (step-consensus-round nodes peer-hexes 6)
        nodes-7 (step-consensus-round nodes-6 peer-hexes 7)
        nodes-8 (step-consensus-round nodes-7 peer-hexes 8)]

    (testing "all nodes catch up to epoch 8"
      (is (= 8 (:epoch (get nodes-8 hex1))))
      (is (= 8 (:epoch (get nodes-8 hex2))))
      (is (= 8 (:epoch (get nodes-8 hex3)))))

    (testing "node3 ingested missing ancestors 1..5"
      (doseq [h (take 5 h1-h5)]
        (is (contains? (:blocks (get nodes-8 hex3)) h))
        (is (contains? (:notarized-blocks (get nodes-8 hex3)) h))))

    (testing "all nodes have non-empty finalized-blocks"
      (is (seq (:finalized-blocks (get nodes-8 hex1))))
      (is (seq (:finalized-blocks (get nodes-8 hex2))))
      (is (seq (:finalized-blocks (get nodes-8 hex3))))
      (is (= (:finalized-blocks (get nodes-8 hex1))
             (:finalized-blocks (get nodes-8 hex2))
             (:finalized-blocks (get nodes-8 hex3)))))))

(defspec ^{:doc "Property: 3 nodes starting with random staggered initial epochs converge to identical epoch and non-empty finalized-blocks after 4 consecutive leader rounds."}
  prop-staggered-epoch-convergence 50
  (prop/for-all [e1 (gen/choose 0 10)
                 e2 (gen/choose 0 10)
                 e3 (gen/choose 0 10)]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
                      sorted-epochs (vec (sort > [e1 e2 e3]))
                      top-epoch (nth sorted-epochs 0)
                      mid-epoch (nth sorted-epochs 1)
                      low-epoch (nth sorted-epochs 2)
                      start-round (inc top-epoch)
                      leader-idx (mod start-round 3)
                      other-idxs (vec (remove #{leader-idx} [0 1 2]))
                      node-epochs {leader-idx top-epoch
                                   (nth other-idxs 0) mid-epoch
                                   (nth other-idxs 1) low-epoch}
                      blocks-seq (if (pos? top-epoch)
                                   (reduce (fn [acc e]
                                             (let [parent-hash (if (empty? acc) "genesis" (:hash (last acc)))
                                                   l-idx (mod e 3)
                                                   l-hex (nth peer-hexes l-idx)
                                                   l-kp (nth pairs l-idx)
                                                   raw-b (core/->Block e parent-hash [] l-hex)
                                                   b (core/sign-block raw-b (:private l-kp))
                                                   h (core/hash-block b)]
                                               (conj acc (assoc b :hash h))))
                                           []
                                           (range 1 (inc top-epoch)))
                                   [])
                      all-blocks (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) blocks-seq))
                      all-hashes (mapv :hash blocks-seq)
                      all-block-votes (into {}
                                            (map (fn [b]
                                                   [(:hash b)
                                                    (:voter-set (make-quorum-votes-for-block (:hash b) (:epoch b) pairs peer-hexes))])
                                                 blocks-seq))
                      all-block-proofs (into {}
                                             (map (fn [b]
                                                    [(:hash b)
                                                     (:vote-proofs (make-quorum-votes-for-block (:hash b) (:epoch b) pairs peer-hexes))])
                                                  blocks-seq))
                      make-node (fn [idx]
                                  (let [hex (nth peer-hexes idx)
                                        kp (nth pairs idx)
                                        ep (get node-epochs idx)
                                        node-hashes (take ep all-hashes)
                                        head (or (last node-hashes) "genesis")]
                                    {:epoch ep
                                     :node-pubkey hex
                                     :keypair kp
                                     :peers-map peers-map
                                     :total-nodes 3
                                     :blocks (select-keys all-blocks node-hashes)
                                     :block-votes (select-keys all-block-votes node-hashes)
                                     :block-vote-proofs (select-keys all-block-proofs node-hashes)
                                     :notarized-blocks (set node-hashes)
                                     :head-hash head}))
                      initial-nodes (into {} (map (fn [idx] [(nth peer-hexes idx) (make-node idx)]) [0 1 2]))
                      final-nodes (reduce (fn [nds r]
                                            (step-consensus-round nds peer-hexes r))
                                          initial-nodes
                                          (range start-round (+ start-round 4)))
                      end-epoch (+ top-epoch 4)
                      st1 (get final-nodes (nth peer-hexes 0))
                      st2 (get final-nodes (nth peer-hexes 1))
                      st3 (get final-nodes (nth peer-hexes 2))]
                  (and (= end-epoch (:epoch st1) (:epoch st2) (:epoch st3))
                       (seq (:finalized-blocks st1))
                       (seq (:finalized-blocks st2))
                       (seq (:finalized-blocks st3))
                       (seq (set/intersection (:finalized-blocks st1) (:finalized-blocks st2) (:finalized-blocks st3)))))))

(defspec ^{:doc "Property: Streamlet reducer drops proposals exceeding max-epoch-catchup-delta fail-closed"}
  prop-rejects-excessive-epoch-proposal 50
  (prop/for-all [curr-epoch (gen/choose 0 50)
                 delta-excess (gen/choose 65 500)]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
                      future-epoch (+ curr-epoch delta-excess)
                      leader-idx (mod future-epoch 3)
                      leader-hex (nth peer-hexes leader-idx)
                      leader-kp (nth pairs leader-idx)
                      raw-b (core/->Block future-epoch "genesis" [] leader-hex)
                      b (core/sign-block raw-b (:private leader-kp))
                      state {:epoch curr-epoch
                             :node-pubkey (first peer-hexes)
                             :keypair (first pairs)
                             :peers-map peers-map
                             :total-nodes 3
                             :blocks {}
                             :head-hash "genesis"}
                      event {:type :receive-propose :block b :sender leader-hex}
                      res (core/handle-streamlet-event state event)]
                  (and (= state (:state res))
                       (= [] (:commands res))))))

(defspec ^{:doc "Property: Streamlet reducer drops votes exceeding max-epoch-catchup-delta fail-closed"}
  prop-rejects-excessive-epoch-vote 50
  (prop/for-all [curr-epoch (gen/choose 0 50)
                 delta-excess (gen/choose 65 500)]
                (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
                      future-epoch (+ curr-epoch delta-excess)
                      voter-idx 1
                      voter-hex (nth peer-hexes voter-idx)
                      voter-kp (nth pairs voter-idx)
                      b-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                      sig-bytes (crypto/sign (:private voter-kp) (.getBytes ^String b-hash "UTF-8"))
                      vote (core/->Vote b-hash future-epoch (core/bytes->hex sig-bytes))
                      state {:epoch curr-epoch
                             :node-pubkey (first peer-hexes)
                             :keypair (first pairs)
                             :peers-map peers-map
                             :total-nodes 3
                             :blocks {}
                             :head-hash "genesis"}
                      event {:type :receive-vote :vote vote :sender voter-hex}
                      res (core/handle-streamlet-event state event)]
                  (and (= state (:state res))
                       (= [] (:commands res))))))

(deftest test-accumulate-vote-proofs
  (testing "accumulate-vote records both voter-hex in :block-votes and vote record in :block-vote-proofs"
    (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
          b (core/->Block 1 "genesis" [] (first peer-hexes))
          b-hash (core/hash-block b)
          voter-kp (second pairs)
          voter-hex (second peer-hexes)
          sig (crypto/sign (:private voter-kp) (.getBytes ^String b-hash "UTF-8"))
          vote (core/->Vote b-hash 1 (core/bytes->hex sig))
          init-state {:epoch 1
                      :node-pubkey (first peer-hexes)
                      :peers-map peers-map
                      :blocks {b-hash b}}
          next-state (core/accumulate-vote init-state vote (:public voter-kp) 3)]
      (is (= #{voter-hex} (get-in next-state [:block-votes b-hash])))
      (is (= vote (get-in next-state [:block-vote-proofs b-hash voter-hex]))))))

(deftest test-extract-notarized-ancestors-bundling
  (testing "extract-notarized-ancestors bundles block and quorum vote proofs"
    (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
          b1 (core/sign-block (core/->Block 1 "genesis" [] (nth peer-hexes 1)) (:private (nth pairs 1)))
          h1 (core/hash-block b1)
          q-votes (make-quorum-votes-for-block h1 1 pairs peer-hexes)
          state {:epoch 2
                 :node-pubkey (first peer-hexes)
                 :peers-map peers-map
                 :total-nodes 3
                 :blocks {h1 b1}
                 :block-votes {h1 (:voter-set q-votes)}
                 :block-vote-proofs {h1 (:vote-proofs q-votes)}
                 :notarized-blocks #{h1}}
          ancestors (core/extract-notarized-ancestors state h1 5)]
      (is (= 1 (count ancestors)))
      (is (= b1 (:block (first ancestors))))
      (is (= (:vote-proofs q-votes) (:votes (first ancestors)))))))

(deftest test-ancestor-quorum-verification
  (let [{:keys [pairs peer-hexes peers-map]} (setup-test-nodes 3)
        [hex1 hex2 hex3] peer-hexes
        [kp1 kp2 kp3] pairs
        b1 (core/sign-block (core/->Block 1 "genesis" [] hex2) (:private kp2))
        h1 (core/hash-block b1)
        q-votes1 (make-quorum-votes-for-block h1 1 pairs peer-hexes)
        valid-entry1 {:block b1 :votes (:vote-proofs q-votes1)}
        b2 (core/sign-block (core/->Block 2 h1 [] hex3) (:private kp3))
        state {:epoch 0
               :node-pubkey hex1
               :keypair kp1
               :peers-map peers-map
               :total-nodes 3
               :blocks {}
               :head-hash "genesis"}]

    (testing "bare ancestor block without votes is rejected fail-closed"
      (let [res (core/handle-streamlet-event state {:type :receive-propose
                                                    :block b2
                                                    :ancestors [b1]
                                                    :sender hex3})]
        (is (not (contains? (:blocks (:state res)) h1)))
        (is (not (contains? (:notarized-blocks (:state res)) h1)))))

    (testing "ancestor with fewer than quorum votes (< threshold) is rejected fail-closed"
      (let [sub-threshold-votes (select-keys (:vote-proofs q-votes1) [hex1])
            res (core/handle-streamlet-event state {:type :receive-propose
                                                    :block b2
                                                    :ancestors [{:block b1 :votes sub-threshold-votes}]
                                                    :sender hex3})]
        (is (not (contains? (:blocks (:state res)) h1)))
        (is (not (contains? (:notarized-blocks (:state res)) h1)))))

    (testing "ancestor with quorum count but corrupted signature is rejected fail-closed"
      (let [bad-vote (core/->Vote h1 1 "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            tampered-votes (assoc (:vote-proofs q-votes1) hex1 bad-vote)
            res (core/handle-streamlet-event state {:type :receive-propose
                                                    :block b2
                                                    :ancestors [{:block b1 :votes tampered-votes}]
                                                    :sender hex3})]
        (is (not (contains? (:blocks (:state res)) h1)))
        (is (not (contains? (:notarized-blocks (:state res)) h1)))))

    (testing "ancestor with quorum count but Sybil voter outside peers-map is rejected fail-closed"
      (let [sybil-kp (crypto/generate-keypair)
            sybil-hex (core/bytes->hex (:public sybil-kp))
            sybil-sig (crypto/sign (:private sybil-kp) (.getBytes ^String h1 "UTF-8"))
            sybil-vote (core/->Vote h1 1 (core/bytes->hex sybil-sig))
            sybil-votes {hex1 (get (:vote-proofs q-votes1) hex1)
                         sybil-hex sybil-vote}
            res (core/handle-streamlet-event state {:type :receive-propose
                                                    :block b2
                                                    :ancestors [{:block b1 :votes sybil-votes}]
                                                    :sender hex3})]
        (is (not (contains? (:blocks (:state res)) h1)))
        (is (not (contains? (:notarized-blocks (:state res)) h1)))))

    (testing "ancestor with epoch jump > 64 is rejected fail-closed"
      (let [b-far (core/sign-block (core/->Block 65 "genesis" [] (nth peer-hexes (mod 65 3)))
                                   (:private (nth pairs (mod 65 3))))
            h-far (core/hash-block b-far)
            q-far (make-quorum-votes-for-block h-far 65 pairs peer-hexes)
            b-next (core/sign-block (core/->Block 66 h-far [] (nth peer-hexes (mod 66 3)))
                                    (:private (nth pairs (mod 66 3))))
            res (core/handle-streamlet-event state {:type :receive-propose
                                                    :block b-next
                                                    :ancestors [{:block b-far :votes (:vote-proofs q-far)}]
                                                    :sender (nth peer-hexes (mod 66 3))})]
        (is (not (contains? (:blocks (:state res)) h-far)))
        (is (not (contains? (:notarized-blocks (:state res)) h-far)))))

    (testing "valid bundled ancestor with quorum vote proofs is accepted and ingested"
      (let [res (core/handle-streamlet-event state {:type :receive-propose
                                                    :block b2
                                                    :ancestors [valid-entry1]
                                                    :sender hex3})]
        (is (contains? (:blocks (:state res)) h1))
        (is (contains? (:notarized-blocks (:state res)) h1))
        (is (= (:voter-set q-votes1) (get-in (:state res) [:block-votes h1])))
        (is (= (:vote-proofs q-votes1) (get-in (:state res) [:block-vote-proofs h1])))
        (is (<= 1 (:epoch (:state res))))))))


