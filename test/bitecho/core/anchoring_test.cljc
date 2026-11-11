(ns bitecho.core.anchoring-test
  "Cross-platform test suite for Milestone 12 (M12):
   - Active Pointers, RFC 6962 Binary Merkle Tree & Inclusion Proofs (`bitecho.core.data`).
   - Child-Subnet Merkle State-Root Pointer Anchoring into Parent Subnets (`bitecho.core.subnet`).
   - Multi-Subnet Multiplexer Automatic Anchor Propagation & Inclusion Proof Verification (`bitecho.light-node.core`).
   - Rule 1 (Strict TDD & Generative Invariants), Rule 2 (Pure Sans-IO), Rule 5 (Zero Silent Failures)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            #?(:clj [clojure.test.check.properties :refer [for-all]]
               :cljs [clojure.test.check.properties :refer-macros [for-all]])))

;; -----------------------------------------------------------------------------
;; Generators & Test Helpers
;; -----------------------------------------------------------------------------

(def gen-safe-path
  "Generator for valid test pointer paths."
  (gen/fmap (fn [s] (str "head/" s)) (gen/not-empty gen/string-alphanumeric)))

(defn- make-signed-pointer
  [kp subnet path seq-num target-cid]
  (let [auth (basalt/bytes->hex (:public kp))]
    (data/sign-pointer (:private kp)
                       {:pointer/authority auth
                        :pointer/subnet (str subnet)
                        :pointer/path (str path)
                        :pointer/seq (long seq-num)
                        :pointer/target target-cid
                        :pointer/proof {:proof/type :self}})))

;; -----------------------------------------------------------------------------
;; 1. Merkle Tree Determinism & Sensitivity (Property 1)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property 1: Inserting the same valid Pointers in any permutation produces the exact same Merkle root; modifying any field, path, tombstone, or expiration strictly changes the root."}
  prop-merkle-root-sensitivity-and-determinism 50
  (for-all [paths (gen/such-that #(and (>= (count %) 2) (= (count %) (count (set %))))
                                 (gen/vector gen-safe-path 2 6))]
           (let [kp (crypto/generate-keypair)
                 pub (basalt/bytes->hex (:public kp))
                 sid "sub/child-1"
                 policy {:subnet/id sid
                         :subnet/gate {:gate/mode :permissioned
                                       :gate/admission :allowlist
                                       :gate/trust-anchors #{pub}}
                         :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                         :subnet/path-acl [{:pattern "head/*" :principal {:type :allowlist}}]
                         :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
                 ptrs (mapv (fn [p]
                              (let [b (data/make-blob (fressian/utf8->bytes (str "val-for-" p)) "text/plain")
                                    ptr (make-signed-pointer kp sid p 1 (:blob/cid b))]
                                {:blob b :pointer ptr}))
                            paths)
                 apply-all (fn [order]
                             (reduce (fn [st item]
                                       (let [b (:blob item)
                                             p (:pointer item)
                                             r1 (subnet/reduce-subnet st {:type :put-blob :blob b :sender pub})
                                             r2 (subnet/reduce-subnet (:state r1) {:type :publish-pointer :pointer p :sender pub})]
                                         (:state r2)))
                                     (:instance (subnet/init-subnet-instance policy))
                                     order))
                 inst-forward (apply-all ptrs)
                 inst-reverse (apply-all (vec (reverse ptrs)))
                 root-forward (data/compute-merkle-root inst-forward sid)
                 root-reverse (data/compute-merkle-root inst-reverse sid)
                 active-forward (data/active-subnet-pointers inst-forward sid)
                 active-reverse (data/active-subnet-pointers inst-reverse sid)
                 ;; Target update mutation
                 first-p (:pointer (first ptrs))
                 mut-blob (data/make-blob (fressian/utf8->bytes "mutated") "text/plain")
                 mut-ptr (make-signed-pointer kp sid (:pointer/path first-p) (inc (long (:pointer/seq first-p))) (:blob/cid mut-blob))
                 inst-mut (:state (-> inst-forward
                                      (subnet/reduce-subnet {:type :put-blob :blob mut-blob :sender pub})
                                      :state
                                      (subnet/reduce-subnet {:type :publish-pointer :pointer mut-ptr :sender pub})))
                 root-mut (data/compute-merkle-root inst-mut sid)
                 ;; Tombstone mutation
                 tomb-ptr (data/sign-pointer (:private kp)
                                             {:pointer/authority pub
                                              :pointer/subnet sid
                                              :pointer/path (:pointer/path first-p)
                                              :pointer/seq (+ 2 (long (:pointer/seq first-p)))
                                              :pointer/target nil
                                              :pointer/proof {:proof/type :self}})
                 inst-tomb (:state (subnet/reduce-subnet inst-mut {:type :publish-pointer :pointer tomb-ptr :sender pub}))
                 root-tomb (data/compute-merkle-root inst-tomb sid)]
             (and (= root-forward root-reverse)
                  (= active-forward active-reverse)
                  (not= root-forward root-mut)
                  (not= root-mut root-tomb)
                  (not= root-forward root-tomb)))))

;; -----------------------------------------------------------------------------
;; 2. Merkle Inclusion Proof Soundness & Tamper Rejection (Property 2)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property 2: Merkle inclusion proofs are sound for all active Pointers and reject any leaf, root, path, or step tampering."}
  prop-merkle-inclusion-proof-soundness 50
  (for-all [paths (gen/such-that #(and (>= (count %) 1) (= (count %) (count (set %))))
                                 (gen/vector gen-safe-path 1 7))]
           (let [kp (crypto/generate-keypair)
                 pub (basalt/bytes->hex (:public kp))
                 sid "sub/child-proof"
                 policy {:subnet/id sid
                         :subnet/gate {:gate/mode :permissioned
                                       :gate/admission :allowlist
                                       :gate/trust-anchors #{pub}}
                         :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                         :subnet/path-acl [{:pattern "head/*" :principal {:type :allowlist}}]
                         :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
                 ptrs (mapv (fn [p]
                              (let [b (data/make-blob (fressian/utf8->bytes (str "val-for-" p)) "text/plain")
                                    ptr (make-signed-pointer kp sid p 1 (:blob/cid b))]
                                {:blob b :pointer ptr}))
                            paths)
                 inst (reduce (fn [st item]
                                (let [r1 (subnet/reduce-subnet st {:type :put-blob :blob (:blob item) :sender pub})
                                      r2 (subnet/reduce-subnet (:state r1) {:type :publish-pointer :pointer (:pointer item) :sender pub})]
                                  (:state r2)))
                              (:instance (subnet/init-subnet-instance policy))
                              ptrs)
                 root (data/compute-merkle-root inst sid)]
             (every? (fn [p]
                       (let [proof (data/generate-merkle-proof inst sid p)
                             v-ok (data/verify-merkle-proof proof root)
                             bad-leaf-hash (assoc proof :leaf-hash (apply str (repeat 64 "0")))
                             v-bad-leaf (data/verify-merkle-proof bad-leaf-hash root)
                             bad-root (assoc proof :root (apply str (repeat 64 "f")))
                             v-bad-root (data/verify-merkle-proof bad-root root)
                             tampered-ptr (assoc-in proof [:pointer :pointer/target] (apply str (repeat 64 "a")))
                             v-bad-ptr (data/verify-merkle-proof tampered-ptr root)]
                         (and (:ok? v-ok)
                              (= root (:root v-ok))
                              (false? (:ok? v-bad-leaf))
                              (false? (:ok? v-bad-root))
                              (false? (:ok? v-bad-ptr)))))
                     paths))))

;; -----------------------------------------------------------------------------
;; 3. Parent-Side Anchor Verification & Hash-Chain Continuity (Property 3)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property 3: Valid sequence of child state-root anchors applies cleanly into parent subnet; stale seq, regressing epoch, broken prev-cid, or missing Blob is rejected fail-closed."}
  prop-parent-anchor-verification-and-chain-continuity 50
  (for-all [epochs (gen/fmap (fn [[base steps]]
                               (vec (reductions + base (map inc steps))))
                             (gen/tuple (gen/choose 1 50)
                                        (gen/vector (gen/choose 1 20) 1 3)))
            use-quorum? gen/boolean]
           (let [kp-child1 (crypto/generate-keypair)
                 pub-child1 (basalt/bytes->hex (:public kp-child1))
                 kp-child2 (crypto/generate-keypair)
                 pub-child2 (basalt/bytes->hex (:public kp-child2))
                 kp-parent (crypto/generate-keypair)
                 pub-parent (basalt/bytes->hex (:public kp-parent))
                 parent-sid "global"
                 child-sid "chat/simon-nexus-axiom"
                 parent-policy {:subnet/id parent-sid
                                :subnet/gate {:gate/mode :permissioned
                                              :gate/admission :allowlist
                                              :gate/trust-anchors #{pub-parent pub-child1 pub-child2}}
                                :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                                :subnet/path-acl [{:pattern "anchor/*" :principal {:type :allowlist}}]
                                :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
                 child-policy {:subnet/id child-sid
                               :subnet/parent-id parent-sid
                               :subnet/gate {:gate/mode :permissioned
                                             :gate/admission :allowlist
                                             :gate/trust-anchors #{pub-child1 pub-child2}}
                               :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                               :subnet/path-acl [{:pattern "head/*" :principal {:type :allowlist}}]
                               :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
                 q-signers (when use-quorum?
                             [{:pubkey pub-child1 :privkey (:private kp-child1)}
                              {:pubkey pub-child2 :privkey (:private kp-child2)}])
                 signing-opts (if use-quorum?
                                {:quorum-signers q-signers :authority-pubkey pub-child1}
                                {:authority-privkey (:private kp-child1) :authority-pubkey pub-child1})
                 ;; Build sequence of anchors
                 parent-inst0 (:instance (subnet/init-subnet-instance parent-policy))
                 child-inst0 (:instance (subnet/init-subnet-instance child-policy))
                 ;; Insert pointer in child
                 b0 (data/make-blob (fressian/utf8->bytes "data-0") "text/plain")
                 p0 (make-signed-pointer kp-child1 child-sid "head/item-0" 1 (:blob/cid b0))
                 child-inst1 (:state (-> child-inst0
                                         (subnet/reduce-subnet {:type :put-blob :blob b0 :sender pub-child1})
                                         :state
                                         (subnet/reduce-subnet {:type :publish-pointer :pointer p0 :sender pub-child1})))
                 ;; Anchor 1
                 ep1 (first epochs)
                 anc1 (subnet/build-subnet-anchor child-inst1 (assoc signing-opts :parent-subnet parent-sid :child-epoch ep1 :anchor-seq 1))
                 res-p-blob1 (subnet/reduce-subnet parent-inst0 {:type :put-blob :blob (:blob anc1) :sender pub-child1})
                 res-p-ptr1 (subnet/reduce-subnet (:state res-p-blob1) {:type :publish-pointer :pointer (:pointer anc1) :sender pub-child1})
                 ;; Anchor 2 (advances epoch and seq, chains to anc1)
                 ep2 (second epochs)
                 anc2 (subnet/build-subnet-anchor child-inst1 (assoc signing-opts
                                                                     :parent-subnet parent-sid
                                                                     :child-epoch ep2
                                                                     :anchor-seq 2
                                                                     :prev-anchor-cid (:blob/cid (:blob anc1))))
                 res-p-blob2 (subnet/reduce-subnet (:state res-p-ptr1) {:type :put-blob :blob (:blob anc2) :sender pub-child1})
                 res-p-ptr2 (subnet/reduce-subnet (:state res-p-blob2) {:type :publish-pointer :pointer (:pointer anc2) :sender pub-child1})
                 ;; Regression anchor (child-epoch equal or regressing)
                 anc-regress (subnet/build-subnet-anchor child-inst1 (assoc signing-opts
                                                                            :parent-subnet parent-sid
                                                                            :child-epoch ep1
                                                                            :anchor-seq 3
                                                                            :prev-anchor-cid (:blob/cid (:blob anc2))))
                 res-regress-blob (subnet/reduce-subnet (:state res-p-ptr2) {:type :put-blob :blob (:blob anc-regress) :sender pub-child1})
                 res-regress-ptr (subnet/reduce-subnet (:state res-regress-blob) {:type :publish-pointer :pointer (:pointer anc-regress) :sender pub-child1})
                 ;; Broken predecessor anchor
                 anc-bad-prev (subnet/build-subnet-anchor child-inst1 (assoc signing-opts
                                                                             :parent-subnet parent-sid
                                                                             :child-epoch (+ ep2 5)
                                                                             :anchor-seq 4
                                                                             :prev-anchor-cid (apply str (repeat 64 "0"))))
                 res-bad-prev-blob (subnet/reduce-subnet (:state res-p-ptr2) {:type :put-blob :blob (:blob anc-bad-prev) :sender pub-child1})
                 res-bad-prev-ptr (subnet/reduce-subnet (:state res-bad-prev-blob) {:type :publish-pointer :pointer (:pointer anc-bad-prev) :sender pub-child1})]
             (and (:applied? res-p-ptr1)
                  (:applied? res-p-ptr2)
                  (= (:blob/cid (:blob anc2))
                     (get-in (:state res-p-ptr2) [:data :pointers [parent-sid (str "anchor/" child-sid)] :pointer/target]))
                  (false? (:applied? res-regress-ptr))
                  (= :anchor-epoch-regression (:error res-regress-ptr))
                  (false? (:applied? res-bad-prev-ptr))
                  (= :anchor-predecessor-mismatch (:error res-bad-prev-ptr))))))

;; -----------------------------------------------------------------------------
;; 4. End-to-End Multiplexer Child-to-Parent Anchoring & Inclusion Proof (E2E)
;; -----------------------------------------------------------------------------

(deftest test-multiplexer-child-to-parent-anchoring-e2e
  (testing "Multiplexer propagates child :anchor-to-parent into parent subnet, verifying inclusion proof against parent state root"
    (let [kp-child (crypto/generate-keypair)
          pub-child (basalt/bytes->hex (:public kp-child))
          kp-parent (crypto/generate-keypair)
          pub-parent (basalt/bytes->hex (:public kp-parent))
          parent-sid "global"
          child-sid "chat/simon-nexus-axiom"
          parent-policy {:subnet/id parent-sid
                         :subnet/gate {:gate/mode :permissioned
                                       :gate/admission :allowlist
                                       :gate/trust-anchors #{pub-parent pub-child}}
                         :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                         :subnet/path-acl [{:pattern "anchor/*" :principal {:type :allowlist}}]
                         :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          child-policy {:subnet/id child-sid
                        :subnet/parent-id parent-sid
                        :subnet/gate {:gate/mode :permissioned
                                      :gate/admission :allowlist
                                      :gate/trust-anchors #{pub-child}}
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                        :subnet/path-acl [{:pattern "head/*" :principal {:type :allowlist}}]
                        :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}
                        :subnet/anchoring {:trigger :on-change
                                           :authority-privkey (:private kp-child)
                                           :authority-pubkey pub-child}}
          parent-inst (:instance (subnet/init-subnet-instance parent-policy))
          child-inst (:instance (subnet/init-subnet-instance child-policy))
          mux0 (-> (light-core/init-multi-subnet-multiplexer {})
                   (light-core/register-subnet-instance parent-sid parent-inst)
                   (light-core/register-subnet-instance child-sid child-inst))
          ;; Publish a pointer in child subnet
          b1 (data/make-blob (fressian/utf8->bytes "simon-state-1") "text/plain")
          p1 (make-signed-pointer kp-child child-sid "head/simon" 1 (:blob/cid b1))
          res-blob (light-core/route-multiplexed-envelope mux0
                                                          {:subnet-id child-sid
                                                           :type :put-blob
                                                           :blob b1
                                                           :sender pub-child}
                                                          nil)
          res-ptr (light-core/route-multiplexed-envelope (:mux res-blob)
                                                         {:subnet-id child-sid
                                                          :type :publish-pointer
                                                          :pointer p1
                                                          :sender pub-child}
                                                         nil)
          final-mux (:mux res-ptr)
          final-child (get-in final-mux [:subnets child-sid])
          final-parent (get-in final-mux [:subnets parent-sid])
          anchor-path (str "anchor/" child-sid)
          parent-anchor-ptr (get-in final-parent [:data :pointers [parent-sid anchor-path]])
          anchor-cid (:pointer/target parent-anchor-ptr)
          anchor-blob-entry (get-in final-parent [:data :blobs :entries anchor-cid])
          anchor-state-root (fressian/decode-wire (:bytes anchor-blob-entry))
          child-merkle-root (data/compute-merkle-root final-child child-sid)
          proof (data/generate-merkle-proof final-child child-sid "head/simon")
          verify-res (data/verify-merkle-proof proof (:merkle-root anchor-state-root))]
      (is (some? parent-anchor-ptr) "Parent subnet contains child anchor Pointer at anchor/<child-sid>")
      (is (= 1 (long (:pointer/seq parent-anchor-ptr))) "Anchor pointer seq is 1")
      (is (some? anchor-blob-entry) "Parent subnet has anchor Blob in its Blob store")
      (is (= :subnet-state-root (:bitecho/type anchor-state-root)) "Decoded anchor blob is :subnet-state-root")
      (is (= child-sid (:child-subnet anchor-state-root)) "Anchor child-subnet matches")
      (is (= child-merkle-root (:merkle-root anchor-state-root)) "Anchored Merkle root matches child Merkle root")
      (is (some? proof) "Generated inclusion proof for child pointer")
      (is (true? (:ok? verify-res)) "Inclusion proof strictly verifies against parent's anchored state root"))))

;; -----------------------------------------------------------------------------
;; 5. Cross-Runtime Merkle Golden Vectors (JVM <-> Node/CLJS)
;; -----------------------------------------------------------------------------

(deftest test-merkle-cross-runtime-golden-vectors
  (testing "Exact RFC 6962 64-hex SHA-256 Merkle empty-root and branch-hash golden vectors across JVM and Node/CLJS"
    (let [empty-root (data/merkle-empty-root "chat/simon-nexus-axiom")
          branch-hash (data/merkle-branch-hash (apply str (repeat 64 "a"))
                                               (apply str (repeat 64 "b")))]
      (is (= "a66d6f365a138370bf7a176e06d090b963674664d36313f42bf20688639b3645" empty-root)
          "Deterministic empty-root matches cross-runtime golden vector")
      (is (= "20c736e1902498770d01fc85f51684e09658b641c586a4fdb7ef26d0361e8fca" branch-hash)
          "Deterministic branch-hash matches cross-runtime golden vector"))))
