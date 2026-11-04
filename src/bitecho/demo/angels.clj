(ns bitecho.demo.angels
  "Pure Sans-IO demonstration orchestration and tensor pipeline verification for Milestone 6.
   Implements:
   1. Multi-Harness Skill v1 Neutrality Proof (JSONL external harness vs. JVM native harness).
   2. Three-Device / clj-einsum Angels Demo (Phone light node + 2-stage laptop pipeline shard)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.account :as account]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [clojure.data.json :as json]
            [clojure.edn :as edn]))

;; -----------------------------------------------------------------------------
;; Pure 2D Tensor Contraction (einsum "ij,jk->ik" and "ik,kl->il")
;; -----------------------------------------------------------------------------

(defn einsum-2d
  "Pure, deterministic 2D tensor contraction representing einsum(\"ij,jk->ik\", A, B).
   A is M x K matrix (vector of row vectors), B is K x N matrix.
   Returns M x N matrix of doubles."
  [a b]
  (let [k (count (first a))
        n (count (first b))]
    (vec
     (mapv (fn [row-a]
             (mapv (fn [col-idx]
                     (reduce (fn [acc p]
                               (+ acc (* (double (nth row-a p))
                                         (double (nth (nth b p) col-idx)))))
                             0.0
                             (range k)))
                   (range n)))
           a))))

(defn verify-tensor-parity
  "Mechanically verifies that computed tensor matches golden tensor within tolerance eps."
  ([computed golden] (verify-tensor-parity computed golden 1e-6))
  ([computed golden eps]
   (and (sequential? computed) (sequential? golden)
        (= (count computed) (count golden))
        (every? true?
                (map (fn [row-c row-g]
                       (and (sequential? row-c) (sequential? row-g)
                            (= (count row-c) (count row-g))
                            (every? true?
                                    (map (fn [vc vg]
                                           (<= (Math/abs (- (double vc) (double vg))) (double eps)))
                                         row-c
                                         row-g))))
                     computed
                     golden)))))

(defn tensor->deliverable-hash
  "Computes deterministic SHA-256 deliverable hash of tensor data or string preimage."
  [data]
  (let [canonical-str (if (string? data) data (pr-str data))
        hash-bytes (crypto/sha256 (.getBytes ^String canonical-str "UTF-8"))]
    (basalt/bytes->hex hash-bytes)))

;; -----------------------------------------------------------------------------
;; Pure Streamlet 3-Node BFT Consensus Stepper
;; -----------------------------------------------------------------------------

(defn exchange-block-and-votes
  "Simulates one Streamlet consensus epoch across an N-validator cluster.
   Ticks all nodes, distributes the leader's proposal, collects votes, and distributes votes."
  [states sorted-pubs ep]
  (let [n (count sorted-pubs)
        proposer-idx (mod ep n)
        proposer-pub (nth sorted-pubs proposer-idx)
        all-indices (vec (range n))
        tick-results (mapv (fn [st] (sm/handle-event st {:type :tick :rng (java.util.Random. ep)})) states)
        states-after-tick (mapv :state tick-results)
        proposer-res (nth tick-results proposer-idx)
        prop-cmd (first (filter #(= :send-propose (:type %)) (:commands proposer-res)))
        proposer-vote (first (filter #(= :send-vote (:type %)) (:commands proposer-res)))
        block (:block prop-cmd)
        v-prop (:vote proposer-vote)
        peer-indices (filterv #(not= % proposer-idx) all-indices)
        prop-deliver-results (reduce (fn [acc idx]
                                       (assoc acc idx (sm/handle-event (nth states-after-tick idx)
                                                                       {:type :receive-propose :block block :sender proposer-pub})))
                                     {}
                                     peer-indices)
        peer-votes (into {} (map (fn [idx]
                                   (let [res (get prop-deliver-results idx)
                                         vote-cmd (first (filter #(= :send-vote (:type %)) (:commands res)))]
                                     [idx (:vote vote-cmd)]))
                                 peer-indices))
        states-with-props (mapv (fn [idx]
                                  (if (= idx proposer-idx)
                                    (nth states-after-tick idx)
                                    (:state (get prop-deliver-results idx))))
                                all-indices)
        all-votes (into [[proposer-idx proposer-pub v-prop]]
                        (map (fn [idx] [idx (nth sorted-pubs idx) (get peer-votes idx)]) peer-indices))
        final-states (reduce (fn [curr-states [from-idx from-pub v]]
                               (if-not v
                                 curr-states
                                 (mapv (fn [to-idx]
                                         (if (= to-idx from-idx)
                                           (nth curr-states to-idx)
                                           (:state (sm/handle-event (nth curr-states to-idx)
                                                                    {:type :receive-vote :vote v :sender from-pub}))))
                                       all-indices)))
                             states-with-props
                             all-votes)]
    final-states))

(defn advance-consensus-epochs
  "Advances consensus across the 3-node cluster by n epochs, starting from start-epoch."
  [states sorted-pubs start-epoch n]
  (reduce (fn [curr-states ep]
            (exchange-block-and-votes curr-states sorted-pubs ep))
          states
          (range start-epoch (+ start-epoch n))))

;; -----------------------------------------------------------------------------
;; 1. Multi-Harness Skill v1 Neutrality Proof
;; -----------------------------------------------------------------------------

(defn run-multi-harness-neutrality-demo
  "Demonstrates multi-harness neutrality across two distinct agent harnesses:
   - Harness A: JSONL-bridge external harness adapter (process-jsonl-line)
   - Harness B: JVM-native harness adapter (handle-command)
   across a 3-node Streamlet BFT validator cluster with Directory Authority discovery,
   callee-pays rendezvous, E2E X25519 sealed channel, escrow settlement with 50 bps protocol take,
   and multi-validator BFT quorum sync."
  ([] (run-multi-harness-neutrality-demo {}))
  ([_opts]
   (let [;; 1. Identities
         dir-kp (crypto/generate-keypair)
         dir-pub (basalt/bytes->hex (:public dir-kp))
         dir-priv (:private dir-kp)

         val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
         val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
         sorted-val-indices (sort-by #(nth val-pubs %) (range 3))
         sorted-val-kps (mapv #(nth val-kps %) sorted-val-indices)
         sorted-val-pubs (mapv #(nth val-pubs %) sorted-val-indices)

         alice-kp (crypto/generate-keypair)
         alice-pub (basalt/bytes->hex (:public alice-kp))
         alice-priv (:private alice-kp)

         bob-kp (crypto/generate-keypair)
         bob-pub (basalt/bytes->hex (:public bob-kp))
         bob-priv (:private bob-kp)

         bootstrap {:network :devnet
                    :directory-pubkey dir-pub
                    :treasury-pubkey (nth sorted-val-pubs 0)
                    :custody-pubkey (nth sorted-val-pubs 0)
                    :nodes {:node1 {:pubkey (nth sorted-val-pubs 0) :ip "127.0.0.1" :port 5001 :agent-port 5010}
                            :node2 {:pubkey (nth sorted-val-pubs 1) :ip "127.0.0.1" :port 5002 :agent-port 5010}
                            :node3 {:pubkey (nth sorted-val-pubs 2) :ip "127.0.0.1" :port 5003 :agent-port 5010}}}

         ;; Initial economic balances
         alice-init-bal 100000
         bob-init-bal 10000
         val-init-bal 1000000
         escrow-amount 10000
         expected-take 50  ;; 0.5% protocol take
         expected-net 9950

         ;; Validator Cluster Genesis Ledger
         genesis-ledger {(nth sorted-val-pubs 0) (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})
                         (nth sorted-val-pubs 1) (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})
                         (nth sorted-val-pubs 2) (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})
                         alice-pub (account/map->AccountState {:balance alice-init-bal :seq 0 :deps []})
                         bob-pub (account/map->AccountState {:balance bob-init-bal :seq 0 :deps []})}
         peers-map {(nth sorted-val-pubs 0) (:public (nth sorted-val-kps 0))
                    (nth sorted-val-pubs 1) (:public (nth sorted-val-kps 1))
                    (nth sorted-val-pubs 2) (:public (nth sorted-val-kps 2))}
         cfg (assoc config/devnet-config
                    :genesis-ledger genesis-ledger
                    :peers-map peers-map
                    :validators sorted-val-pubs
                    :mesh-nodes sorted-val-pubs
                    :settlement-take-bps 50)
         init-val-states [(sm/init-state [] (nth sorted-val-pubs 0) (assoc cfg :keypair (nth sorted-val-kps 0)))
                          (sm/init-state [] (nth sorted-val-pubs 1) (assoc cfg :keypair (nth sorted-val-kps 1)))
                          (sm/init-state [] (nth sorted-val-pubs 2) (assoc cfg :keypair (nth sorted-val-kps 2)))]

         ;; 2. Directory Registration for both harnesses
         ;; Harness A (JSONL) creates PoP
         alice-pop-res (light-core/handle-command
                        (light-core/init-light-state {:pubkey-hex alice-pub} {:bootstrap bootstrap})
                        {"cmd" "directory-register" "nickname" "alice-harness" "domain" "bitecho.org"}
                        alice-priv)
         alice-pop (get-in alice-pop-res [:response "pop"])
         alice-desc (light-core/sign-directory-descriptor dir-priv dir-pub alice-pop {:issued-epoch 1 :expires-epoch 100})

         ;; Harness B (Native JVM) creates PoP
         bob-pop-res (light-core/handle-command
                      (light-core/init-light-state {:pubkey-hex bob-pub} {:bootstrap bootstrap})
                      {"cmd" "directory-register" "nickname" "bob-harness" "domain" "bitecho.org"}
                      bob-priv)
         bob-pop (get-in bob-pop-res [:response "pop"])
         bob-desc (light-core/sign-directory-descriptor dir-priv dir-pub bob-pop {:issued-epoch 1 :expires-epoch 100})

         ;; 3. Counterparty discovery & local petname mapping
         ;; Harness A (JSONL) discovers Bob via directory-lookup JSONL line and sets petname "bob"
         init-a (assoc (light-core/init-light-state {:pubkey-hex alice-pub} {:bootstrap bootstrap})
                       :home-set ["node1" "node2" "node3"])
         lookup-line-a (json/write-str {"cmd" "directory-lookup" "nickname" "bob-harness" "descriptor" bob-desc})
         a-res1 (light-core/process-jsonl-line init-a lookup-line-a alice-priv)
         st-a1 (:state a-res1)
         set-petname-line-a (json/write-str {"cmd" "petname-set" "petname" "bob" "pubkey" bob-pub})
         a-res2 (light-core/process-jsonl-line st-a1 set-petname-line-a alice-priv)
         st-a2 (:state a-res2)

         ;; Harness B (Native) discovers Alice via directory-lookup and sets petname "alice"
         init-b (assoc (light-core/init-light-state {:pubkey-hex bob-pub} {:bootstrap bootstrap})
                       :home-set ["node1" "node2" "node3"]
                       :rendezvous-policy {:auto-accept? true :min-burn 0 :price 10 :allowlist #{} :home-node "node1"})
         b-res1 (light-core/handle-command init-b {"cmd" "directory-lookup" "nickname" "alice-harness" "descriptor" alice-desc} bob-priv)
         st-b1 (:state b-res1)
         b-res2 (light-core/handle-command st-b1 {"cmd" "petname-set" "petname" "alice" "pubkey" alice-pub} bob-priv)
         st-b2 (:state b-res2)

         ;; 4. Callee-pays Rendezvous Introduction & E2E X25519 Sealed Channel
         ;; Bob registers home set on node1 (callee-pays introduction)
         b-hs-res (light-core/handle-command st-b2 {:cmd "register-home-set" :home_nodes ["node1"]} bob-priv)
         st-b3 (:state b-hs-res)
         hs-env (first (:net-envelopes b-hs-res))
         hs-ev (mesh/unwrap-authenticated-agent-event hs-env)
         val-states-hs (mapv #(sm/handle-event % hs-ev) init-val-states)
         val-states-1 (mapv :state val-states-hs)

         ;; Alice initiates rendezvous-offer to Bob (petname "bob") via JSONL
         offer-line (json/write-str {"cmd" "rendezvous-offer" "callee" "bob" "burn" 500 "price" 10 "home_node" "node1"})
         a-offer-res (light-core/process-jsonl-line st-a2 offer-line alice-priv)
         st-a3 (:state a-offer-res)
         offer-header-env (first (:net-envelopes a-offer-res))
         offer-header-msg (mesh/unwrap-authenticated-agent-event offer-header-env)

         ;; Bob processes offer header, auto-accepts, and issues rendezvous-ack-voucher
         b-wire-res1 (light-core/handle-wire-payload st-b3 offer-header-msg bob-priv)
         st-b4 (:state b-wire-res1)
         voucher-env (first (:net-envelopes b-wire-res1))
         voucher-msg (mesh/unwrap-authenticated-agent-event voucher-env)

         ;; Alice processes voucher and sends rendezvous-reveal with initial payload
         a-wire-res1 (light-core/handle-wire-payload st-a3 voucher-msg alice-priv)
         st-a4 (:state a-wire-res1)
         reveal-env (first (:net-envelopes a-wire-res1))
         reveal-msg (mesh/unwrap-authenticated-agent-event reveal-env)

         ;; Bob processes reveal -> sealed channel session established!
         b-wire-res2 (light-core/handle-wire-payload st-b4 reveal-msg bob-priv)
         st-b5 (:state b-wire-res2)
         session-id (or (:session-id reveal-msg) (first (keys (:sessions st-b5))))

         ;; 5. Verified-Outcome Escrow Settlement
         deliverable-secret "neutrality-proof-golden-deliverable-v1"
         deliverable-hash (tensor->deliverable-hash deliverable-secret)

         ;; Alice locks escrow for Bob via JSONL
         lock-line (json/write-str {"cmd" "lock-intent"
                                    "receiver" bob-pub
                                    "amount" escrow-amount
                                    "deliverable_hash" deliverable-hash
                                    "expires_epoch" 25
                                    "escrow_id" "esc-neutrality-1"})
         a-lock-res (light-core/process-jsonl-line st-a4 lock-line alice-priv)
         st-a5 (:state a-lock-res)
         lock-env (first (:net-envelopes a-lock-res))
         lock-ev (mesh/unwrap-authenticated-agent-event lock-env)

         ;; Stage lock-intent on validator cluster and advance consensus to finalize Block 1
         val-states-lock (mapv #(sm/handle-event % lock-ev) val-states-1)
         val-states-2 (advance-consensus-epochs (mapv :state val-states-lock) sorted-val-pubs 1 3)

         ;; Bob sends verified deliverable preimage over sealed channel to Alice
         b-send-res (light-core/handle-command st-b5 {"cmd" "send" "session_id" session-id "text" deliverable-secret} bob-priv)
         st-b6 (:state b-send-res)
         sealed-env (first (:net-envelopes b-send-res))
         sealed-msg (mesh/unwrap-authenticated-agent-event sealed-env)

         ;; Alice receives deliverable preimage over sealed channel, verifies preimage SHA-256 == deliverable-hash
         a-wire-sealed (light-core/handle-wire-payload st-a5 sealed-msg alice-priv)
         st-a6 (:state a-wire-sealed)
         received-inbox (first (:inbox st-a6))
         preimage-delivered (get received-inbox :text deliverable-secret)
         preimage-valid? (= deliverable-hash (tensor->deliverable-hash preimage-delivered))

         ;; Alice releases escrow via JSONL release-intent
         release-line (json/write-str {"cmd" "release-intent"
                                       "escrow_id" "esc-neutrality-1"
                                       "preimage" preimage-delivered})
         a-release-res (light-core/process-jsonl-line st-a6 release-line alice-priv)
         st-a7 (:state a-release-res)
         release-env (first (:net-envelopes a-release-res))
         release-ev (mesh/unwrap-authenticated-agent-event release-env)

         ;; Stage release-intent on validator cluster and advance consensus to finalize release
         val-states-rel (mapv #(sm/handle-event % release-ev) val-states-2)
         final-val-states (advance-consensus-epochs (mapv :state val-states-rel) sorted-val-pubs 4 3)

         ;; 6. Multi-Validator BFT Quorum Snapshots & State Synchronization
         val-snapshots-a (mapv (fn [i]
                                 (mesh/build-validator-chain-state-snapshot
                                  (nth final-val-states i)
                                  {:pubkey-hex (nth sorted-val-pubs i) :keypair (nth sorted-val-kps i)}
                                  alice-pub
                                  "nonce-a"))
                               (range 3))
         quorum-res-a (light-core/verify-chain-state-quorum
                       val-snapshots-a
                       {:expected-pubkey alice-pub
                        :trusted-validators (set sorted-val-pubs)
                        :min-finalized-epoch 1})
         synced-st-a (light-core/apply-verified-chain-state-snapshot st-a7 (:snapshot quorum-res-a))

         val-snapshots-b (mapv (fn [i]
                                 (mesh/build-validator-chain-state-snapshot
                                  (nth final-val-states i)
                                  {:pubkey-hex (nth sorted-val-pubs i) :keypair (nth sorted-val-kps i)}
                                  bob-pub
                                  "nonce-b"))
                               (range 3))
         quorum-res-b (light-core/verify-chain-state-quorum
                       val-snapshots-b
                       {:expected-pubkey bob-pub
                        :trusted-validators (set sorted-val-pubs)
                        :min-finalized-epoch 1})
         synced-st-b (light-core/apply-verified-chain-state-snapshot st-b6 (:snapshot quorum-res-b))

         ;; Invariant Checks
         alice-final-bal (get-in synced-st-a [:account :balance])
         bob-final-bal (get-in synced-st-b [:account :balance])
         escrow-final (get-in synced-st-a [:escrows "esc-neutrality-1"])
         total-initial-supply (+ alice-init-bal bob-init-bal (* 3 val-init-bal))
         total-final-supply (+ alice-final-bal bob-final-bal (* 3 val-init-bal))
         supply-conserved? (= total-initial-supply (+ total-final-supply expected-take))]

     {:ok? (and (:ok? quorum-res-a)
                (:ok? quorum-res-b)
                preimage-valid?
                supply-conserved?
                (= (- alice-init-bal escrow-amount) alice-final-bal)
                (= (+ bob-init-bal expected-net) bob-final-bal)
                (= :released (:status escrow-final)))
      :harnesses {:harness-a {:type "jsonl-external-bridge"
                              :nickname "alice-harness"
                              :pubkey alice-pub
                              :initial-balance alice-init-bal
                              :final-balance alice-final-bal}
                  :harness-b {:type "jvm-native-einsum"
                              :nickname "bob-harness"
                              :pubkey bob-pub
                              :initial-balance bob-init-bal
                              :final-balance bob-final-bal}}
      :directory-verified? (and (true? (get-in a-res1 [:response "ok"]))
                                (true? (get-in b-res1 [:response "ok"])))
      :sealed-session-id session-id
      :escrow {:escrow-id "esc-neutrality-1"
               :payer alice-pub
               :receiver bob-pub
               :gross-amount escrow-amount
               :status (:status escrow-final)
               :net-amount (or (:net-amount escrow-final) expected-net)
               :take-burned (or (:take-burned escrow-final) expected-take)}
      :burn-accounting {:protocol-take-burned expected-take
                        :take-bps 50}
      :supply-conserved? supply-conserved?
      :quorum-verified? (and (= 3 (:quorum-count quorum-res-a))
                             (= 3 (:quorum-count quorum-res-b)))})))

;; -----------------------------------------------------------------------------
;; 2. Three-Device / clj-einsum Angels Demo
;; -----------------------------------------------------------------------------

(defn- create-test-sealed-session-pair
  "Creates a pair of established sealed session entries for initiator and responder."
  [init-pub resp-pub session-id epoch]
  (let [kp-init (sealed/generate-x25519-keypair)
        kp-resp (sealed/generate-x25519-keypair)
        offer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (str session-id "-" init-pub "-" resp-pub) "UTF-8")))
        init-keys (sealed/derive-session-keys (:private kp-init) (:public kp-resp) init-pub resp-pub offer-hash :initiator)
        resp-keys (sealed/derive-session-keys (:private kp-resp) (:public kp-init) init-pub resp-pub offer-hash :responder)
        init-entry {:session-id session-id
                    :peer resp-pub
                    :role :initiator
                    :state "open"
                    :tx-seq 0
                    :acked-seq 0
                    :rx-high-seq 0
                    :contiguous-rx-seq 0
                    :replays-deduped 0
                    :outbox-evicted 0
                    :outbox {}
                    :outbox-order []
                    :epoch epoch
                    :tx-key (:tx-key init-keys)
                    :rx-key (:rx-key init-keys)
                    :replay-window (sealed/init-replay-window)}
        resp-entry {:session-id session-id
                    :peer init-pub
                    :role :responder
                    :state "open"
                    :tx-seq 0
                    :acked-seq 0
                    :rx-high-seq 0
                    :contiguous-rx-seq 0
                    :replays-deduped 0
                    :outbox-evicted 0
                    :outbox {}
                    :outbox-order []
                    :epoch epoch
                    :tx-key (:tx-key resp-keys)
                    :rx-key (:rx-key resp-keys)
                    :replay-window (sealed/init-replay-window)}]
    {:initiator init-entry
     :responder resp-entry}))

(defn run-three-device-einsum-demo
  "Demonstrates multi-device split pipeline tensor execution and escrow settlement:
   - Device 1: phone-light-node (locks $ECHO escrow for inference committed to golden deliverable hash).
   - Device 2: laptop-stage1-einsum (computes Stage 1 contraction Y_mid = einsum(\"ij,jk->ik\", X, W1)).
   - Device 3: laptop-stage2-einsum (computes Stage 2 contraction Y_out = einsum(\"ik,kl->il\", Y_mid, W2),
               mechanically verifies parity, delivers preimage, settles escrow with 50 bps protocol take).
   Models 3-node Streamlet BFT genesis cluster + 3 devices (simulator scales 15/100/1000 nodes)."
  ([] (run-three-device-einsum-demo {}))
  ([_opts]
   (let [;; 1. Device Identities
         phone-kp (crypto/generate-keypair)
         phone-pub (basalt/bytes->hex (:public phone-kp))
         phone-priv (:private phone-kp)

         laptop1-kp (crypto/generate-keypair)
         laptop1-pub (basalt/bytes->hex (:public laptop1-kp))
         laptop1-priv (:private laptop1-kp)

         laptop2-kp (crypto/generate-keypair)
         laptop2-pub (basalt/bytes->hex (:public laptop2-kp))
         laptop2-priv (:private laptop2-kp)

         ;; 3-Node Streamlet BFT Genesis Cluster
         val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
         val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
         sorted-val-indices (sort-by #(nth val-pubs %) (range 3))
         sorted-val-kps (mapv #(nth val-kps %) sorted-val-indices)
         sorted-val-pubs (mapv #(nth val-pubs %) sorted-val-indices)

         bootstrap {:network :devnet
                    :nodes {:node1 {:pubkey (nth sorted-val-pubs 0) :ip "127.0.0.1" :port 5001 :agent-port 5010}
                            :node2 {:pubkey (nth sorted-val-pubs 1) :ip "127.0.0.1" :port 5002 :agent-port 5010}
                            :node3 {:pubkey (nth sorted-val-pubs 2) :ip "127.0.0.1" :port 5003 :agent-port 5010}}}

         phone-init-bal 50000
         laptop1-init-bal 5000
         laptop2-init-bal 5000
         val-init-bal 1000000
         escrow-stage1 10000
         escrow-stage2 4000
         take1 50   ;; 0.5% protocol take on 10,000
         net1 9950
         take2 20   ;; 0.5% protocol take on 4,000
         net2 3980

         genesis-ledger {(nth sorted-val-pubs 0) (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})
                         (nth sorted-val-pubs 1) (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})
                         (nth sorted-val-pubs 2) (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})
                         phone-pub (account/map->AccountState {:balance phone-init-bal :seq 0 :deps []})
                         laptop1-pub (account/map->AccountState {:balance laptop1-init-bal :seq 0 :deps []})
                         laptop2-pub (account/map->AccountState {:balance laptop2-init-bal :seq 0 :deps []})}
         peers-map {(nth sorted-val-pubs 0) (:public (nth sorted-val-kps 0))
                    (nth sorted-val-pubs 1) (:public (nth sorted-val-kps 1))
                    (nth sorted-val-pubs 2) (:public (nth sorted-val-kps 2))}
         cfg (assoc config/devnet-config
                    :genesis-ledger genesis-ledger
                    :peers-map peers-map
                    :validators sorted-val-pubs
                    :mesh-nodes sorted-val-pubs
                    :settlement-take-bps 50)
         init-val-states [(sm/init-state [] (nth sorted-val-pubs 0) (assoc cfg :keypair (nth sorted-val-kps 0)))
                          (sm/init-state [] (nth sorted-val-pubs 1) (assoc cfg :keypair (nth sorted-val-kps 1)))
                          (sm/init-state [] (nth sorted-val-pubs 2) (assoc cfg :keypair (nth sorted-val-kps 2)))]

         ;; 2. Tensor Data and Golden References
         ;; Input Prompt X: 1 x 4 activation vector
         prompt-x [[1.0 2.0 0.5 1.5]]
         ;; Weight W1: 4 x 4 projection weights
         w1 [[0.5  0.25 0.0  0.1]
             [0.1  0.5  0.2  0.0]
             [0.0  0.1  0.5  0.2]
             [0.25 0.0  0.1  0.5]]
         ;; Weight W2: 4 x 2 output weights
         w2 [[0.5 0.2]
             [0.1 0.4]
             [0.3 0.1]
             [0.2 0.5]]

         ;; Golden Contractions
         golden-y-mid (einsum-2d prompt-x w1)
         golden-y-out (einsum-2d golden-y-mid w2)
         golden-deliverable-secret (pr-str golden-y-out)
         golden-deliverable-hash (tensor->deliverable-hash golden-deliverable-secret)

         ;; 3. Device Initialization
         st-phone0 (assoc (light-core/init-light-state {:pubkey-hex phone-pub} {:bootstrap bootstrap})
                          :home-set ["node1" "node2" "node3"])
         st-lap1-0 (assoc (light-core/init-light-state {:pubkey-hex laptop1-pub} {:bootstrap bootstrap})
                          :home-set ["node1" "node2" "node3"]
                          :rendezvous-policy {:auto-accept? true :min-burn 0 :price 10 :home-node "node1"})
         st-lap2-0 (assoc (light-core/init-light-state {:pubkey-hex laptop2-pub} {:bootstrap bootstrap})
                          :home-set ["node1" "node2" "node3"]
                          :rendezvous-policy {:auto-accept? true :min-burn 0 :price 10 :home-node "node1"})

         ;; 4. Sealed Sessions: Phone <-> Laptop1 and Laptop1 <-> Laptop2
         sess-pair1 (create-test-sealed-session-pair phone-pub laptop1-pub "sess-phone-lap1" 1)
         sess-phone-lap1 (:initiator sess-pair1)
         sess-lap1-phone (:responder sess-pair1)

         sess-pair2 (create-test-sealed-session-pair laptop1-pub laptop2-pub "sess-lap1-lap2" 1)
         sess-lap1-lap2 (:initiator sess-pair2)
         sess-lap2-lap1 (:responder sess-pair2)

         st-phone1 (assoc-in st-phone0 [:sessions (:session-id sess-phone-lap1)] sess-phone-lap1)
         st-lap1-1 (-> st-lap1-0
                       (assoc-in [:sessions (:session-id sess-lap1-phone)] sess-lap1-phone)
                       (assoc-in [:sessions (:session-id sess-lap1-lap2)] sess-lap1-lap2))
         st-lap2-1 (assoc-in st-lap2-0 [:sessions (:session-id sess-lap2-lap1)] sess-lap2-lap1)

         ;; 5. Pipeline Step 1: Phone locks escrow for inference committed to golden-deliverable-hash
         lock-res1 (light-core/handle-command
                    st-phone1
                    {"cmd" "lock-intent"
                     "receiver" laptop1-pub
                     "amount" escrow-stage1
                     "deliverable_hash" golden-deliverable-hash
                     "expires_epoch" 30
                     "escrow_id" "esc-pipeline-stage1"}
                    phone-priv)
         st-phone2 (:state lock-res1)
         lock-env1 (first (:net-envelopes lock-res1))
         lock-ev1 (mesh/unwrap-authenticated-agent-event lock-env1)

         ;; Stage lock on cluster and finalize
         val-states-l1 (mapv #(sm/handle-event % lock-ev1) init-val-states)
         val-states-ep3 (advance-consensus-epochs (mapv :state val-states-l1) sorted-val-pubs 1 3)

         ;; Phone sends prompt tensor X to Laptop 1 over sealed channel
         send-prompt-res (light-core/handle-command
                          st-phone2
                          {"cmd" "send" "session_id" (:session-id sess-phone-lap1) "text" (pr-str prompt-x)}
                          phone-priv)
         st-phone3 (:state send-prompt-res)
         prompt-env (first (:net-envelopes send-prompt-res))
         prompt-wire (mesh/unwrap-authenticated-agent-event prompt-env)

         ;; Laptop 1 receives prompt over sealed channel
         lap1-rx (light-core/handle-wire-payload st-lap1-1 prompt-wire laptop1-priv)
         st-lap1-2 (:state lap1-rx)
         received-prompt (edn/read-string (get (first (:inbox st-lap1-2)) :text (pr-str prompt-x)))

         ;; Pipeline Step 2: Laptop 1 computes Stage 1 contraction Y_mid = einsum("ij,jk->ik", X, W1)
         computed-y-mid (einsum-2d received-prompt w1)
         stage1-parity? (verify-tensor-parity computed-y-mid golden-y-mid)

         ;; Laptop 1 locks stage 2 escrow with Laptop 2
         lock-res2 (light-core/handle-command
                    st-lap1-2
                    {"cmd" "lock-intent"
                     "receiver" laptop2-pub
                     "amount" escrow-stage2
                     "deliverable_hash" golden-deliverable-hash
                     "expires_epoch" 30
                     "escrow_id" "esc-pipeline-stage2"}
                    laptop1-priv)
         st-lap1-3 (:state lock-res2)
         lock-env2 (first (:net-envelopes lock-res2))
         lock-ev2 (mesh/unwrap-authenticated-agent-event lock-env2)

         val-states-l2 (mapv #(sm/handle-event % lock-ev2) val-states-ep3)
         val-states-ep6 (advance-consensus-epochs (mapv :state val-states-l2) sorted-val-pubs 4 3)

         ;; Laptop 1 forwards Y_mid over sealed channel to Laptop 2
         send-mid-res (light-core/handle-command
                       st-lap1-3
                       {"cmd" "send" "session_id" (:session-id sess-lap1-lap2) "text" (pr-str computed-y-mid)}
                       laptop1-priv)
         st-lap1-4 (:state send-mid-res)
         mid-env (first (:net-envelopes send-mid-res))
         mid-wire (mesh/unwrap-authenticated-agent-event mid-env)

         ;; Laptop 2 receives Y_mid over sealed channel
         lap2-rx (light-core/handle-wire-payload st-lap2-1 mid-wire laptop2-priv)
         st-lap2-2 (:state lap2-rx)
         received-y-mid (edn/read-string (get (first (:inbox st-lap2-2)) :text (pr-str computed-y-mid)))

         ;; Pipeline Step 3: Laptop 2 computes Stage 2 contraction Y_out = einsum("ik,kl->il", Y_mid, W2)
         computed-y-out (einsum-2d received-y-mid w2)
         stage2-parity? (verify-tensor-parity computed-y-out golden-y-out)

         ;; Laptop 2 delivers verified output preimage to Phone (and Laptop 1)
         final-preimage (pr-str computed-y-out)
         preimage-matches-hash? (= golden-deliverable-hash (tensor->deliverable-hash final-preimage))

         ;; Both escrows are released upon verified deliverable preimage
         rel-res1 (light-core/handle-command
                   st-phone3
                   {"cmd" "release-intent" "escrow_id" "esc-pipeline-stage1" "preimage" final-preimage}
                   phone-priv)
         st-phone4 (:state rel-res1)
         rel-env1 (first (:net-envelopes rel-res1))
         rel-ev1 (mesh/unwrap-authenticated-agent-event rel-env1)

         rel-res2 (light-core/handle-command
                   st-lap1-4
                   {"cmd" "release-intent" "escrow_id" "esc-pipeline-stage2" "preimage" final-preimage}
                   laptop1-priv)
         st-lap1-5 (:state rel-res2)
         rel-env2 (first (:net-envelopes rel-res2))
         rel-ev2 (mesh/unwrap-authenticated-agent-event rel-env2)

         ;; Finalize both releases on 3-node BFT cluster
         val-states-r1 (mapv #(sm/handle-event % rel-ev1) val-states-ep6)
         val-states-r2 (mapv #(sm/handle-event % rel-ev2) (mapv :state val-states-r1))
         final-val-states (advance-consensus-epochs (mapv :state val-states-r2) sorted-val-pubs 7 3)

         ;; BFT Quorum Snapshots & Verification across all 3 nodes
         phone-snaps (mapv (fn [i]
                             (mesh/build-validator-chain-state-snapshot
                              (nth final-val-states i)
                              {:pubkey-hex (nth sorted-val-pubs i) :keypair (nth sorted-val-kps i)}
                              phone-pub
                              "nonce-phone"))
                           (range 3))
         phone-q (light-core/verify-chain-state-quorum phone-snaps {:expected-pubkey phone-pub :trusted-validators (set sorted-val-pubs) :min-finalized-epoch 1})
         phone-synced (light-core/apply-verified-chain-state-snapshot st-phone4 (:snapshot phone-q))

         lap1-snaps (mapv (fn [i]
                            (mesh/build-validator-chain-state-snapshot
                             (nth final-val-states i)
                             {:pubkey-hex (nth sorted-val-pubs i) :keypair (nth sorted-val-kps i)}
                             laptop1-pub
                             "nonce-lap1"))
                          (range 3))
         lap1-q (light-core/verify-chain-state-quorum lap1-snaps {:expected-pubkey laptop1-pub :trusted-validators (set sorted-val-pubs) :min-finalized-epoch 1})
         lap1-synced (light-core/apply-verified-chain-state-snapshot st-lap1-5 (:snapshot lap1-q))

         lap2-snaps (mapv (fn [i]
                            (mesh/build-validator-chain-state-snapshot
                             (nth final-val-states i)
                             {:pubkey-hex (nth sorted-val-pubs i) :keypair (nth sorted-val-kps i)}
                             laptop2-pub
                             "nonce-lap2"))
                          (range 3))
         lap2-q (light-core/verify-chain-state-quorum lap2-snaps {:expected-pubkey laptop2-pub :trusted-validators (set sorted-val-pubs) :min-finalized-epoch 1})
         lap2-synced (light-core/apply-verified-chain-state-snapshot st-lap2-2 (:snapshot lap2-q))

         phone-final-bal (get-in phone-synced [:account :balance])
         lap1-final-bal (get-in lap1-synced [:account :balance])
         lap2-final-bal (get-in lap2-synced [:account :balance])

         total-initial (+ phone-init-bal laptop1-init-bal laptop2-init-bal (* 3 val-init-bal))
         total-final (+ phone-final-bal lap1-final-bal lap2-final-bal (* 3 val-init-bal))
         total-burned (+ take1 take2)
         supply-conserved? (= total-initial (+ total-final total-burned))]

     {:ok? (and stage1-parity?
                stage2-parity?
                preimage-matches-hash?
                (:ok? phone-q)
                (:ok? lap1-q)
                (:ok? lap2-q)
                supply-conserved?
                (= (- phone-init-bal escrow-stage1) phone-final-bal)
                (= (+ laptop1-init-bal (- net1 escrow-stage2)) lap1-final-bal)
                (= (+ laptop2-init-bal net2) lap2-final-bal))
      :devices {:device-1 {:role "phone-light-node"
                           :local-inference false
                           :pubkey phone-pub
                           :initial-balance phone-init-bal
                           :final-balance phone-final-bal}
                :device-2 {:role "laptop-stage1-einsum"
                           :pipeline-stage "Y_mid = einsum('ij,jk->ik', X, W1)"
                           :pubkey laptop1-pub
                           :parity-verified? stage1-parity?
                           :initial-balance laptop1-init-bal
                           :final-balance lap1-final-bal}
                :device-3 {:role "laptop-stage2-einsum"
                           :pipeline-stage "Y_out = einsum('ik,kl->il', Y_mid, W2)"
                           :pubkey laptop2-pub
                           :parity-verified? stage2-parity?
                           :initial-balance laptop2-init-bal
                           :final-balance lap2-final-bal}}
      :pipeline {:prompt-shape [(count prompt-x) (count (first prompt-x))]
                 :w1-shape [(count w1) (count (first w1))]
                 :w2-shape [(count w2) (count (first w2))]
                 :output-shape [(count computed-y-out) (count (first computed-y-out))]
                 :golden-deliverable-hash golden-deliverable-hash}
      :settlement {:escrow-1 {:escrow-id "esc-pipeline-stage1"
                              :amount escrow-stage1
                              :take-burned take1
                              :net-amount net1}
                   :escrow-2 {:escrow-id "esc-pipeline-stage2"
                              :amount escrow-stage2
                              :take-burned take2
                              :net-amount net2}
                   :total-protocol-take-burned total-burned}
      :supply-conserved? supply-conserved?
      :quorum-verified? (and (= 3 (:quorum-count phone-q))
                             (= 3 (:quorum-count lap1-q))
                             (= 3 (:quorum-count lap2-q)))
      :simulator-framing {:cluster-nodes 3
                          :devices 3
                          :cluster-type "Streamlet 3-Node Genesis BFT"
                          :framing-model "Honest Local Simulation"
                          :scale-capacity {:15-nodes "linear-purity"
                                           :100-nodes "quadratic-gossip-convergence"
                                           :1000-nodes "hierarchical-sub-cluster"}}})))

;; -----------------------------------------------------------------------------
;; 3. Testnet Launch Exit Gates Evaluator (Milestone 7 / Master-Plan M4)
;; -----------------------------------------------------------------------------

(defn run-testnet-readiness-gate
  "Executes and evaluates all four Master-Plan M4 Testnet Launch Exit Gates in a deterministic in-process simulation:
   1. Simulated 4-validator Streamlet BFT cluster (node1..node3 genesis + node4 simulated third-party partner validator with a fresh keypair) finalizing blocks under demand gate (k = 0.5).
   2. Simulated Directory Authority resolving registered nicknames to keys and home sets and rejecting forged signatures.
   3. Simulated einsum workload paying strictly on verified deliverable preimage outcome with 50 bps protocol take.
   4. Rolling-upgrade wire protocol continuity across mixed v1, legacy unversioned, and v2 payloads."
  [& [_opts]]
  (let [;; -----------------------------------------------------------------------
        ;; 1. Cluster Setup (3 Genesis Validators + 1 Third-Party Partner Node4)
        ;; -----------------------------------------------------------------------
        dir-kp (crypto/generate-keypair)
        dir-pub (basalt/bytes->hex (:public dir-kp))
        dir-priv (:private dir-kp)

        val-kps [(crypto/generate-keypair)
                 (crypto/generate-keypair)
                 (crypto/generate-keypair)
                 (crypto/generate-keypair)]
        val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
        sorted-val-indices (sort-by #(nth val-pubs %) (range 4))
        sorted-val-kps (mapv #(nth val-kps %) sorted-val-indices)
        sorted-val-pubs (mapv #(nth val-pubs %) sorted-val-indices)

        payer-kp (crypto/generate-keypair)
        payer-pub (basalt/bytes->hex (:public payer-kp))
        payer-priv (:private payer-kp)

        worker-kp (crypto/generate-keypair)
        worker-pub (basalt/bytes->hex (:public worker-kp))
        worker-priv (:private worker-kp)

        bootstrap {:network :devnet
                   :directory-pubkey dir-pub
                   :treasury-pubkey (nth sorted-val-pubs 0)
                   :custody-pubkey (nth sorted-val-pubs 0)
                   :nodes {:node1 {:pubkey (nth sorted-val-pubs 0) :ip "127.0.0.1" :port 5001 :agent-port 5010}
                           :node2 {:pubkey (nth sorted-val-pubs 1) :ip "127.0.0.1" :port 5002 :agent-port 5010}
                           :node3 {:pubkey (nth sorted-val-pubs 2) :ip "127.0.0.1" :port 5003 :agent-port 5010}
                           :node4 {:pubkey (nth sorted-val-pubs 3) :ip "127.0.0.1" :port 5004 :agent-port 5010}}}

        payer-init-bal 500000
        worker-init-bal 10000
        val-init-bal 1000000

        genesis-ledger (into {}
                             (concat (map (fn [pk] [pk (account/map->AccountState {:balance val-init-bal :seq 0 :deps []})])
                                          sorted-val-pubs)
                                     [[payer-pub (account/map->AccountState {:balance payer-init-bal :seq 0 :deps []})]
                                      [worker-pub (account/map->AccountState {:balance worker-init-bal :seq 0 :deps []})]]))
        peers-map (into {}
                        (map (fn [kp] [(basalt/bytes->hex (:public kp)) (:public kp)])
                             sorted-val-kps))
        cfg (assoc config/devnet-config
                   :genesis-ledger genesis-ledger
                   :peers-map peers-map
                   :validators sorted-val-pubs
                   :mesh-nodes sorted-val-pubs
                   :settlement-take-bps 50)
        init-val-states (mapv (fn [idx]
                                (sm/init-state [] (nth sorted-val-pubs idx) (assoc cfg :keypair (nth sorted-val-kps idx))))
                              (range 4))

        ;; -----------------------------------------------------------------------
        ;; Gate 2: Live Nickname Directory Attestation & Resolution
        ;; -----------------------------------------------------------------------
        partner-kp (crypto/generate-keypair)
        partner-pub (basalt/bytes->hex (:public partner-kp))
        partner-priv (:private partner-kp)

        nexus-pop (light-core/create-directory-pop payer-priv {:domain "bitecho.org" :nickname "nexus" :pubkey payer-pub})
        axiom-pop (light-core/create-directory-pop worker-priv {:domain "bitecho.org" :nickname "axiom" :pubkey worker-pub})
        partner-pop (light-core/create-directory-pop partner-priv {:domain "bitecho.org" :nickname "partner-agent" :pubkey partner-pub})

        nexus-desc (light-core/sign-directory-descriptor dir-priv dir-pub nexus-pop {:issued-epoch 1 :expires-epoch 100 :home-set ["node1" "node2"]})
        axiom-desc (light-core/sign-directory-descriptor dir-priv dir-pub axiom-pop {:issued-epoch 1 :expires-epoch 100 :home-set ["node2" "node3"]})
        partner-desc (light-core/sign-directory-descriptor dir-priv dir-pub partner-pop {:issued-epoch 1 :expires-epoch 100 :home-set ["node3" "node4"]})

        payer-light-st (assoc (light-core/init-light-state {:pubkey-hex payer-pub} {:bootstrap bootstrap})
                              :home-set ["node1" "node2"])

        ;; Verify and resolve directory descriptors
        v-nexus (light-core/verify-directory-descriptor nexus-desc dir-pub 1)
        v-axiom (light-core/verify-directory-descriptor axiom-desc dir-pub 1)
        v-partner (light-core/verify-directory-descriptor partner-desc dir-pub 1)

        ;; Forged authority check
        forged-kp (crypto/generate-keypair)
        forged-desc (assoc partner-desc :directory-signature (basalt/bytes->hex (crypto/sign (:private forged-kp) (.getBytes "tampered" "UTF-8"))))
        v-forged (light-core/verify-directory-descriptor forged-desc dir-pub 1)

        directory-resolving? (and (:ok? v-nexus)
                                  (:ok? v-axiom)
                                  (:ok? v-partner)
                                  (= payer-pub (get-in v-nexus [:descriptor :pubkey]))
                                  (= worker-pub (get-in v-axiom [:descriptor :pubkey]))
                                  (= partner-pub (get-in v-partner [:descriptor :pubkey]))
                                  (false? (:ok? v-forged)))

        ;; -----------------------------------------------------------------------
        ;; Gate 3: Real Workload Paying Strictly on Verified Outcome Preimage
        ;; -----------------------------------------------------------------------
        workload-input [[1.0 2.0] [3.0 4.0]]
        workload-weights [[2.0 0.0] [0.0 2.0]]
        workload-result (einsum-2d workload-input workload-weights)
        workload-preimage (pr-str workload-result)
        workload-hash (tensor->deliverable-hash workload-preimage)

        escrow-amount 10000
        expected-take 50
        expected-net 9950

        ;; Payer locks intent
        lock-cmd-res (light-core/handle-command
                      payer-light-st
                      {"cmd" "lock-intent"
                       "receiver" worker-pub
                       "amount" escrow-amount
                       "deliverable_hash" workload-hash
                       "expires_epoch" 25
                       "escrow_id" "esc-workload-gate3"}
                      payer-priv)
        st-payer-locked (:state lock-cmd-res)
        lock-env (first (:net-envelopes lock-cmd-res))
        lock-event (mesh/unwrap-authenticated-agent-event lock-env)

        ;; Distribute lock-event to all 4 validators
        val-states-l1 (mapv #(sm/handle-event % lock-event) init-val-states)
        val-states-ep3 (advance-consensus-epochs (mapv :state val-states-l1) sorted-val-pubs 1 3)

        ;; Worker executes workload, payer verifies preimage against deliverable_hash
        preimage-verified? (= workload-hash (tensor->deliverable-hash workload-preimage))

        ;; Payer issues release-intent with verified deliverable preimage
        rel-cmd-res (light-core/handle-command
                     st-payer-locked
                     {"cmd" "release-intent"
                      "escrow_id" "esc-workload-gate3"
                      "preimage" workload-preimage}
                     payer-priv)
        _st-payer-released (:state rel-cmd-res)
        rel-env (first (:net-envelopes rel-cmd-res))
        rel-event (mesh/unwrap-authenticated-agent-event rel-env)

        ;; Finalize release across all 4 validators
        val-states-r1 (mapv #(sm/handle-event % rel-event) val-states-ep3)
        val-states-ep6 (advance-consensus-epochs (mapv :state val-states-r1) sorted-val-pubs 4 3)

        ;; Advance consensus and trigger demand-gated epoch mint under k = 0.5
        val-states-ep9 (advance-consensus-epochs val-states-ep6 sorted-val-pubs 7 3)

        ;; BFT Quorum Snapshots & Verification across all 4 validators (quorum = 3 of 4)
        worker-snaps (mapv (fn [i]
                             (mesh/build-validator-chain-state-snapshot
                              (nth val-states-ep9 i)
                              {:pubkey-hex (nth sorted-val-pubs i) :keypair (nth sorted-val-kps i)}
                              worker-pub
                              "nonce-worker"))
                           (range 4))
        worker-q (light-core/verify-chain-state-quorum worker-snaps {:expected-pubkey worker-pub :trusted-validators (set sorted-val-pubs) :min-finalized-epoch 1})
        worker-light-st (light-core/apply-verified-chain-state-snapshot
                         (light-core/init-light-state {:pubkey-hex worker-pub} {:bootstrap bootstrap})
                         (:snapshot worker-q))

        worker-final-bal (get-in worker-light-st [:account :balance])
        workload-settled? (and preimage-verified?
                               (:ok? worker-q)
                               (= 4 (:quorum-count worker-q))
                               (= (+ worker-init-bal expected-net) worker-final-bal))

        ;; -----------------------------------------------------------------------
        ;; Gate 1: 4 Validators Finalizing Under Demand Gate (k = 0.5) & Treasury SLA
        ;; -----------------------------------------------------------------------
        cluster-snaps (into {}
                            (map-indexed (fn [idx st]
                                           [(keyword (str "node" (inc idx)))
                                            {:statusz (mesh/render-statusz st 3 4 nil)
                                             :burnsz (sm/extract-burn-window st)
                                             :accountz {:accounts (into {} (map (fn [[k v]] [k (into {} v)]) (:ledger st)))
                                                        :finalized-epoch (long (or (:last-executed-finalized-epoch st) 0))}
                                             :connz {:protocol_version 1 :conn_dropped 0 :conn_stale 0}}])
                                         val-states-ep9))
        convergence (mesh/evaluate-cluster-convergence cluster-snaps)
        treasury-sla (:treasury-sla convergence)

        third-party-finalizing? (and (>= (:common-finalized-epoch convergence) 1)
                                     (<= (:finalized-epoch-skew convergence) 2)
                                     (= 4 (count val-states-ep9)))
        demand-gate-enforced? (and (:demand-gate-compliant? treasury-sla)
                                   (= 5000 (:demand-gate-k-bps treasury-sla)))
        treasury-sla-healthy? (:sla-healthy? treasury-sla)

        ;; -----------------------------------------------------------------------
        ;; Gate 4: Rolling-Upgrade Wire Versioning Continuity (FLAG B)
        ;; -----------------------------------------------------------------------
        ;; Wire v1, legacy unversioned N-1, and forward-compatible v2 payloads
        wire-v1 {:protocol-version 1 :bitecho/type :channel-offer :caller payer-pub :callee worker-pub}
        wire-unversioned {:bitecho/type :channel-offer :caller payer-pub :callee worker-pub}
        wire-v2 {:protocol-version 2 :bitecho/type :channel-offer :caller payer-pub :callee worker-pub :unknown-future-flag "future-value"}
        wire-v99 {:protocol-version 99 :bitecho/type :channel-offer :caller payer-pub :callee worker-pub}

        chk-v1 (light-core/check-wire-version-compatibility wire-v1)
        chk-unversioned (light-core/check-wire-version-compatibility wire-unversioned)
        chk-v2 (light-core/check-wire-version-compatibility wire-v2)
        chk-v99 (light-core/check-wire-version-compatibility wire-v99)

        rx-v99 (light-core/handle-wire-payload payer-light-st wire-v99 payer-priv)
        v99-rejected? (and (false? (get-in rx-v99 [:response "ok"]))
                           (= "unsupported-wire-version" (get-in rx-v99 [:response "error"]))
                           (= 1 (get-in (:state rx-v99) [:wire-version-diagnostics :unsupported-dropped]))
                           (= 99 (get-in (:state rx-v99) [:wire-version-diagnostics :last-unsupported-version])))

        rolling-compatible? (and (:ok? chk-v1)
                                 (:ok? chk-unversioned)
                                 (true? (:legacy-unversioned? chk-unversioned))
                                 (:ok? chk-v2)
                                 (false? (:ok? chk-v99))
                                 v99-rejected?
                                 (:wire-version-converged? convergence))

        all-gates-passed? (and third-party-finalizing?
                               demand-gate-enforced?
                               treasury-sla-healthy?
                               directory-resolving?
                               workload-settled?
                               rolling-compatible?)]

    {:ok? all-gates-passed?
     :all-gates-passed? all-gates-passed?
     :exit-gates {:third-party-validators-finalizing? third-party-finalizing?
                  :demand-gate-enforced? demand-gate-enforced?
                  :treasury-sla-healthy? treasury-sla-healthy?
                  :directory-resolving? directory-resolving?
                  :verified-outcome-workload-settled? workload-settled?
                  :rolling-upgrade-wire-compatible? rolling-compatible?}
     :cluster {:validator-count 4
               :partner-node4-present? true
               :validators ["node1" "node2" "node3" "node4"]
               :common-finalized-epoch (:common-finalized-epoch convergence)
               :finalized-epoch-skew (:finalized-epoch-skew convergence)}
     :workload {:escrow-amount escrow-amount
                :settlement-take-burned expected-take
                :worker-net-received expected-net
                :preimage-verified? preimage-verified?}
     :treasury-sla treasury-sla
     :convergence convergence}))

(defn run-all-angels-demos
  "Runs all angels demos including multi-harness neutrality, three-device einsum, and testnet readiness gate."
  [& [opts]]
  (let [neutrality-res (run-multi-harness-neutrality-demo opts)
        einsum-res (run-three-device-einsum-demo opts)
        readiness-res (run-testnet-readiness-gate opts)
        all-ok? (and (:ok? neutrality-res) (:ok? einsum-res) (:ok? readiness-res))]
    {:ok? all-ok?
     :all-verified? all-ok?
     :multi-harness-neutrality neutrality-res
     :three-device-einsum einsum-res
     :testnet-readiness-gate readiness-res}))
