(ns bitecho.d28-autosync-and-p2p-ack-hotfix-test
  "Milestone D28 (v0.23.6) Scenario & Generative Verification Suite.
   Validates:
   - F-D28-1: Preserve on-chain :reconfigure-membership validator set across restarts in mesh.clj
   - F-D28-2: :expired-gossip-ids tombstone set preventing zombie gossip resurrection across lagging peers
   - F-D28-3: Lock-free @(:state-atom shell-node) for :query-chain-state & fail-closed on empty state
   - F-D28-4: Direct-leg :session-ack routing, fallback outbox re-wrapping, & relay watermark reset."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.mesh :as mesh]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.api :as api]))

;; -----------------------------------------------------------------------------
;; Test Helpers
;; -----------------------------------------------------------------------------

(defn- test-keypair []
  (crypto/generate-keypair))

(defn- kp->pk-hex [kp]
  (basalt/bytes->hex (or (:public kp) (:public-key kp))))

(defn- kp->sk [kp]
  (or (:private kp) (:private-key kp)))

;; -----------------------------------------------------------------------------
;; 1. F-D28-1: Preserve Dynamic Validator Set Across Restarts
;; -----------------------------------------------------------------------------

(deftest test-f-d28-1-preserve-dynamic-validators-across-restarts
  (testing "rebind-restored-state and build-initial-node-state preserve 6-validator on-chain set when config.edn only lists 3 validators"
    (let [kps (vec (repeatedly 6 test-keypair))
          pks (vec (sort (map kp->pk-hex kps)))
          three-pks (vec (take 3 pks))
          all-six-mesh (into {} (map (fn [pk] [pk 1.0]) pks))
          loaded-state {:epoch 500
                        :validators pks
                        :mesh-nodes all-six-mesh
                        :pending-receipts [{:receipt-id "r-already-done" :type :burn :amount 100}
                                           {:receipt-id "r-still-pending" :type :burn :amount 100}]
                        :executed-receipt-ids #{"r-already-done"}
                        :config {:validators pks
                                 :mesh-nodes all-six-mesh}}
          static-cfg {:node/id :node-1
                      :cluster {:validators three-pks
                                :nodes {:node-1 {:pubkey (nth three-pks 0) :ip "127.0.0.1" :port 5000}
                                        :node-2 {:pubkey (nth three-pks 1) :ip "127.0.0.1" :port 5001}
                                        :node-3 {:pubkey (nth three-pks 2) :ip "127.0.0.1" :port 5002}}}}
          id-map {:node-id :node-1
                  :pubkey-hex (first three-pks)
                  :keypair (first kps)}
          rebound (mesh/rebind-restored-state loaded-state static-cfg id-map)
          via-build (mesh/build-initial-node-state static-cfg id-map loaded-state)]
      (is (= pks (:validators rebound)))
      (is (= pks (get-in rebound [:config :validators])))
      (is (= 6 (count (:mesh-nodes rebound))))
      (is (= 6 (count (get-in rebound [:config :mesh-nodes]))))
      (is (= [{:receipt-id "r-still-pending" :type :burn :amount 100}]
             (:pending-receipts rebound)))
      (is (= pks (:validators via-build)))
      (is (= pks (get-in via-build [:config :validators])))

      (testing "When [:cluster :force-config-validators? true] is set, static config validators take precedence"
        (let [forced-cfg (assoc-in static-cfg [:cluster :force-config-validators?] true)
              forced-rebound (mesh/rebind-restored-state loaded-state forced-cfg id-map)]
          (is (= three-pks (:validators forced-rebound)))
          (is (= three-pks (get-in forced-rebound [:config :validators]))))))))

;; -----------------------------------------------------------------------------
;; 2. F-D28-2: Zombie Gossip Never Resurrects (:expired-gossip-ids Tombstone)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Generative property (F-D28-2): Across offset validator ticks (Node A at E+9, Node B at E+10 with gossip-ttl-epochs=10), expired gossip IDs in :expired-gossip-ids are bounded by max-tracked-receipts and never re-pulled or re-accepted."}
  prop-zombie-gossip-never-resurrects
  25
  (prop/for-all [msg-count (gen/choose 2 6)
                 max-tracked (gen/choose 3 10)]
                (let [sender-kp (test-keypair)
                      sender-pk (kp->pk-hex sender-kp)
                      node-a-kp (test-keypair)
                      node-b-kp (test-keypair)
                      node-a-pk (kp->pk-hex node-a-kp)
                      node-b-pk (kp->pk-hex node-b-kp)
                      cfg (assoc config/default-config
                                 :gossip-ttl-epochs 10
                                 :max-tracked-receipts max-tracked
                                 :genesis-ledger {sender-pk (account/map->AccountState {:balance 100000 :seq 0 :deps []})})
                      st-a0 (assoc (sm/init-state [] node-a-pk cfg) :epoch 0)
                      st-b0 (assoc (sm/init-state [] node-b-pk cfg) :epoch 0)
                      msgs (mapv (fn [i]
                                   (let [bs (.getBytes (str "zombie-prop-msg-" i) "UTF-8")
                                         mid (basalt/bytes->hex (crypto/sha256 bs))]
                                     {:id mid
                                      :sieve (sieve/wrap-message bs (kp->sk sender-kp) (:public sender-kp) 100)}))
                                 (range msg-count))
                      ;; Both nodes receive all messages at epoch 0
                      st-a1 (reduce (fn [s m] (:state (sm/handle-event s {:type :receive-gossip :message (:sieve m)})))
                                    st-a0 msgs)
                      st-b1 (reduce (fn [s m] (:state (sm/handle-event s {:type :receive-gossip :message (:sieve m)})))
                                    st-b0 msgs)
                      ;; Node A ticks 9 times (epoch 9, messages NOT yet expired)
                      st-a9 (reduce (fn [s _] (:state (sm/handle-event s {:type :tick}))) st-a1 (range 9))
                      ;; Node B ticks 11 times (epoch 11 > cutoff 1, messages expired into :expired-gossip-ids)
                      st-b11 (reduce (fn [s _] (:state (sm/handle-event s {:type :tick}))) st-b1 (range 11))
                      ;; Kept tombstone IDs (bounded by max-tracked)
                      kept-expired (into #{} (filter (:contagion-known-ids st-a9)) (:expired-gossip-ids st-b11))
                      ;; Node A (at epoch 9) advertises kept-expired in :receive-summary to Node B (at epoch 11)
                      sum-res (sm/handle-event st-b11 {:type :receive-summary :sender node-a-pk :summary kept-expired})
                      pull-cmds (filter #(= :send-pull-request (:type %)) (:commands sum-res))
                      ;; Even if Node A pushes a kept-expired gossip message directly to Node B:
                      sample-expired-msg (first (filter #(contains? kept-expired (:id %)) msgs))
                      gos-res (sm/handle-event st-b11 {:type :receive-gossip :message (:sieve sample-expired-msg)})
                      st-b11-after (:state gos-res)]
                  (and (<= (count (:expired-gossip-ids st-b11)) max-tracked)
                       (<= (count (:expired-gossip-order st-b11)) max-tracked)
                       (= (count (:expired-gossip-ids st-b11)) (count (:expired-gossip-order st-b11)))
                       (empty? (:messages st-b11))
                       (empty? (:contagion-known-ids st-b11))
                       (empty? pull-cmds)
                       (empty? (:commands gos-res))
                       (not (contains? (:messages st-b11-after) (:id sample-expired-msg)))
                       (not (contains? (:contagion-known-ids st-b11-after) (:id sample-expired-msg)))
                       (= 1 (get-in st-b11-after [:diagnostics :expired-gossip-dropped]))))))

(deftest test-f-d28-2-three-node-lagging-peer-zombie-gossip-e2e
  (testing "3-node, 14-epoch in-memory E2E scenario with 1-epoch lagging peer (node3): epoch 0..2 gossip expires and never resurrects, and validator chain-state snapshot remains non-empty and valid"
    (let [kps (vec (repeatedly 3 test-keypair))
          pubs (vec (sort (map kp->pk-hex kps)))
          kp-by-pub (into {} (map (fn [kp] [(kp->pk-hex kp) kp]) kps))
          peers-map (into {} (map (fn [pk] [pk (:public (get kp-by-pub pk))]) pubs))
          sender-kp (test-keypair)
          sender-pk (kp->pk-hex sender-kp)
          cfg (assoc config/default-config
                     :gossip-ttl-epochs 10
                     :validators pubs
                     :peers-map peers-map
                     :genesis-ledger {sender-pk (account/map->AccountState {:balance 50000 :seq 0 :deps []})
                                      (nth pubs 0) (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      (nth pubs 1) (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      (nth pubs 2) (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
          make-node (fn [idx]
                      (let [pk (nth pubs idx)
                            kp (get kp-by-pub pk)
                            other-peers (mapv (fn [opk]
                                                (basalt/make-peer "127.0.0.1" 8000 (:public (get kp-by-pub opk))))
                                              (remove #(= % pk) pubs))]
                        (-> (sm/init-state other-peers pk (assoc cfg :keypair kp))
                            (assoc :epoch 0
                                   :validators pubs
                                   :peers-map peers-map
                                   :node-pubkey pk
                                   :node-private-key (kp->sk kp)
                                   :keypair kp))))
          init-nodes [(make-node 0) (make-node 1) (make-node 2)]
          ;; Create 3 signed gossip messages injected at epochs 0, 1, 2
          epoch-msgs (mapv (fn [ep]
                             (let [bs (.getBytes (str "e2e-zombie-msg-ep-" ep) "UTF-8")
                                   mid (basalt/bytes->hex (crypto/sha256 bs))]
                               {:epoch ep
                                :id mid
                                :sieve (sieve/wrap-message bs (kp->sk sender-kp) (:public sender-kp) 100)}))
                           (range 3))
          exchange-contagion-step
          (fn [nodes]
            ;; Every node advertises its current :contagion-known-ids to every other node;
            ;; if a peer emits :send-pull-request, the sender responds via :receive-pull-request -> :receive-gossip
            (reduce
             (fn [curr-nodes [src-idx dst-idx]]
               (let [src-st (nth curr-nodes src-idx)
                     dst-st (nth curr-nodes dst-idx)
                     summary (or (:contagion-known-ids src-st) #{})
                     sum-res (sm/handle-event dst-st {:type :receive-summary
                                                      :sender (:node-pubkey src-st)
                                                      :summary summary})
                     pull-cmds (filter #(= :send-pull-request (:type %)) (:commands sum-res))
                     dst-st' (reduce
                              (fn [d-st pcmd]
                                (let [pr-res (sm/handle-event src-st {:type :receive-pull-request
                                                                      :sender (:node-pubkey d-st)
                                                                      :missing-ids (:missing-ids pcmd)})
                                      gossip-cmds (filter #(= :send-gossip (:type %)) (:commands pr-res))]
                                  (reduce (fn [d2 gcmd]
                                            (:state (sm/handle-event d2 {:type :receive-gossip
                                                                         :sender (:node-pubkey src-st)
                                                                         :message (:message gcmd)})))
                                          d-st
                                          gossip-cmds)))
                              (:state sum-res)
                              pull-cmds)]
                 (assoc curr-nodes dst-idx dst-st')))
             nodes
             [[0 1] [1 0] [2 0] [2 1] [0 2] [1 2]]))
          ;; Run epochs 0..14 where node0 & node1 advance at step `ep`, while node2 lags 1 epoch behind
          final-nodes
          (reduce
           (fn [[n0 n1 n2] ep]
             (let [;; Inject gossip message at epochs 0..2 into all 3 nodes
                   [n0a n1a n2a] (if (< ep 3)
                                   (let [m (:sieve (nth epoch-msgs ep))]
                                     [(:state (sm/handle-event n0 {:type :receive-gossip :message m}))
                                      (:state (sm/handle-event n1 {:type :receive-gossip :message m}))
                                      (:state (sm/handle-event n2 {:type :receive-gossip :message m}))])
                                   [n0 n1 n2])
                   ;; Tick node0 and node1 first (so node2 is 1 epoch behind during anti-entropy!)
                   n0-ticked (:state (sm/handle-event n0a {:type :tick}))
                   n1-ticked (:state (sm/handle-event n1a {:type :tick}))
                   ;; Exchange Contagion summaries while node2 lags 1 epoch behind node0 & node1!
                   [n0-ex n1-ex n2-ex] (exchange-contagion-step [n0-ticked n1-ticked n2a])
                   ;; Now tick node2 (when ep >= 1) and exchange Contagion summaries again
                   n2-ticked (if (>= ep 1)
                               (:state (sm/handle-event n2-ex {:type :tick}))
                               n2-ex)]
               (exchange-contagion-step [n0-ex n1-ex n2-ticked])))
           init-nodes
           (range 15))
          ;; Tick node2 one final time so all 3 nodes are past epoch 14
          final-nodes' (update final-nodes 2 #(:state (sm/handle-event % {:type :tick})))]
      (doseq [[idx st] (map-indexed vector final-nodes')]
        (is (> (:epoch st) 13) (str "Node " idx " should have advanced past epoch 13"))
        (is (empty? (:messages st)) (str "Node " idx " should have 0 active messages after TTL expiry"))
        (is (empty? (:contagion-known-ids st)) (str "Node " idx " should have 0 contagion-known-ids after TTL expiry"))
        (doseq [m epoch-msgs]
          (is (contains? (:expired-gossip-ids st) (:id m))
              (str "Node " idx " must retain expired tombstone for " (:id m)))))
      ;; Verify validator chain-state snapshot from node0 is non-empty and validly signed
      (let [st0 (assoc (first final-nodes') :last-executed-finalized-epoch 14)
            v-id {:pubkey-hex (nth pubs 0)
                  :keypair (get kp-by-pub (nth pubs 0))}
            snap (mesh/build-validator-chain-state-snapshot st0 v-id sender-pk "nonce-e2e-14")]
        (is (map? snap))
        (is (= 14 (:finalized-epoch snap)))
        (is (pos? (:balance snap)))
        (is (string? (:signature snap)))))))

;; -----------------------------------------------------------------------------
;; 3. F-D28-3: Lock-Free :query-chain-state & Fail-Closed on Empty State
;; -----------------------------------------------------------------------------

(deftest test-f-d28-3-lock-free-query-chain-state-and-no-empty-signing
  (testing "make-agent-connection-handler serves :query-chain-state directly from @(:state-atom shell-node) without blocking on events-in, and never signs an empty {} state"
    (let [val-kp (test-keypair)
          val-pk (kp->pk-hex val-kp)
          agent-kp (test-keypair)
          agent-pk (kp->pk-hex agent-kp)
          validator-id {:pubkey-hex val-pk :keypair val-kp}
          populated-state {:epoch 42
                           :last-executed-finalized-epoch 41
                           :ledger {agent-pk (account/map->AccountState {:balance 777000 :seq 3 :deps ["tx-a"]})}}
          sent-payloads (atom [])
          fake-agent-node {:state-atom (atom {})}
          query-env (light-core/build-chain-state-query-envelope agent-pk (kp->sk agent-kp) {"nonce" "nonce-fast-1"})
          signed-wire (fressian/encode-wire query-env)]
      (with-redefs [api/set-callbacks! (fn [_node cbs] cbs)
                    api/send! (fn [_node payload _cid]
                                (swap! sent-payloads conj (fressian/decode payload)))]
        ;; Case 1: shell-node has populated :state-atom (and no :events-in reader at all!)
        (let [shell-node {:state-atom (atom populated-state)
                          :identity validator-id}
              handler (mesh/make-agent-connection-handler shell-node nil nil validator-id)
              cbs (handler fake-agent-node)]
          ((:on-open cbs) {:channel-id 1})
          ((:on-message cbs) {:channel-id 1 :payload signed-wire})
          (is (= 1 (count @sent-payloads)))
          (let [snap (first @sent-payloads)]
            (is (= 41 (:finalized-epoch snap)))
            (is (= 777000 (:balance snap)))
            (is (= ["tx-a"] (:deps snap)))))

        ;; Case 2: shell-node :state-atom is empty {} -> must NOT sign or send a bogus 0-balance snapshot!
        (reset! sent-payloads [])
        (let [empty-shell-node {:state-atom (atom {})
                                :identity validator-id}
              handler (mesh/make-agent-connection-handler empty-shell-node nil nil validator-id)
              cbs (handler fake-agent-node)]
          ((:on-open cbs) {:channel-id 1})
          ((:on-message cbs) {:channel-id 1 :payload signed-wire})
          (is (empty? @sent-payloads)))))))

;; -----------------------------------------------------------------------------
;; 4. F-D28-4: Direct-Leg :session-ack Routing, Fallback Outbox, & Relay Watermark
;; -----------------------------------------------------------------------------

(deftest test-f-d28-4-direct-leg-session-ack-and-outbox-fallback
  (testing "build-session-ack-envelope tags :p2p-direct? true and 0 burn when session P2P leg is connected, and 100 burn when disconnected"
    (let [alice-kp (test-keypair)
          alice-pk (kp->pk-hex alice-kp)
          bob-kp (test-keypair)
          bob-pk (kp->pk-hex bob-kp)
          sid "sess-direct-ack-1"
          state-open {:pubkey alice-pk
                      :subnet-id "devnet.bitecho.org"
                      :epoch 50
                      :sessions {sid {:state "open"
                                      :peer bob-pk
                                      :epoch 50
                                      :p2p {:connected? true :phase :open}}}}
          state-closed (assoc-in state-open [:sessions sid :p2p :connected?] false)
          ack-open (light-core/build-session-ack-envelope state-open sid bob-pk 1 1 [1] (kp->sk alice-kp))
          ack-closed (light-core/build-session-ack-envelope state-closed sid bob-pk 1 1 [1] (kp->sk alice-kp))]
      (is (true? (:p2p-direct? ack-open)))
      (is (= bob-pk (:p2p-peer ack-open)))
      (is (= sid (:p2p-session-id ack-open)))
      (is (= 0 (get-in ack-open [:event :message :burn-amount])))
      (is (nil? (:p2p-direct? ack-closed)))
      (is (= 100 (get-in ack-closed [:event :message :burn-amount])))))

  (testing "retransmit-unacked-outbox strips :p2p-direct? and re-wraps 0-burn envelope with burn floor when P2P disconnects"
    (let [alice-kp (test-keypair)
          alice-pk (kp->pk-hex alice-kp)
          bob-kp (test-keypair)
          bob-pk (kp->pk-hex bob-kp)
          sid "sess-fallback-1"
          msg-payload {:protocol-version 1
                       :wire-format "fressian-v1"
                       :subnet-id "devnet.bitecho.org"
                       :bitecho/type :sealed-message
                       :session-id sid
                       :sender alice-pk
                       :recipient bob-pk
                       :seq 1
                       :epoch 50}
          zero-burn-env (-> (#'light-core/build-gossip-envelope
                             alice-pk (kp->sk alice-kp) (#'light-core/freeze-payload msg-payload) 0 "devnet.bitecho.org")
                            (assoc :p2p-direct? true
                                   :p2p-peer bob-pk
                                   :p2p-session-id sid))
          state-disconnected {:pubkey alice-pk
                              :subnet-id "devnet.bitecho.org"
                              :economy-enabled? true
                              :epoch 55
                              :sessions {sid {:state "open"
                                              :peer bob-pk
                                              :p2p {:connected? false :phase :closed}
                                              :outbox {1 {:seq 1
                                                          :retries 0
                                                          :last-sent-ms 10
                                                          :burn 0
                                                          :msg-payload msg-payload
                                                          :gossip-env zero-burn-env}}
                                              :outbox-order [1]}}}
          retrans (light-core/retransmit-unacked-outbox state-disconnected sid 1000 0 (kp->sk alice-kp))
          env (first (:net-envelopes retrans))]
      (is (= 1 (:count retrans)))
      (is (map? env))
      (is (nil? (:p2p-direct? env)))
      (is (nil? (:p2p-peer env)))
      (is (nil? (:p2p-session-id env)))
      (is (>= (long (get-in env [:event :message :burn-amount] 0)) 100)))))

(deftest test-f-d28-4-relay-watermark-reset-on-restart
  (testing "relay/reduce-relay resets effective since-seq and since-broadcast-seq to 0 and emits counted :relay-watermark-reset diagnostic when client cursor exceeds restarted relay high-water mark"
    (let [client-kp (test-keypair)
          client-pk (kp->pk-hex client-kp)
          now-ms 1700000000000
          restarted-state (-> (relay/init-relay-state)
                              (assoc-in [:inboxes client-pk] [{:relay-seq 1
                                                               :envelope-id "env-1"
                                                               :recipient client-pk
                                                               :received-at now-ms}])
                              (assoc-in [:inbox-seqs client-pk] 1)
                              (assoc :broadcasts [{:broadcast-seq 1
                                                   :envelope-id "bcast-1"
                                                   :subnet-id "devnet.bitecho.org"
                                                   :received-at now-ms}]
                                     :next-broadcast-seq 1))
          ;; Client polls with stale pre-restart cursors since-seq=50, since-broadcast-seq=90
          nonce "poll-watermark-reset-1"
          sig-hex (relay/sign-poll-request (kp->sk client-kp)
                                           {:pubkey client-pk
                                            :since-seq 50
                                            :timestamp-ms now-ms
                                            :nonce nonce})
          poll-res (relay/reduce-relay restarted-state {:type :relay-poll
                                                        :pubkey client-pk
                                                        :nonce nonce
                                                        :timestamp-ms now-ms
                                                        :now-ms now-ms
                                                        :signature sig-hex
                                                        :since-seq 50
                                                        :since-broadcast-seq 90})]
      (is (true? (:ok? poll-res)))
      (is (= 1 (count (get-in poll-res [:response "messages"]))))
      (is (= 1 (count (get-in poll-res [:response "broadcasts"]))))
      (is (= 1 (get-in poll-res [:state :diagnostics :watermark-reset])))
      (is (some #(and (= :diagnose (:effect %))
                      (= :relay-watermark-reset (:reason %)))
                (:effects poll-res))))))
