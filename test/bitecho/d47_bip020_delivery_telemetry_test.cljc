(ns bitecho.d47-bip020-delivery-telemetry-test
  "BIP-020 Draft 2 Strict TDD generative & stateful command-sequence tests (Rules 1-6).
   Covers all 4 shared-core telemetry pillars and all 5 folded Stage 1 catches:
   - Catch 1: Two-phase prepare-send/prepare-broadcast + commit-delivery-outcome,
              wall-clock now-ms fix, disconnect retry pause, 6 eviction reasons,
              exec-status diagnostics merge, persistence allowlist.
   - Catch 2: N-1 wire compatibility (zero route metadata in signed wire bytes),
              cross-transport dedup, inner subnet-id relay poll filtering (burn > 0),
              bounded 256-entry ring / 1024-entry broadcast-seen / redial concurrency <= 2.
   - Catch 3: Browser liveness honesty on ICE disconnected/failed prior to onclose,
              stale-generation callback accounting, populated string-keyed sorted-map safe lookup.
   - Catch 4: Relay min_available_broadcast_seq + relay_id gap detection,
              unified core event-matches-wait-filter? with broadcast_seq & equivalent-subnet-id?,
              non-destructive cursor exec-wait & foreign-unicast suppression accounting."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- make-test-identity
  [seed-str]
  (let [seed (crypto/sha256 (fressian/utf8->bytes seed-str))
        kp (crypto/generate-keypair seed)
        pub-hex (basalt/bytes->hex (:public-key kp))]
    {:identity {:pubkey pub-hex
                :pubkey-hex pub-hex
                :pubkey-bytes (:public-key kp)
                :privkey-bytes (:private-key kp)}
     :pubkey-hex pub-hex
     :privkey-bytes (:private-key kp)}))

(defn- make-open-session-state
  "Returns {:alice-state :bob-state :alice-id :bob-id :session-id} with an open sealed session."
  [seed-prefix]
  (let [alice (make-test-identity (str seed-prefix "-alice"))
        bob (make-test-identity (str seed-prefix "-bob"))
        sid (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes (str seed-prefix "-sid"))))
        tx-key (crypto/sha256 (fressian/utf8->bytes (str seed-prefix "-tx")))
        rx-key (crypto/sha256 (fressian/utf8->bytes (str seed-prefix "-rx")))
        st-a (-> (light-core/init-light-state (:identity alice)
                                              {:epoch 85690
                                               :subnet-id "bitecho.org/dev"
                                               :subscribed-subnets #{"bitecho.org/dev"}})
                 (assoc :account {:balance 100000 :spendable 100000 :finalized-epoch 85690})
                 (assoc-in [:sessions sid]
                           {:session-id sid
                            :peer (:pubkey-hex bob)
                            :role :caller
                            :state "open"
                            :epoch 85690
                            :tx-seq 0
                            :rx-high-seq 0
                            :acked-seq 0
                            :tx-key tx-key
                            :rx-key rx-key
                            :outbox {}
                            :outbox-order []}))
        st-b (-> (light-core/init-light-state (:identity bob)
                                              {:epoch 85690
                                               :subnet-id "bitecho.org/dev"
                                               :subscribed-subnets #{"bitecho.org/dev"}})
                 (assoc :account {:balance 100000 :spendable 100000 :finalized-epoch 85690})
                 (assoc-in [:sessions sid]
                           {:session-id sid
                            :peer (:pubkey-hex alice)
                            :role :callee
                            :state "open"
                            :epoch 85690
                            :tx-seq 0
                            :rx-high-seq 0
                            :acked-seq 0
                            :tx-key rx-key
                            :rx-key tx-key
                            :outbox {}
                            :outbox-order []}))]
    {:alice-state st-a
     :bob-state st-b
     :alice-id alice
     :bob-id bob
     :session-id sid}))

(defn- make-relay-poll-event
  [id-map opts]
  (let [ts-ms (long (or (:now-ms opts) 1795000000000))
        nonce (or (:nonce opts) (str "n-" ts-ms "-" (rand-int 1000000)))
        since-seq (long (or (:since-seq opts) 0))
        since-bseq (long (or (:since-broadcast-seq opts) 0))
        pub-hex (:pubkey-hex id-map)
        sig (relay/sign-poll-request (:privkey-bytes id-map)
                                     {:pubkey pub-hex
                                      :since-seq since-seq
                                      :timestamp-ms ts-ms
                                      :nonce nonce})]
    (cond-> {:type :relay-poll
             :pubkey pub-hex
             :since-seq since-seq
             :since-broadcast-seq since-bseq
             :timestamp-ms ts-ms
             :nonce nonce
             :signature sig
             :now-ms ts-ms}
      (:subnets opts) (assoc :subnets (:subnets opts)))))

;; =============================================================================
;; CATCH 1: Two-Phase Send/Broadcast, Wall-Clock now-ms, Evictions, & Status
;; =============================================================================

(defspec ^{:doc "Two-phase prepare-send/prepare-broadcast + commit-delivery-outcome matches injected shell outcomes 1:1 and enforces ring bounds."}
  prop-two-phase-delivery-matches-shell-outcomes-and-bounds 30
  (prop/for-all
   [ops (gen/vector
         (gen/hash-map
          :kind (gen/elements [:broadcast :send])
          :mesh-ok? gen/boolean
          :p2p-ok? gen/boolean
          :mesh-peers (gen/choose 0 6)
          :p2p-peers (gen/choose 0 4)
          :text (gen/not-empty gen/string-alphanumeric))
         1 40)]
   (let [{:keys [alice-state alice-id session-id]} (make-open-session-state "bip020-two-phase")
         base-now 1795000000000
         final
         (reduce
          (fn [{:keys [state idx ok-acc]} op]
            (let [now-ms (+ base-now (* idx 1000))
                  prep (if (= :broadcast (:kind op))
                         (light-core/prepare-broadcast
                          state
                          {"subnet_id" "bitecho.org/dev"
                           "text" (:text op)
                           "now_ms" now-ms}
                          (:privkey-bytes alice-id))
                         (light-core/prepare-send
                          state
                          {"session_id" session-id
                           "text" (:text op)
                           "now_ms" now-ms}
                          (:privkey-bytes alice-id)))
                  ;; Pre-commit MUST NOT claim ok:true or mesh_submitted:true
                  prep-honest? (and (false? (get-in prep [:response "ok"]))
                                    (false? (get-in prep [:response "mesh_submitted"]))
                                    (true? (get-in prep [:response "pending"]))
                                    (map? (:fanout-intent prep))
                                    (= 1 (count (:net-envelopes prep))))
                  outcome {:mesh-submitted? (:mesh-ok? op)
                           :p2p-direct? (:p2p-ok? op)
                           :mesh-peers-targeted (if (:mesh-ok? op) (max 1 (:mesh-peers op)) 0)
                           :p2p-peers-targeted (if (:p2p-ok? op) (max 1 (:p2p-peers op)) 0)
                           :now-ms (+ now-ms 50)
                           :error (when-not (or (:mesh-ok? op) (:p2p-ok? op)) "all-transports-down")}
                  committed (light-core/commit-delivery-outcome (:state prep) (:fanout-intent prep) outcome)
                  expected-ok? (or (:mesh-ok? op) (:p2p-ok? op))
                  expected-peers (+ (:mesh-peers-targeted outcome) (:p2p-peers-targeted outcome))
                  commit-honest? (and (= expected-ok? (get-in committed [:response "ok"]))
                                      (= (:mesh-ok? op) (get-in committed [:response "mesh_submitted"]))
                                      (= (:p2p-ok? op) (get-in committed [:response "p2p_direct"]))
                                      (= expected-peers (get-in committed [:response "peers_targeted"]))
                                      (if expected-ok?
                                        true
                                        (some #(= "mesh-submit-failed" (get % "reason"))
                                              (:stdout-events committed))))
                  ring (get-in (:state committed) [:delivery-telemetry :ring-buffer] [])
                  ring-bounded? (and (<= (count ring) 256)
                                     (every? #(<= (fressian/count-bytes (fressian/utf8->bytes (pr-str %))) 1024)
                                             ring))]
              {:state (:state committed)
               :idx (inc idx)
               :ok-acc (and ok-acc prep-honest? commit-honest? ring-bounded?)}))
          {:state alice-state :idx 0 :ok-acc true}
          ops)]
     (:ok-acc final))))

(defspec ^{:doc "Wall-clock now_ms never falls back to :epoch, never triggers false unacked_aged, and pauses retries while disconnected."}
  prop-wall-clock-now-ms-no-false-aging-and-disconnect-pause 30
  (prop/for-all
   [base-now (gen/choose 1790000000000 1800000000000)
    delta-ms (gen/choose 1000 59000)
    disconnect-steps (gen/choose 1 10)]
   (let [{:keys [alice-state alice-id session-id]} (make-open-session-state "bip020-wall-clock")
         prep (light-core/prepare-send
               alice-state
               {"session_id" session-id "text" "hello-wall-clock" "now_ms" base-now}
               (:privkey-bytes alice-id))
         st1 (:state prep)
         entry (get-in st1 [:sessions session-id :outbox 1])
         ;; 1. created-ms and last-sent-ms MUST be wall-clock base-now, NEVER :epoch (85690)
         stamped-wall-clock? (and (= base-now (:created-ms entry))
                                  (= base-now (:last-sent-ms entry)))
         ;; 2. Within < 60s threshold, unacked_aged MUST be 0
         aged-before (light-core/compute-unacked-aged-count st1 (+ base-now delta-ms))
         ;; 3. At >= 60s threshold, unacked_aged MUST be 1
         aged-after (light-core/compute-unacked-aged-count st1 (+ base-now 60000))
         ;; 4. When disconnected (:connected? false and P2P closed), retransmit pauses retry burns
         st-disc (assoc st1 :connected? false)
         st-after-disc (reduce
                        (fn [st step]
                          (:state (light-core/retransmit-unacked-outbox
                                   st session-id (+ base-now (* (inc step) 60000)) 30000 (:privkey-bytes alice-id))))
                        st-disc
                        (range disconnect-steps))
         retries-after-disc (get-in st-after-disc [:sessions session-id :outbox 1 :retries] -1)]
     (and stamped-wall-clock?
          (zero? aged-before)
          (= 1 aged-after)
          (zero? retries-after-disc)))))

(deftest test-delivery-ring-cap-and-all-six-eviction-reasons
  (testing "Ring buffer caps at 256 entries and <= 1024 bytes per entry"
    (let [{:keys [alice-state]} (make-open-session-state "bip020-ring-cap")
          huge-str (apply str (repeat 2000 "X"))
          st-filled (reduce
                     (fn [st i]
                       (light-core/append-delivery-ring-entry
                        st
                        {:msg-id (str "m-" i)
                         :kind :broadcast
                         :state :submitted
                         :route :mesh
                         :error huge-str
                         :ts-ms (+ 1795000000000 i)}))
                     alice-state
                     (range 300))
          ring (get-in st-filled [:delivery-telemetry :ring-buffer])]
      (is (= 256 (count ring)))
      (is (= "m-44" (:msg-id (first ring))))
      (is (= "m-299" (:msg-id (last ring))))
      (is (every? #(<= (fressian/count-bytes (fressian/utf8->bytes (pr-str %))) 1024) ring))))

  (testing "All 6 evicted_by_reason categories are tracked cleanly in delivery_telemetry and exec-status"
    (let [{:keys [alice-state]} (make-open-session-state "bip020-evict-reasons")
          reasons [:retries-exhausted :epoch-skew :session-not-open
                   :mesh-disconnected :capacity-overflow :expired]
          st-evicted (reduce (fn [st r]
                               (light-core/record-eviction st r {:msg-id (name r) :ts-ms 1795000000000}))
                             alice-state
                             reasons)
          st-with-conn (assoc st-evicted
                              :conn-diagnostics {:phase :open :generation 3 :dropped 1}
                              :diagnostics (assoc (:diagnostics st-evicted) :subnet-mismatch-dropped 2))
          status (light-core/exec-status st-with-conn)
          resp (:response status)
          ev-map (get-in resp ["delivery_telemetry" "evicted_by_reason"])]
      (is (= 1 (get ev-map "retries_exhausted")))
      (is (= 1 (get ev-map "epoch_skew")))
      (is (= 1 (get ev-map "session_not_open")))
      (is (= 1 (get ev-map "mesh_disconnected")))
      (is (= 1 (get ev-map "capacity_overflow")))
      (is (= 1 (get ev-map "expired")))
      ;; exec-status merges core :diagnostics AND :conn-diagnostics
      (is (= 2 (get-in resp ["diagnostics" :subnet-mismatch-dropped])))
      (is (= :open (get-in resp ["diagnostics" :phase])))
      (is (= 6 (get-in resp ["diagnostics" :outbox-evicted]))))))

(defspec ^{:doc "Browser persistence allowlist preserves Pillar 1-3 delivery telemetry while stripping Rule 4 runtime liveness keys."}
  prop-browser-persistence-keeps-telemetry-strips-liveness 20
  (prop/for-all
   [sent-cnt (gen/choose 0 500)
    acked-cnt (gen/choose 0 500)]
   (let [raw-state {:pubkey "aabbcc"
                    :connected? true
                    :connection-error "transient-err"
                    :conn {:phase :open :generation 5}
                    :active-channels {"node1" :live-dc}
                    :p2p-channels {"peer1" :live-p2p}
                    :delivery-telemetry {:sent sent-cnt
                                         :acked acked-cnt
                                         :evicted-by-reason {:retries-exhausted 1
                                                             :epoch-skew 0
                                                             :session-not-open 0
                                                             :mesh-disconnected 0
                                                             :capacity-overflow 2
                                                             :expired 0}
                                         :received-but-not-emitted {:foreign-unicast 3
                                                                    :subnet-mismatch 1}
                                         :fanout {:mesh-submitted sent-cnt
                                                  :p2p-direct 1
                                                  :peers-targeted 4
                                                  :mesh-submit-failed 0}
                                         :ring-buffer [{:msg-id "m1" :kind :broadcast :state :fanned-out :route :mesh+p2p :ts-ms 1795000000000}]}}
         sanitized (browser/sanitize-state-for-persistence raw-state)]
     (and (= sent-cnt (get-in sanitized [:delivery-telemetry :sent]))
          (= acked-cnt (get-in sanitized [:delivery-telemetry :acked]))
          (= 2 (get-in sanitized [:delivery-telemetry :evicted-by-reason :capacity-overflow]))
          (= 3 (get-in sanitized [:delivery-telemetry :received-but-not-emitted :foreign-unicast]))
          (= 1 (count (get-in sanitized [:delivery-telemetry :ring-buffer])))
          (not (contains? sanitized :connected?))
          (not (contains? sanitized :connection-error))
          (not (contains? sanitized :conn))
          (not (contains? sanitized :active-channels))
          (not (contains? sanitized :p2p-channels))))))

;; =============================================================================
;; CATCH 2: N-1 Wire Compat, Inner Subnet Poll Filter, & e2-micro Bounds
;; =============================================================================

(defspec ^{:doc "N-1 wire compatibility: zero route metadata inside signed wire bytes, canonical-broadcast-str valid, and relay dedup intact."}
  prop-n1-wire-compatibility-and-cross-transport-dedup 25
  (prop/for-all
   [text (gen/not-empty gen/string-alphanumeric)
    burn (gen/elements [0 50 100])]
   (let [{:keys [alice-state bob-state alice-id bob-id]} (make-open-session-state "bip020-n1-wire")
         prep (light-core/prepare-broadcast
               alice-state
               {"subnet_id" "bitecho.org/dev"
                "text" text
                "burn" burn
                "now_ms" 1795000000000}
               (:privkey-bytes alice-id))
         env (first (:net-envelopes prep))
         wire-bytes (fressian/encode-wire env)
         inner (light-core/thaw-payload (get-in env [:event :message :payload]))
         ;; Route metadata MUST NEVER appear inside signed wire payload
         no-route-meta? (and (not (contains? inner :mesh-submitted))
                             (not (contains? inner :p2p-direct))
                             (not (contains? inner :peers-targeted))
                             (not (contains? inner :fanout)))
         ;; N-1 canonical-broadcast-str verification
         sig-str (light-core/canonical-broadcast-str
                  (:subnet-id inner) (:sender inner) (:seq inner)
                  (:msg-id inner) (:text inner) (:epoch inner) nil)
         sig-ok? (crypto/verify (basalt/hex->bytes (:sender inner))
                                (fressian/utf8->bytes sig-str)
                                (basalt/hex->bytes (:signature inner)))
         ;; Relay dedup across P2P + mesh legs with identical wire bytes
         r0 (relay/init-relay-state {:relay-id "ns1"})
         sub1 (relay/reduce-relay r0 {:type :relay-submit :wire-bytes wire-bytes :now-ms 1795000001000})
         sub2 (relay/reduce-relay (:state sub1) {:type :relay-submit :wire-bytes wire-bytes :now-ms 1795000001100})
         ;; Bob receives broadcast and tags :type :broadcast + emits broadcast_seq
         rx-bob (light-core/handle-wire-payload bob-state env (:privkey-bytes bob-id))
         bob-evt (first (:stdout-events rx-bob))
         bob-inbox-item (first (:inbox (:state rx-bob)))]
     (and no-route-meta?
          sig-ok?
          (:ok? sub1)
          (false? (:duplicate? sub1))
          (:ok? sub2)
          (true? (:duplicate? sub2))
          (= (:envelope-id sub1) (:envelope-id sub2))
          (= "broadcast-received" (get bob-evt "event"))
          (= (:seq inner) (get bob-evt "broadcast_seq"))
          (= :broadcast (:type bob-inbox-item))))))

(deftest test-relay-poll-filters-inner-subnet-when-burn-positive
  (testing "burn > 0 wraps outer subnet-id as '*', relay poll still filters on inner :subnet-id"
    (let [{:keys [alice-state alice-id bob-id]} (make-open-session-state "bip020-burn-sub")
          prep-dev (light-core/prepare-broadcast
                    alice-state
                    {"subnet_id" "bitecho.org/dev" "text" "dev-msg" "burn" 100 "now_ms" 1795000000000}
                    (:privkey-bytes alice-id))
          prep-cafe (light-core/prepare-broadcast
                     (:state prep-dev)
                     {"subnet_id" "homebrew-cafe" "text" "cafe-msg" "burn" 100 "now_ms" 1795000001000}
                     (:privkey-bytes alice-id))
          env-dev (first (:net-envelopes prep-dev))
          env-cafe (first (:net-envelopes prep-cafe))
          _ (is (= "*" (:subnet-id env-dev)))
          _ (is (= "*" (:subnet-id env-cafe)))
          r0 (relay/init-relay-state {:relay-id "ns1"})
          r1 (:state (relay/reduce-relay r0 {:type :relay-submit :wire-bytes (fressian/encode-wire env-dev) :now-ms 1795000002000}))
          r2 (:state (relay/reduce-relay r1 {:type :relay-submit :wire-bytes (fressian/encode-wire env-cafe) :now-ms 1795000003000}))
          poll-dev (relay/reduce-relay r2 (make-relay-poll-event bob-id {:subnets ["bitecho.org/dev"] :now-ms 1795000004000}))
          bcasts (get-in poll-dev [:response "broadcasts"])]
      (is (:ok? poll-dev))
      (is (= 1 (count bcasts)))
      (is (= "bitecho.org/dev" (:subnet-id (first bcasts))))
      (is (= 1 (get-in poll-dev [:response "min_available_broadcast_seq"])))
      (is (= "ns1" (get-in poll-dev [:response "relay_id"]))))))

(deftest test-broadcast-seen-bounded-1024-entries
  (testing ":broadcast-seen is capped at 1024 entries (e2-micro bound)"
    (let [{:keys [alice-state]} (make-open-session-state "bip020-bseen")
          st-final (reduce (fn [st i]
                             (light-core/record-broadcast-seen st ["sender-a" i (str "mid-" i)]))
                           alice-state
                           (range 1150))]
      (is (= 1024 (count (:broadcast-seen st-final))))
      (is (= 1024 (count (:broadcast-seen-order st-final))))
      (is (not (contains? (:broadcast-seen st-final) ["sender-a" 0 "mid-0"])))
      (is (contains? (:broadcast-seen st-final) ["sender-a" 1149 "mid-1149"])))))

(defspec ^{:doc "Bounded auto-redial reducer enforces <= 2 concurrent dials, <= 5 attempts/outage, and 2s..30s backoff across 6-peer outages."}
  prop-browser-redial-bounds-concurrency-and-attempts 25
  (prop/for-all
   [tick-count (gen/choose 1 25)]
   (let [peers ["node1" "node2" "node3" "ns1" "ns2" "ns3"]
         r0 (browser/initial-redial-state {:peers peers})
         ;; Trigger outage on all 6 peers simultaneously
         [r1 _] (reduce (fn [[st effs] pid]
                          (let [[st' e'] (browser/transition-redial st {:type :peer-down :peer-id pid :now-ms 1000})]
                            [st' (into effs e')]))
                        [r0 []]
                        peers)
         ;; Step time forward and fail every dial attempt
         result
         (reduce
          (fn [{:keys [st max-concurrent max-attempts backoff-ok?]} step]
            (let [now (+ 1000 (* (inc step) 4000))
                  [st1 effs1] (browser/transition-redial st {:type :tick :now-ms now})
                  dial-effs (filterv #(= :start-dial (:type %)) effs1)
                  in-flight (count (:in-flight st1))
                  ;; Fail each started dial
                  [st2 _] (reduce (fn [[s _] de]
                                    (browser/transition-redial
                                     s {:type :dial-failed
                                        :peer-id (:peer-id de)
                                        :generation (:generation de)
                                        :now-ms (+ now 100)}))
                                  [st1 []]
                                  dial-effs)
                  peer-attempts (mapv #(long (or (:attempts %) 0)) (vals (:peers st2)))
                  peer-backoffs (mapv #(long (or (:backoff-ms %) 2000)) (vals (:peers st2)))]
              {:st st2
               :max-concurrent (max max-concurrent in-flight (count dial-effs))
               :max-attempts (max max-attempts (apply max 0 peer-attempts))
               :backoff-ok? (and backoff-ok?
                                 (every? #(and (>= % 2000) (<= % 30000)) peer-backoffs))}))
          {:st r1 :max-concurrent 0 :max-attempts 0 :backoff-ok? true}
          (range tick-count))]
     (and (<= (:max-concurrent result) 2)
          (<= (:max-attempts result) 5)
          (:backoff-ok? result)))))

;; =============================================================================
;; CATCH 3: Browser Liveness Honesty & Populated sorted-map Safe Lookup
;; =============================================================================

(defspec ^{:doc "Browser 6-peer ICE cascade transitions peers out of :open before DataChannel.onclose and counts stale-generation callbacks."}
  prop-browser-ice-cascade-honest-liveness-and-stale-gen 25
  (prop/for-all
   [fail-states (gen/vector (gen/elements ["disconnected" "failed" "closed"]) 6 6)]
   (let [peers ["node1" "node2" "node3" "ns1" "ns2" "ns3"]
         ;; Open all 6 peers at generation 1
         mesh-open (reduce (fn [m pid]
                             (let [[m1 _] (browser/transition-mesh-peer m pid {:type :dial :generation 1 :timestamp-ms 1000})
                                   [m2 _] (browser/transition-mesh-peer m1 pid {:type :open :generation 1 :channel :dc :transport :webrtc :timestamp-ms 1100})]
                               m2))
                           (browser/initial-mesh-conns-state)
                           peers)
         open-summary (browser/summarize-mesh-diagnostics mesh-open)
         ;; Cascade ICE failure across all 6 peers BEFORE DataChannel.onclose fires
         mesh-failed (reduce (fn [m [pid ice-st]]
                               (let [[m1 _] (browser/transition-mesh-peer m pid {:type :ice-state-change :generation 1 :ice-state ice-st :timestamp-ms 2000})]
                                 m1))
                             mesh-open
                             (map vector peers fail-states))
         failed-summary (browser/summarize-mesh-diagnostics mesh-failed)
         ;; Dial gen 2 on node1, then inject stale gen 1 :open callback
         [mesh-g2 _] (browser/transition-mesh-peer mesh-failed "node1" {:type :dial :generation 2 :timestamp-ms 3000})
         [mesh-stale stale-effs] (browser/transition-mesh-peer mesh-g2 "node1" {:type :open :generation 1 :channel :stale-dc :timestamp-ms 3100})]
     (and (= 6 (count (:open-peers open-summary)))
          (empty? (:open-peers failed-summary))
          (not= :open (:phase failed-summary))
          (some #(= :ignored-stale (:kind %)) stale-effs)
          (= 1 (get-in mesh-stale [:peers "node1" :diagnostics :ignored-stale]))))))

(defspec ^{:doc "Populated string-keyed sorted-map probed with keyword keys via safe-map-get never throws CompareError."}
  prop-populated-sorted-map-safe-get-never-throws 30
  (prop/for-all
   [k-str (gen/not-empty gen/string-alphanumeric)
    probe-str (gen/not-empty gen/string-alphanumeric)]
   (let [sm (sorted-map "alice" "aa01" "bob" "bb02" k-str "cc03")
         kw-probe (keyword probe-str)
         str-res (light-core/safe-map-get sm k-str)
         kw-res (light-core/safe-map-get sm kw-probe)]
     (and (= "cc03" str-res)
          (nil? kw-res)))))

;; =============================================================================
;; CATCH 4: Relay Gap Detection, Unified Filter, Non-Destructive Wait, Foreign Unicast
;; =============================================================================

(defspec ^{:doc "Relay ring-buffer eviction exposes min_available_broadcast_seq and relay_id, firing counted :broadcast-gap-detected."}
  prop-relay-ring-eviction-exposes-min-seq-and-detects-gap 20
  (prop/for-all
   [extra-count (gen/choose 1 12)]
   (let [{:keys [alice-state alice-id bob-id]} (make-open-session-state "bip020-relay-gap")
         r0 (relay/init-relay-state {:relay-id "ns2" :max-broadcast-size 4})
         total (+ 4 extra-count)
         [_ r-final]
         (reduce
          (fn [[st r] i]
            (let [prep (light-core/prepare-broadcast
                        st
                        {"subnet_id" "bitecho.org/dev" "text" (str "msg-" i) "now_ms" (+ 1795000000000 i)}
                        (:privkey-bytes alice-id))
                  sub (relay/reduce-relay r {:type :relay-submit
                                             :wire-bytes (fressian/encode-wire (first (:net-envelopes prep)))
                                             :now-ms (+ 1795000000000 i)})]
              [(:state prep) (:state sub)]))
          [alice-state r0]
          (range total))
         poll-res (relay/reduce-relay r-final (make-relay-poll-event bob-id {:since-broadcast-seq 1 :now-ms 1795000010000}))
         min-avail (get-in poll-res [:response "min_available_broadcast_seq"])
         relay-id (get-in poll-res [:response "relay_id"])
         gap-res (light-core/detect-relay-broadcast-gap
                  alice-state
                  {:relay-id relay-id
                   :local-cursor 1
                   :min-available-broadcast-seq min-avail
                   :last-broadcast-seq (get-in poll-res [:response "last_broadcast_seq"])})]
     (and (= (inc extra-count) min-avail)
          (= "ns2" relay-id)
          (true? (:gap-detected? gap-res))
          (= 1 (get-in (:state gap-res) [:diagnostics :broadcast-gap-detected]))
          (some #(= "broadcast-gap-detected" (get % "reason")) (:stdout-events gap-res))))))

(deftest test-unified-wait-filter-non-destructive-cursor-and-foreign-unicast
  (testing "Unified event-matches-wait-filter? supports broadcast_seq and equivalent-subnet-id?"
    (let [evt {"event" "broadcast-received"
               "subnet_id" "global"
               "seq" 42
               "broadcast_seq" 42
               "timestamp_ms" 1795000005000}]
      (is (true? (light-core/event-matches-wait-filter?
                  evt {:subnet-id "devnet.bitecho.org"
                       :network-uri "devnet.bitecho.org"
                       :min-broadcast-seq 42})))
      (is (false? (light-core/event-matches-wait-filter?
                   evt {:subnet-id "bitecho.org/dev"
                        :network-uri "devnet.bitecho.org"
                        :min-broadcast-seq 42})))
      (is (false? (light-core/event-matches-wait-filter?
                   evt {:min-broadcast-seq 43})))))

  (testing "Non-destructive cursor exec-wait separates event_id from seq and counts received_but_not_emitted"
    (let [{:keys [alice-state]} (make-open-session-state "bip020-wait-cursor")
          st1 (light-core/enqueue-actionable-events
               alice-state
               [{"event" "broadcast-received" "subnet_id" "bitecho.org/dev" "seq" 10 "broadcast_seq" 10 "text" "b1"}
                {"event" "broadcast-received" "subnet_id" "other-sub" "seq" 11 "broadcast_seq" 11 "text" "b2"}
                {"event" "broadcast-received" "subnet_id" "bitecho.org/dev" "seq" 12 "broadcast_seq" 12 "text" "b3"}])
          ;; Watcher 1 reads with cursor 0 and subnet_id "bitecho.org/dev"
          w1 (light-core/exec-wait st1 {"cursor" 0 "subnet_id" "bitecho.org/dev"})
          ;; Watcher 2 reads concurrently from cursor 0 without losing events
          w2 (light-core/exec-wait (:state w1) {"cursor" 0 "subnet_id" "other-sub"})]
      (is (= 2 (count (get-in w1 [:response "events"]))))
      (is (= [1 3] (mapv #(get % "event_id") (get-in w1 [:response "events"]))))
      (is (= 3 (get-in w1 [:response "cursor"])))
      ;; Event queue preserved non-destructively for Watcher 2
      (is (= 1 (count (get-in w2 [:response "events"]))))
      (is (= [2] (mapv #(get % "event_id") (get-in w2 [:response "events"]))))
      ;; Suppressed events counted in received_but_not_emitted
      (is (= 1 (get-in (:state w1) [:delivery-telemetry :received-but-not-emitted :subnet-mismatch])))))

  (testing "Foreign unicast drop in handle-wire-payload increments received_but_not_emitted :foreign-unicast"
    (let [{:keys [alice-state bob-id]} (make-open-session-state "bip020-foreign-unicast")
          carol (make-test-identity "bip020-carol")
          foreign-msg {:protocol-version 1
                       :wire-format "fressian-v1"
                       :subnet-id "bitecho.org/dev"
                       :bitecho/type :sealed-message
                       :session-id "sess-foreign"
                       :sender (:pubkey-hex bob-id)
                       :recipient (:pubkey-hex carol)
                       :epoch 85690
                       :seq 1}
          res (light-core/handle-wire-payload alice-state foreign-msg nil)]
      (is (= 1 (get-in (:state res) [:delivery-telemetry :received-but-not-emitted :foreign-unicast])))
      (is (= 1 (get-in (:state res) [:diagnostics :foreign-unicast-dropped]))))))
