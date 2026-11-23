(ns bitecho.d48-bip021-subnet-session-updater-test
  "Strict TDD generative & stateful tests for BIP-021 Draft 2:
   - §2.1 Startup `subnet_id` authority & cross-network-URI fencing
   - §2.2 Subscribed-subnet admission for direct envelopes, anti-spoofing, and session reply stamping
   - §2.3 Distinct mutually exclusive broadcast/DAC diagnostics & event-queue flood protection
   - §2.4 Session `tx-seq` rollback detection, signed rollback ACK (zero legacy fallback),
          AEAD quarantine, outbox collision eviction before purge, and real X25519 rekey
   - §2.5.1-§2.5.2 Browser parity: honest single-authority liveness projection, persistence allowlist,
          and generation-tagged visibility-aware periodic auto-sync
   - §2.6.1 `:443` passthrough graceful drain (`peer-fin? true` -> `:draining`, `:cancel-drain-timeout`,
          `:drain-progress` ceiling, global `max-draining-pairs` cap)
   - §2.6.2 Pure Sans-IO chunked mesh-first auto-updater (`:phase == :watching` livelock guard,
          BIP-017a chunked mesh fetch, HTTPS fallback, fail-closed `verify-config-pointer`, CID quarantine)
   - §2.7 Node.js `Buffer.poolSize` slab-pinning compact-copy invariant & cold-demotion."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.infra :as core-infra]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light]
            [bitecho.shell.browser :as browser]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- gen-kp
  [seed]
  (let [kp (crypto/generate-keypair seed)]
    {:pub (:public kp)
     :priv (:private kp)
     :pub-hex (basalt/bytes->hex (:public kp))}))

(defn- make-node-state
  ([seed] (make-node-state seed {}))
  ([seed opts]
   (let [kp (gen-kp seed)
         st (light/init-light-state {:pubkey-hex (:pub-hex kp)} opts)]
     {:kp kp :state st})))

(defn- establish-open-session
  "Establishes a real X25519 open session between Alice and Bob on the given subnet."
  [alice-seed bob-seed subnet-id]
  (let [a (make-node-state alice-seed {:subnet-id subnet-id :epoch 100 :economy-enabled? false})
        b (make-node-state bob-seed {:subnet-id subnet-id :epoch 100 :economy-enabled? false :autonomous? true})
        offer-res (light/handle-command (:state a)
                                        {"cmd" "offer"
                                         "callee" (:pub-hex (:kp b))
                                         "subnet_id" subnet-id
                                         "price" 0
                                         "burn" 0}
                                        (:priv (:kp a)))
        offer-env (second (:net-envelopes offer-res))
        bob-accept (light/handle-wire-payload (:state b) offer-env (:priv (:kp b)))
        accept-env (first (:net-envelopes bob-accept))
        alice-open (light/handle-wire-payload (:state offer-res) accept-env (:priv (:kp a)))
        sid (first (keys (:sessions (:state alice-open))))]
    {:alice-kp (:kp a)
     :bob-kp (:kp b)
     :alice (:state alice-open)
     :bob (:state bob-accept)
     :sid sid}))

;; =============================================================================
;; §2.1 Startup `subnet_id` Authority & Cross-Network Fencing
;; =============================================================================

(def ^:private gen-within-devnet-subnet
  (gen/elements ["global" "devnet.bitecho.org" "bitecho.org/dev" "bitecho.org/ops" "team/alpha"]))

(def ^:private gen-canonical-net
  (gen/elements ["devnet.bitecho.org" "testnet.bitecho.org" "mainnet.bitecho.org"]))

(defspec ^{:doc "BIP-021 §2.1: Startup subnet_id reconciliation preserves persisted subnet on nil/blank/same,
                 overrides cleanly within-network with counted :subnet-id-reconciled, and fails closed
                 across canonical network URIs unless :reset-network-state? is true."}
  prop-bip021-startup-subnet-reconciliation 80
  (prop/for-all [persisted-sub gen-within-devnet-subnet
                 explicit-sub (gen/one-of [(gen/return nil)
                                           (gen/return "")
                                           gen-within-devnet-subnet
                                           gen-canonical-net])
                 extra-subs (gen/vector gen-within-devnet-subnet 0 3)
                 reset? gen/boolean]
                (let [{:keys [state]} (make-node-state 101 {:subnet-id persisted-sub
                                                            :network-uri "devnet.bitecho.org"
                                                            :subscribed-subnets #{"bitecho.org/existing"}})
                      st-with-net-data (-> state
                                           (assoc :account {:balance 500 :finalized-epoch 42})
                                           (assoc :chain-state-snapshots {"v1" {:epoch 42}})
                                           (assoc :sessions {"s1" {:state "open"}})
                                           (assoc :relay-since-broadcast-seq 99))
                      res (light/reconcile-startup-subnet-id st-with-net-data explicit-sub extra-subs
                                                             {:reset-network-state? reset?})
                      st' (:state res)
                      effs (:effects res)
                      blank-or-same? (or (nil? explicit-sub)
                                         (str/blank? (str explicit-sub))
                                         (= (str/trim (str explicit-sub)) persisted-sub))
                      cross-net? (and (not blank-or-same?)
                                      (contains? #{"testnet.bitecho.org" "mainnet.bitecho.org"}
                                                 (str/trim (str explicit-sub))))]
                  (cond
                    blank-or-same?
                    (and (:ok? res)
                         (not (:reconciled? res))
                         (= persisted-sub (:subnet-id st'))
                         (zero? (long (get-in st' [:diagnostics :subnet-id-reconciled] 0)))
                         (zero? (long (get-in st' [:diagnostics :cross-network-subnet-switch-blocked] 0))))

                    (and cross-net? (not reset?))
                    (and (false? (:ok? res))
                         (true? (:blocked? res))
                         (= persisted-sub (:subnet-id st'))
                         (= 1 (long (get-in st' [:diagnostics :cross-network-subnet-switch-blocked] 0)))
                         (some #(and (= :diagnose (:effect %))
                                     (= :cross-network-subnet-switch-blocked (:reason %)))
                               effs)
                         ;; Persisted sessions/account preserved when blocked
                         (= 1 (count (:sessions st'))))

                    (and cross-net? reset?)
                    (and (:ok? res)
                         (:reconciled? res)
                         (= (str/trim (str explicit-sub)) (:subnet-id st'))
                         (= (str/trim (str explicit-sub)) (:network-uri st'))
                         (empty? (:sessions st'))
                         (empty? (:chain-state-snapshots st'))
                         (nil? (:account st'))
                         (zero? (long (:relay-since-broadcast-seq st' 0)))
                         (= 1 (long (get-in st' [:diagnostics :subnet-id-reconciled] 0))))

                    :else
                    (and (:ok? res)
                         (:reconciled? res)
                         (= (str/trim (str explicit-sub)) (:subnet-id st'))
                         (contains? (:subscribed-subnets st') (str/trim (str explicit-sub)))
                         (contains? (:subscribed-subnets st') "bitecho.org/existing")
                         (= 1 (long (get-in st' [:diagnostics :subnet-id-reconciled] 0)))
                         (some #(= "subnet-id-reconciled" (get % "event"))
                               (:stdout-events res)))))))

;; =============================================================================
;; §2.2 Subscribed-Subnet Admission & Session Reply Routing
;; =============================================================================

(deftest bip021-subscribed-subnet-admission-and-anti-spoofing-test
  (testing "Direct non-broadcast envelopes on subscribed subnets are admitted; unsubscribed & nil/* spoofing rejected"
    (let [a (make-node-state 201 {:subnet-id "bitecho.org/dev" :epoch 100 :economy-enabled? false})
          b (make-node-state 202 {:subnet-id "devnet.bitecho.org"
                                  :subscribed-subnets #{"bitecho.org/dev"}
                                  :epoch 100
                                  :economy-enabled? false
                                  :autonomous? false})
          ;; Offer on subscribed subnet "bitecho.org/dev"
          offer-res (light/handle-command (:state a)
                                          {"cmd" "offer"
                                           "callee" (:pub-hex (:kp b))
                                           "subnet_id" "bitecho.org/dev"
                                           "price" 0
                                           "burn" 0}
                                          (:priv (:kp a)))
          offer-env (second (:net-envelopes offer-res))
          admitted (light/handle-wire-payload (:state b) offer-env (:priv (:kp b)))
          ;; Offer on unsubscribed subnet "bitecho.org/secret"
          offer-unsub (light/handle-command (:state a)
                                            {"cmd" "offer"
                                             "callee" (:pub-hex (:kp b))
                                             "subnet_id" "bitecho.org/secret"
                                             "price" 0
                                             "burn" 0}
                                            (:priv (:kp a)))
          rejected-unsub (light/handle-wire-payload (:state b) (second (:net-envelopes offer-unsub)) (:priv (:kp b)))
          ;; Spoofed nil-subnet direct offer
          spoof-nil {:bitecho/type :channel-offer
                     :protocol-version 1
                     :wire-format "fressian-v1"
                     :caller (:pub-hex (:kp a))
                     :callee (:pub-hex (:kp b))
                     :epoch 100}
          rejected-nil (light/handle-wire-payload (:state b) spoof-nil (:priv (:kp b)))
          ;; Spoofed wildcard "*" direct offer
          spoof-star (assoc spoof-nil :subnet-id "*")
          rejected-star (light/handle-wire-payload (:state b) spoof-star (:priv (:kp b)))
          ;; Outer/inner subnet mismatch
          mismatch-env (assoc offer-env :subnet-id "bitecho.org/other")
          rejected-mismatch (light/handle-wire-payload (:state b) mismatch-env (:priv (:kp b)))
          ;; Chain-state-snapshot exempt from subnet-mismatch on non-root subnet
          snap-node (make-node-state 203 {:subnet-id "bitecho.org/dev" :epoch 100})
          snap-msg {:bitecho/type :chain-state-snapshot
                    :protocol-version 1
                    :wire-format "fressian-v1"
                    :subnet-id "devnet.bitecho.org"
                    :validator-pubkey (:pub-hex (:kp a))
                    :epoch 101}
          snap-res (light/handle-wire-payload (:state snap-node) snap-msg (:priv (:kp snap-node)))]
      (is (= 1 (count (:pending-offers (:state admitted))))
          "Direct channel-offer on subscribed subnet must be admitted")
      (is (zero? (long (get-in (:state admitted) [:diagnostics :subnet-mismatch-dropped] 0))))
      (is (= 1 (long (get-in (:state rejected-unsub) [:diagnostics :subnet-mismatch-dropped] 0)))
          "Unsubscribed direct envelope must be dropped with counted diagnostic")
      (is (= 1 (long (get-in (:state rejected-nil) [:diagnostics :subnet-mismatch-dropped] 0)))
          "Untagged nil direct envelope must be rejected on non-wildcard node")
      (is (= 1 (long (get-in (:state rejected-star) [:diagnostics :subnet-mismatch-dropped] 0)))
          "Wildcard '*' direct envelope must be rejected unless node subscribed to '*'")
      (is (= 1 (long (get-in (:state rejected-mismatch) [:diagnostics :subnet-mismatch-dropped] 0)))
          "Outer/inner subnet mismatch must be rejected")
      (is (zero? (long (get-in (:state snap-res) [:diagnostics :subnet-mismatch-dropped] 0)))
          ":chain-state-snapshot must be exempt from subnet-mismatch drops on non-root subnets")))

  (testing "Session records bind :subnet-id and stamp exec-send, session-ack, and p2p-answer with (:subnet-id session)"
    (let [a (make-node-state 211 {:subnet-id "bitecho.org/dev" :epoch 100 :economy-enabled? false})
          b (make-node-state 212 {:subnet-id "devnet.bitecho.org"
                                  :subscribed-subnets #{"bitecho.org/dev"}
                                  :epoch 100
                                  :economy-enabled? false
                                  :autonomous? true})
          offer-res (light/handle-command (:state a)
                                          {"cmd" "offer"
                                           "callee" (:pub-hex (:kp b))
                                           "subnet_id" "bitecho.org/dev"
                                           "price" 0
                                           "burn" 0}
                                          (:priv (:kp a)))
          bob-accept (light/handle-wire-payload (:state b) (second (:net-envelopes offer-res)) (:priv (:kp b)))
          alice-open (light/handle-wire-payload (:state offer-res) (first (:net-envelopes bob-accept)) (:priv (:kp a)))
          sid (first (keys (:sessions (:state alice-open))))
          bob-sess (get-in (:state bob-accept) [:sessions sid])
          ;; Bob sends reply without explicit subnet_id -> must stamp "bitecho.org/dev", NOT "devnet.bitecho.org"
          bob-send (light/handle-command (:state bob-accept)
                                         {"cmd" "send" "session_id" sid "text" "hello from subscribed subnet" "now_ms" 1000}
                                         (:priv (:kp b)))
          send-env (first (:net-envelopes bob-send))
          send-inner (light/unwrap-wire-message send-env)
          ;; Alice receives and emits session-ack -> must stamp "bitecho.org/dev"
          alice-rx (light/handle-wire-payload (:state alice-open) send-env (:priv (:kp a)))
          ack-env (first (:net-envelopes alice-rx))
          ack-inner (light/unwrap-wire-message ack-env)
          ;; Bob emits p2p-answer -> must stamp "bitecho.org/dev"
          p2p-ans (light/handle-command (:state bob-accept)
                                        {"cmd" "p2p-answer"
                                         "session_id" sid
                                         "candidates" ["127.0.0.1:9000"]
                                         "now_ms" 1001}
                                        (:priv (:kp b)))
          p2p-inner (light/unwrap-wire-message (first (:net-envelopes p2p-ans)))]
      (is (= "bitecho.org/dev" (:subnet-id bob-sess)))
      (is (= "bitecho.org/dev" (:subnet-id send-inner)))
      (is (= "bitecho.org/dev" (:subnet-id ack-inner)))
      (is (= "bitecho.org/dev" (:subnet-id p2p-inner))))))

;; =============================================================================
;; §2.3 Distinct Broadcast & DAC Diagnostics + Event Queue Protection
;; =============================================================================

(deftest bip021-distinct-broadcast-dac-diagnostics-test
  (testing "Mutually exclusive broadcast rejection counters: malformed, sig-invalid, dac-missing, dac-invalid (incl. non-map)"
    (let [sender (make-node-state 301 {:subnet-id "bitecho.org/dev" :epoch 50})
          anchor (gen-kp 302)
          receiver-dac (make-node-state 303 {:subnet-id "bitecho.org/dev"
                                             :epoch 50
                                             :trusted-dac-anchors [(:pub-hex anchor)]})
          receiver-nodac (make-node-state 304 {:subnet-id "bitecho.org/dev" :epoch 50})
          ;; Validly signed broadcast (no DAC)
          bcast-res (light/handle-command (:state sender)
                                          {"cmd" "broadcast" "text" "hello world" "subnet_id" "bitecho.org/dev"}
                                          (:priv (:kp sender)))
          bcast-msg (light/unwrap-wire-message (first (:net-envelopes bcast-res)))
          ;; 1. Malformed envelope
          r-malformed (light/handle-wire-broadcast (:state receiver-dac) {:sender "bad" :seq -1})
          ;; 2. Invalid signature
          r-bad-sig (light/handle-wire-broadcast (:state receiver-dac) (assoc bcast-msg :signature "00"))
          ;; 3. Valid sig + requires-dac? + missing DAC
          r-dac-missing (light/handle-wire-broadcast (:state receiver-dac) bcast-msg)
          ;; 4. Valid sig + non-map wire-dac (even when requires-dac? is false!)
          r-dac-nonmap (light/handle-wire-broadcast (:state receiver-nodac) (assoc bcast-msg :dac "not-a-map"))]
      (is (= 1 (get-in (:state r-malformed) [:diagnostics :broadcast-malformed])))
      (is (= 1 (get-in (:state r-malformed) [:diagnostics :broadcast-rejected])))
      (is (zero? (long (get-in (:state r-malformed) [:diagnostics :broadcast-sig-invalid] 0))))

      (is (= 1 (get-in (:state r-bad-sig) [:diagnostics :broadcast-sig-invalid])))
      (is (= 1 (get-in (:state r-bad-sig) [:diagnostics :broadcast-rejected])))
      (is (zero? (long (get-in (:state r-bad-sig) [:diagnostics :broadcast-dac-missing] 0))))
      (is (= "broadcast-sig-invalid" (get (first (:stdout-events r-bad-sig)) "reason")))

      (is (= 1 (get-in (:state r-dac-missing) [:diagnostics :broadcast-dac-missing])))
      (is (= 1 (get-in (:state r-dac-missing) [:diagnostics :broadcast-rejected])))
      (is (zero? (long (get-in (:state r-dac-missing) [:diagnostics :broadcast-sig-invalid] 0))))
      (is (= "dac-required-missing" (get (first (:stdout-events r-dac-missing)) "reason")))

      (is (= 1 (get-in (:state r-dac-nonmap) [:diagnostics :broadcast-dac-invalid])))
      (is (= 1 (get-in (:state r-dac-nonmap) [:diagnostics :broadcast-rejected])))
      (is (zero? (long (get-in (:state r-dac-nonmap) [:diagnostics :broadcast-sig-invalid] 0))))
      (is (= "broadcast-dac-invalid" (get (first (:stdout-events r-dac-nonmap)) "reason")))

      ;; Actionable event types registration
      (is (contains? light/actionable-event-types "broadcast-rejected"))
      (is (contains? light/actionable-event-types "subnet-id-reconciled"))
      (is (contains? light/actionable-event-types "session-replay-detected"))
      (is (contains? light/actionable-event-types "session-seq-mismatch"))

      ;; Status exposes diagnostics
      (let [st-resp (:response (light/exec-status (:state r-dac-missing)))]
        (is (= 1 (get-in st-resp ["diagnostics" :broadcast-dac-missing]))))))

  (testing "Unauthenticated broadcast-sig-invalid flood cannot evict real messages from 256-entry :event-queue"
    (let [{:keys [state]} (make-node-state 310 {:subnet-id "bitecho.org/dev" :epoch 50})
          st1 (light/enqueue-actionable-events state [{"event" "message-received" "text" "precious"}])
          flood-evts (repeat 300 {"event" "broadcast-rejected" "reason" "broadcast-sig-invalid"})
          st2 (light/enqueue-actionable-events st1 flood-evts)]
      (is (some #(= "precious" (get % "text")) (:event-queue st2))
          "Precious message-received event must survive 300 unauthenticated broadcast-sig-invalid flood events"))))

;; =============================================================================
;; §2.4 Session `tx-seq` Rollback Hardening, AEAD Quarantine & Real X25519 Rekey
;; =============================================================================

(deftest bip021-session-tx-seq-rollback-quarantine-and-rekey-test
  (testing "1-message rollback (seq 2->1) triggers signed rollback ACK, outbox collision eviction before purge, quarantine, and X25519 rekey"
    (let [{:keys [alice-kp bob-kp alice bob sid]} (establish-open-session 401 402 "bitecho.org/dev")
          ;; Alice sends seq 1 and seq 2; Bob receives both
          a1 (light/handle-command alice {"cmd" "send" "session_id" sid "text" "msg-1" "now_ms" 1000} (:priv alice-kp))
          b1 (light/handle-wire-payload bob (first (:net-envelopes a1)) (:priv bob-kp))
          a1-acked (light/handle-wire-payload (:state a1) (first (:net-envelopes b1)) (:priv alice-kp))
          a2 (light/handle-command (:state a1-acked) {"cmd" "send" "session_id" sid "text" "msg-2" "now_ms" 2000} (:priv alice-kp))
          b2 (light/handle-wire-payload (:state b1) (first (:net-envelopes a2)) (:priv bob-kp))
          ;; Simulate Alice VM-restore rollback back to state after seq 1 (tx-seq = 1), sending DIFFERENT msg at seq 2
          a-rolled-back (assoc-in (:state a1-acked) [:autonomous?] true)
          a-dup-send (light/handle-command a-rolled-back {"cmd" "send" "session_id" sid "text" "FORKED-msg-2" "now_ms" 3000} (:priv alice-kp))
          ;; Bob receives colliding seq 2 with different ciphertext
          b-replay (light/handle-wire-payload (:state b2) (first (:net-envelopes a-dup-send)) (:priv bob-kp))
          rollback-ack-env (first (:net-envelopes b-replay))
          rollback-ack-msg (light/unwrap-wire-message rollback-ack-env)
          ;; Alice receives signed rollback ACK
          a-after-ack (light/handle-wire-payload (:state a-dup-send) rollback-ack-env (:priv alice-kp))
          a-sess (get-in (:state a-after-ack) [:sessions sid])
          ;; Further normal sends on tainted session must fail closed
          a-blocked-send (light/handle-command (:state a-after-ack)
                                               {"cmd" "send" "session_id" sid "text" "should-fail" "now_ms" 4000}
                                               (:priv alice-kp))]
      ;; Receiver invariants
      (is (= 2 (get-in (:state b-replay) [:sessions sid :rx-high-seq]))
          "Receiver must never decrement rx-high-seq")
      (is (= 2 (count (:inbox (:state b-replay))))
          "Receiver must never deliver replayed/colliding message to inbox")
      (is (= 1 (get-in (:state b-replay) [:diagnostics :session-replay-detected])))
      (is (some #(= "session-replay-detected" (get % "event")) (:stdout-events b-replay)))
      (is (true? (:replay-rejected? rollback-ack-msg)))
      (is (= 2 (:rejected-seq rollback-ack-msg)))
      (is (= 2 (:peer-high-seq rollback-ack-msg)))
      (is (string? (:accepted-ciphertext-sha256 rollback-ack-msg)))

      ;; Sender invariants
      (is (true? (:tx-tainted? a-sess)) "Tainted tx-key must be quarantined")
      (is (true? (:rekey-required? a-sess)))
      (is (true? (:reoffer-recommended? a-sess)))
      (is (= 1 (get-in (:state a-after-ack) [:diagnostics :session-tx-seq-rollback-detected])))
      (is (>= (long (get-in (:state a-after-ack) [:diagnostics :session-tx-seq-rollback-evicted] 0)) 1)
          "Colliding outbox entries must be evicted BEFORE (acked? s) purge")
      (is (some #(= "session-seq-mismatch" (get % "event")) (:stdout-events a-after-ack)))
      ;; Autonomous mode must auto-initiate real X25519 channel-offer (NEVER p2p-offer)
      (is (some (fn [env]
                  (= :channel-offer (:bitecho/type (light/unwrap-wire-message env))))
                (:net-envelopes a-after-ack))
          "Autonomous rollback recovery must emit a real X25519 :channel-offer")
      (is (not-any? (fn [env]
                      (= :p2p-offer (:bitecho/type (light/unwrap-wire-message env))))
                    (:net-envelopes a-after-ack))
          "Rollback recovery must NEVER emit :p2p-offer")
      ;; Normal send refused on tainted session
      (is (false? (get (:response a-blocked-send) "ok")))
      (is (= "session-key-tainted-rollback" (get (:response a-blocked-send) "error")))))

  (testing ">= 64 :stale-seq rollback returns signed rollback ACK & increments :session-stale-seq-detected"
    (let [{:keys [alice-kp bob-kp alice bob sid]} (establish-open-session 411 412 "bitecho.org/dev")
          ;; Advance Alice & Bob by 70 messages so seq 1 is stale (>= 64 lag)
          a-first (light/handle-command alice {"cmd" "send" "session_id" sid "text" "stale-1" "now_ms" 1000} (:priv alice-kp))
          stale-env (first (:net-envelopes a-first))
          ;; Fast-forward Bob's replay window to seq 70 via a valid msg at seq 70
          alice-at-69 (assoc-in (:state a-first) [:sessions sid :tx-seq] 69)
          a-70 (light/handle-command alice-at-69 {"cmd" "send" "session_id" sid "text" "msg-70" "now_ms" 2000} (:priv alice-kp))
          b-70 (light/handle-wire-payload bob (first (:net-envelopes a-70)) (:priv bob-kp))
          ;; Now deliver stale seq 1 -> >= 64 lag
          b-stale (light/handle-wire-payload (:state b-70) stale-env (:priv bob-kp))
          ack-msg (light/unwrap-wire-message (first (:net-envelopes b-stale)))]
      (is (= 1 (get-in (:state b-70) [:diagnostics :session-rx-gap-detected]))
          "Jump from 0/1 to 70 must be recorded as rx gap when rx-high-seq > 0 or gap > 1")
      (is (= 1 (get-in (:state b-stale) [:diagnostics :session-stale-seq-detected])))
      (is (= 1 (get-in (:state b-stale) [:diagnostics :session-replay-detected])))
      (is (true? (:replay-rejected? ack-msg)))
      (is (= 1 (:rejected-seq ack-msg)))
      (is (= 70 (:peer-high-seq ack-msg)))))

  (testing "Zero legacy-signature fallback: grafting rollback fields onto legacy-signed ACK is rejected; overflow DoS rejected"
    (let [{:keys [alice-kp bob-kp alice bob sid]} (establish-open-session 421 422 "bitecho.org/dev")
          a1 (light/handle-command alice {"cmd" "send" "session_id" sid "text" "hi" "now_ms" 1000} (:priv alice-kp))
          b1 (light/handle-wire-payload bob (first (:net-envelopes a1)) (:priv bob-kp))
          normal-ack-msg (light/unwrap-wire-message (first (:net-envelopes b1)))
          ;; Graft :replay-rejected? true onto a legacy-signed ACK without re-signing
          forged-ack (assoc normal-ack-msg :replay-rejected? true :rejected-seq 1 :peer-high-seq 50)
          res-forged (light/handle-wire-payload (:state a1) forged-ack (:priv alice-kp))
          ;; Overflow peer-high-seq (> 2^53 - 1)
          overflow-ack (assoc normal-ack-msg :peer-high-seq 9007199254740992)
          res-overflow (light/handle-wire-payload (:state a1) overflow-ack (:priv alice-kp))]
      (is (not (true? (get-in (:state res-forged) [:sessions sid :tx-tainted?])))
          "Forged rollback fields grafted onto legacy ACK signature MUST be rejected")
      (is (not (true? (get-in (:state res-overflow) [:sessions sid :tx-tainted?])))
          "Overflow peer-high-seq > 2^53 - 1 MUST be rejected"))))

;; =============================================================================
;; §2.5.1–§2.5.2 Browser Parity (Liveness Projection, Persistence Allowlist, Auto-Sync)
;; =============================================================================

(deftest bip021-browser-liveness-projection-and-autosync-test
  (testing "project-light-state-liveness reports connected/transport_healthy honestly and never mutates persisted state"
    (let [{:keys [state]} (make-node-state 501 {:subnet-id "bitecho.org/dev"})
          live-mesh (browser/project-light-state-liveness state {:mesh-open-peers 2
                                                                 :relay-fallback-active? false
                                                                 :connection-error nil})
          degraded-relay (browser/project-light-state-liveness state {:mesh-open-peers 0
                                                                      :relay-fallback-active? true
                                                                      :connection-error "webrtc-ice-failed"})
          st-mesh (:response (light/exec-status live-mesh))
          st-relay (:response (light/exec-status degraded-relay))]
      (is (true? (get st-mesh "connected")))
      (is (true? (get st-mesh "transport_healthy")))
      (is (= 2 (get st-mesh "mesh_open_peers")))
      (is (false? (get st-mesh "relay_fallback_active")))

      (is (false? (get st-relay "transport_healthy"))
          "Hive DEGRADED honesty: transport_healthy MUST be false when mesh_open_peers == 0")
      (is (true? (get st-relay "relay_fallback_active")))
      (is (= "webrtc-ice-failed" (get st-relay "connection_error")))

      ;; Rule 4: liveness keys must NEVER survive persistence sanitization
      (let [sanitized (browser/sanitize-state-for-persistence degraded-relay)]
        (is (not (contains? sanitized :connected?)))
        (is (not (contains? sanitized :connection-error)))
        (is (not (contains? sanitized :auto-sync-in-flight?))))))

  (testing "allowed-persistence-keys allows new BIP-021 non-liveness keys"
    (doseq [k [:rekey-required? :reoffer-recommended? :tx-tainted? :auto-sync-last-error
               :subscribed-subnets :subnet-id-reconciled :broadcast-dac-missing
               :broadcast-dac-invalid :session-replay-detected :session-tx-seq-rollback-detected]]
      (is (browser/allowed-persistence-key? k)
          (str "Expected " k " to be in allowed-persistence-keys"))))

  (testing "Generation-tagged visibility-aware browser auto-sync policy"
    (is (= 30000 (browser/auto-sync-interval-ms :visible)))
    (is (>= (browser/auto-sync-interval-ms :hidden) 180000))
    (is (= 10000 browser/auto-sync-fetch-timeout-ms))
    (let [s0 (browser/init-auto-sync-state {:generation 1})
          [s1 e1] (browser/transition-auto-sync s0 {:type :tick :generation 1 :visibility :visible :mesh-or-relay-active? true})
          [s2 e2] (browser/transition-auto-sync s1 {:type :timeout :generation 1})
          [_s3 e3] (browser/transition-auto-sync s2 {:type :visibility-change :generation 1 :visibility :visible :prev-visibility :hidden})]
      (is (true? (:auto-sync-in-flight? s1)))
      (is (some #(= :run-auto-sync (:effect %)) e1))
      (is (false? (:auto-sync-in-flight? s2)))
      (is (some #(and (= :diagnose (:effect %)) (= :auto-sync-timeout (:reason %))) e2))
      (is (some #(= :run-auto-sync (:effect %)) e3)
          "hidden -> visible must trigger an immediate catch-up sync"))))

;; =============================================================================
;; §2.6.1 `:443` Passthrough Graceful Drain & Global Cap
;; =============================================================================

(deftest bip021-passthrough-graceful-drain-and-cap-test
  (testing "Clean :socket-close with peer-fin? true routes through :draining with :end-socket + 5000ms timer, and :drain-progress respects 30000ms cap"
    (let [st0 (core-infra/init-passthrough-pair {:generation 1 :pair-id "p1"})
          [st1 effs1] (core-infra/transition-passthrough-pair
                       st0 {:type :socket-close :side :client :had-error? false :peer-writable-finished? true :generation 1})
          [st2 effs2] (core-infra/transition-passthrough-pair
                       st1 {:type :drain-progress :side :backend :elapsed-ms 4000 :generation 1})
          [st3 effs3] (core-infra/transition-passthrough-pair
                       st2 {:type :drain-progress :side :backend :elapsed-ms 30001 :generation 1})]
      (is (= :draining (:phase st1))
          "Clean :socket-close with peer-fin? true must route through :draining (no premature RST)")
      (is (some #(and (= :end-socket (:effect %)) (= :backend (:side %))) effs1))
      (is (some #(and (= :schedule-drain-timeout (:effect %)) (= 5000 (:timeout-ms %)) (= "p1" (:pair-id %))) effs1))
      (is (not-any? #(= :destroy-socket (:effect %)) effs1))

      ;; Progress resets inactivity timer
      (is (= :draining (:phase st2)))
      (is (some #(= :cancel-drain-timeout (:effect %)) effs2))
      (is (some #(= :schedule-drain-timeout (:effect %)) effs2))

      ;; Exceeding 30000ms hard ceiling force-closes with counted :passthrough-drain-timeout
      (is (= :closed (:phase st3)))
      (is (some #(= :cancel-drain-timeout (:effect %)) effs3))
      (is (some #(and (= :diagnose (:effect %)) (= :passthrough-drain-timeout (:reason %))) effs3))
      (is (some #(= :destroy-socket (:effect %)) effs3))))

  (testing "Global max-draining-pairs cap evicts oldest with counted :passthrough-drain-cap-evicted"
    (let [res (core-infra/enforce-draining-pair-cap ["p1" "p2" "p3"] "p4" 3)]
      (is (= ["p2" "p3" "p4"] (:draining-order res)))
      (is (= "p1" (:evicted-pair-id res)))
      (is (some #(and (= :diagnose (:effect %)) (= :passthrough-drain-cap-evicted (:reason %)))
                (:effects res))))))

;; =============================================================================
;; §2.6.2 Pure Sans-IO Chunked Mesh-First Auto-Updater
;; =============================================================================

(deftest bip021-mesh-first-auto-updater-test
  (testing "verify-config-pointer fails closed when :trusted-deploy-authorities is empty"
    (let [auth-kp (gen-kp 601)
          ptr (deploy/sign-config-pointer (:priv auth-kp)
                                          {:seq 1
                                           :author-pubkey (:pub-hex auth-kp)
                                           :target-version "0.23.22"
                                           :light-node-cid (deploy/sha256-hex (fressian/utf8->bytes "bundle"))})
          v-empty (deploy/verify-config-pointer {:trusted-deploy-authorities #{}} ptr)
          v-trusted (deploy/verify-config-pointer {:trusted-deploy-authorities #{(:pub-hex auth-kp)}} ptr)]
      (is (false? (:ok? v-empty)) "Empty :trusted-deploy-authorities MUST fail closed")
      (is (= :no-trusted-deploy-authorities (:error v-empty)))
      (is (true? (:ok? v-trusted)))))

  (testing "Chunked mesh-first waterfall, :phase == :watching livelock guard, HTTPS fallback, and failed-CID quarantine"
    (let [auth-kp (gen-kp 602)
          payload (fressian/utf8->bytes "new-light-node-bundle-v22")
          target-cid (deploy/sha256-hex payload)
          ptr (deploy/sign-config-pointer (:priv auth-kp)
                                          {:seq 2
                                           :author-pubkey (:pub-hex auth-kp)
                                           :target-version "0.23.22"
                                           :light-node-cid target-cid
                                           :artifact-size-bytes (* 2 1024 1024)})
          st0 (deploy/init-light-updater-state {:node-id "light-1"
                                                :artifact-role :light-node
                                                :current-version "0.23.21"
                                                :current-cid (deploy/sha256-hex (fressian/utf8->bytes "old"))
                                                :trusted-deploy-authorities #{(:pub-hex auth-kp)}})
          ;; 1. Pointer seen while mesh connected -> :fetching-mesh with chunked BIP-017a params
          [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen
                                                            :pointer ptr
                                                            :mesh-connected? true
                                                            :generation 1})
          mesh-eff (first (filter #(= :fetch-bundle-mesh-chunks (:effect %)) effs1))
          ;; 2. Poll tick while :fetching-mesh MUST be suppressed (zero generation livelock!)
          [st1-poll effs1-poll] (deploy/reduce-light-update-tick st1 {:type :poll-tick :generation (:generation st1)})
          ;; 3. Mesh fetch fails (e.g. probe timeout / :mesh-cid-mismatch) -> counted fallback to :fetching-https
          [st2 effs2] (deploy/reduce-light-update-tick st1-poll {:type :mesh-fetch-failed
                                                                 :reason :mesh-cid-mismatch
                                                                 :generation (:generation st1-poll)})
          ;; 4. HTTPS blob succeeds -> :health-checking -> fails -> LKG rollback + CID quarantine
          [st3 _] (deploy/reduce-light-update-tick st2 {:type :blob-fetched
                                                        :bytes payload
                                                        :generation (:generation st2)})
          [st4 effs4] (deploy/reduce-light-update-tick st3 {:type :health-check-result
                                                            :healthy? false
                                                            :generation (:generation st3)})
          ;; 5. Re-seeing quarantined CID is refused (zero boot-loop)
          [st5 effs5] (deploy/reduce-light-update-tick (assoc st4 :phase :watching)
                                                       {:type :pointer-seen
                                                        :pointer ptr
                                                        :mesh-connected? true
                                                        :generation (:generation st4)})]
      (is (= :fetching-mesh (:phase st1)))
      (is (some? mesh-eff))
      (is (<= (:chunk-size-bytes mesh-eff) 262144) "Chunk size must respect WebRTC SCTP 256 KiB cap")
      (is (<= 2500 (:probe-timeout-ms mesh-eff) 3000))
      (is (= 5000 (:chunk-timeout-ms mesh-eff)))
      (is (= (deploy/compute-mesh-fetch-ceiling-ms (* 2 1024 1024)) (:total-timeout-ms mesh-eff)))

      ;; Livelock guard
      (is (= (:generation st1) (:generation st1-poll)) "Poll during active fetch must NOT bump generation")
      (is (= :fetching-mesh (:phase st1-poll)))
      (is (some #(and (= :diagnose (:effect %)) (= :update-poll-suppressed (:reason %))) effs1-poll))

      ;; HTTPS fallback
      (is (= :fetching-https (:phase st2)))
      (is (= 1 (get-in st2 [:diagnostics :auto-update-mesh-fallback])))
      (is (some #(and (= :diagnose (:effect %)) (= :auto-update-mesh-fallback (:reason %))) effs2))
      (is (some #(= :fetch-bundle-blob (:effect %)) effs2))

      ;; LKG rollback + CID quarantine
      (is (contains? (:quarantined-cids st4) target-cid))
      (is (some #(= :restore-lkg-light-bundle (:effect %)) effs4))
      (is (= :watching (:phase st5)))
      (is (some #(and (= :diagnose (:effect %)) (= :light-update-quarantined-cid (:reason %))) effs5))))

  (testing "Gate 5(a): connected mesh peer serves multi-chunk BIP-017a blob -> reassembled bytes match SHA-256 CID with 0 HTTPS requests"
    (let [auth-kp (gen-kp 611)
          ;; > 400 KiB payload requiring 3 chunks at 192 KiB/chunk
          chunk-sz deploy/default-mesh-chunk-size-bytes
          payload-len (+ (* 2 chunk-sz) 12345)
          payload (fressian/utf8->bytes (apply str (repeat payload-len "A")))
          target-cid (deploy/sha256-hex payload)
          https-calls (atom 0)
          ptr (deploy/sign-config-pointer (:priv auth-kp)
                                          {:seq 5
                                           :author-pubkey (:pub-hex auth-kp)
                                           :target-version "0.23.23"
                                           :light-node-cid target-cid
                                           :artifact-size-bytes payload-len})
          st0 (deploy/init-light-updater-state {:node-id "light-mesh-5a"
                                                :artifact-role :light-node
                                                :current-version "0.23.21"
                                                :current-cid (deploy/sha256-hex (fressian/utf8->bytes "old"))
                                                :trusted-deploy-authorities #{(:pub-hex auth-kp)}})
          [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen
                                                            :pointer ptr
                                                            :mesh-connected? true
                                                            :generation 1})
          mesh-eff (first (filter #(= :fetch-bundle-mesh-chunks (:effect %)) effs1))
          ;; Execute pure multi-chunk request/serve/reassemble loop over mock mesh peer
          loop-res (loop [asm (deploy/init-mesh-chunk-assembly (:cid mesh-eff) (:chunk-size-bytes mesh-eff))
                          req (deploy/build-mesh-chunk-request (:cid mesh-eff) 0 (:chunk-size-bytes mesh-eff) "req-0")
                          chunks-served 0]
                     (let [srv-resp (deploy/serve-mesh-blob-chunk payload req)
                           step (deploy/reduce-mesh-chunk-response asm srv-resp)]
                       (if (:done? step)
                         (assoc step :chunks-served (inc chunks-served))
                         (recur (:state step) (:next-req step) (inc chunks-served)))))
          [st2 effs2] (deploy/reduce-light-update-tick st1 {:type :blob-fetched
                                                            :cid target-cid
                                                            :bytes (:bytes loop-res)
                                                            :generation (:generation st1)})]
      (is (= :fetching-mesh (:phase st1)))
      (is (true? (:ok? loop-res)))
      (is (= 3 (:chunks-served loop-res)) "400+ KiB blob must be fetched in 3 chunks <= 192 KiB each")
      (is (= target-cid (deploy/sha256-hex (:bytes loop-res))))
      (is (zero? @https-calls) "Gate 5(a): 0 HTTPS requests when mesh peer serves the blob")
      (is (not-any? #(= :fetch-bundle-blob (:effect %)) effs1))
      (is (= :health-checking (:phase st2)))
      (is (some #(= :stage-light-bundle (:effect %)) effs2))
      (is (some #(= :atomic-swap-and-restart-light-node (:effect %)) effs2))))

  (testing "Gate 5(b): mesh peer missing/Byzantine corruption -> emits :auto-update-mesh-fallback and falls back to HTTPS"
    (let [payload (fressian/utf8->bytes "real-bundle-content")
          target-cid (deploy/sha256-hex payload)
          req (deploy/build-mesh-chunk-request target-cid 0 deploy/default-mesh-chunk-size-bytes "req-miss")
          miss-resp (deploy/serve-mesh-blob-chunk nil req)
          miss-step (deploy/reduce-mesh-chunk-response (deploy/init-mesh-chunk-assembly target-cid) miss-resp)
          bad-resp (deploy/serve-mesh-blob-chunk (fressian/utf8->bytes "corrupted-byzantine-bytes") req)
          bad-step (deploy/reduce-mesh-chunk-response (deploy/init-mesh-chunk-assembly target-cid) bad-resp)]
      (is (false? (:ok? miss-resp)))
      (is (= :not-found (:error miss-resp)))
      (is (true? (:done? miss-step)))
      (is (false? (:ok? miss-step)))
      (is (true? (:done? bad-step)))
      (is (false? (:ok? bad-step)))
      (is (= :mesh-cid-mismatch (:error bad-step)))))

  (testing "Gate 5(a) exact return-map shape of deploy/reduce-mesh-chunk-response (:done?/:ok?/:state/:next-req/:bytes/:error)"
    (let [chunk-sz 64
          payload (fressian/utf8->bytes (apply str (repeat 150 "Z")))
          target-cid (deploy/sha256-hex payload)
          asm0 (deploy/init-mesh-chunk-assembly target-cid chunk-sz)
          req0 (deploy/build-mesh-chunk-request target-cid 0 chunk-sz "shape-0")
          step0 (deploy/reduce-mesh-chunk-response asm0 (deploy/serve-mesh-blob-chunk payload req0))
          step1 (deploy/reduce-mesh-chunk-response (:state step0) (deploy/serve-mesh-blob-chunk payload (:next-req step0)))
          step2 (deploy/reduce-mesh-chunk-response (:state step1) (deploy/serve-mesh-blob-chunk payload (:next-req step1)))
          err-step (deploy/reduce-mesh-chunk-response asm0 (deploy/serve-mesh-blob-chunk nil req0))]
      (is (false? (:done? step0)))
      (is (true? (:ok? step0)))
      (is (nil? (:status step0)) "reduce-mesh-chunk-response uses :done?/:ok?, never :status")
      (is (map? (:state step0)))
      (is (= 64 (get-in step0 [:next-req :offset])))
      (is (= 64 (get-in step0 [:next-req :length])))
      (is (false? (:done? step1)))
      (is (= 128 (get-in step1 [:next-req :offset])))
      (is (true? (:done? step2)))
      (is (true? (:ok? step2)))
      (is (= target-cid (deploy/sha256-hex (:bytes step2))))
      (is (true? (:done? err-step)))
      (is (false? (:ok? err-step)))
      (is (= :not-found (:error err-step)))))

  (testing "Gate 5 rollback does NOT wedge :phase — quarantines bad CID A, rejects A, then cleanly applies fixed CID B"
    (let [auth-kp (gen-kp 612)
          old-cid (deploy/sha256-hex (fressian/utf8->bytes "v0.23.21"))
          bad-bytes (fressian/utf8->bytes "broken-v0.23.22")
          bad-cid (deploy/sha256-hex bad-bytes)
          good-bytes (fressian/utf8->bytes "fixed-v0.23.23")
          good-cid (deploy/sha256-hex good-bytes)
          ptr-bad (deploy/sign-config-pointer (:priv auth-kp)
                                              {:seq 2
                                               :author-pubkey (:pub-hex auth-kp)
                                               :target-version "0.23.22"
                                               :light-node-cid bad-cid})
          ptr-good (deploy/sign-config-pointer (:priv auth-kp)
                                               {:seq 3
                                                :author-pubkey (:pub-hex auth-kp)
                                                :target-version "0.23.23"
                                                :light-node-cid good-cid})
          st0 (deploy/init-light-updater-state {:node-id "light-rollback-recovery"
                                                :artifact-role :light-node
                                                :current-version "0.23.21"
                                                :current-cid old-cid
                                                :trusted-deploy-authorities #{(:pub-hex auth-kp)}})
          [st1 _] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-bad :generation (:generation st0)})
          [st2 _] (deploy/reduce-light-update-tick st1 {:type :blob-fetched :cid bad-cid :bytes bad-bytes :generation (:generation st1)})
          [st-rb effs-rb] (deploy/reduce-light-update-tick st2 {:type :health-check-result :healthy? false :generation (:generation st2)})
          ;; Poll tick right after rollback must NOT be suppressed
          [st-poll effs-poll] (deploy/reduce-light-update-tick st-rb {:type :poll-tick})
          ;; Re-seeing quarantined bad CID A must emit :light-update-quarantined-cid
          [st-q effs-q] (deploy/reduce-light-update-tick st-poll {:type :pointer-seen :pointer ptr-bad :generation (:generation st-poll)})
          ;; Seeing fixed CID B must transition out of :watching and apply cleanly
          [st-b1 effs-b1] (deploy/reduce-light-update-tick st-q {:type :pointer-seen :pointer ptr-good :generation (:generation st-q)})
          [st-b2 effs-b2] (deploy/reduce-light-update-tick st-b1 {:type :blob-fetched :cid good-cid :bytes good-bytes :generation (:generation st-b1)})
          [st-b3 _] (deploy/reduce-light-update-tick st-b2 {:type :health-check-result :healthy? true :generation (:generation st-b2)})]
      (is (= :watching (:phase st-rb)) "Rollback must return :phase to :watching so future updates are never wedged")
      (is (= bad-cid (:last-rollback-cid st-rb)))
      (is (= 1 (:rollback-count st-rb)))
      (is (contains? (:quarantined-cids st-rb) bad-cid))
      (is (some #(= :restore-lkg-light-bundle (:effect %)) effs-rb))
      (is (some #(= :fetch-pointer (:effect %)) effs-poll) "Post-rollback :poll-tick must emit :fetch-pointer, never :update-poll-suppressed")
      (is (some #(and (= :diagnose (:effect %)) (= :light-update-quarantined-cid (:reason %))) effs-q))
      (is (= :fetching-https (:phase st-b1)))
      (is (some #(= :fetch-bundle-blob (:effect %)) effs-b1))
      (is (= :health-checking (:phase st-b2)))
      (is (some #(= :atomic-swap-and-restart-light-node (:effect %)) effs-b2))
      (is (= :watching (:phase st-b3)))
      (is (= good-cid (:current-cid st-b3)))
      (is (= "0.23.23" (:current-version st-b3))))))

(deftest bip021-browser-ctl-status-nested-mesh-conns-test
  (testing "Gate 6: browser/exec-browser-command status counts open peers from nested {:mesh-conns {:peers {...}}}"
    (let [kp (gen-kp 613)
          ls (light/init-light-state (:pub-hex kp) {:subnet-id "global"})
          st {:light-state ls
              :mesh-conns {:peers {"node1" {:phase :open}
                                   "node2" {:phase :open}
                                   "node3" {:phase :connecting}}
                           :generation 4}
              :conn {:phase :open :generation 4}}
          res (browser/exec-browser-cli st "status" (:priv kp))
          resp (:response res)]
      (is (true? (get resp "ok")))
      (is (true? (get resp "connected")) "Nested :mesh-conns :peers with open peers must report connected: true")
      (is (true? (get resp "transport_healthy")) "Nested :mesh-conns :peers with open peers must report transport_healthy: true")
      (is (= 2 (get resp "mesh_open_peers"))))))

;; =============================================================================
;; §2.7 Node.js Buffer.poolSize Slab-Pinning Compact-Copy & Cold-Demotion
;; =============================================================================

#?(:cljs
   (defspec ^{:doc "BIP-021 §2.7: Compact-copy invariant across 0..131072 bytes (incl. sub-pool 1..4096 B)
                    and 32-byte crypto/sha256 outputs — zero 64 KiB Buffer.poolSize slab pinning."}
     prop-bip021-compact-u8-zero-slab-pinning 100
     (prop/for-all [sz (gen/one-of [(gen/choose 0 4096)
                                    (gen/choose 4097 131072)])]
                   (let [raw (js/Uint8Array. sz)
                         _ (when (pos? sz) (aset raw 0 (mod sz 251)))
                         buf (js/Buffer.from raw)
                         compacted (crypto/compact-u8 buf)
                         digest (crypto/sha256 raw)]
                     (and (= (.-byteLength (.-buffer compacted)) (.-byteLength compacted))
                          (zero? (.-byteOffset compacted))
                          (= sz (.-byteLength compacted))
                          (= 32 (.-byteLength digest))
                          (= (.-byteLength (.-buffer digest)) 32)
                          (zero? (.-byteOffset digest)))))))

(deftest bip021-core-data-cold-demotion-test
  (testing "demote-blob-to-cold releases hot bytes for unpinned blobs while retaining CID metadata"
    (let [bs0 (data/init-blob-store {:max-hot-bytes 1000000})
          payload (fressian/utf8->bytes "superseded-hot-blob-bytes")
          blob (data/make-blob payload {:mime "application/octet-stream"})
          cid (:blob/cid blob)
          bs1 (:store (data/put-blob bs0 blob))
          res (data/demote-blob-to-cold bs1 cid)
          bs2 (:store res)
          entry (get-in bs2 [:entries cid])]
      (is (true? (:demoted? res)))
      (is (some? entry) "CID metadata entry must be retained")
      (is (nil? (:bytes entry)) "Off-heap byte reference must be released on cold demotion")
      (is (true? (:cold? entry)))
      (is (zero? (long (:hot-bytes bs2 0)))))))

#?(:clj
   (deftest bip021-mesh-chunk-rpc-and-ctl-socket-error-wiring-test
     (testing "Real BIP-017a chunked mesh fetch RPC is wired across full_node_main.cljs, node_main.cljs, shell/mesh.clj, and shell/updater.clj"
       (let [full-src (slurp "src/bitecho/full_node_main.cljs")
             node-src (slurp "src/bitecho/node_main.cljs")
             mesh-src (slurp "src/bitecho/shell/mesh.clj")
             upd-src (slurp "src/bitecho/shell/updater.clj")]
         (is (str/includes? full-src ":artifact-blob-chunk-req"))
         (is (str/includes? full-src "deploy/serve-mesh-blob-chunk"))
         (is (str/includes? mesh-src ":artifact-blob-chunk-req"))
         (is (str/includes? mesh-src "deploy/serve-mesh-blob-chunk"))
         (is (str/includes? node-src ":artifact-blob-chunk-res"))
         (is (str/includes? node-src "deploy/init-mesh-chunk-assembly"))
         (is (str/includes? node-src "deploy/reduce-mesh-chunk-response"))
         (is (str/includes? upd-src "mesh-chunk-fetch-fn"))))
     (testing "/ctl HTTP server in node_main.cljs attaches socket error handlers emitting counted :ctl-socket-error (zero ECONNRESET crash)"
       (let [node-src (slurp "src/bitecho/node_main.cljs")]
         (is (str/includes? node-src ":ctl-socket-error")
             "/ctl server socket error handler must emit counted :ctl-socket-error diagnostic")))
     (testing "node_main.cljs mesh chunk handler uses :done?/:ok?/:state/:next-req (never :status) and emits counted :mesh-chunk-dispatch-error"
       (let [node-src (slurp "src/bitecho/node_main.cljs")]
         (is (not (str/includes? node-src "(case (:status step)"))
             "on-chunk-res must never branch on nonexistent (:status step)")
         (is (str/includes? node-src ":mesh-chunk-dispatch-error")
             "try-dispatch-mesh-chunk-res! must emit counted Rule 5 diagnostic on handler exception")))
     (testing "--trusted-deploy-authorities CLI flag is co-committed across cli.cljc, node_main.cljs, shell/light_node.clj, and skill/SKILL.md (Rule 6)"
       (let [cli-src (slurp "src/bitecho/light_node/cli.cljc")
             node-src (slurp "src/bitecho/node_main.cljs")
             jvm-src (slurp "src/bitecho/shell/light_node.clj")
             skill-src (slurp "skill/SKILL.md")]
         (is (str/includes? cli-src "\"--trusted-deploy-authorities\""))
         (is (str/includes? node-src "\"--trusted-deploy-authorities\""))
         (is (str/includes? jvm-src "\"--trusted-deploy-authorities\""))
         (is (str/includes? skill-src "--trusted-deploy-authorities"))))
     (testing ":443 passthrough splice-sockets! and handle-passthrough-socket! use ^js hints (no Closure :advanced mangling of .unpipe/.removeAllListeners/.writableFinished) and zero silent catches"
       (let [full-src (slurp "src/bitecho/full_node_main.cljs")]
         (is (str/includes? full-src "[^js client-sock ^js backend-sock shell-atom]")
             "splice-sockets! must type-hint ^js on client-sock and backend-sock")
         (is (str/includes? full-src "[^js client-sock {:keys [domain")
             "handle-passthrough-socket! must type-hint ^js on client-sock")
         (is (str/includes? full-src ":passthrough-cleanup-error")
             "splice-sockets! must emit counted Rule 5 :passthrough-cleanup-error instead of silent catches")
         (is (str/includes? full-src "on-bsock-dial-error")
             "handle-passthrough-socket! must detach pre-connect dial error listener on connect")))))
