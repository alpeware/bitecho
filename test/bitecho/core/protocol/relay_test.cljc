(ns bitecho.core.protocol.relay-test
  "Cross-platform generative and invariant test suite for HTTP Gateway Relay (`bitecho.core.protocol.relay`).
   Covers Rule 1 (Strict TDD & Generative Invariants), Rule 2 (Pure Sans-IO), Rule 5 (Zero Silent Failures)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.sieve.core :as sieve]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            #?(:clj [clojure.test.check.properties :refer [for-all]]
               :cljs [clojure.test.check.properties :refer-macros [for-all]])))

;; -----------------------------------------------------------------------------
;; Helpers
;; -----------------------------------------------------------------------------

(defn- make-signed-envelope
  [kp recipient text]
  (let [sender (basalt/bytes->hex (:public kp))
        payload (fressian/utf8->bytes text)
        sig (crypto/sign (:private kp) payload)
        sig-hex (if (string? sig) sig (basalt/bytes->hex sig))]
    {:sender sender
     :recipient recipient
     :payload payload
     :signature sig-hex}))

(defn- make-signed-gossip-envelope
  [kp text burn-amt msg-id]
  (let [sender (basalt/bytes->hex (:public kp))
        payload (fressian/utf8->bytes text)
        msg (cond-> (sieve/wrap-message payload (:private kp) (:public kp) burn-amt)
              msg-id (assoc :message-id msg-id))]
    {:type :receive-gossip
     :sender sender
     :message msg
     :signature (basalt/bytes->hex (crypto/sign (:private kp) (fressian/encode-canonical msg)))}))

;; -----------------------------------------------------------------------------
;; 1. Generative Property: Deduplication & Monotonic Delivery
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property 1: Valid signed envelopes submitted to relay are routed to recipient inboxes and deduplicated deterministically by SHA-256 ID."}
  prop-envelope-submission-and-deduplication 50
  (for-all [text gen/string-alphanumeric]
           (let [kp-sender (crypto/generate-keypair)
                 kp-recip (crypto/generate-keypair)
                 recip-pub (basalt/bytes->hex (:public kp-recip))
                 env (make-signed-envelope kp-sender recip-pub (str "msg-" text))
                 st0 (relay/init-relay-state)
                 r1 (relay/reduce-relay st0 {:type :relay-submit :envelope env :now-ms 1000})
                 st1 (:state r1)
                 r2 (relay/reduce-relay st1 {:type :relay-submit :envelope env :now-ms 2000})
                 st2 (:state r2)]
             (and (true? (:ok? r1))
                  (false? (:duplicate? r1))
                  (= 1 (count (get-in st1 [:inboxes recip-pub])))
                  (true? (:ok? r2))
                  (true? (:duplicate? r2))
                  (= 1 (count (get-in st2 [:inboxes recip-pub])))
                  (= 1 (get-in st2 [:diagnostics :duplicates]))))))

;; -----------------------------------------------------------------------------
;; 2. Generative Property: Proof-of-Possession Poll & Replay Rejection
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property 2: Proof-of-Possession (PoP) verify-poll-request strictly authenticates key possession, rejects clock skew > max-skew-ms, and rejects nonce replay fail-closed."}
  prop-poll-proof-of-possession-and-replay 50
  (for-all [since-seq gen/nat
            skew-delta (gen/choose 1 60000)]
           (let [kp (crypto/generate-keypair)
                 pub (basalt/bytes->hex (:public kp))
                 now-ms 1000000
                 ts-valid (+ now-ms skew-delta)
                 ts-expired (+ now-ms 500000) ;; > 300,000 max skew
                 nonce-1 "test-nonce-1"
                 sig-valid (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq since-seq :timestamp-ms ts-valid :nonce nonce-1})
                 sig-expired (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq since-seq :timestamp-ms ts-expired :nonce nonce-1})
                 st0 (relay/init-relay-state)
          ;; Valid poll
                 r1 (relay/reduce-relay st0 {:type :relay-poll
                                             :pubkey pub
                                             :since-seq since-seq
                                             :timestamp-ms ts-valid
                                             :nonce nonce-1
                                             :signature sig-valid
                                             :now-ms now-ms})
          ;; Replay with same nonce
                 r-replay (relay/reduce-relay (:state r1) {:type :relay-poll
                                                           :pubkey pub
                                                           :since-seq since-seq
                                                           :timestamp-ms ts-valid
                                                           :nonce nonce-1
                                                           :signature sig-valid
                                                           :now-ms now-ms})
          ;; Clock skew exceeded
                 r-skew (relay/reduce-relay st0 {:type :relay-poll
                                                 :pubkey pub
                                                 :since-seq since-seq
                                                 :timestamp-ms ts-expired
                                                 :nonce "nonce-skew"
                                                 :signature sig-expired
                                                 :now-ms now-ms})]
             (and (true? (:ok? r1))
                  (= pub (get-in r1 [:response "pubkey"]))
                  (false? (:ok? r-replay))
                  (= :poll-replay-rejected (:error r-replay))
                  (false? (:ok? r-skew))
                  (= :poll-skew-exceeded (:error r-skew))))))

;; -----------------------------------------------------------------------------
;; 3. Generative Property: Bounded Inbox Eviction & Ack Pruning
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property 3: Inboxes strictly enforce :max-inbox-size bounds and prune entries up to ack-seq on :relay-ack."}
  prop-bounded-inbox-and-ack-pruning 30
  (for-all [total-count (gen/choose 10 25)]
           (let [max-inbox 5
                 st0 (relay/init-relay-state {:max-inbox-size max-inbox})
                 kp-sender (crypto/generate-keypair)
                 kp-recip (crypto/generate-keypair)
                 recip-pub (basalt/bytes->hex (:public kp-recip))
          ;; Submit multiple envelopes
                 final-st (reduce (fn [st idx]
                                    (let [env (make-signed-envelope kp-sender recip-pub (str "msg-" idx))
                                          res (relay/reduce-relay st {:type :relay-submit :envelope env :now-ms (+ 1000 idx)})]
                                      (:state res)))
                                  st0
                                  (range total-count))
                 inbox (get-in final-st [:inboxes recip-pub])
                 max-seq (long (:relay-seq (last inbox)))
                 ack-target (- max-seq 2)
          ;; Send ack for ack-target
                 ack-nonce (str "ack-nonce-" total-count)
                 ack-sig (relay/sign-poll-request (:private kp-recip) {:pubkey recip-pub :since-seq ack-target :timestamp-ms 2000 :nonce ack-nonce})
                 ack-res (relay/reduce-relay final-st {:type :relay-ack
                                                       :pubkey recip-pub
                                                       :ack-seq ack-target
                                                       :timestamp-ms 2000
                                                       :nonce ack-nonce
                                                       :signature ack-sig
                                                       :now-ms 2000})
                 remaining-inbox (get-in (:state ack-res) [:inboxes recip-pub])]
             (and (<= (count inbox) max-inbox)
                  (true? (:ok? ack-res))
                  (= (count remaining-inbox) 2)
                  (every? #(> (long (:relay-seq %)) ack-target) remaining-inbox)))))

;; -----------------------------------------------------------------------------
;; 4. Unit Tests: Fail-Closed Enforcements (Rule 5)
;; -----------------------------------------------------------------------------

(deftest test-oversized-payload-rejection
  (testing "Payloads exceeding :max-payload-bytes are rejected fail-closed with counted :diagnose effect"
    (let [max-bytes 1024
          st0 (relay/init-relay-state {:max-payload-bytes max-bytes})
          kp (crypto/generate-keypair)
          huge-text (apply str (repeat 2048 "x"))
          env (make-signed-envelope kp (basalt/bytes->hex (:public kp)) huge-text)
          res (relay/reduce-relay st0 {:type :relay-submit :envelope env :now-ms 1000})]
      (is (false? (:ok? res)))
      (is (= :payload-too-large (:error res)))
      (is (= 1 (get-in (:state res) [:diagnostics :too-large])))
      (is (= 1 (get-in (:state res) [:diagnostics :rejected])))
      (is (= 1 (count (:effects res))))
      (is (= :diagnose (:effect (first (:effects res))))))))

(deftest test-invalid-signature-rejection
  (testing "Envelopes with tampered signatures or malformed payloads are rejected fail-closed"
    (let [st0 (relay/init-relay-state)
          kp (crypto/generate-keypair)
          bogus-sig (apply str (repeat 128 "0"))
          env {:sender (basalt/bytes->hex (:public kp))
               :recipient (basalt/bytes->hex (:public kp))
               :payload (fressian/utf8->bytes "tampered")
               :signature bogus-sig}
          res (relay/reduce-relay st0 {:type :relay-submit :envelope env :now-ms 1000})]
      (is (false? (:ok? res)))
      (is (= :invalid-signature (:error res)))
      (is (= 1 (get-in (:state res) [:diagnostics :invalid-sig])))
      (is (= 1 (get-in (:state res) [:diagnostics :rejected])))
      (is (= :diagnose (:effect (first (:effects res))))))))

(deftest test-broadcast-ring-delivery
  (testing "Broadcast envelopes with recipient '*' or nil are appended to broadcast ring buffer"
    (let [st0 (relay/init-relay-state {:max-broadcast-size 2})
          kp (crypto/generate-keypair)
          env1 (make-signed-envelope kp "*" "bcast-1")
          env2 (make-signed-envelope kp "*" "bcast-2")
          env3 (make-signed-envelope kp "*" "bcast-3")
          s1 (:state (relay/reduce-relay st0 {:type :relay-submit :envelope env1 :now-ms 1000}))
          s2 (:state (relay/reduce-relay s1 {:type :relay-submit :envelope env2 :now-ms 2000}))
          s3 (:state (relay/reduce-relay s2 {:type :relay-submit :envelope env3 :now-ms 3000}))
          bcasts (:broadcasts s3)]
      (is (= 2 (count bcasts)) "Broadcast ring buffer bounded to max 2 entries")
      (is (= 3 (long (:next-broadcast-seq s3))) "Broadcast counter advanced to 3")
      (is (= 2 (long (:broadcast-seq (first bcasts)))) "Oldest broadcast evicted"))))

(deftest test-normalize-relay-base-url
  (testing "F-Relay-2: normalize-relay-base-url strips trailing slashes, /relay/v1 suffix, and any subpaths under /relay/v1"
    (is (nil? (relay/normalize-relay-base-url nil)))
    (is (nil? (relay/normalize-relay-base-url "")))
    (is (nil? (relay/normalize-relay-base-url "   ")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org/")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org///")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org/relay/v1")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org/relay/v1/")))
    (is (= "http://127.0.0.1:8080" (relay/normalize-relay-base-url "http://127.0.0.1:8080/relay/v1/   ")))
    (is (= "http://127.0.0.1:8080" (relay/normalize-relay-base-url "http://127.0.0.1:8080/relay/v1/poll")))
    (is (= "http://127.0.0.1:8080" (relay/normalize-relay-base-url "http://127.0.0.1:8080/relay/v1/send/")))
    (is (= "http://127.0.0.1:8080" (relay/normalize-relay-base-url "http://127.0.0.1:8080/relay/v1/ack")))
    (is (= "http://127.0.0.1:8080" (relay/normalize-relay-base-url "http://127.0.0.1:8080/relay/v1/chain-state")))))

(deftest test-validator-only-ledger-dispatch
  (testing "F-Relay-7: Validator-only ledger transactions are forwarded without polluting chat inboxes/broadcast ring"
    (let [st0 (relay/init-relay-state)
          kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          payload (fressian/utf8->bytes "tx-payload")
          sig (crypto/sign (:private kp) payload)
          env {:type :transfer
               :sender pub
               :payload payload
               :signature (if (string? sig) sig (basalt/bytes->hex sig))}
          res (relay/reduce-relay st0 {:type :relay-submit :envelope env :now-ms 1000})]
      (is (true? (:ok? res)))
      (is (= "forwarded-validator-only" (get-in res [:response "status"])))
      (is (empty? (get-in (:state res) [:inboxes])))
      (is (empty? (get-in (:state res) [:broadcasts])))
      (is (= 1 (count (:effects res))))
      (is (= :forward-to-validators (:effect (first (:effects res))))))))

(deftest test-broadcast-ttl-eviction
  (testing "F-Relay-6: Broadcasts older than 24h TTL are evicted on submit and filtered on poll"
    (let [st0 (relay/init-relay-state {:ttl-ms 1000})
          kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          env1 (make-signed-envelope kp "*" "bcast-old")
          env2 (make-signed-envelope kp "*" "bcast-fresh")
          s1 (:state (relay/reduce-relay st0 {:type :relay-submit :envelope env1 :now-ms 1000}))
          ;; 2000ms later (> ttl 1000ms), submit second broadcast
          s2 (:state (relay/reduce-relay s1 {:type :relay-submit :envelope env2 :now-ms 3000}))
          ;; Poll at now-ms 3500
          sig (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq 0 :timestamp-ms 3500 :nonce "nonce-poll"})
          poll-res (relay/reduce-relay s2 {:type :relay-poll
                                           :pubkey pub
                                           :since-seq 0
                                           :since-broadcast-seq 0
                                           :timestamp-ms 3500
                                           :nonce "nonce-poll"
                                           :signature sig
                                           :now-ms 3500})
          bcasts (get-in poll-res [:response "broadcasts"])]
      (is (= 1 (count (:broadcasts s2))) "Old broadcast evicted on submit")
      (is (= 1 (count bcasts)) "Only fresh broadcast returned on poll"))))

(deftest test-poll-skew-and-nonce-rate-limiting
  (testing "F-Relay-7: ts <= 0 rejected with :poll-skew-exceeded, active nonces >= max-nonces rejected with :poll-rate-limited"
    (let [st0 (relay/init-relay-state {:max-nonces 2 :max-skew-ms 10000})
          kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          now-ms 1000000
          ;; 1. ts = 0
          sig0 (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq 0 :timestamp-ms 0 :nonce "n0"})
          r0 (relay/reduce-relay st0 {:type :relay-poll :pubkey pub :timestamp-ms 0 :nonce "n0" :signature sig0 :now-ms now-ms})
          ;; 2. poll 1 and poll 2
          sig1 (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq 0 :timestamp-ms now-ms :nonce "n1"})
          r1 (relay/reduce-relay st0 {:type :relay-poll :pubkey pub :timestamp-ms now-ms :nonce "n1" :signature sig1 :now-ms now-ms})
          sig2 (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq 0 :timestamp-ms now-ms :nonce "n2"})
          r2 (relay/reduce-relay (:state r1) {:type :relay-poll :pubkey pub :timestamp-ms now-ms :nonce "n2" :signature sig2 :now-ms now-ms})
          ;; 3. poll 3 exceeds capacity 2
          sig3 (relay/sign-poll-request (:private kp) {:pubkey pub :since-seq 0 :timestamp-ms now-ms :nonce "n3"})
          r3 (relay/reduce-relay (:state r2) {:type :relay-poll :pubkey pub :timestamp-ms now-ms :nonce "n3" :signature sig3 :now-ms now-ms})]
      (is (false? (:ok? r0)))
      (is (= :poll-skew-exceeded (:error r0)))
      (is (true? (:ok? r1)))
      (is (true? (:ok? r2)))
      (is (false? (:ok? r3)))
      (is (= :poll-rate-limited (:error r3))))))

(deftest test-global-queued-bytes-cap-and-eviction
  (testing "F-Rem-2: Global queued bytes limit evicts oldest messages and emits :queued-bytes-evicted diagnose effects"
    (let [kp (crypto/generate-keypair)
          recip1 (basalt/bytes->hex (:public (crypto/generate-keypair)))
          recip2 (basalt/bytes->hex (:public (crypto/generate-keypair)))
          env1 (make-signed-envelope kp recip1 "first-msg-payload")
          sz1 (fressian/count-bytes (fressian/encode-canonical env1))
          ;; Cap to allow exactly ~2 messages
          max-cap (+ (* 2 sz1) 10)
          st0 (relay/init-relay-state {:max-total-queued-bytes max-cap})
          r1 (relay/reduce-relay st0 {:type :relay-submit :envelope env1 :now-ms 1000})
          st1 (:state r1)
          env2 (make-signed-envelope kp recip2 "second-msg-payload")
          r2 (relay/reduce-relay st1 {:type :relay-submit :envelope env2 :now-ms 2000})
          st2 (:state r2)
          env3 (make-signed-envelope kp recip1 "third-msg-payload")
          r3 (relay/reduce-relay st2 {:type :relay-submit :envelope env3 :now-ms 3000})
          st3 (:state r3)]
      (is (true? (:ok? r1)))
      (is (true? (:ok? r2)))
      (is (true? (:ok? r3)))
      ;; Total queued bytes must remain <= max-cap
      (is (<= (relay/total-queued-bytes st3) max-cap))
      ;; Diagnostic counter for evicted must be at least 1
      (is (pos? (get-in st3 [:diagnostics :evicted] 0)))
      ;; r3 must have emitted a :queued-bytes-evicted diagnose effect
      (let [evicted-eff (first (filter #(= :queued-bytes-evicted (:reason %)) (:effects r3)))]
        (is (some? evicted-eff))
        (is (= :diagnose (:effect evicted-eff)))
        (is (pos? (:evicted-bytes evicted-eff))))
      ;; First message must be gone from recip1's inbox, leaving only the third message
      (is (= 1 (count (get-in st3 [:inboxes recip1]))))
      (is (= 1 (count (get-in st3 [:inboxes recip2]))))
      ;; Submitting a single message that exceeds max-total-queued-bytes must be rejected immediately
      (let [huge-text (apply str (repeat (inc max-cap) "x"))
            huge-env (make-signed-envelope kp recip1 huge-text)
            r-huge (relay/reduce-relay st3 {:type :relay-submit :envelope huge-env :now-ms 4000})]
        (is (false? (:ok? r-huge)))
        (is (= :payload-too-large (:error r-huge)))))))

(defspec ^{:doc "Property: Total queued bytes across inboxes and broadcasts strictly satisfies global cap invariant"}
  prop-global-queued-bytes-invariant 25
  (for-all [msg-count (gen/choose 3 8)]
           (let [kp (crypto/generate-keypair)
                 recip (basalt/bytes->hex (:public (crypto/generate-keypair)))
                 st0 (relay/init-relay-state {:max-total-queued-bytes 600})
                 final-st (reduce (fn [st idx]
                                    (let [env (make-signed-envelope kp recip (str "msg-" idx "-" (apply str (repeat 20 "a"))))
                                          res (relay/reduce-relay st {:type :relay-submit :envelope env :now-ms (+ 1000 idx)})]
                                      (:state res)))
                                  st0
                                  (range msg-count))]
             (and (<= (relay/total-queued-bytes final-st) 600)
                  (pos? (get-in final-st [:diagnostics :submitted] 0))))))

(deftest test-signaling-burn-floor-and-gossip-deduplication
  (testing "Rejects :receive-gossip envelope with burn-amount < min-signaling-burn"
    (let [st0 (relay/init-relay-state {:min-signaling-burn 100})
          kp (crypto/generate-keypair)
          env-0 (make-signed-gossip-envelope kp "burn-test" 0 "gossip-mid-1")
          r0 (relay/reduce-relay st0 {:type :relay-submit :envelope env-0 :now-ms 1000})]
      (is (false? (:ok? r0)))
      (is (= :insufficient-burn (:error r0)))
      (is (= 1 (get-in (:state r0) [:diagnostics :insufficient-burn])))
      (is (= 1 (get-in (:state r0) [:diagnostics :rejected])))))

  (testing "Accepts :receive-gossip with burn-amount >= min-signaling-burn and deduplicates by message-id"
    (let [st0 (relay/init-relay-state {:min-signaling-burn 100})
          kp (crypto/generate-keypair)
          kp2 (crypto/generate-keypair)
          msg-id "canonical-gossip-mid-42"
          env1 (make-signed-gossip-envelope kp "valid-burn" 100 msg-id)
          r1 (relay/reduce-relay st0 {:type :relay-submit :envelope env1 :now-ms 1000})
          st1 (:state r1)]
      (is (true? (:ok? r1)))
      (is (false? (:duplicate? r1)))
      (is (= 1 (count (:broadcasts st1))))

      ;; Re-submit same gossip message wrapped in another agent envelope (e.g. forwarded by validator)
      (let [sender2 (basalt/bytes->hex (:public kp2))
            gossip-msg (:message env1)
            env2 {:type :receive-gossip
                  :sender sender2
                  :message gossip-msg
                  :signature (basalt/bytes->hex (crypto/sign (:private kp2) (fressian/encode-canonical gossip-msg)))}
            r2 (relay/reduce-relay st1 {:type :relay-submit :envelope env2 :from-validator? true :now-ms 2000})]
        (is (true? (:ok? r2)))
        (is (true? (:duplicate? r2)))
        (is (= msg-id (:envelope-id r2)))
        (is (= 1 (count (:broadcasts (:state r2)))) "Duplicate is not appended to broadcasts")))))

(deftest test-relay-validator-chain-state-snapshot-routing-f-bb-8
  (testing "F-Bb-8: Validator-signed :chain-state-snapshot envelopes are verified and routed to queried pubkey inbox"
    (let [st0 (relay/init-relay-state)
          kp-val (crypto/generate-keypair)
          kp-user (crypto/generate-keypair)
          val-pub (basalt/bytes->hex (:public kp-val))
          user-pub (basalt/bytes->hex (:public kp-user))
          base-snap {:type :chain-state-snapshot
                     :bitecho/type :chain-state-snapshot
                     :validator-pubkey val-pub
                     :pubkey user-pub
                     :finalized-epoch 42
                     :balance 100000
                     :spendable 95000
                     :seq 7
                     :deps []
                     :escrows []
                     :nonce "qcs-42-nonce"}
          canonical-str (relay/canonical-chain-state-snapshot-str base-snap)
          sig (crypto/sign (:private kp-val) (fressian/utf8->bytes canonical-str))
          signed-snap (assoc base-snap :signature (basalt/bytes->hex sig))]

      ;; 1. Signature verification
      (is (true? (relay/verify-chain-state-snapshot-signature signed-snap)))
      ;; Alter balance -> signature invalid
      (let [forged (assoc signed-snap :balance 999999)]
        (is (false? (relay/verify-chain-state-snapshot-signature forged))))

      ;; 2. Relay submission routes into user-pub inbox
      (let [r1 (relay/reduce-relay st0 {:type :relay-submit :envelope signed-snap :from-validator? true :now-ms 1000})]
        (is (true? (:ok? r1)))
        (is (= user-pub (get-in r1 [:response "recipient"])))
        (is (false? (get-in r1 [:response "broadcast"])))
        (is (empty? (:effects r1)) "No forwarding effects for incoming validator snapshot")
        (let [st1 (:state r1)
              user-inbox (get-in st1 [:inboxes user-pub])]
          (is (= 1 (count user-inbox)))
          (is (= 1 (:relay-seq (first user-inbox))))

          ;; 3. Poll by user delivers the validator snapshot envelope
          (let [ts 1050
                nonce "poll-nonce-1"
                sig-poll (relay/sign-poll-request (:private kp-user)
                                                  {:pubkey user-pub
                                                   :since-seq 0
                                                   :timestamp-ms ts
                                                   :nonce nonce})
                poll-res (relay/reduce-relay st1 {:type :relay-poll
                                                  :pubkey user-pub
                                                  :since-seq 0
                                                  :timestamp-ms ts
                                                  :nonce nonce
                                                  :signature sig-poll
                                                  :now-ms 1050})]
            (is (true? (:ok? poll-res)))
            (let [msgs (get-in poll-res [:response "messages"])]
              (is (= 1 (count msgs)))
              (is (= user-pub (:recipient (first msgs))))))))

      ;; 4. Forged snapshot is rejected fail-closed
      (let [forged-snap (assoc signed-snap :balance 999999)
            r-bad (relay/reduce-relay st0 {:type :relay-submit :envelope forged-snap :now-ms 1100})]
        (is (false? (:ok? r-bad)))
        (is (= :invalid-signature (:error r-bad))))

      ;; 5. F-P0-9: Known-validators allowlist rejection
      (let [kp-other (crypto/generate-keypair)
            other-pub (basalt/bytes->hex (:public kp-other))
            st-with-known (assoc st0 :known-validators {:primary other-pub})
            r-rejected (relay/reduce-relay st-with-known {:type :relay-submit :envelope signed-snap :from-validator? true :now-ms 1200})]
        (is (false? (:ok? r-rejected)) "Snapshot signed by unknown validator must be rejected")
        (is (= :unknown-validator (:error r-rejected)))
        (is (some #(= :unknown-validator (:reason %)) (:effects r-rejected)) "Emits :unknown-validator diagnostic")
        (is (empty? (get-in (:state r-rejected) [:inboxes user-pub])) "Inbox remains empty on unknown validator rejection"))

      ;; 6. F-P0-9: Known-validators allowlist acceptance when matching
      (let [st-with-val (assoc st0 :known-validators {:primary val-pub})
            r-accepted (relay/reduce-relay st-with-val {:type :relay-submit :envelope signed-snap :from-validator? true :now-ms 1300})]
        (is (true? (:ok? r-accepted)) "Snapshot signed by authorized validator in allowlist must be accepted")
        (is (= 1 (count (get-in (:state r-accepted) [:inboxes user-pub]))))))))


