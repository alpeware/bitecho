(ns bitecho.core.protocol.relay-test
  "Cross-platform generative and invariant test suite for HTTP Gateway Relay (`bitecho.core.protocol.relay`).
   Covers Rule 1 (Strict TDD & Generative Invariants), Rule 2 (Pure Sans-IO), Rule 5 (Zero Silent Failures)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
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
  (testing "F-Relay-2: normalize-relay-base-url strips trailing slashes and /relay/v1 suffix"
    (is (nil? (relay/normalize-relay-base-url nil)))
    (is (nil? (relay/normalize-relay-base-url "")))
    (is (nil? (relay/normalize-relay-base-url "   ")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org/")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org///")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org/relay/v1")))
    (is (= "https://bitecho.org" (relay/normalize-relay-base-url "https://bitecho.org/relay/v1/")))
    (is (= "http://127.0.0.1:8080" (relay/normalize-relay-base-url "http://127.0.0.1:8080/relay/v1/   ")))))

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

