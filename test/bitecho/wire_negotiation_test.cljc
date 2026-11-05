(ns bitecho.wire-negotiation-test
  "Cross-runtime test suite for Milestone 9: Wire Format + Crypto-Suite Negotiation.
   Verifies:
   - Fressian wire codec (encode-wire / decode-wire) round-trip with chunked strings,
     chunked byte arrays, records, and untrusted crypto tag stripping.
   - Wire format versioning and rolling upgrade (:wire-format 'fressian-v1' vs 'legacy-nippy'),
     and fail-closed rejection of reserved formats with diagnostics.
   - AES-256-GCM AEAD golden vector and cross-runtime parity (byte-identical on JVM and Node).
   - Generative property tests for crypto-suite negotiation determinism.
   - Downgrade attack resistance: signed offer suite stripping, rendezvous suite tampering,
     directory descriptor suite binding, and mid-session suite switching rejection.
   - Live cross-runtime JVM <-> Node AEAD and wire envelope interop."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-node]
            #?(:clj [taoensso.nippy :as nippy])
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            #?(:clj [clojure.test.check.properties :refer [for-all]]
               :cljs [clojure.test.check.properties :refer-macros [for-all]])))

(defrecord ^{:doc "Sample record for wire normalization testing."} WireRecordTest [field-a field-b field-c])

;; =============================================================================
;; 1. Step 9A: Fressian Wire Codec Round-Trip & Chunking Tests
;; =============================================================================

(deftest test-wire-codec-basic-roundtrip
  (testing "encode-wire and decode-wire round-trip with primitive and collection types"
    (let [sample-data {:nil nil
                       :bool-t true
                       :bool-f false
                       :int-small 42
                       :int-neg -12345
                       :int-large 9876543210
                       :str "Bitecho wire codec"
                       :kw :sample/keyword
                       :sym 'sample/symbol
                       :bytes (fressian/utf8->bytes "binary payload")
                       :vec [1 2 3 "four" :five]
                       :set #{:a :b :c}
                       :nested {:inner-map {:x 10 :y [20 30]}}}
          enc (fressian/encode-wire sample-data)
          dec (fressian/decode-wire enc)]
      (is (fressian/bytes? enc))
      (is (= (:nil dec) nil))
      (is (= (:bool-t dec) true))
      (is (= (:bool-f dec) false))
      (is (= (:int-small dec) 42))
      (is (= (:int-neg dec) -12345))
      (is (= (:int-large dec) 9876543210))
      (is (= (:str dec) "Bitecho wire codec"))
      (is (= (:kw dec) :sample/keyword))
      (is (= (:sym dec) 'sample/symbol))
      (is (= (basalt/bytes->hex (:bytes dec)) (basalt/bytes->hex (:bytes sample-data))))
      (is (= (:vec dec) [1 2 3 "four" :five]))
      (is (= (:set dec) #{:a :b :c}))
      (is (= (get-in dec [:nested :inner-map :x]) 10))
      (is (= (get-in dec [:nested :inner-map :y]) [20 30]))
      ;; Standalone boolean false and nil payloads (closing decode-wire false-sentinel)
      (is (= false (fressian/decode-wire (fressian/encode-wire false))))
      (is (= nil (fressian/decode-wire (fressian/encode-wire nil)))))))

(deftest test-wire-codec-compact-chunked-fixtures
  (testing "deterministic chunked string and bytes golden fixtures decode across JVM and CLJS"
    ;; 1. Compact multi-chunk string & byte fixtures
    (let [chunked-str-fixture (fressian/hex->bytes "e2024142db43")
          chunked-bytes-fixture (fressian/hex->bytes "d8024142d143")
          dec-str (fressian/decode-wire chunked-str-fixture)
          dec-bytes (fressian/decode-wire chunked-bytes-fixture)]
      (is (= "ABC" dec-str))
      (is (fressian/bytes? dec-bytes))
      (is (= "414243" (basalt/bytes->hex dec-bytes))))
    ;; 2. Full 66,000-byte JVM org.clojure/data.fressian wire-exact chunked fixtures:
    ;;    - String (66,000 'A's): e2 69 00 00 (STRING_CHUNK len=65536) + 65536*'A' + e3 51 d0 (STRING len=464) + 464*'A'
    ;;    - Bytes  (66,000 0x2a): d8 68 ff ff (BYTES_CHUNK  len=65535) + 65535*0x2a + d9 51 d1 (BYTES  len=465) + 465*0x2a
    (let [expected-str (apply str (repeat 66000 "A"))
          jvm-str-fixture (fressian/concat-bytes
                           (fressian/hex->bytes "e2690000")
                           (fressian/utf8->bytes (apply str (repeat 65536 "A")))
                           (fressian/hex->bytes "e351d0")
                           (fressian/utf8->bytes (apply str (repeat 464 "A"))))
          jvm-bytes-fixture (fressian/concat-bytes
                             (fressian/hex->bytes "d868ffff")
                             (fressian/utf8->bytes (apply str (repeat 65535 "*")))
                             (fressian/hex->bytes "d951d1")
                             (fressian/utf8->bytes (apply str (repeat 465 "*"))))
          dec-jvm-str (fressian/decode-wire jvm-str-fixture)
          dec-jvm-bytes (fressian/decode-wire jvm-bytes-fixture)]
      #?(:clj (do
                (is (= (basalt/bytes->hex (fressian/encode-wire expected-str))
                       (basalt/bytes->hex jvm-str-fixture)))
                (is (= (basalt/bytes->hex (fressian/encode-wire (byte-array 66000 (byte 42))))
                       (basalt/bytes->hex jvm-bytes-fixture)))))
      (is (= 66000 (count dec-jvm-str)))
      (is (= expected-str dec-jvm-str))
      (is (fressian/bytes? dec-jvm-bytes))
      (is (= 66000 (fressian/count-bytes dec-jvm-bytes))))))

#?(:clj
   (deftest test-wire-codec-jvm-data-fressian-chunk-tags
     (testing "JVM org.clojure.data.fressian outputs chunk tags 0xCA (226) and 0xCE (216) on >65536 inputs"
       (let [large-str (apply str (repeat 6600 "0123456789"))
             large-bytes (byte-array 66000 (byte 42))
             enc-str (fressian/encode-wire large-str)
             enc-bytes (fressian/encode-wire large-bytes)]
         (is (= 226 (bit-and 0xFF (aget ^bytes enc-str 0))))
         (is (= 216 (bit-and 0xFF (aget ^bytes enc-bytes 0))))
         (is (= large-str (fressian/decode-wire enc-str)))
         (is (= 66000 (count (fressian/decode-wire enc-bytes))))))))

(deftest test-wire-codec-chunked-string
  (testing "encode-wire and decode-wire handle large strings (> 65536 code points) chunking cleanly"
    (let [large-str (apply str (repeat 7000 "0123456789"))
          _ (is (> (count large-str) 65536))
          enc (fressian/encode-wire large-str)
          dec (fressian/decode-wire enc)]
      (is (= large-str dec)))))

(deftest test-wire-codec-chunked-bytes
  (testing "encode-wire and decode-wire handle large byte arrays (> 65536 bytes) chunking cleanly"
    (let [large-str (apply str (repeat 7000 "abcdefghij"))
          large-bytes (fressian/utf8->bytes large-str)
          _ (is (> (fressian/count-bytes large-bytes) 65536))
          enc (fressian/encode-wire large-bytes)
          dec (fressian/decode-wire enc)]
      (is (fressian/bytes? dec))
      (is (= (fressian/count-bytes large-bytes) (fressian/count-bytes dec)))
      (is (= (basalt/bytes->hex large-bytes) (basalt/bytes->hex dec))))))

(deftest test-wire-codec-record-normalization
  (testing "records are normalized into standard persistent maps during wire encoding"
    (let [rec (->WireRecordTest "val-a" 42 [:x :y])
          enc (fressian/encode-wire rec)
          dec (fressian/decode-wire enc)]
      (is (map? dec))
      (is (not (record? dec)))
      (is (= (:field-a dec) "val-a"))
      (is (= (:field-b dec) 42))
      (is (= (:field-c dec) [:x :y])))))

(deftest test-wire-codec-strips-untrusted-crypto-tags
  (testing "decode-wire recursively strips untrusted shell-boundary crypto tags"
    (let [data {:name "peer1"
                :crypto/verified? true
                :crypto/verified-a? true
                :nested {:amount 100
                         :crypto/verified-b? true
                         :items [{:id 1 :crypto/verified? true}]}}
          enc (fressian/encode-wire data)
          dec (fressian/decode-wire enc)]
      (is (= dec {:name "peer1"
                  :nested {:amount 100
                           :items [{:id 1}]}})))))

#?(:clj
   (deftest test-legacy-nippy-wire-decoding-on-jvm
     (testing "JVM decode-wire transparently decodes legacy Nippy-encoded payloads"
       (let [legacy-data {:hello "nippy-wire" :number 99}
             nippy-bytes (nippy/freeze legacy-data)
             _ (is (fressian/nippy-payload? nippy-bytes))
             decoded (fressian/decode-wire nippy-bytes)]
         (is (= legacy-data decoded))))))

;; =============================================================================
;; 2. Step 9B: Wire Format Versioning & Rolling Upgrade Rejection Tests
;; =============================================================================

(deftest test-wire-format-compatibility-predicate
  (testing "check-wire-format-compatibility correctly classifies supported, unversioned, and reserved formats"
    ;; Unversioned legacy messages default to fressian-v1
    (let [unver (light-node/check-wire-format-compatibility {:some "msg"})]
      (is (:ok? unver))
      (is (= "fressian-v1" (:wire-format unver)))
      (is (:legacy-unversioned? unver)))

    ;; Supported formats
    (let [f-str (light-node/check-wire-format-compatibility {:wire-format "fressian-v1"})
          f-kw (light-node/check-wire-format-compatibility {:wire-format :fressian-v1})
          n-str (light-node/check-wire-format-compatibility {:wire-format "legacy-nippy"})
          n-kw (light-node/check-wire-format-compatibility {:wire-format :legacy-nippy})]
      (is (and (:ok? f-str) (= "fressian-v1" (:wire-format f-str))))
      (is (and (:ok? f-kw) (= "fressian-v1" (:wire-format f-kw))))
      (is (and (:ok? n-str) (= "legacy-nippy" (:wire-format n-str))))
      (is (and (:ok? n-kw) (= "legacy-nippy" (:wire-format n-kw)))))

    ;; Reserved formats fail-closed
    (let [t-json (light-node/check-wire-format-compatibility {:wire-format "transit-json"})
          t-msgpack (light-node/check-wire-format-compatibility {:wire-format "transit-msgpack"})
          unknown (light-node/check-wire-format-compatibility {:wire-format "protobuf-v99"})]
      (is (not (:ok? t-json)))
      (is (= "unsupported-wire-format" (:error t-json)))
      (is (= "transit-json" (:wire-format t-json)))
      (is (not (:ok? t-msgpack)))
      (is (= "unsupported-wire-format" (:error t-msgpack)))
      (is (not (:ok? unknown)))
      (is (= "unsupported-wire-format" (:error unknown))))))

(deftest test-handle-wire-payload-unsupported-format-fail-closed
  (testing "handle-wire-payload drops unsupported wire format, increments diagnostics, and emits rejection event"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          state (light-node/init-light-state {:pubkey-hex pub-hex} {:autonomous? false})
          msg {:protocol-version 1
               :wire-format "transit-json"
               :bitecho/type :channel-offer
               :caller pub-hex}
          res (light-node/handle-wire-payload state msg (:private kp))]
      (is (= [] (:net-envelopes res)))
      (is (= 1 (get-in (:state res) [:wire-version-diagnostics :unsupported-format-dropped])))
      (is (= "transit-json" (get-in (:state res) [:wire-version-diagnostics :last-unsupported-format])))
      (is (= "unsupported-wire-format" (get-in (:state res) [:wire-version-diagnostics :last-error])))
      (let [stdout-evt (first (:stdout-events res))]
        (is (= "wire-format-rejected" (get stdout-evt "event")))
        (is (= "unsupported-wire-format" (get stdout-evt "error")))
        (is (= "transit-json" (get stdout-evt "wire_format")))))))

(deftest test-status-surfaces-wire-protocol-format
  (testing "exec-status exposes wire_format, supported_formats, and drop count under wire_protocol"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          state (light-node/init-light-state {:pubkey-hex pub-hex} {:autonomous? false})
          st (light-node/handle-command state {"cmd" "status"} nil)
          wp (get-in st [:response "wire_protocol"])]
      (is (= 1 (get wp "version")))
      (is (= "fressian-v1" (get wp "wire_format")))
      (is (= ["fressian-v1" "legacy-nippy"] (get wp "supported_formats")))
      (is (= 0 (get wp "unsupported_format_dropped")))
      (is (nil? (get wp "last_unsupported_format"))))))

;; =============================================================================
;; 3. Step 9C: AES-256-GCM AEAD & Cross-Runtime Golden Vectors
;; =============================================================================

(deftest test-aes256gcm-golden-vector
  (testing "AES-256-GCM produces byte-for-byte exact ciphertext and 16-byte tag across JDK and Node.js"
    (let [key (basalt/hex->bytes (apply str (repeat 32 "01")))
          nonce (basalt/hex->bytes (apply str (repeat 12 "02")))
          pt (fressian/utf8->bytes "hello bitecho")
          aad (fressian/utf8->bytes "aad-test")
          expected-ct-hex "6fb3a5252577a394a7a9dfa033afa4d4959f5b7e4a1e6958257c2c39c4"
          raw-ct (sealed/aes-gcm-seal key nonce pt aad)
          raw-ct-hex (basalt/bytes->hex raw-ct)]
      ;; Golden vector match with raw AES-GCM
      (is (= expected-ct-hex raw-ct-hex))
      (let [dec-raw (sealed/aes-gcm-open key nonce raw-ct aad)]
        (is (= "hello bitecho" (fressian/bytes->utf8 dec-raw))))
      ;; High-level seal-message produces deterministic seq->nonce and round-trips cleanly
      (let [sealed (sealed/seal-message key 1 pt aad "suite-v1-aes256gcm")
            ct (:ciphertext sealed)
            dec-4 (sealed/open-message key 1 ct aad)
            dec-5 (sealed/open-message key 1 ct aad "suite-v1-aes256gcm")]
        (is (= "d3bffcebb31e1b4b7d56b3115a0d9acf436381dabe5f5cc9bfe3d118a2" (basalt/bytes->hex ct)))
        (is (= "hello bitecho" (fressian/bytes->utf8 dec-4)))
        (is (= "hello bitecho" (fressian/bytes->utf8 dec-5)))))))

(deftest test-aes256gcm-tamper-resistance
  (testing "AES-256-GCM fails closed (returns nil) on any tampered ciphertext, wrong tag, or wrong AAD"
    (let [key (basalt/hex->bytes (apply str (repeat 32 "aa")))
          seq-num 42
          pt (fressian/utf8->bytes "tamper resistance test payload")
          aad (fressian/utf8->bytes "aad-bound")
          sealed (sealed/seal-message key seq-num pt aad "suite-v1-aes256gcm")
          ct (:ciphertext sealed)
          ;; Tamper 1: flip first byte of ciphertext
          tampered-ct (let [b (fressian/utf8->bytes (fressian/bytes->utf8 ct))]
                        #?(:clj (aset ^bytes b 0 (byte (bit-xor 0x01 (aget ^bytes b 0))))
                           :cljs (aset b 0 (bit-xor 0x01 (aget b 0))))
                        b)
          ;; Tamper 2: tamper AAD
          tampered-aad (fressian/utf8->bytes "aad-bound-tampered")]
      (is (nil? (sealed/open-message key seq-num tampered-ct aad "suite-v1-aes256gcm")))
      (is (nil? (sealed/open-message key seq-num ct tampered-aad "suite-v1-aes256gcm")))
      (is (nil? (sealed/open-message key (inc seq-num) ct aad "suite-v1-aes256gcm"))))))

;; =============================================================================
;; 4. Step 9C: Crypto-Suite Negotiation & Generative Property Tests
;; =============================================================================

(def ^:private suite-pool
  ["suite-v1-aes256gcm" "suite-v1-chacha20poly1305" "suite-future-quantum" "suite-legacy-des"])

(def ^:private gen-suite-subsets
  (gen/fmap (fn [items] (vec (distinct items)))
            (gen/vector (gen/elements suite-pool) 0 4)))

(defspec ^{:doc "Property: Crypto-suite negotiation is deterministic and selects caller's highest priority mutual suite."}
  prop-crypto-suite-negotiation-determinism 50
  (for-all [caller-suites gen-suite-subsets
            callee-suites gen-suite-subsets]
           (let [res (sealed/negotiate-crypto-suite caller-suites callee-suites)
                 supported #{"suite-v1-aes256gcm" "suite-v1-chacha20poly1305"}
                 callee-set (set callee-suites)
                 expected (first (filterv (fn [s] (and (contains? supported s) (contains? callee-set s))) caller-suites))]
             (if expected
               (and (:ok? res)
                    (= expected (:selected-suite res)))
               (and (not (:ok? res))
                    (= "no-mutually-supported-crypto-suite" (:error res)))))))

;; =============================================================================
;; 5. Step 9C: Downgrade Attack Resistance Tests
;; =============================================================================

(deftest test-channel-offer-suite-downgrade-resistance
  (testing "An offer signed with advertised suites rejects tampering or stripping of :crypto-suites"
    (let [kp-caller (crypto/generate-keypair)
          kp-callee (crypto/generate-keypair)
          caller-pub (basalt/bytes->hex (:public kp-caller))
          callee-pub (basalt/bytes->hex (:public kp-callee))
          caller-state (light-node/init-light-state {:pubkey-hex caller-pub} {:autonomous? false})
          callee-state (light-node/init-light-state {:pubkey-hex callee-pub} {:autonomous? false})
          offer-res (light-node/handle-command caller-state
                                               {"cmd" "offer"
                                                "callee" callee-pub
                                                "price" 10
                                                "burn" 500}
                                               (:private kp-caller))
          gossip-env (second (:net-envelopes offer-res))
          msg (or (fressian/decode-wire (get-in gossip-env [:event :message :payload]))
                  (fressian/decode-wire (get-in gossip-env [:message :payload])))
          sid (:session-id msg)]
      ;; Legitimate offer is accepted into pending-offers
      (let [ok-res (light-node/handle-wire-payload callee-state msg (:private kp-callee))]
        (is (contains? (:pending-offers (:state ok-res)) sid))
        (is (= "suite-v1-aes256gcm" (get-in (:state ok-res) [:pending-offers sid :selected-suite]))))

      ;; Downgrade 1: Attacker strips :crypto-suites from wire message
      (let [stripped-msg (dissoc msg :crypto-suites)
            stripped-res (light-node/handle-wire-payload callee-state stripped-msg (:private kp-callee))]
        (is (not (contains? (:pending-offers (:state stripped-res)) sid))))

      ;; Downgrade 2: Attacker replaces suite list with only chacha20poly1305
      (let [tampered-msg (assoc msg :crypto-suites ["suite-v1-chacha20poly1305"])
            tampered-res (light-node/handle-wire-payload callee-state tampered-msg (:private kp-callee))]
        (is (not (contains? (:pending-offers (:state tampered-res)) sid))))

      ;; Downgrade 3: Callee accepts offer, attacker strips or tampers :selected-suite on channel-accept
      (let [callee-offered-state (:state (light-node/handle-wire-payload callee-state msg (:private kp-callee)))
            accept-res (light-node/handle-command callee-offered-state
                                                  {"cmd" "accept" "session_id" sid}
                                                  (:private kp-callee))
            accept-env (first (:net-envelopes accept-res))
            accept-msg (or (fressian/decode-wire (get-in accept-env [:event :message :payload]))
                           (fressian/decode-wire (get-in accept-env [:message :payload])))
            caller-offered-state (:state offer-res)]
        ;; Legitimate accept opens caller session with suite-v1-aes256gcm
        (let [caller-open (light-node/handle-wire-payload caller-offered-state accept-msg (:private kp-caller))]
          (is (= "open" (get-in (:state caller-open) [:sessions sid :state])))
          (is (= "suite-v1-aes256gcm" (get-in (:state caller-open) [:sessions sid :suite]))))
        ;; Stripping :selected-suite from channel-accept is rejected
        (let [stripped-accept (dissoc accept-msg :selected-suite)
              bad-open-1 (light-node/handle-wire-payload caller-offered-state stripped-accept (:private kp-caller))]
          (is (= "offered" (get-in (:state bad-open-1) [:sessions sid :state]))))
        ;; Tampering :selected-suite to suite-v1-chacha20poly1305 on channel-accept is rejected
        (let [tampered-accept (assoc accept-msg :selected-suite "suite-v1-chacha20poly1305")
              bad-open-2 (light-node/handle-wire-payload caller-offered-state tampered-accept (:private kp-caller))]
          (is (= "offered" (get-in (:state bad-open-2) [:sessions sid :state]))))))))

(deftest test-rendezvous-offer-suite-downgrade-resistance
  (testing "A rendezvous offer header signed with advertised suites rejects tampering or stripping of :crypto-suites"
    (let [kp-caller (crypto/generate-keypair)
          kp-callee (crypto/generate-keypair)
          caller-pub (basalt/bytes->hex (:public kp-caller))
          callee-pub (basalt/bytes->hex (:public kp-callee))
          caller-state (light-node/init-light-state {:pubkey-hex caller-pub} {:autonomous? false})
          callee-state (light-node/init-light-state {:pubkey-hex callee-pub} {:autonomous? false})
          rend-res (light-node/handle-command caller-state
                                              {"cmd" "rendezvous-offer"
                                               "callee" callee-pub
                                               "burn" 500
                                               "topic" "test-rendezvous"}
                                              (:private kp-caller))
          gossip-env (first (:net-envelopes rend-res))
          msg (or (fressian/decode-wire (get-in gossip-env [:event :message :payload]))
                  (fressian/decode-wire (get-in gossip-env [:message :payload])))
          oh (:offer-hash msg)]
      ;; Legitimate rendezvous offer is buffered in :pending-rendezvous
      (let [ok-res (light-node/handle-wire-payload callee-state msg (:private kp-callee))]
        (is (contains? (:pending-rendezvous (:state ok-res)) oh)))

      ;; Downgrade 1: Attacker strips :crypto-suites
      (let [stripped-msg (dissoc msg :crypto-suites)
            stripped-res (light-node/handle-wire-payload callee-state stripped-msg (:private kp-callee))]
        (is (not (contains? (:pending-rendezvous (:state stripped-res)) oh))))

      ;; Downgrade 2: Attacker tampers with :crypto-suites
      (let [tampered-msg (assoc msg :crypto-suites ["suite-v1-chacha20poly1305"])
            tampered-res (light-node/handle-wire-payload callee-state tampered-msg (:private kp-callee))]
        (is (not (contains? (:pending-rendezvous (:state tampered-res)) oh))))

      ;; Downgrade 3: Callee issues rendezvous-ack-voucher, attacker strips or tampers :selected-suite
      (let [callee-pending-state (:state (light-node/handle-wire-payload callee-state msg (:private kp-callee)))
            ack-res (light-node/handle-command callee-pending-state
                                               {"cmd" "rendezvous-accept" "offer_hash" oh}
                                               (:private kp-callee))
            ack-env (first (:net-envelopes ack-res))
            ack-msg (or (fressian/decode-wire (get-in ack-env [:event :message :payload]))
                        (fressian/decode-wire (get-in ack-env [:message :payload])))
            caller-outbound-state (:state rend-res)]
        ;; Legitimate ack establishes caller session with suite-v1-aes256gcm
        (let [caller-est (light-node/handle-wire-payload caller-outbound-state ack-msg (:private kp-caller))
              sid (get-in caller-outbound-state [:outbound-rendezvous oh :session-id])]
          (is (= "open" (get-in (:state caller-est) [:sessions sid :state])))
          (is (= "suite-v1-aes256gcm" (get-in (:state caller-est) [:sessions sid :suite]))))
        ;; Stripping :selected-suite from rendezvous-ack-voucher is rejected
        (let [stripped-ack (dissoc ack-msg :selected-suite)
              bad-est-1 (light-node/handle-wire-payload caller-outbound-state stripped-ack (:private kp-caller))]
          (is (contains? (:outbound-rendezvous (:state bad-est-1)) oh)))
        ;; Tampering :selected-suite on rendezvous-ack-voucher is rejected
        (let [tampered-ack (assoc ack-msg :selected-suite "suite-v1-chacha20poly1305")
              bad-est-2 (light-node/handle-wire-payload caller-outbound-state tampered-ack (:private kp-caller))]
          (is (contains? (:outbound-rendezvous (:state bad-est-2)) oh)))))))

(deftest test-directory-descriptor-suite-binding-and-tamper-resistance
  (testing "Directory descriptor PoP and attestation cryptographically bind :crypto-suites"
    (let [kp-dir (crypto/generate-keypair)
          kp-agent (crypto/generate-keypair)
          dir-pub (basalt/bytes->hex (:public kp-dir))
          agent-pub (basalt/bytes->hex (:public kp-agent))
          pop (light-node/create-directory-pop (:private kp-agent)
                                               {:domain "bitecho.org"
                                                :nickname "charlie"
                                                :pubkey agent-pub
                                                :epoch 10
                                                :crypto-suites ["suite-v1-aes256gcm" "suite-v1-chacha20poly1305"]})
          desc (light-node/sign-directory-descriptor (:private kp-dir) dir-pub pop
                                                     {:issued-epoch 10 :expires-epoch 20})
          ;; Valid descriptor verifies cleanly
          v-ok (light-node/verify-directory-descriptor desc dir-pub 10)
          _ (is (:ok? v-ok))
          ;; Directory suite compatibility check
          compat-ok (light-node/check-directory-suite-compatibility desc ["suite-v1-aes256gcm"])
          _ (is (:ok? compat-ok))
          _ (is (= "suite-v1-aes256gcm" (:selected-suite compat-ok)))
          ;; Incompatible suites detected
          compat-bad (light-node/check-directory-suite-compatibility desc ["suite-future-quantum"])
          _ (is (not (:ok? compat-bad)))
          ;; Stripping :crypto-suites breaks directory authority signature
          tampered-desc (dissoc desc :crypto-suites)
          v-bad (light-node/verify-directory-descriptor tampered-desc dir-pub 10)]
      (is (not (:ok? v-bad))))))

(deftest test-mid-session-suite-switching-rejection
  (testing "A session negotiated with suite-v1-aes256gcm strictly rejects frames sealed with another suite"
    (let [key (fressian/utf8->bytes "01234567890123456789012345678901")
          seq-num 1
          pt (fressian/utf8->bytes "classified message")
          aad (fressian/utf8->bytes "session-xyz")
          ;; Frame legitimately encrypted with chacha20-poly1305
          sealed-chacha (sealed/seal-message key seq-num pt aad "suite-v1-chacha20poly1305")
          ;; Frame legitimately encrypted with aes-256-gcm
          sealed-aes (sealed/seal-message key seq-num pt aad "suite-v1-aes256gcm")]
      ;; AES session with AES frame succeeds
      (is (some? (sealed/open-message key seq-num (:ciphertext sealed-aes) aad "suite-v1-aes256gcm" "suite-v1-aes256gcm")))
      ;; AES session receiving ChaCha frame with suite tag: rejected due to session-suite != frame-suite!
      (is (nil? (sealed/open-message key seq-num (:ciphertext sealed-chacha) aad "suite-v1-aes256gcm" "suite-v1-chacha20poly1305")))
      ;; AES session receiving ChaCha frame where adversary falsely claims suite-v1-aes256gcm: rejected by AES authentication tag!
      (is (nil? (sealed/open-message key seq-num (:ciphertext sealed-chacha) aad "suite-v1-aes256gcm" "suite-v1-aes256gcm"))))))

;; =============================================================================
;; 7. Pure-CLJS Browser Cryptographic Fallbacks (Step 10A)
;; =============================================================================

(deftest test-pure-browser-crypto-primitives
  (testing "Pure browser cryptographic fallbacks pass RFC vectors and cross-verify with standard implementations"
    ;; 1. HMAC-SHA256
    (let [k (fressian/utf8->bytes "secret-key")
          d (fressian/utf8->bytes "hello world")
          hmac-res (sealed/pure-hmac-sha256 k d)]
      (is (= "095d5a21fe6d0646db223fdf3de6436bb8dfb2fab0b51677ecf6441fcf5f2a67"
             (basalt/bytes->hex hmac-res))))

    ;; 2. X25519 RFC 7748 §6.1 Alice/Bob test vector
    (let [alice-priv (fressian/hex->bytes "77076d0a7318a57d3c16c17251525302a50f354c0307c2cb071e649b5c328559")
          bob-pub (fressian/hex->bytes "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
          shared-secret (sealed/pure-x25519-shared-secret alice-priv bob-pub)]
      (is (= "61897f186837199212de3506429b0e74b202b5336b3ee24851147eea9742f211"
             (basalt/bytes->hex shared-secret))))

    ;; 3. AES-256-GCM pure seal / open roundtrip, tamper resistance, and cross-compatibility
    (let [key (fressian/hex->bytes "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
          nonce (fressian/hex->bytes "000000000000000000000001")
          pt (fressian/utf8->bytes "browser aes-256-gcm payload")
          aad (fressian/utf8->bytes "browser-aad")
          pure-ct (sealed/pure-aes-gcm-seal key nonce pt aad)
          std-ct (sealed/aes-gcm-seal key nonce pt aad)]
      ;; Both implementations produce identical 16-byte authenticated ciphertext
      (is (= (basalt/bytes->hex std-ct) (basalt/bytes->hex pure-ct)))
      ;; Decrypt pure-ct with standard open
      (is (= "browser aes-256-gcm payload" (fressian/bytes->utf8 (sealed/aes-gcm-open key nonce pure-ct aad))))
      ;; Decrypt std-ct with pure open
      (is (= "browser aes-256-gcm payload" (fressian/bytes->utf8 (sealed/pure-aes-gcm-open key nonce std-ct aad))))
      ;; Tampered ciphertext fails closed
      (let [tampered (fressian/concat-bytes pure-ct)]
        #?(:clj (aset ^bytes tampered 0 (unchecked-byte (bit-xor (aget ^bytes tampered 0) 1)))
           :cljs (aset tampered 0 (bit-xor (aget tampered 0) 1)))
        (is (nil? (sealed/pure-aes-gcm-open key nonce tampered aad)))))

    ;; 4. ChaCha20-Poly1305 pure seal / open roundtrip, tamper resistance, and cross-compatibility
    (let [key (fressian/hex->bytes "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
          nonce (fressian/hex->bytes "000000000000000000000002")
          pt (fressian/utf8->bytes "browser chacha20-poly1305 payload")
          aad (fressian/utf8->bytes "browser-aad-chacha")
          pure-ct (sealed/pure-chacha-poly-seal key nonce pt aad)
          std-ct (sealed/chacha-poly-seal key nonce pt aad)]
      ;; Both implementations produce identical authenticated ciphertext
      (is (= (basalt/bytes->hex std-ct) (basalt/bytes->hex pure-ct)))
      ;; Decrypt pure-ct with standard open
      (is (= "browser chacha20-poly1305 payload" (fressian/bytes->utf8 (sealed/chacha-poly-open key nonce pure-ct aad))))
      ;; Decrypt std-ct with pure open
      (is (= "browser chacha20-poly1305 payload" (fressian/bytes->utf8 (sealed/pure-chacha-poly-open key nonce std-ct aad))))
      ;; Tampered ciphertext fails closed
      (let [tampered (fressian/concat-bytes pure-ct)]
        #?(:clj (aset ^bytes tampered 0 (unchecked-byte (bit-xor (aget ^bytes tampered 0) 1)))
           :cljs (aset tampered 0 (bit-xor (aget tampered 0) 1)))
        (is (nil? (sealed/pure-chacha-poly-open key nonce tampered aad)))))))

#?(:clj
   (deftest test-live-node-jvm-interop
     (testing "Live cross-process interop: JVM seals AES-256-GCM AEAD message and Node.js subprocess opens it"
       (let [node-bin (or (System/getenv "NODE_BIN")
                          (let [local-node (java.io.File. (System/getProperty "user.home") ".local/bin/node")]
                            (if (.canExecute local-node)
                              (.getAbsolutePath local-node)
                              "node")))
             key (byte-array 32 (byte 55))
             pt-str "live jvm to node aes-256-gcm test string"
             pt (fressian/utf8->bytes pt-str)
             aad (fressian/utf8->bytes "cross-runtime-aad")
             sealed (sealed/seal-message key 1 pt aad "suite-v1-aes256gcm")
             ct-hex (basalt/bytes->hex (:ciphertext sealed))
             key-hex (basalt/bytes->hex key)
             nonce-hex (basalt/bytes->hex (:nonce sealed))
             aad-hex (basalt/bytes->hex aad)
             js-script (str "const crypto = require('node:crypto');\n"
                            "const key = Buffer.from('" key-hex "', 'hex');\n"
                            "const nonce = Buffer.from('" nonce-hex "', 'hex');\n"
                            "const aad = Buffer.from('" aad-hex "', 'hex');\n"
                            "const ct = Buffer.from('" ct-hex "', 'hex');\n"
                            "const tag = ct.subarray(ct.length - 16);\n"
                            "const data = ct.subarray(0, ct.length - 16);\n"
                            "const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, {authTagLength: 16});\n"
                            "decipher.setAAD(aad);\n"
                            "decipher.setAuthTag(tag);\n"
                            "const out = Buffer.concat([decipher.update(data), decipher.final()]);\n"
                            "process.stdout.write(out.toString('utf8'));\n")
             proc (-> (ProcessBuilder. [node-bin "-e" js-script])
                      (.redirectError java.lang.ProcessBuilder$Redirect/DISCARD)
                      (.start))
             node-out (slurp (.getInputStream proc))
             exit (.waitFor proc)]
         (is (zero? exit))
         (is (= pt-str node-out))))))
