(ns bitecho.fressian-test
  "Cross-runtime test suite for deterministic canonical Fressian encoding and SHA-256.
   Verifies byte-identical output across JVM and Node/CLJS with golden vectors and
   test.check generative properties."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            #?(:clj [clojure.data.fressian :as data-fressian])
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            #?(:clj [clojure.test.check.properties :refer [for-all]]
               :cljs [clojure.test.check.properties :refer-macros [for-all]])))

;; =============================================================================
;; Fixed Golden Vectors
;; =============================================================================

(def ^{:doc "Fixed golden vectors for Canonical Fressian binary encoding."}
  canonical-fressian-golden-vectors
  [;; Primitives
   {:label "nil"
    :val nil
    :hex "f7"}
   {:label "true"
    :val true
    :hex "f5"}
   {:label "false"
    :val false
    :hex "f6"}

   ;; Integers across width tiers
   {:label "int-0"
    :val 0
    :hex "00"}
   {:label "int-1"
    :val 1
    :hex "01"}
   {:label "int-42"
    :val 42
    :hex "2a"}
   {:label "int-minus-1"
    :val -1
    :hex "ff"}
   {:label "int-100"
    :val 100
    :hex "5064"}
   {:label "int-minus-100"
    :val -100
    :hex "4f9c"}
   {:label "int-1000"
    :val 1000
    :hex "53e8"}
   {:label "int-100000"
    :val 100000
    :hex "6986a0"}
   {:label "int-10000000000"
    :val 10000000000
    :hex "7a02540be400"}

   ;; Strings
   {:label "str-empty"
    :val ""
    :hex "da"}
   {:label "str-hello"
    :val "hello"
    :hex "df68656c6c6f"}
   {:label "str-emoji-grinning"
    :val "😀"
    :hex "e0eda0bdedb880"}
   {:label "str-astral-mixed"
    :val "hi 🌍🚀!"
    :hex "e310686920eda0bcedbc8deda0bdedba8021"}

   ;; Keywords & Symbols
   {:label "kw-foo"
    :val :foo
    :hex "caf7dd666f6f"}
   {:label "kw-foo-bar"
    :val :foo/bar
    :hex "cadd666f6fdd626172"}
   {:label "sym-bar"
    :val (symbol "bar")
    :hex "c9f7dd626172"}
   {:label "sym-foo-bar"
    :val (symbol "foo" "bar")
    :hex "c9dd666f6fdd626172"}

   ;; Vectors & Raw Bytes
   {:label "vec-1-2-3"
    :val [1 2 3]
    :hex "e7010203"}
   {:label "bytes-1-2-3"
    :val (fressian/hex->bytes "010203")
    :hex "d3010203"}

   ;; Sets & Maps
   {:label "set-1-2"
    :val #{1 2}
    :hex "c1e60102"}
   {:label "map-a-b"
    :val {:a 1 :b 2}
    :hex "c0e8caf7db6101caf7db6202"}
   {:label "map-b-a-unordered"
    :val (into (sorted-map-by #(compare %2 %1)) {:a 1 :b 2})
    :hex "c0e8caf7db6101caf7db6202"}

   ;; Complex Nested Payload
   {:label "nested"
    :val {:epoch 42
          :from "alice"
          :tags #{:y :x}
          :payload [1 "data" true nil {:inner 99}]}
    :hex "c0ec08caf7df65706f63682acaf7de66726f6ddf616c696365caf7e17061796c6f6164e901de64617461f5f7c0e6caf7df696e6e65725063caf7de74616773c1e6caf7db78caf7db79"}])

(def ^{:doc "Fixed NIST golden vectors for pure synchronous SHA-256."}
  sha256-golden-vectors
  [{:input ""
    :hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
   {:input "abc"
    :hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
   {:input "hello world"
    :hex "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}
   {:input (apply str (repeat 55 "a"))
    :hex "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"}
   {:input "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    :hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}
   {:input (apply str (repeat 64 "a"))
    :hex "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"}
   {:input (apply str (repeat 1000 "a"))
    :hex "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"}])

;; =============================================================================
;; Golden Vector Assertions (Both JVM and CLJS)
;; =============================================================================

(deftest test-canonical-fressian-golden-vectors
  (testing "Exact byte-identical hex output for Canonical Fressian golden vectors"
    (doseq [{:keys [label val hex]} canonical-fressian-golden-vectors]
      (let [encoded (fressian/encode-canonical val)
            actual-hex (fressian/bytes->hex encoded)]
        (is (= hex actual-hex)
            (str "Golden vector failed for: " label))
        (let [decoded (fressian/decode encoded)]
          (if (fressian/bytes? val)
            (is (fressian/byte-array-equals? val decoded))
            (is (= val decoded)
                (str "Decode roundtrip failed for: " label))))))))

(deftest test-sha256-golden-vectors
  (testing "Exact byte-identical hex output for pure synchronous SHA-256 NIST vectors"
    (doseq [{:keys [input hex]} sha256-golden-vectors]
      (is (= hex (crypto/sha256-hex input))))))

(deftest test-map-and-set-order-independence
  (testing "Unordered maps and sets produce byte-identical canonical Fressian bytes"
    (let [m1 {:b 2 :a 1 :c 3}
          m2 (into (sorted-map) {:a 1 :b 2 :c 3})
          m3 (into (sorted-map-by #(compare %2 %1)) {:a 1 :b 2 :c 3})
          s1 #{3 1 2}
          s2 (into (sorted-set) [1 2 3])]
      (is (= (fressian/bytes->hex (fressian/encode-canonical m1))
             (fressian/bytes->hex (fressian/encode-canonical m2))
             (fressian/bytes->hex (fressian/encode-canonical m3))))
      (is (= (fressian/bytes->hex (fressian/encode-canonical s1))
             (fressian/bytes->hex (fressian/encode-canonical s2)))))))

(deftest test-signing-fallback
  (testing "verify-with-fallback verifies v2 canonical bytes, falls back to v1 pr-str bytes, rejects tampered"
    (let [kp (crypto/generate-keypair)
          payload {:offer-id "off-123" :price 50 :caller "alice"}
          ;; v2 canonical signature
          sig-v2 (crypto/sign-canonical (:private kp) payload)
          ;; v1 legacy signature
          v1-bytes (crypto/legacy-pr-str-signing-bytes payload)
          sig-v1 (crypto/sign (:private kp) v1-bytes)]
      ;; Both v2 and v1 verify successfully with fallback enabled
      (is (true? (crypto/verify-with-fallback (:public kp) payload sig-v2)))
      (is (true? (crypto/verify-with-fallback (:public kp) payload sig-v1)))
      ;; When fallback is disabled via dynamic binding, v1 is rejected and v2 passes
      (binding [crypto/*allow-legacy-v1-signing-fallback* false]
        (is (true? (crypto/verify-with-fallback (:public kp) payload sig-v2)))
        (is (false? (crypto/verify-with-fallback (:public kp) payload sig-v1))))
      ;; When fallback is disabled via 4-arity options map, v1 is rejected and v2 passes
      (is (true? (crypto/verify-with-fallback (:public kp) payload sig-v2 {:allow-v1-fallback? false})))
      (is (false? (crypto/verify-with-fallback (:public kp) payload sig-v1 {:allow-v1-fallback? false})))
      ;; Tampered payload fails closed
      (is (false? (crypto/verify-with-fallback (:public kp) (assoc payload :price 999) sig-v2)))
      (is (false? (crypto/verify-with-fallback (:public kp) (assoc payload :price 999) sig-v1))))))

(deftest test-standard-data-fressian-vectors-decode
  (testing "Decodes standard org.clojure/data.fressian byte sequences on both JVM and CLJS"
    ;; Priority cached map: {:a 1, :b "hello"}
    (let [m-bytes (fressian/hex->bytes "c0e8caf7cddb6101caf7cddb62df68656c6c6f")
          m-decoded (fressian/decode m-bytes)]
      (is (= {:a 1 :b "hello"} m-decoded)))
    ;; Priority cached keyword: :foo/bar
    (let [kw-bytes (fressian/hex->bytes "cacddd666f6fcddd626172")
          kw-decoded (fressian/decode kw-bytes)]
      (is (= :foo/bar kw-decoded)))
    ;; Astral string: "😀"
    (let [astral-bytes (fressian/hex->bytes "e0eda0bdedb880")
          astral-decoded (fressian/decode astral-bytes)]
      (is (= "😀" astral-decoded)))
    ;; Mixed astral string: "hi 🌍🚀!"
    (let [mixed-bytes (fressian/hex->bytes "e310686920eda0bcedbc8deda0bdedba8021")
          mixed-decoded (fressian/decode mixed-bytes)]
      (is (= "hi 🌍🚀!" mixed-decoded)))))

#?(:clj
   (deftest test-data-fressian-reader-compatibility
     (testing "Standard org.clojure/data.fressian reads canonical Fressian encoded bytes"
       (doseq [{:keys [label val]} canonical-fressian-golden-vectors]
         (let [encoded (fressian/encode-canonical val)
               std-read (data-fressian/read (java.nio.ByteBuffer/wrap encoded))]
           (if (fressian/bytes? val)
             (is (fressian/byte-array-equals? val std-read) (str "data.fressian read bytes mismatch for: " label))
             (is (= (if (vector? val) (seq val) val)
                    (if (instance? java.util.List std-read) (seq std-read) std-read))
                 (str "data.fressian read mismatch for: " label))))))))

#?(:clj
   (defspec ^{:doc "Property: Bidirectional roundtrip between canonical encoder and standard data.fressian including astral characters."}
     prop-data-fressian-bidirectional-astral-roundtrip 50
     (for-all [s (gen/one-of [gen/string (gen/return "😀") (gen/return "hi 🌍🚀!")])]
              (let [canon-bytes (fressian/encode-canonical s)
                    read-by-std (data-fressian/read (java.nio.ByteBuffer/wrap canon-bytes))
                    std-bytes (fressian/write-standard-fressian s)
                    read-by-canon (fressian/decode std-bytes)]
                (and (= s read-by-std)
                     (= s read-by-canon))))))

;; =============================================================================
;; Generative Property Tests
;; =============================================================================

(def ^{:doc "Generator for primitive leaf values."} gen-leaf
  (gen/one-of
   [gen/small-integer
    gen/large-integer
    (gen/return nil)
    gen/boolean
    gen/string-alphanumeric
    gen/string
    gen/keyword
    gen/keyword-ns]))

(def ^{:doc "Generator for nested portable Clojure data structures."} gen-portable-value
  (gen/recursive-gen
   (fn [inner]
     (gen/one-of
      [(gen/vector inner 0 5)
       (gen/fmap set (gen/vector inner 0 5))
       (gen/map gen/keyword inner {:max-elements 5})]))
   gen-leaf))

(defspec ^{:doc "Property: Arbitrary portable data structures roundtrip through encode-canonical and decode."}
  prop-canonical-fressian-roundtrip 50
  (for-all [val gen-portable-value]
           (let [encoded (fressian/encode-canonical val)
                 decoded (fressian/decode encoded)]
             (= val decoded))))

(defspec ^{:doc "Property: Map key order does not alter canonical Fressian bytes."}
  prop-canonical-fressian-map-set-order-independence 50
  (for-all [kvs (gen/vector (gen/tuple gen/keyword gen/small-integer) 1 6)]
           (let [m1 (into {} kvs)
                 m2 (into (sorted-map) kvs)
                 m3 (into (sorted-map-by #(compare %2 %1)) kvs)
                 h1 (fressian/bytes->hex (fressian/encode-canonical m1))
                 h2 (fressian/bytes->hex (fressian/encode-canonical m2))
                 h3 (fressian/bytes->hex (fressian/encode-canonical m3))]
             (and (= h1 h2) (= h2 h3)))))
