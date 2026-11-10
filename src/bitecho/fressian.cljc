(ns bitecho.fressian
  "Deterministic Canonical Fressian Codec & Wire Envelope Facade for Bitecho.
   Delegates core Fressian binary serialization to pure-CLJC `fressian.core` and
   layered LZ4 (`BTEC`) wire framing to `fressian.lz4` (`alpeware/clj-fressian`),
   while providing Bitecho-specific domain helpers:
   - Recursive stripping of untrusted shell-boundary crypto verification tags.
   - Canonical signing-byte construction and legacy v1 `pr-str` fallback helpers.
   - Legacy Nippy payload detection and transparent JVM rolling-upgrade decoding."
  (:refer-clojure :exclude [bytes?])
  (:require [fressian.core :as fcore]
            [fressian.lz4 :as flz4]
            #?(:clj [taoensso.nippy :as nippy])))

;; =============================================================================
;; Re-exported Portable Byte & String Utilities
;; =============================================================================

(defn bytes?
  "Returns true if x is a raw byte array (byte[] on JVM, Uint8Array on JS)."
  [x]
  (fcore/bytes? x))

(defn count-bytes
  "Returns the length in bytes of x."
  ^long [x]
  (fcore/count-bytes x))

(defn utf8->bytes
  "Encodes a string to UTF-8 bytes."
  ^bytes [^String s]
  (fcore/utf8->bytes s))

(defn bytes->utf8
  "Decodes UTF-8 bytes to a string."
  [ba]
  (fcore/bytes->utf8 ba))

(defn string->cesu8-bytes
  "Encodes a string as CESU-8 bytes (UTF-16 code units encoded in 1-3 bytes each)."
  [s]
  (fcore/string->cesu8-bytes s))

(defn cesu8-bytes->string
  "Decodes CESU-8 bytes into a string, with permissive 4-byte UTF-8 fallback."
  [ba]
  (fcore/cesu8-bytes->string ba))

(defn byte-array-equals?
  "Checks byte equality between two byte arrays."
  [a b]
  (fcore/byte-array-equals? a b))

(defn concat-bytes
  "Concatenates byte arrays / Uint8Arrays into a single byte array."
  ([] (fcore/concat-bytes))
  ([a] (fcore/concat-bytes a))
  ([a b] (fcore/concat-bytes a b))
  ([a b & more] (apply fcore/concat-bytes a b more)))

(defn bytes->hex
  "Converts a byte array / Uint8Array to a lowercase hex string."
  [ba]
  (fcore/bytes->hex ba))

(defn hex->bytes
  "Converts a hex string to a byte array / Uint8Array."
  [s]
  (fcore/hex->bytes s))

(defn byte-array-compare
  "Lexicographic unsigned byte comparison of two byte arrays."
  [a b]
  (fcore/byte-array-compare a b))

(defn canonical-compare
  "Deterministic total ordering for portable Clojure data structures."
  [a b]
  (fcore/canonical-compare a b))

;; =============================================================================
;; Untrusted Crypto Tag Sanitization & Legacy Nippy Detection
;; =============================================================================

(defn- nth-byte
  "Returns signed byte value at index i from a byte array."
  [ba i]
  #?(:clj  (aget ^bytes ba (int i))
     :cljs (aget ba i)))

(defn nippy-payload?
  "Returns true if the byte array appears to be a Nippy serialized payload
   (starts with Nippy uncompressed magic header 'NPY' [78 80 89] or compressed [0x88 78 80 89])."
  [ba]
  (and (bytes? ba)
       (let [cnt (count-bytes ba)]
         (or (and (>= cnt 3)
                  (= (nth-byte ba 0) 78)
                  (= (nth-byte ba 1) 80)
                  (= (nth-byte ba 2) 89))
             (and (>= cnt 4)
                  (let [b0 (nth-byte ba 0)]
                    (or (= b0 -120) (= b0 136) (= (bit-and b0 0xff) 0x88)))
                  (= (nth-byte ba 1) 78)
                  (= (nth-byte ba 2) 80)
                  (= (nth-byte ba 3) 89))))))

(def ^:private untrusted-crypto-keys
  #{:crypto/verified? :crypto/verified-a? :crypto/verified-b?
    "crypto/verified?" "crypto/verified-a?" "crypto/verified-b?"
    ":crypto/verified?" ":crypto/verified-a?" ":crypto/verified-b?"})

(defn- untrusted-crypto-key? [k]
  (contains? untrusted-crypto-keys k))

(defn strip-untrusted-crypto-tags
  "Recursively removes untrusted shell-boundary crypto tags (:crypto/verified?, :crypto/verified-a?,
   :crypto/verified-b?, and their string equivalents) from data structures (maps, vectors, sets), preserving records."
  [x]
  (cond
    (record? x)
    (reduce-kv (fn [r k v]
                 (if (untrusted-crypto-key? k)
                   (dissoc r k)
                   (assoc r k (strip-untrusted-crypto-tags v))))
               x
               x)

    (map? x)
    (reduce-kv (fn [m k v]
                 (if (untrusted-crypto-key? k)
                   m
                   (assoc m k (strip-untrusted-crypto-tags v))))
               (empty x)
               x)

    (vector? x)
    (mapv strip-untrusted-crypto-tags x)

    (set? x)
    (into (empty x) (map strip-untrusted-crypto-tags x))

    (seq? x)
    (map strip-untrusted-crypto-tags x)

    :else x))

;; =============================================================================
;; Canonical & Standard Fressian Codec Facade
;; =============================================================================

(defn encode-canonical
  "Encodes a Clojure data structure into deterministic Canonical Fressian bytes."
  [val]
  (fcore/encode-canonical val))

(defn decode
  "Decodes a Fressian byte array into Clojure persistent data structures
   and recursively strips untrusted shell-boundary crypto tags."
  [ba]
  (strip-untrusted-crypto-tags (fcore/decode ba)))

(defn write-standard-fressian
  "Writes val using standard Fressian priority/struct caching via pure-CLJC `fressian.core/write`."
  ^bytes [val & opts]
  (apply fcore/write val opts))

(defn read-standard-fressian
  "Reads bytes using pure-CLJC `fressian.core/read`."
  [ba & opts]
  (apply fcore/read ba opts))

;; =============================================================================
;; Canonical Signing & N/N-1 Rolling Verification Helpers (Standing Constraint 4)
;; =============================================================================

(defn canonical-signing-bytes
  "Encodes payload into deterministic canonical Fressian bytes (v2 format).
   If payload is already a raw byte array, returns it directly.
   Always recursively strips untrusted shell-boundary crypto tags before encoding."
  [payload]
  (if (bytes? payload)
    payload
    (encode-canonical (strip-untrusted-crypto-tags payload))))

(defn legacy-pr-str-signing-bytes
  "Encodes payload using (pr-str payload) as UTF-8 bytes (v1 legacy format).
   If payload is already a raw byte array, returns it directly.
   Always recursively strips untrusted shell-boundary crypto tags before encoding."
  [payload]
  (if (bytes? payload)
    payload
    (utf8->bytes (pr-str (strip-untrusted-crypto-tags payload)))))

;; =============================================================================
;; Wire Normalization & Layered LZ4 (`BTEC`) Wire Codec
;; =============================================================================

(defn normalize-for-wire
  "Recursively pre-normalizes Clojure data structures for wire encoding."
  [x]
  (fcore/normalize-for-wire x))

(defn normalize-decoded-wire
  "Recursively normalizes decoded collections into standard Clojure persistent data structures."
  [x]
  (fcore/normalize-decoded-wire x))

(defn encode-wire-uncompressed
  "Encodes val into uncompressed Fressian wire bytes."
  [val]
  (let [norm (normalize-for-wire val)]
    #?(:clj  (fcore/write norm)
       :cljs (fcore/encode-canonical norm))))

(def wire-compression-threshold-bytes
  "Minimum uncompressed Fressian payload byte length (> 1 KiB) before attempting LZ4 compression."
  flz4/wire-compression-threshold-bytes)

(def max-wire-decompressed-bytes
  "Maximum allowed uncompressed payload size (1 MiB) when decoding a BTEC compressed frame."
  flz4/max-wire-decompressed-bytes)

(def btec-tag-lz4
  "Algorithm selector byte for raw LZ4 block compression in a BTEC frame."
  flz4/btec-tag-lz4)

(defn lz4-compress-block
  "Pure-CLJC raw LZ4 block compressor."
  [input-bytes]
  (flz4/lz4-compress-block input-bytes))

(defn lz4-decompress-block
  "Pure-CLJC raw LZ4 block decompressor with strict bounds checking."
  ([compressed-bytes orig-len]
   (flz4/lz4-decompress-block compressed-bytes orig-len))
  ([compressed-bytes start-idx end-idx orig-len]
   (flz4/lz4-decompress-block compressed-bytes start-idx end-idx orig-len)))

(defn btec-compressed-frame?
  "Returns true if ba is a byte array of length >= 4 starting with the 'BTEC' magic header."
  [ba]
  (flz4/btec-compressed-frame? ba))

(defn encode-wire
  "Encodes val into wire bytes using Fressian, applying synchronous LZ4 block compression
   ('BTEC' + tag 0x01 + 4-byte BE original length) when the uncompressed Fressian payload
   exceeds 1 KiB and the compressed frame is strictly smaller than the raw Fressian bytes.
   Accepts optional `:compress? false` to disable LZ4 framing."
  [val & {:keys [compress?] :or {compress? true}}]
  (let [raw-bytes (encode-wire-uncompressed val)
        raw-len (count-bytes raw-bytes)]
    (if (and compress? (> raw-len wire-compression-threshold-bytes))
      (let [compressed (lz4-compress-block raw-bytes)
            comp-len (count-bytes compressed)]
        (if (< (+ 9 comp-len) raw-len)
          (flz4/wrap-btec-lz4-frame compressed raw-len)
          raw-bytes))
      raw-bytes)))

(def false-sentinel
  "Explicit namespaced sentinel to distinguish boolean false from decoding errors or nil."
  :bitecho.fressian/boolean-false-sentinel-v1)

(def decode-error-sentinel
  "Internal sentinel representing a decode error or failure."
  :bitecho.fressian/decode-error-sentinel-v1)

(defn- decode-fressian-or-nippy-bytes
  [ba]
  (let [sentinel decode-error-sentinel
        raw #?(:clj
               (if (nippy-payload? ba)
                 (try (nippy/thaw ba)
                      (catch Exception _
                        (try (fcore/read ba)
                             (catch Exception _
                               (try (fcore/decode ba) (catch Exception _ sentinel))))))
                 (try (fcore/read ba)
                      (catch Exception _
                        (try (fcore/decode ba)
                             (catch Exception _
                               (if (nippy-payload? ba)
                                 (try (nippy/thaw ba) (catch Exception _ sentinel))
                                 sentinel))))))
               :cljs
               (try (fcore/decode ba)
                    (catch :default _ sentinel)))]
    (if (identical? raw sentinel)
      sentinel
      (strip-untrusted-crypto-tags (normalize-decoded-wire raw)))))

(defn decode-wire-strict
  "Strictly decodes wire bytes, throwing ExceptionInfo with :reason on BTEC compression
   framing violations (:unknown-compression-tag, :decompressed-size-exceeded, :corrupt-compressed-frame)
   or returning nil if Fressian decode fails."
  [ba]
  (when (and (bytes? ba) (pos? (count-bytes ba)))
    (let [payload-bytes (if (btec-compressed-frame? ba)
                          (flz4/unwrap-btec-frame ba)
                          ba)
          decoded (decode-fressian-or-nippy-bytes payload-bytes)]
      (when-not (identical? decoded decode-error-sentinel)
        decoded))))

(defn decode-wire
  "Decodes wire bytes into Clojure persistent data structures."
  [ba]
  (try
    (decode-wire-strict ba)
    (catch #?(:clj Exception :cljs :default) _
      nil)))
