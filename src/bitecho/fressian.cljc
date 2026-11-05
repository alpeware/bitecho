(ns bitecho.fressian
  "Deterministic Canonical Fressian Codec & Scoped Portable Subset for Bitecho.
   Implements Step 8A per Milestone 8 and Standing Constraint 4:
   - Portable subset: nil, boolean, int64, bytes (byte[]/Uint8Array), string (UTF-8),
     keyword, symbol, vector, set, map.
   - Deterministic Canonical Fressian Mode: sorted map keys, sorted set elements,
     compact integer widths, raw byte chunks, UTF-8 strings.
   - Fully compatible with standard org.clojure/data.fressian readers on JVM.
   - Zero-dependency implementation running identically on Clojure and ClojureScript.
   - Canonical signing-byte construction and N/N-1 rolling-upgrade verification helpers."
  (:refer-clojure :exclude [bytes?])
  #?(:clj
     (:require [clojure.data.fressian :as data-fressian]
               [taoensso.nippy :as nippy])))

;; =============================================================================
;; Portable Byte Utilities
;; =============================================================================

(defn bytes?
  "Returns true if x is a raw byte array (byte[] on JVM, Uint8Array on JS)."
  [x]
  #?(:clj  (clojure.core/bytes? x)
     :cljs (instance? js/Uint8Array x)))

(defn count-bytes
  "Returns the length in bytes of x."
  ^long [x]
  #?(:clj  (alength ^bytes x)
     :cljs (.-length x)))

(defn- nth-byte
  "Returns byte value at index i from a byte array."
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

(defn utf8->bytes
  "Encodes a string to UTF-8 bytes."
  ^bytes [^String s]
  #?(:clj  (.getBytes s "UTF-8")
     :cljs (.encode (js/TextEncoder.) (str s))))

(defn bytes->utf8
  "Decodes UTF-8 bytes to a string."
  [ba]
  #?(:clj  (String. ^bytes ba "UTF-8")
     :cljs (.decode (js/TextDecoder.) ba)))

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

(defn string->cesu8-bytes
  "Encodes a string as CESU-8 bytes (UTF-16 code units encoded in 1-3 bytes each).
   Guarantees byte-level compatibility with org.clojure/data.fressian on astral-plane characters."
  [s]
  #?(:clj
     (let [s (str s)
           len (.length ^String s)
           bos (java.io.ByteArrayOutputStream.)]
       (dotimes [i len]
         (let [c (int (.charAt ^String s i))]
           (cond
             (<= c 0x007f)
             (.write bos (unchecked-byte c))

             (<= c 0x07ff)
             (do
               (.write bos (unchecked-byte (bit-or 0xc0 (bit-shift-right c 6))))
               (.write bos (unchecked-byte (bit-or 0x80 (bit-and c 0x3f)))))

             :else
             (do
               (.write bos (unchecked-byte (bit-or 0xe0 (bit-shift-right c 12))))
               (.write bos (unchecked-byte (bit-or 0x80 (bit-and (bit-shift-right c 6) 0x3f))))
               (.write bos (unchecked-byte (bit-or 0x80 (bit-and c 0x3f))))))))
       (.toByteArray bos))
     :cljs
     (let [s (str s)
           len (.-length s)
           out (js/Array.)]
       (dotimes [i len]
         (let [c (.charCodeAt s i)]
           (cond
             (<= c 0x007f)
             (.push out c)

             (<= c 0x07ff)
             (do
               (.push out (bit-or 0xc0 (bit-shift-right c 6)))
               (.push out (bit-or 0x80 (bit-and c 0x3f))))

             :else
             (do
               (.push out (bit-or 0xe0 (bit-shift-right c 12)))
               (.push out (bit-or 0x80 (bit-and (bit-shift-right c 6) 0x3f)))
               (.push out (bit-or 0x80 (bit-and c 0x3f)))))))
       (js/Uint8Array. out))))

(defn cesu8-bytes->string
  "Decodes CESU-8 bytes into a string, with permissive 4-byte UTF-8 fallback."
  [ba]
  #?(:clj
     (let [len (alength ^bytes ba)
           sb (StringBuilder.)]
       (loop [i 0]
         (when (< i len)
           (let [b0 (bit-and (aget ^bytes ba i) 0xff)]
             (cond
               (< b0 0x80)
               (do (.append sb (char b0)) (recur (inc i)))

               (< b0 0xe0)
               (let [b1 (bit-and (aget ^bytes ba (inc i)) 0xff)
                     c (bit-or (bit-shift-left (bit-and b0 0x1f) 6) (bit-and b1 0x3f))]
                 (.append sb (char c))
                 (recur (+ i 2)))

               (< b0 0xf0)
               (let [b1 (bit-and (aget ^bytes ba (inc i)) 0xff)
                     b2 (bit-and (aget ^bytes ba (+ i 2)) 0xff)
                     c (bit-or (bit-shift-left (bit-and b0 0x0f) 12)
                               (bit-shift-left (bit-and b1 0x3f) 6)
                               (bit-and b2 0x3f))]
                 (.append sb (char c))
                 (recur (+ i 3)))

               (< b0 0xf8)
               (let [b1 (bit-and (aget ^bytes ba (inc i)) 0xff)
                     b2 (bit-and (aget ^bytes ba (+ i 2)) 0xff)
                     b3 (bit-and (aget ^bytes ba (+ i 3)) 0xff)
                     cp (bit-or (bit-shift-left (bit-and b0 0x07) 18)
                                (bit-shift-left (bit-and b1 0x3f) 12)
                                (bit-shift-left (bit-and b2 0x3f) 6)
                                (bit-and b3 0x3f))
                     adj (- cp 0x10000)
                     hi (+ 0xd800 (bit-shift-right adj 10))
                     lo (+ 0xdc00 (bit-and adj 0x3ff))]
                 (.append sb (char hi))
                 (.append sb (char lo))
                 (recur (+ i 4)))

               :else
               (recur (inc i))))))
       (.toString sb))
     :cljs
     (let [len (.-length ba)
           chars (js/Array.)]
       (loop [i 0]
         (when (< i len)
           (let [b0 (aget ba i)]
             (cond
               (< b0 0x80)
               (do (.push chars b0) (recur (inc i)))

               (< b0 0xe0)
               (let [b1 (aget ba (inc i))
                     c (bit-or (bit-shift-left (bit-and b0 0x1f) 6) (bit-and b1 0x3f))]
                 (.push chars c)
                 (recur (+ i 2)))

               (< b0 0xf0)
               (let [b1 (aget ba (+ i 1))
                     b2 (aget ba (+ i 2))
                     c (bit-or (bit-shift-left (bit-and b0 0x0f) 12)
                               (bit-shift-left (bit-and b1 0x3f) 6)
                               (bit-and b2 0x3f))]
                 (.push chars c)
                 (recur (+ i 3)))

               (< b0 0xf8)
               (let [b1 (aget ba (+ i 1))
                     b2 (aget ba (+ i 2))
                     b3 (aget ba (+ i 3))
                     cp (bit-or (bit-shift-left (bit-and b0 0x07) 18)
                                (bit-shift-left (bit-and b1 0x3f) 12)
                                (bit-shift-left (bit-and b2 0x3f) 6)
                                (bit-and b3 0x3f))
                     adj (- cp 0x10000)
                     hi (+ 0xd800 (bit-shift-right adj 10))
                     lo (+ 0xdc00 (bit-and adj 0x3ff))]
                 (.push chars hi)
                 (.push chars lo)
                 (recur (+ i 4)))

               :else
               (recur (inc i))))))
       (let [chunk-size 4096
             num-chunks (js/Math.ceil (/ (.-length chars) chunk-size))
             result (js/Array.)]
         (dotimes [c num-chunks]
           (let [sub (.slice chars (* c chunk-size) (* (inc c) chunk-size))]
             (.push result (.apply (.-fromCharCode js/String) nil sub))))
         (.join result "")))))

(defn byte-array-equals?
  "Checks byte equality between two byte arrays."
  [a b]
  (if (or (nil? a) (nil? b))
    (identical? a b)
    #?(:clj  (java.util.Arrays/equals ^bytes a ^bytes b)
       :cljs (and (bytes? a)
                  (bytes? b)
                  (= (.-length a) (.-length b))
                  (loop [i 0]
                    (if (= i (.-length a))
                      true
                      (if (= (aget a i) (aget b i))
                        (recur (inc i))
                        false)))))))

(defn concat-bytes
  "Concatenates byte arrays / Uint8Arrays into a single byte array."
  ([] #?(:clj (byte-array 0) :cljs (js/Uint8Array. 0)))
  ([a] a)
  ([a b]
   #?(:clj  (let [la (alength ^bytes a)
                  lb (alength ^bytes b)
                  out (byte-array (+ la lb))]
              (System/arraycopy a 0 out 0 la)
              (System/arraycopy b 0 out la lb)
              out)
      :cljs (let [la (.-length a)
                  lb (.-length b)
                  out (js/Uint8Array. (+ la lb))]
              (.set out a 0)
              (.set out b la)
              out)))
  ([a b & more]
   (reduce concat-bytes (concat-bytes a b) more)))

(defn bytes->hex
  "Converts a byte array / Uint8Array to a lowercase hex string."
  [ba]
  (if (nil? ba)
    ""
    #?(:clj  (let [sb (StringBuilder. (* 2 (alength ^bytes ba)))]
               (doseq [b ba]
                 (.append sb (String/format "%02x" (to-array [(bit-and b 0xff)]))))
               (.toString sb))
       :cljs (let [len (.-length ba)
                   parts #js []]
               (dotimes [i len]
                 (let [hex (.toString (aget ba i) 16)]
                   (.push parts (if (< (.-length hex) 2) (str "0" hex) hex))))
               (.join parts "")))))

(defn hex->bytes
  "Converts a hex string to a byte array / Uint8Array."
  [s]
  (let [s (str s)
        len (count s)]
    (when (odd? len)
      #?(:clj (throw (IllegalArgumentException. (str "Hex string must have an even length: " s)))
         :cljs (throw (js/Error. (str "Hex string must have an even length: " s)))))
    #?(:clj  (let [data (byte-array (quot len 2))]
               (loop [i 0]
                 (if (< i len)
                   (let [high (Character/digit (.charAt s i) 16)
                         low  (Character/digit (.charAt s (inc i)) 16)]
                     (when (or (= high -1) (= low -1))
                       (throw (IllegalArgumentException. (str "Invalid hex character in: " s))))
                     (aset data (quot i 2)
                           (unchecked-byte (+ (bit-shift-left high 4) low)))
                     (recur (+ i 2)))
                   data)))
       :cljs (let [out (js/Uint8Array. (quot len 2))]
               (loop [i 0]
                 (if (< i len)
                   (let [sub (.substring s i (+ i 2))]
                     (when-not (re-matches #"^[0-9a-fA-F]{2}$" sub)
                       (throw (js/Error. (str "Invalid hex character in: " s))))
                     (aset out (quot i 2) (js/parseInt sub 16))
                     (recur (+ i 2)))
                   out))))))

(defn byte-array-compare
  "Lexicographical unsigned comparison of two byte arrays."
  [a b]
  (let [len-a (count-bytes a)
        len-b (count-bytes b)
        min-len (min len-a len-b)]
    (loop [i 0]
      (if (< i min-len)
        (let [va #?(:clj (bit-and (aget ^bytes a i) 0xff) :cljs (aget a i))
              vb #?(:clj (bit-and (aget ^bytes b i) 0xff) :cljs (aget b i))
              diff (- va vb)]
          (if (zero? diff)
            (recur (inc i))
            diff))
        (- len-a len-b)))))

;; =============================================================================
;; Deterministic Canonical Ordering
;; =============================================================================

(defn- canonical-type-rank
  [x]
  (cond
    (nil? x)       0
    (boolean? x)   1
    (number? x)    2
    (string? x)    3
    (keyword? x)   4
    (symbol? x)    5
    (bytes? x)     6
    (vector? x)    7
    (set? x)       8
    (map? x)       9
    :else          10))

(defn canonical-compare
  "Deterministic total ordering for portable Clojure data structures.
   Guarantees byte-identical iteration order across JVM and CLJS for maps and sets."
  [a b]
  (let [ra (canonical-type-rank a)
        rb (canonical-type-rank b)]
    (if (not= ra rb)
      (compare ra rb)
      (case ra
        0 0
        1 (compare (if a 1 0) (if b 1 0))
        2 (compare a b)
        3 (compare (str a) (str b))
        4 (let [c (compare (or (namespace a) "") (or (namespace b) ""))]
            (if (zero? c)
              (compare (name a) (name b))
              c))
        5 (let [c (compare (or (namespace a) "") (or (namespace b) ""))]
            (if (zero? c)
              (compare (name a) (name b))
              c))
        6 (byte-array-compare a b)
        7 (let [ca (count a) cb (count b)
                cdiff (compare ca cb)]
            (if (not= 0 cdiff)
              cdiff
              (loop [i 0]
                (if (= i ca)
                  0
                  (let [c (canonical-compare (nth a i) (nth b i))]
                    (if (not= 0 c)
                      c
                      (recur (inc i))))))))
        8 (let [ca (count a) cb (count b)
                cdiff (compare ca cb)]
            (if (not= 0 cdiff)
              cdiff
              (let [sa (sort canonical-compare a)
                    sb (sort canonical-compare b)]
                (canonical-compare (vec sa) (vec sb)))))
        9 (let [ca (count a) cb (count b)
                cdiff (compare ca cb)]
            (if (not= 0 cdiff)
              cdiff
              (let [ska (sort canonical-compare (keys a))
                    skb (sort canonical-compare (keys b))
                    key-diff (canonical-compare (vec ska) (vec skb))]
                (if (not= 0 key-diff)
                  key-diff
                  (loop [ks ska]
                    (if-let [k (first ks)]
                      (let [c (canonical-compare (get a k) (get b k))]
                        (if (not= 0 c)
                          c
                          (recur (rest ks))))
                      0))))))
        (compare (str a) (str b))))))

;; =============================================================================
;; Fressian Byte Codes (Scoped Subset)
;; =============================================================================

(def ^{:doc "Fressian MAP byte code."} ^:const tag-map 192)
(def ^{:doc "Fressian SET byte code."} ^:const tag-set 193)
(def ^{:doc "Fressian SYM byte code."} ^:const tag-sym 201)
(def ^{:doc "Fressian KEY byte code."} ^:const tag-key 202)
(def ^{:doc "Fressian GET_PRIORITY_CACHE byte code."} ^:const tag-get-priority-cache 204)
(def ^{:doc "Fressian PUT_PRIORITY_CACHE byte code."} ^:const tag-put-priority-cache 205)
(def ^{:doc "Fressian BYTES_PACKED_LENGTH_START byte code."} ^:const tag-bytes-packed-length-start 208)
(def ^{:doc "Fressian BYTES_PACKED_LENGTH_END byte code."} ^:const tag-bytes-packed-length-end 216)
(def ^{:doc "Fressian BYTES_CHUNK byte code."} ^:const tag-bytes-chunk 216)
(def ^{:doc "Fressian BYTES byte code."} ^:const tag-bytes 217)
(def ^{:doc "Fressian STRING_PACKED_LENGTH_START byte code."} ^:const tag-string-packed-length-start 218)
(def ^{:doc "Fressian STRING_PACKED_LENGTH_END byte code."} ^:const tag-string-packed-length-end 226)
(def ^{:doc "Fressian STRING_CHUNK byte code."} ^:const tag-string-chunk 226)
(def ^{:doc "Fressian STRING byte code."} ^:const tag-string 227)
(def ^{:doc "Fressian LIST_PACKED_LENGTH_START byte code."} ^:const tag-list-packed-length-start 228)
(def ^{:doc "Fressian LIST_PACKED_LENGTH_END byte code."} ^:const tag-list-packed-length-end 236)
(def ^{:doc "Fressian LIST byte code."} ^:const tag-list 236)
(def ^{:doc "Fressian TRUE byte code."} ^:const tag-true 245)
(def ^{:doc "Fressian FALSE byte code."} ^:const tag-false 246)
(def ^{:doc "Fressian NULL byte code."} ^:const tag-null 247)
(def ^{:doc "Fressian INT byte code."} ^:const tag-int 248)
(def ^{:doc "Fressian RESET_CACHES byte code."} ^:const tag-reset-caches 254)
(def ^{:doc "Fressian PRIORITY_CACHE_PACKED_START byte code."} ^:const tag-priority-cache-packed-start 128)
(def ^{:doc "Fressian PRIORITY_CACHE_PACKED_END byte code."} ^:const tag-priority-cache-packed-end 160)

;; =============================================================================
;; Byte Writer Protocol & Implementations
;; =============================================================================

(defprotocol IByteWriter
  (write-raw-byte [this b])
  (write-raw-bytes [this ba])
  (get-result-bytes [this]))

#?(:clj
   (deftype JVMByteWriter [^java.io.ByteArrayOutputStream baos]
     IByteWriter
     (write-raw-byte [_ b]
       (.write baos (unchecked-int (bit-and b 0xff))))
     (write-raw-bytes [_ ba]
       (.write baos ^bytes ba 0 (alength ^bytes ba)))
     (get-result-bytes [_]
       (.toByteArray baos))))

#?(:cljs
   (deftype JSByteWriter [arr]
     IByteWriter
     (write-raw-byte [_ b]
       (.push arr (bit-and b 0xff)))
     (write-raw-bytes [_ ba]
       (let [len (.-length ba)]
         (dotimes [i len]
           (.push arr (aget ba i)))))
     (get-result-bytes [_]
       (js/Uint8Array. (clj->js arr)))))

(defn- make-byte-writer []
  #?(:clj  (JVMByteWriter. (java.io.ByteArrayOutputStream. 128))
     :cljs (JSByteWriter. #js [])))

;; =============================================================================
;; Canonical Integer Writer (Fressian Width-Optimized)
;; =============================================================================

(defn- shift-right-helper
  [n shift]
  #?(:clj  (bit-shift-right n shift)
     :cljs (let [b (bit-shift-right (js/BigInt n) (js/BigInt shift))]
             (js/Number (js/BigInt.asIntN 64 b)))))

(defn- write-canonical-int
  [w n]
  (cond
    (= n -1)
    (write-raw-byte w 255)

    (<= 0 n 63)
    (write-raw-byte w (unchecked-int n))

    (<= -4096 n 4095)
    (do
      (write-raw-byte w (+ 80 (unchecked-int (shift-right-helper n 8))))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))

    (<= -524288 n 524287)
    (do
      (write-raw-byte w (+ 104 (unchecked-int (shift-right-helper n 16))))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 8)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))

    (<= -33554432 n 33554431)
    (do
      (write-raw-byte w (+ 114 (unchecked-int (shift-right-helper n 24))))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 16)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 8)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))

    (<= -8589934592 n 8589934591)
    (do
      (write-raw-byte w (+ 118 (unchecked-int (shift-right-helper n 32))))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 24)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 16)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 8)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))

    (<= -2199023255552 n 2199023255551)
    (do
      (write-raw-byte w (+ 122 (unchecked-int (shift-right-helper n 40))))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 32)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 24)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 16)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 8)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))

    (<= -562949953421312 n 562949953421311)
    (do
      (write-raw-byte w (+ 126 (unchecked-int (shift-right-helper n 48))))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 40)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 32)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 24)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 16)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 8)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))

    :else
    (do
      (write-raw-byte w tag-int)
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 56)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 48)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 40)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 32)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 24)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 16)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int (shift-right-helper n 8)) 0xff))
      (write-raw-byte w (bit-and (unchecked-int n) 0xff)))))

(defn- write-count
  [w cnt]
  (write-canonical-int w cnt))

;; =============================================================================
;; Canonical Encoder Core
;; =============================================================================

(declare write-canonical-value)

(defn- write-canonical-bytes
  [w ba]
  (let [len (count-bytes ba)]
    (if (< len 8)
      (do
        (write-raw-byte w (+ tag-bytes-packed-length-start len))
        (write-raw-bytes w ba))
      (do
        (write-raw-byte w tag-bytes)
        (write-count w len)
        (write-raw-bytes w ba)))))

(defn- write-canonical-string
  [w s]
  (let [cesu8 (string->cesu8-bytes s)
        len (count-bytes cesu8)]
    (if (< len 8)
      (do
        (write-raw-byte w (+ tag-string-packed-length-start len))
        (write-raw-bytes w cesu8))
      (do
        (write-raw-byte w tag-string)
        (write-count w len)
        (write-raw-bytes w cesu8)))))

(defn- write-canonical-vector
  [w v]
  (let [cnt (count v)]
    (if (< cnt 8)
      (write-raw-byte w (+ tag-list-packed-length-start cnt))
      (do
        (write-raw-byte w tag-list)
        (write-count w cnt)))
    (doseq [item v]
      (write-canonical-value w item))))

(defn- write-canonical-value
  [w val]
  (cond
    (nil? val)
    (write-raw-byte w tag-null)

    (true? val)
    (write-raw-byte w tag-true)

    (false? val)
    (write-raw-byte w tag-false)

    (integer? val)
    (write-canonical-int w val)

    (bytes? val)
    (write-canonical-bytes w val)

    (string? val)
    (write-canonical-string w val)

    (keyword? val)
    (do
      (write-raw-byte w tag-key)
      (if-let [ns (namespace val)]
        (write-canonical-string w ns)
        (write-raw-byte w tag-null))
      (write-canonical-string w (name val)))

    (symbol? val)
    (do
      (write-raw-byte w tag-sym)
      (if-let [ns (namespace val)]
        (write-canonical-string w ns)
        (write-raw-byte w tag-null))
      (write-canonical-string w (name val)))

    (set? val)
    (let [sorted-items (vec (sort canonical-compare val))]
      (write-raw-byte w tag-set)
      (write-canonical-vector w sorted-items))

    (map? val)
    (let [sorted-ks (sort canonical-compare (keys val))
          flat-items (vec (mapcat (fn [k] [k (get val k)]) sorted-ks))]
      (write-raw-byte w tag-map)
      (write-canonical-vector w flat-items))

    (sequential? val)
    (write-canonical-vector w (vec val))

    :else
    (throw (ex-info (str "Unsupported canonical Fressian type: " (type val))
                    {:val val}))))

(defn encode-canonical
  "Encodes a portable data structure into deterministic Canonical Fressian bytes.
   Returns byte[] on JVM, Uint8Array on ClojureScript.
   Guarantees:
   - Map keys deterministically sorted.
   - Set elements deterministically sorted.
   - Minimal canonical compact integer width.
   - Standard Fressian byte-code conformance readable by standard readers."
  [val]
  (let [w (make-byte-writer)]
    (write-canonical-value w val)
    (get-result-bytes w)))

;; =============================================================================
;; Reader / Decoder
;; =============================================================================

(defprotocol IByteReader
  (read-raw-byte [this])
  (read-slice [this n]))

#?(:clj
   (deftype JVMByteReader [^bytes ba ^:unsynchronized-mutable ^int idx ^int len]
     IByteReader
     (read-raw-byte [_]
       (if (< idx len)
         (let [b (bit-and (aget ba idx) 0xff)]
           (set! idx (unchecked-inc-int idx))
           b)
         (throw (java.io.EOFException. "Unexpected EOF in Fressian stream"))))
     (read-slice [_ n]
       (let [n-int (int n)
             end (unchecked-add-int idx n-int)]
         (if (<= end len)
           (let [res (java.util.Arrays/copyOfRange ba idx end)]
             (set! idx end)
             res)
           (throw (java.io.EOFException. "Unexpected EOF in Fressian stream")))))))

#?(:cljs
   (deftype JSByteReader [ba ^:mutable idx len]
     IByteReader
     (read-raw-byte [_]
       (if (< idx len)
         (let [b (aget ba idx)]
           (set! idx (inc idx))
           b)
         (throw (ex-info "Unexpected EOF in Fressian stream" {}))))
     (read-slice [_ n]
       (let [end (+ idx n)]
         (if (<= end len)
           (let [res (.subarray ba idx end)]
             (set! idx end)
             res)
           (throw (ex-info "Unexpected EOF in Fressian stream" {})))))))

(defn- make-byte-reader [ba]
  #?(:clj  (JVMByteReader. ba 0 (alength ^bytes ba))
     :cljs (JSByteReader. ba 0 (.-length ba))))

(declare decode-value)

(defn- read-packed-int
  [rdr code]
  (cond
    (= code 255)
    -1

    (<= 0 code 63)
    code

    (<= 64 code 95)
    (let [b0 (- code 80)
          b1 (read-raw-byte rdr)]
      (+ (bit-shift-left b0 8) b1))

    (<= 96 code 111)
    (let [b0 (- code 104)
          b1 (read-raw-byte rdr)
          b2 (read-raw-byte rdr)]
      (+ (bit-shift-left b0 16) (bit-shift-left b1 8) b2))

    (<= 112 code 115)
    (let [b0 (- code 114)
          b1 (read-raw-byte rdr)
          b2 (read-raw-byte rdr)
          b3 (read-raw-byte rdr)]
      (+ (bit-shift-left b0 24) (bit-shift-left b1 16) (bit-shift-left b2 8) b3))

    (<= 116 code 119)
    (let [b0 (- code 118)
          b1 (read-raw-byte rdr)
          b2 (read-raw-byte rdr)
          b3 (read-raw-byte rdr)
          b4 (read-raw-byte rdr)]
      #?(:clj  (+ (bit-shift-left (long b0) 32)
                  (bit-shift-left (long b1) 24)
                  (bit-shift-left (long b2) 16)
                  (bit-shift-left (long b3) 8)
                  (long b4))
         :cljs (let [hi (+ (bit-shift-left b0 8) b1)
                     lo (+ (bit-shift-left b2 16) (bit-shift-left b3 8) b4)]
                 (+ (* hi 0x1000000) lo))))

    (<= 120 code 123)
    (let [b0 (- code 122)
          b1 (read-raw-byte rdr)
          b2 (read-raw-byte rdr)
          b3 (read-raw-byte rdr)
          b4 (read-raw-byte rdr)
          b5 (read-raw-byte rdr)]
      #?(:clj  (+ (bit-shift-left (long b0) 40)
                  (bit-shift-left (long b1) 32)
                  (bit-shift-left (long b2) 24)
                  (bit-shift-left (long b3) 16)
                  (bit-shift-left (long b4) 8)
                  (long b5))
         :cljs (let [hi (+ (bit-shift-left b0 16) (bit-shift-left b1 8) b2)
                     lo (+ (bit-shift-left b3 16) (bit-shift-left b4 8) b5)]
                 (+ (* hi 0x1000000) lo))))

    (<= 124 code 127)
    (let [b0 (- code 126)
          b1 (read-raw-byte rdr)
          b2 (read-raw-byte rdr)
          b3 (read-raw-byte rdr)
          b4 (read-raw-byte rdr)
          b5 (read-raw-byte rdr)
          b6 (read-raw-byte rdr)]
      #?(:clj  (+ (bit-shift-left (long b0) 48)
                  (bit-shift-left (long b1) 40)
                  (bit-shift-left (long b2) 32)
                  (bit-shift-left (long b3) 24)
                  (bit-shift-left (long b4) 16)
                  (bit-shift-left (long b5) 8)
                  (long b6))
         :cljs (let [b (js/BigInt.asIntN 64
                                         (bit-or
                                          (bit-shift-left (js/BigInt b0) (js/BigInt 48))
                                          (bit-shift-left (js/BigInt b1) (js/BigInt 40))
                                          (bit-shift-left (js/BigInt b2) (js/BigInt 32))
                                          (bit-shift-left (js/BigInt b3) (js/BigInt 24))
                                          (bit-shift-left (js/BigInt b4) (js/BigInt 16))
                                          (bit-shift-left (js/BigInt b5) (js/BigInt 8))
                                          (js/BigInt b6)))]
                 (js/Number b))))

    (= code tag-int)
    (let [b0 (read-raw-byte rdr)
          b1 (read-raw-byte rdr)
          b2 (read-raw-byte rdr)
          b3 (read-raw-byte rdr)
          b4 (read-raw-byte rdr)
          b5 (read-raw-byte rdr)
          b6 (read-raw-byte rdr)
          b7 (read-raw-byte rdr)]
      #?(:clj  (+ (bit-shift-left (long b0) 56)
                  (bit-shift-left (long b1) 48)
                  (bit-shift-left (long b2) 40)
                  (bit-shift-left (long b3) 32)
                  (bit-shift-left (long b4) 24)
                  (bit-shift-left (long b5) 16)
                  (bit-shift-left (long b6) 8)
                  (long b7))
         :cljs (let [b (js/BigInt.asIntN 64
                                         (bit-or
                                          (bit-shift-left (js/BigInt b0) (js/BigInt 56))
                                          (bit-shift-left (js/BigInt b1) (js/BigInt 48))
                                          (bit-shift-left (js/BigInt b2) (js/BigInt 40))
                                          (bit-shift-left (js/BigInt b3) (js/BigInt 32))
                                          (bit-shift-left (js/BigInt b4) (js/BigInt 24))
                                          (bit-shift-left (js/BigInt b5) (js/BigInt 16))
                                          (bit-shift-left (js/BigInt b6) (js/BigInt 8))
                                          (js/BigInt b7)))]
                 (js/Number b))))

    :else
    (throw (ex-info (str "Expected integer code, got: " code) {:code code}))))

(defn- decode-count
  [rdr]
  (let [code (read-raw-byte rdr)]
    (read-packed-int rdr code)))

(defn- decode-value
  [rdr cache-atom]
  (let [code (read-raw-byte rdr)]
    (cond
      (= code tag-null)
      nil

      (= code tag-true)
      true

      (= code tag-false)
      false

      (or (<= 0 code 63)
          (= code 255)
          (<= 64 code 127)
          (= code tag-int))
      (read-packed-int rdr code)

      (<= tag-bytes-packed-length-start code (dec tag-bytes-packed-length-end))
      (let [len (- code tag-bytes-packed-length-start)]
        (read-slice rdr len))

      (= code tag-bytes-chunk)
      (let [initial-len (decode-count rdr)
            initial-chunk (read-slice rdr initial-len)]
        (loop [chunks [initial-chunk]]
          (let [next-code (read-raw-byte rdr)]
            (cond
              (= next-code tag-bytes-chunk)
              (let [len (decode-count rdr)
                    chunk (read-slice rdr len)]
                (recur (conj chunks chunk)))

              (<= tag-bytes-packed-length-start next-code (dec tag-bytes-packed-length-end))
              (let [len (- next-code tag-bytes-packed-length-start)
                    chunk (read-slice rdr len)]
                (apply concat-bytes (conj chunks chunk)))

              (= next-code tag-bytes)
              (let [len (decode-count rdr)
                    chunk (read-slice rdr len)]
                (apply concat-bytes (conj chunks chunk)))

              :else
              (throw (ex-info (str "Unexpected code in chunked bytes: " next-code) {:code next-code}))))))

      (= code tag-bytes)
      (let [len (decode-count rdr)]
        (read-slice rdr len))

      (<= tag-string-packed-length-start code (dec tag-string-packed-length-end))
      (let [len (- code tag-string-packed-length-start)
            cesu8 (read-slice rdr len)]
        (cesu8-bytes->string cesu8))

      (= code tag-string-chunk)
      (let [initial-len (decode-count rdr)
            initial-chunk (read-slice rdr initial-len)]
        (loop [chunks [initial-chunk]]
          (let [next-code (read-raw-byte rdr)]
            (cond
              (= next-code tag-string-chunk)
              (let [len (decode-count rdr)
                    chunk (read-slice rdr len)]
                (recur (conj chunks chunk)))

              (<= tag-string-packed-length-start next-code (dec tag-string-packed-length-end))
              (let [len (- next-code tag-string-packed-length-start)
                    chunk (read-slice rdr len)]
                (cesu8-bytes->string (apply concat-bytes (conj chunks chunk))))

              (= next-code tag-string)
              (let [len (decode-count rdr)
                    chunk (read-slice rdr len)]
                (cesu8-bytes->string (apply concat-bytes (conj chunks chunk))))

              :else
              (throw (ex-info (str "Unexpected code in chunked string: " next-code) {:code next-code}))))))

      (= code tag-string)
      (let [len (decode-count rdr)
            cesu8 (read-slice rdr len)]
        (cesu8-bytes->string cesu8))

      (= code tag-key)
      (let [ns (decode-value rdr cache-atom)
            name (decode-value rdr cache-atom)]
        (if ns (keyword ns name) (keyword name)))

      (= code tag-sym)
      (let [ns (decode-value rdr cache-atom)
            name (decode-value rdr cache-atom)]
        (if ns (symbol ns name) (symbol name)))

      (<= tag-list-packed-length-start code (dec tag-list-packed-length-end))
      (let [cnt (- code tag-list-packed-length-start)]
        (loop [i 0 acc (transient [])]
          (if (< i cnt)
            (recur (inc i) (conj! acc (decode-value rdr cache-atom)))
            (persistent! acc))))

      (= code tag-list)
      (let [cnt (decode-count rdr)]
        (loop [i 0 acc (transient [])]
          (if (< i cnt)
            (recur (inc i) (conj! acc (decode-value rdr cache-atom)))
            (persistent! acc))))

      (= code tag-set)
      (let [items (decode-value rdr cache-atom)]
        (set items))

      (= code tag-map)
      (let [items (decode-value rdr cache-atom)]
        (into {} (map vec (partition 2 items))))

      (= code tag-put-priority-cache)
      (let [obj (decode-value rdr cache-atom)]
        (swap! cache-atom conj obj)
        obj)

      (<= tag-priority-cache-packed-start code (dec tag-priority-cache-packed-end))
      (let [idx (- code tag-priority-cache-packed-start)]
        (get @cache-atom idx))

      (= code tag-get-priority-cache)
      (let [idx (decode-count rdr)]
        (get @cache-atom idx))

      (= code tag-reset-caches)
      (do
        (reset! cache-atom [])
        (decode-value rdr cache-atom))

      :else
      (throw (ex-info (str "Unrecognized Fressian byte code: " code) {:code code})))))

(defn decode
  "Decodes a Fressian byte array into Clojure persistent data structures.
   Accepts byte[] on JVM, Uint8Array on ClojureScript.
   Decodes both Canonical Fressian mode and standard priority-cached Fressian streams.
   Recursively strips untrusted shell-boundary crypto tags from the result."
  [ba]
  (let [rdr (make-byte-reader ba)
        cache (atom [])
        val (decode-value rdr cache)]
    (strip-untrusted-crypto-tags val)))

;; =============================================================================
;; JVM Standard data.fressian Interop
;; =============================================================================

#?(:clj
   (defn write-standard-fressian
     "Writes val using org.clojure.data.fressian on the JVM. Returns byte[]."
     ^bytes [val]
     (let [buf (data-fressian/write val)
           n (.remaining buf)
           ba (byte-array n)]
       (.get buf ba)
       ba)))

#?(:clj
   (defn read-standard-fressian
     "Reads bytes using org.clojure.data.fressian on the JVM."
     [^bytes ba]
     (data-fressian/read (java.nio.ByteBuffer/wrap ba))))

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
;; Wire Codec (Step 9A)
;; =============================================================================

(defn normalize-for-wire
  "Recursively pre-normalizes Clojure data structures for wire encoding:
   converts defrecords and maps into standard persistent maps,
   sequential collections/lazy seqs into persistent vectors, and
   JVM Byte/Short boxed primitives into Long so data.fressian can serialize them."
  [x]
  (cond
    #?@(:clj [(or (instance? Byte x) (instance? Short x))
              (long x)])

    (record? x)
    (reduce-kv (fn [m k v]
                 (assoc m (normalize-for-wire k) (normalize-for-wire v)))
               {}
               x)

    (map? x)
    (reduce-kv (fn [m k v]
                 (assoc m (normalize-for-wire k) (normalize-for-wire v)))
               {}
               x)

    (vector? x)
    (mapv normalize-for-wire x)

    (set? x)
    (into #{} (map normalize-for-wire) x)

    (sequential? x)
    (mapv normalize-for-wire x)

    :else x))

#?(:clj
   (defn normalize-decoded-wire
     "Recursively normalizes Java collection types decoded by standard Fressian into
      standard Clojure persistent data structures."
     [x]
     (cond
       (instance? java.util.Map x)
       (reduce (fn [m ^java.util.Map$Entry e]
                 (assoc m
                        (normalize-decoded-wire (.getKey e))
                        (normalize-decoded-wire (.getValue e))))
               {}
               (.entrySet ^java.util.Map x))

       (instance? java.util.List x)
       (mapv normalize-decoded-wire x)

       (instance? java.util.Set x)
       (into #{} (map normalize-decoded-wire) x)

       (sequential? x)
       (mapv normalize-decoded-wire x)

       :else x))
   :cljs
   (defn normalize-decoded-wire
     "Normalizes collections into standard Clojure persistent data structures."
     [x]
     (cond
       (map? x)
       (reduce-kv (fn [m k v]
                    (assoc m (normalize-decoded-wire k) (normalize-decoded-wire v)))
                  {}
                  x)

       (vector? x)
       (mapv normalize-decoded-wire x)

       (set? x)
       (into #{} (map normalize-decoded-wire) x)

       (sequential? x)
       (mapv normalize-decoded-wire x)

       :else x)))

(defn encode-wire-uncompressed
  "Encodes val into uncompressed Fressian wire bytes.
   Pre-normalizes Clojure records, lazy seqs, and JVM Byte/Short primitives.
   On JVM uses org.clojure.data.fressian; on CLJS uses the zero-dependency Fressian encoder."
  [val]
  (let [norm (normalize-for-wire val)]
    #?(:clj  (write-standard-fressian norm)
       :cljs (encode-canonical norm))))

;; =============================================================================
;; Pure-CLJC LZ4 Raw Block Codec & BTEC Wire Framing (H-2 / Seq 220)
;; =============================================================================

(def wire-compression-threshold-bytes
  "Minimum uncompressed Fressian payload byte length (> 1 KiB) before attempting LZ4 compression."
  1024)

(def max-wire-decompressed-bytes
  "Maximum allowed uncompressed payload size (1 MiB) when decoding a BTEC compressed frame."
  1048576)

(def btec-tag-lz4
  "Algorithm selector byte for raw LZ4 block compression in a BTEC frame."
  1)

(defn- u8
  ^long [ba ^long idx]
  #?(:clj  (bit-and (long (aget ^bytes ba (int idx))) 0xff)
     :cljs (aget ba idx)))

(defn- aset-u8!
  [ba ^long idx ^long v]
  #?(:clj  (aset ^bytes ba (int idx) (unchecked-byte v))
     :cljs (aset ba idx (bit-and v 0xff))))

(defn- write-lz4-run-length
  [w ^long len]
  (loop [rem-len len]
    (if (>= rem-len 255)
      (do
        (write-raw-byte w 255)
        (recur (- rem-len 255)))
      (write-raw-byte w rem-len))))

(defn- lz4-hash4
  ^long [ba ^long pos]
  (let [v (bit-or (u8 ba pos)
                  (bit-shift-left (u8 ba (+ pos 1)) 8)
                  (bit-shift-left (u8 ba (+ pos 2)) 16)
                  (bit-shift-left (u8 ba (+ pos 3)) 24))
        prod #?(:clj  (unchecked-multiply-int (unchecked-int v) -1640531535)
                :cljs (js/Math.imul v -1640531535))]
    (bit-and (unsigned-bit-shift-right prod 20) 0xfff)))

(defn lz4-compress-block
  "Pure-CLJC raw LZ4 block compressor compatible with standard LZ4 block decoders
   (including io.airlift.compress.lz4.Lz4Decompressor).
   Enforces standard LZ4 block safety margins (MIN_MATCH=4, LAST_LITERAL_SIZE=5, MF_LIMIT=12)."
  [input-bytes]
  (let [in-len (count-bytes input-bytes)]
    (if (zero? in-len)
      #?(:clj (byte-array 0) :cljs (js/Uint8Array. 0))
      (let [w (make-byte-writer)
            match-limit (- in-len 5)
            mf-limit (- in-len 12)
            htable #?(:clj  (int-array 4096 -1)
                      :cljs (let [a (js/Int32Array. 4096)] (.fill a -1) a))]
        (loop [anchor 0
               pos 0]
          (if (> pos mf-limit)
            ;; Emit final literal-only sequence from anchor..in-len
            (let [lit-len (- in-len anchor)]
              (write-raw-byte w (bit-shift-left (min lit-len 15) 4))
              (when (>= lit-len 15)
                (write-lz4-run-length w (- lit-len 15)))
              (loop [i anchor]
                (when (< i in-len)
                  (write-raw-byte w (u8 input-bytes i))
                  (recur (inc i))))
              (get-result-bytes w))
            (let [h (lz4-hash4 input-bytes pos)
                  ref-pos (long (aget htable h))
                  _ (aset htable h (int pos))
                  offset (- pos ref-pos)
                  match? (and (>= ref-pos 0)
                              (pos? offset)
                              (<= offset 65535)
                              (= (u8 input-bytes ref-pos) (u8 input-bytes pos))
                              (= (u8 input-bytes (+ ref-pos 1)) (u8 input-bytes (+ pos 1)))
                              (= (u8 input-bytes (+ ref-pos 2)) (u8 input-bytes (+ pos 2)))
                              (= (u8 input-bytes (+ ref-pos 3)) (u8 input-bytes (+ pos 3))))]
              (if-not match?
                (recur anchor (inc pos))
                (let [mlen (loop [m 4]
                             (if (and (< (+ pos m) match-limit)
                                      (= (u8 input-bytes (+ ref-pos m))
                                         (u8 input-bytes (+ pos m))))
                               (recur (inc m))
                               m))
                      lit-len (- pos anchor)
                      m-extra (- mlen 4)
                      token (bit-or (bit-shift-left (min lit-len 15) 4)
                                    (min m-extra 15))]
                  (write-raw-byte w token)
                  (when (>= lit-len 15)
                    (write-lz4-run-length w (- lit-len 15)))
                  (loop [i anchor]
                    (when (< i pos)
                      (write-raw-byte w (u8 input-bytes i))
                      (recur (inc i))))
                  (write-raw-byte w (bit-and offset 0xff))
                  (write-raw-byte w (bit-and (unsigned-bit-shift-right offset 8) 0xff))
                  (when (>= m-extra 15)
                    (write-lz4-run-length w (- m-extra 15)))
                  (let [next-pos (+ pos mlen)]
                    (recur next-pos next-pos)))))))))))

(defn lz4-decompress-block
  "Pure-CLJC raw LZ4 block decompressor with strict bounds checking.
   Throws ExceptionInfo with :reason :corrupt-compressed-frame on any malformed input."
  ([compressed-bytes orig-len]
   (lz4-decompress-block compressed-bytes 0 (count-bytes compressed-bytes) orig-len))
  ([compressed-bytes start-idx end-idx orig-len]
   (let [orig-len (long orig-len)
         start-idx (long start-idx)
         end-idx (long end-idx)
         in-len (- end-idx start-idx)]
     (cond
       (or (neg? orig-len) (> orig-len max-wire-decompressed-bytes))
       (throw (ex-info (str "BTEC decompressed size exceeds 1 MiB limit: " orig-len)
                       {:reason :decompressed-size-exceeded :orig-len orig-len}))

       (zero? orig-len)
       (if (zero? in-len)
         #?(:clj (byte-array 0) :cljs (js/Uint8Array. 0))
         (throw (ex-info "Corrupt LZ4 block: non-empty input for zero-length output"
                         {:reason :corrupt-compressed-frame})))

       (<= in-len 0)
       (throw (ex-info "Corrupt LZ4 block: empty input for non-zero output"
                       {:reason :corrupt-compressed-frame}))

       :else
       (let [out #?(:clj (byte-array orig-len) :cljs (js/Uint8Array. orig-len))]
         (loop [in-pos start-idx
                out-pos 0]
           (if (>= in-pos end-idx)
             (if (= out-pos orig-len)
               out
               (throw (ex-info "Corrupt LZ4 block: unexpected end of stream"
                               {:reason :corrupt-compressed-frame})))
             (let [token (u8 compressed-bytes in-pos)
                   in-pos-1 (inc in-pos)
                   lit-base (unsigned-bit-shift-right token 4)
                   [lit-len in-pos-2] (if (= lit-base 15)
                                        (loop [acc 15
                                               p in-pos-1]
                                          (when (>= p end-idx)
                                            (throw (ex-info "Corrupt LZ4 block: truncated literal length"
                                                            {:reason :corrupt-compressed-frame})))
                                          (let [b (u8 compressed-bytes p)
                                                next-acc (+ acc b)]
                                            (when (> next-acc orig-len)
                                              (throw (ex-info "Corrupt LZ4 block: literal length overflow"
                                                              {:reason :corrupt-compressed-frame})))
                                            (if (= b 255)
                                              (recur next-acc (inc p))
                                              [next-acc (inc p)])))
                                        [lit-base in-pos-1])
                   lit-end-in (+ in-pos-2 lit-len)
                   lit-end-out (+ out-pos lit-len)]
               (when (or (> lit-end-in end-idx) (> lit-end-out orig-len))
                 (throw (ex-info "Corrupt LZ4 block: literal copy out of bounds"
                                 {:reason :corrupt-compressed-frame})))
               (loop [i 0]
                 (when (< i lit-len)
                   (aset-u8! out (+ out-pos i) (u8 compressed-bytes (+ in-pos-2 i)))
                   (recur (inc i))))
               (if (= lit-end-in end-idx)
                 (if (= lit-end-out orig-len)
                   out
                   (throw (ex-info "Corrupt LZ4 block: output size mismatch after final literals"
                                   {:reason :corrupt-compressed-frame})))
                 (do
                   (when (> (+ lit-end-in 2) end-idx)
                     (throw (ex-info "Corrupt LZ4 block: truncated match offset"
                                     {:reason :corrupt-compressed-frame})))
                   (let [offset (bit-or (u8 compressed-bytes lit-end-in)
                                        (bit-shift-left (u8 compressed-bytes (inc lit-end-in)) 8))
                         in-pos-3 (+ lit-end-in 2)]
                     (when (or (<= offset 0) (> offset lit-end-out))
                       (throw (ex-info "Corrupt LZ4 block: invalid match offset"
                                       {:reason :corrupt-compressed-frame :offset offset})))
                     (let [m-base (bit-and token 0x0f)
                           [match-len in-pos-4] (if (= m-base 15)
                                                  (loop [acc 19
                                                         p in-pos-3]
                                                    (when (>= p end-idx)
                                                      (throw (ex-info "Corrupt LZ4 block: truncated match length"
                                                                      {:reason :corrupt-compressed-frame})))
                                                    (let [b (u8 compressed-bytes p)
                                                          next-acc (+ acc b)]
                                                      (when (> (+ lit-end-out next-acc) orig-len)
                                                        (throw (ex-info "Corrupt LZ4 block: match length overflow"
                                                                        {:reason :corrupt-compressed-frame})))
                                                      (if (= b 255)
                                                        (recur next-acc (inc p))
                                                        [next-acc (inc p)])))
                                                  [(+ m-base 4) in-pos-3])
                           match-end-out (+ lit-end-out match-len)
                           match-src (- lit-end-out offset)]
                       (when (> match-end-out orig-len)
                         (throw (ex-info "Corrupt LZ4 block: match copy overrun"
                                         {:reason :corrupt-compressed-frame})))
                       (loop [i 0]
                         (when (< i match-len)
                           (aset-u8! out (+ lit-end-out i) (u8 out (+ match-src i)))
                           (recur (inc i))))
                       (recur in-pos-4 match-end-out)))))))))))))

(defn btec-compressed-frame?
  "Returns true if ba is a byte array of length >= 4 starting with the 'BTEC' magic header (0x42 0x54 0x45 0x43)."
  [ba]
  (and (bytes? ba)
       (>= (count-bytes ba) 4)
       (= (u8 ba 0) 0x42)
       (= (u8 ba 1) 0x54)
       (= (u8 ba 2) 0x45)
       (= (u8 ba 3) 0x43)))

(defn- wrap-btec-lz4-frame
  [compressed-bytes ^long orig-len]
  (let [c-len (count-bytes compressed-bytes)
        total-len (+ 9 c-len)
        out #?(:clj (byte-array total-len) :cljs (js/Uint8Array. total-len))]
    (aset-u8! out 0 0x42) ;; 'B'
    (aset-u8! out 1 0x54) ;; 'T'
    (aset-u8! out 2 0x45) ;; 'E'
    (aset-u8! out 3 0x43) ;; 'C'
    (aset-u8! out 4 btec-tag-lz4)
    (aset-u8! out 5 (bit-and (unsigned-bit-shift-right orig-len 24) 0xff))
    (aset-u8! out 6 (bit-and (unsigned-bit-shift-right orig-len 16) 0xff))
    (aset-u8! out 7 (bit-and (unsigned-bit-shift-right orig-len 8) 0xff))
    (aset-u8! out 8 (bit-and orig-len 0xff))
    (loop [i 0]
      (when (< i c-len)
        (aset-u8! out (+ 9 i) (u8 compressed-bytes i))
        (recur (inc i))))
    out))

(defn- unwrap-btec-frame
  "Strictly validates and decompresses a BTEC-prefixed frame.
   Fails closed by throwing ExceptionInfo on truncated header (< 9 bytes),
   unknown algorithm tag (!= 0x01), > 1 MiB claimed size, or corrupt LZ4 stream."
  [ba]
  (let [total-len (count-bytes ba)]
    (when (< total-len 9)
      (throw (ex-info "Truncated BTEC compressed frame"
                      {:reason :corrupt-compressed-frame :length total-len})))
    (let [tag (u8 ba 4)]
      (when (not= tag btec-tag-lz4)
        (throw (ex-info (str "Unsupported BTEC compression tag: " tag)
                        {:reason :unknown-compression-tag :tag tag})))
      (let [b5 (u8 ba 5)
            b6 (u8 ba 6)
            b7 (u8 ba 7)
            b8 (u8 ba 8)
            orig-len (bit-or (bit-shift-left b5 24)
                             (bit-shift-left b6 16)
                             (bit-shift-left b7 8)
                             b8)]
        (when (or (neg? orig-len) (> orig-len max-wire-decompressed-bytes))
          (throw (ex-info (str "BTEC decompressed size exceeds 1 MiB limit: " orig-len)
                          {:reason :decompressed-size-exceeded :orig-len orig-len})))
        (lz4-decompress-block ba 9 total-len orig-len)))))

(defn encode-wire
  "Encodes val into wire bytes using Fressian, applying synchronous LZ4 block compression
   ('BTEC' + tag 0x01 + 4-byte BE original length) when the uncompressed Fressian payload
   exceeds 1 KiB and the compressed frame is strictly smaller than the raw Fressian bytes."
  [val]
  (let [raw-bytes (encode-wire-uncompressed val)
        raw-len (count-bytes raw-bytes)]
    (if (> raw-len wire-compression-threshold-bytes)
      (let [compressed (lz4-compress-block raw-bytes)
            comp-len (count-bytes compressed)]
        (if (< (+ 9 comp-len) raw-len)
          (wrap-btec-lz4-frame compressed raw-len)
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
                        (try (read-standard-fressian ba)
                             (catch Exception _
                               (try (decode ba) (catch Exception _ sentinel))))))
                 (try (read-standard-fressian ba)
                      (catch Exception _
                        (try (decode ba)
                             (catch Exception _
                               (if (nippy-payload? ba)
                                 (try (nippy/thaw ba) (catch Exception _ sentinel))
                                 sentinel))))))
               :cljs
               (try (decode ba)
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
                          (unwrap-btec-frame ba)
                          ba)
          decoded (decode-fressian-or-nippy-bytes payload-bytes)]
      (when-not (identical? decoded decode-error-sentinel)
        decoded))))

(defn decode-wire
  "Decodes wire bytes into Clojure persistent data structures.
   Dispatch order:
   1. BTEC compressed frame check (len >= 4 and 'BTEC' magic) -> LZ4 decompress (tag 0x01 only;
      fails closed returning nil on unknown tag, >1 MiB size, or corrupt stream).
   2. Legacy Nippy payload check (on JVM).
   3. Standard Fressian / portable Fressian decode -> normalize-decoded-wire -> strip-untrusted-crypto-tags."
  [ba]
  (try
    (decode-wire-strict ba)
    (catch #?(:clj Exception :cljs :default) _
      nil)))
