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
   and sequential collections/lazy seqs into persistent vectors."
  [x]
  (cond
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

(defn encode-wire
  "Encodes val into wire bytes using Fressian.
   Pre-normalizes Clojure records and lazy seqs into standard maps and vectors.
   On JVM uses org.clojure.data.fressian; on CLJS uses the zero-dependency Fressian encoder."
  [val]
  (let [norm (normalize-for-wire val)]
    #?(:clj  (write-standard-fressian norm)
       :cljs (encode-canonical norm))))

(def false-sentinel
  "Explicit namespaced sentinel to distinguish boolean false from decoding errors or nil."
  :bitecho.fressian/boolean-false-sentinel-v1)

(def decode-error-sentinel
  "Internal sentinel representing a decode error or failure."
  :bitecho.fressian/decode-error-sentinel-v1)

(defn decode-wire
  "Decodes wire bytes into Clojure persistent data structures.
   Supports Fressian-encoded payloads and legacy Nippy payloads (on JVM).
   Recursively normalizes collections and strips untrusted shell-boundary crypto tags.
   Distinguishes boolean false and nil payloads from decoding failures using an internal sentinel."
  [ba]
  (when (and (bytes? ba) (pos? (count-bytes ba)))
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
      (when-not (identical? raw sentinel)
        (strip-untrusted-crypto-tags (normalize-decoded-wire raw))))))
