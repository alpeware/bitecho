(ns bitecho.cbor
  "Pure .cljc CBOR (RFC 8949) encoder and recursive index-threading decoder.
   Supports major types:
     0: unsigned integer
     1: negative integer
     2: byte string (byte[] / Uint8Array)
     3: UTF-8 text string
     4: array
     5: map
     6: tagged data item
     7: simple values (true, false, nil)
   Provides `encode`, `decode`, `decode-first`, and `decode-sequence`.")

(defn- to-byte-seq
  "Normalizes byte array, Uint8Array, or sequential collection into a vector of unsigned byte ints (0..255)."
  [bytes-or-seq]
  #?(:clj
     (cond
       (bytes? bytes-or-seq) (mapv #(bit-and (int %) 0xff) ^bytes bytes-or-seq)
       (sequential? bytes-or-seq) (mapv #(bit-and (int %) 0xff) bytes-or-seq)
       :else nil)
     :cljs
     (cond
       (instance? js/Uint8Array bytes-or-seq) (vec (js/Array.from bytes-or-seq))
       (sequential? bytes-or-seq) (mapv #(bit-and (int %) 0xff) bytes-or-seq)
       :else nil)))

(defn- to-byte-array
  "Converts a vector/seq of unsigned byte ints (0..255) into platform byte representation (byte[] on JVM, Uint8Array on CLJS)."
  [seq-of-ints]
  #?(:clj  (byte-array (map byte (map #(if (> % 127) (- % 256) %) seq-of-ints)))
     :cljs (js/Uint8Array. (clj->js seq-of-ints))))

(defn- u16 [b1 b2]
  (bit-or (bit-shift-left (bit-and (int b1) 0xff) 8)
          (bit-and (int b2) 0xff)))

(defn- u32 [b1 b2 b3 b4]
  (+ (* (bit-and (int b1) 0xff) 0x1000000)
     (* (bit-and (int b2) 0xff) 0x10000)
     (* (bit-and (int b3) 0xff) 0x100)
     (bit-and (int b4) 0xff)))

(defn- u64 [b1 b2 b3 b4 b5 b6 b7 b8]
  (+ (* (u32 b1 b2 b3 b4) 4294967296)
     (u32 b5 b6 b7 b8)))

(defn- utf8-bytes [^String s]
  #?(:clj  (mapv #(bit-and (int %) 0xff) (.getBytes s "UTF-8"))
     :cljs (vec (js/Array.from (.encode (js/TextEncoder.) s)))))

(defn- utf8-str [seq-of-ints]
  #?(:clj  (String. ^bytes (to-byte-array seq-of-ints) "UTF-8")
     :cljs (.decode (js/TextDecoder. "UTF-8") (to-byte-array seq-of-ints))))

;;; ---------------------------------------------------------------------------
;;; CBOR Encoding
;;; ---------------------------------------------------------------------------

(defn- encode-header-arg [major arg]
  (let [tag (bit-shift-left (int major) 5)]
    (cond
      (< arg 24)
      [(bit-or tag (int arg))]

      (<= arg 0xff)
      [(bit-or tag 24) (bit-and (int arg) 0xff)]

      (<= arg 0xffff)
      [(bit-or tag 25)
       (bit-and (unsigned-bit-shift-right (int arg) 8) 0xff)
       (bit-and (int arg) 0xff)]

      (<= arg 0xffffffff)
      [(bit-or tag 26)
       (bit-and (unsigned-bit-shift-right arg 24) 0xff)
       (bit-and (unsigned-bit-shift-right arg 16) 0xff)
       (bit-and (unsigned-bit-shift-right arg 8) 0xff)
       (bit-and arg 0xff)]

      :else
      [(bit-or tag 27)
       (bit-and (unsigned-bit-shift-right (long (/ arg 4294967296)) 24) 0xff)
       (bit-and (unsigned-bit-shift-right (long (/ arg 4294967296)) 16) 0xff)
       (bit-and (unsigned-bit-shift-right (long (/ arg 4294967296)) 8) 0xff)
       (bit-and (long (/ arg 4294967296)) 0xff)
       (bit-and (unsigned-bit-shift-right (long (mod arg 4294967296)) 24) 0xff)
       (bit-and (unsigned-bit-shift-right (long (mod arg 4294967296)) 16) 0xff)
       (bit-and (unsigned-bit-shift-right (long (mod arg 4294967296)) 8) 0xff)
       (bit-and (long (mod arg 4294967296)) 0xff)])))

(declare encode-value-bytes)

(defn- encode-map-bytes [m]
  (let [header (encode-header-arg 5 (count m))]
    (reduce (fn [acc [k v]]
              (into acc (concat (encode-value-bytes k) (encode-value-bytes v))))
            header
            m)))

(defn- encode-seq-bytes [xs]
  (let [header (encode-header-arg 4 (count xs))]
    (reduce (fn [acc x]
              (into acc (encode-value-bytes x)))
            header
            xs)))

(defn- encode-value-bytes [val]
  (cond
    (nil? val)
    [0xf6]

    (true? val)
    [0xf5]

    (false? val)
    [0xf4]

    (integer? val)
    (if (neg? val)
      (encode-header-arg 1 (- -1 val))
      (encode-header-arg 0 val))

    (string? val)
    (let [bs (utf8-bytes val)]
      (into (encode-header-arg 3 (count bs)) bs))

    (or (keyword? val) (symbol? val))
    (let [bs (utf8-bytes (name val))]
      (into (encode-header-arg 3 (count bs)) bs))

    #?(:clj (bytes? val) :cljs (instance? js/Uint8Array val))
    (let [bs (to-byte-seq val)]
      (into (encode-header-arg 2 (count bs)) bs))

    (map? val)
    (encode-map-bytes val)

    (sequential? val)
    (encode-seq-bytes val)

    :else
    (throw (ex-info (str "Unsupported type for CBOR encoding: " (type val)) {:val val}))))

(defn encode
  "Encodes a Clojure value into CBOR bytes (byte[] on JVM, Uint8Array on CLJS)."
  [val]
  (to-byte-array (encode-value-bytes val)))

;;; ---------------------------------------------------------------------------
;;; CBOR Decoding
;;; ---------------------------------------------------------------------------

(declare decode-item)

(defn- decode-header [bytes-seq offset]
  (let [cnt (count bytes-seq)]
    (when (>= offset cnt)
      (throw (ex-info "CBOR input truncated at header" {:offset offset :count cnt})))
    (let [b (bit-and (int (nth bytes-seq offset)) 0xff)
          major (unsigned-bit-shift-right b 5)
          info (bit-and b 0x1f)]
      (cond
        (< info 24) [major info (inc offset)]
        (= info 24)
        (if (< (inc offset) cnt)
          [major (bit-and (int (nth bytes-seq (inc offset))) 0xff) (+ offset 2)]
          (throw (ex-info "CBOR input truncated at 1-byte int" {:offset offset})))
        (= info 25)
        (if (< (+ offset 2) cnt)
          [major (u16 (nth bytes-seq (inc offset)) (nth bytes-seq (+ offset 2))) (+ offset 3)]
          (throw (ex-info "CBOR input truncated at 2-byte int" {:offset offset})))
        (= info 26)
        (if (< (+ offset 4) cnt)
          [major (u32 (nth bytes-seq (+ offset 1)) (nth bytes-seq (+ offset 2))
                      (nth bytes-seq (+ offset 3)) (nth bytes-seq (+ offset 4))) (+ offset 5)]
          (throw (ex-info "CBOR input truncated at 4-byte int" {:offset offset})))
        (= info 27)
        (if (< (+ offset 8) cnt)
          [major (u64 (nth bytes-seq (+ offset 1)) (nth bytes-seq (+ offset 2))
                      (nth bytes-seq (+ offset 3)) (nth bytes-seq (+ offset 4))
                      (nth bytes-seq (+ offset 5)) (nth bytes-seq (+ offset 6))
                      (nth bytes-seq (+ offset 7)) (nth bytes-seq (+ offset 8))) (+ offset 9)]
          (throw (ex-info "CBOR input truncated at 8-byte int" {:offset offset})))
        :else (throw (ex-info (str "Unsupported CBOR additional info: " info) {:info info :offset offset}))))))

(defn decode-item
  "Decodes a single CBOR data item from `bytes-seq` starting at index `offset`.
   Returns `[item next-offset]`."
  [bytes-seq offset]
  (let [[major arg next-offset] (decode-header bytes-seq offset)]
    (case major
      0 [arg next-offset]
      1 [(- -1 arg) next-offset]
      2 (if (<= (+ next-offset arg) (count bytes-seq))
          [(to-byte-array (subvec bytes-seq next-offset (+ next-offset arg))) (+ next-offset arg)]
          (throw (ex-info "CBOR byte string truncated" {:needed arg :remaining (- (count bytes-seq) next-offset)})))
      3 (if (<= (+ next-offset arg) (count bytes-seq))
          [(utf8-str (subvec bytes-seq next-offset (+ next-offset arg))) (+ next-offset arg)]
          (throw (ex-info "CBOR text string truncated" {:needed arg :remaining (- (count bytes-seq) next-offset)})))
      4 (loop [i 0 cur next-offset acc []]
          (if (< i arg)
            (let [[item nxt] (decode-item bytes-seq cur)]
              (recur (inc i) nxt (conj acc item)))
            [acc cur]))
      5 (loop [i 0 cur next-offset acc (array-map)]
          (if (< i arg)
            (let [[k nxt-k] (decode-item bytes-seq cur)
                  [v nxt-v] (decode-item bytes-seq nxt-k)]
              (recur (inc i) nxt-v (assoc acc k v)))
            [acc cur]))
      6 (let [[val nxt] (decode-item bytes-seq next-offset)]
          [{:cbor/tag arg :value val} nxt])
      7 (case arg
          20 [false next-offset]
          21 [true next-offset]
          22 [nil next-offset]
          23 [nil next-offset]
          (throw (ex-info (str "Unknown CBOR simple value: " arg) {:arg arg :offset offset}))))))

(defn decode-first
  "Decodes the first CBOR data item from `bytes-or-seq` starting at `offset` (default 0).
   Returns `[item next-offset]`."
  ([bytes-or-seq] (decode-first bytes-or-seq 0))
  ([bytes-or-seq offset]
   (try
     (when-let [b-seq (to-byte-seq bytes-or-seq)]
       (when (< offset (count b-seq))
         (decode-item b-seq offset)))
     (catch #?(:clj Exception :cljs :default) _
       nil))))

(defn decode
  "Decodes the first CBOR item from `bytes-or-seq`. Returns the decoded value."
  [bytes-or-seq]
  (try
    (first (decode-first bytes-or-seq 0))
    (catch #?(:clj Exception :cljs :default) _
      nil)))

(defn decode-sequence
  "Decodes a sequence of concatenated CBOR data items from `bytes-or-seq` starting at `offset` (default 0)
   until end-of-input. Returns a vector of all decoded items."
  ([bytes-or-seq] (decode-sequence bytes-or-seq 0))
  ([bytes-or-seq offset]
   (try
     (when-let [b-seq (to-byte-seq bytes-or-seq)]
       (loop [cur offset acc []]
         (if (< cur (count b-seq))
           (let [res (decode-item b-seq cur)
                 [item nxt] res]
             (if (and nxt (> nxt cur))
               (recur nxt (conj acc item))
               acc))
           acc)))
     (catch #?(:clj Exception :cljs :default) _
       nil))))
