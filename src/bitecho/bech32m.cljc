(ns bitecho.bech32m
  "BIP-0350 Bech32m checksummed human-readable encoding for Bitecho keys and addresses.
   Specification: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki"
  (:require [clojure.string :as str]))

(def ^:const ^{:doc "Bech32 charset string."} charset "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
(def ^:const ^{:doc "Bech32m polymod XOR constant per BIP-0350."} m 0x2bc830a3)
(def ^:const ^{:doc "Bech32 generator polynomials for polymod checksum."} generators [0x3B6A57B2 0x26508E6D 0x1EA119FA 0x3D4233DD 0x2A1462B3])

(def ^:private charset-map
  (into {} (map-indexed (fn [i c] [i c]) charset)))

(def ^:private value-map
  (into {} (map-indexed (fn [i c] [c i]) charset)))

(defn polymod
  "Computes the Bech32m polymod checksum over a sequence of 5-bit integers."
  [values]
  (reduce (fn [chk x]
            (let [top (unsigned-bit-shift-right chk 25)
                  chk (bit-xor (bit-shift-left (bit-and chk 0x1FFFFFF) 5) (bit-and x 0x1f))]
              (reduce (fn [c i]
                        (if (pos? (bit-and (bit-shift-right top i) 1))
                          (bit-xor c (nth generators i))
                          c))
                      chk
                      (range 5))))
          1
          values))

(defn- char-code [c]
  #?(:clj  (int c)
     :cljs (.charCodeAt c 0)))

(defn hrp-expand
  "Expands human-readable prefix into 5-bit integers for polymod checksum computation."
  [hrp]
  (let [s (str/lower-case (name hrp))]
    (concat (map #(bit-shift-right (char-code %) 5) s)
            [0]
            (map #(bit-and (char-code %) 0x1f) s))))

(defn checksum
  "Computes the 6 5-bit checksum words for human-readable prefix `hrp` and data words `xs`."
  [hrp xs]
  (let [ys (concat (hrp-expand hrp) xs [0 0 0 0 0 0])
        mod-val (bit-xor (polymod ys) m)]
    (mapv (fn [i]
            (bit-and (bit-shift-right mod-val (* (- 5 i) 5)) 0x1f))
          (range 6))))

(defn verify-checksum
  "Verifies that data words `xs` (including 6-word checksum) match Bech32m constant `m`."
  [hrp xs]
  (= m (polymod (concat (hrp-expand hrp) xs))))

(defn convert-bits
  "Converts integer values from bit-width `from` to `to`.
   If `pad?` is true, remaining bits are padded with zeroes.
   If `pad?` is false, remaining bits must be strictly zero."
  [data from to pad?]
  (let [maxv (dec (bit-shift-left 1 to))
        {:keys [acc bits ret error?]}
        (reduce (fn [{:keys [acc bits ret] :as state} x]
                  (let [v (bit-and (int x) 0xff)]
                    (if (neg? (bit-shift-right v from))
                      (assoc state :error? true)
                      (let [acc (bit-or (bit-shift-left acc from) v)
                            bits (+ bits from)
                            [acc bits ret] (loop [acc acc bits bits ret ret]
                                             (if (>= bits to)
                                               (recur acc (- bits to)
                                                      (conj ret (bit-and (bit-shift-right acc (- bits to)) maxv)))
                                               [acc bits ret]))]
                        {:acc acc :bits bits :ret ret :error? false}))))
                {:acc 0 :bits 0 :ret [] :error? false}
                data)]
    (cond
      error? nil
      pad? (if (pos? bits)
             (conj ret (bit-and (bit-shift-left acc (- to bits)) maxv))
             ret)
      (pos? bits)
      (let [excess (bit-and (bit-shift-left acc (- to bits)) maxv)]
        (if (zero? excess) ret nil))
      :else ret)))

(defn encode
  "Encodes `data-words` (sequence of 5-bit integers) with human-readable prefix `hrp` into a Bech32m string."
  [hrp data-words]
  (let [hrp-str (str/lower-case (name hrp))
        chks (checksum hrp-str data-words)]
    (str hrp-str "1" (apply str (map charset-map (concat data-words chks))))))

(defn decode
  "Decodes a Bech32m string into `[hrp data-words]` (omitting checksum), or nil if invalid.
   Enforces BIP-0350: length between 8 and 90 chars, no mixed case, valid charset and checksum."
  [bech32m-str]
  (when (and (string? bech32m-str)
             (>= (count bech32m-str) 8)
             (<= (count bech32m-str) 90))
    (let [has-lower? (boolean (re-find #"[a-z]" bech32m-str))
          has-upper? (boolean (re-find #"[A-Z]" bech32m-str))]
      (when-not (and has-lower? has-upper?)
        (let [s (str/lower-case bech32m-str)
              sep (str/last-index-of s "1")]
          (when (and (some? sep) (pos? sep) (< sep (dec (count s))))
            (let [hrp (subs s 0 sep)
                  data-str (subs s (inc sep))
                  data (mapv value-map data-str)]
              (when (and (every? some? data)
                         (>= (count data) 6)
                         (verify-checksum hrp data))
                [hrp (subvec data 0 (- (count data) 6))]))))))))

(defn- to-byte-seq [bytes-or-seq]
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

(defn- to-byte-array [seq-of-ints]
  #?(:clj  (byte-array (map byte (map #(if (> % 127) (- % 256) %) seq-of-ints)))
     :cljs (js/Uint8Array. (clj->js seq-of-ints))))

(defn- bytes->hex-str [ba]
  #?(:clj
     (let [sb (StringBuilder.)]
       (doseq [b ba]
         (.append sb (String/format "%02x" (to-array [(bit-and (int b) 0xff)]))))
       (.toString sb))
     :cljs
     (let [arr (if (instance? js/Uint8Array ba) ba (js/Uint8Array. (clj->js ba)))]
       (apply str (map (fn [b]
                         (let [s (.toString b 16)]
                           (if (< (count s) 2) (str "0" s) s)))
                       arr)))))

(defn- hex-str->byte-seq [hex]
  (when (and (string? hex) (even? (count hex)))
    (mapv #(let [sub (subs hex (* 2 %) (+ (* 2 %) 2))]
             #?(:clj  (Integer/parseInt sub 16)
                :cljs (js/parseInt sub 16)))
          (range (/ (count hex) 2)))))

(defn encode-address
  "Encodes raw 8-bit bytes (byte array, Uint8Array, or seq of ints) into a Bech32m address string with `hrp` (default 'ech')."
  ([raw-bytes] (encode-address "ech" raw-bytes))
  ([hrp raw-bytes]
   (when-let [b-seq (to-byte-seq raw-bytes)]
     (when-let [words (convert-bits b-seq 8 5 true)]
       (encode hrp words)))))

(defn decode-address
  "Decodes a Bech32m address string into `{:hrp hrp :bytes byte-array :hex hex-string :words words}` or nil."
  [bech32m-str]
  (when-let [[hrp words] (decode bech32m-str)]
    (when-let [b-seq (convert-bits words 5 8 false)]
      {:hrp hrp
       :bytes (to-byte-array b-seq)
       :hex (bytes->hex-str b-seq)
       :words words})))

(defn pubkey->bech32m
  "Encodes an Ed25519 public key (hex string, byte array, Uint8Array; 32-byte raw or 44-byte SPKI DER)
   into a Bech32m address. If 44-byte SPKI DER / 88-char hex is passed, extracts the 32-byte raw key."
  ([pubkey] (pubkey->bech32m pubkey "ech"))
  ([pubkey hrp]
   (cond
     (string? pubkey)
     (let [hex (str/lower-case (str/trim pubkey))
           raw-hex (if (and (= (count hex) 88) (str/starts-with? hex "302a300506032b6570032100"))
                     (subs hex 24)
                     hex)]
       (encode-address hrp (hex-str->byte-seq raw-hex)))

     (or #?(:clj (bytes? pubkey) :cljs (instance? js/Uint8Array pubkey)) (sequential? pubkey))
     (let [b-seq (to-byte-seq pubkey)
           raw-seq (if (and (= (count b-seq) 44) (= (take 12 b-seq) [48 42 48 5 6 3 43 101 112 3 33 0]))
                     (drop 12 b-seq)
                     b-seq)]
       (encode-address hrp raw-seq))

     :else nil)))

(defn bech32m->pubkey
  "Decodes a Bech32m address into public key hex and bytes.
   Returns `{:hex raw-hex :spki-hex spki-der-hex :bytes byte-array :hrp hrp}`."
  [bech32m-str]
  (when-let [dec (decode-address bech32m-str)]
    (assoc dec :spki-hex (if (= (count (:hex dec)) 64)
                           (str "302a300506032b6570032100" (:hex dec))
                           (:hex dec)))))
