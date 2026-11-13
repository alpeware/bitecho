(ns bitecho.crypto
  "Cryptographic primitives and shell-boundary abstractions for Bitecho:
   - Pure synchronous SHA-256 hashing across JVM and CLJS
   - Seeded portable PRNG protocol (IRandom)
   - Ed25519 signing and verification (JDK on JVM, node:crypto on Node/CLJS)
   - Canonical signing bytes & N/N-1 rolling-upgrade verification (Decision A(i) / Standing Constraint 4)
   - Shell-boundary crypto protocol (ICryptoBoundary) for async envelope pre-verification and egress effects."
  (:require [bitecho.fressian :as fressian])
  #?(:clj
     (:import [java.security MessageDigest KeyPairGenerator KeyFactory Signature]
              [java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec]
              [java.util Random Arrays])))

;; =============================================================================
;; Pure Synchronous SHA-256
;; =============================================================================

#?(:cljs
   (def ^:private node-crypto
     (when (exists? js/require)
       (try (js/require "node:crypto") (catch :default _ nil)))))

#?(:cljs
   (def ^:private sha256-k
     (js/Uint32Array.
      #js [0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5
           0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
           0xd807aa98 0x12835b01 0x243185be 0x550c7dc3
           0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
           0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc
           0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
           0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7
           0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
           0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13
           0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
           0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3
           0xd192e819 0xd6990624 0xf40e3585 0x106aa070
           0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5
           0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
           0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208
           0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2])))

#?(:cljs
   (defn- rotr-32 [x n]
     (bit-or (unsigned-bit-shift-right x n)
             (bit-shift-left x (- 32 n)))))

#?(:cljs
   (defn- pure-cljs-sha256
     [^js/Uint8Array bytes-arr]
     (let [len (.-length bytes-arr)
           bit-len (* len 8)
           pad-len (inc (bit-shift-right (+ len 8) 6))
           blocks (js/Uint32Array. (* pad-len 16))]
       (dotimes [i len]
         (let [word-idx (bit-shift-right i 2)
               byte-shift (* (- 3 (bit-and i 3)) 8)
               curr (aget blocks word-idx)]
           (aset blocks word-idx (bit-or curr (bit-shift-left (aget bytes-arr i) byte-shift)))))
       (let [len-word (bit-shift-right len 2)
             len-shift (* (- 3 (bit-and len 3)) 8)
             curr (aget blocks len-word)]
         (aset blocks len-word (bit-or curr (bit-shift-left 0x80 len-shift))))
       (aset blocks (dec (.-length blocks)) bit-len)
       (aset blocks (- (.-length blocks) 2) (js/Math.floor (/ bit-len 0x100000000)))
       (let [w (js/Uint32Array. 64)]
         (loop [blk-idx 0
                h0 (int 0x6a09e667)
                h1 (int 0xbb67ae85)
                h2 (int 0x3c6ef372)
                h3 (int 0xa54ff53a)
                h4 (int 0x510e527f)
                h5 (int 0x9b05688c)
                h6 (int 0x1f83d9ab)
                h7 (int 0x5be0cd19)]
           (if (< blk-idx (.-length blocks))
             (do
               (dotimes [t 16]
                 (aset w t (aget blocks (+ blk-idx t))))
               (loop [t 16]
                 (when (< t 64)
                   (let [w15 (aget w (- t 15))
                         s0 (bit-xor (rotr-32 w15 7) (rotr-32 w15 18) (unsigned-bit-shift-right w15 3))
                         w2 (aget w (- t 2))
                         s1 (bit-xor (rotr-32 w2 17) (rotr-32 w2 19) (unsigned-bit-shift-right w2 10))
                         val (bit-or (+ (aget w (- t 16)) s0 (aget w (- t 7)) s1) 0)]
                     (aset w t val)
                     (recur (inc t)))))
               (let [[a b c d e f g h]
                     (loop [t 0
                            a h0 b h1 c h2 d h3 e h4 f h5 g h6 h h7]
                       (if (< t 64)
                         (let [s1 (bit-xor (rotr-32 e 6) (rotr-32 e 11) (rotr-32 e 25))
                               ch (bit-xor (bit-and e f) (bit-and (bit-not e) g))
                               temp1 (bit-or (+ h s1 ch (aget sha256-k t) (aget w t)) 0)
                               s0 (bit-xor (rotr-32 a 2) (rotr-32 a 13) (rotr-32 a 22))
                               maj (bit-xor (bit-and a b) (bit-and a c) (bit-and b c))
                               temp2 (bit-or (+ s0 maj) 0)]
                           (recur (inc t)
                                  (bit-or (+ temp1 temp2) 0)
                                  a
                                  b
                                  c
                                  (bit-or (+ d temp1) 0)
                                  e
                                  f
                                  g))
                         [a b c d e f g h]))]
                 (recur (+ blk-idx 16)
                        (bit-or (+ h0 a) 0)
                        (bit-or (+ h1 b) 0)
                        (bit-or (+ h2 c) 0)
                        (bit-or (+ h3 d) 0)
                        (bit-or (+ h4 e) 0)
                        (bit-or (+ h5 f) 0)
                        (bit-or (+ h6 g) 0)
                        (bit-or (+ h7 h) 0))))
             (let [out (js/Uint8Array. 32)
                   h-arr #js [h0 h1 h2 h3 h4 h5 h6 h7]]
               (dotimes [i 8]
                 (let [hv (aget h-arr i)]
                   (aset out (+ (* i 4) 0) (bit-and (unsigned-bit-shift-right hv 24) 0xff))
                   (aset out (+ (* i 4) 1) (bit-and (unsigned-bit-shift-right hv 16) 0xff))
                   (aset out (+ (* i 4) 2) (bit-and (unsigned-bit-shift-right hv 8) 0xff))
                   (aset out (+ (* i 4) 3) (bit-and hv 0xff))))
               out)))))))

(defn sha256
  "Computes the SHA-256 hash of the given byte array or string.
   Pure and synchronous on both JVM and ClojureScript.
   Returns a 32-byte array (byte[] on JVM, Uint8Array on CLJS)."
  [input]
  (let [ba (if (string? input)
             (fressian/utf8->bytes input)
             input)]
    #?(:clj  (let [md (MessageDigest/getInstance "SHA-256")]
               (.digest md ^bytes ba))
       :cljs (pure-cljs-sha256 ba))))

(defn sha256-hex
  "Computes SHA-256 and returns a 64-character lowercase hex string."
  [input]
  (fressian/bytes->hex (sha256 input)))

;; =============================================================================
;; Portable Seeded PRNG Protocol (IRandom) & SplitMix64
;; =============================================================================

(defprotocol IRandom
  (next-int [this] [this bound])
  (next-long [this])
  (next-double [this])
  (next-bytes [this byte-arr])
  (random-state [this])
  (fork-random [this] [this branch-id]))

#?(:clj
   (do
     (def ^:private ^:const SPLITMIX_GAMMA (long -7046029254386353131))
     (def ^:private ^:const SPLITMIX_MIX1  (long -4658895280553007687))
     (def ^:private ^:const SPLITMIX_MIX2  (long -7723592293110705685))

     (defn- mix64-step
       ^long [^long z]
       (let [z1 (unchecked-multiply (bit-xor z (unsigned-bit-shift-right z 30)) SPLITMIX_MIX1)
             z2 (unchecked-multiply (bit-xor z1 (unsigned-bit-shift-right z1 27)) SPLITMIX_MIX2)]
         (bit-xor z2 (unsigned-bit-shift-right z2 31))))

     (defn- branch-id->long [branch-id]
       (cond
         (nil? branch-id) (long 0)
         (number? branch-id) (.longValue ^Number branch-id)
         (keyword? branch-id) (branch-id->long (name branch-id))
         (string? branch-id)
         (let [bs (fressian/utf8->bytes branch-id)
               len (alength ^bytes bs)]
           (loop [i 0
                  h (long -3750763034362895579)]
             (if (= i len)
               h
               (let [b (aget ^bytes bs i)]
                 (recur (inc i)
                        (unchecked-multiply (bit-xor h (bit-and (int b) 0xFF)) (long 1099511628211)))))))
         :else (long (hash branch-id))))))

#?(:cljs
   (do
     (defn- branch-id->bi [branch-id]
       (cond
         (nil? branch-id) (js/BigInt 0)
         (js* "typeof ~{} === 'bigint'" branch-id) branch-id
         (number? branch-id) (js/BigInt (str (long branch-id)))
         (keyword? branch-id) (branch-id->bi (name branch-id))
         (string? branch-id)
         (let [bs (fressian/utf8->bytes branch-id)
               len (.-length bs)]
           (loop [i 0
                  h (js/BigInt "14695981039346656037")]
             (if (= i len)
               (js* "~{} & 18446744073709551615n" h)
               (let [b (js/BigInt (aget bs i))]
                 (recur (inc i)
                        (js* "((~{} ^ ~{}) * 1099511628211n) & 18446744073709551615n" h b))))))
         :else (js/BigInt (str (hash branch-id)))))

     (defn- mix64-bi [z]
       (let [u (js/BigInt.asUintN 64 z)
             z1 (js* "((~{} ^ (~{} >> 30n)) * 13787848793156543929n) & 18446744073709551615n" u u)
             z2 (js* "((~{} ^ (~{} >> 27n)) * 10723151780598845931n) & 18446744073709551615n" z1 z1)
             z3 (js* "(~{} ^ (~{} >> 31n)) & 18446744073709551615n" z2 z2)]
         z3))))

#?(:clj
   (deftype SplitMix64PRNG [state-atom]
     IRandom
     (next-long [_]
       (let [s (swap! state-atom (fn [^long s] (unchecked-add s SPLITMIX_GAMMA)))]
         (mix64-step s)))
     (next-int [this]
       (unchecked-int (next-long this)))
     (next-int [this bound]
       (let [n (bit-and (next-int this) 0x7fffffff)]
         (mod n bound)))
     (next-double [this]
       (let [n (bit-and (next-int this) 0x7fffffff)]
         (/ (double n) 2147483647.0)))
     (next-bytes [this byte-arr]
       (let [len (alength ^bytes byte-arr)]
         (dotimes [i len]
           (aset-byte ^bytes byte-arr i (unchecked-byte (bit-and (next-int this) 0xff))))
         byte-arr))
     (random-state [_]
       @state-atom)
     (fork-random [this]
       (fork-random this nil))
     (fork-random [_ branch-id]
       (let [cur (long @state-atom)
             salt (branch-id->long branch-id)
             new-seed (mix64-step (bit-xor cur salt))]
         (SplitMix64PRNG. (atom new-seed))))

     clojure.lang.IDeref
     (deref [_]
       @state-atom)))

#?(:cljs
   (deftype SplitMix64PRNG [state-atom]
     IRandom
     (next-long [_]
       (let [s (swap! state-atom
                      (fn [s]
                        (let [cur (if (js* "typeof ~{} === 'bigint'" s) s (js/BigInt (str (or s 0))))]
                          (js/BigInt.asIntN 64 (js* "(~{} + 11400714819323198485n) & 18446744073709551615n" cur)))))
             z3 (mix64-bi s)]
         (js/Number (js/BigInt.asIntN 53 z3))))
     (next-int [_]
       (let [s (swap! state-atom
                      (fn [s]
                        (let [cur (if (js* "typeof ~{} === 'bigint'" s) s (js/BigInt (str (or s 0))))]
                          (js/BigInt.asIntN 64 (js* "(~{} + 11400714819323198485n) & 18446744073709551615n" cur)))))
             z3 (mix64-bi s)]
         (js/Number (js/BigInt.asIntN 32 z3))))
     (next-int [this bound]
       (let [n (bit-and (next-int this) 0x7fffffff)]
         (mod n bound)))
     (next-double [this]
       (let [n (bit-and (next-int this) 0x7fffffff)]
         (/ n 0x7fffffff)))
     (next-bytes [this byte-arr]
       (let [len (.-length byte-arr)]
         (dotimes [i len]
           (aset byte-arr i (bit-and (next-int this) 0xff)))
         byte-arr))
     (random-state [_]
       (let [cur @state-atom]
         (if (js* "typeof ~{} === 'bigint'" cur) cur (js/BigInt (str (or cur 0))))))
     (fork-random [this]
       (fork-random this nil))
     (fork-random [_ branch-id]
       (let [cur (if (js* "typeof ~{} === 'bigint'" @state-atom) @state-atom (js/BigInt (str (or @state-atom 0))))
             salt (branch-id->bi branch-id)
             new-seed (mix64-bi (js* "(~{} ^ ~{}) & 18446744073709551615n" cur salt))]
         (SplitMix64PRNG. (atom (js/BigInt.asIntN 64 new-seed)))))

     IDeref
     (-deref [_]
       @state-atom)))

#?(:clj
   (extend-type Random
     IRandom
     (next-int
       ([this] (.nextInt this))
       ([this bound] (.nextInt this (int bound))))
     (next-long [this] (.nextLong this))
     (next-double [this] (.nextDouble this))
     (next-bytes [this byte-arr]
       (.nextBytes this ^bytes byte-arr)
       byte-arr)
     (random-state [_] nil)
     (fork-random
       ([this] (Random. (.nextLong this)))
       ([this _branch-id] (Random. (.nextLong this))))))

(defn make-random
  "Constructs an IRandom seeded SplitMix64 PRNG instance."
  ([]
   #?(:clj  (SplitMix64PRNG. (atom (System/nanoTime)))
      :cljs (SplitMix64PRNG. (atom (js/BigInt (.now js/Date))))))
  ([seed]
   (cond
     (instance? SplitMix64PRNG seed)
     (SplitMix64PRNG. (atom @seed))

     #?@(:clj
         [(instance? Random seed)
          (SplitMix64PRNG. (atom (.nextLong ^Random seed)))
          (number? seed)
          (SplitMix64PRNG. (atom (.longValue ^Number seed)))
          (string? seed)
          (SplitMix64PRNG. (atom (try (Long/parseLong seed) (catch Exception _ (branch-id->long seed)))))
          (nil? seed)
          (SplitMix64PRNG. (atom (long 0)))
          :else
          (SplitMix64PRNG. (atom (long (hash seed))))]
         :cljs
         [(js* "typeof ~{} === 'bigint'" seed)
          (SplitMix64PRNG. (atom seed))
          (number? seed)
          (SplitMix64PRNG. (atom (js/BigInt (str (long seed)))))
          (string? seed)
          (SplitMix64PRNG. (atom (try (js/BigInt seed) (catch :default _ (branch-id->bi seed)))))
          (nil? seed)
          (SplitMix64PRNG. (atom (js/BigInt 0)))
          :else
          (SplitMix64PRNG. (atom (js/BigInt (str (hash seed)))))]))))

(defn random-bytes
  "Generates n random bytes.
   When rng (implementing IRandom) is provided, fills deterministically from rng.
   Otherwise uses SecureRandom on JVM, globalThis.crypto.getRandomValues in Browser,
   or node:crypto randomBytes on Node.js. Fails closed if no CSPRNG is available."
  ([n]
   #?(:clj
      (let [ba (byte-array n)]
        (.nextBytes (java.security.SecureRandom.) ba)
        ba)
      :cljs
      (cond
        (and (exists? js/globalThis) (.-crypto js/globalThis) (.-getRandomValues (.-crypto js/globalThis)))
        (let [buf (js/Uint8Array. n)]
          (.getRandomValues (.-crypto js/globalThis) buf)
          buf)

        node-crypto
        (let [rb-fn (or (aget node-crypto "randomBytes") (.-randomBytes node-crypto))]
          (js/Uint8Array. (.call rb-fn node-crypto n)))

        :else
        (throw (js/Error. "No CSPRNG available (neither globalThis.crypto.getRandomValues nor node:crypto).")))))
  ([rng n]
   (if (satisfies? IRandom rng)
     (let [ba #?(:clj (byte-array n) :cljs (js/Uint8Array. n))]
       (next-bytes rng ba)
       ba)
     (random-bytes n))))

;; =============================================================================
;; Pure Synchronous SHA-512 & RFC 8032 Ed25519 (Browser + CLJS Fallback)
;; =============================================================================

#?(:cljs
   (do
     (def ^:private K512
       (into-array
        [(js/BigInt "0x428a2f98d728ae22") (js/BigInt "0x7137449123ef65cd") (js/BigInt "0xb5c0fbcfec4d3b2f") (js/BigInt "0xe9b5dba58189dbbc")
         (js/BigInt "0x3956c25bf348b538") (js/BigInt "0x59f111f1b605d019") (js/BigInt "0x923f82a4af194f9b") (js/BigInt "0xab1c5ed5da6d8118")
         (js/BigInt "0xd807aa98a3030242") (js/BigInt "0x12835b0145706fbe") (js/BigInt "0x243185be4ee4b28c") (js/BigInt "0x550c7dc3d5ffb4e2")
         (js/BigInt "0x72be5d74f27b896f") (js/BigInt "0x80deb1fe3b1696b1") (js/BigInt "0x9bdc06a725c71235") (js/BigInt "0xc19bf174cf692694")
         (js/BigInt "0xe49b69c19ef14ad2") (js/BigInt "0xefbe4786384f25e3") (js/BigInt "0x0fc19dc68b8cd5b5") (js/BigInt "0x240ca1cc77ac9c65")
         (js/BigInt "0x2de92c6f592b0275") (js/BigInt "0x4a7484aa6ea6e483") (js/BigInt "0x5cb0a9dcbd41fbd4") (js/BigInt "0x76f988da831153b5")
         (js/BigInt "0x983e5152ee66dfab") (js/BigInt "0xa831c66d2db43210") (js/BigInt "0xb00327c898fb213f") (js/BigInt "0xbf597fc7beef0ee4")
         (js/BigInt "0xc6e00bf33da88fc2") (js/BigInt "0xd5a79147930aa725") (js/BigInt "0x06ca6351e003826f") (js/BigInt "0x142929670a0e6e70")
         (js/BigInt "0x27b70a8546d22ffc") (js/BigInt "0x2e1b21385c26c926") (js/BigInt "0x4d2c6dfc5ac42aed") (js/BigInt "0x53380d139d95b3df")
         (js/BigInt "0x650a73548baf63de") (js/BigInt "0x766a0abb3c77b2a8") (js/BigInt "0x81c2c92e47edaee6") (js/BigInt "0x92722c851482353b")
         (js/BigInt "0xa2bfe8a14cf10364") (js/BigInt "0xa81a664bbc423001") (js/BigInt "0xc24b8b70d0f89791") (js/BigInt "0xc76c51a30654be30")
         (js/BigInt "0xd192e819d6ef5218") (js/BigInt "0xd69906245565a910") (js/BigInt "0xf40e35855771202a") (js/BigInt "0x106aa07032bbd1b8")
         (js/BigInt "0x19a4c116b8d2d0c8") (js/BigInt "0x1e376c085141ab53") (js/BigInt "0x2748774cdf8eeb99") (js/BigInt "0x34b0bcb5e19b48a8")
         (js/BigInt "0x391c0cb3c5c95a63") (js/BigInt "0x4ed8aa4ae3418acb") (js/BigInt "0x5b9cca4f7763e373") (js/BigInt "0x682e6ff3d6b2b8a3")
         (js/BigInt "0x748f82ee5defb2fc") (js/BigInt "0x78a5636f43172f60") (js/BigInt "0x84c87814a1f0ab72") (js/BigInt "0x8cc702081a6439ec")
         (js/BigInt "0x90befffa23631e28") (js/BigInt "0xa4506cebde82bde9") (js/BigInt "0xbef9a3f7b2c67915") (js/BigInt "0xc67178f2e372532b")
         (js/BigInt "0xca273eceea26619c") (js/BigInt "0xd186b8c721c0c207") (js/BigInt "0xeada7dd6cde0eb1e") (js/BigInt "0xf57d4f7fee6ed178")
         (js/BigInt "0x06f067aa72176fba") (js/BigInt "0x0a637dc5a2c898a6") (js/BigInt "0x113f9804bef90dae") (js/BigInt "0x1b710b35131c471b")
         (js/BigInt "0x28db77f523047d84") (js/BigInt "0x32caab7b40c72493") (js/BigInt "0x3c9ebe0a15c9bebc") (js/BigInt "0x431d67c49c100d4c")
         (js/BigInt "0x4cc5d4becb3e42b6") (js/BigInt "0x597f299cfc657e2a") (js/BigInt "0x5fcb6fab3ad6faec") (js/BigInt "0x6c44198c4a475817")]))

     (def ^:private H512
       (into-array
        [(js/BigInt "0x6a09e667f3bcc908") (js/BigInt "0xbb67ae8584caa73b") (js/BigInt "0x3c6ef372fe94f82b") (js/BigInt "0xa54ff53a5f1d36f1")
         (js/BigInt "0x510e527fade682d1") (js/BigInt "0x9b05688c2b3e6c1f") (js/BigInt "0x1f83d9abfb41bd6b") (js/BigInt "0x5be0cd19137e2179")]))

     (def ^:private M64 (js/BigInt "0xffffffffffffffff"))

     (defn- rotr64 [x n]
       (let [bn (js/BigInt n)
             b64-n (js/BigInt (- 64 n))]
         (js* "((((~{} >> ~{}) | ((~{} << ~{}) & ~{})) & ~{}))" x bn x b64-n M64 M64)))

     (defn- ed-sha512 [msg]
       (let [len (.-length msg)
             bit-len (js* "(BigInt(~{}) * 8n)" len)
             pad-len (bit-and (+ len 17 127) (bit-not 127))
             buf (js/Uint8Array. pad-len)]
         (.set buf msg 0)
         (aset buf len 0x80)
         (let [bl (atom bit-len)]
           (dotimes [i 8]
             (aset buf (- pad-len 1 i) (js/Number (js* "(~{} & 0xffn)" @bl)))
             (reset! bl (js* "(~{} >> 8n)" @bl))))
         (let [h (into-array (map #(js/BigInt %) H512))
               W (js/Array. 80)]
           (loop [off 0]
             (when (< off pad-len)
               (dotimes [i 16]
                 (let [w (atom (js/BigInt 0))]
                   (dotimes [b 8]
                     (reset! w (js* "((~{} << 8n) | BigInt(~{}))" @w (aget buf (+ off (* i 8) b)))))
                   (aset W i @w)))
               (dotimes [idx (- 80 16)]
                 (let [i (+ idx 16)
                       w-i15 (aget W (- i 15))
                       w-i2 (aget W (- i 2))
                       s0 (js* "(~{} ^ ~{} ^ (~{} >> 7n))" (rotr64 w-i15 1) (rotr64 w-i15 8) w-i15)
                       s1 (js* "(~{} ^ ~{} ^ (~{} >> 6n))" (rotr64 w-i2 19) (rotr64 w-i2 61) w-i2)]
                   (aset W i (js* "((~{} + ~{} + ~{} + ~{}) & ~{})" (aget W (- i 16)) s0 (aget W (- i 7)) s1 M64))))
               (let [a (atom (aget h 0))
                     b (atom (aget h 1))
                     c (atom (aget h 2))
                     d (atom (aget h 3))
                     e (atom (aget h 4))
                     f (atom (aget h 5))
                     g (atom (aget h 6))
                     h-val (atom (aget h 7))]
                 (dotimes [i 80]
                   (let [cur-e @e
                         S1 (js* "(~{} ^ ~{} ^ ~{})" (rotr64 cur-e 14) (rotr64 cur-e 18) (rotr64 cur-e 41))
                         ch (js* "((~{} & ~{}) ^ ((~{} ^ ~{}) & ~{}))" cur-e @f cur-e M64 @g)
                         temp1 (js* "((~{} + ~{} + ~{} + ~{} + ~{}) & ~{})" @h-val S1 ch (aget K512 i) (aget W i) M64)
                         cur-a @a
                         S0 (js* "(~{} ^ ~{} ^ ~{})" (rotr64 cur-a 28) (rotr64 cur-a 34) (rotr64 cur-a 39))
                         maj (js* "(((~{} & ~{}) ^ (~{} & ~{}) ^ (~{} & ~{})))" cur-a @b cur-a @c @b @c)
                         temp2 (js* "((~{} + ~{}) & ~{})" S0 maj M64)]
                     (reset! h-val @g)
                     (reset! g @f)
                     (reset! f @e)
                     (reset! e (js* "((~{} + ~{}) & ~{})" @d temp1 M64))
                     (reset! d @c)
                     (reset! c @b)
                     (reset! b @a)
                     (reset! a (js* "((~{} + ~{}) & ~{})" temp1 temp2 M64))))
                 (aset h 0 (js* "((~{} + ~{}) & ~{})" (aget h 0) @a M64))
                 (aset h 1 (js* "((~{} + ~{}) & ~{})" (aget h 1) @b M64))
                 (aset h 2 (js* "((~{} + ~{}) & ~{})" (aget h 2) @c M64))
                 (aset h 3 (js* "((~{} + ~{}) & ~{})" (aget h 3) @d M64))
                 (aset h 4 (js* "((~{} + ~{}) & ~{})" (aget h 4) @e M64))
                 (aset h 5 (js* "((~{} + ~{}) & ~{})" (aget h 5) @f M64))
                 (aset h 6 (js* "((~{} + ~{}) & ~{})" (aget h 6) @g M64))
                 (aset h 7 (js* "((~{} + ~{}) & ~{})" (aget h 7) @h-val M64)))
               (recur (+ off 128))))
           (let [out (js/Uint8Array. 64)]
             (dotimes [i 8]
               (let [v (atom (aget h i))]
                 (loop [b 7]
                   (when (>= b 0)
                     (aset out (+ (* i 8) b) (js/Number (js* "(~{} & 0xffn)" @v)))
                     (reset! v (js* "(~{} >> 8n)" @v))
                     (recur (dec b))))))
             out))))

     (def ^:private ed-P (js/BigInt "57896044618658097711785492504343953926634992332820282019728792003956564819949"))
     (def ^:private ed-L (js/BigInt "7237005577332262213973186563042994240857116359379907606001950938285454250989"))
     (defn- modP [x] (js* "((((~{} % ~{}) + ~{}) % ~{}))" x ed-P ed-P ed-P))
     (defn- modL [x] (js* "((((~{} % ~{}) + ~{}) % ~{}))" x ed-L ed-L ed-L))
     (defn- modPow [base exp]
       (let [res (atom (js/BigInt 1))
             b (atom (modP base))
             e (atom exp)]
         (while (js* "(~{} > 0n)" @e)
           (when (js* "((~{} & 1n) !== 0n)" @e)
             (reset! res (modP (js* "(~{} * ~{})" @res @b))))
           (reset! b (modP (js* "(~{} * ~{})" @b @b)))
           (reset! e (js* "(~{} >> 1n)" @e)))
         @res))
     (defn- invP [x] (modPow x (js* "(~{} - 2n)" ed-P)))
     (def ^:private ed-D (modP (js* "(-121665n * ~{})" (invP (js/BigInt 121666)))))
     (def ^:private ed-I-SQRT (modPow (js/BigInt 2) (js* "((~{} - 1n) / 4n)" ed-P)))
     (def ^:private ed-BY (modP (js* "(4n * ~{})" (invP (js/BigInt 5)))))
     (def ^:private ed-BX (js/BigInt "15112221349535400772501151409588531511454012693041857206046113283949847762202"))
     (def ^:private ed-B-PT #js [ed-BX ed-BY (js/BigInt 1) (modP (js* "(~{} * ~{})" ed-BX ed-BY))])

     (defn- ptAdd [P1 P2]
       (let [X1 (aget P1 0) Y1 (aget P1 1) Z1 (aget P1 2) T1 (aget P1 3)
             X2 (aget P2 0) Y2 (aget P2 1) Z2 (aget P2 2) T2 (aget P2 3)
             A (modP (js* "((~{} - ~{}) * (~{} - ~{}))" Y1 X1 Y2 X2))
             B (modP (js* "((~{} + ~{}) * (~{} + ~{}))" Y1 X1 Y2 X2))
             C (modP (js* "(2n * ~{} * ~{} * ~{})" ed-D T1 T2))
             D2 (modP (js* "(2n * ~{} * ~{})" Z1 Z2))
             E (modP (js* "(~{} - ~{})" B A))
             F (modP (js* "(~{} - ~{})" D2 C))
             G (modP (js* "(~{} + ~{})" D2 C))
             H (modP (js* "(~{} + ~{})" B A))]
         #js [(modP (js* "(~{} * ~{})" E F))
              (modP (js* "(~{} * ~{})" G H))
              (modP (js* "(~{} * ~{})" F G))
              (modP (js* "(~{} * ~{})" E H))]))

     (defn- scalarMult [k pt]
       (let [R (atom #js [(js/BigInt 0) (js/BigInt 1) (js/BigInt 1) (js/BigInt 0)])
             Q (atom pt)
             n (atom k)]
         (while (js* "(~{} > 0n)" @n)
           (when (js* "((~{} & 1n) !== 0n)" @n)
             (reset! R (ptAdd @R @Q)))
           (reset! Q (ptAdd @Q @Q))
           (reset! n (js* "(~{} >> 1n)" @n)))
         @R))

     (defn- encodePoint [pt]
       (let [X (aget pt 0) Y (aget pt 1) Z (aget pt 2)
             zi (invP Z)
             x (modP (js* "(~{} * ~{})" X zi))
             y (modP (js* "(~{} * ~{})" Y zi))
             out (js/Uint8Array. 32)
             n (atom y)]
         (dotimes [i 32]
           (aset out i (js/Number (js* "(~{} & 0xffn)" @n)))
           (reset! n (js* "(~{} >> 8n)" @n)))
         (aset out 31 (bit-or (aget out 31) (bit-shift-left (js/Number (js* "(~{} & 1n)" x)) 7)))
         out))

     (defn- decodePoint [bytes]
       (if (or (nil? bytes) (not= (.-length bytes) 32))
         nil
         (let [sign (bit-and (unsigned-bit-shift-right (aget bytes 31) 7) 1)
               y (atom (js/BigInt 0))]
           (dotimes [i 32]
             (let [b (if (= i 31) (bit-and (aget bytes i) 0x7f) (aget bytes i))
                   bi (js/BigInt (* i 8))]
               (reset! y (js* "(~{} | (BigInt(~{}) << ~{}))" @y b bi))))
           (if (js* "(~{} >= ~{})" @y ed-P)
             nil
             (let [y-val @y
                   y2 (modP (js* "(~{} * ~{})" y-val y-val))
                   u (modP (js* "(~{} - 1n)" y2))
                   v (modP (js* "((~{} * ~{}) + 1n)" ed-D y2))
                   x-cand1 (modP (js* "(~{} * ~{})" u (invP v)))
                   x-root (modPow x-cand1 (js* "((~{} + 3n) / 8n)" ed-P))
                   x-cand2 (if (js* "(~{} !== ~{})" (modP (js* "(~{} * ~{} * ~{})" x-root x-root v)) u)
                             (let [x-alt (modP (js* "(~{} * ~{})" x-root ed-I-SQRT))]
                               (if (js* "(~{} !== ~{})" (modP (js* "(~{} * ~{} * ~{})" x-alt x-alt v)) u)
                                 nil
                                 x-alt))
                             x-root)]
               (when x-cand2
                 (if (and (js* "(~{} === 0n)" x-cand2) (= sign 1))
                   nil
                   (let [x (if (not= (js/Number (js* "(~{} & 1n)" x-cand2)) sign)
                             (js* "(~{} - ~{})" ed-P x-cand2)
                             x-cand2)]
                     #js [x y-val (js/BigInt 1) (modP (js* "(~{} * ~{})" x y-val))]))))))))

     (defn- decodeLE [bytes]
       (let [n (atom (js/BigInt 0))]
         (dotimes [i (.-length bytes)]
           (let [bi (js/BigInt (* i 8))]
             (reset! n (js* "(~{} | (BigInt(~{}) << ~{}))" @n (aget bytes i) bi))))
         @n))

     (defn- encodeLE32 [num]
       (let [out (js/Uint8Array. 32)
             n (atom num)]
         (dotimes [i 32]
           (aset out i (js/Number (js* "(~{} & 0xffn)" @n)))
           (reset! n (js* "(~{} >> 8n)" @n)))
         out))

     (defn- expandSecret [seed32]
       (let [h (ed-sha512 seed32)
             sBytes (.slice h 0 32)]
         (aset sBytes 0 (bit-and (aget sBytes 0) 248))
         (aset sBytes 31 (bit-and (aget sBytes 31) 127))
         (aset sBytes 31 (bit-or (aget sBytes 31) 64))
         (let [s (decodeLE sBytes)
               prefix (.slice h 32 64)
               pub (encodePoint (scalarMult s ed-B-PT))]
           #js {:s s :prefix prefix :pub pub})))

     (defn- ed-public-key [seed32]
       (.-pub (expandSecret seed32)))

     (defn- ed-sign [seed32 msgBytes]
       (let [expanded (expandSecret seed32)
             s (.-s expanded)
             prefix (.-prefix expanded)
             pub (.-pub expanded)
             rInput (js/Uint8Array. (+ 32 (.-length msgBytes)))]
         (.set rInput prefix 0)
         (.set rInput msgBytes 32)
         (let [r (modL (decodeLE (ed-sha512 rInput)))
               R (encodePoint (scalarMult r ed-B-PT))
               kInput (js/Uint8Array. (+ 64 (.-length msgBytes)))]
           (.set kInput R 0)
           (.set kInput pub 32)
           (.set kInput msgBytes 64)
           (let [k (modL (decodeLE (ed-sha512 kInput)))
                 S (modL (js* "(~{} + (~{} * ~{}))" r k s))
                 sig (js/Uint8Array. 64)]
             (.set sig R 0)
             (.set sig (encodeLE32 S) 32)
             sig))))

     (defn- ed-verify [pub32 msgBytes sig64]
       (if (or (nil? sig64) (not= (.-length sig64) 64) (nil? pub32) (not= (.-length pub32) 32))
         false
         (let [Rbytes (.subarray sig64 0 32)
               Sbytes (.subarray sig64 32 64)
               S (decodeLE Sbytes)]
           (if (js* "(~{} >= ~{})" S ed-L)
             false
             (let [A (decodePoint pub32)
                   R (decodePoint Rbytes)]
               (if (or (nil? A) (nil? R))
                 false
                 (let [kInput (js/Uint8Array. (+ 64 (.-length msgBytes)))]
                   (.set kInput Rbytes 0)
                   (.set kInput pub32 32)
                   (.set kInput msgBytes 64)
                   (let [k (modL (decodeLE (ed-sha512 kInput)))
                         lhs (encodePoint (scalarMult S ed-B-PT))
                         rhs (encodePoint (ptAdd R (scalarMult k A)))]
                     (loop [i 0]
                       (if (< i 32)
                         (if (not= (aget lhs i) (aget rhs i))
                           false
                           (recur (inc i)))
                         true))))))))))

     (def ^:private pure-ed25519-engine
       #js {:sha512 ed-sha512
            :publicKey ed-public-key
            :getPublicKey ed-public-key
            :sign ed-sign
            :verify ed-verify})))

#?(:cljs
   (def ^:private ed25519-spki-prefix (fressian/hex->bytes "302a300506032b6570032100")))
#?(:cljs
   (def ^:private ed25519-pkcs8-prefix (fressian/hex->bytes "302e020100300506032b657004220420")))

(defn sha512
  "Computes synchronous SHA-512 digest of a byte array (or UTF-8 string).
   Uses MessageDigest on JVM and pure ClojureScript SHA-512 on CLJS."
  ^bytes [input]
  (let [b (if (string? input) (fressian/utf8->bytes input) input)]
    #?(:clj (let [md (MessageDigest/getInstance "SHA-512")]
              (.digest md ^bytes b))
       :cljs (.sha512 pure-ed25519-engine b))))

#?(:cljs
   (defn pure-ed25519-keypair
     "Generates an Ed25519 keypair in pure ClojureScript (RFC 8032),
      returning {:public spki-der (44B) :private pkcs8-der (48B)}."
     ([] (pure-ed25519-keypair (random-bytes 32)))
     ([seed32]
      (let [pub-raw (.publicKey pure-ed25519-engine seed32)
            pub-der (fressian/concat-bytes ed25519-spki-prefix pub-raw)
            priv-der (fressian/concat-bytes ed25519-pkcs8-prefix seed32)]
        {:public pub-der :private priv-der :public-key pub-der :private-key priv-der}))))

#?(:cljs
   (defn pure-ed25519-sign
     "Signs message bytes using pure ClojureScript Ed25519 (RFC 8032).
      Accepts either 32-byte raw seed or 48-byte PKCS#8 DER private key."
     [priv-bytes msg-bytes]
     (let [seed32 (if (= (fressian/count-bytes priv-bytes) 48)
                    (.subarray priv-bytes 16)
                    priv-bytes)]
       (.sign pure-ed25519-engine seed32 msg-bytes))))

#?(:cljs
   (defn pure-ed25519-verify
     "Verifies an Ed25519 signature using pure ClojureScript Ed25519 (RFC 8032).
      Accepts either 32-byte raw public key or 44-byte X.509 SPKI DER public key."
     [pub-bytes msg-bytes sig-bytes]
     (let [pub32 (if (= (fressian/count-bytes pub-bytes) 44)
                   (.subarray pub-bytes 12)
                   pub-bytes)]
       (boolean (.verify pure-ed25519-engine pub32 msg-bytes sig-bytes)))))

#?(:clj
   (do
     (declare generate-keypair sign verify)
     (let [p (.subtract (.shiftLeft BigInteger/ONE 255) (BigInteger/valueOf 19))
           d (.mod (.multiply (BigInteger/valueOf -121665)
                              (.modInverse (BigInteger/valueOf 121666) p)) p)
           by (.mod (.multiply (BigInteger/valueOf 4)
                               (.modInverse (BigInteger/valueOf 5) p)) p)
           bx (BigInteger. "15112221349535400772501151409588531511454012693041857206046113283949847762202")
           b-pt [bx by BigInteger/ONE (.mod (.multiply bx by) p)]
           pt-add (fn [[X1 Y1 Z1 T1] [X2 Y2 Z2 T2]]
                    (let [A (.mod (.multiply (.subtract Y1 X1) (.subtract Y2 X2)) p)
                          B (.mod (.multiply (.add Y1 X1) (.add Y2 X2)) p)
                          C (.mod (.multiply (.multiply (.shiftLeft d 1) T1) T2) p)
                          D2 (.mod (.multiply (.shiftLeft Z1 1) Z2) p)
                          E (.mod (.subtract B A) p)
                          F (.mod (.subtract D2 C) p)
                          G (.mod (.add D2 C) p)
                          H (.mod (.add B A) p)]
                      [(.mod (.multiply E F) p)
                       (.mod (.multiply G H) p)
                       (.mod (.multiply F G) p)
                       (.mod (.multiply E H) p)]))
           scalar-mult (fn [k pt]
                         (loop [R [BigInteger/ZERO BigInteger/ONE BigInteger/ONE BigInteger/ZERO]
                                Q pt
                                n k]
                           (if (pos? (.signum n))
                             (recur (if (.testBit n 0) (pt-add R Q) R)
                                    (pt-add Q Q)
                                    (.shiftRight n 1))
                             R)))
           encode-pt (fn [[X Y Z _]]
                       (let [zi (.modInverse Z p)
                             x (.mod (.multiply X zi) p)
                             y (.mod (.multiply Y zi) p)
                             out (byte-array 32)]
                         (dotimes [i 32]
                           (aset-byte out i (unchecked-byte (.intValue (.and (.shiftRight y (* i 8)) (BigInteger/valueOf 0xff))))))
                         (aset-byte out 31 (unchecked-byte (bit-or (bit-and (aget out 31) 0x7f)
                                                                   (if (.testBit x 0) 0x80 0x00))))
                         out))]
       (defn- jvm-ed25519-pub-from-seed ^bytes [^bytes seed32]
         (let [h (sha512 seed32)
               s-bytes (java.util.Arrays/copyOfRange h 0 32)
               _ (aset-byte s-bytes 0 (unchecked-byte (bit-and (aget s-bytes 0) 248)))
               _ (aset-byte s-bytes 31 (unchecked-byte (bit-or (bit-and (aget s-bytes 31) 127) 64)))
               s (reduce (fn [acc i]
                           (.or acc (.shiftLeft (BigInteger/valueOf (bit-and (aget s-bytes i) 0xff)) (* i 8))))
                         BigInteger/ZERO
                         (range 32))]
           (encode-pt (scalar-mult s b-pt)))))
     (defn pure-ed25519-keypair
       "JVM mirror for pure-ed25519-keypair."
       ([] (generate-keypair))
       ([seed32]
        (let [pub-raw (jvm-ed25519-pub-from-seed seed32)
              pub-der (fressian/concat-bytes (fressian/hex->bytes "302a300506032b6570032100") pub-raw)
              priv-der (fressian/concat-bytes (fressian/hex->bytes "302e020100300506032b657004220420") seed32)]
          {:public pub-der :private priv-der :public-key pub-der :private-key priv-der})))
     (defn pure-ed25519-sign
       "JVM mirror for pure-ed25519-sign."
       [priv-bytes msg-bytes]
       (let [p-der (if (= (alength ^bytes priv-bytes) 32)
                     (fressian/concat-bytes (fressian/hex->bytes "302e020100300506032b657004220420") priv-bytes)
                     priv-bytes)]
         (sign p-der msg-bytes)))
     (defn pure-ed25519-verify
       "JVM mirror for pure-ed25519-verify."
       [pub-bytes msg-bytes sig-bytes]
       (let [u-der (if (= (alength ^bytes pub-bytes) 32)
                     (fressian/concat-bytes (fressian/hex->bytes "302a300506032b6570032100") pub-bytes)
                     pub-bytes)]
         (verify u-der msg-bytes sig-bytes)))))

;; =============================================================================
;; Ed25519 Signing & Verification
;; =============================================================================

(defn generate-keypair
  "Generates an Ed25519 keypair.
   When seed-or-rng is provided, generates deterministically across JVM and CLJS.
   Returns a map with :public (X.509 SPKI DER) and :private (PKCS#8 DER) byte arrays."
  ([] (generate-keypair nil))
  ([seed-or-rng]
   (if seed-or-rng
     (let [seed32 (cond
                    (fressian/bytes? seed-or-rng) seed-or-rng
                    (satisfies? IRandom seed-or-rng)
                    (let [ba #?(:clj (byte-array 32) :cljs (js/Uint8Array. 32))]
                      (next-bytes seed-or-rng ba)
                      ba)
                    :else
                    (let [r (make-random seed-or-rng)
                          ba #?(:clj (byte-array 32) :cljs (js/Uint8Array. 32))]
                      (next-bytes r ba)
                      ba))]
       (pure-ed25519-keypair seed32))
     #?(:clj
        (let [kpg (KeyPairGenerator/getInstance "Ed25519")
              kp (.generateKeyPair kpg)
              pub (.getEncoded (.getPublic kp))
              priv (.getEncoded (.getPrivate kp))]
          {:public pub :private priv :public-key pub :private-key priv})
        :cljs
        (if node-crypto
          (let [gen-fn (or (aget node-crypto "generateKeyPairSync") (.-generateKeyPairSync node-crypto))
                kp (.call gen-fn node-crypto "ed25519")
                pub-obj (or (aget kp "publicKey") (.-publicKey kp))
                priv-obj (or (aget kp "privateKey") (.-privateKey kp))
                exp-pub (or (aget pub-obj "export") (.-export pub-obj))
                exp-priv (or (aget priv-obj "export") (.-export priv-obj))
                pub-der (.call exp-pub pub-obj #js {:type "spki" :format "der"})
                priv-der (.call exp-priv priv-obj #js {:type "pkcs8" :format "der"})
                pub (js/Uint8Array. pub-der)
                priv (js/Uint8Array. priv-der)]
            {:public pub :private priv :public-key pub :private-key priv})
          (pure-ed25519-keypair))))))

(defn- ensure-bytes [x]
  (cond
    (nil? x) nil
    (string? x) (fressian/hex->bytes x)
    (sequential? x) #?(:clj (byte-array (map byte x))
                       :cljs (js/Uint8Array. (clj->js x)))
    :else x))

(defn sign
  "Signs a message byte array using an Ed25519 private key byte array (PKCS#8).
   Returns signature bytes (byte[] on JVM, Uint8Array on CLJS)."
  ^bytes [private-key message]
  (let [msg-bytes (if (string? message) (fressian/utf8->bytes message) (ensure-bytes message))
        priv-bytes (ensure-bytes private-key)]
    #?(:clj
       (let [kf (KeyFactory/getInstance "Ed25519")
             ks (PKCS8EncodedKeySpec. ^bytes priv-bytes)
             priv (.generatePrivate kf ks)
             sig (Signature/getInstance "Ed25519")]
         (.initSign sig priv)
         (.update sig ^bytes msg-bytes)
         (.sign sig))
       :cljs
       (if node-crypto
         (let [create-key-fn (or (aget node-crypto "createPrivateKey") (.-createPrivateKey node-crypto))
               sign-fn (or (aget node-crypto "sign") (.-sign node-crypto))
               key-obj (.call create-key-fn node-crypto #js {:key (js/Buffer.from priv-bytes) :format "der" :type "pkcs8"})
               sig (.call sign-fn node-crypto nil (js/Buffer.from msg-bytes) key-obj)]
           (js/Uint8Array. sig))
         (pure-ed25519-sign priv-bytes msg-bytes)))))

(defn verify
  "Verifies an Ed25519 signature of a message using a public key byte array (X.509 SPKI).
   Returns true if valid, false otherwise."
  [public-key message signature]
  (try
    (let [msg-bytes (if (string? message) (fressian/utf8->bytes message) (ensure-bytes message))
          pub-bytes (ensure-bytes public-key)
          sig-bytes (ensure-bytes signature)]
      #?(:clj
         (let [kf (KeyFactory/getInstance "Ed25519")
               ks (X509EncodedKeySpec. ^bytes pub-bytes)
               pub (.generatePublic kf ks)
               sig (Signature/getInstance "Ed25519")]
           (.initVerify sig pub)
           (.update sig ^bytes msg-bytes)
           (.verify sig ^bytes sig-bytes))
         :cljs
         (if node-crypto
           (let [create-pub-fn (or (aget node-crypto "createPublicKey") (.-createPublicKey node-crypto))
                 verify-fn (or (aget node-crypto "verify") (.-verify node-crypto))
                 key-obj (.call create-pub-fn node-crypto #js {:key (js/Buffer.from pub-bytes) :format "der" :type "spki"})
                 ok (.call verify-fn node-crypto nil (js/Buffer.from msg-bytes) key-obj (js/Buffer.from sig-bytes))]
             (boolean ok))
           (pure-ed25519-verify pub-bytes msg-bytes sig-bytes))))
    (catch #?(:clj Exception :cljs :default) _
      false)))

;; =============================================================================
;; Canonical Signing Bytes & N/N-1 Verification Fallback (Standing Constraint 4)
;; =============================================================================

(defn canonical-signing-bytes
  "Encodes payload into deterministic canonical Fressian bytes (v2 canonical format)."
  [payload]
  (fressian/canonical-signing-bytes payload))

(defn legacy-pr-str-signing-bytes
  "Encodes payload using (pr-str payload) as UTF-8 bytes (v1 legacy format)."
  [payload]
  (fressian/legacy-pr-str-signing-bytes payload))

(defn sign-canonical
  "Signs canonical Fressian bytes (v2 format) using Ed25519 private key."
  [private-key payload]
  (let [b (canonical-signing-bytes payload)]
    (sign private-key b)))

(def ^:dynamic *allow-legacy-v1-signing-fallback*
  "Controls whether verify-with-fallback accepts v1 pr-str signatures during N/N-1 rolling upgrades.
   Sunset in Milestone 10; defaults to false. Set to true for explicit opt-in."
  false)

(defn verify-with-fallback
  "Verifies signature against v2 canonical Fressian signing bytes first.
   If false, falls back to v1 legacy (pr-str) signing bytes when allowed.
   Enforces Standing Constraint 4: N/N-1 rolling upgrade compatibility without breaking in-flight signatures."
  ([public-key payload signature]
   (verify-with-fallback public-key payload signature {:allow-v1-fallback? *allow-legacy-v1-signing-fallback*}))
  ([public-key payload signature opts]
   (let [v2-bytes (canonical-signing-bytes payload)]
     (if (verify public-key v2-bytes signature)
       true
       (if (get opts :allow-v1-fallback? *allow-legacy-v1-signing-fallback*)
         (let [v1-bytes (legacy-pr-str-signing-bytes payload)]
           (boolean (verify public-key v1-bytes signature)))
         false)))))

;; =============================================================================
;; Shell-Boundary Crypto Protocol (Decision A(i))
;; =============================================================================

(defprotocol ICryptoBoundary
  (pre-verify-envelope [this envelope]
    "Pre-verifies cryptographic signatures on inbound envelopes before passing to pure reducers.")
  (sign-and-emit [this effect]
    "Executes an egress signing effect at the shell boundary.")
  (seal-and-emit [this effect]
    "Executes an egress encryption/sealing effect at the shell boundary."))

;; =============================================================================
;; XSalsa20-Poly1305 Secretbox
;; =============================================================================

(defn- rotl-32 [^long x ^long n]
  #?(:clj (Integer/rotateLeft (unchecked-int x) (unchecked-int n))
     :cljs (bit-or (bit-shift-left (bit-and x 0xffffffff) n)
                   (unsigned-bit-shift-right (bit-and x 0xffffffff) (- 32 n)))))

(defn- bytes->u32-le [bs ^long offset]
  (unchecked-int
   (bit-or (bit-and (int #?(:clj (aget ^bytes bs offset) :cljs (aget bs offset))) 0xff)
           (bit-shift-left (bit-and (int #?(:clj (aget ^bytes bs (+ offset 1)) :cljs (aget bs (+ offset 1)))) 0xff) 8)
           (bit-shift-left (bit-and (int #?(:clj (aget ^bytes bs (+ offset 2)) :cljs (aget bs (+ offset 2)))) 0xff) 16)
           (bit-shift-left (bit-and (int #?(:clj (aget ^bytes bs (+ offset 3)) :cljs (aget bs (+ offset 3)))) 0xff) 24))))

(defn- u32->bytes-le! [^long val bs ^long offset]
  #?(:clj
     (do
       (aset ^bytes bs offset (unchecked-byte (bit-and val 0xff)))
       (aset ^bytes bs (+ offset 1) (unchecked-byte (bit-and (unsigned-bit-shift-right val 8) 0xff)))
       (aset ^bytes bs (+ offset 2) (unchecked-byte (bit-and (unsigned-bit-shift-right val 16) 0xff)))
       (aset ^bytes bs (+ offset 3) (unchecked-byte (bit-and (unsigned-bit-shift-right val 24) 0xff))))
     :cljs
     (do
       (aset bs offset (bit-and val 0xff))
       (aset bs (+ offset 1) (bit-and (unsigned-bit-shift-right val 8) 0xff))
       (aset bs (+ offset 2) (bit-and (unsigned-bit-shift-right val 16) 0xff))
       (aset bs (+ offset 3) (bit-and (unsigned-bit-shift-right val 24) 0xff)))))

(def ^:private c0 (unchecked-int 0x61707865))
(def ^:private c1 (unchecked-int 0x3320646e))
(def ^:private c2 (unchecked-int 0x79622d32))
(def ^:private c3 (unchecked-int 0x6b206574))

(defn- hsalsa20 [k in]
  (let [x #?(:clj (int-array 16) :cljs (js/Int32Array. 16))]
    (aset x 0 c0)
    (aset x 1 (bytes->u32-le k 0))
    (aset x 2 (bytes->u32-le k 4))
    (aset x 3 (bytes->u32-le k 8))
    (aset x 4 (bytes->u32-le k 12))
    (aset x 5 c1)
    (aset x 6 (bytes->u32-le in 0))
    (aset x 7 (bytes->u32-le in 4))
    (aset x 8 (bytes->u32-le in 8))
    (aset x 9 (bytes->u32-le in 12))
    (aset x 10 c2)
    (aset x 11 (bytes->u32-le k 16))
    (aset x 12 (bytes->u32-le k 20))
    (aset x 13 (bytes->u32-le k 24))
    (aset x 14 (bytes->u32-le k 28))
    (aset x 15 c3)
    (dotimes [_ 10]
      ;; column round
      (aset x 4 (unchecked-int (bit-xor (aget x 4) (rotl-32 (unchecked-add (aget x 0) (aget x 12)) 7))))
      (aset x 8 (unchecked-int (bit-xor (aget x 8) (rotl-32 (unchecked-add (aget x 4) (aget x 0)) 9))))
      (aset x 12 (unchecked-int (bit-xor (aget x 12) (rotl-32 (unchecked-add (aget x 8) (aget x 4)) 13))))
      (aset x 0 (unchecked-int (bit-xor (aget x 0) (rotl-32 (unchecked-add (aget x 12) (aget x 8)) 18))))

      (aset x 9 (unchecked-int (bit-xor (aget x 9) (rotl-32 (unchecked-add (aget x 5) (aget x 1)) 7))))
      (aset x 13 (unchecked-int (bit-xor (aget x 13) (rotl-32 (unchecked-add (aget x 9) (aget x 5)) 9))))
      (aset x 1 (unchecked-int (bit-xor (aget x 1) (rotl-32 (unchecked-add (aget x 13) (aget x 9)) 13))))
      (aset x 5 (unchecked-int (bit-xor (aget x 5) (rotl-32 (unchecked-add (aget x 1) (aget x 13)) 18))))

      (aset x 14 (unchecked-int (bit-xor (aget x 14) (rotl-32 (unchecked-add (aget x 10) (aget x 6)) 7))))
      (aset x 2 (unchecked-int (bit-xor (aget x 2) (rotl-32 (unchecked-add (aget x 14) (aget x 10)) 9))))
      (aset x 6 (unchecked-int (bit-xor (aget x 6) (rotl-32 (unchecked-add (aget x 2) (aget x 14)) 13))))
      (aset x 10 (unchecked-int (bit-xor (aget x 10) (rotl-32 (unchecked-add (aget x 6) (aget x 2)) 18))))

      (aset x 3 (unchecked-int (bit-xor (aget x 3) (rotl-32 (unchecked-add (aget x 15) (aget x 11)) 7))))
      (aset x 7 (unchecked-int (bit-xor (aget x 7) (rotl-32 (unchecked-add (aget x 3) (aget x 15)) 9))))
      (aset x 11 (unchecked-int (bit-xor (aget x 11) (rotl-32 (unchecked-add (aget x 7) (aget x 3)) 13))))
      (aset x 15 (unchecked-int (bit-xor (aget x 15) (rotl-32 (unchecked-add (aget x 11) (aget x 7)) 18))))

      ;; row round
      (aset x 1 (unchecked-int (bit-xor (aget x 1) (rotl-32 (unchecked-add (aget x 0) (aget x 3)) 7))))
      (aset x 2 (unchecked-int (bit-xor (aget x 2) (rotl-32 (unchecked-add (aget x 1) (aget x 0)) 9))))
      (aset x 3 (unchecked-int (bit-xor (aget x 3) (rotl-32 (unchecked-add (aget x 2) (aget x 1)) 13))))
      (aset x 0 (unchecked-int (bit-xor (aget x 0) (rotl-32 (unchecked-add (aget x 3) (aget x 2)) 18))))

      (aset x 6 (unchecked-int (bit-xor (aget x 6) (rotl-32 (unchecked-add (aget x 5) (aget x 4)) 7))))
      (aset x 7 (unchecked-int (bit-xor (aget x 7) (rotl-32 (unchecked-add (aget x 6) (aget x 5)) 9))))
      (aset x 4 (unchecked-int (bit-xor (aget x 4) (rotl-32 (unchecked-add (aget x 7) (aget x 6)) 13))))
      (aset x 5 (unchecked-int (bit-xor (aget x 5) (rotl-32 (unchecked-add (aget x 4) (aget x 7)) 18))))

      (aset x 11 (unchecked-int (bit-xor (aget x 11) (rotl-32 (unchecked-add (aget x 10) (aget x 9)) 7))))
      (aset x 8 (unchecked-int (bit-xor (aget x 8) (rotl-32 (unchecked-add (aget x 11) (aget x 10)) 9))))
      (aset x 9 (unchecked-int (bit-xor (aget x 9) (rotl-32 (unchecked-add (aget x 8) (aget x 11)) 13))))
      (aset x 10 (unchecked-int (bit-xor (aget x 10) (rotl-32 (unchecked-add (aget x 9) (aget x 8)) 18))))

      (aset x 12 (unchecked-int (bit-xor (aget x 12) (rotl-32 (unchecked-add (aget x 15) (aget x 14)) 7))))
      (aset x 13 (unchecked-int (bit-xor (aget x 13) (rotl-32 (unchecked-add (aget x 12) (aget x 15)) 9))))
      (aset x 14 (unchecked-int (bit-xor (aget x 14) (rotl-32 (unchecked-add (aget x 13) (aget x 12)) 13))))
      (aset x 15 (unchecked-int (bit-xor (aget x 15) (rotl-32 (unchecked-add (aget x 14) (aget x 13)) 18)))))
    (let [out #?(:clj (byte-array 32) :cljs (js/Uint8Array. 32))]
      (u32->bytes-le! (aget x 0) out 0)
      (u32->bytes-le! (aget x 5) out 4)
      (u32->bytes-le! (aget x 10) out 8)
      (u32->bytes-le! (aget x 15) out 12)
      (u32->bytes-le! (aget x 6) out 16)
      (u32->bytes-le! (aget x 7) out 20)
      (u32->bytes-le! (aget x 8) out 24)
      (u32->bytes-le! (aget x 9) out 28)
      out)))

(defn- salsa20-block [k n ^long counter]
  (let [x #?(:clj (int-array 16) :cljs (js/Int32Array. 16))
        orig #?(:clj (int-array 16) :cljs (js/Int32Array. 16))]
    (aset x 0 c0)
    (aset x 1 (bytes->u32-le k 0))
    (aset x 2 (bytes->u32-le k 4))
    (aset x 3 (bytes->u32-le k 8))
    (aset x 4 (bytes->u32-le k 12))
    (aset x 5 c1)
    (aset x 6 (bytes->u32-le n 0))
    (aset x 7 (bytes->u32-le n 4))
    (aset x 8 (unchecked-int (bit-and counter 0xffffffff)))
    (aset x 9 (unchecked-int (unsigned-bit-shift-right counter 32)))
    (aset x 10 c2)
    (aset x 11 (bytes->u32-le k 16))
    (aset x 12 (bytes->u32-le k 20))
    (aset x 13 (bytes->u32-le k 24))
    (aset x 14 (bytes->u32-le k 28))
    (aset x 15 c3)
    #?(:clj (System/arraycopy x 0 orig 0 16)
       :cljs (.set orig x 0))
    (dotimes [_ 10]
      (aset x 4 (unchecked-int (bit-xor (aget x 4) (rotl-32 (unchecked-add (aget x 0) (aget x 12)) 7))))
      (aset x 8 (unchecked-int (bit-xor (aget x 8) (rotl-32 (unchecked-add (aget x 4) (aget x 0)) 9))))
      (aset x 12 (unchecked-int (bit-xor (aget x 12) (rotl-32 (unchecked-add (aget x 8) (aget x 4)) 13))))
      (aset x 0 (unchecked-int (bit-xor (aget x 0) (rotl-32 (unchecked-add (aget x 12) (aget x 8)) 18))))

      (aset x 9 (unchecked-int (bit-xor (aget x 9) (rotl-32 (unchecked-add (aget x 5) (aget x 1)) 7))))
      (aset x 13 (unchecked-int (bit-xor (aget x 13) (rotl-32 (unchecked-add (aget x 9) (aget x 5)) 9))))
      (aset x 1 (unchecked-int (bit-xor (aget x 1) (rotl-32 (unchecked-add (aget x 13) (aget x 9)) 13))))
      (aset x 5 (unchecked-int (bit-xor (aget x 5) (rotl-32 (unchecked-add (aget x 1) (aget x 13)) 18))))

      (aset x 14 (unchecked-int (bit-xor (aget x 14) (rotl-32 (unchecked-add (aget x 10) (aget x 6)) 7))))
      (aset x 2 (unchecked-int (bit-xor (aget x 2) (rotl-32 (unchecked-add (aget x 14) (aget x 10)) 9))))
      (aset x 6 (unchecked-int (bit-xor (aget x 6) (rotl-32 (unchecked-add (aget x 2) (aget x 14)) 13))))
      (aset x 10 (unchecked-int (bit-xor (aget x 10) (rotl-32 (unchecked-add (aget x 6) (aget x 2)) 18))))

      (aset x 3 (unchecked-int (bit-xor (aget x 3) (rotl-32 (unchecked-add (aget x 15) (aget x 11)) 7))))
      (aset x 7 (unchecked-int (bit-xor (aget x 7) (rotl-32 (unchecked-add (aget x 3) (aget x 15)) 9))))
      (aset x 11 (unchecked-int (bit-xor (aget x 11) (rotl-32 (unchecked-add (aget x 7) (aget x 3)) 13))))
      (aset x 15 (unchecked-int (bit-xor (aget x 15) (rotl-32 (unchecked-add (aget x 11) (aget x 7)) 18))))

      (aset x 1 (unchecked-int (bit-xor (aget x 1) (rotl-32 (unchecked-add (aget x 0) (aget x 3)) 7))))
      (aset x 2 (unchecked-int (bit-xor (aget x 2) (rotl-32 (unchecked-add (aget x 1) (aget x 0)) 9))))
      (aset x 3 (unchecked-int (bit-xor (aget x 3) (rotl-32 (unchecked-add (aget x 2) (aget x 1)) 13))))
      (aset x 0 (unchecked-int (bit-xor (aget x 0) (rotl-32 (unchecked-add (aget x 3) (aget x 2)) 18))))

      (aset x 6 (unchecked-int (bit-xor (aget x 6) (rotl-32 (unchecked-add (aget x 5) (aget x 4)) 7))))
      (aset x 7 (unchecked-int (bit-xor (aget x 7) (rotl-32 (unchecked-add (aget x 6) (aget x 5)) 9))))
      (aset x 4 (unchecked-int (bit-xor (aget x 4) (rotl-32 (unchecked-add (aget x 7) (aget x 6)) 13))))
      (aset x 5 (unchecked-int (bit-xor (aget x 5) (rotl-32 (unchecked-add (aget x 4) (aget x 7)) 18))))

      (aset x 11 (unchecked-int (bit-xor (aget x 11) (rotl-32 (unchecked-add (aget x 10) (aget x 9)) 7))))
      (aset x 8 (unchecked-int (bit-xor (aget x 8) (rotl-32 (unchecked-add (aget x 11) (aget x 10)) 9))))
      (aset x 9 (unchecked-int (bit-xor (aget x 9) (rotl-32 (unchecked-add (aget x 8) (aget x 11)) 13))))
      (aset x 10 (unchecked-int (bit-xor (aget x 10) (rotl-32 (unchecked-add (aget x 9) (aget x 8)) 18))))

      (aset x 12 (unchecked-int (bit-xor (aget x 12) (rotl-32 (unchecked-add (aget x 15) (aget x 14)) 7))))
      (aset x 13 (unchecked-int (bit-xor (aget x 13) (rotl-32 (unchecked-add (aget x 12) (aget x 15)) 9))))
      (aset x 14 (unchecked-int (bit-xor (aget x 14) (rotl-32 (unchecked-add (aget x 13) (aget x 12)) 13))))
      (aset x 15 (unchecked-int (bit-xor (aget x 15) (rotl-32 (unchecked-add (aget x 14) (aget x 13)) 18)))))
    (let [out #?(:clj (byte-array 64) :cljs (js/Uint8Array. 64))]
      (dotimes [i 16]
        (u32->bytes-le! (unchecked-add (aget x i) (aget orig i)) out (* i 4)))
      out)))

#?(:clj
   (def ^:private ^BigInteger P-poly
     (-> BigInteger/ONE (.shiftLeft 130) (.subtract (BigInteger/valueOf 5)))))
#?(:clj
   (def ^:private ^BigInteger MOD-128
     (-> BigInteger/ONE (.shiftLeft 128))))

(defn- poly1305-mac [k msg]
  #?(:clj
     (let [r-bytes (byte-array 16)
           _ (System/arraycopy k 0 r-bytes 0 16)
           _ (aset r-bytes 3 (unchecked-byte (bit-and (int (aget r-bytes 3)) 15)))
           _ (aset r-bytes 7 (unchecked-byte (bit-and (int (aget r-bytes 7)) 15)))
           _ (aset r-bytes 11 (unchecked-byte (bit-and (int (aget r-bytes 11)) 15)))
           _ (aset r-bytes 15 (unchecked-byte (bit-and (int (aget r-bytes 15)) 15)))
           _ (aset r-bytes 4 (unchecked-byte (bit-and (int (aget r-bytes 4)) 252)))
           _ (aset r-bytes 8 (unchecked-byte (bit-and (int (aget r-bytes 8)) 252)))
           _ (aset r-bytes 12 (unchecked-byte (bit-and (int (aget r-bytes 12)) 252)))
           r (let [rev (byte-array 17)]
               (dotimes [i 16] (aset rev (- 16 i) (aget r-bytes i)))
               (BigInteger. 1 rev))
           s (let [rev (byte-array 17)]
               (dotimes [i 16] (aset rev (- 16 i) (aget ^bytes k (+ 16 i))))
               (BigInteger. 1 rev))
           msg-len (alength ^bytes msg)]
       (loop [offset 0
              acc BigInteger/ZERO]
         (if (< offset msg-len)
           (let [chunk-len (min 16 (- msg-len offset))
                 chunk-rev (byte-array (inc chunk-len))]
             (dotimes [i chunk-len]
               (aset chunk-rev (- chunk-len i) (aget ^bytes msg (+ offset i))))
             (aset chunk-rev 0 (unchecked-byte 1))
             (let [n (BigInteger. 1 chunk-rev)
                   next-acc (-> acc (.add n) (.multiply r) (.mod P-poly))]
               (recur (+ offset chunk-len) next-acc)))
           (let [final-val (-> acc (.add s) (.mod MOD-128))
                 raw-bytes (.toByteArray final-val)
                 out (byte-array 16)]
             (let [raw-len (alength raw-bytes)]
               (dotimes [i 16]
                 (let [rev-idx (dec (- raw-len i))]
                   (when (>= rev-idx 0)
                     (aset out i (aget raw-bytes rev-idx))))))
             out))))
     :cljs
     (let [r-val (atom (js/BigInt 0))]
       (dotimes [i 16]
         (let [bi (js/BigInt (* i 8))]
           (reset! r-val (js* "(~{} | (BigInt(~{}[~{}]) << ~{}))" @r-val k i bi))))
       (reset! r-val (js* "(~{} & 0x0ffffffc0ffffffc0ffffffc0fffffffn)" @r-val))
       (let [s-val (atom (js/BigInt 0))]
         (dotimes [i 16]
           (let [bi (js/BigInt (* i 8))]
             (reset! s-val (js* "(~{} | (BigInt(~{}[16 + ~{}]) << ~{}))" @s-val k i bi))))
         (let [p (js* "((1n << 130n) - 5n)")
               a (atom (js/BigInt 0))
               len (.-length msg)]
           (loop [i 0]
             (when (< i len)
               (let [chunk-len (js/Math.min 16 (- len i))
                     chunk (.subarray msg i (+ i chunk-len))
                     num (atom (js/BigInt 0))]
                 (dotimes [j chunk-len]
                   (let [bj (js/BigInt (* j 8))]
                     (reset! num (js* "(~{} | (BigInt(~{}[~{}]) << ~{}))" @num chunk j bj))))
                 (let [bcl (js/BigInt (* chunk-len 8))]
                   (reset! num (js* "(~{} | (1n << ~{}))" @num bcl)))
                 (reset! a (js* "(((~{} + ~{}) * ~{}) % ~{})" @a @num @r-val p))
                 (recur (+ i 16)))))
           (reset! a (js* "((~{} + ~{}) % (1n << 128n))" @a @s-val))
           (let [tag (js/Uint8Array. 16)
                 n (atom @a)]
             (dotimes [i 16]
               (aset tag i (js/Number (js* "(~{} & 0xffn)" @n)))
               (reset! n (js* "(~{} >> 8n)" @n)))
             tag))))))

(defn secretbox
  "Encrypts and authenticates plaintext using 32-byte key and 24-byte nonce (XSalsa20-Poly1305).
   Returns [16-byte Poly1305 tag || ciphertext] byte array."
  [key nonce plaintext]
  (let [k (ensure-bytes key)
        n (ensure-bytes nonce)
        pt (if (string? plaintext) (fressian/utf8->bytes plaintext) (ensure-bytes plaintext))
        pt-len (fressian/count-bytes pt)]
    #?(:clj
       (let [n-sub (byte-array 16)
             n-rem (byte-array 8)]
         (System/arraycopy n 0 n-sub 0 16)
         (System/arraycopy n 16 n-rem 0 8)
         (let [sub-k (hsalsa20 k n-sub)
               ct (byte-array pt-len)
               block0 (salsa20-block sub-k n-rem 0)
               poly-k (byte-array 32)]
           (System/arraycopy block0 0 poly-k 0 32)
           (let [first-chunk (min 32 pt-len)]
             (dotimes [i first-chunk]
               (aset ct i (unchecked-byte (bit-xor (int (aget ^bytes pt i)) (int (aget ^bytes block0 (+ 32 i))))))))
           (when (> pt-len 32)
             (let [rem (- pt-len 32)
                   num-blocks (long (Math/ceil (/ (double rem) 64.0)))]
               (dotimes [b-idx num-blocks]
                 (let [block (salsa20-block sub-k n-rem (inc b-idx))
                       b-offset (+ 32 (* b-idx 64))
                       cur-chunk (min 64 (- pt-len b-offset))]
                   (dotimes [j cur-chunk]
                     (aset ct (+ b-offset j) (unchecked-byte (bit-xor (int (aget ^bytes pt (+ b-offset j))) (int (aget ^bytes block j))))))))))
           (let [tag (poly1305-mac poly-k ct)
                 res (byte-array (+ 16 pt-len))]
             (System/arraycopy tag 0 res 0 16)
             (System/arraycopy ct 0 res 16 pt-len)
             res)))
       :cljs
       (let [n-sub (.subarray n 0 16)
             n-rem (.subarray n 16 24)
             sub-k (hsalsa20 k n-sub)
             ct (js/Uint8Array. pt-len)
             block0 (salsa20-block sub-k n-rem 0)
             poly-k (.subarray block0 0 32)
             first-chunk (js/Math.min 32 pt-len)]
         (dotimes [i first-chunk]
           (aset ct i (bit-xor (aget pt i) (aget block0 (+ 32 i)))))
         (when (> pt-len 32)
           (let [rem (- pt-len 32)
                 num-blocks (js/Math.ceil (/ rem 64))]
             (dotimes [b-idx num-blocks]
               (let [block (salsa20-block sub-k n-rem (inc b-idx))
                     b-offset (+ 32 (* b-idx 64))
                     cur-chunk (js/Math.min 64 (- pt-len b-offset))]
                 (dotimes [j cur-chunk]
                   (aset ct (+ b-offset j) (bit-xor (aget pt (+ b-offset j)) (aget block j))))))))
         (let [tag (poly1305-mac poly-k ct)
               res (js/Uint8Array. (+ 16 pt-len))]
           (.set res tag 0)
           (.set res ct 16)
           res)))))

(defn secretbox-open
  "Decrypts and authenticates ciphertext using 32-byte key and 24-byte nonce (XSalsa20-Poly1305).
   ciphertext: [16-byte Poly1305 tag || ciphertext] byte array.
   Returns decrypted plaintext bytes on success, or nil on authentication failure."
  [key nonce boxed]
  (let [k (ensure-bytes key)
        n (ensure-bytes nonce)
        b (ensure-bytes boxed)
        b-len (if b (fressian/count-bytes b) 0)]
    (when (>= b-len 16)
      (let [ct-len (- b-len 16)]
        #?(:clj
           (let [n-sub (byte-array 16)
                 n-rem (byte-array 8)]
             (System/arraycopy n 0 n-sub 0 16)
             (System/arraycopy n 16 n-rem 0 8)
             (let [sub-k (hsalsa20 k n-sub)
                   ct (byte-array ct-len)
                   recv-tag (byte-array 16)]
               (System/arraycopy b 0 recv-tag 0 16)
               (System/arraycopy b 16 ct 0 ct-len)
               (let [block0 (salsa20-block sub-k n-rem 0)
                     poly-k (byte-array 32)]
                 (System/arraycopy block0 0 poly-k 0 32)
                 (let [expected-tag (poly1305-mac poly-k ct)]
                   (if (Arrays/equals ^bytes recv-tag ^bytes expected-tag)
                     (let [pt (byte-array ct-len)
                           first-chunk (min 32 ct-len)]
                       (dotimes [i first-chunk]
                         (aset pt i (unchecked-byte (bit-xor (int (aget ct i)) (int (aget ^bytes block0 (+ 32 i)))))))
                       (when (> ct-len 32)
                         (let [rem (- ct-len 32)
                               num-blocks (long (Math/ceil (/ (double rem) 64.0)))]
                           (dotimes [b-idx num-blocks]
                             (let [block (salsa20-block sub-k n-rem (inc b-idx))
                                   b-offset (+ 32 (* b-idx 64))
                                   cur-chunk (min 64 (- ct-len b-offset))]
                               (dotimes [j cur-chunk]
                                 (aset pt (+ b-offset j) (unchecked-byte (bit-xor (int (aget ^bytes ct (+ b-offset j))) (int (aget ^bytes block j))))))))))
                       pt)
                     nil)))))
           :cljs
           (let [n-sub (.subarray n 0 16)
                 n-rem (.subarray n 16 24)
                 sub-k (hsalsa20 k n-sub)
                 recv-tag (.subarray b 0 16)
                 ct (.subarray b 16 b-len)
                 block0 (salsa20-block sub-k n-rem 0)
                 poly-k (.subarray block0 0 32)
                 expected-tag (poly1305-mac poly-k ct)
                 tag-diff (atom 0)]
             (dotimes [i 16]
               (reset! tag-diff (bit-or @tag-diff (bit-xor (aget recv-tag i) (aget expected-tag i)))))
             (if (zero? @tag-diff)
               (let [pt (js/Uint8Array. ct-len)
                     first-chunk (js/Math.min 32 ct-len)]
                 (dotimes [i first-chunk]
                   (aset pt i (bit-xor (aget ct i) (aget block0 (+ 32 i)))))
                 (when (> ct-len 32)
                   (let [rem (- ct-len 32)
                         num-blocks (js/Math.ceil (/ rem 64))]
                     (dotimes [b-idx num-blocks]
                       (let [block (salsa20-block sub-k n-rem (inc b-idx))
                             b-offset (+ 32 (* b-idx 64))
                             cur-chunk (js/Math.min 64 (- ct-len b-offset))]
                         (dotimes [j cur-chunk]
                           (aset pt (+ b-offset j) (bit-xor (aget ct (+ b-offset j)) (aget block j))))))))
                 pt)
               nil)))))))

(defn canonicalize-agent-event
  "Recursively converts an agent event data structure into a content-deterministic
   canonical form for Fressian/pr-str signing (converting byte arrays to [:bytes hex]
   and sorting maps and sets deterministically)."
  [x]
  (cond
    (fressian/bytes? x)
    [:bytes (fressian/bytes->hex x)]

    (map? x)
    (into (sorted-map-by (fn [a b] (compare (pr-str a) (pr-str b))))
          (map (fn [[k v]] [(canonicalize-agent-event k) (canonicalize-agent-event v)]) x))

    (set? x)
    (vec (sort-by pr-str (map canonicalize-agent-event x)))

    (sequential? x)
    (mapv canonicalize-agent-event x)

    :else x))

(defn- execute-pre-verify
  [envelope]
  (let [clean-env (fressian/strip-untrusted-crypto-tags envelope)
        sender (or (:sender clean-env) (:from clean-env) (:agent-pubkey clean-env))
        sig (or (:signature clean-env) (:sig clean-env))
        payload (cond
                  (and (:agent-pubkey clean-env) (:event clean-env))
                  [(:agent-pubkey clean-env)
                   (canonicalize-agent-event (dissoc (:event clean-env) :sender :sender-pubkey-bytes :rng))]

                  (contains? clean-env :payload)
                  (if-let [burn (:burn-amount clean-env)]
                    (let [p-bytes (if (fressian/bytes? (:payload clean-env))
                                    (:payload clean-env)
                                    (fressian/utf8->bytes (str (:payload clean-env))))]
                      (fressian/concat-bytes p-bytes (fressian/utf8->bytes (str ":burn:" burn))))
                    (:payload clean-env))

                  (and (:frame-type clean-env) (:message-id clean-env))
                  {:type (:frame-type clean-env) :message-id (:message-id clean-env)}

                  (and (:sender clean-env) (:receiver clean-env) (:amount clean-env))
                  (into (sorted-map) (dissoc clean-env :signature :crypto/verified? :crypto/verified-a? :crypto/verified-b?))

                  :else nil)
        verified? (boolean
                   (and sender sig (some? payload)
                        (try
                          (if (fressian/bytes? payload)
                            (verify sender payload sig)
                            (verify-with-fallback sender payload sig))
                          (catch #?(:clj Exception :cljs :default) _ false))))]
    (if verified?
      (assoc clean-env :crypto/verified? true :crypto/verification-status :ok)
      (assoc clean-env :crypto/verified? false
             :crypto/verification-status :failed
             :diagnose {:effect :diagnose :reason :pre-verify-failed :sender sender}))))

(defn- execute-sign-and-emit
  [effect]
  (let [sub-eff (or (:crypto-effect effect) effect)
        payload (if (contains? sub-eff :signing-payload)
                  (:signing-payload sub-eff)
                  (:payload sub-eff))
        priv (:private-key effect)]
    (if (or (nil? priv) (nil? payload))
      (let [fail-res {:ok? false
                      :error :missing-private-key-or-payload
                      :diagnose {:effect :diagnose :reason :sign-and-emit-invalid-input}}
            on-signed (:on-signed effect)]
        (when (fn? on-signed) (on-signed fail-res))
        fail-res)
      (let [sig-field (or (:signature-field sub-eff) :signature)
            env (or (:envelope sub-eff) (when (:crypto-effect effect) (dissoc effect :crypto-effect)))
            on-signed (:on-signed effect)
            sig-bytes (if (fressian/bytes? payload)
                        (sign priv payload)
                        (sign-canonical priv payload))
            sig-hex (when sig-bytes (fressian/bytes->hex sig-bytes))
            signed-env (if (and env sig-hex)
                         (assoc (dissoc env :crypto-effect) sig-field sig-hex)
                         sig-bytes)]
        (when (fn? on-signed)
          (on-signed signed-env))
        signed-env))))

(defn- execute-seal-and-emit
  [effect]
  (let [{:keys [payload plaintext seal-fn on-sealed]} effect
        data (or plaintext payload)]
    (if (or (not (fn? seal-fn)) (nil? data))
      (let [fail-res {:ok? false
                      :error :missing-seal-fn
                      :diagnose {:effect :diagnose :reason :seal-and-emit-missing-seal-fn}}]
        (when (fn? on-sealed) (on-sealed fail-res))
        fail-res)
      (let [sealed-out (seal-fn data)]
        (when (fn? on-sealed)
          (on-sealed sealed-out))
        sealed-out))))

#?(:clj
   (deftype JVMCryptoBoundary []
     ICryptoBoundary
     (pre-verify-envelope [_ envelope]
       (execute-pre-verify envelope))
     (sign-and-emit [_ effect]
       (execute-sign-and-emit effect))
     (seal-and-emit [_ effect]
       (execute-seal-and-emit effect))))

#?(:cljs
   (deftype WebCryptoBoundary [subtle]
     ICryptoBoundary
     (pre-verify-envelope [_ envelope]
       (execute-pre-verify envelope))
     (sign-and-emit [_ effect]
       (execute-sign-and-emit effect))
     (seal-and-emit [_ effect]
       (execute-seal-and-emit effect))

     Object
     (subtle-digest-sha256 [_ data-bytes]
       (when subtle
         (.digest subtle "SHA-256" data-bytes)))
     (subtle-verify-ed25519 [_ pub-crypto-key sig-bytes data-bytes]
       (when subtle
         (.verify subtle (clj->js {:name "Ed25519"}) pub-crypto-key sig-bytes data-bytes)))))

(defn make-crypto-boundary
  "Creates an ICryptoBoundary instance for the active runtime (JVM or Node/Browser)."
  []
  #?(:clj  (JVMCryptoBoundary.)
     :cljs (let [subtle (or (when (exists? js/crypto) (.-subtle js/crypto))
                            (when (exists? js/globalThis) (.. js/globalThis -crypto -subtle)))]
             (WebCryptoBoundary. subtle))))

#?(:cljs
   (defn make-web-crypto-boundary
     "Creates a WebCryptoBoundary instance for Node/browser environments."
     []
     (make-crypto-boundary)))
