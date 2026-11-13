(ns bitecho.crypto.sealed
  "Pure sealed-channel cryptographic primitives using JDK standard library on JVM and node:crypto on Node.
   Provides X25519 key agreement, HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 AEAD,
   deterministic nonce derivation, and gap-tolerant replay window.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str])
  #?(:clj (:import [java.nio ByteBuffer]
                   [java.security KeyFactory KeyPairGenerator]
                   [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
                   [javax.crypto Cipher KeyAgreement Mac]
                   [javax.crypto.spec GCMParameterSpec IvParameterSpec SecretKeySpec])))

;; -----------------------------------------------------------------------------
;; Crypto-Suite Negotiation & Constants (Step 9C)
;; -----------------------------------------------------------------------------

(def ^{:doc "Mandatory-to-implement AES-256-GCM AEAD crypto suite identifier."}
  suite-v1-aes256gcm "suite-v1-aes256gcm")

(def ^{:doc "ChaCha20-Poly1305 AEAD crypto suite identifier."}
  suite-v1-chacha20poly1305 "suite-v1-chacha20poly1305")

(def ^{:doc "Default list of advertised crypto-suites in priority order."}
  default-crypto-suites [suite-v1-aes256gcm suite-v1-chacha20poly1305])

(def ^{:doc "Set of supported crypto-suite identifiers."}
  supported-crypto-suites #{suite-v1-aes256gcm suite-v1-chacha20poly1305})

(defn negotiate-crypto-suite
  "Negotiates a mutual crypto-suite between caller and callee.
   Caller suites are ordered by preference (highest to lowest).
   Selects caller's highest-priority mutually supported suite.
   Returns {:ok? true :selected-suite suite-str} on success,
   or {:ok? false :error \"no-mutually-supported-crypto-suite\" ...} on failure."
  [caller-suites callee-suites]
  (let [callee-set (set (map #(if (keyword? %) (name %) (str %)) (or callee-suites [])))
        caller-list (map #(if (keyword? %) (name %) (str %)) (or caller-suites []))
        mutually-supported (filterv (fn [s]
                                      (and (contains? supported-crypto-suites s)
                                           (contains? callee-set s)))
                                    caller-list)]
    (if-let [selected (first mutually-supported)]
      {:ok? true
       :selected-suite selected
       :mutual-suites mutually-supported}
      {:ok? false
       :error "no-mutually-supported-crypto-suite"
       :caller-suites (vec caller-list)
       :callee-suites (vec callee-set)
       :supported-suites (vec supported-crypto-suites)})))

;; -----------------------------------------------------------------------------
;; Browser Pure-CLJS Fallback Primitives & Helpers (Step 10A)
;; -----------------------------------------------------------------------------

#?(:cljs
   (def ^:private node-crypto
     (when (exists? js/require)
       (try (js/require "node:crypto") (catch :default _ nil)))))

#?(:cljs
   (do
     (def ^:private c25519-p (js/BigInt "57896044618658097711785492504343953926634992332820282019728792003956564819949"))
     (def ^:private c25519-a24 (js/BigInt 121665))
     (defn- c25519-modP [x] (js* "((((~{} % ~{}) + ~{}) % ~{}))" x c25519-p c25519-p c25519-p))
     (defn- c25519-modPow [b exp]
       (let [res (atom (js/BigInt 1))
             base (atom (c25519-modP b))
             e (atom exp)]
         (while (js* "(~{} > 0n)" @e)
           (when (js* "((~{} & 1n) !== 0n)" @e)
             (reset! res (c25519-modP (js* "(~{} * ~{})" @res @base))))
           (reset! base (c25519-modP (js* "(~{} * ~{})" @base @base)))
           (reset! e (js* "(~{} >> 1n)" @e)))
         @res))
     (defn- c25519-decodeLE [buf]
       (let [res (atom (js/BigInt 0))]
         (dotimes [i (.-length buf)]
           (let [bi (js/BigInt (* i 8))]
             (reset! res (js* "(~{} | (BigInt(~{}) << ~{}))" @res (aget buf i) bi))))
         @res))
     (defn- c25519-encodeLE [num]
       (let [buf (js/Uint8Array. 32)
             n (atom num)]
         (dotimes [i 32]
           (aset buf i (js/Number (js* "(~{} & 0xffn)" @n)))
           (reset! n (js* "(~{} >> 8n)" @n)))
         buf))

     (defn pure-curve25519
       "Pure ClojureScript Montgomery ladder scalar multiplication over Curve25519 (RFC 7748 §5)."
       [scalar-bytes u-bytes]
       (let [k-clamped (js/Uint8Array. scalar-bytes)]
         (aset k-clamped 0 (bit-and (aget k-clamped 0) 248))
         (aset k-clamped 31 (bit-and (aget k-clamped 31) 127))
         (aset k-clamped 31 (bit-or (aget k-clamped 31) 64))
         (let [k (c25519-decodeLE k-clamped)
               u (c25519-modP (c25519-decodeLE u-bytes))
               x1 u
               x2 (atom (js/BigInt 1))
               z2 (atom (js/BigInt 0))
               x3 (atom u)
               z3 (atom (js/BigInt 1))
               swap (atom (js/BigInt 0))]
           (loop [t 254]
             (when (>= t 0)
               (let [bt (js/BigInt t)
                     kt (js* "((~{} >> ~{}) & 1n)" k bt)]
                 (reset! swap (js* "(~{} ^ ~{})" @swap kt))
                 (when (js* "(~{} === 1n)" @swap)
                   (let [tmp-x @x2] (reset! x2 @x3) (reset! x3 tmp-x))
                   (let [tmp-z @z2] (reset! z2 @z3) (reset! z3 tmp-z)))
                 (reset! swap kt)
                 (let [A (c25519-modP (js* "(~{} + ~{})" @x2 @z2))
                       AA (c25519-modP (js* "(~{} * ~{})" A A))
                       B (c25519-modP (js* "(~{} - ~{})" @x2 @z2))
                       BB (c25519-modP (js* "(~{} * ~{})" B B))
                       E (c25519-modP (js* "(~{} - ~{})" AA BB))
                       C (c25519-modP (js* "(~{} + ~{})" @x3 @z3))
                       D (c25519-modP (js* "(~{} - ~{})" @x3 @z3))
                       DA (c25519-modP (js* "(~{} * ~{})" D A))
                       CB (c25519-modP (js* "(~{} * ~{})" C B))]
                   (reset! x3 (c25519-modP (js* "((~{} + ~{}) * (~{} + ~{}))" DA CB DA CB)))
                   (reset! z3 (c25519-modP (js* "(~{} * (~{} - ~{}) * (~{} - ~{}))" x1 DA CB DA CB)))
                   (reset! x2 (c25519-modP (js* "(~{} * ~{})" AA BB)))
                   (reset! z2 (c25519-modP (js* "(~{} * (~{} + (~{} * ~{})))" E AA c25519-a24 E))))
                 (recur (dec t)))))
           (when (js* "(~{} === 1n)" @swap)
             (let [tmp-x @x2] (reset! x2 @x3) (reset! x3 tmp-x))
             (let [tmp-z @z2] (reset! z2 @z3) (reset! z3 tmp-z)))
           (let [result (c25519-modP (js* "(~{} * ~{})" @x2 (c25519-modPow @z2 (js* "(~{} - 2n)" c25519-p))))]
             (c25519-encodeLE result)))))

     (set! (.-scalarMult pure-curve25519) (fn [s u] (pure-curve25519 s u)))
     (set! (.-scalarMultBase pure-curve25519)
           (fn [s]
             (let [u9 (js/Uint8Array. 32)]
               (aset u9 0 9)
               (pure-curve25519 s u9))))))

#?(:cljs
   (def ^:private spki-header (fressian/hex->bytes "302a300506032b656e032100")))
#?(:cljs
   (def ^:private pkcs8-header (fressian/hex->bytes "302e020100300506032b656e04220420")))

#?(:cljs
   (defn pure-x25519-keypair
     "Generates an X25519 keypair in pure ClojureScript.
      Returns {:public spki-der-bytes (44 bytes), :private pkcs8-der-bytes (48 bytes)}."
     []
     (let [priv-raw (crypto/random-bytes 32)
           u9 (let [b (js/Uint8Array. 32)] (aset b 0 9) b)
           pub-raw (pure-curve25519 priv-raw u9)
           pub (fressian/concat-bytes spki-header pub-raw)
           priv (fressian/concat-bytes pkcs8-header priv-raw)]
       {:public pub :private priv :public-key pub :private-key priv})))

#?(:cljs
   (defn pure-x25519-shared-secret
     "Derives 32-byte shared secret from private and public key bytes (raw or DER-encoded)."
     [priv-bytes pub-bytes]
     (let [priv-raw (if (= (fressian/count-bytes priv-bytes) 48)
                      (.subarray priv-bytes 16)
                      priv-bytes)
           pub-raw (if (= (fressian/count-bytes pub-bytes) 44)
                     (.subarray pub-bytes 12)
                     pub-bytes)]
       (pure-curve25519 priv-raw pub-raw))))

#?(:cljs
   (defn pure-hmac-sha256
     "Pure ClojureScript HMAC-SHA256 using crypto/sha256."
     [key data]
     (let [k-bytes (if (string? key) (fressian/utf8->bytes key) key)
           d-bytes (if (string? data) (fressian/utf8->bytes data) data)
           k-len (fressian/count-bytes k-bytes)
           k-norm (if (> k-len 64)
                    (crypto/sha256 k-bytes)
                    k-bytes)
           k0 (js/Uint8Array. 64)]
       (.set k0 k-norm 0)
       (let [ipad (js/Uint8Array. 64)
             opad (js/Uint8Array. 64)]
         (dotimes [i 64]
           (let [b (aget k0 i)]
             (aset ipad i (bit-xor b 0x36))
             (aset opad i (bit-xor b 0x5c))))
         (let [inner-input (fressian/concat-bytes ipad d-bytes)
               inner-hash (crypto/sha256 inner-input)
               outer-input (fressian/concat-bytes opad inner-hash)]
           (crypto/sha256 outer-input))))))

#?(:cljs
   (defn pure-hkdf-extract
     "Extracts a pseudorandom key (PRK) from salt and input keying material using pure HMAC-SHA256."
     [salt ikm]
     (let [eff-salt (if (or (nil? salt) (zero? (fressian/count-bytes salt)))
                      (js/Uint8Array. 32)
                      salt)]
       (pure-hmac-sha256 eff-salt ikm))))

#?(:cljs
   (defn pure-hkdf-expand
     "Expands a pseudorandom key (PRK) and info into output keying material (OKM) of desired length."
     [prk info length]
     (let [hash-len 32
           n (long (js/Math.ceil (/ length hash-len)))
           _ (when (> n 255)
               (throw (ex-info "Requested length exceeds HKDF-SHA256 maximum" {:length length})))
           safe-info (or info (js/Uint8Array. 0))
           out (js/Uint8Array. length)]
       (loop [i 1
              t (js/Uint8Array. 0)
              offset 0]
         (if (<= i n)
           (let [step-byte (js/Uint8Array. #js [i])
                 input (fressian/concat-bytes t safe-info step-byte)
                 t-next (pure-hmac-sha256 prk input)
                 to-copy (min hash-len (- length offset))]
             (.set out (.subarray t-next 0 to-copy) offset)
             (recur (inc i) t-next (+ offset to-copy)))
           out)))))

#?(:cljs
   (defn pure-hkdf-sha256
     "Pure ClojureScript HKDF-SHA256."
     [ikm salt info length]
     (let [prk (pure-hkdf-extract salt ikm)]
       (pure-hkdf-expand prk info length))))

#?(:cljs
   (do
     (defn- chacha20-block [k counter n]
       (let [state (js/Uint32Array. 16)]
         (aset state 0 0x61707865)
         (aset state 1 0x3320646e)
         (aset state 2 0x79622d32)
         (aset state 3 0x6b206574)
         (dotimes [i 8]
           (let [i4 (* 4 i)]
             (aset state (+ 4 i)
                   (js* "((~{}[~{}] | (~{}[~{} + 1] << 8) | (~{}[~{} + 2] << 16) | (~{}[~{} + 3] << 24)) >>> 0)"
                        k i4 k i4 k i4 k i4))))
         (aset state 12 (unsigned-bit-shift-right counter 0))
         (dotimes [i 3]
           (let [i4 (* 4 i)]
             (aset state (+ 13 i)
                   (js* "((~{}[~{}] | (~{}[~{} + 1] << 8) | (~{}[~{} + 2] << 16) | (~{}[~{} + 3] << 24)) >>> 0)"
                        n i4 n i4 n i4 n i4))))
         (let [working (js/Uint32Array. state)
               qround (fn [a b c d]
                        (let [rotl (fn [v shift] (js* "(((~{} << ~{}) | (~{} >>> (32 - ~{}))) >>> 0)" v shift v shift))]
                          (aset working a (js* "((~{}[~{}] + ~{}[~{}]) >>> 0)" working a working b))
                          (aset working d (rotl (bit-xor (aget working d) (aget working a)) 16))
                          (aset working c (js* "((~{}[~{}] + ~{}[~{}]) >>> 0)" working c working d))
                          (aset working b (rotl (bit-xor (aget working b) (aget working c)) 12))
                          (aset working a (js* "((~{}[~{}] + ~{}[~{}]) >>> 0)" working a working b))
                          (aset working d (rotl (bit-xor (aget working d) (aget working a)) 8))
                          (aset working c (js* "((~{}[~{}] + ~{}[~{}]) >>> 0)" working c working d))
                          (aset working b (rotl (bit-xor (aget working b) (aget working c)) 7))))]
           (dotimes [_ 10]
             (qround 0 4 8 12)
             (qround 1 5 9 13)
             (qround 2 6 10 14)
             (qround 3 7 11 15)
             (qround 0 5 10 15)
             (qround 1 6 11 12)
             (qround 2 7 8 13)
             (qround 3 4 9 14))
           (let [out (js/Uint8Array. 64)]
             (dotimes [i 16]
               (let [val (js* "((~{}[~{}] + ~{}[~{}]) >>> 0)" working i state i)
                     i4 (* 4 i)]
                 (aset out i4 (bit-and val 0xff))
                 (aset out (+ i4 1) (bit-and (unsigned-bit-shift-right val 8) 0xff))
                 (aset out (+ i4 2) (bit-and (unsigned-bit-shift-right val 16) 0xff))
                 (aset out (+ i4 3) (bit-and (unsigned-bit-shift-right val 24) 0xff))))
             out))))

     (defn- poly1305-mac [k msg]
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
               tag)))))

     (defn pure-chacha20-poly1305
       "Pure ClojureScript ChaCha20-Poly1305 AEAD (RFC 8439)."
       [key nonce input aad is-encrypt?]
       (let [block0 (chacha20-block key 0 nonce)
             poly-key (.subarray block0 0 32)
             in-len (if input (.-length input) 0)
             pt-len (if is-encrypt? in-len (- in-len 16))]
         (if (< pt-len 0)
           nil
           (let [out (js/Uint8Array. pt-len)
                 counter (atom 1)]
             (loop [i 0]
               (when (< i pt-len)
                 (let [ks (chacha20-block key @counter nonce)
                       chunk-len (js/Math.min 64 (- pt-len i))]
                   (swap! counter inc)
                   (dotimes [j chunk-len]
                     (aset out (+ i j) (bit-xor (aget input (+ i j)) (aget ks j))))
                   (recur (+ i 64)))))
             (let [ct (if is-encrypt? out (.subarray input 0 pt-len))
                   aad-buf (or aad (js/Uint8Array. 0))
                   aad-len (.-length aad-buf)
                   ct-len (.-length ct)
                   aad-pad-len (mod (- 16 (mod aad-len 16)) 16)
                   ct-pad-len (mod (- 16 (mod ct-len 16)) 16)
                   poly-input (js/Uint8Array. (+ aad-len aad-pad-len ct-len ct-pad-len 16))]
               (.set poly-input aad-buf 0)
               (let [off1 (+ aad-len aad-pad-len)]
                 (.set poly-input ct off1)
                 (let [off2 (+ off1 ct-len ct-pad-len)
                       aad-len-big (atom (js/BigInt aad-len))]
                   (dotimes [i 8]
                     (aset poly-input (+ off2 i) (js/Number (js* "(~{} & 0xffn)" @aad-len-big)))
                     (reset! aad-len-big (js* "(~{} >> 8n)" @aad-len-big)))
                   (let [ct-len-big (atom (js/BigInt ct-len))]
                     (dotimes [i 8]
                       (aset poly-input (+ off2 8 i) (js/Number (js* "(~{} & 0xffn)" @ct-len-big)))
                       (reset! ct-len-big (js* "(~{} >> 8n)" @ct-len-big)))
                     (let [tag (poly1305-mac poly-key poly-input)]
                       (if is-encrypt?
                         (let [res (js/Uint8Array. (+ pt-len 16))]
                           (.set res out 0)
                           (.set res tag pt-len)
                           res)
                         (let [expected-tag (.subarray input pt-len)
                               diff (atom 0)]
                           (dotimes [i 16]
                             (reset! diff (bit-or @diff (bit-xor (aget tag i) (aget expected-tag i)))))
                           (if (zero? @diff)
                             out
                             nil))))))))))))

     (set! (.-encrypt pure-chacha20-poly1305) (fn [k n in aad] (pure-chacha20-poly1305 k n in aad true)))
     (set! (.-decrypt pure-chacha20-poly1305) (fn [k n in aad] (pure-chacha20-poly1305 k n in aad false)))))

#?(:cljs
   (defn pure-chacha-poly-seal
     "Encrypts and authenticates plaintext using pure ClojureScript ChaCha20-Poly1305."
     [key nonce plaintext aad]
     (pure-chacha20-poly1305 key nonce (or plaintext (js/Uint8Array. 0)) (or aad (js/Uint8Array. 0)) true)))

#?(:cljs
   (defn pure-chacha-poly-open
     "Decrypts and authenticates ciphertext using pure ClojureScript ChaCha20-Poly1305."
     [key nonce ciphertext aad]
     (pure-chacha20-poly1305 key nonce ciphertext (or aad (js/Uint8Array. 0)) false)))

#?(:cljs
   (do
     (def ^:private aes-sbox
       (js/Uint8Array.
        #js [0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5 0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76
             0xca 0x82 0xc9 0x7d 0xfa 0x59 0x47 0xf0 0xad 0xd4 0xa2 0xaf 0x9c 0xa4 0x72 0xc0
             0xb7 0xfd 0x93 0x26 0x36 0x3f 0xf7 0xcc 0x34 0xa5 0xe5 0xf1 0x71 0xd8 0x31 0x15
             0x04 0xc7 0x23 0xc3 0x18 0x96 0x05 0x9a 0x07 0x12 0x80 0xe2 0xeb 0x27 0xb2 0x75
             0x09 0x83 0x2c 0x1a 0x1b 0x6e 0x5a 0xa0 0x52 0x3b 0xd6 0xb3 0x29 0xe3 0x2f 0x84
             0x53 0xd1 0x00 0xed 0x20 0xfc 0xb1 0x5b 0x6a 0xcb 0xbe 0x39 0x4a 0x4c 0x58 0xcf
             0xd0 0xef 0xaa 0xfb 0x43 0x4d 0x33 0x85 0x45 0xf9 0x02 0x7f 0x50 0x3c 0x9f 0xa8
             0x51 0xa3 0x40 0x8f 0x92 0x9d 0x38 0xf5 0xbc 0xb6 0xda 0x21 0x10 0xff 0xf3 0xd2
             0xcd 0x0c 0x13 0xec 0x5f 0x97 0x44 0x17 0xc4 0xa7 0x7e 0x3d 0x64 0x5d 0x19 0x73
             0x60 0x81 0x4f 0xdc 0x22 0x2a 0x90 0x88 0x46 0xee 0xb8 0x14 0xde 0x5e 0x0b 0xdb
             0xe0 0x32 0x3a 0x0a 0x49 0x06 0x24 0x5c 0xc2 0xd3 0xac 0x62 0x91 0x95 0xe4 0x79
             0xe7 0xc8 0x37 0x6d 0x8d 0xd5 0x4e 0xa9 0x6c 0x56 0xf4 0xea 0x65 0x7a 0xae 0x08
             0xba 0x78 0x25 0x2e 0x1c 0xa6 0xb4 0xc6 0xe8 0xdd 0x74 0x1f 0x4b 0xbd 0x8b 0x8a
             0x70 0x3e 0xb5 0x66 0x48 0x03 0xf6 0x0e 0x61 0x35 0x57 0xb9 0x86 0xc1 0x1d 0x9e
             0xe1 0xf8 0x98 0x11 0x69 0xd9 0x8e 0x94 0x9b 0x1e 0x87 0xe9 0xce 0x55 0x28 0xdf
             0x8c 0xa1 0x89 0x0d 0xbf 0xe6 0x42 0x68 0x41 0x99 0x2d 0x0f 0xb0 0x54 0xbb 0x16]))

     (def ^:private aes-rcon
       (into-array [0 0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0x1b 0x36]))

     (defn- aes-expand-key [k]
       (let [w (js/Uint32Array. 60)]
         (dotimes [i 8]
           (let [i4 (* 4 i)]
             (aset w i (js* "(((~{}[~{}] << 24) | (~{}[~{} + 1] << 16) | (~{}[~{} + 2] << 8) | ~{}[~{} + 3]) >>> 0)"
                            k i4 k i4 k i4 k i4))))
         (dotimes [idx (- 60 8)]
           (let [i (+ idx 8)
                 temp (atom (aget w (dec i)))]
             (cond
               (zero? (mod i 8))
               (let [t @temp
                     sub (js* "(((~{}[(~{} >>> 16) & 0xff] << 24) | (~{}[(~{} >>> 8) & 0xff] << 16) | (~{}[~{} & 0xff] << 8) | ~{}[(~{} >>> 24) & 0xff]) >>> 0)"
                              aes-sbox t aes-sbox t aes-sbox t aes-sbox t)
                     rcon-val (bit-shift-left (aget aes-rcon (quot i 8)) 24)]
                 (reset! temp (bit-xor sub rcon-val)))

               (= (mod i 8) 4)
               (let [t @temp
                     sub (js* "(((~{}[(~{} >>> 24) & 0xff] << 24) | (~{}[(~{} >>> 16) & 0xff] << 16) | (~{}[(~{} >>> 8) & 0xff] << 8) | ~{}[~{} & 0xff]) >>> 0)"
                              aes-sbox t aes-sbox t aes-sbox t aes-sbox t)]
                 (reset! temp sub)))
             (aset w i (unsigned-bit-shift-right (bit-xor (aget w (- i 8)) @temp) 0))))
         w))

     (defn- aes-sub-bytes [s]
       (dotimes [i 16]
         (aset s i (aget aes-sbox (aget s i)))))

     (defn- aes-shift-rows [s]
       (let [t1 (aget s 1)] (aset s 1 (aget s 5)) (aset s 5 (aget s 9)) (aset s 9 (aget s 13)) (aset s 13 t1))
       (let [t2 (aget s 2)] (aset s 2 (aget s 10)) (aset s 10 t2))
       (let [t6 (aget s 6)] (aset s 6 (aget s 14)) (aset s 14 t6))
       (let [t15 (aget s 15)] (aset s 15 (aget s 11)) (aset s 11 (aget s 7)) (aset s 7 (aget s 3)) (aset s 3 t15)))

     (defn- aes-xtime [x]
       (bit-and (bit-xor (bit-shift-left x 1)
                         (* (bit-and (unsigned-bit-shift-right x 7) 1) 0x11b))
                0xff))

     (defn- aes-mix-columns [s]
       (dotimes [i 4]
         (let [i4 (* i 4)
               a (aget s i4) b (aget s (+ i4 1)) c (aget s (+ i4 2)) d (aget s (+ i4 3))
               t (bit-xor a b c d)]
           (aset s i4 (bit-xor (aget s i4) t (aes-xtime (bit-xor a b))))
           (aset s (+ i4 1) (bit-xor (aget s (+ i4 1)) t (aes-xtime (bit-xor b c))))
           (aset s (+ i4 2) (bit-xor (aget s (+ i4 2)) t (aes-xtime (bit-xor c d))))
           (aset s (+ i4 3) (bit-xor (aget s (+ i4 3)) t (aes-xtime (bit-xor d a)))))))

     (defn- aes-add-round-key [s w round]
       (dotimes [i 4]
         (let [word (aget w (+ (* round 4) i))
               i4 (* i 4)]
           (aset s i4 (bit-xor (aget s i4) (bit-and (unsigned-bit-shift-right word 24) 0xff)))
           (aset s (+ i4 1) (bit-xor (aget s (+ i4 1)) (bit-and (unsigned-bit-shift-right word 16) 0xff)))
           (aset s (+ i4 2) (bit-xor (aget s (+ i4 2)) (bit-and (unsigned-bit-shift-right word 8) 0xff)))
           (aset s (+ i4 3) (bit-xor (aget s (+ i4 3)) (bit-and word 0xff))))))

     (defn- aes-cipher-block [inp w]
       (let [s (js/Uint8Array. inp)]
         (aes-add-round-key s w 0)
         (loop [round 1]
           (when (< round 14)
             (aes-sub-bytes s)
             (aes-shift-rows s)
             (aes-mix-columns s)
             (aes-add-round-key s w round)
             (recur (inc round))))
         (aes-sub-bytes s)
         (aes-shift-rows s)
         (aes-add-round-key s w 14)
         s))

     (defn- aes-ghash-mul [X Y]
       (let [v0 (atom (js* "((BigInt(~{}[0]) << 56n) | (BigInt(~{}[1]) << 48n) | (BigInt(~{}[2]) << 40n) | (BigInt(~{}[3]) << 32n) | (BigInt(~{}[4]) << 24n) | (BigInt(~{}[5]) << 16n) | (BigInt(~{}[6]) << 8n) | BigInt(~{}[7]))" Y Y Y Y Y Y Y Y))
             v1 (atom (js* "((BigInt(~{}[8]) << 56n) | (BigInt(~{}[9]) << 48n) | (BigInt(~{}[10]) << 40n) | (BigInt(~{}[11]) << 32n) | (BigInt(~{}[12]) << 24n) | (BigInt(~{}[13]) << 16n) | (BigInt(~{}[14]) << 8n) | BigInt(~{}[15]))" Y Y Y Y Y Y Y Y))
             z0 (atom (js/BigInt 0))
             z1 (atom (js/BigInt 0))
             R (js/BigInt "0xe100000000000000")]
         (dotimes [i 16]
           (let [b (aget X i)]
             (loop [j 7]
               (when (>= j 0)
                 (when (not= (bit-and (unsigned-bit-shift-right b j) 1) 0)
                   (reset! z0 (js* "(~{} ^ ~{})" @z0 @v0))
                   (reset! z1 (js* "(~{} ^ ~{})" @z1 @v1)))
                 (let [lsb (js* "(~{} & 1n)" @v1)]
                   (reset! v1 (js* "((~{} >> 1n) | ((~{} & 1n) << 63n))" @v1 @v0))
                   (reset! v0 (js* "(~{} >> 1n)" @v0))
                   (when (js* "(~{} !== 0n)" lsb)
                     (reset! v0 (js* "(~{} ^ ~{})" @v0 R))))
                 (recur (dec j))))))
         (let [out (js/Uint8Array. 16)]
           (loop [i 7]
             (when (>= i 0)
               (aset out i (js/Number (js* "(~{} & 0xffn)" @z0)))
               (reset! z0 (js* "(~{} >> 8n)" @z0))
               (aset out (+ 8 i) (js/Number (js* "(~{} & 0xffn)" @z1)))
               (reset! z1 (js* "(~{} >> 8n)" @z1))
               (recur (dec i))))
           out)))

     (defn pure-aes-gcm
       "Pure ClojureScript AES-256-GCM AEAD (NIST SP 800-38D)."
       [key nonce input aad is-encrypt?]
       (let [w (aes-expand-key key)
             H (aes-cipher-block (js/Uint8Array. 16) w)
             J0 (js/Uint8Array. 16)]
         (.set J0 nonce 0)
         (aset J0 15 1)
         (let [in-len (if input (.-length input) 0)
               pt-len (if is-encrypt? in-len (- in-len 16))]
           (if (< pt-len 0)
             nil
             (let [out (js/Uint8Array. pt-len)
                   cb (js/Uint8Array. J0)
                   inc32 (fn [blk]
                           (let [val (js* "((((~{}[12] << 24) | (~{}[13] << 16) | (~{}[14] << 8) | ~{}[15]) + 1) >>> 0)"
                                          blk blk blk blk)]
                             (aset blk 12 (bit-and (unsigned-bit-shift-right val 24) 0xff))
                             (aset blk 13 (bit-and (unsigned-bit-shift-right val 16) 0xff))
                             (aset blk 14 (bit-and (unsigned-bit-shift-right val 8) 0xff))
                             (aset blk 15 (bit-and val 0xff))))]
               (loop [i 0]
                 (when (< i pt-len)
                   (inc32 cb)
                   (let [ks (aes-cipher-block cb w)
                         chunk-len (js/Math.min 16 (- pt-len i))]
                     (dotimes [j chunk-len]
                       (aset out (+ i j) (bit-xor (aget input (+ i j)) (aget ks j))))
                     (recur (+ i 16)))))
               (let [ct (if is-encrypt? out (.subarray input 0 pt-len))
                     S (atom (js/Uint8Array. 16))
                     update-ghash (fn [data]
                                    (let [len (.-length data)]
                                      (loop [i 0]
                                        (when (< i len)
                                          (let [block (js/Uint8Array. 16)
                                                chunk-len (js/Math.min 16 (- len i))]
                                            (.set block (.subarray data i (+ i chunk-len)) 0)
                                            (dotimes [j 16]
                                              (aset @S j (bit-xor (aget @S j) (aget block j))))
                                            (reset! S (aes-ghash-mul @S H))
                                            (recur (+ i 16)))))))]
                 (when (and aad (> (.-length aad) 0))
                   (update-ghash aad))
                 (when (> (.-length ct) 0)
                   (update-ghash ct))
                 (let [len-block (js/Uint8Array. 16)
                       aad-bits (atom (if aad (js/BigInt (* (.-length aad) 8)) (js/BigInt 0)))
                       ct-bits (atom (js/BigInt (* (.-length ct) 8)))]
                   (loop [i 7]
                     (when (>= i 0)
                       (aset len-block i (js/Number (js* "(~{} & 0xffn)" @aad-bits)))
                       (reset! aad-bits (js* "(~{} >> 8n)" @aad-bits))
                       (aset len-block (+ 8 i) (js/Number (js* "(~{} & 0xffn)" @ct-bits)))
                       (reset! ct-bits (js* "(~{} >> 8n)" @ct-bits))
                       (recur (dec i))))
                   (dotimes [j 16]
                     (aset @S j (bit-xor (aget @S j) (aget len-block j))))
                   (reset! S (aes-ghash-mul @S H))
                   (let [tag-mask (aes-cipher-block J0 w)
                         tag (js/Uint8Array. 16)]
                     (dotimes [i 16]
                       (aset tag i (bit-xor (aget @S i) (aget tag-mask i))))
                     (if is-encrypt?
                       (let [res (js/Uint8Array. (+ pt-len 16))]
                         (.set res out 0)
                         (.set res tag pt-len)
                         res)
                       (let [expected-tag (.subarray input pt-len)
                             diff (atom 0)]
                         (dotimes [i 16]
                           (reset! diff (bit-or @diff (bit-xor (aget tag i) (aget expected-tag i)))))
                         (if (zero? @diff)
                           out
                           nil)))))))))))

     (set! (.-encrypt pure-aes-gcm) (fn [k n in aad] (pure-aes-gcm k n in aad true)))
     (set! (.-decrypt pure-aes-gcm) (fn [k n in aad] (pure-aes-gcm k n in aad false)))))

#?(:cljs
   (defn pure-aes-gcm-seal
     "Encrypts and authenticates plaintext using pure ClojureScript AES-256-GCM."
     [key nonce plaintext aad]
     (pure-aes-gcm key nonce (or plaintext (js/Uint8Array. 0)) (or aad (js/Uint8Array. 0)) true)))

#?(:cljs
   (defn pure-aes-gcm-open
     "Decrypts and authenticates ciphertext using pure ClojureScript AES-256-GCM."
     [key nonce ciphertext aad]
     (pure-aes-gcm key nonce ciphertext (or aad (js/Uint8Array. 0)) false)))

#?(:clj
   (do
     (declare hkdf-extract hkdf-expand hkdf-sha256 x25519-shared-secret aes-gcm-seal aes-gcm-open chacha-poly-seal chacha-poly-open)
     (defn pure-hmac-sha256 "JVM mirror" [key data] (hkdf-extract key data))
     (defn pure-hkdf-extract "JVM mirror" [salt ikm] (hkdf-extract salt ikm))
     (defn pure-hkdf-expand "JVM mirror" [prk info length] (hkdf-expand prk info length))
     (defn pure-hkdf-sha256 "JVM mirror" [ikm salt info length] (hkdf-sha256 ikm salt info length))
     (defn pure-x25519-shared-secret "JVM mirror" [priv-bytes pub-bytes] (x25519-shared-secret priv-bytes pub-bytes))
     (defn pure-aes-gcm-seal "JVM mirror" [key nonce plaintext aad] (aes-gcm-seal key nonce plaintext aad))
     (defn pure-aes-gcm-open "JVM mirror" [key nonce ciphertext aad] (aes-gcm-open key nonce ciphertext aad))
     (defn pure-chacha-poly-seal "JVM mirror" [key nonce plaintext aad] (chacha-poly-seal key nonce plaintext aad))
     (defn pure-chacha-poly-open "JVM mirror" [key nonce ciphertext aad] (chacha-poly-open key nonce ciphertext aad))))

;; -----------------------------------------------------------------------------
;; X25519 Key Exchange
;; -----------------------------------------------------------------------------

(defn generate-x25519-keypair
  "Generates a new X25519 keypair.
   Returns a map with :public and :private encoded byte arrays."
  []
  #?(:clj (let [kpg (KeyPairGenerator/getInstance "X25519")
                kp (.generateKeyPair kpg)
                pub (.getEncoded (.getPublic kp))
                priv (.getEncoded (.getPrivate kp))]
            {:public pub :private priv :public-key pub :private-key priv})
     :cljs (if node-crypto
             (let [gen-fn (or (aget node-crypto "generateKeyPairSync") (.-generateKeyPairSync node-crypto))
                   kp (.call gen-fn node-crypto "x25519"
                             #js {:publicKeyEncoding #js {:type "spki" :format "der"}
                                  :privateKeyEncoding #js {:type "pkcs8" :format "der"}})
                   pub-obj (or (aget kp "publicKey") (.-publicKey kp))
                   priv-obj (or (aget kp "privateKey") (.-privateKey kp))
                   pub (js/Uint8Array. pub-obj)
                   priv (js/Uint8Array. priv-obj)]
               {:public pub :private priv :public-key pub :private-key priv})
             (pure-x25519-keypair))))

(defn x25519-shared-secret
  "Derives a 32-byte shared secret from local private key bytes and remote public key bytes.
   Accepts both raw 32-byte keys and PKCS8/SPKI DER-encoded keys."
  [priv-bytes pub-bytes]
  #?(:clj (let [p-bytes (if (= (alength ^bytes priv-bytes) 32)
                          (fressian/concat-bytes (fressian/hex->bytes "302e020100300506032b656e04220420") priv-bytes)
                          priv-bytes)
                u-bytes (if (= (alength ^bytes pub-bytes) 32)
                          (fressian/concat-bytes (fressian/hex->bytes "302a300506032b656e032100") pub-bytes)
                          pub-bytes)
                kf (KeyFactory/getInstance "X25519")
                priv-key (.generatePrivate kf (PKCS8EncodedKeySpec. p-bytes))
                pub-key (.generatePublic kf (X509EncodedKeySpec. u-bytes))
                ka (KeyAgreement/getInstance "X25519")]
            (.init ka priv-key)
            (.doPhase ka pub-key true)
            (.generateSecret ka))
     :cljs (if node-crypto
             (let [p-bytes (if (= (fressian/count-bytes priv-bytes) 32)
                             (fressian/concat-bytes (fressian/hex->bytes "302e020100300506032b656e04220420") priv-bytes)
                             priv-bytes)
                   u-bytes (if (= (fressian/count-bytes pub-bytes) 32)
                             (fressian/concat-bytes (fressian/hex->bytes "302a300506032b656e032100") pub-bytes)
                             pub-bytes)
                   create-priv-fn (or (aget node-crypto "createPrivateKey") (.-createPrivateKey node-crypto))
                   create-pub-fn (or (aget node-crypto "createPublicKey") (.-createPublicKey node-crypto))
                   dh-fn (or (aget node-crypto "diffieHellman") (.-diffieHellman node-crypto))
                   priv-key (.call create-priv-fn node-crypto #js {:key (js/Buffer.from p-bytes) :format "der" :type "pkcs8"})
                   pub-key (.call create-pub-fn node-crypto #js {:key (js/Buffer.from u-bytes) :format "der" :type "spki"})]
               (js/Uint8Array. (.call dh-fn node-crypto #js {:privateKey priv-key :publicKey pub-key})))
             (pure-x25519-shared-secret priv-bytes pub-bytes))))

;; -----------------------------------------------------------------------------
;; HKDF-SHA256 (RFC 5869)
;; -----------------------------------------------------------------------------

(defn hkdf-extract
  "Extracts a pseudorandom key (PRK) from salt and input keying material (IKM) using HMAC-SHA256.
   If salt is nil or empty, a 32-byte array of zeros is used per RFC 5869 §2.2."
  [salt ikm]
  #?(:clj (let [effective-salt (if (or (nil? salt) (zero? (alength ^bytes salt)))
                                 (byte-array 32)
                                 salt)
                mac (Mac/getInstance "HmacSHA256")]
            (.init mac (SecretKeySpec. effective-salt "HmacSHA256"))
            (.doFinal mac ikm))
     :cljs (pure-hkdf-extract salt ikm)))

(defn hkdf-expand
  "Expands a pseudorandom key (PRK) and info into output keying material (OKM) of desired length.
   Follows RFC 5869 §2.3 for HMAC-SHA256."
  [prk info length]
  #?(:clj (let [hash-len 32
                n (long (Math/ceil (/ (double length) hash-len)))
                _ (when (> n 255)
                    (throw (IllegalArgumentException. "Requested length exceeds HKDF-SHA256 maximum (255 * 32 bytes)")))
                mac (Mac/getInstance "HmacSHA256")
                key-spec (SecretKeySpec. prk "HmacSHA256")
                out-buf (ByteBuffer/allocate length)
                safe-info (or info (byte-array 0))]
            (loop [i 1
                   t (byte-array 0)]
              (if (<= i n)
                (do
                  (.init mac key-spec)
                  (when (pos? (alength ^bytes t))
                    (.update mac ^bytes t))
                  (when (pos? (alength ^bytes safe-info))
                    (.update mac ^bytes safe-info))
                  (.update mac (byte i))
                  (let [t-next (.doFinal mac)
                        to-copy (min hash-len (- length (.position out-buf)))]
                    (.put out-buf t-next 0 to-copy)
                    (recur (inc i) t-next)))
                (.array out-buf))))
     :cljs (pure-hkdf-expand prk info length)))

(defn hkdf-sha256
  "Combines hkdf-extract and hkdf-expand into a single RFC 5869 HKDF-SHA256 operation."
  [ikm salt info length]
  (let [prk (hkdf-extract salt ikm)]
    (hkdf-expand prk info length)))

;; -----------------------------------------------------------------------------
;; Directional Channel Keys & Nonce Derivation
;; -----------------------------------------------------------------------------

(defn derive-channel-keys
  "Derives directional 32-byte :tx-key and :rx-key from shared-secret and session-id.
   For role :initiator:
     :tx-key = i2r key, :rx-key = r2i key
   For role :responder:
     :tx-key = r2i key, :rx-key = i2r key."
  [shared-secret session-id role]
  (let [salt (fressian/utf8->bytes (or session-id ""))
        prk (hkdf-extract salt shared-secret)
        info-i2r (fressian/utf8->bytes "bitecho-sealed-v1-i2r")
        info-r2i (fressian/utf8->bytes "bitecho-sealed-v1-r2i")
        k-i2r (hkdf-expand prk info-i2r 32)
        k-r2i (hkdf-expand prk info-r2i 32)]
    (if (= role :initiator)
      {:tx-key k-i2r :rx-key k-r2i}
      {:tx-key k-r2i :rx-key k-i2r})))

(defn derive-session-keys
  "Derives directional channel keys for a rendezvous sealed-channel handoff.
   Accepts [my-priv peer-pub caller-pub callee-pub offer-hash role] or [my-priv peer-pub caller-pub callee-pub offer-hash].
   Uses X25519 Diffie-Hellman to derive the shared secret and derives directional keys
   bound to offer-hash salt."
  ([my-priv peer-pub caller-pub callee-pub offer-hash]
   (derive-session-keys my-priv peer-pub caller-pub callee-pub offer-hash :initiator))
  ([my-priv peer-pub _caller-pub _callee-pub offer-hash role]
   (let [priv-bytes (if (string? my-priv) (basalt/hex->bytes my-priv) my-priv)
         peer-bytes (if (string? peer-pub) (basalt/hex->bytes peer-pub) peer-pub)
         shared-secret (x25519-shared-secret priv-bytes peer-bytes)
         salt-str (str (or offer-hash ""))]
     (derive-channel-keys shared-secret salt-str role))))

(defn seq->nonce
  "Deterministically encodes a 64-bit sequence number into a 12-byte (96-bit) nonce:
   4 zero prefix bytes followed by 8-byte big-endian sequence number."
  [seq-num]
  #?(:clj (let [bb (ByteBuffer/allocate 12)]
            (.putInt bb 0)
            (.putLong bb (long seq-num))
            (.array bb))
     :cljs (let [buf (js/Uint8Array. 12)
                 dv (js/DataView. (.-buffer buf))]
             (.setBigUint64 dv 4 (js/BigInt (str seq-num)))
             buf)))

;; -----------------------------------------------------------------------------
;; AEAD Implementations (AES-256-GCM & ChaCha20-Poly1305)
;; -----------------------------------------------------------------------------

(defn chacha-poly-seal
  "Encrypts and authenticates plaintext using ChaCha20-Poly1305 AEAD.
   Appends 16-byte authentication tag to ciphertext."
  [tx-key nonce plaintext aad]
  #?(:clj (let [cipher (Cipher/getInstance "ChaCha20-Poly1305")
                key-spec (SecretKeySpec. tx-key "ChaCha20")
                iv-spec (IvParameterSpec. nonce)]
            (.init cipher Cipher/ENCRYPT_MODE key-spec iv-spec)
            (when (and aad (pos? (alength ^bytes aad)))
              (.updateAAD cipher ^bytes aad))
            (let [input (or plaintext (byte-array 0))]
              (.doFinal cipher input)))
     :cljs (if node-crypto
             (let [cipher (.createCipheriv node-crypto "chacha20-poly1305" (js/Buffer.from tx-key) (js/Buffer.from nonce) #js {:authTagLength 16})]
               (when (and aad (pos? (fressian/count-bytes aad)))
                 (.setAAD cipher (js/Buffer.from aad)))
               (let [input (or plaintext (js/Uint8Array. 0))
                     part1 (.update cipher (js/Buffer.from input))
                     _part2 (.final cipher)
                     tag (.getAuthTag cipher)
                     total (js/Buffer.concat #js [part1 tag])]
                 (js/Uint8Array. total)))
             (pure-chacha-poly-seal tx-key nonce plaintext aad))))

(defn chacha-poly-open
  "Decrypts and verifies ciphertext (including 16-byte tag) using ChaCha20-Poly1305 AEAD.
   Returns plaintext bytes on success, nil on tampering or verification failure."
  [rx-key nonce ciphertext aad]
  (try
    #?(:clj (let [cipher (Cipher/getInstance "ChaCha20-Poly1305")
                  key-spec (SecretKeySpec. rx-key "ChaCha20")
                  iv-spec (IvParameterSpec. nonce)]
              (.init cipher Cipher/DECRYPT_MODE key-spec iv-spec)
              (when (and aad (pos? (alength ^bytes aad)))
                (.updateAAD cipher ^bytes aad))
              (.doFinal cipher ^bytes ciphertext))
       :cljs (if node-crypto
               (let [ct-buf (js/Buffer.from ciphertext)
                     tag-len 16
                     payload-len (- (.-length ct-buf) tag-len)]
                 (when (>= payload-len 0)
                   (let [payload (.subarray ct-buf 0 payload-len)
                         tag (.subarray ct-buf payload-len)
                         decipher (.createDecipheriv node-crypto "chacha20-poly1305" (js/Buffer.from rx-key) (js/Buffer.from nonce) #js {:authTagLength 16})]
                     (when (and aad (pos? (fressian/count-bytes aad)))
                       (.setAAD decipher (js/Buffer.from aad)))
                     (.setAuthTag decipher tag)
                     (let [part1 (.update decipher payload)
                           part2 (.final decipher)]
                       (js/Uint8Array. (js/Buffer.concat #js [part1 part2]))))))
               (pure-chacha-poly-open rx-key nonce ciphertext aad)))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn aes-gcm-seal
  "Encrypts and authenticates plaintext using AES-256-GCM AEAD.
   Appends 16-byte authentication tag to ciphertext."
  [tx-key nonce plaintext aad]
  #?(:clj (let [cipher (Cipher/getInstance "AES/GCM/NoPadding")
                key-spec (SecretKeySpec. tx-key "AES")
                gcm-spec (GCMParameterSpec. 128 nonce)]
            (.init cipher Cipher/ENCRYPT_MODE key-spec gcm-spec)
            (when (and aad (pos? (alength ^bytes aad)))
              (.updateAAD cipher ^bytes aad))
            (let [input (or plaintext (byte-array 0))]
              (.doFinal cipher input)))
     :cljs (if node-crypto
             (let [cipher (.createCipheriv node-crypto "aes-256-gcm" (js/Buffer.from tx-key) (js/Buffer.from nonce) #js {:authTagLength 16})]
               (when (and aad (pos? (fressian/count-bytes aad)))
                 (.setAAD cipher (js/Buffer.from aad)))
               (let [input (or plaintext (js/Uint8Array. 0))
                     part1 (.update cipher (js/Buffer.from input))
                     part2 (.final cipher)
                     tag (.getAuthTag cipher)
                     total (js/Buffer.concat #js [part1 part2 tag])]
                 (js/Uint8Array. total)))
             (pure-aes-gcm-seal tx-key nonce plaintext aad))))

(defn aes-gcm-open
  "Decrypts and verifies ciphertext (including 16-byte tag) using AES-256-GCM AEAD.
   Returns plaintext bytes on success, nil on tampering or verification failure."
  [rx-key nonce ciphertext aad]
  (try
    #?(:clj (let [cipher (Cipher/getInstance "AES/GCM/NoPadding")
                  key-spec (SecretKeySpec. rx-key "AES")
                  gcm-spec (GCMParameterSpec. 128 nonce)]
              (.init cipher Cipher/DECRYPT_MODE key-spec gcm-spec)
              (when (and aad (pos? (alength ^bytes aad)))
                (.updateAAD cipher ^bytes aad))
              (.doFinal cipher ^bytes ciphertext))
       :cljs (if node-crypto
               (let [ct-buf (js/Buffer.from ciphertext)
                     tag-len 16
                     payload-len (- (.-length ct-buf) tag-len)]
                 (when (>= payload-len 0)
                   (let [payload (.subarray ct-buf 0 payload-len)
                         tag (.subarray ct-buf payload-len)
                         decipher (.createDecipheriv node-crypto "aes-256-gcm" (js/Buffer.from rx-key) (js/Buffer.from nonce) #js {:authTagLength 16})]
                     (when (and aad (pos? (fressian/count-bytes aad)))
                       (.setAAD decipher (js/Buffer.from aad)))
                     (.setAuthTag decipher tag)
                     (let [part1 (.update decipher payload)
                           part2 (.final decipher)]
                       (js/Uint8Array. (js/Buffer.concat #js [part1 part2]))))))
               (pure-aes-gcm-open rx-key nonce ciphertext aad)))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn seal-message
  "Encrypts and authenticates plaintext using AEAD.
   Accepts [tx-key seq-num plaintext aad] (defaults to suite-v1-aes256gcm)
   or [tx-key seq-num plaintext aad suite].
   Returns a map with :seq, :nonce (12 bytes), :ciphertext (including 16-byte tag), and :suite."
  ([tx-key seq-num plaintext aad suite]
   (let [k (if (map? tx-key) (or (:tx-key tx-key) tx-key) tx-key)
         suite-norm (if (keyword? suite) (name suite) (or suite suite-v1-aes256gcm))
         nonce (seq->nonce seq-num)
         ct (case suite-norm
              "suite-v1-aes256gcm" (aes-gcm-seal k nonce plaintext aad)
              "suite-v1-chacha20poly1305" (chacha-poly-seal k nonce plaintext aad)
              (throw (ex-info (str "Unsupported crypto-suite for sealing: " suite-norm) {:suite suite-norm})))]
     {:seq seq-num
      :nonce nonce
      :ciphertext ct
      :suite suite-norm}))
  ([tx-key seq-num plaintext aad]
   (if (or (= aad suite-v1-aes256gcm)
           (= aad suite-v1-chacha20poly1305)
           (= aad :suite-v1-aes256gcm)
           (= aad :suite-v1-chacha20poly1305))
     (seal-message tx-key seq-num plaintext nil aad)
     (seal-message tx-key seq-num plaintext aad suite-v1-aes256gcm))))

(defn open-message
  "Decrypts and verifies ciphertext using AEAD.
   Supports 4-arity [rx-key seq-num ciphertext aad],
   5-arity [rx-key seq-num ciphertext aad suite-or-opts],
   and 6-arity [rx-key seq-num ciphertext aad session-suite frame-suite].
   Rejects frame if session-suite and frame-suite mismatch (anti-downgrade).
   Returns the decrypted plaintext byte array on success, or nil on failure/tampering."
  ([rx-key seq-num ciphertext aad session-suite frame-suite]
   (let [k (if (map? rx-key) (or (:rx-key rx-key) rx-key) rx-key)
         ct (if (map? ciphertext) (or (:ciphertext ciphertext) ciphertext) ciphertext)
         s-norm (when session-suite (if (keyword? session-suite) (name session-suite) (str session-suite)))
         f-norm (when frame-suite (if (keyword? frame-suite) (name frame-suite) (str frame-suite)))]
     (cond
       ;; Mid-session downgrade / suite mismatch rejection
       (and s-norm f-norm (not= s-norm f-norm))
       nil

       :else
       (let [target-suite (or f-norm s-norm)
             nonce (seq->nonce seq-num)]
         (case target-suite
           "suite-v1-aes256gcm"
           (aes-gcm-open k nonce ct aad)

           "suite-v1-chacha20poly1305"
           (chacha-poly-open k nonce ct aad)

           nil
           ;; No suite specified: try suite-v1-aes256gcm first, fallback to suite-v1-chacha20poly1305
           (or (aes-gcm-open k nonce ct aad)
               (chacha-poly-open k nonce ct aad))

           nil)))))
  ([rx-key seq-num ciphertext aad suite-or-opts]
   (if (map? suite-or-opts)
     (open-message rx-key seq-num ciphertext aad
                   (or (:session-suite suite-or-opts) (:expected-suite suite-or-opts))
                   (or (:frame-suite suite-or-opts) (:suite suite-or-opts)))
     (open-message rx-key seq-num ciphertext aad suite-or-opts suite-or-opts)))
  ([rx-key seq-num ciphertext aad]
   (open-message rx-key seq-num ciphertext aad nil nil)))

;; -----------------------------------------------------------------------------
;; Offer Hash Binding & DAC Integrity (SPEC §4)
;; -----------------------------------------------------------------------------

(defn- safe-long [v default-val]
  (cond
    (integer? v) (long v)
    (number? v) (long v)
    (string? v) (try
                  #?(:clj (Long/parseLong (str/trim v))
                     :cljs (let [n (js/parseInt (str/trim v) 10)]
                             (if (js/isNaN n) default-val n)))
                  (catch #?(:clj Exception :cljs :default) _ default-val))
    :else default-val))

(defn offer-hash
  "Computes deterministic offer-hash binding session-id, caller, callee, ephemeral key, epoch, price, home-node,
   optional :crypto-suites, and optional :dac.
   When :crypto-suites is present, appends |<suites-csv> to bind the negotiated suite preference to the signature."
  [offer-map]
  (let [sid (str (or (:session-id offer-map) (get offer-map "session_id") (get offer-map "session-id") ""))
        caller (str (or (:caller offer-map) (get offer-map "caller") ""))
        callee (str (or (:callee offer-map) (get offer-map "callee") ""))
        eph (str (or (:caller-ephemeral-pub offer-map) (get offer-map "caller_ephemeral_pub") (get offer-map "caller-ephemeral-pub") ""))
        epoch (safe-long (or (:epoch offer-map) (get offer-map "epoch")) 0)
        price (safe-long (or (:price offer-map) (get offer-map "price") (:burn offer-map) (get offer-map "burn")) 0)
        home-node (or (:home-node offer-map) (get offer-map "home_node") (get offer-map "home-node") "")
        hn-str (if (keyword? home-node) (name home-node) (str home-node))
        dac (or (:dac offer-map) (get offer-map "dac"))
        dac-id (when dac (or (:dac-id dac) (get dac "dac_id") (get dac "dac-id") (:dac_id dac)))
        suites (or (:crypto-suites offer-map) (get offer-map "crypto_suites") (get offer-map "crypto-suites"))
        suites-str (when (seq suites)
                     (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))
        base-str (str "bitecho-sealed-offer-v1|" sid "|" caller "|" callee "|" eph "|" epoch "|" price "|" hn-str)
        with-suites (if (seq suites-str)
                      (str base-str "|" suites-str)
                      base-str)
        canonical-str (if (and dac (seq (str dac-id)))
                        (str with-suites "|" dac-id)
                        with-suites)]
    (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes canonical-str)))))

;; -----------------------------------------------------------------------------
;; Gap-Tolerant Replay Window (SPEC §7)
;; -----------------------------------------------------------------------------

(defn init-replay-window
  "Initializes an anti-replay window state map with highest-seq 0, empty seen set, and window-size."
  ([] (init-replay-window 64))
  ([window-size]
   {:highest-seq 0
    :seen #{}
    :window-size (long window-size)}))

(defn check-and-advance-replay-window
  "Evaluates seq-num against anti-replay window.
   Rejects non-positive sequence numbers (:invalid-seq),
   duplicates (:replayed-seq), and entries older than the sliding window (:stale-seq).
   Returns {:accepted? boolean :error keyword :window updated-window}."
  [window seq-num]
  (let [seq-val (long seq-num)
        window-size (:window-size window 64)
        highest (:highest-seq window 0)
        seen (:seen window #{})]
    (cond
      (<= seq-val 0)
      {:accepted? false :error :invalid-seq :window window}

      (> seq-val highest)
      (let [cutoff (- seq-val window-size)
            pruned (into #{} (filter #(>= % cutoff)) seen)
            updated-window (assoc window
                                  :highest-seq seq-val
                                  :seen (conj pruned seq-val))]
        {:accepted? true :window updated-window})

      (< (- highest seq-val) window-size)
      (if (contains? seen seq-val)
        {:accepted? false :error :replayed-seq :window window}
        (let [updated-window (update window :seen conj seq-val)]
          {:accepted? true :window updated-window}))

      :else
      {:accepted? false :error :stale-seq :window window})))
