(ns bitecho.crypto
  "Cryptographic primitives and shell-boundary abstractions for Bitecho:
   - Pure synchronous SHA-256 hashing across JVM and CLJS
   - Seeded portable PRNG protocol (IRandom)
   - Ed25519 signing and verification (JDK on JVM, node:crypto on Node/CLJS)
   - Canonical signing bytes & N/N-1 rolling-upgrade verification (Decision A(i) / Standing Constraint 4)
   - Shell-boundary crypto protocol (ICryptoBoundary) for async envelope pre-verification and egress effects."
  (:require [bitecho.fressian :as fressian]
            #?(:cljs ["crypto" :as node-crypto]))
  #?(:clj
     (:import [java.security MessageDigest KeyPairGenerator KeyFactory Signature]
              [java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec]
              [java.util Random])))

;; =============================================================================
;; Pure Synchronous SHA-256
;; =============================================================================

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
;; Portable Seeded PRNG Protocol (IRandom)
;; =============================================================================

(defprotocol IRandom
  (next-int [this] [this bound])
  (next-long [this])
  (next-double [this])
  (next-bytes [this byte-arr]))

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
       byte-arr)))

#?(:cljs
   (deftype SplitMix64PRNG [^:mutable state]
     IRandom
     (next-long [_]
       (let [s (.asUintN js/BigInt 64 (+ state (js/BigInt "0x9e3779b97f4a7c15")))]
         (set! state s)
         (let [z1 (.asUintN js/BigInt 64 (* (bit-xor s (bit-shift-right s (js/BigInt 30)))
                                            (js/BigInt "0xbf58476d1ce4e5b9")))
               z2 (.asUintN js/BigInt 64 (* (bit-xor z1 (bit-shift-right z1 (js/BigInt 27)))
                                            (js/BigInt "0x94d049bb133111eb")))
               z3 (bit-xor z2 (bit-shift-right z2 (js/BigInt 31)))]
           (js/Number (.asIntN js/BigInt 64 z3)))))
     (next-int [this]
       (bit-or (int (next-long this)) 0))
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
         byte-arr))))

(defn make-random
  "Constructs an IRandom seeded PRNG instance."
  ([]
   #?(:clj  (Random.)
      :cljs (SplitMix64PRNG. (js/BigInt (.now js/Date)))))
  ([seed]
   #?(:clj  (Random. (long seed))
      :cljs (SplitMix64PRNG. (js/BigInt seed)))))

;; =============================================================================
;; Ed25519 Signing & Verification
;; =============================================================================

(defn generate-keypair
  "Generates an Ed25519 keypair.
   Returns a map with :public (X.509 SPKI DER) and :private (PKCS#8 DER) byte arrays."
  []
  #?(:clj
     (let [kpg (KeyPairGenerator/getInstance "Ed25519")
           kp (.generateKeyPair kpg)]
       {:public (.getEncoded (.getPublic kp))
        :private (.getEncoded (.getPrivate kp))})
     :cljs
     (let [kp (.generateKeyPairSync node-crypto "ed25519")
           pub-der (.export (.-publicKey kp) #js {:type "spki" :format "der"})
           priv-der (.export (.-privateKey kp) #js {:type "pkcs8" :format "der"})]
       {:public (js/Uint8Array. pub-der)
        :private (js/Uint8Array. priv-der)})))

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
       (let [key-obj (.createPrivateKey node-crypto #js {:key (js/Buffer.from priv-bytes) :format "der" :type "pkcs8"})
             sig (.sign node-crypto nil (js/Buffer.from msg-bytes) key-obj)]
         (js/Uint8Array. sig)))))

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
         (let [key-obj (.createPublicKey node-crypto #js {:key (js/Buffer.from pub-bytes) :format "der" :type "spki"})
               ok (.verify node-crypto nil (js/Buffer.from msg-bytes) key-obj (js/Buffer.from sig-bytes))]
           (boolean ok))))
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
   Scheduled for sunset in Milestone 10."
  true)

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

(defn- canonicalize-agent-event
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
