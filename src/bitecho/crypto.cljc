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
              [java.util Random])))

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

(defn random-bytes
  "Generates n cryptographically secure random bytes.
   Uses SecureRandom on JVM, globalThis.crypto.getRandomValues in Browser,
   or node:crypto randomBytes on Node.js. Fails closed if no CSPRNG is available."
  [n]
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
       (js/Uint8Array. (.randomBytes node-crypto n))

       :else
       (throw (js/Error. "No CSPRNG available (neither globalThis.crypto.getRandomValues nor node:crypto).")))))

;; =============================================================================
;; Pure Synchronous SHA-512 & RFC 8032 Ed25519 (Browser + CLJS Fallback)
;; =============================================================================

#?(:cljs
   (def ^:private pure-ed25519-engine
     ((js/Function.
       "const K512 = [
  0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
  0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
  0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
  0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
  0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
  0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
  0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
  0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n
];
const H512 = [
  0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n
];
const M64 = 0xffffffffffffffffn;
function rotr64(x, n) { return ((x >> n) | ((x << (64n - n)) & M64)) & M64; }
function sha512(msg) {
  const len = msg.length;
  const bitLen = BigInt(len) * 8n;
  const padLen = ((len + 17 + 127) & ~127);
  const buf = new Uint8Array(padLen);
  buf.set(msg, 0);
  buf[len] = 0x80;
  let bl = bitLen;
  for (let i = 0; i < 8; i++) {
    buf[padLen - 1 - i] = Number(bl & 0xffn);
    bl >>= 8n;
  }
  let h0 = H512[0], h1 = H512[1], h2 = H512[2], h3 = H512[3],
      h4 = H512[4], h5 = H512[5], h6 = H512[6], h7 = H512[7];
  const W = new Array(80);
  for (let off = 0; off < padLen; off += 128) {
    for (let i = 0; i < 16; i++) {
      let w = 0n;
      for (let b = 0; b < 8; b++) w = (w << 8n) | BigInt(buf[off + i * 8 + b]);
      W[i] = w;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(W[i-15], 1n) ^ rotr64(W[i-15], 8n) ^ (W[i-15] >> 7n);
      const s1 = rotr64(W[i-2], 19n) ^ rotr64(W[i-2], 61n) ^ (W[i-2] >> 6n);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) & M64;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ ((~e & M64) & g);
      const temp1 = (h + S1 + ch + K512[i] + W[i]) & M64;
      const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) & M64;
      h = g; g = f; f = e; e = (d + temp1) & M64;
      d = c; c = b; b = a; a = (temp1 + temp2) & M64;
    }
    h0 = (h0 + a) & M64; h1 = (h1 + b) & M64; h2 = (h2 + c) & M64; h3 = (h3 + d) & M64;
    h4 = (h4 + e) & M64; h5 = (h5 + f) & M64; h6 = (h6 + g) & M64; h7 = (h7 + h) & M64;
  }
  const out = new Uint8Array(64);
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i++) {
    let v = hs[i];
    for (let b = 7; b >= 0; b--) { out[i * 8 + b] = Number(v & 0xffn); v >>= 8n; }
  }
  return out;
}
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
function modP(x) { return ((x % P) + P) % P; }
function modL(x) { return ((x % L) + L) % L; }
function modPow(base, exp) {
  let res = 1n, b = modP(base), e = exp;
  while (e > 0n) {
    if (e & 1n) res = modP(res * b);
    b = modP(b * b);
    e >>= 1n;
  }
  return res;
}
function invP(x) { return modPow(x, P - 2n); }
const D = modP(-121665n * invP(121666n));
const I_SQRT = modPow(2n, (P - 1n) / 4n);
const BY = modP(4n * invP(5n));
const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const B_PT = [BX, BY, 1n, modP(BX * BY)];
function ptAdd(P1, P2) {
  const [X1, Y1, Z1, T1] = P1;
  const [X2, Y2, Z2, T2] = P2;
  const A = modP((Y1 - X1) * (Y2 - X2));
  const B = modP((Y1 + X1) * (Y2 + X2));
  const C = modP(2n * D * T1 * T2);
  const D2 = modP(2n * Z1 * Z2);
  const E = modP(B - A);
  const F = modP(D2 - C);
  const G = modP(D2 + C);
  const H = modP(B + A);
  return [modP(E * F), modP(G * H), modP(F * G), modP(E * H)];
}
function scalarMult(k, pt) {
  let R = [0n, 1n, 1n, 0n];
  let Q = pt;
  let n = k;
  while (n > 0n) {
    if (n & 1n) R = ptAdd(R, Q);
    Q = ptAdd(Q, Q);
    n >>= 1n;
  }
  return R;
}
function encodePoint(pt) {
  const [X, Y, Z] = pt;
  const zi = invP(Z);
  const x = modP(X * zi);
  const y = modP(Y * zi);
  const out = new Uint8Array(32);
  let n = y;
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  out[31] |= Number(x & 1n) << 7;
  return out;
}
function decodePoint(bytes) {
  if (!bytes || bytes.length !== 32) return null;
  const sign = (bytes[31] >> 7) & 1;
  let y = 0n;
  for (let i = 0; i < 32; i++) {
    const b = (i === 31) ? (bytes[i] & 0x7f) : bytes[i];
    y |= BigInt(b) << (BigInt(i) * 8n);
  }
  if (y >= P) return null;
  const y2 = modP(y * y);
  const u = modP(y2 - 1n);
  const v = modP(D * y2 + 1n);
  let x = modP(u * invP(v));
  x = modPow(x, (P + 3n) / 8n);
  if (modP(x * x * v) !== u) {
    x = modP(x * I_SQRT);
    if (modP(x * x * v) !== u) return null;
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return [x, y, 1n, modP(x * y)];
}
function decodeLE(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n |= BigInt(bytes[i]) << (BigInt(i) * 8n);
  return n;
}
function encodeLE32(num) {
  const out = new Uint8Array(32);
  let n = num;
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
function expandSecret(seed32) {
  const h = sha512(seed32);
  const sBytes = h.slice(0, 32);
  sBytes[0] &= 248;
  sBytes[31] &= 127;
  sBytes[31] |= 64;
  const s = decodeLE(sBytes);
  const prefix = h.slice(32, 64);
  const pub = encodePoint(scalarMult(s, B_PT));
  return { s, prefix, pub };
}
function publicKey(seed32) { return expandSecret(seed32).pub; }
function sign(seed32, msgBytes) {
  const { s, prefix, pub } = expandSecret(seed32);
  const rInput = new Uint8Array(32 + msgBytes.length);
  rInput.set(prefix, 0); rInput.set(msgBytes, 32);
  const r = modL(decodeLE(sha512(rInput)));
  const R = encodePoint(scalarMult(r, B_PT));
  const kInput = new Uint8Array(64 + msgBytes.length);
  kInput.set(R, 0); kInput.set(pub, 32); kInput.set(msgBytes, 64);
  const k = modL(decodeLE(sha512(kInput)));
  const S = modL(r + k * s);
  const sig = new Uint8Array(64);
  sig.set(R, 0); sig.set(encodeLE32(S), 32);
  return sig;
}
function verify(pub32, msgBytes, sig64) {
  if (!sig64 || sig64.length !== 64 || !pub32 || pub32.length !== 32) return false;
  const Rbytes = sig64.subarray(0, 32);
  const Sbytes = sig64.subarray(32, 64);
  const S = decodeLE(Sbytes);
  if (S >= L) return false;
  const A = decodePoint(pub32);
  const R = decodePoint(Rbytes);
  if (!A || !R) return false;
  const kInput = new Uint8Array(64 + msgBytes.length);
  kInput.set(Rbytes, 0); kInput.set(pub32, 32); kInput.set(msgBytes, 64);
  const k = modL(decodeLE(sha512(kInput)));
  const lhs = encodePoint(scalarMult(S, B_PT));
  const rhs = encodePoint(ptAdd(R, scalarMult(k, A)));
  for (let i = 0; i < 32; i++) if (lhs[i] !== rhs[i]) return false;
  return true;
}
return { sha512, publicKey, sign, verify };"))))

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
   Returns a map with :public (X.509 SPKI DER) and :private (PKCS#8 DER) byte arrays."
  []
  #?(:clj
     (let [kpg (KeyPairGenerator/getInstance "Ed25519")
           kp (.generateKeyPair kpg)
           pub (.getEncoded (.getPublic kp))
           priv (.getEncoded (.getPrivate kp))]
       {:public pub :private priv :public-key pub :private-key priv})
     :cljs
     (if node-crypto
       (let [kp (.generateKeyPairSync node-crypto "ed25519")
             pub-der (.export (.-publicKey kp) #js {:type "spki" :format "der"})
             priv-der (.export (.-privateKey kp) #js {:type "pkcs8" :format "der"})
             pub (js/Uint8Array. pub-der)
             priv (js/Uint8Array. priv-der)]
         {:public pub :private priv :public-key pub :private-key priv})
       (pure-ed25519-keypair))))

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
         (let [key-obj (.createPrivateKey node-crypto #js {:key (js/Buffer.from priv-bytes) :format "der" :type "pkcs8"})
               sig (.sign node-crypto nil (js/Buffer.from msg-bytes) key-obj)]
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
           (let [key-obj (.createPublicKey node-crypto #js {:key (js/Buffer.from pub-bytes) :format "der" :type "spki"})
                 ok (.verify node-crypto nil (js/Buffer.from msg-bytes) key-obj (js/Buffer.from sig-bytes))]
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
