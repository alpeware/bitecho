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
   (def ^{:doc "Pure ClojureScript Montgomery ladder scalar multiplication over Curve25519 (RFC 7748 §5)."}
     pure-curve25519
     (js/Function. "scalarBytes" "uBytes"
                   "const p = (1n << 255n) - 19n;
const a24 = 121665n;
function modP(x) { return ((x % p) + p) % p; }
function modPow(b, exp) {
  let res = 1n;
  let base = modP(b);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = modP(res * base);
    base = modP(base * base);
    e >>= 1n;
  }
  return res;
}
function decodeLE(buf) {
  let res = 0n;
  for (let i = 0; i < buf.length; i++) {
    res |= BigInt(buf[i]) << (BigInt(i) * 8n);
  }
  return res;
}
function encodeLE(num) {
  const buf = new Uint8Array(32);
  let n = num;
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return buf;
}
const kClamped = new Uint8Array(scalarBytes);
kClamped[0] &= 248;
kClamped[31] &= 127;
kClamped[31] |= 64;
const k = decodeLE(kClamped);
const u = modP(decodeLE(uBytes));
let x1 = u, x2 = 1n, z2 = 0n, x3 = u, z3 = 1n;
let swap = 0n;
for (let t = 254; t >= 0; t--) {
  const kt = (k >> BigInt(t)) & 1n;
  swap ^= kt;
  if (swap === 1n) {
    let tmp = x2; x2 = x3; x3 = tmp;
    tmp = z2; z2 = z3; z3 = tmp;
  }
  swap = kt;
  const A = modP(x2 + z2);
  const AA = modP(A * A);
  const B = modP(x2 - z2);
  const BB = modP(B * B);
  const E = modP(AA - BB);
  const C = modP(x3 + z3);
  const D = modP(x3 - z3);
  const DA = modP(D * A);
  const CB = modP(C * B);
  x3 = modP((DA + CB) * (DA + CB));
  z3 = modP(x1 * modP((DA - CB) * (DA - CB)));
  x2 = modP(AA * BB);
  z2 = modP(E * (AA + a24 * E));
}
if (swap === 1n) {
  let tmp = x2; x2 = x3; x3 = tmp;
  tmp = z2; z2 = z3; z3 = tmp;
}
const result = modP(x2 * modPow(z2, p - 2n));
return encodeLE(result);")))

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
   (def ^{:doc "Pure ClojureScript ChaCha20-Poly1305 AEAD (RFC 8439)."}
     pure-chacha20-poly1305
     (js/Function. "key" "nonce" "input" "aad" "isEncrypt"
                   "function rotl(a, b) { return ((a << b) | (a >>> (32 - b))) >>> 0; }
function qround(x, a, b, c, d) {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
}
function chacha20Block(k, counter, n) {
  const state = new Uint32Array(16);
  state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) {
    state[4 + i] = (k[4*i] | (k[4*i+1] << 8) | (k[4*i+2] << 16) | (k[4*i+3] << 24)) >>> 0;
  }
  state[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) {
    state[13 + i] = (n[4*i] | (n[4*i+1] << 8) | (n[4*i+2] << 16) | (n[4*i+3] << 24)) >>> 0;
  }
  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    qround(working, 0, 4, 8, 12);
    qround(working, 1, 5, 9, 13);
    qround(working, 2, 6, 10, 14);
    qround(working, 3, 7, 11, 15);
    qround(working, 0, 5, 10, 15);
    qround(working, 1, 6, 11, 12);
    qround(working, 2, 7, 8, 13);
    qround(working, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const val = (working[i] + state[i]) >>> 0;
    out[4*i] = val & 0xff;
    out[4*i+1] = (val >>> 8) & 0xff;
    out[4*i+2] = (val >>> 16) & 0xff;
    out[4*i+3] = (val >>> 24) & 0xff;
  }
  return out;
}
function poly1305(k, msg) {
  let r = 0n;
  for (let i = 0; i < 16; i++) r |= BigInt(k[i]) << (BigInt(i) * 8n);
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  let s = 0n;
  for (let i = 0; i < 16; i++) s |= BigInt(k[16 + i]) << (BigInt(i) * 8n);
  const p = (1n << 130n) - 5n;
  let a = 0n;
  const len = msg.length;
  for (let i = 0; i < len; i += 16) {
    const chunk = msg.subarray(i, Math.min(i + 16, len));
    let num = 0n;
    for (let j = 0; j < chunk.length; j++) num |= BigInt(chunk[j]) << (BigInt(j) * 8n);
    num |= 1n << (BigInt(chunk.length) * 8n);
    a = ((a + num) * r) % p;
  }
  a = (a + s) % (1n << 128n);
  const tag = new Uint8Array(16);
  let n = a;
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return tag;
}
const block0 = chacha20Block(key, 0, nonce);
const polyKey = block0.subarray(0, 32);
const inLen = input ? input.length : 0;
const ptLen = isEncrypt ? inLen : (inLen - 16);
if (ptLen < 0) return null;
const out = new Uint8Array(ptLen);
let counter = 1;
for (let i = 0; i < ptLen; i += 64) {
  const ks = chacha20Block(key, counter++, nonce);
  const chunkLen = Math.min(64, ptLen - i);
  for (let j = 0; j < chunkLen; j++) out[i + j] = input[i + j] ^ ks[j];
}
const ct = isEncrypt ? out : input.subarray(0, ptLen);
const aadBuf = aad || new Uint8Array(0);
const aadPadLen = (16 - (aadBuf.length % 16)) % 16;
const ctPadLen = (16 - (ct.length % 16)) % 16;
const polyInput = new Uint8Array(aadBuf.length + aadPadLen + ct.length + ctPadLen + 16);
let off = 0;
polyInput.set(aadBuf, off); off += aadBuf.length + aadPadLen;
polyInput.set(ct, off); off += ct.length + ctPadLen;
let aadLenBig = BigInt(aadBuf.length);
for (let i = 0; i < 8; i++) { polyInput[off + i] = Number(aadLenBig & 0xffn); aadLenBig >>= 8n; }
let ctLenBig = BigInt(ct.length);
for (let i = 0; i < 8; i++) { polyInput[off + 8 + i] = Number(ctLenBig & 0xffn); ctLenBig >>= 8n; }
const tag = poly1305(polyKey, polyInput);
if (isEncrypt) {
  const res = new Uint8Array(ptLen + 16);
  res.set(out, 0);
  res.set(tag, ptLen);
  return res;
} else {
  const expectedTag = input.subarray(ptLen);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= (tag[i] ^ expectedTag[i]);
  if (diff !== 0) return null;
  return out;
}")))

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
   (def ^{:doc "Pure ClojureScript AES-256-GCM AEAD (NIST SP 800-38D)."}
     pure-aes-gcm
     (js/Function. "key" "nonce" "input" "aad" "isEncrypt"
                   "const sbox = new Uint8Array(256);
{
  let p = 1, q = 1;
  do {
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x11b : 0);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q ^= q & 0x80 ? 0x09 : 0;
    q &= 0xff;
    const xformed = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4) ^ 0x63;
    sbox[p] = xformed & 0xff;
  } while (p !== 1);
  sbox[0] = 0x63;
}
const Rcon = [0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
function expandKey(k) {
  const w = new Uint32Array(60);
  for (let i = 0; i < 8; i++) w[i] = (k[4*i] << 24) | (k[4*i+1] << 16) | (k[4*i+2] << 8) | k[4*i+3];
  for (let i = 8; i < 60; i++) {
    let temp = w[i - 1];
    if (i % 8 === 0) {
      temp = (sbox[(temp >>> 16) & 0xff] << 24) |
             (sbox[(temp >>> 8) & 0xff] << 16) |
             (sbox[temp & 0xff] << 8) |
             sbox[(temp >>> 24) & 0xff];
      temp ^= Rcon[i / 8] << 24;
    } else if (i % 8 === 4) {
      temp = (sbox[(temp >>> 24) & 0xff] << 24) |
             (sbox[(temp >>> 16) & 0xff] << 16) |
             (sbox[(temp >>> 8) & 0xff] << 8) |
             sbox[temp & 0xff];
    }
    w[i] = (w[i - 8] ^ temp) >>> 0;
  }
  return w;
}
function subBytes(s) { for (let i = 0; i < 16; i++) s[i] = sbox[s[i]]; }
function shiftRows(s) {
  let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
  t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
  t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}
const xtime = (x) => ((x << 1) ^ (((x >> 7) & 1) * 0x11b)) & 0xff;
function mixColumns(s) {
  for (let i = 0; i < 4; i++) {
    const i4 = i * 4;
    const a = s[i4], b = s[i4+1], c = s[i4+2], d = s[i4+3];
    const t = a ^ b ^ c ^ d;
    s[i4]   ^= t ^ xtime(a ^ b);
    s[i4+1] ^= t ^ xtime(b ^ c);
    s[i4+2] ^= t ^ xtime(c ^ d);
    s[i4+3] ^= t ^ xtime(d ^ a);
  }
}
function addRoundKey(s, w, round) {
  for (let i = 0; i < 4; i++) {
    const word = w[round * 4 + i];
    s[i * 4]     ^= (word >>> 24) & 0xff;
    s[i * 4 + 1] ^= (word >>> 16) & 0xff;
    s[i * 4 + 2] ^= (word >>> 8)  & 0xff;
    s[i * 4 + 3] ^= word & 0xff;
  }
}
function cipherBlock(inp, w) {
  const s = new Uint8Array(inp);
  addRoundKey(s, w, 0);
  for (let round = 1; round < 14; round++) {
    subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, w, round);
  }
  subBytes(s); shiftRows(s); addRoundKey(s, w, 14);
  return s;
}
function ghashMul(X, Y) {
  let z0 = 0n, z1 = 0n;
  let v0 = (BigInt(Y[0]) << 56n) | (BigInt(Y[1]) << 48n) | (BigInt(Y[2]) << 40n) | (BigInt(Y[3]) << 32n) |
           (BigInt(Y[4]) << 24n) | (BigInt(Y[5]) << 16n) | (BigInt(Y[6]) << 8n)  | BigInt(Y[7]);
  let v1 = (BigInt(Y[8]) << 56n) | (BigInt(Y[9]) << 48n) | (BigInt(Y[10]) << 40n) | (BigInt(Y[11]) << 32n) |
           (BigInt(Y[12]) << 24n) | (BigInt(Y[13]) << 16n) | (BigInt(Y[14]) << 8n) | BigInt(Y[15]);
  const R = 0xe100000000000000n;
  for (let i = 0; i < 16; i++) {
    const byte = X[i];
    for (let j = 7; j >= 0; j--) {
      if ((byte >> j) & 1) { z0 ^= v0; z1 ^= v1; }
      const lsb = v1 & 1n;
      v1 = (v1 >> 1n) | ((v0 & 1n) << 63n);
      v0 = v0 >> 1n;
      if (lsb) v0 ^= R;
    }
  }
  const out = new Uint8Array(16);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(z0 & 0xffn); z0 >>= 8n;
    out[8 + i] = Number(z1 & 0xffn); z1 >>= 8n;
  }
  return out;
}
const w = expandKey(key);
const H = cipherBlock(new Uint8Array(16), w);
const J0 = new Uint8Array(16);
J0.set(nonce, 0); J0[15] = 1;
const inLen = input ? input.length : 0;
const ptLen = isEncrypt ? inLen : (inLen - 16);
if (ptLen < 0) return null;
const out = new Uint8Array(ptLen);
const cb = new Uint8Array(J0);
function inc32(blk) {
  let val = (blk[12] << 24) | (blk[13] << 16) | (blk[14] << 8) | blk[15];
  val = (val + 1) >>> 0;
  blk[12] = (val >>> 24) & 0xff; blk[13] = (val >>> 16) & 0xff;
  blk[14] = (val >>> 8) & 0xff; blk[15] = val & 0xff;
}
for (let i = 0; i < ptLen; i += 16) {
  inc32(cb);
  const ks = cipherBlock(cb, w);
  const chunkLen = Math.min(16, ptLen - i);
  for (let j = 0; j < chunkLen; j++) out[i + j] = input[i + j] ^ ks[j];
}
const ct = isEncrypt ? out : input.subarray(0, ptLen);
let S = new Uint8Array(16);
function updateGhash(data) {
  const len = data.length;
  for (let i = 0; i < len; i += 16) {
    const block = new Uint8Array(16);
    const chunkLen = Math.min(16, len - i);
    block.set(data.subarray(i, i + chunkLen), 0);
    for (let j = 0; j < 16; j++) S[j] ^= block[j];
    S = ghashMul(S, H);
  }
}
if (aad && aad.length > 0) updateGhash(aad);
if (ct.length > 0) updateGhash(ct);
const lenBlock = new Uint8Array(16);
let aadBits = BigInt(aad ? aad.length * 8 : 0);
let ctBits = BigInt(ct.length * 8);
for (let i = 7; i >= 0; i--) {
  lenBlock[i] = Number(aadBits & 0xffn); aadBits >>= 8n;
  lenBlock[8 + i] = Number(ctBits & 0xffn); ctBits >>= 8n;
}
for (let j = 0; j < 16; j++) S[j] ^= lenBlock[j];
S = ghashMul(S, H);
const tagMask = cipherBlock(J0, w);
const tag = new Uint8Array(16);
for (let i = 0; i < 16; i++) tag[i] = S[i] ^ tagMask[i];
if (isEncrypt) {
  const res = new Uint8Array(ptLen + 16);
  res.set(out, 0); res.set(tag, ptLen);
  return res;
} else {
  const expectedTag = input.subarray(ptLen);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= (tag[i] ^ expectedTag[i]);
  if (diff !== 0) return null;
  return out;
}")))

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
             (let [kp (.generateKeyPairSync node-crypto "x25519"
                                            #js {:publicKeyEncoding #js {:type "spki" :format "der"}
                                                 :privateKeyEncoding #js {:type "pkcs8" :format "der"}})
                   pub (js/Uint8Array. (.-publicKey kp))
                   priv (js/Uint8Array. (.-privateKey kp))]
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
                   priv-key (.createPrivateKey node-crypto #js {:key (js/Buffer.from p-bytes) :format "der" :type "pkcs8"})
                   pub-key (.createPublicKey node-crypto #js {:key (js/Buffer.from u-bytes) :format "der" :type "spki"})]
               (js/Uint8Array. (.diffieHellman node-crypto #js {:privateKey priv-key :publicKey pub-key})))
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
