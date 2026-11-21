(ns bitecho.shell.memento-crypto
  "JVM Crypto Shell Adapter for Memento Agent Continuity (BIP-A + BIP-C).
   Isolates key material handling and cryptographic operations at the shell boundary (Rule 2):
   - Ed25519 signing/verification under domain tag \"bitecho/rolodex/v1\"
   - RFC 8032 Ed25519 genesis signature over \"bitecho/memento/genesis/v1\" || raw32(pubkey)
   - HKDF-SHA-256 key & nonce derivation over Ed25519 32-byte seed
   - AES-256-GCM sealing/opening with canonical AAD and framing."
  (:require [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.memento.constants :as mc]
            [bitecho.memento.memory-chain :as memory-chain]
            [bitecho.memento.rolodex :as rolodex]))

;; =============================================================================
;; Key Extraction Helpers (SPKI 44B / PKCS#8 48B -> Raw 32B)
;; =============================================================================

(defn extract-ed25519-seed32
  "Extracts the raw 32-byte Ed25519 seed from a 48-byte PKCS#8 DER private key
   (or returns a 32-byte raw seed directly)."
  ^bytes [priv-bytes]
  (let [bs (if (string? priv-bytes) (fressian/hex->bytes priv-bytes) priv-bytes)
        n (fressian/count-bytes bs)]
    (cond
      (= n 32) bs
      (= n 48) (mc/slice-bytes bs 16 32)
      :else (throw (ex-info "Unsupported Ed25519 private key length" {:length n})))))

(defn extract-ed25519-pub32
  "Extracts the raw 32-byte Ed25519 public key from a 44-byte X.509 SPKI DER public key
   (or returns a 32-byte raw public key directly)."
  ^bytes [pub-bytes]
  (let [bs (if (string? pub-bytes) (fressian/hex->bytes pub-bytes) pub-bytes)
        n (fressian/count-bytes bs)]
    (cond
      (= n 32) bs
      (= n 44) (mc/slice-bytes bs 12 32)
      :else (throw (ex-info "Unsupported Ed25519 public key length" {:length n})))))

;; =============================================================================
;; BIP-A Rolodex Signing & Verification
;; =============================================================================

(defn sign-rolodex-entry
  "Signs a Rolodex entry under domain tag \"bitecho/rolodex/v1\", returning hex signature."
  [ed25519-priv entry]
  (let [msg (rolodex/entry-signing-bytes entry)]
    (fressian/bytes->hex (crypto/sign ed25519-priv msg))))

(defn verify-rolodex-entry
  "Verifies a Rolodex entry's Ed25519 signature under domain tag \"bitecho/rolodex/v1\"."
  [ed25519-pub entry sig-hex-or-bytes]
  (let [msg (rolodex/entry-signing-bytes entry)
        sig (if (string? sig-hex-or-bytes)
              (fressian/hex->bytes sig-hex-or-bytes)
              sig-hex-or-bytes)]
    (boolean (crypto/verify ed25519-pub msg sig))))

;; =============================================================================
;; BIP-C Genesis Signature & HKDF-SHA-256 + AES-256-GCM Memory Chain
;; =============================================================================

(defn sign-genesis-memory
  "Produces the 64-byte RFC 8032 Ed25519 signature over
   \"bitecho/memento/genesis/v1\" || raw32(pubkey)."
  ^bytes [ed25519-priv ed25519-pub]
  (let [pub32 (extract-ed25519-pub32 ed25519-pub)
        msg (memory-chain/genesis-message-bytes pub32)]
    (crypto/sign ed25519-priv msg)))

(defn verify-genesis-memory
  "Verifies the 64-byte RFC 8032 Ed25519 genesis signature over
   \"bitecho/memento/genesis/v1\" || raw32(pubkey)."
  [ed25519-pub sig-bytes]
  (let [pub32 (extract-ed25519-pub32 ed25519-pub)
        sig (if (string? sig-bytes) (fressian/hex->bytes sig-bytes) sig-bytes)
        msg (memory-chain/genesis-message-bytes pub32)]
    (boolean (and (= 64 (fressian/count-bytes sig))
                  (crypto/verify ed25519-pub msg sig)))))

(defn derive-aead-key
  "Derives 32-byte AES-256-GCM key via HKDF-SHA-256 over Ed25519 seed
   with info = \"bitecho/memento/aead/v1\"."
  ^bytes [ed25519-priv-or-seed]
  (let [seed32 (extract-ed25519-seed32 ed25519-priv-or-seed)]
    (sealed/hkdf-sha256 seed32 nil (memory-chain/aead-key-info) 32)))

(defn derive-nonce
  "Derives 12-byte AES-256-GCM nonce via HKDF-SHA-256 over Ed25519 seed
   with info = \"bitecho/memento/nonce/v1\" || be64(seq)."
  ^bytes [ed25519-priv-or-seed seq-num]
  (let [seed32 (extract-ed25519-seed32 ed25519-priv-or-seed)]
    (sealed/hkdf-sha256 seed32 nil (memory-chain/nonce-info seq-num) 12)))

(defn seal-memory-frame
  "Encrypts plaintext-bytes with AES-256-GCM using HKDF-derived key & nonce and canonical AAD,
   frames as be64(seq) || raw32(prev-cid) || be32(len) || ciphertext, and computes CID.
   Never returns key or seed bytes."
  [ed25519-priv seq-num prev-cid-hex plaintext-bytes]
  (let [k (derive-aead-key ed25519-priv)
        nonce (derive-nonce ed25519-priv seq-num)
        aad (memory-chain/aad-bytes seq-num prev-cid-hex)
        ct (sealed/aes-gcm-seal k nonce plaintext-bytes aad)
        frame (memory-chain/encode-frame seq-num prev-cid-hex ct)
        cid (memory-chain/frame-cid frame)]
    {:seq seq-num
     :prev-cid prev-cid-hex
     :cid cid
     :frame-bytes frame
     :ciphertext-len (fressian/count-bytes ct)}))

(defn open-memory-frame
  "Decodes canonical frame (enforcing 256 KiB pre-decode ceiling) and decrypts with AES-256-GCM.
   Returns {:ok? true :seq :prev-cid :cid :plaintext} or {:ok? false :code ...}."
  [ed25519-priv frame-bytes]
  (let [decoded (memory-chain/decode-frame frame-bytes)]
    (if-not (:ok? decoded)
      decoded
      (let [seq-num (:seq decoded)
            prev-cid (:prev-cid decoded)
            k (derive-aead-key ed25519-priv)
            nonce (derive-nonce ed25519-priv seq-num)
            aad (memory-chain/aad-bytes seq-num prev-cid)
            pt (sealed/aes-gcm-open k nonce (:ciphertext decoded) aad)]
        (if (nil? pt)
          {:ok? false :code :aead-tag-failure :cid (:cid decoded)}
          {:ok? true
           :seq seq-num
           :prev-cid prev-cid
           :cid (:cid decoded)
           :plaintext pt})))))
