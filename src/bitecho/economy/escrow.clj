(ns bitecho.economy.escrow
  "Pure Sans-IO Escrow & Hash-Lock Settlement Primitives for Bitecho.
   Enforces single-currency ($ECHO) verified-outcome escrow lifecycle:
   :lock-intent -> :release-intent (preimage or payer signature) or :refund-intent (timeout).
   Guarantees mandatory tau = 0.5% protocol settlement take burned on verified release."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.burn :as burn]
            [clojure.string :as str])
  (:import (java.nio.charset StandardCharsets)))

(defn valid-deliverable-hash?
  "Returns true if s is a valid 64-character hex string representing a SHA-256 commitment."
  [s]
  (boolean
   (and (string? s)
        (re-matches #"(?i)[0-9a-f]{64}" (str/trim s)))))

(defn normalize-hex
  "Trims and lower-cases a hex string."
  [s]
  (cond
    (string? s) (str/lower-case (str/trim s))
    (bytes? s) (str/lower-case (basalt/bytes->hex s))
    :else nil))

(defn normalize-party
  "Normalizes a public key party identifier (string hex or byte array) to lower-case hex string."
  [p]
  (cond
    (string? p) (str/lower-case (str/trim p))
    (bytes? p) (str/lower-case (basalt/bytes->hex p))
    :else nil))

(defn canonical-escrow-id-str
  "Formats canonical string for escrow identification."
  [payer receiver amount deliverable-hash created-epoch expires-epoch nonce]
  (str "bitecho-escrow-v1|"
       (normalize-party payer) "|"
       (normalize-party receiver) "|"
       (long (if (integer? amount) amount (or amount 0))) "|"
       (normalize-hex deliverable-hash) "|"
       (long (if (integer? created-epoch) created-epoch (or created-epoch 0))) "|"
       (long (if (integer? expires-epoch) expires-epoch (or expires-epoch 0))) "|"
       (or nonce "0")))

(defn compute-escrow-id
  "Computes deterministic 64-character SHA-256 hex escrow-id from escrow parameters."
  ([m]
   (compute-escrow-id (or (:payer m) (get m "payer"))
                      (or (:receiver m) (get m "receiver") (:recipient m) (get m "recipient"))
                      (or (:amount m) (get m "amount"))
                      (or (:deliverable-hash m) (get m "deliverable_hash") (get m "deliverable-hash"))
                      (or (:created-epoch m) (get m "created_epoch") (get m "created-epoch") 0)
                      (or (:expires-epoch m) (get m "expires_epoch") (get m "expires-epoch"))
                      (or (:nonce m) (get m "nonce") "0")))
  ([payer receiver amount deliverable-hash created-epoch expires-epoch nonce]
   (let [s (canonical-escrow-id-str payer receiver amount deliverable-hash created-epoch expires-epoch nonce)
         b (.getBytes ^String s StandardCharsets/UTF_8)]
     (basalt/bytes->hex (crypto/sha256 b)))))

(defn canonical-escrow-release-str
  "Formats canonical outcome attestation string for payer Ed25519 release signature."
  [escrow-id deliverable-hash]
  (str "bitecho-escrow-release-v1|"
       (normalize-hex escrow-id) "|"
       (normalize-hex deliverable-hash)))

(defn sign-escrow-release
  "Signs canonical outcome release string using payer's private key bytes. Returns hex string."
  [^bytes privkey-bytes escrow-id deliverable-hash]
  (let [s (canonical-escrow-release-str escrow-id deliverable-hash)
        b (.getBytes ^String s StandardCharsets/UTF_8)
        sig (crypto/sign privkey-bytes b)]
    (if (string? sig) sig (basalt/bytes->hex sig))))

(defn verify-escrow-release-sig
  "Verifies payer's Ed25519 signature over canonical outcome release string."
  [payer-pubkey escrow-id deliverable-hash sig-bytes-or-hex]
  (try
    (let [pub-bytes (cond
                      (bytes? payer-pubkey) payer-pubkey
                      (string? payer-pubkey) (basalt/hex->bytes payer-pubkey)
                      :else nil)
          sig-bytes (cond
                      (bytes? sig-bytes-or-hex) sig-bytes-or-hex
                      (string? sig-bytes-or-hex) (basalt/hex->bytes sig-bytes-or-hex)
                      :else nil)
          s (canonical-escrow-release-str escrow-id deliverable-hash)
          msg-bytes (.getBytes ^String s StandardCharsets/UTF_8)]
      (boolean
       (and pub-bytes sig-bytes
            (crypto/verify pub-bytes msg-bytes sig-bytes))))
    (catch Exception _ false)))

(defn verify-deliverable-preimage
  "Verifies whether SHA-256(preimage) equals deliverable-hash."
  [preimage deliverable-hash]
  (try
    (and (string? preimage)
         (valid-deliverable-hash? deliverable-hash)
         (let [b (.getBytes ^String preimage StandardCharsets/UTF_8)
               h (basalt/bytes->hex (crypto/sha256 b))]
           (= (normalize-hex h) (normalize-hex deliverable-hash))))
    (catch Exception _ false)))

(defn calculate-escrow-settlement-take
  "Computes mandatory tau = 0.5% protocol settlement take via (burn/calculate-settlement-take amount take-bps)
   with take-bps = (max 1 configured-bps) and minimum 1 unit burned for positive amounts."
  ([amount]
   (calculate-escrow-settlement-take amount burn/default-settlement-take-bps))
  ([amount configured-bps]
   (let [amt (long (or amount 0))
         take-bps (max 1 (long (or configured-bps burn/default-settlement-take-bps)))
         calc-take (burn/calculate-settlement-take amt take-bps)]
     (if (pos? amt)
       (max 1 calc-take)
       0))))
