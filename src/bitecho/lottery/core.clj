(ns bitecho.lottery.core
  "Core logic for Phase 2: The Echo Economy (Lottery)
   Generates and validates cryptographic lottery tickets."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto])
  (:import [java.math BigInteger]))

(defn- hash-ticket
  "Computes a hash of the ticket contents.
   The ticket map must contain :payload-hash, :nonce, :public-key, and :signature."
  [ticket]
  (let [hash-hex (:payload-hash ticket)
        nonce-str (str (:nonce ticket))
        pub-key-hex (:public-key ticket)
        sig-hex (:signature ticket)
        input-str (str hash-hex nonce-str pub-key-hex sig-hex)]
    (crypto/sha256 (.getBytes input-str "UTF-8"))))

(defn- verify-ticket-signature?
  "Verifies that the ticket signature is valid for the given payload hash and nonce.
   Returns false if any hex strings are invalid."
  [ticket]
  (try
    (let [pub-key (basalt/hex->bytes ^String (:public-key ticket))
          sig (basalt/hex->bytes ^String (:signature ticket))
          payload-hash-bytes (basalt/hex->bytes ^String (:payload-hash ticket))
          nonce-bytes (.getBytes (str (:nonce ticket)) "UTF-8")
          ;; To sign, we concatenate the payload-hash and nonce bytes
          message (byte-array (+ (alength ^bytes payload-hash-bytes) (alength ^bytes nonce-bytes)))]
      (System/arraycopy payload-hash-bytes 0 message 0 (alength ^bytes payload-hash-bytes))
      (System/arraycopy nonce-bytes 0 message (alength ^bytes payload-hash-bytes) (alength ^bytes nonce-bytes))
      (crypto/verify pub-key message sig))
    (catch Exception _
      false)))

(defn generate-ticket
  "Generates a cryptographic lottery ticket.
   Takes a byte array payload, a long nonce, and the private/public keys."
  [^bytes payload nonce ^bytes private-key ^bytes public-key]
  (let [payload-hash (crypto/sha256 payload)
        nonce-bytes (.getBytes (str nonce) "UTF-8")
        ;; The message to sign is the concatenation of the payload-hash and nonce
        message (byte-array (+ (alength ^bytes payload-hash) (alength ^bytes nonce-bytes)))]
    (System/arraycopy payload-hash 0 message 0 (alength ^bytes payload-hash))
    (System/arraycopy nonce-bytes 0 message (alength ^bytes payload-hash) (alength ^bytes nonce-bytes))
    {:payload-hash (basalt/bytes->hex payload-hash)
     :nonce nonce
     :public-key (basalt/bytes->hex public-key)
     :signature (basalt/bytes->hex (crypto/sign private-key message))}))

(defn- hex->bigint
  "Converts a hex string to a BigInteger."
  [^String hex-str]
  (BigInteger. hex-str 16))

(defn winning-ticket?
  "Evaluates if a ticket is a winning ticket given a target difficulty hex string.
   A ticket is a winner if its signature is valid and its hash is numerically less than the difficulty."
  [ticket ^String difficulty-hex]
  (if (verify-ticket-signature? ticket)
    (let [ticket-hash (hash-ticket ticket)
          ticket-hash-hex (basalt/bytes->hex ticket-hash)
          ticket-val (hex->bigint ticket-hash-hex)
          difficulty-val (hex->bigint difficulty-hex)]
      (< (.compareTo ticket-val difficulty-val) 0))
    false))
