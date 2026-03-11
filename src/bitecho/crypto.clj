(ns bitecho.crypto
  "Cryptographic primitives for Bitecho phase 1:
   SHA-256 hashing and Ed25519 signing/verification."
  (:import [java.security MessageDigest KeyPairGenerator KeyFactory Signature]
           [java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec]))

(defn sha256
  "Computes the SHA-256 hash of the given byte array.
   Returns a 32-byte array."
  ^bytes [^bytes input]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md input)))

(defn generate-keypair
  "Generates an Ed25519 keypair.
   Returns a map with :public and :private keys as encoded byte arrays."
  []
  (let [kpg (KeyPairGenerator/getInstance "Ed25519")
        kp (.generateKeyPair kpg)]
    {:public (.getEncoded (.getPublic kp))
     :private (.getEncoded (.getPrivate kp))}))

(defn sign
  "Signs a message byte array using an Ed25519 private key byte array.
   Returns the signature as a byte array."
  ^bytes [^bytes private-key ^bytes message]
  (let [kf (KeyFactory/getInstance "Ed25519")
        ks (PKCS8EncodedKeySpec. private-key)
        priv (.generatePrivate kf ks)
        sig (Signature/getInstance "Ed25519")]
    (.initSign sig priv)
    (.update sig message)
    (.sign sig)))

(defn verify
  "Verifies an Ed25519 signature of a message using a public key byte array.
   Returns true if valid, false otherwise."
  [^bytes public-key ^bytes message ^bytes signature]
  (try
    (let [kf (KeyFactory/getInstance "Ed25519")
          ks (X509EncodedKeySpec. public-key)
          pub (.generatePublic kf ks)
          sig (Signature/getInstance "Ed25519")]
      (.initVerify sig pub)
      (.update sig message)
      (.verify sig signature))
    (catch Exception _
      false)))
