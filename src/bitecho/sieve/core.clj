(ns bitecho.sieve.core
  "Core logic for Sieve consistent broadcast validation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn- to-bytes
  "Normalizes a byte array, vector of numbers, or hex string into a byte-array."
  [x]
  (cond
    (bytes? x) x
    (sequential? x) (byte-array (map byte x))
    (string? x) (if (re-matches #"^[0-9a-fA-F]+$" x)
                  (basalt/hex->bytes x)
                  (.getBytes ^String x "UTF-8"))
    :else (byte-array 0)))

(defn wrap-message
  "Wraps a payload with an Ed25519 signature and the sender's public key hex.
   Returns a map with :payload, :sender, and :signature."
  [^bytes payload ^bytes private-key ^bytes public-key]
  (let [signature (crypto/sign private-key payload)]
    {:payload payload
     :sender (basalt/bytes->hex public-key)
     :signature signature}))

(defn validate-message
  "Validates a signed message.
   Takes a message containing :payload, :sender (hex), and :signature.
   Returns the message if the signature is valid, nil otherwise."
  [message]
  (try
    (let [payload (:payload message)
          sender-pub-key (basalt/hex->bytes ^String (:sender message))
          signature (:signature message)]
      (if (crypto/verify sender-pub-key payload signature)
        message
        nil))
    (catch Exception _
      nil)))

(defn sign-control-frame
  "Signs a canonical control payload for frame-type and message-id.
   Returns a map containing :sender (hex), :message-id, :frame-type, and :signature."
  [frame-type message-id private-key public-key]
  (let [payload (.getBytes (pr-str {:type frame-type :message-id message-id}) "UTF-8")
        priv-bytes (to-bytes private-key)
        pub-hex (if (string? public-key) public-key (basalt/bytes->hex public-key))
        sig (crypto/sign priv-bytes payload)]
    {:sender pub-hex
     :message-id message-id
     :frame-type frame-type
     :signature (basalt/bytes->hex sig)}))

(defn validate-control-frame
  "Validates the sender's Ed25519 signature on an incoming control frame event against expected-type.
   If :signature is present, it MUST be cryptographically valid for (:sender event).
   If require-signed? is true, missing signatures are rejected."
  ([event expected-type]
   (validate-control-frame event expected-type false))
  ([event expected-type require-signed?]
   (try
     (let [sender (:sender event)
           sig (:signature event)
           mid (:message-id event)
           payload (:payload event)]
       (cond
         (some? sig)
         (and (some? sender)
              (or (some? mid) (some? payload))
              (let [sender-bytes (to-bytes sender)
                    sig-bytes (to-bytes sig)
                    payload-bytes (if payload
                                    (to-bytes payload)
                                    (.getBytes (pr-str {:type expected-type :message-id mid}) "UTF-8"))]
                (boolean (crypto/verify sender-bytes payload-bytes sig-bytes))))

         require-signed?
         false

         :else
         true))
     (catch Exception _
       false))))

