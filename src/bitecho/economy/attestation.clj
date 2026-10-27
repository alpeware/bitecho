(ns bitecho.economy.attestation
  "Bilateral epoch transcript attestations and deterministic node weight calculation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(def max-stake-multiplier
  "Maximum multiplier allowed for stake weighting (4.0x)."
  4.0)

(def default-min-stake
  "Default minimum baseline stake (S_min) for weight calculation."
  1000)

(defrecord EpochTranscript [epoch peer-a peer-b message-roles digest sig-a sig-b])

(defn- to-hex
  "Normalizes a public key or digest representation to a hex string."
  [x]
  (cond
    (string? x) x
    (bytes? x) (basalt/bytes->hex x)
    (sequential? x) (basalt/bytes->hex (byte-array (map byte x)))
    :else (str x)))

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

(defn- canonicalize-message-roles
  "Sorts message-role entries deterministically."
  [message-roles]
  (vec (sort-by pr-str (or message-roles []))))

(defn compute-exchange-digest
  "Computes a deterministic SHA-256 hex digest over a bilateral exchange transcript:
   (epoch, peer-a, peer-b, sorted-message-roles).
   Bilateral symmetry is enforced by sorting peer public keys canonically."
  [epoch peer-a peer-b message-roles]
  (let [[p1 p2] (sort [(to-hex peer-a) (to-hex peer-b)])
        canonical-map (into (sorted-map)
                            {:epoch (int epoch)
                             :peer-a p1
                             :peer-b p2
                             :roles (canonicalize-message-roles message-roles)})
        payload-bytes (.getBytes (pr-str canonical-map) "UTF-8")]
    (basalt/bytes->hex (crypto/sha256 payload-bytes))))

(defn create-transcript
  "Creates an EpochTranscript.
   Supports:
     (create-transcript {:epoch ... :peer-a ... :peer-b ... :roles ... :priv-a ... :priv-b ...})
     (create-transcript epoch peer-a peer-b message-roles priv-a)
     (create-transcript epoch peer-a peer-b message-roles [priv-a priv-b])
   Returns an EpochTranscript record with computed digest and signature(s)."
  ([params]
   (create-transcript (:epoch params)
                      (:peer-a params)
                      (:peer-b params)
                      (or (:message-roles params) (:roles params))
                      (if (contains? params :priv-b)
                        [(:priv-a params) (:priv-b params)]
                        (:priv-a params))))
  ([epoch peer-a peer-b message-roles priv-spec]
   (let [p-a (to-hex peer-a)
         p-b (to-hex peer-b)
         roles (canonicalize-message-roles message-roles)
         digest (compute-exchange-digest epoch p-a p-b roles)
         digest-bytes (.getBytes ^String digest "UTF-8")
         [priv-a priv-b] (cond
                           (sequential? priv-spec) [(first priv-spec) (second priv-spec)]
                           (map? priv-spec) [(:priv-a priv-spec) (:priv-b priv-spec)]
                           :else [priv-spec nil])
         sig-a (when priv-a (vec (crypto/sign (to-bytes priv-a) digest-bytes)))
         sig-b (when priv-b (vec (crypto/sign (to-bytes priv-b) digest-bytes)))]
     (map->EpochTranscript {:epoch epoch
                            :peer-a p-a
                            :peer-b p-b
                            :message-roles roles
                            :digest digest
                            :sig-a sig-a
                            :sig-b sig-b}))))

(defn cosign-transcript
  "Appends peer B's signature to a transcript, returning an updated EpochTranscript."
  [transcript priv-b]
  (let [digest-bytes (.getBytes ^String (:digest transcript) "UTF-8")
        sig-b (vec (crypto/sign (to-bytes priv-b) digest-bytes))]
    (assoc transcript :sig-b sig-b)))

(defn verify-transcript
  "Verifies that the transcript's digest matches the canonical exchange data,
   sig-a is valid for peer-a, and sig-b (if present) is valid for peer-b."
  [transcript]
  (try
    (if (and (map? transcript)
             (some? (:epoch transcript))
             (some? (:peer-a transcript))
             (some? (:peer-b transcript))
             (some? (:digest transcript))
             (some? (:sig-a transcript)))
      (let [expected-digest (compute-exchange-digest (:epoch transcript)
                                                     (:peer-a transcript)
                                                     (:peer-b transcript)
                                                     (:message-roles transcript))]
        (if (= expected-digest (:digest transcript))
          (let [digest-bytes (.getBytes ^String (:digest transcript) "UTF-8")
                valid-a? (crypto/verify (to-bytes (:peer-a transcript))
                                        digest-bytes
                                        (to-bytes (:sig-a transcript)))
                valid-b? (if-let [sig-b (:sig-b transcript)]
                           (crypto/verify (to-bytes (:peer-b transcript))
                                          digest-bytes
                                          (to-bytes sig-b))
                           true)]
            (boolean (and valid-a? valid-b?)))
          false))
      false)
    (catch Exception _
      false)))

(defn mutually-signed?
  "Returns true if both peer signatures are present and valid."
  [transcript]
  (boolean (and (some? (:sig-a transcript))
                (some? (:sig-b transcript))
                (verify-transcript transcript))))

(defn half-signed?
  "Returns true if only peer A's signature is present and valid."
  [transcript]
  (boolean (and (some? (:sig-a transcript))
                (nil? (:sig-b transcript))
                (verify-transcript transcript))))

(defn calculate-node-weight
  "Calculates node weight using the formula:
     w_i = participation_i * min(4.0, stake_i / S_min)
   Handles boundary conditions (s-min <= 0, zero or negative participation/stake) safely."
  ([participation stake]
   (calculate-node-weight participation stake default-min-stake))
  ([participation stake s-min]
   (if (or (nil? s-min) (not (number? s-min)) (<= s-min 0)
           (nil? participation) (not (number? participation)) (<= participation 0)
           (nil? stake) (not (number? stake)) (<= stake 0))
     0.0
     (let [stake-ratio (/ (double stake) (double s-min))
           multiplier (min max-stake-multiplier (max 0.0 stake-ratio))]
       (* (double participation) multiplier)))))
