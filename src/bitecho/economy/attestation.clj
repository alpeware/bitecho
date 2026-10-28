(ns bitecho.economy.attestation
  "Bilateral epoch transcript attestations and deterministic node weight calculation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [clojure.set :as set]
            [clojure.string :as str]))

(def max-stake-multiplier
  "Maximum multiplier allowed for stake weighting (4.0x)."
  4.0)

(def default-min-stake
  "Default minimum baseline stake (S_min) for weight calculation (250,000 ECHO testnet floor)."
  250000)

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

(defn canonicalize-message-roles
  "Sorts message-role entries deterministically into a vector of [message-id role]."
  [message-roles]
  (cond
    (nil? message-roles) []
    (map? message-roles)
    (vec (sort-by (comp str first) (mapv (fn [[k v]] [(str k) v]) message-roles)))
    (coll? message-roles)
    (vec (sort-by (comp str first)
                  (mapv (fn [item]
                          (cond
                            (map? item) [(str (or (:message-id item) (:id item))) (:role item)]
                            (sequential? item) [(str (first item)) (second item)]
                            :else [(str item) :seen]))
                        message-roles)))
    :else []))

(def canonical-digest-format
  "Canonical format for exchange digest byte concatenation per v2.1 §4."
  "SHA-256(epoch_e || peer_a || peer_b || pr-str(sorted_vec_of_[message_id, role]))")

(defn compute-exchange-digest
  "Computes a deterministic SHA-256 hex digest over a bilateral exchange transcript
   using raw UTF-8 byte concatenation per v2.1 §4:
     SHA-256(epoch_e || peer_a || peer_b || pr-str(sorted_vec_of_[message_id, role]))
   Bilateral symmetry is enforced by sorting peer public keys lexicographically."
  [epoch peer-a peer-b message-roles]
  (let [[p1 p2] (sort [(to-hex peer-a) (to-hex peer-b)])
        roles-vec (canonicalize-message-roles message-roles)
        baos (java.io.ByteArrayOutputStream.)]
    (.write baos (.getBytes (str (int epoch)) "UTF-8"))
    (.write baos (.getBytes ^String p1 "UTF-8"))
    (.write baos (.getBytes ^String p2 "UTF-8"))
    (.write baos (.getBytes (pr-str roles-vec) "UTF-8"))
    (basalt/bytes->hex (crypto/sha256 (.toByteArray baos)))))

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
  "Calculates node weight using continuous linear scaling:
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

(defn reconcile-message-roles
  "Filters `roles` to only those whose message-id is present in the intersection
   of `frozen-ids-a` and `frozen-ids-b`. Returns a deterministically sorted vector of [message-id role]."
  [frozen-ids-a frozen-ids-b roles]
  (let [common-ids (set/intersection (set (or frozen-ids-a #{}))
                                     (set (or frozen-ids-b #{})))
        canonical (canonicalize-message-roles roles)]
    (filterv (fn [[mid _]] (contains? common-ids mid)) canonical)))

(defn verify-transcript-against-log
  "Verifies that a transcript is validly signed and that its digest matches
   the recomputed exchange digest derived from the frozen log message roles."
  [transcript frozen-log-roles]
  (try
    (if (verify-transcript transcript)
      (let [expected-digest (compute-exchange-digest (:epoch transcript)
                                                     (:peer-a transcript)
                                                     (:peer-b transcript)
                                                     frozen-log-roles)]
        (= expected-digest (:digest transcript)))
      false)
    (catch Exception _
      false)))

(defn evaluate-transcript-dispute
  "Evaluates a bilateral transcript against the local frozen log snapshot.
   - If transcript does not verify against frozen log -> {:status :rejected :credit #{} :strike nil}
   - If mutually-signed -> {:status :settled :credit #{peer-a peer-b} :strike nil}
   - If half-signed -> {:status :half-signed-fault :credit #{peer-a} :strike peer-b}"
  [transcript frozen-log-roles]
  (if (not (verify-transcript-against-log transcript frozen-log-roles))
    {:status :rejected :credit #{} :strike nil}
    (let [p-a (:peer-a transcript)
          p-b (:peer-b transcript)]
      (cond
        (mutually-signed? transcript)
        {:status :settled :credit #{p-a p-b} :strike nil}

        (half-signed? transcript)
        {:status :half-signed-fault :credit #{p-a} :strike p-b}

        :else
        {:status :rejected :credit #{} :strike nil}))))

(defn sign-frozen-log
  "Signs a counterparty frozen message log for an epoch using privkey.
   Canonical payload: (pr-str [epoch peer-hex sorted-ids]).
   Returns {:epoch epoch :peer peer-hex :frozen-ids sorted-ids :signature sig-hex}."
  [epoch peer-pubkey frozen-ids privkey]
  (let [peer-hex (to-hex peer-pubkey)
        sorted-ids (vec (sort (map str (or frozen-ids []))))
        payload (.getBytes (pr-str [epoch peer-hex sorted-ids]) "UTF-8")
        sig (crypto/sign (to-bytes privkey) payload)]
    {:epoch epoch
     :peer peer-hex
     :frozen-ids sorted-ids
     :signature (basalt/bytes->hex sig)}))

(defn verify-frozen-log
  "Verifies a cryptographically signed counterparty frozen log map.
   Validates map shape, integer epoch, non-blank peer and signature,
   and verifies that the signature matches the canonical payload under peer's public key."
  [signed-log]
  (try
    (if (and (map? signed-log)
             (integer? (:epoch signed-log))
             (or (sequential? (:frozen-ids signed-log))
                 (set? (:frozen-ids signed-log)))
             (string? (:peer signed-log))
             (not (str/blank? (:peer signed-log)))
             (string? (:signature signed-log))
             (not (str/blank? (:signature signed-log))))
      (let [peer-hex (to-hex (:peer signed-log))
            sorted-ids (vec (sort (map str (or (:frozen-ids signed-log) []))))
            payload (.getBytes (pr-str [(:epoch signed-log) peer-hex sorted-ids]) "UTF-8")
            pub-bytes (to-bytes peer-hex)
            sig-bytes (to-bytes (:signature signed-log))]
        (boolean (crypto/verify pub-bytes payload sig-bytes)))
      false)
    (catch Exception _
      false)))
