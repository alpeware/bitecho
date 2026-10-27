(ns bitecho.rendezvous.core
  "Multi-homed Callee registration, home node selection, and DeliveryAck vouchers."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defrecord DeliveryAck [callee home-node epoch offer-hash seq cumulative-debit signature])

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

(defn- ack-payload-bytes
  "Extracts canonical payload bytes for DeliveryAck signature."
  [ack]
  (let [canonical-data [(:callee ack)
                        (:home-node ack)
                        (:epoch ack)
                        (:offer-hash ack)
                        (:seq ack)
                        (:cumulative-debit ack)]]
    (.getBytes (pr-str canonical-data) "UTF-8")))

(defn register-home-set
  "Registers a home set of nodes for Callee B.
   Validates uniform price p_B, stepping up to p_B_max when fewer than 3 nodes accept.
   Returns {:status :ok ...} if >= 3 nodes accept,
           {:status :degraded ...} if 1 <= m < 3 at p_B_max,
           {:status :rejected ...} if m = 0 at p_B_max."
  [candidates p-b p-b-max]
  (let [at-max (filterv #(<= (:price %) p-b-max) candidates)
        m (count at-max)]
    (cond
      (>= m 3)
      (let [sorted-candidates (sort-by :price at-max)
            p3 (:price (nth sorted-candidates 2))
            p (max p-b p3)
            accepting (filterv #(<= (:price %) p) candidates)]
        {:status :ok
         :home-nodes accepting
         :price p
         :degraded? false})

      (>= m 1)
      {:status :degraded
       :home-nodes at-max
       :price p-b-max
       :degraded? true}

      :else
      {:status :rejected
       :home-nodes []
       :price p-b-max
       :degraded? false})))

(defn select-home-node
  "Selects the lowest-latency responsive node from B's home set.
   Returns nil if home-set is empty or contains no responsive nodes."
  [home-set]
  (let [responsive (filterv :responsive? home-set)]
    (when (seq responsive)
      (apply min-key #(or (:latency %) (:latency-ms %) 0) responsive))))

(defn process-offer-header
  "Validates caller against Callee's allowlist and min-burn requirement.
   If valid, produces a signed DeliveryAck record bound to epoch."
  [offer-ctx]
  (let [caller (:caller offer-ctx)
        allowlist (:allowlist offer-ctx)
        min-burn (or (:min-burn offer-ctx) 0)
        burn (or (:burn offer-ctx) 0)]
    (cond
      (and (seq allowlist) (not (contains? (set allowlist) caller)))
      {:status :error :delivery-ack nil :error :rejected-allowlist}

      (< burn min-burn)
      {:status :error :delivery-ack nil :error :insufficient-burn}

      :else
      (let [unsigned-ack (map->DeliveryAck
                          {:callee (:callee offer-ctx)
                           :home-node (:home-node offer-ctx)
                           :epoch (:epoch offer-ctx)
                           :offer-hash (:offer-hash offer-ctx)
                           :seq (:seq offer-ctx)
                           :cumulative-debit (:cumulative-debit offer-ctx)
                           :signature nil})
            payload (ack-payload-bytes unsigned-ack)
            privkey (to-bytes (:home-node-privkey offer-ctx))
            sig (basalt/bytes->hex (crypto/sign privkey payload))
            signed-ack (assoc unsigned-ack :signature sig)]
        {:status :ok :delivery-ack signed-ack}))))

(defn verify-delivery-ack
  "Verifies the cryptographic signature of a DeliveryAck.
   Accepts [ack] (using (:home-node ack) as public key) or [ack home-pubkey]."
  ([ack]
   (verify-delivery-ack ack (:home-node ack)))
  ([ack home-pubkey]
   (try
     (let [pub-bytes (to-bytes (or home-pubkey (:home-node ack)))
           sig-bytes (to-bytes (:signature ack))
           payload-bytes (ack-payload-bytes ack)]
       (boolean (crypto/verify pub-bytes payload-bytes sig-bytes)))
     (catch Exception _
       false))))
