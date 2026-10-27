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
        burn (or (:burn offer-ctx) 0)
        seq-num (:seq offer-ctx)
        last-seq (:last-seq offer-ctx)
        p-b (or (:price offer-ctx) (:p-b offer-ctx))
        expected-debit (when (and seq-num p-b) (* seq-num p-b))
        actual-debit (:cumulative-debit offer-ctx)
        debit (or expected-debit actual-debit)]
    (cond
      (and (seq allowlist) (not (contains? (set allowlist) caller)))
      {:status :error :delivery-ack nil :error :rejected-allowlist}

      (< burn min-burn)
      {:status :error :delivery-ack nil :error :insufficient-burn}

      (or (nil? seq-num) (< seq-num 1) (and last-seq (not= seq-num (inc last-seq))))
      {:status :error :delivery-ack nil :error :invalid-seq}

      (and p-b actual-debit (not= actual-debit expected-debit))
      {:status :error :delivery-ack nil :error :invalid-debit}

      :else
      (let [unsigned-ack (map->DeliveryAck
                          {:callee (:callee offer-ctx)
                           :home-node (:home-node offer-ctx)
                           :epoch (:epoch offer-ctx)
                           :offer-hash (:offer-hash offer-ctx)
                           :seq seq-num
                           :cumulative-debit debit
                           :signature nil})
            payload (ack-payload-bytes unsigned-ack)
            privkey (to-bytes (or (:callee-privkey offer-ctx) (:home-node-privkey offer-ctx)))
            sig (basalt/bytes->hex (crypto/sign privkey payload))
            signed-ack (assoc unsigned-ack :signature sig)]
        {:status :ok :delivery-ack signed-ack}))))

(defn verify-delivery-ack
  "Verifies the cryptographic signature of a DeliveryAck.
   Accepts [ack] (using (:callee ack) as public key) or [ack callee-pubkey]."
  ([ack]
   (verify-delivery-ack ack (:callee ack)))
  ([ack callee-pubkey]
   (try
     (let [pub-bytes (to-bytes (or callee-pubkey (:callee ack)))
           sig-bytes (to-bytes (:signature ack))
           payload-bytes (ack-payload-bytes ack)]
       (boolean (crypto/verify pub-bytes payload-bytes sig-bytes)))
     (catch Exception _
       false))))

(defn verify-ack-for-settlement
  "Verifies a DeliveryAck voucher for epoch boundary settlement.
   Validates replay protection, epoch matching, positive sequence number,
   debit consistency with registered price, and cryptographic signature.
   Returns {:valid? true :debit ... :tuple ...} or {:valid? false :error ...}."
  [ack settlement-ctx]
  (let [callee (:callee ack)
        home-node (:home-node ack)
        epoch (:epoch ack)
        seq-num (:seq ack)
        debit (:cumulative-debit ack)
        tuple [callee home-node epoch]
        settlement-epoch (or (:settlement-epoch settlement-ctx) (:current-epoch settlement-ctx))
        settled-tuples (or (:settled-tuples settlement-ctx) #{})
        reg-price (:registered-price settlement-ctx)]
    (cond
      (contains? settled-tuples tuple)
      {:valid? false :error :replayed-tuple}

      (and (some? settlement-epoch) (not= epoch settlement-epoch))
      {:valid? false :error :expired-epoch}

      (or (nil? seq-num) (<= seq-num 0))
      {:valid? false :error :invalid-debit}

      (or (nil? debit)
          (and reg-price (not= debit (* seq-num reg-price))))
      {:valid? false :error :invalid-debit}

      (not (verify-delivery-ack ack))
      {:valid? false :error :invalid-signature}

      :else
      {:valid? true
       :debit debit
       :tuple tuple})))
