(ns bitecho.rendezvous.core
  "Multi-homed Callee registration, home node selection, and DeliveryAck vouchers.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]))

(defrecord ^{:doc "Delivery acknowledgment voucher record."} DeliveryAck [callee home-node epoch offer-hash seq cumulative-debit signature])

(defn normalize-home-node
  "Normalizes a home-node identifier to a string (converting keywords/symbols via name, or non-nil values via str)."
  [hn]
  (cond
    (nil? hn) nil
    (string? hn) hn
    (or (keyword? hn) (symbol? hn)) (name hn)
    :else (str hn)))

(defn- to-bytes
  "Normalizes a byte array, vector of numbers, or hex string into a byte-array."
  [x]
  (cond
    (fressian/bytes? x) x
    (sequential? x) #?(:clj (byte-array (map byte x)) :cljs (js/Uint8Array. (clj->js x)))
    (string? x) (if (re-matches #"^[0-9a-fA-F]+$" x)
                  (basalt/hex->bytes x)
                  (fressian/utf8->bytes x))
    :else #?(:clj (byte-array 0) :cljs (js/Uint8Array. 0))))

(defn ack-payload-data
  "Extracts canonical payload tuple for DeliveryAck signature."
  [ack]
  [(:callee ack)
   (:home-node ack)
   (:epoch ack)
   (:offer-hash ack)
   (:seq ack)
   (:cumulative-debit ack)])

(defn- ack-payload-bytes
  "Extracts canonical payload bytes for DeliveryAck signature."
  [ack]
  (crypto/canonical-signing-bytes (ack-payload-data ack)))

(defn register-home-set
  "Registers a home set of nodes for Callee B.
   Validates uniform price p_B, stepping up to p_B_max when fewer than 3 nodes accept.
   Returns {:status :ok ...} if >= 3 nodes accept,
           {:status :degraded ...} if 1 <= m < 3 at p_B_max,
           {:status :rejected ...} if m = 0 at p_B_max."
  [candidates p-b p-b-max]
  (let [candidates (mapv (fn [c]
                           (if (contains? c :node-id)
                             (assoc c :node-id (normalize-home-node (:node-id c)))
                             c))
                         candidates)
        at-max (filterv #(<= (:price %) p-b-max) candidates)
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
                           :home-node (normalize-home-node (:home-node offer-ctx))
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

(defn create-delivery-ack
  "Creates and signs a DeliveryAck record."
  [privkey callee home-node epoch offer-hash seq-num cumulative-debit]
  (let [unsigned-ack (map->DeliveryAck
                      {:callee callee
                       :home-node (normalize-home-node home-node)
                       :epoch epoch
                       :offer-hash offer-hash
                       :seq seq-num
                       :cumulative-debit cumulative-debit
                       :signature nil})
        data (ack-payload-data unsigned-ack)
        sig (basalt/bytes->hex (crypto/sign-canonical (to-bytes privkey) data))]
    (assoc unsigned-ack :signature sig)))

(defn verify-delivery-ack
  "Verifies the cryptographic signature of a DeliveryAck.
   Supports N/N-1 canonical Fressian with legacy pr-str fallback and shell-boundary pre-verification.
   Accepts [ack] (using (:callee ack) as public key) or [ack callee-pubkey]."
  ([ack]
   (verify-delivery-ack ack (:callee ack)))
  ([ack callee-pubkey]
   (try
     (let [pub-bytes (to-bytes (or callee-pubkey (:callee ack)))
           sig-bytes (to-bytes (:signature ack))
           verify-data (fn [data]
                         (try
                           (boolean (crypto/verify-with-fallback pub-bytes data sig-bytes))
                           (catch #?(:clj Exception :cljs :default) _ false)))]
       (boolean
        (or (verify-data (ack-payload-data ack))
            (when (and (:home-node ack) (or (string? (:home-node ack)) (keyword? (:home-node ack))))
              (let [norm (normalize-home-node (:home-node ack))
                    kw (keyword norm)]
                (or (verify-data (ack-payload-data (assoc ack :home-node kw)))
                    (verify-data (ack-payload-data (assoc ack :home-node norm)))))))))
     (catch #?(:clj Exception :cljs :default) _
       false))))

(defn verify-ack-for-settlement
  "Verifies a DeliveryAck voucher for epoch boundary settlement.
   Validates replay protection, epoch matching, positive sequence number,
   debit consistency with registered price, and cryptographic signature.
   Returns {:valid? true :debit ... :tuple ...} or {:valid? false :error ...}."
  [ack settlement-ctx]
  (let [callee (:callee ack)
        raw-home-node (:home-node ack)
        home-node (normalize-home-node raw-home-node)
        epoch (:epoch ack)
        seq-num (:seq ack)
        debit (:cumulative-debit ack)
        tuple [callee home-node epoch]
        raw-tuple [callee raw-home-node epoch]
        settlement-epoch (or (:settlement-epoch settlement-ctx) (:current-epoch settlement-ctx))
        settled-tuples (or (:settled-tuples settlement-ctx) #{})
        reg-price (:registered-price settlement-ctx)]
    (cond
      (or (contains? settled-tuples tuple)
          (contains? settled-tuples raw-tuple))
      {:valid? false :error :replayed-tuple}

      (if (some? (:min-settlement-epoch settlement-ctx))
        (or (nil? epoch)
            (< epoch (:min-settlement-epoch settlement-ctx))
            (and (some? settlement-epoch) (> epoch settlement-epoch)))
        (and (some? settlement-epoch) (not= epoch settlement-epoch)))
      {:valid? false :error :expired-epoch}

      (or (nil? seq-num) (<= seq-num 0))
      {:valid? false :error :invalid-debit}

      (or (nil? debit)
          (nil? reg-price)
          (not (integer? reg-price))
          (neg? (long reg-price))
          (not= debit (* (long seq-num) (long reg-price))))
      {:valid? false :error :invalid-debit}

      (not (verify-delivery-ack ack))
      {:valid? false :error :invalid-signature}

      :else
      {:valid? true
       :debit debit
       :tuple tuple})))

;; -----------------------------------------------------------------------------
;; Rendezvous Subnet Advertisement (Step 12A)
;; -----------------------------------------------------------------------------

(defn subnet-advertisement-payload
  "Extracts canonical tuple for subnet advertisement signing."
  [ad]
  ["bitecho-subnet-ad-v1"
   (str (:subnet-id ad))
   (str (:topic ad))
   (boolean (:economy-enabled? ad))
   (long (:burn-floor ad))
   (vec (sort (map str (:crypto-suites ad))))
   (str (:wire-format ad))
   (str (:coordinator-pubkey ad))])

(defn build-subnet-advertisement
  "Constructs and signs an authority rendezvous advertisement for a subnet."
  [coordinator-pubkey coordinator-privkey opts]
  (let [coord-pub (if (string? coordinator-pubkey)
                    coordinator-pubkey
                    (basalt/bytes->hex coordinator-pubkey))
        sub-id (str (or (:subnet-id opts) "global"))
        topic (str (or (:topic opts) (str "subnet/" sub-id)))
        econ? (boolean (get opts :economy-enabled? true))
        burn-fl (long (or (:burn-floor opts) (if econ? 100 0)))
        suites (vec (or (:crypto-suites opts) ["suite-v1-aes256gcm"]))
        wire-fmt (str (or (:wire-format opts) "fressian-v1"))
        base-ad {:subnet-id sub-id
                 :topic topic
                 :economy-enabled? econ?
                 :burn-floor burn-fl
                 :crypto-suites suites
                 :wire-format wire-fmt
                 :coordinator-pubkey coord-pub}
        payload (subnet-advertisement-payload base-ad)
        sig (crypto/sign-canonical coordinator-privkey payload)
        sig-hex (if (string? sig) sig (basalt/bytes->hex sig))]
    (assoc base-ad :signature sig-hex)))

(defn parse-subnet-advertisement
  "Validates structure and signature of a rendezvous subnet advertisement map."
  [ad-map & [_opts]]
  (if-not (map? ad-map)
    {:ok? false :error "invalid-advertisement-map"}
    (let [sub-id (:subnet-id ad-map)
          topic (:topic ad-map)
          coord-pub (:coordinator-pubkey ad-map)
          sig (:signature ad-map)]
      (if-not (and sub-id topic coord-pub sig)
        {:ok? false :error "missing-required-fields"}
        (let [econ? (boolean (get ad-map :economy-enabled? true))
              burn-fl (long (or (:burn-floor ad-map) (if econ? 100 0)))
              suites (vec (or (:crypto-suites ad-map) ["suite-v1-aes256gcm"]))
              wire-fmt (str (or (:wire-format ad-map) "fressian-v1"))
              base-ad {:subnet-id (str sub-id)
                       :topic (str topic)
                       :economy-enabled? econ?
                       :burn-floor burn-fl
                       :crypto-suites suites
                       :wire-format wire-fmt
                       :coordinator-pubkey (str coord-pub)}
              payload (subnet-advertisement-payload base-ad)
              valid? (crypto/verify-with-fallback (str coord-pub) payload sig)]
          (if valid?
            {:ok? true :advertisement (assoc base-ad :signature sig)}
            {:ok? false :error "invalid-signature"}))))))
