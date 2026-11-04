(ns bitecho.economy.account
  "Account ledger state and transfer transactions.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]))

(defrecord ^{:doc "Account ledger state record holding balance, seq, and transaction dependency hashes."} AccountState [balance seq deps])

(defrecord ^{:doc "Transfer transaction record with signature and dependencies."} Transfer [sender receiver amount seq deps signature])

(defn create-transfer
  "Creates and signs a transfer using canonical Fressian signing bytes."
  [privkey unsigned-transfer]
  (let [signature-bytes (crypto/sign-canonical privkey (into {} unsigned-transfer))]
    (map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes)))))

(defn transfer-hash
  "Calculates the SHA-256 hash of a transfer using canonical Fressian encoding."
  [transfer]
  (let [sig-hex (if (string? (:signature transfer))
                  (:signature transfer)
                  (let [sig-col (:signature transfer)]
                    (basalt/bytes->hex (if (fressian/bytes? sig-col)
                                         sig-col
                                         #?(:clj (byte-array (map byte sig-col))
                                            :cljs (js/Uint8Array. (clj->js sig-col)))))))
        safe-transfer (assoc (dissoc (into {} transfer) :crypto/verified?) :signature sig-hex)]
    (basalt/bytes->hex (crypto/sha256 (fressian/encode-canonical safe-transfer)))))

(defn validate-transfer
  "Validates a transfer against a current account state.
   Supports N/N-1 rolling verification (v2 canonical Fressian with v1 pr-str fallback)
   and shell-boundary pre-verification (:crypto/verified? true)."
  [current-state transfer]
  (try
    (let [sender (:sender transfer)
          sender-bytes (if (string? sender)
                         (basalt/hex->bytes sender)
                         sender)
          valid-seq? (= (:seq transfer) (inc (:seq current-state)))
          valid-deps? (= (:deps transfer) (:deps current-state))
          valid-balance? (>= (:balance current-state) (:amount transfer))

          unsigned-transfer (into (sorted-map) (dissoc transfer :signature :crypto/verified?))
          sig-bytes (if (coll? (:signature transfer))
                      #?(:clj (byte-array (map byte (:signature transfer)))
                         :cljs (js/Uint8Array. (clj->js (:signature transfer))))
                      (:signature transfer))
          valid-signature? (or (:crypto/verified? transfer)
                               (crypto/verify-with-fallback sender-bytes unsigned-transfer sig-bytes))]

      (and valid-seq? valid-deps? valid-balance? (boolean valid-signature?)))
    (catch #?(:clj Exception :cljs :default) _
      false)))

(defn apply-transfer
  "Applies a transfer to the given ledger (a map of pubkeys to AccountState).
   Validates the transfer against the sender's current state.
   If valid, decrements the sender's balance, increments the sender's seq,
   updates the sender's deps to the transfer hash, and increments the receiver's balance.
   If invalid, returns the ledger unmodified."
  [ledger transfer]
  (let [sender (:sender transfer)
        receiver (:receiver transfer)
        sender-state (get ledger sender)
        amount (:amount transfer)]
    (if (and sender-state (validate-transfer sender-state transfer))
      (let [t-hash (transfer-hash transfer)
            new-sender-state (map->AccountState
                              {:balance (- (:balance sender-state) amount)
                               :seq (:seq transfer)
                               :deps [t-hash]})
            ledger-after-send (assoc ledger sender new-sender-state)
            receiver-state (get ledger-after-send receiver (map->AccountState {:balance 0 :seq 0 :deps []}))
            new-receiver-state (assoc receiver-state :balance (+ (:balance receiver-state) amount))]
        (assoc ledger-after-send receiver new-receiver-state))
      ledger)))

(defn apply-mint
  "Applies mint allocations to the given ledger.
   Can accept [ledger receiver amount] for a single credit,
   or [ledger allocations] where allocations is a map of {receiver -> amount}.
   Credits receivers (creating zero-balance AccountState if absent).
   If any amount is negative, returns the ledger unmodified."
  ([ledger receiver amount]
   (if (and (string? receiver) (integer? amount) (not (neg? amount)))
     (if (zero? amount)
       ledger
       (let [curr-state (get ledger receiver (map->AccountState {:balance 0 :seq 0 :deps []}))
             new-state (assoc curr-state :balance (+ (:balance curr-state) amount))]
         (assoc ledger receiver new-state)))
     ledger))
  ([ledger allocations]
   (if (some (fn [[_ amt]] (or (not (integer? amt)) (neg? amt))) allocations)
     ledger
     (reduce-kv
      (fn [l recv amt]
        (if (pos? amt)
          (let [curr-state (get l recv (map->AccountState {:balance 0 :seq 0 :deps []}))]
            (assoc l recv (assoc curr-state :balance (+ (:balance curr-state) amt))))
          l))
      ledger
      allocations))))
