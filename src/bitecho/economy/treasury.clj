(ns bitecho.economy.treasury
  "Pure logic to integrate Streamlet finalized blocks containing Proof of Delivery receipts
   and emit payout transfer commands."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]))

(defn- valid-receipt?
  "Checks if a payload is a valid Receipt record and cryptographically sound."
  [payload]
  (try
    (when (and (map? payload)
               (contains? payload :agent)
               (contains? payload :node)
               (contains? payload :payload-id)
               (contains? payload :signature))
      ;; Receipt verification
      (let [unsigned-receipt (into (sorted-map) (dissoc payload :signature))
            payload-bytes (.getBytes (pr-str unsigned-receipt) "UTF-8")
            agent-pub (byte-array (map byte (:agent payload)))
            sig-bytes (byte-array (map byte (:signature payload)))]
        (crypto/verify agent-pub payload-bytes sig-bytes)))
    (catch Exception _
      false)))

(defn process-finalized-blocks
  "Iterates through the provided blocks.
   For every valid receipt found in the payloads, generates a Transfer command
   to pay the routing node (`node-pubkey` inside the receipt) `payout-amount`.
   Assigns sequential `seq` numbers, updating `deps` (linking back to the previous transfer hash),
   and cryptographically signs each transfer with the treasury's private key.

   Returns a map:
     {:seq next-seq
      :deps last-deps
      :commands [Transfer...]}"
  [^bytes treasury-pubkey ^bytes treasury-privkey start-seq start-deps blocks payout-amount]
  (let [;; Extract all valid receipts from all blocks
        receipts (->> blocks
                      (mapcat :payload)
                      (filter valid-receipt?))

        ;; Iterate over receipts to build transfers and update state sequentially
        initial-acc {:seq start-seq
                     :deps start-deps
                     :commands []}

        result-acc
        (reduce (fn [acc receipt]
                  (let [current-seq (:seq acc)
                        current-deps (:deps acc)
                        next-seq (inc current-seq)

                        receiver-pubkey-hex (basalt/bytes->hex (byte-array (map byte (:node receipt))))

                        unsigned-transfer {:sender treasury-pubkey
                                           :receiver receiver-pubkey-hex
                                           :amount payout-amount
                                           :seq next-seq
                                           :deps current-deps}

                        payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
                        signature (crypto/sign treasury-privkey payload-bytes)

                        transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature)))

                        ;; Calculate hash for next transfer's deps
                        safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex signature))
                        transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))]

                    {:seq next-seq
                     :deps [transfer-hash]
                     :commands (conj (:commands acc) transfer)}))
                initial-acc
                receipts)]
    result-acc))
