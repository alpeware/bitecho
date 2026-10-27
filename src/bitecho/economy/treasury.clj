(ns bitecho.economy.treasury
  "Pure logic to integrate Streamlet finalized blocks containing routing claims
   and emit payout transfer commands."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]))

(defn- valid-claim?
  "Checks if a payload is a valid routing claim and cryptographically sound."
  [payload]
  (try
    (when (and (map? payload)
               (contains? payload :agent)
               (contains? payload :node)
               (contains? payload :payload-id)
               (contains? payload :signature))
      (let [unsigned (into (sorted-map) (dissoc payload :signature))
            payload-bytes (.getBytes (pr-str unsigned) "UTF-8")
            agent-pub (byte-array (map byte (:agent payload)))
            sig-bytes (byte-array (map byte (:signature payload)))]
        (crypto/verify agent-pub payload-bytes sig-bytes)))
    (catch Exception _
      false)))

(defn process-finalized-blocks
  "Iterates through the provided blocks.
   For every valid claim found in the payloads, generates a Transfer command
   to pay the routing node (`node-pubkey` inside the claim) `payout-amount`.
   Assigns sequential `seq` numbers, updating `deps` (linking back to the previous transfer hash),
   and cryptographically signs each transfer with the treasury's private key.

   Returns a map:
     {:seq next-seq
      :deps last-deps
      :commands [Transfer...]}"
  [^bytes treasury-pubkey ^bytes treasury-privkey start-seq start-deps blocks payout-amount]
  (let [claims (->> blocks
                    (mapcat :payload)
                    (filter valid-claim?))
        initial-acc {:seq start-seq
                     :deps start-deps
                     :commands []}
        result-acc
        (reduce (fn [acc claim]
                  (let [current-seq (:seq acc)
                        current-deps (:deps acc)
                        next-seq (inc current-seq)
                        receiver-pubkey-hex (basalt/bytes->hex (byte-array (map byte (:node claim))))
                        unsigned-transfer {:sender treasury-pubkey
                                           :receiver receiver-pubkey-hex
                                           :amount payout-amount
                                           :seq next-seq
                                           :deps current-deps}
                        payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
                        signature (crypto/sign treasury-privkey payload-bytes)
                        transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature)))
                        safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex signature))
                        transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))]
                    {:seq next-seq
                     :deps [transfer-hash]
                     :commands (conj (:commands acc) transfer)}))
                initial-acc
                claims)]
    result-acc))
