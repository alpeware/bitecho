(ns bitecho.economy.difficulty
  "Pure logic for dynamic lottery difficulty calculation."
  (:import [java.math BigInteger]))

(def max-target-hex
  "The maximum difficulty target (easiest difficulty), represented as all FFs."
  (apply str (repeat 64 "f")))

(def max-target
  "The maximum difficulty target as a BigInteger."
  (BigInteger. max-target-hex 16))

(defn calculate-difficulty
  "Calculates the dynamic difficulty target based on fanout (k) and network-scale.
   Target = MaxTarget * (k / network-scale).
   Returns a 64-character 0-padded hex string.
   Bounded by MaxTarget."
  [k network-scale]
  (let [k-big (BigInteger/valueOf k)
        n-big (BigInteger/valueOf network-scale)
        ;; max-target * k
        numerator (.multiply max-target k-big)
        ;; (max-target * k) / network-scale
        target (.divide numerator n-big)]
    (if (>= (.compareTo target max-target) 0)
      max-target-hex
      (let [hex-str (.toString target 16)
            ;; Format to 64 chars, 0-padded
            padded-hex (format "%64s" hex-str)
            result (.replace padded-hex \space \0)]
        result))))
