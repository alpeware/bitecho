(ns bitecho.channels.core
  "Core pure logic and data structures for a 2-of-2 multisig Payment Channel state."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn create-initial-state
  "Creates the pure data structures for a 2-of-2 multisig Payment Channel initial state."
  [pubkey-a pubkey-b amount-a amount-b]
  {:pubkey-a pubkey-a
   :pubkey-b pubkey-b
   :balance-a amount-a
   :balance-b amount-b
   :nonce 0})

(defn generate-multisig-puzzle
  "Generates a multisig Puzzle string to be evaluated by `sci-sandbox`.
   The puzzle expects a `solution` map with keys `:sig-a`, `:sig-b`, and `:tx-hash`.
   It verifies the cryptographic signatures against the transaction hash."
  [pubkey-a pubkey-b]
  (str "(let [pub-a-bytes (bitecho.basalt.core/hex->bytes \"" pubkey-a "\") "
       "pub-b-bytes (bitecho.basalt.core/hex->bytes \"" pubkey-b "\") "
       "sig-a-bytes (bitecho.basalt.core/hex->bytes (:sig-a solution)) "
       "sig-b-bytes (bitecho.basalt.core/hex->bytes (:sig-b solution)) "
       "tx-hash-bytes (bitecho.basalt.core/hex->bytes (:tx-hash solution))] "
       "(and (bitecho.crypto/verify pub-a-bytes tx-hash-bytes sig-a-bytes) "
       "(bitecho.crypto/verify pub-b-bytes tx-hash-bytes sig-b-bytes)))"))

(defn mutually-sign-update
  "Mutually signs off-chain balance updates, verifying signatures against the
   canonical state hash and returning the updated state.
   Returns the unchanged `state` if the signatures are invalid or if the new
   nonce is not strictly greater than the old nonce."
  [state update-map sig-a-hex sig-b-hex]
  (if (<= (:nonce update-map) (:nonce state))
    state
    (let [canonical-map (into (sorted-map) update-map)
          update-hash (crypto/sha256 (.getBytes (pr-str canonical-map) "UTF-8"))
          pub-a-bytes (basalt/hex->bytes (:pubkey-a state))
          pub-b-bytes (basalt/hex->bytes (:pubkey-b state))
          sig-a-bytes (basalt/hex->bytes sig-a-hex)
          sig-b-bytes (basalt/hex->bytes sig-b-hex)
          valid-a? (crypto/verify pub-a-bytes update-hash sig-a-bytes)
          valid-b? (crypto/verify pub-b-bytes update-hash sig-b-bytes)]
      (if (and valid-a? valid-b?)
        (assoc update-map
               :pubkey-a (:pubkey-a state)
               :pubkey-b (:pubkey-b state))
        state))))
