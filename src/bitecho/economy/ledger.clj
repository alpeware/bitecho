(ns bitecho.economy.ledger
  "Pure functions to define the Genesis state data structure and apply valid lottery
   ticket payouts to an agent's Echo balance."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.sci-sandbox :as sci-sandbox]
            [bitecho.lottery.core :as lottery]))

(defn init-ledger
  "Initializes the ledger genesis state."
  []
  {:utxos {}
   :claimed-tickets #{}})

(defn- hash-ticket
  "Computes a hex hash of the full ticket contents for tracking claims."
  [ticket]
  (let [hash-hex (:payload-hash ticket)
        nonce-str (str (:nonce ticket))
        pub-key-hex (:public-key ticket)
        sig-hex (:signature ticket)
        input-str (str hash-hex nonce-str pub-key-hex sig-hex)]
    (basalt/bytes->hex (crypto/sha256 (.getBytes input-str "UTF-8")))))

(defn- standard-puzzle-hash
  "Generates the standard puzzle hash for a public key."
  [pubkey-hex]
  (let [puzzle (str "(= \"" pubkey-hex "\" solution)")]
    (basalt/bytes->hex (crypto/sha256 (.getBytes puzzle "UTF-8")))))

(defn claim-ticket
  "Applies a valid lottery ticket payout to an agent by creating a new UTXO.
   If the ticket wins and hasn't been claimed before, creates the UTXO
   and marks the ticket as claimed. Otherwise, returns the ledger unchanged."
  [ledger ticket difficulty-hex claimer-pubkey payout-amount]
  (let [ticket-hash (hash-ticket ticket)]
    (if (and (lottery/winning-ticket? ticket difficulty-hex)
             (not (contains? (:claimed-tickets ledger) ticket-hash)))
      (let [puzzle-hash (standard-puzzle-hash claimer-pubkey)]
        (-> ledger
            (assoc-in [:utxos ticket-hash] {:amount payout-amount :puzzle-hash puzzle-hash})
            (update :claimed-tickets conj ticket-hash)))
      ledger)))

(defn- valid-puzzle-execution?
  "Checks if a puzzle hashes to the expected puzzle-hash and evaluates to true."
  [puzzle solution expected-hash]
  (let [actual-hash (basalt/bytes->hex (crypto/sha256 (.getBytes puzzle "UTF-8")))]
    (if (= actual-hash expected-hash)
      (try
        (let [script (str "(let [solution " (pr-str solution) "] " puzzle ")")
              result (sci-sandbox/eval-string script)]
          (true? result))
        (catch Exception _
          false))
      false)))

(defn process-transaction
  "Processes a transaction by consuming UTXOs and creating new ones.
   Validates that inputs exist, are unique,
   outputs are strictly positive, have sufficient funds,
   and for each input the provided puzzle hashes to the UTXO's puzzle-hash
   and the script (sci-sandbox/eval puzzle solution) evaluates to true.
   Returns the updated ledger if valid, or unchanged ledger if invalid."
  [ledger tx]
  (let [{:keys [inputs outputs puzzles solutions]} tx
        utxos (:utxos ledger)
        input-utxos (map #(get utxos %) inputs)]
    (if (and (every? some? input-utxos)
             (= (count inputs) (count (set inputs)))
             (= (count inputs) (count puzzles))
             (= (count inputs) (count solutions))
             (every? #(pos? (:amount %)) outputs)
             (>= (reduce + (map :amount input-utxos))
                 (reduce + (map :amount outputs)))
             (every? true? (map (fn [utxo puzzle solution]
                                  (valid-puzzle-execution? puzzle solution (:puzzle-hash utxo)))
                                input-utxos puzzles solutions)))
      (let [ledger-without-inputs (reduce (fn [l input-id] (update l :utxos dissoc input-id)) ledger inputs)
            tx-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str tx) "UTF-8")))
            new-outputs-with-ids (map-indexed (fn [idx output]
                                                [(basalt/bytes->hex (crypto/sha256 (.getBytes (str tx-hash idx) "UTF-8")))
                                                 output])
                                              outputs)]
        (reduce (fn [l [out-id out]] (assoc-in l [:utxos out-id] out)) ledger-without-inputs new-outputs-with-ids))
      ledger)))
