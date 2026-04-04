(require '[bitecho.crypto :as crypto])
(require '[bitecho.basalt.core :as basalt])
(require '[bitecho.economy.account :as account])

(def sender-pubkey "sender123")
(def receiver-pubkey "receiver456")
(def sender-privkey "priv123")

(def unsigned-transfer {:sender sender-pubkey
                        :receiver receiver-pubkey
                        :amount 100
                        :seq 1
                        :deps []})

(def signature-bytes (byte-array [1 2 3]))
;; E2E uses map->Transfer (assoc ... :signature (vec signature-bytes))
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes))))

;; Simulator E2E hashing
(def safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (byte-array (:signature transfer)))))
(println "Simulator E2E Hash:" (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8"))))

;; State Machine payload formatting
(def payload-str (pr-str {:id "uuid" :transfer transfer}))

;; State Machine receiving process
(def payload-edn (clojure.edn/read-string {:default clojure.core/tagged-literal
                                           :readers {'bitecho.economy.account.Transfer account/map->Transfer}}
                                          payload-str))

(def raw-transfer (:transfer payload-edn))
(def transfer-map (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                    (:form raw-transfer)
                    (if (map? raw-transfer)
                        (into {} raw-transfer)
                        (into {} raw-transfer))))

(def transfer-map (if (vector? (:signature transfer-map))
                    (assoc transfer-map :signature (byte-array (:signature transfer-map)))
                    transfer-map))

(def transfer-map (if (string? (:signature transfer-map))
                    (assoc transfer-map :signature (.getBytes ^String (:signature transfer-map) "UTF-8"))
                    transfer-map))

(def transfer-map (if (and (seqable? (:signature transfer-map))
                           (every? number? (:signature transfer-map)))
                    (assoc transfer-map :signature (byte-array (map byte (:signature transfer-map))))
                    transfer-map))

(def transfer-map (if (not (bytes? (:signature transfer-map)))
                    (assoc transfer-map :signature (byte-array 0))
                    transfer-map))

(def transfer-rehydrated (account/map->Transfer transfer-map))

;; State machine inner apply-transfer hashing
(def safe-transfer-node (assoc (into (sorted-map) transfer-rehydrated) :signature (basalt/bytes->hex (byte-array (:signature transfer-rehydrated)))))

(println "Node E2E Hash:" (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer-node) "UTF-8"))))
