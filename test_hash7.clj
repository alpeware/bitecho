(require '[bitecho.crypto :as crypto])
(require '[bitecho.basalt.core :as basalt])
(require '[bitecho.economy.account :as account])

(def sender-pubkey "sender123")
(def receiver-pubkey "receiver456")
(def sender-privkey "priv123")
(def last-hash nil)

(def unsigned-transfer {:sender sender-pubkey
                        :receiver receiver-pubkey
                        :amount 100
                        :seq 1
                        :deps (if last-hash [last-hash] [])})

(defn dummy-sign [privkey data]
  (.getBytes (str "sig-" (hash (vec data))) "UTF-8"))

(def payload-bytes-for-sig (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8"))
(def signature-bytes (dummy-sign sender-privkey payload-bytes-for-sig))
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes))))

;; Simulator calculation for deps logic loop
(def safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (byte-array (:signature transfer)))))
(def transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8"))))

;; Sim loop calculates transfer hash 2 the same way for loop
(def unsigned-transfer-2 (into (sorted-map) (dissoc safe-transfer :signature)))
(def payload-bytes-check (.getBytes (pr-str unsigned-transfer-2) "UTF-8"))
(println "Sim Transfer Hash 1:" transfer-hash)
(println "Valid sig?:" (crypto/verify (:sender safe-transfer) payload-bytes-check (basalt/hex->bytes (:signature safe-transfer))))


(def last-hash transfer-hash)
(def unsigned-transfer-next {:sender sender-pubkey
                             :receiver receiver-pubkey
                             :amount 200
                             :seq 2
                             :deps (if last-hash [last-hash] [])})
(def payload-bytes-for-sig-2 (.getBytes (pr-str (into (sorted-map) unsigned-transfer-next)) "UTF-8"))
(def signature-bytes-2 (dummy-sign sender-privkey payload-bytes-for-sig-2))
(def transfer-2 (account/map->Transfer (assoc unsigned-transfer-next :signature (vec signature-bytes-2))))
(def payload-str (pr-str {:id "uuid" :transfer transfer-2}))
(println payload-str)

;; Inside node
(def payload-edn (clojure.edn/read-string {:default clojure.core/tagged-literal
                                           :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                     'bitecho.economy.account.AccountState account/map->AccountState}}
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
(println "Node Rehydrated seq 2 deps:" (:deps transfer-rehydrated))
