(require '[bitecho.crypto :as crypto])
(require '[bitecho.basalt.core :as basalt])
(require '[bitecho.economy.account :as account])

(defn fast-dummy-sha256 [data]
  (.getBytes (str (hash (vec data))) "UTF-8"))
(defn dummy-sign [privkey data]
  (.getBytes (str "sig-" (hash (vec data))) "UTF-8"))

(def sender-pubkey "sender123")
(def receiver-pubkey "receiver456")
(def sender-privkey "priv123")
(def last-hash nil)

(def unsigned-transfer {:sender sender-pubkey
                        :receiver receiver-pubkey
                        :amount 100
                        :seq 1
                        :deps (if last-hash [last-hash] [])})

(def payload-bytes-for-sig (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8"))
(def signature-bytes (dummy-sign sender-privkey payload-bytes-for-sig))
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes))))
(def safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (byte-array (:signature transfer)))))
(def transfer-hash (basalt/bytes->hex (fast-dummy-sha256 (.getBytes (pr-str safe-transfer) "UTF-8"))))

(println "Sim Loop Hash 1:" transfer-hash)
(def ledger {sender-pubkey (account/map->AccountState {:balance 1000 :seq 0 :deps []})})

;; Node side
(def payload-str (pr-str {:id "uuid" :transfer transfer}))
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

(with-redefs [crypto/sha256 fast-dummy-sha256
              crypto/verify (fn [_ _ _] true)
              crypto/sign   dummy-sign]
  (let [new-ledger (account/apply-transfer ledger transfer-rehydrated)]
    (println "Node Ledgers:")
    (println new-ledger)
    (println "Node sender hash deps:" (:deps (get new-ledger sender-pubkey)))))
