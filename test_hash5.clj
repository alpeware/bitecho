(require '[bitecho.crypto :as crypto])
(require '[bitecho.basalt.core :as basalt])
(require '[bitecho.economy.account :as account])

(def payload-str "{:id \"uuid\", :transfer #bitecho.economy.account.Transfer{:sender \"sender123\", :receiver \"receiver456\", :amount 100, :seq 1, :deps [], :signature [1 2 3]}}")

;; EDN parsing in state-machine
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

(def safe-transfer-node (assoc (into (sorted-map) transfer-rehydrated) :signature (basalt/bytes->hex (byte-array (:signature transfer-rehydrated)))))
(println "Safe Node:" safe-transfer-node)
(println "Hash:" (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer-node) "UTF-8"))))
