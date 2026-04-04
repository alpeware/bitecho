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
;; HERE is the change: use (vec signature-bytes)
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes))))

;; E2E hash calc (the node does this too)
(def safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (byte-array (:signature transfer)))))
(println "Safe E2E:" safe-transfer)

;; EDN payload
(def payload-str (pr-str {:id "uuid" :transfer transfer}))

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
                    (assoc transfer-map :signature (byte-array (:signature transfer-map)))
                    transfer-map))

(def transfer-map (if (not (bytes? (:signature transfer-map)))
                    (assoc transfer-map :signature (byte-array 0))
                    transfer-map))

(def transfer-rehydrated (account/map->Transfer transfer-map))

(def safe-transfer-node (assoc (into (sorted-map) transfer-rehydrated) :signature (basalt/bytes->hex (:signature transfer-rehydrated))))
(println "Safe Node:" safe-transfer-node)
