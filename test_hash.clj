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
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature signature-bytes)))

(def safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (:signature transfer))))
(def transfer-hash (basalt/bytes->hex (fast-dummy-sha256 (.getBytes (pr-str safe-transfer) "UTF-8"))))

(println "E2E Hash calculated:" transfer-hash)
(println "Safe transfer stringified:" (pr-str safe-transfer))

;; Now simulate what happens in the node state machine
(def payload-str (pr-str {:id "uuid" :transfer transfer}))
(def payload-edn (clojure.edn/read-string {:default clojure.core/tagged-literal
                                           :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                     'bitecho.economy.account.AccountState account/map->AccountState}}
                                          payload-str))

(def raw-transfer (:transfer payload-edn))
(def transfer-map (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                    (:form raw-transfer)
                    (into {} raw-transfer)))

;; In state-machine, it forces signature to byte array
(def transfer-map-2 (assoc transfer-map :signature (.getBytes ^String (:signature transfer-map) "UTF-8")))
;; It re-hydrates
(def transfer-rehydrated (account/map->Transfer transfer-map-2))

;; Apply-transfer hash
(def safe-transfer-2 (assoc (into (sorted-map) transfer-rehydrated) :signature (basalt/bytes->hex (:signature transfer-rehydrated))))
(def transfer-hash-2 (basalt/bytes->hex (fast-dummy-sha256 (.getBytes (pr-str safe-transfer-2) "UTF-8"))))

(println "Node Hash calculated:" transfer-hash-2)
(println "Safe transfer 2 stringified:" (pr-str safe-transfer-2))
