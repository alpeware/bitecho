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

(def unsigned-transfer {:sender sender-pubkey
                        :receiver receiver-pubkey
                        :amount 100
                        :seq 1
                        :deps []})

(def payload-bytes-for-sig (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8"))
(def signature-bytes (dummy-sign sender-privkey payload-bytes-for-sig))
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature signature-bytes)))

(def payload-str (pr-str {:id "uuid" :transfer transfer}))
(println "Payload STR:")
(println payload-str)

(def payload-edn (clojure.edn/read-string {:default clojure.core/tagged-literal
                                           :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                     'bitecho.economy.account.AccountState account/map->AccountState}}
                                          payload-str))

(def raw-transfer (:transfer payload-edn))
(println "raw transfer:")
(println raw-transfer)
(println "type signature:" (type (:signature raw-transfer)))
