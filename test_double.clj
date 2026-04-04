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
(def transfer (account/map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes))))

(def ledger {sender-pubkey (account/map->AccountState {:balance 1000 :seq 0 :deps []})})

(with-redefs [crypto/sha256 fast-dummy-sha256
              crypto/verify (fn [_ _ _] true)
              crypto/sign   dummy-sign]
  (let [new-ledger (account/apply-transfer ledger transfer)]
    (println "After first apply:")
    (println new-ledger)
    (let [second-ledger (account/apply-transfer new-ledger transfer)]
      (println "After second apply:")
      (println second-ledger))))
