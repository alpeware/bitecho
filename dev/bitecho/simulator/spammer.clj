(ns bitecho.simulator.spammer
  "A Byzantine Spammer shell for testing the network."
  (:require [clojure.core.async :as async]
            [bitecho.crypto :as crypto]
            [bitecho.basalt.core :as basalt]))

(defn start-spammer
  "Starts a spammer loop that continuously broadcasts invalid messages."
  [target-pubkey net-out-ch stop-ch]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))]
    (async/go-loop []
      (let [msg {:type :route-directed-message
                 :destination target-pubkey
                 :envelope {:payload "spam"
                            :signature "invalidsig"}
                 :payout-amount 0}]
        (async/put! net-out-ch msg))
      (let [[_ port] (async/alts! [(async/timeout 10) stop-ch])]
        (when (not= port stop-ch)
          (recur))))))

(defn init-node
  "Initializes a spammer node that conforms to the orchestrator."
  [target-pubkey]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        net-out-ch (async/chan 10)
        stop-ch (async/chan)]
    (start-spammer target-pubkey net-out-ch stop-ch)
    {:keys keys
     :pubkey-hex pubkey-hex
     ;; No events-in or network-in as spammers only broadcast
     :net-out net-out-ch
     :stop-ch stop-ch}))

(defn stop-node
  "Stops the spammer node."
  [node]
  (async/put! (:stop-ch node) true)
  (async/close! (:stop-ch node)))
