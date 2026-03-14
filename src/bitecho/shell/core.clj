(ns bitecho.shell.core
  "Provides the transparent go-loop shell wrapping the pure bitecho state machine."
  (:require [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.string :as str]))

(defn is-network-command?
  "Determines if a given command map is meant for external network peers."
  [cmd]
  (let [t (:type cmd)]
    (or (= :network-out t)
        (and (keyword? t) (str/starts-with? (name t) "send-"))
        (and (keyword? t) (str/starts-with? (name t) "route-")))))

(defn start-node
  "Starts a transparent go-loop wrapping the state machine.
   Returns a map with the internal channels :events-in and :net-out, and the loop :stop-ch."
  [initial-peers]
  (let [events-in (async/chan 1024)
        net-out (async/chan 1024)
        stop-ch (async/chan)]
    (async/go-loop [state (sm/init-state initial-peers)]
      (let [[val port] (async/alts! [events-in stop-ch])]
        (if (= port stop-ch)
          nil ;; Node stopped
          (let [{:keys [state commands]} (sm/handle-event state val)]
            (doseq [cmd commands]
              (if (is-network-command? cmd)
                (async/put! net-out cmd)
                ;; Route internal events back to the processing loop
                (async/put! events-in cmd)))
            (recur state)))))
    {:events-in events-in
     :net-out net-out
     :stop-ch stop-ch}))

(defn stop-node
  "Gracefully stops a running shell node."
  [node]
  (async/put! (:stop-ch node) true)
  (async/close! (:events-in node))
  (async/close! (:net-out node)))
