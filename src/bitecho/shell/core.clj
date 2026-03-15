(ns bitecho.shell.core
  "Provides the transparent go-loop shell wrapping the pure bitecho state machine."
  (:require [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.string :as str]))

(defn is-network-command?
  "Determines if a given command map is meant for external network peers."
  [cmd]
  (let [t (:type cmd)]
    (or (= :network-out t)
        (and (keyword? t) (str/starts-with? (name t) "send-"))
        (and (keyword? t) (str/starts-with? (name t) "route-")))))

(def ^:private allowed-network-events
  #{:receive-push-view
    :receive-summary
    :receive-pull-request
    :receive-gossip
    :turn-allocate-request
    :turn-relay-request})

(defn- valid-network-event?
  "Validates if an incoming event map from the external network is in the whitelist."
  [event]
  (contains? allowed-network-events (:type event)))

(defn start-node
  "Starts a transparent go-loop wrapping the state machine.
   Returns a map with the internal channels :events-in, :network-in, :net-out, :app-out, :persist-ch, and the loop :stop-ch.
   Snapshots state to disk automatically via a dedicated sliding-buffer channel when state changes."
  ([initial-state]
   (start-node initial-state persistence/default-snapshot-filename))
  ([initial-state snapshot-filename]
   (let [events-in (async/chan 1024)
         network-in (async/chan 1024)
         net-out (async/chan 1024)
         app-out (async/chan 1024)
         persist-ch (async/chan (async/sliding-buffer 1))
         stop-ch (async/chan)]

     ;; Dedicated I/O loop for persistence
     (async/go-loop []
       (when-let [state-to-save (async/<! persist-ch)]
         (persistence/save-state-to-disk snapshot-filename state-to-save)
         (recur)))

     (async/go-loop [state initial-state]
       (let [[val port] (async/alts! [events-in network-in stop-ch])]
         (cond
           (= port stop-ch)
           nil ;; Node stopped

           (nil? val)
           (recur state) ;; Handle channel close

           (= port network-in)
           (if (valid-network-event? val)
             (let [{new-state :state commands :commands} (sm/handle-event state val)]
               (doseq [cmd commands]
                 (cond
                   (= (:type cmd) :app-event) (async/put! app-out cmd)
                   (is-network-command? cmd) (async/put! net-out cmd)
                   :else (async/put! events-in cmd)))
               (when (not= state new-state)
                 (async/put! persist-ch new-state))
               (recur new-state))
             ;; Drop invalid network events
             (recur state))

           (= port events-in)
           (let [{new-state :state commands :commands} (sm/handle-event state val)]
             (doseq [cmd commands]
               (cond
                 (= (:type cmd) :app-event) (async/put! app-out cmd)
                 (is-network-command? cmd) (async/put! net-out cmd)
                 :else (async/put! events-in cmd)))
             (when (not= state new-state)
               (async/put! persist-ch new-state))
             (recur new-state)))))
     {:events-in events-in
      :network-in network-in
      :net-out net-out
      :app-out app-out
      :persist-ch persist-ch
      :stop-ch stop-ch})))

(defn stop-node
  "Gracefully stops a running shell node."
  [node]
  (async/put! (:stop-ch node) true)
  (async/close! (:events-in node))
  (async/close! (:network-in node))
  (async/close! (:net-out node))
  (async/close! (:app-out node))
  (async/close! (:persist-ch node)))
