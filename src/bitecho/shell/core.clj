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

(def snapshot-interval-ms
  "The interval in milliseconds to periodically snapshot the state map."
  10000)

(defn start-node
  "Starts a transparent go-loop wrapping the state machine.
   Returns a map with the internal channels :events-in, :network-in, :net-out, and the loop :stop-ch.
   Periodically snapshots state to disk if an :internal-snapshot event is received."
  ([initial-state]
   (start-node initial-state persistence/default-snapshot-filename))
  ([initial-state snapshot-filename]
   (let [events-in (async/chan 1024)
         network-in (async/chan 1024)
         net-out (async/chan 1024)
         stop-ch (async/chan)]

     ;; Snapshot ticker loop
     (async/go-loop []
       (let [[_ port] (async/alts! [(async/timeout snapshot-interval-ms) stop-ch])]
         (when (not= port stop-ch)
           (async/put! events-in {:type :internal-snapshot})
           (recur))))

     (async/go-loop [state initial-state]
       (let [[val port] (async/alts! [events-in network-in stop-ch])]
         (cond
           (= port stop-ch)
           nil ;; Node stopped

           (nil? val)
           (recur state) ;; Handle channel close

           (and (= port events-in) (= (:type val) :internal-snapshot))
           (do
             ;; Offload serialization and I/O to a dedicated thread
             (async/thread
               (persistence/save-state-to-disk snapshot-filename state))
             (recur state))

           (= port network-in)
           (if (valid-network-event? val)
             (let [{:keys [state commands]} (sm/handle-event state val)]
               (doseq [cmd commands]
                 (if (is-network-command? cmd)
                   (async/put! net-out cmd)
                   (async/put! events-in cmd)))
               (recur state))
             ;; Drop invalid network events
             (recur state))

           (= port events-in)
           (let [{:keys [state commands]} (sm/handle-event state val)]
             (doseq [cmd commands]
               (if (is-network-command? cmd)
                 (async/put! net-out cmd)
                 (async/put! events-in cmd)))
             (recur state)))))
     {:events-in events-in
      :network-in network-in
      :net-out net-out
      :stop-ch stop-ch})))

(defn stop-node
  "Gracefully stops a running shell node."
  [node]
  (async/put! (:stop-ch node) true)
  (async/close! (:events-in node))
  (async/close! (:network-in node))
  (async/close! (:net-out node)))
