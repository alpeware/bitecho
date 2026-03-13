(ns bitecho.shell.flow
  "Provides the core.async.flow topology map and pure adapter step function
   wrapping the bitecho state machine."
  (:require [bitecho.state-machine :as sm]
            [clojure.core.async.flow :as flow]))

(defn state-machine-step
  "A pure core.async.flow step function wrapping the bitecho state machine.
   It has 4 arities:
   () -> describes params, ins, outs.
   (args) -> initializes state.
   (state transition) -> handles lifecycle transition (returns current state since it's pure).
   (state input msg) -> transforms state given a message on an input channel."
  ([]
   {:params {:initial-peers "Initial Basalt peers for genesis"}
    :ins {:net-in "Incoming network messages from datachannels"
          :events-in "Internal loopback events (ticks, self-messages)"}
    :outs {:net-out "Outgoing network messages to datachannels"
           :events-out "Internal loopback events to be routed back to events-in"}})
  ([args]
   (let [base-state (sm/init-state (:initial-peers args))
         in-ports (cond-> {}
                    (:net-in args) (assoc :net-in (:net-in args))
                    (:events-in args) (assoc :events-in (:events-in args)))
         out-ports (cond-> {}
                     (:net-out args) (assoc :net-out (:net-out args))
                     (:events-out args) (assoc :events-out (:events-out args)))]
     (cond-> base-state
       (seq in-ports) (assoc ::flow/in-ports in-ports)
       (seq out-ports) (assoc ::flow/out-ports out-ports))))
  ([state _transition]
   state)
  ([state _input msg]
   (let [result (sm/handle-event state msg)
         new-state (:state result)
         commands (:commands result)
         net-commands (filterv #(= :network-out (:type %)) commands)
         event-commands (filterv #(not= :network-out (:type %)) commands)
         outs (cond-> {}
                (seq net-commands) (assoc :net-out net-commands)
                (seq event-commands) (assoc :events-out event-commands))]
     [new-state outs])))

(defn create-topology
  "Creates the core.async.flow topology definition map for the bitecho node.
   Maps the provided external channels into the state-machine process via args."
  [initial-peers net-in-chan events-in-chan net-out-chan events-out-chan]
  {:procs {:state-machine-proc {:proc (flow/process #'state-machine-step)
                                :args {:initial-peers initial-peers
                                       :net-in net-in-chan
                                       :events-in events-in-chan
                                       :net-out net-out-chan
                                       :events-out events-out-chan}}}
   :conns [[[:state-machine-proc :events-out] [:state-machine-proc :events-in]]]})
