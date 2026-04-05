(ns bitecho.streamlet.core
  "Streamlet core data structures and pure functions.")

(defrecord Block [epoch parent-hash payload proposer])

(defrecord Vote [block-hash epoch voter-signature])
