(ns bitecho.services.turn
  "Pure TURN negotiation protocol using Payment Channels."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.channels.core :as channels]
            [bitecho.crypto :as crypto]))

(defn create-allocation-request
  "Creates a pure data request for a TURN allocation."
  [client-pubkey]
  {:type :turn-allocate-request
   :client-pubkey client-pubkey})

(defn handle-allocation-request
  "Handles an allocation request, returning a granted response with server details and pricing."
  [_request server-pubkey price-per-byte]
  {:type :turn-allocate-granted
   :server-pubkey server-pubkey
   :price-per-byte price-per-byte})

(defn verify-channel-open
  "Verifies that a provided channel state is valid for relaying."
  [state expected-client-pub expected-server-pub min-balance]
  (boolean (and (= expected-client-pub (:pubkey-a state))
                (= expected-server-pub (:pubkey-b state))
                (>= (:balance-a state) min-balance))))

(defn- hash-update
  "Helper to compute the SHA-256 hash of an update map."
  [update-map]
  (let [canonical-map (into (sorted-map) update-map)]
    (crypto/sha256 (.getBytes (pr-str canonical-map) "UTF-8"))))

(defn create-relay-request
  "Client side: Creates a relay request with a signed channel update paying for the data."
  [initial-state data price client-priv]
  (let [cost (* (count data) price)
        update-map {:nonce (inc (:nonce initial-state))
                    :balance-a (- (:balance-a initial-state) cost)
                    :balance-b (+ (:balance-b initial-state) cost)}
        sig-a-bytes (crypto/sign client-priv (hash-update update-map))]
    {:type :turn-relay-request
     :data data
     :update update-map
     :sig-a (basalt/bytes->hex sig-a-bytes)}))

(defn handle-relay-request
  "Server side: Validates a relay request and its payment update.
   Returns `{:valid? true :new-state state :command ...}` on success, or `{:valid? false}`."
  [req initial-state price server-priv]
  (let [{:keys [data update sig-a]} req
        cost (* (count data) price)
        expected-nonce (inc (:nonce initial-state))
        expected-balance-a (- (:balance-a initial-state) cost)
        expected-balance-b (+ (:balance-b initial-state) cost)]
    (if (and (= expected-nonce (:nonce update))
             (= expected-balance-a (:balance-a update))
             (= expected-balance-b (:balance-b update))
             (>= (:balance-a update) 0))
      (let [update-hash (hash-update update)
            pub-a-bytes (basalt/hex->bytes (:pubkey-a initial-state))
            sig-a-bytes (basalt/hex->bytes sig-a)]
        (if (crypto/verify pub-a-bytes update-hash sig-a-bytes)
          (let [sig-b-bytes (crypto/sign server-priv update-hash)
                sig-b (basalt/bytes->hex sig-b-bytes)
                new-state (channels/mutually-sign-update initial-state update sig-a sig-b)]
            {:valid? true
             :new-state new-state
             :command {:type :relay-data :data data}})
          {:valid? false}))
      {:valid? false})))
