(ns bitecho.core.protocol.faucet
  "Pure Sans-IO Treasury-Managed Faucet Protocol (Milestone D26 — F-D26-11/12, A-D26-3, A-CARB-D26-5).

   The Faucet is outside core consensus (does not mint extra emission).
   It issues standard signed transfer intents from the Treasury keypair upon
   WebAuthn/FIDO2 hardware key attestation. Challenge TTL is 60s single-use,
   and duplicate claims against credential IDs are rejected using fractal
   Blob/Pointer receipts (faucet/<network-uri>/claims/<credential-id-hash>)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn now-timestamp-ms
  "Current wall-clock milliseconds."
  []
  #?(:clj (System/currentTimeMillis)
     :cljs (.now js/Date)))

(defn init-faucet-state
  "Initializes pure Sans-IO Faucet protocol state."
  ([] (init-faucet-state {}))
  ([opts]
   {:network-uri         (or (:network-uri opts) "devnet.bitecho.org")
    :treasury-privkey    (:treasury-privkey opts)
    :treasury-pubkey     (:treasury-pubkey opts)
    :drip-amount-ech     (or (:drip-amount-ech opts) 1000000)
    :challenge-ttl-ms    (or (:challenge-ttl-ms opts) 60000)
    :challenges          {}
    :claimed-credentials (set (or (:claimed-credentials opts) #{}))
    :receipts            (or (:receipts opts) {})
    :diagnostics         (or (:diagnostics opts) {})}))

(defn issue-faucet-challenge
  "Issues a 60s single-use WebAuthn challenge bound to the specified network URI."
  ([state req]
   (issue-faucet-challenge state req (now-timestamp-ms)))
  ([state req now-ms]
   (let [ttl (or (:challenge-ttl-ms state) 60000)
         net-uri (or (:network-uri req) (:network-uri state) "devnet.bitecho.org")
         nonce (or (:nonce req) (basalt/bytes->hex (crypto/random-bytes 16)))
         challenge {:nonce      nonce
                    :network-uri net-uri
                    :created-at (long now-ms)
                    :expires-at (+ (long now-ms) (long ttl))}]
     {:state     (assoc-in state [:challenges nonce] challenge)
      :challenge challenge})))

(defn reduce-faucet-claim
  "Pure reducer for a faucet claim request.
   Verifies challenge existence, network binding, expiration, duplicate credentials,
   and optional authenticator verification.
   Returns {:ok? true/false :state ... :transfer-intent ... :receipt-path ... :error ...}."
  ([state claim-req]
   (reduce-faucet-claim state claim-req (now-timestamp-ms)))
  ([state claim-req now-ms]
   (let [nonce (:nonce claim-req)
         challenge (get-in state [:challenges nonce])
         claim-net-uri (or (:network-uri claim-req) (:network-uri state))
         cred-hash (:credential-id-hash claim-req)]
     (cond
       ;; Missing or mismatched challenge
       (or (nil? challenge)
           (and claim-net-uri
                (:network-uri challenge)
                (not= claim-net-uri (:network-uri challenge))))
       {:ok?    false
        :error  :faucet-claim-rejected
        :reason "invalid-challenge"
        :state  (update-in state [:diagnostics :faucet-claim-rejected] (fnil inc 0))}

       ;; Expired challenge
       (> (long now-ms) (long (:expires-at challenge)))
       {:ok?    false
        :error  :faucet-challenge-expired
        :reason "challenge-expired"
        :state  (-> state
                    (update :challenges dissoc nonce)
                    (update-in [:diagnostics :faucet-challenge-expired] (fnil inc 0)))}

       ;; Already claimed credential ID
       (or (contains? (:claimed-credentials state) cred-hash)
           (contains? (:receipts state) cred-hash))
       {:ok?    false
        :error  :faucet-credential-already-claimed
        :reason "credential-already-claimed"
        :state  (-> state
                    (update :challenges dissoc nonce)
                    (update-in [:diagnostics :faucet-credential-already-claimed] (fnil inc 0)))}

       ;; Explicitly failed authenticator verification
       (and (contains? claim-req :authenticator-verified?)
            (not (:authenticator-verified? claim-req)))
       {:ok?    false
        :error  :faucet-claim-rejected
        :reason "authenticator-verification-failed"
        :state  (-> state
                    (update :challenges dissoc nonce)
                    (update-in [:diagnostics :faucet-claim-rejected] (fnil inc 0)))}

       ;; Valid claim
       :else
       (let [drip-amount (or (:drip-amount-ech state) 1000000)
             net-uri (or claim-net-uri (:network-uri challenge) (:network-uri state) "devnet.bitecho.org")
             receipt-path (str "faucet/" net-uri "/claims/" cred-hash)
             transfer-intent {:from        (:treasury-pubkey state)
                              :to          (:claimant-pubkey claim-req)
                              :amount      drip-amount
                              :memo        receipt-path
                              :network-uri net-uri}
             receipt {:claimed-at   (long now-ms)
                      :claimant     (:claimant-pubkey claim-req)
                      :amount       drip-amount
                      :receipt-path receipt-path}]
         {:ok?             true
          :transfer-intent transfer-intent
          :receipt-path    receipt-path
          :state           (-> state
                               (update :challenges dissoc nonce)
                               (update :claimed-credentials (fnil conj #{}) cred-hash)
                               (assoc-in [:receipts cred-hash] receipt))})))))
