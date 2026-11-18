(ns bitecho.core.protocol.faucet
  "Pure Sans-IO Treasury-Managed Faucet Protocol (Milestone D26 & D32 / BIP-006 Part 3).

   The Faucet is outside core consensus (does not mint extra emission).
   It issues standard signed transfer intents from the Treasury keypair upon
   WebAuthn/FIDO2 hardware key attestation. Challenge TTL is 60s single-use,
   and duplicate claims against credential IDs are rejected using fractal
   Blob/Pointer receipts (faucet/<network-uri>/claims/<credential-id-hash>)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

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
    :claim-seq           (long (or (:claim-seq opts) 0))
    :challenges          {}
    :claimed-credentials (set (or (:claimed-credentials opts) #{}))
    :receipts            (or (:receipts opts) {})
    :blobs               (or (:blobs opts) {})
    :pointers            (or (:pointers opts) {})
    :diagnostics         (or (:diagnostics opts) {})}))

(defn issue-faucet-challenge
  "Issues a 60s single-use WebAuthn challenge bound to the specified network URI."
  ([state req]
   (issue-faucet-challenge state req (now-timestamp-ms)))
  ([state req now-ms]
   (let [ttl (or (:challenge-ttl-ms state) 60000)
         net-uri (or (:network-uri req) (:network-uri state) "devnet.bitecho.org")
         nonce (or (:nonce req) (basalt/bytes->hex (crypto/random-bytes 16)))
         challenge {:nonce       nonce
                    :network-uri net-uri
                    :created-at  (long now-ms)
                    :expires-at  (+ (long now-ms) (long ttl))}]
     {:state     (assoc-in state [:challenges nonce] challenge)
      :challenge challenge})))

(defn- valid-claimant-pubkey?
  [pk]
  (and (string? pk)
       (boolean (re-matches #"(?i)^(?:[0-9a-f]{64}|302a300506032b6570032100[0-9a-f]{64})$" (str/trim pk)))))

(defn reduce-faucet-claim
  "Pure reducer for a faucet claim request.
   Verifies challenge existence, network binding, expiration, duplicate credentials,
   and optional authenticator verification.
   Produces a fractal Blob/Pointer receipt at `faucet/<network-uri>/claims/<credential-id-hash>`
   and (when `:treasury-privkey` and `:treasury-pubkey` are present) a cryptographically signed
   transfer map and signed Pointer.
   Returns {:ok? true/false :state ... :transfer-intent ... :receipt-path ... :receipt-cid ... :error ...}."
  ([state claim-req]
   (reduce-faucet-claim state claim-req (now-timestamp-ms)))
  ([state claim-req now-ms]
   (let [nonce (:nonce claim-req)
         challenge (get-in state [:challenges nonce])
         claim-net-uri (or (:network-uri claim-req) (:network-uri state))
         cred-hash (when (string? (:credential-id-hash claim-req))
                     (str/trim (:credential-id-hash claim-req)))
         claimant-pk (when (string? (:claimant-pubkey claim-req))
                       (str/lower-case (str/trim (:claimant-pubkey claim-req))))]
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

       ;; Invalid claimant pubkey or credential-id-hash
       (or (str/blank? cred-hash)
           (not (valid-claimant-pubkey? claimant-pk)))
       {:ok?    false
        :error  :faucet-claim-rejected
        :reason "invalid-claim-parameters"
        :state  (-> state
                    (update :challenges dissoc nonce)
                    (update-in [:diagnostics :faucet-claim-rejected] (fnil inc 0)))}

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
       (let [drip-amount (long (or (:drip-amount-ech state) 1000000))
             net-uri (or claim-net-uri (:network-uri challenge) (:network-uri state) "devnet.bitecho.org")
             receipt-path (str "faucet/" net-uri "/claims/" cred-hash)
             next-seq (inc (long (or (:claim-seq state) 0)))
             treasury-pk (when (string? (:treasury-pubkey state))
                           (str/lower-case (str/trim (:treasury-pubkey state))))
             treasury-sk (:treasury-privkey state)
             transfer-intent {:from        treasury-pk
                              :to          claimant-pk
                              :amount      drip-amount
                              :seq         next-seq
                              :memo        receipt-path
                              :network-uri net-uri}
             receipt {:claimed-at         (long now-ms)
                      :claimant           claimant-pk
                      :credential-id-hash cred-hash
                      :amount             drip-amount
                      :seq                next-seq
                      :network-uri        net-uri
                      :receipt-path       receipt-path}
             receipt-blob (data/make-blob (fressian/utf8->bytes (pr-str receipt)) "application/edn")
             receipt-cid (:blob/cid receipt-blob)
             receipt-ptr (when (and treasury-sk treasury-pk)
                           (data/sign-pointer
                            treasury-sk
                            {:pointer/authority   treasury-pk
                             :pointer/subnet      net-uri
                             :pointer/path        receipt-path
                             :pointer/seq         1
                             :pointer/leader-term 1
                             :pointer/target      receipt-cid
                             :pointer/proof       {:proof/type :self}}))
             signed-transfer (when (and treasury-sk treasury-pk)
                               (let [unsigned {:sender      treasury-pk
                                               :receiver    claimant-pk
                                               :amount      drip-amount
                                               :seq         next-seq
                                               :deps        []
                                               :network-uri net-uri}
                                     tf (account/create-transfer treasury-sk unsigned)]
                                 (into {} tf)))]
         (cond-> {:ok?             true
                  :transfer-intent transfer-intent
                  :receipt-path    receipt-path
                  :receipt-cid     receipt-cid
                  :receipt         receipt
                  :receipt-blob    receipt-blob
                  :state           (-> state
                                       (assoc :claim-seq next-seq)
                                       (update :challenges dissoc nonce)
                                       (update :claimed-credentials (fnil conj #{}) cred-hash)
                                       (assoc-in [:receipts cred-hash] receipt)
                                       (assoc-in [:blobs receipt-cid] receipt-blob)
                                       (cond-> receipt-ptr
                                         (assoc-in [:pointers [net-uri receipt-path]] receipt-ptr)))}
           receipt-ptr (assoc :receipt-pointer receipt-ptr)
           signed-transfer (assoc :signed-transfer signed-transfer)))))))
