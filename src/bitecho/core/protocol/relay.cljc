(ns bitecho.core.protocol.relay
  "Pure Sans-IO HTTP Gateway Relay Protocol (UNIFICATION.md §§4-6, DESIGN.md):
   - Canonical Proof-of-Possession (PoP) poll signing and verification.
   - Pure relay state machine reducer (`reduce-relay`):
     - `:relay-submit`: Enforces payload size, verifies outer Ed25519 signature fail-closed,
       SHA-256 deduplication, and routes to recipient inboxes or broadcast ring.
     - `:relay-poll`: Verifies poll PoP, bounds nonces, and returns unexpired messages & broadcasts.
     - `:relay-ack`: Verifies PoP and prunes recipient inbox up to ack-seq.
   - Rule 1 (Strict TDD & Generative Invariants), Rule 2 (Pure Sans-IO), Rule 5 (Zero Silent Failures)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.sieve.core :as sieve]
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

(defn normalize-pubkey-hex
  "Returns lowercase trimmed pubkey hex string (64 or 88 hex chars), else nil."
  [s]
  (when (and (string? s) (not (str/blank? s)))
    (let [t (str/lower-case (str/trim s))]
      (when (re-matches #"(?:302a300506032b6570032100)?[0-9a-f]{64}" t)
        t))))

;; =============================================================================
;; 1. Relay State Initialization
;; =============================================================================

(defn init-relay-state
  "Initializes pure relay state with configurable limits and default empty collections."
  ([] (init-relay-state {}))
  ([opts]
   {:max-inbox-size (long (or (:max-inbox-size opts) 256))
    :max-broadcast-size (long (or (:max-broadcast-size opts) 256))
    :max-payload-bytes (long (or (:max-payload-bytes opts) 65536))
    :ttl-ms (long (or (:ttl-ms opts) 86400000))
    :max-skew-ms (long (or (:max-skew-ms opts) 300000))
    :max-nonces (long (or (:max-nonces opts) 2048))
    :inboxes {}
    :inbox-seqs {}
    :broadcasts []
    :next-broadcast-seq 0
    :seen-ids {}
    :seen-id-order []
    :max-seen-ids (long (or (:max-seen-ids opts) 4096))
    :used-poll-nonces #{}
    :poll-nonce-order []
    :diagnostics {:submitted 0
                  :duplicates 0
                  :delivered 0
                  :broadcast 0
                  :polled 0
                  :acked 0
                  :rejected 0
                  :too-large 0
                  :malformed 0
                  :invalid-sig 0
                  :auth-failed 0
                  :skew-exceeded 0
                  :replay-rejected 0}}))

;; =============================================================================
;; 2. Canonical Poll Proof-of-Possession (PoP)
;; =============================================================================

(defn poll-signing-str
  "Canonical signing string for HTTP relay poll proof-of-possession (PoP)."
  [pubkey since-seq timestamp-ms nonce]
  (let [pk (str/lower-case (str/trim (str (or pubkey ""))))
        seq-num (long (or since-seq 0))
        ts (long (or timestamp-ms 0))
        n (str (or nonce ""))]
    (str "bitecho-relay-poll-v1|" pk "|" seq-num "|" ts "|" n)))

(defn sign-poll-request
  "Signs a poll request using caller's Ed25519 private key. Returns 128-hex lowercase signature."
  [privkey-bytes {:keys [pubkey since-seq timestamp-ms nonce]}]
  (let [s (poll-signing-str pubkey since-seq timestamp-ms nonce)
        sig (crypto/sign privkey-bytes (fressian/utf8->bytes s))]
    (if (string? sig) sig (basalt/bytes->hex sig))))

(defn verify-poll-request
  "Verifies a canonical poll Proof-of-Possession (PoP) request map against relay state."
  [state {:keys [pubkey since-seq timestamp-ms nonce signature now-ms]}]
  (let [now (long (or now-ms 0))
        ts (long (or timestamp-ms 0))
        max-skew (long (get state :max-skew-ms 300000))
        norm-pk (when pubkey (normalize-pubkey-hex pubkey))
        nonce-str (str (or nonce ""))]
    (cond
      (or (nil? norm-pk) (not (re-matches #"(?:302a300506032b6570032100)?[0-9a-f]{64}" norm-pk)))
      {:ok? false :error :poll-auth-failed :reason :invalid-pubkey}

      (or (str/blank? nonce-str) (str/blank? (str signature)))
      {:ok? false :error :poll-auth-failed :reason :missing-auth-fields}

      (and (pos? now) (pos? ts) (> (Math/abs (- now ts)) max-skew))
      {:ok? false :error :poll-skew-exceeded :skew-ms (Math/abs (- now ts)) :max-skew-ms max-skew}

      (contains? (get state :used-poll-nonces #{}) [norm-pk nonce-str])
      {:ok? false :error :poll-replay-rejected :pubkey norm-pk :nonce nonce-str}

      :else
      (let [signing-str (poll-signing-str norm-pk (or since-seq 0) ts nonce-str)
            sig-bytes (try (basalt/hex->bytes signature) (catch #?(:clj Exception :cljs :default) _ nil))
            valid? (and (some? sig-bytes)
                        (try (crypto/verify norm-pk (fressian/utf8->bytes signing-str) sig-bytes)
                             (catch #?(:clj Exception :cljs :default) _ false)))]
        (if valid?
          {:ok? true :pubkey norm-pk :nonce nonce-str}
          {:ok? false :error :poll-auth-failed :reason :invalid-signature})))))

;; =============================================================================
;; 3. State Machine Helpers (Pure & Bounded)
;; =============================================================================

(defn- record-poll-nonce
  [state pubkey nonce]
  (let [nonces (get state :used-poll-nonces #{})
        nonce-order (get state :poll-nonce-order [])
        pair [pubkey (str nonce)]
        max-n (long (get state :max-nonces 2048))]
    (if (contains? nonces pair)
      state
      (let [new-order (conj nonce-order pair)
            drop-count (max 0 (- (count new-order) max-n))
            trimmed-order (if (pos? drop-count) (subvec new-order drop-count) new-order)
            trimmed-set (set trimmed-order)]
        (assoc state :used-poll-nonces trimmed-set :poll-nonce-order trimmed-order)))))

(defn- record-seen-id
  [state envelope-id now-ms]
  (let [seen (get state :seen-ids {})
        order (get state :seen-id-order [])
        max-ids (long (get state :max-seen-ids 4096))]
    (if (contains? seen envelope-id)
      (assoc-in state [:seen-ids envelope-id] now-ms)
      (let [new-order (conj order envelope-id)
            drop-count (max 0 (- (count new-order) max-ids))
            trimmed-order (if (pos? drop-count) (subvec new-order drop-count) new-order)
            trimmed-seen (reduce (fn [acc id] (assoc acc id (get seen id now-ms))) {} trimmed-order)]
        (assoc state :seen-ids (assoc trimmed-seen envelope-id now-ms)
               :seen-id-order trimmed-order)))))

(defn- verify-envelope-signature
  [env]
  (let [cb (crypto/make-crypto-boundary)
        verified (crypto/pre-verify-envelope cb env)]
    (if (true? (:crypto/verified? verified))
      true
      (if (map? (:message env))
        (some? (sieve/validate-message (:message env)))
        (let [sender (or (:sender env) (:agent-pubkey env) (:from env)
                         (get env "sender") (get env "agent-pubkey") (get env "from"))
              sig (or (:signature env) (:sig env)
                      (get env "signature") (get env "sig"))]
          (and (some? sender) (some? sig)
               (try
                 (let [sig-bytes (if (string? sig) (basalt/hex->bytes sig) sig)]
                   (cond
                     (or (and (:agent-pubkey env) (:event env))
                         (and (get env "agent-pubkey") (get env "event")))
                     (let [ev (or (:event env) (get env "event"))
                           apk (or (:agent-pubkey env) (get env "agent-pubkey"))
                           clean (dissoc ev :sender :sender-pubkey-bytes :rng "sender" "sender-pubkey-bytes" "rng")]
                       (crypto/verify sender
                                      (crypto/canonical-signing-bytes [(or apk "") (crypto/canonicalize-agent-event clean)])
                                      sig-bytes))

                     (or (contains? env :payload) (contains? env "payload"))
                     (let [p (or (:payload env) (get env "payload"))
                           p-bytes (if (bytes? p) p (fressian/utf8->bytes (str p)))
                           burn (or (:burn-amount env) (get env "burn-amount"))
                           payload (if burn
                                     (fressian/concat-bytes p-bytes (fressian/utf8->bytes (str ":burn:" burn)))
                                     p-bytes)]
                       (crypto/verify sender payload sig-bytes))

                     :else
                     (crypto/verify sender (crypto/canonical-signing-bytes env) sig-bytes)))
                 (catch #?(:clj Exception :cljs :default) _ false))))))))

;; =============================================================================
;; 4. Pure Sans-IO Relay Reducer (`reduce-relay`)
;; =============================================================================

(defn reduce-relay
  "Pure Sans-IO HTTP Gateway Relay Reducer (`state + event -> {:state :ok? :response :effects}`)."
  [state event]
  (let [now-ms (long (or (:now-ms event) 0))]
    (case (:type event)
      :relay-submit
      (let [raw-env (:envelope event)
            max-payload (long (get state :max-payload-bytes 65536))
            wire-bytes (cond
                         (bytes? raw-env) raw-env
                         (string? raw-env) (try (basalt/hex->bytes raw-env) (catch #?(:clj Exception :cljs :default) _ nil))
                         (map? raw-env) (try (fressian/encode-canonical raw-env) (catch #?(:clj Exception :cljs :default) _ nil))
                         :else nil)
            payload-size (if wire-bytes (fressian/count-bytes wire-bytes) 0)]
        (cond
          (nil? wire-bytes)
          (let [diag {:effect :diagnose :reason :malformed-envelope :now-ms now-ms}
                new-st (-> state
                           (update-in [:diagnostics :rejected] (fnil inc 0))
                           (update-in [:diagnostics :malformed] (fnil inc 0)))]
            {:state new-st :ok? false :error :malformed-envelope :response {"ok" false "error" "malformed-envelope"} :effects [diag]})

          (> payload-size max-payload)
          (let [diag {:effect :diagnose :reason :payload-too-large :size payload-size :max max-payload :now-ms now-ms}
                new-st (-> state
                           (update-in [:diagnostics :rejected] (fnil inc 0))
                           (update-in [:diagnostics :too-large] (fnil inc 0)))]
            {:state new-st :ok? false :error :payload-too-large :response {"ok" false "error" "payload-too-large"} :effects [diag]})

          :else
          (let [decoded (or (try (fressian/decode-wire wire-bytes) (catch #?(:clj Exception :cljs :default) _ nil))
                            (when (map? raw-env) raw-env))]
            (cond
              (not (map? decoded))
              (let [diag {:effect :diagnose :reason :malformed-envelope :now-ms now-ms}
                    new-st (-> state
                               (update-in [:diagnostics :rejected] (fnil inc 0))
                               (update-in [:diagnostics :malformed] (fnil inc 0)))]
                {:state new-st :ok? false :error :malformed-envelope :response {"ok" false "error" "malformed-envelope"} :effects [diag]})

              (not (verify-envelope-signature decoded))
              (let [sender (or (:sender decoded) (:agent-pubkey decoded))
                    diag {:effect :diagnose :reason :invalid-signature :sender sender :now-ms now-ms}
                    new-st (-> state
                               (update-in [:diagnostics :rejected] (fnil inc 0))
                               (update-in [:diagnostics :invalid-sig] (fnil inc 0)))]
                {:state new-st :ok? false :error :invalid-signature :response {"ok" false "error" "invalid-signature"} :effects [diag]})

              :else
              (let [envelope-id (basalt/bytes->hex (crypto/sha256 wire-bytes))
                    wire-hex (basalt/bytes->hex wire-bytes)]
                (if (contains? (get state :seen-ids {}) envelope-id)
                  {:state (update-in state [:diagnostics :duplicates] (fnil inc 0))
                   :ok? true
                   :duplicate? true
                   :envelope-id envelope-id
                   :response {"ok" true "duplicate" true "envelope_id" envelope-id "status" "duplicate"}
                   :effects []}

                  (let [raw-inner-payload (or (get-in decoded [:event :message :payload])
                                              (get-in decoded [:message :payload]))
                        inner-msg (when (bytes? raw-inner-payload)
                                    (try (fressian/decode-wire raw-inner-payload)
                                         (catch #?(:clj Exception :cljs :default) _ nil)))
                        sender (or (when-let [s (:sender decoded)] (normalize-pubkey-hex s))
                                   (when-let [s (get-in decoded [:message :sender])] (normalize-pubkey-hex s))
                                   (when-let [s (:agent-pubkey decoded)] (normalize-pubkey-hex s))
                                   (when-let [s (:from decoded)] (normalize-pubkey-hex s))
                                   (when-let [s (:caller inner-msg)] (normalize-pubkey-hex s))
                                   (when-let [s (:sender inner-msg)] (normalize-pubkey-hex s)))
                        recipient (or (when-let [r (:recipient decoded)] (normalize-pubkey-hex r))
                                      (when-let [r (get-in decoded [:event :recipient])] (normalize-pubkey-hex r))
                                      (when-let [r (get-in decoded [:event :to])] (normalize-pubkey-hex r))
                                      (when-let [r (get-in decoded [:event :callee])] (normalize-pubkey-hex r))
                                      (when-let [r (get-in decoded [:payload :recipient])] (normalize-pubkey-hex r))
                                      (when-let [r (get-in decoded [:payload :to])] (normalize-pubkey-hex r))
                                      (when-let [r (:recipient inner-msg)] (normalize-pubkey-hex r))
                                      (when-let [r (:to inner-msg)] (normalize-pubkey-hex r))
                                      (when-let [r (:callee inner-msg)] (normalize-pubkey-hex r)))
                        raw-recip (or (:recipient decoded)
                                      (get-in decoded [:event :recipient])
                                      (get-in decoded [:payload :recipient])
                                      (:recipient inner-msg))
                        broadcast? (or (= raw-recip "*")
                                       (nil? recipient)
                                       (= :broadcast (:type decoded))
                                       (= :p2p-broadcast (:type decoded))
                                       (= :broadcast (get-in decoded [:event :type]))
                                       (= :receive-gossip (get-in decoded [:event :type])))
                        from-val? (boolean (:from-validator? event))]
                    (if broadcast?
                      (let [next-bseq (inc (long (get state :next-broadcast-seq 0)))
                            b-entry {:broadcast-seq next-bseq
                                     :broadcast_seq next-bseq
                                     :envelope-id envelope-id
                                     :envelope_id envelope-id
                                     :envelope wire-hex
                                     :envelope-hex wire-hex
                                     :envelope_hex wire-hex
                                     :sender sender
                                     :received-at now-ms
                                     :received_at now-ms}
                            b-ring (conj (or (:broadcasts state) []) b-entry)
                            max-b (long (get state :max-broadcast-size 256))
                            trimmed-b (if (> (count b-ring) max-b)
                                        (subvec b-ring (- (count b-ring) max-b))
                                        b-ring)
                            new-st (-> (record-seen-id state envelope-id now-ms)
                                       (assoc :broadcasts trimmed-b
                                              :next-broadcast-seq next-bseq)
                                       (update-in [:diagnostics :submitted] (fnil inc 0))
                                       (update-in [:diagnostics :broadcast] (fnil inc 0)))
                            eff {:effect :forward-to-validators
                                 :envelope decoded
                                 :wire-bytes wire-bytes
                                 :envelope-id envelope-id
                                 :broadcast? true}]
                        {:state new-st
                         :ok? true
                         :duplicate? false
                         :envelope-id envelope-id
                         :response {"ok" true "envelope_id" envelope-id "seq" next-bseq "broadcast" true "status" "forwarded"}
                         :effects (if from-val? [] [eff])})

                      (let [next-seq (inc (long (get-in state [:inbox-seqs recipient] 0)))
                            ttl-ms (long (get state :ttl-ms 86400000))
                            cutoff-ms (- now-ms ttl-ms)
                            existing-inbox (filterv (fn [e] (>= (long (:received-at e 0)) cutoff-ms))
                                                    (get-in state [:inboxes recipient] []))
                            new-entry {:relay-seq next-seq
                                       :relay_seq next-seq
                                       :envelope-id envelope-id
                                       :envelope_id envelope-id
                                       :envelope wire-hex
                                       :envelope-hex wire-hex
                                       :envelope_hex wire-hex
                                       :sender sender
                                       :recipient recipient
                                       :received-at now-ms
                                       :received_at now-ms}
                            new-inbox (conj existing-inbox new-entry)
                            max-inbox (long (get state :max-inbox-size 256))
                            trimmed-inbox (if (> (count new-inbox) max-inbox)
                                            (subvec new-inbox (- (count new-inbox) max-inbox))
                                            new-inbox)
                            new-st (-> (record-seen-id state envelope-id now-ms)
                                       (assoc-in [:inboxes recipient] trimmed-inbox)
                                       (assoc-in [:inbox-seqs recipient] next-seq)
                                       (update-in [:diagnostics :submitted] (fnil inc 0))
                                       (update-in [:diagnostics :delivered] (fnil inc 0)))
                            eff {:effect :forward-to-validators
                                 :envelope decoded
                                 :wire-bytes wire-bytes
                                 :envelope-id envelope-id
                                 :recipient recipient
                                 :sender sender
                                 :broadcast? false}]
                        {:state new-st
                         :ok? true
                         :duplicate? false
                         :envelope-id envelope-id
                         :response {"ok" true "envelope_id" envelope-id "seq" next-seq "recipient" recipient "broadcast" false "status" "accepted"}
                         :effects (if from-val? [] [eff])})))))))))

      :relay-poll
      (let [v (verify-poll-request state event)]
        (if-not (:ok? v)
          (let [diag {:effect :diagnose :reason (:error v) :pubkey (:pubkey event) :now-ms now-ms}
                new-st (-> state
                           (update-in [:diagnostics :rejected] (fnil inc 0))
                           (cond->
                            (= :poll-auth-failed (:error v)) (update-in [:diagnostics :auth-failed] (fnil inc 0))
                            (= :poll-skew-exceeded (:error v)) (update-in [:diagnostics :skew-exceeded] (fnil inc 0))
                            (= :poll-replay-rejected (:error v)) (update-in [:diagnostics :replay-rejected] (fnil inc 0))))]
            {:state new-st
             :ok? false
             :error (:error v)
             :response {"ok" false "error" (name (:error v))}
             :effects [diag]})

          (let [norm-pk (:pubkey v)
                nonce (:nonce v)
                state-with-nonce (record-poll-nonce state norm-pk nonce)
                since-seq (long (or (:since-seq event) 0))
                since-bseq (long (or (:since-broadcast-seq event) 0))
                ttl-ms (long (get state :ttl-ms 86400000))
                cutoff-ms (- now-ms ttl-ms)
                inbox (filterv (fn [e] (and (> (long (:relay-seq e)) since-seq)
                                            (>= (long (:received-at e 0)) cutoff-ms)))
                               (get-in state [:inboxes norm-pk] []))
                bcasts (filterv (fn [e] (> (long (:broadcast-seq e)) since-bseq))
                                (get state :broadcasts []))
                new-st (update-in state-with-nonce [:diagnostics :polled] (fnil inc 0))]
            {:state new-st
             :ok? true
             :response {"ok" true
                        "pubkey" norm-pk
                        "messages" inbox
                        "broadcasts" bcasts}
             :effects []})))

      :relay-ack
      (let [ack-seq (long (or (:ack-seq event) 0))
            pop-event (assoc event :since-seq ack-seq)
            v (verify-poll-request state pop-event)]
        (if-not (:ok? v)
          (let [diag {:effect :diagnose :reason (:error v) :pubkey (:pubkey event) :now-ms now-ms}
                new-st (-> state
                           (update-in [:diagnostics :rejected] (fnil inc 0))
                           (cond->
                            (= :poll-auth-failed (:error v)) (update-in [:diagnostics :auth-failed] (fnil inc 0))
                            (= :poll-skew-exceeded (:error v)) (update-in [:diagnostics :skew-exceeded] (fnil inc 0))
                            (= :poll-replay-rejected (:error v)) (update-in [:diagnostics :replay-rejected] (fnil inc 0))))]
            {:state new-st
             :ok? false
             :error (:error v)
             :response {"ok" false "error" (name (:error v))}
             :effects [diag]})

          (let [norm-pk (:pubkey v)
                nonce (:nonce v)
                state-with-nonce (record-poll-nonce state norm-pk nonce)
                existing-inbox (get-in state [:inboxes norm-pk] [])
                new-inbox (filterv (fn [e] (> (long (:relay-seq e)) ack-seq)) existing-inbox)
                pruned-count (- (count existing-inbox) (count new-inbox))
                new-st (-> state-with-nonce
                           (assoc-in [:inboxes norm-pk] new-inbox)
                           (update-in [:diagnostics :acked] (fnil inc 0)))]
            {:state new-st
             :ok? true
             :response {"ok" true
                        "pubkey" norm-pk
                        "acked_seq" ack-seq
                        "pruned" pruned-count}
             :effects []})))

      (let [diag {:effect :diagnose :reason :unknown-relay-event :event-type (:type event) :now-ms now-ms}]
        {:state state
         :ok? false
         :error :unknown-relay-event
         :response {"ok" false "error" "unknown-relay-event"}
         :effects [diag]}))))
