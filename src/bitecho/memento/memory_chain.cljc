(ns bitecho.memento.memory-chain
  "BIP-C: Encrypted Hash-Linked Memory Chain.
   Pure Sans-IO .cljc core:
   - Canonical framing: be64(seq) || raw32(prev-cid) || be32(len) || ciphertext
   - CID = lowercase hex SHA-256 of canonical frame
   - Canonical HKDF info, AAD, and Genesis signing-message builders
   - Pure write reducer enforcing CAS-before-encrypt and zero secret bytes in effects
   - Streaming constant-memory walk-back reducer with configurable depth cap (default 1024)
     and counted :diagnose on every fault."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.memento.constants :as mc]))

;; =============================================================================
;; Canonical Cryptographic Input Builders (Pure .cljc)
;; =============================================================================

(defn aead-key-info
  "HKDF info bytes for AES-256-GCM key derivation: utf8(\"bitecho/memento/aead/v1\")."
  []
  (fressian/utf8->bytes mc/memory-aead-info))

(defn nonce-info
  "HKDF info bytes for 12-byte GCM nonce: utf8(\"bitecho/memento/nonce/v1\") || be64(seq)."
  [seq-num]
  (fressian/concat-bytes
   (fressian/utf8->bytes mc/memory-nonce-info)
   (mc/be64-bytes seq-num)))

(defn aad-bytes
  "AEAD Associated Data: utf8(\"bitecho/memento/aad/v1\") || be64(seq) || raw32(prev-cid)."
  [seq-num prev-cid-hex]
  (let [prev32 (fressian/hex->bytes prev-cid-hex)]
    (when (not= 32 (fressian/count-bytes prev32))
      (throw (ex-info "prev-cid must decode to 32 raw bytes" {:prev-cid prev-cid-hex})))
    (fressian/concat-bytes
     (fressian/utf8->bytes mc/memory-aad-prefix)
     (mc/be64-bytes seq-num)
     prev32)))

(defn genesis-message-bytes
  "Genesis signature input: utf8(\"bitecho/memento/genesis/v1\") || raw32(pubkey)."
  [pubkey-raw32]
  (when (not= 32 (fressian/count-bytes pubkey-raw32))
    (throw (ex-info "pubkey-raw32 must be exactly 32 bytes"
                    {:actual-len (fressian/count-bytes pubkey-raw32)})))
  (fressian/concat-bytes
   (fressian/utf8->bytes mc/memory-genesis-prefix)
   pubkey-raw32))

;; =============================================================================
;; Canonical Framing & CID (Pure .cljc)
;; =============================================================================

(defn frame-cid
  "Computes the lowercase 64-char hex SHA-256 CID of a canonical memory frame."
  [frame-bytes]
  (crypto/sha256-hex frame-bytes))

(defn encode-frame
  "Encodes canonical memory frame: be64(seq) || raw32(prev-cid) || be32(len) || ciphertext.
   Enforces pre-decode/encode blob ceiling (256 KiB)."
  [seq-num prev-cid-hex ciphertext-bytes]
  (let [prev32 (fressian/hex->bytes prev-cid-hex)
        ct-len (fressian/count-bytes ciphertext-bytes)
        total-len (+ mc/frame-header-bytes ct-len)]
    (when (not= 32 (fressian/count-bytes prev32))
      (throw (ex-info "prev-cid must be 32 raw bytes" {:prev-cid prev-cid-hex})))
    (when (> total-len mc/max-blob-bytes)
      (throw (ex-info "Frame exceeds 256 KiB blob ceiling"
                      {:total-len total-len :ceiling mc/max-blob-bytes})))
    (fressian/concat-bytes
     (mc/be64-bytes seq-num)
     prev32
     (mc/be32-bytes ct-len)
     ciphertext-bytes)))

(defn decode-frame
  "Decodes canonical memory frame checking pre-decode ceiling (256 KiB) BEFORE slicing.
   Returns {:ok? true :seq :prev-cid :len :ciphertext :cid} or {:ok? false :code :diagnose}."
  [frame-bytes]
  (let [total-len (if (fressian/bytes? frame-bytes)
                    (fressian/count-bytes frame-bytes)
                    -1)]
    (cond
      (< total-len 0)
      {:ok? false :code :invalid-frame-type}

      (> total-len mc/max-blob-bytes)
      {:ok? false
       :code :blob-ceiling-exceeded
       :declared-bytes total-len
       :ceiling mc/max-blob-bytes}

      (< total-len mc/frame-header-bytes)
      {:ok? false
       :code :truncated-frame
       :actual-bytes total-len}

      :else
      (let [seq-num (mc/read-be64 frame-bytes 0)
            prev-raw (mc/slice-bytes frame-bytes 8 32)
            ct-len (mc/read-be32 frame-bytes 40)
            expected-total (+ mc/frame-header-bytes ct-len)]
        (cond
          (> expected-total mc/max-blob-bytes)
          {:ok? false
           :code :blob-ceiling-exceeded
           :declared-bytes expected-total
           :ceiling mc/max-blob-bytes}

          (not= expected-total total-len)
          {:ok? false
           :code :frame-length-mismatch
           :declared-ct-len ct-len
           :actual-bytes total-len}

          :else
          {:ok? true
           :seq seq-num
           :prev-cid (fressian/bytes->hex prev-raw)
           :len ct-len
           :ciphertext (mc/slice-bytes frame-bytes mc/frame-header-bytes ct-len)
           :cid (frame-cid frame-bytes)})))))

;; =============================================================================
;; BIP-016 Memento Head Pointer Descriptor (Encrypted Memory Continuity)
;; =============================================================================

(defn make-memento-pointer
  "Creates a minimal :memento/head-pointer descriptor pointing to the latest
   encrypted memory CID in the network, carrying explicit owner(s), retention
   policy, and bytes-at-rest storage accounting."
  [{:keys [head-cid seq gen owner-pubkeys retention-policy storage-accounting]}]
  {:pointer/type :memento/head-pointer
   :head-cid head-cid
   :seq (long (or seq 0))
   :gen (long (or gen 0))
   :encrypted? true
   :owner-pubkeys (when (some? owner-pubkeys) (vec owner-pubkeys))
   :retention-policy retention-policy
   :storage-accounting storage-accounting})

(defn validate-memento-pointer
  "Validates a :memento/head-pointer against BIP-016 state discipline:
   must be encrypted, point to a valid 64-char CID, and satisfy owner, retention,
   and storage-accounting invariants. Emits counted :diagnose on violation."
  [ptr]
  (let [disc (mc/validate-pointer-discipline ptr)]
    (cond
      (not= :memento/head-pointer (:pointer/type ptr))
      {:ok? false :diagnose {:type :diagnose :code :invalid-memento-pointer-type :count 1}}

      (not (true? (:encrypted? ptr)))
      {:ok? false :diagnose {:type :diagnose :code :unencrypted-memory-rejected :count 1}}

      (not (mc/valid-cid64? (:head-cid ptr)))
      {:ok? false :diagnose {:type :diagnose :code :invalid-head-cid :head-cid (:head-cid ptr) :count 1}}

      (not (:ok? disc))
      {:ok? false :diagnose (merge {:type :diagnose :code (:code disc) :count 1} (:detail disc))}

      (not (mc/valid-storage-accounting? (:storage-accounting ptr)))
      {:ok? false :diagnose {:type :diagnose :code :invalid-storage-accounting :count 1}}

      :else
      {:ok? true})))

;; =============================================================================
;; Pure Sans-IO Write Reducer (Single-Authority Head Record + CAS-Before-Encrypt)
;; =============================================================================

(defn init-chain
  "Initializes a pure generation-tagged Memory Chain writer state.
   Accepts optional runtime config map loaded from network storage."
  ([] (init-chain nil))
  ([config]
   {:phase :idle
    :generation 0
    :owner-pubkeys (:owner-pubkeys config)
    :retention-policy (:retention-policy config)
    :head {:seq 0 :head-cid mc/zero-cid-hex :gen 0}
    :total-bytes-at-rest 0
    :pending nil
    :last-error nil
    :dropped 0
    :diagnostics-count 0}))

(defn- halt-chain
  [chain code detail]
  (let [next-count (inc (:diagnostics-count chain))
        diag (merge {:type :diagnose
                     :code code
                     :generation (:generation chain)
                     :count next-count}
                    detail)]
    [(assoc chain
            :phase :halted
            :pending nil
            :last-error diag
            :diagnostics-count next-count)
     [diag]]))

(defn- drop-stale-chain-cb
  [chain cb-gen event-type]
  (let [next-dropped (inc (:dropped chain))
        next-count (inc (:diagnostics-count chain))
        diag {:type :diagnose
              :code :stale-generation
              :event-type event-type
              :callback-gen cb-gen
              :current-gen (:generation chain)
              :dropped next-dropped
              :count next-count}]
    [(assoc chain
            :dropped next-dropped
            :diagnostics-count next-count)
     [diag]]))

(defn transition
  "Pure Sans-IO write reducer for BIP-C Memory Chain.
   Enforces :cas-head BEFORE :encrypt, :cas-put, or :emit. Zero secret bytes in effects."
  [chain event]
  (case (:type event)
    :propose-memory
    (let [acct (:storage-accounting event)
          policy (:retention-policy chain)
          plaintext (:plaintext-bytes event)
          pt-len (fressian/count-bytes plaintext)
          est-frame-bytes (+ mc/frame-header-bytes pt-len 16)
          projected-bytes (+ (long (or (:total-bytes-at-rest chain) 0))
                             (long (or (:bytes-at-rest acct) est-frame-bytes)))]
      (cond
        (not= :idle (:phase chain))
        (halt-chain chain :writer-not-idle {:current-phase (:phase chain)})

        (> est-frame-bytes mc/max-blob-bytes)
        (halt-chain chain :blob-ceiling-exceeded {:plaintext-bytes pt-len :ceiling mc/max-blob-bytes})

        (and (some? acct) (not (mc/valid-storage-accounting? acct)))
        (halt-chain chain :invalid-storage-accounting {:storage-accounting acct})

        (and policy (> projected-bytes (:max-bytes policy)))
        (halt-chain chain :retention-bound-exceeded
                    {:projected-bytes projected-bytes :max-bytes (:max-bytes policy)})

        :else
        (let [head (:head chain)
              next-seq (inc (:seq head))
              next-gen (inc (:generation chain))
              prev-cid (:head-cid head)]
          [(assoc chain
                  :phase :claiming-cas
                  :generation next-gen
                  :pending {:seq next-seq
                            :gen next-gen
                            :prev-cid prev-cid
                            :plaintext-bytes plaintext
                            :storage-accounting acct})
           [{:type :cas-head
             :gen next-gen
             :expected-head head
             :claimed-head {:seq next-seq :head-cid nil :gen next-gen}}]])))

    :cas-head-result
    (let [cb-gen (:gen event)]
      (cond
        (< cb-gen (:generation chain))
        (drop-stale-chain-cb chain cb-gen :cas-head-result)

        (not= :claiming-cas (:phase chain))
        (halt-chain chain :unexpected-cas-head-result {:phase (:phase chain)})

        (not (:ok? event))
        (halt-chain chain :cas-head-lost {:reason (:reason event)})

        :else
        (let [p (:pending chain)
              aad (aad-bytes (:seq p) (:prev-cid p))]
          [(assoc chain :phase :awaiting-encrypt)
           [{:type :encrypt
             :gen cb-gen
             :seq (:seq p)
             :prev-cid (:prev-cid p)
             :aad aad
             :plaintext-bytes (:plaintext-bytes p)}]])))

    :encrypt-result
    (let [cb-gen (:gen event)]
      (cond
        (< cb-gen (:generation chain))
        (drop-stale-chain-cb chain cb-gen :encrypt-result)

        (not= :awaiting-encrypt (:phase chain))
        (halt-chain chain :unexpected-encrypt-result {:phase (:phase chain)})

        (not (:ok? event))
        (halt-chain chain :encrypt-failed {:error (:error event)})

        :else
        (let [p (:pending chain)
              frame (encode-frame (:seq p) (:prev-cid p) (:ciphertext-bytes event))
              cid (frame-cid frame)]
          [(assoc chain
                  :phase :awaiting-put
                  :pending (assoc p :cid cid :frame-bytes frame))
           [{:type :cas-put
             :gen cb-gen
             :seq (:seq p)
             :cid cid
             :frame-bytes frame
             :declared-bytes (fressian/count-bytes frame)}]])))

    :cas-put-result
    (let [cb-gen (:gen event)]
      (cond
        (< cb-gen (:generation chain))
        (drop-stale-chain-cb chain cb-gen :cas-put-result)

        (not= :awaiting-put (:phase chain))
        (halt-chain chain :unexpected-cas-put-result {:phase (:phase chain)})

        (not (:ok? event))
        (halt-chain chain :cas-put-failed {:error (:error event)})

        :else
        (let [p (:pending chain)
              frame-bytes (long (or (get-in p [:storage-accounting :bytes-at-rest])
                                    (fressian/count-bytes (:frame-bytes p))))
              next-bytes (+ (long (or (:total-bytes-at-rest chain) 0)) frame-bytes)
              new-head {:seq (:seq p) :head-cid (:cid p) :gen cb-gen}]
          [(assoc chain
                  :phase :idle
                  :pending nil
                  :head new-head
                  :total-bytes-at-rest next-bytes)
           [{:type :emit
             :gen cb-gen
             :seq (:seq p)
             :cid (:cid p)
             :head new-head
             :total-bytes-at-rest next-bytes}]])))

    (halt-chain chain :unknown-event {:event-type (:type event)})))

;; =============================================================================
;; BIP-016 R2: Rotation Grace Window & Deterministic :grace-expired Recovery
;; =============================================================================

(defn evaluate-wake-grace
  "Evaluates whether a sleeping agent waking at current-epoch is within the pinned
   rotation grace window N (with hardcoded floor N-min = 4).
   - Within N: returns {:status :within-grace ... :effects []}.
   - Past N: emits counted :diagnose :grace-expired and deterministically selects
     newest reachable :memento/head-pointer or checksum-verified .lkg fallback."
  [{:keys [last-seen-epoch current-epoch grace-epochs pinned-config-cid
           newest-head-cid lkg-pointer]}]
  (let [eff-n (max mc/min-rotation-grace-epochs (long (or grace-epochs mc/min-rotation-grace-epochs)))
        elapsed (max 0 (- (long current-epoch) (long last-seen-epoch)))]
    (if (<= elapsed eff-n)
      {:status :within-grace
       :elapsed-epochs elapsed
       :grace-epochs eff-n
       :pinned-config-cid pinned-config-cid
       :effects []}
      (let [head-valid? (mc/valid-cid64? newest-head-cid)
            lkg-valid? (and (map? lkg-pointer)
                            (true? (:checksum-verified? lkg-pointer))
                            (mc/valid-cid64? (:snapshot-cid lkg-pointer)))
            target (cond
                     head-valid? :memento-head-pointer
                     lkg-valid? :lkg-pointer
                     :else :no-verified-recovery-target)
            recovery-cid (case target
                           :memento-head-pointer newest-head-cid
                           :lkg-pointer (:snapshot-cid lkg-pointer)
                           nil)
            diag {:type :diagnose
                  :code :grace-expired
                  :elapsed-epochs elapsed
                  :grace-epochs eff-n
                  :pinned-config-cid pinned-config-cid
                  :recovery-target target
                  :recovery-cid recovery-cid
                  :count 1}]
        {:status :grace-expired
         :elapsed-epochs elapsed
         :grace-epochs eff-n
         :pinned-config-cid pinned-config-cid
         :recovery-target target
         :recovery-cid recovery-cid
         :effects [diag]}))))

;; =============================================================================
;; Streaming Constant-Memory Walk-Back Reducer
;; =============================================================================

(defn init-walk-back
  "Initializes a constant-memory streaming walk-back state from head-cid to genesis.
   Does NOT retain raw blob ciphertexts across steps."
  [{:keys [head-cid depth-cap generation pubkey-raw32]}]
  {:phase :walking ;; :walking | :complete | :halted
   :generation (long (or generation 1))
   :depth-cap (long (or depth-cap mc/default-walk-back-depth-cap))
   :expected-cid head-cid
   :expected-seq nil
   :pubkey-raw32 pubkey-raw32
   :walked-count 0
   :genesis-verified? false
   :last-error nil
   :dropped 0
   :diagnostics-count 0})

(defn- halt-walk
  [ws code detail]
  (let [next-count (inc (:diagnostics-count ws))
        diag (merge {:type :diagnose
                     :code code
                     :generation (:generation ws)
                     :walked-count (:walked-count ws)
                     :count next-count}
                    detail)]
    [(assoc ws
            :phase :halted
            :last-error diag
            :diagnostics-count next-count)
     [diag]]))

(defn walk-back-step
  "Processes one streamed :blob-fetched event in constant memory.
   Halts with counted :diagnose on missing blob, AEAD tag failure, stale generation,
   forked :prev-cid, key loss, bad genesis signature, ceiling breach, or depth cap exceeded."
  [ws event]
  (let [cb-gen (long (or (:gen event) 0))
        curr-gen (:generation ws)]
    (cond
      (not= :walking (:phase ws))
      (halt-walk ws :walk-not-active {:phase (:phase ws)})

      (< cb-gen curr-gen)
      (let [next-dropped (inc (:dropped ws))
            next-count (inc (:diagnostics-count ws))
            diag {:type :diagnose
                  :code :stale-generation
                  :callback-gen cb-gen
                  :current-gen curr-gen
                  :dropped next-dropped
                  :count next-count}]
        [(assoc ws
                :dropped next-dropped
                :diagnostics-count next-count)
         [diag]])

      (and (not (:found? event)) (true? (:grace-expired? event)))
      (let [next-count (inc (:diagnostics-count ws))
            newest-head (:newest-head-cid event)
            lkg-ptr (:lkg-pointer event)
            head-valid? (mc/valid-cid64? newest-head)
            lkg-valid? (and (map? lkg-ptr)
                            (true? (:checksum-verified? lkg-ptr))
                            (mc/valid-cid64? (:snapshot-cid lkg-ptr)))
            recovery-eff (cond
                           head-valid?
                           {:type :resync-from-head
                            :gen curr-gen
                            :head-cid newest-head}

                           lkg-valid?
                           {:type :resync-from-lkg
                            :gen curr-gen
                            :snapshot-cid (:snapshot-cid lkg-ptr)}

                           :else nil)
            diag {:type :diagnose
                  :code :grace-expired
                  :generation curr-gen
                  :cid (:cid event)
                  :elapsed-epochs (:elapsed-epochs event)
                  :grace-epochs (max mc/min-rotation-grace-epochs
                                     (long (or (:grace-epochs event) mc/min-rotation-grace-epochs)))
                  :pinned-config-cid (:pinned-config-cid event)
                  :recovery-target (cond head-valid? :memento-head-pointer
                                         lkg-valid? :lkg-pointer
                                         :else :none)
                  :count next-count}]
        [(assoc ws
                :phase :resync-required
                :last-error diag
                :diagnostics-count next-count)
         (cond-> [diag]
           (some? recovery-eff) (conj recovery-eff))])

      (not (:found? event))
      (halt-walk ws :missing-blob {:cid (:cid event)})

      (:key-lost? event)
      (halt-walk ws :key-loss {:cid (:cid event)})

      (and (:frame-bytes event) (> (fressian/count-bytes (:frame-bytes event)) mc/max-blob-bytes))
      (halt-walk ws :blob-ceiling-exceeded
                 {:cid (:cid event)
                  :declared-bytes (fressian/count-bytes (:frame-bytes event))
                  :ceiling mc/max-blob-bytes})

      (not (:aead-ok? event))
      (halt-walk ws :aead-tag-failure {:cid (:cid event)})

      (not= (:cid event) (:expected-cid ws))
      (halt-walk ws :forked-prev-cid
                 {:expected-cid (:expected-cid ws) :actual-cid (:cid event)})

      :else
      (let [link-seq (long (:seq event))
            prev-cid (:prev-cid event)
            expected-seq (:expected-seq ws)
            next-walked (inc (:walked-count ws))]
        (cond
          (and (some? expected-seq) (not= link-seq expected-seq))
          (halt-walk ws :forked-prev-cid
                     {:expected-seq expected-seq :actual-seq link-seq :cid (:cid event)})

          (and (= link-seq 1) (not= prev-cid mc/zero-cid-hex))
          (halt-walk ws :forked-prev-cid
                     {:seq 1 :expected-prev mc/zero-cid-hex :actual-prev prev-cid})

          (= link-seq 1)
          (if (true? (:genesis-sig-valid? event))
            [(assoc ws
                    :phase :complete
                    :walked-count next-walked
                    :expected-cid nil
                    :expected-seq 0
                    :genesis-verified? true)
             [{:type :walk-complete
               :gen curr-gen
               :walked-count next-walked
               :genesis-cid (:cid event)}]]
            (halt-walk ws :bad-genesis-signature {:cid (:cid event)}))

          (>= next-walked (:depth-cap ws))
          (halt-walk ws :depth-cap-exceeded
                     {:depth-cap (:depth-cap ws) :walked-count next-walked :next-prev-cid prev-cid})

          (not (mc/valid-cid64? prev-cid))
          (halt-walk ws :forked-prev-cid {:invalid-prev-cid prev-cid})

          :else
          [(assoc ws
                  :walked-count next-walked
                  :expected-cid prev-cid
                  :expected-seq (dec link-seq))
           [{:type :fetch-blob
             :gen curr-gen
             :cid prev-cid}]])))))
