(ns bitecho.shell.infra
  "Single-Authority Shell Lifecycle State Machine & Unified Subnet Runtime (Rules 4, 5 & Flag F1):
   1. Pure generation-tagged `(transition-shell state event) -> [new-state effects]` reducer
      shared across `bitecho.shell.{dns,http,smtp,acme,upnp,infra}`:
      - Ignores stale generation callbacks (`(:generation event) < (:generation state)`) without
        mutating phase, resources, or liveness, incrementing `:ignored-stale` and emitting `:diagnose`.
      - Counts every dropped packet/request and failed start/dial in `:dropped` / `:last-error`
        with bounded diagnostic ring buffer (`64` entries).
   2. AES-256-GCM authenticated encryption/decryption for `\"tls/current-cert\"` private-key Blobs.
   3. Production shell executor (`start-subnet-runtime!`) wiring all 7 `bitecho.core.subnet/reduce-subnet`
      effects (`:fetch-blob`, `:eager-push-blob`, `:replicate-pointer`, `:leader-elected`,
      `:broadcast-heartbeat`, `:policy-updated`, `:diagnose`) to `bitecho.shell.blob-fs`,
      atomic pointer-table snapshots, peer replication, and TLS hot-reload."
  (:require [bitecho.core.data :as data]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.shell.blob-fs :as blob-fs]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io File]
           [java.nio.charset StandardCharsets]
           [java.nio.file CopyOption Files OpenOption StandardCopyOption]
           [java.security SecureRandom]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit]
           [javax.crypto Cipher]
           [javax.crypto.spec GCMParameterSpec SecretKeySpec]))

;; =============================================================================
;; 1. Single-Authority Generation-Tagged Shell Lifecycle Reducer (Rules 4 & 5)
;; =============================================================================

(defn init-shell-state
  "Initializes a generation-tagged single-authority shell lifecycle state map."
  ([] (init-shell-state :shell))
  ([shell-id]
   {:shell-id shell-id
    :phase :stopped
    :generation 0
    :resources nil
    :last-error nil
    :dropped 0
    :ignored-stale 0
    :diagnostics-counts {}
    :diagnostics []}))

(defn record-shell-diagnostic
  "Records a `:diagnose` map into `:diagnostics-counts` and bounded 64-entry `:diagnostics` ring."
  [state diag]
  (let [reason (or (:reason diag) (:error diag) :unknown)]
    (-> state
        (update-in [:diagnostics-counts reason] (fnil inc 0))
        (update :diagnostics (fn [ds] (vec (take-last 64 (conj (vec ds) diag))))))))

(defn transition-shell
  "Pure reducer `(transition-shell state event) -> [new-state effects]`.
   Phases: `:stopped`, `:starting`, `:running`, `:stopping`, `:failed`."
  [state event]
  (let [st (merge (init-shell-state) state)
        cur-gen (long (:generation st 0))
        ev-gen (:generation event)
        etype (:type event)]
    (cond
      ;; Stale generation callback -> ignore without mutating phase/resources, count & diagnose (Rule 4 & Rule 5)
      (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:effect :diagnose
                  :shell (:shell-id st)
                  :reason :stale-generation-callback
                  :event-type etype
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}
            st' (-> st
                    (update :ignored-stale (fnil inc 0))
                    (record-shell-diagnostic diag))]
        [st' [diag]])

      (= etype :start)
      (let [next-gen (inc cur-gen)
            close-effs (if (:resources st)
                         [{:effect :close-resources :resources (:resources st) :generation cur-gen}]
                         [])]
        [(assoc st
                :phase :starting
                :generation next-gen
                :resources nil
                :last-error nil)
         close-effs])

      (= etype :started)
      [(assoc st
              :phase :running
              :resources (:resources event)
              :last-error nil)
       []]

      (= etype :failed)
      (let [err (or (:error event) :shell-failed)
            diag {:effect :diagnose
                  :shell (:shell-id st)
                  :reason err
                  :generation cur-gen
                  :detail (:detail event)}
            close-effs (if (:resources st)
                         [{:effect :close-resources :resources (:resources st) :generation cur-gen}]
                         [])
            st' (-> st
                    (assoc :phase :failed
                           :resources nil
                           :last-error err)
                    (record-shell-diagnostic diag))]
        [st' (conj close-effs diag)])

      (= etype :stop)
      (let [close-effs (if (:resources st)
                         [{:effect :close-resources :resources (:resources st) :generation cur-gen}]
                         [])]
        [(assoc st
                :phase :stopped
                :resources nil)
         close-effs])

      (= etype :drop)
      (let [reason (or (:reason event) :packet-dropped)
            diag (cond-> {:effect :diagnose
                          :shell (:shell-id st)
                          :reason reason
                          :generation cur-gen}
                   (:detail event) (assoc :detail (:detail event)))
            st' (-> st
                    (update :dropped (fnil inc 0))
                    (record-shell-diagnostic diag))]
        [st' [diag]])

      (= etype :diagnose)
      (let [reason (or (:reason event) :diagnostic)
            diag (assoc event :effect :diagnose :shell (:shell-id st) :reason reason)
            st' (record-shell-diagnostic st diag)]
        [st' [diag]])

      :else
      (let [diag {:effect :diagnose :shell (:shell-id st) :reason :unknown-shell-event :event-type etype}
            st' (record-shell-diagnostic st diag)]
        [st' [diag]]))))

(defn apply-shell-event!
  "Atomically applies `transition-shell` to `shell-atom` and executes `:close-resources` effects outside `swap!`."
  ([shell-atom event]
   (apply-shell-event! shell-atom event nil))
  ([shell-atom event close-fn]
   (let [effects-box (atom [])]
     (swap! shell-atom
            (fn [st]
              (let [[st' effs] (transition-shell st event)]
                (reset! effects-box effs)
                st')))
     (doseq [eff @effects-box]
       (when (and (= :close-resources (:effect eff)) close-fn)
         (try (close-fn (:resources eff)) (catch Exception _ nil))))
     @shell-atom)))

(defn shell-status-summary
  "Extracts clean status diagnostics (`:phase`, `:generation`, `:last-error`, `:dropped`, `:ignored-stale`, `:diagnostics-counts`)."
  [shell-state]
  (select-keys shell-state [:shell-id :phase :generation :last-error :dropped :ignored-stale :diagnostics-counts :diagnostics]))

;; =============================================================================
;; 2. AES-256-GCM Encryption for Replicated TLS Private-Key Blobs
;; =============================================================================

(defn- normalize-32-byte-secret
  ^bytes [secret]
  (cond
    (and (bytes? secret) (= 32 (alength ^bytes secret))) secret
    (bytes? secret) (crypto/sha256 secret)
    (string? secret) (crypto/sha256 (fressian/utf8->bytes secret))
    :else (throw (ex-info "Invalid 32-byte TLS cluster secret" {}))))

(defn encrypt-tls-key-pem
  "Encrypts `key-pem` UTF-8 string under `secret` using AES-256-GCM (`12`-byte random IV, `128`-bit auth tag).
   Returns `{:iv <bytes> :ciphertext <bytes>}`."
  [secret ^String key-pem]
  (let [key-bytes (normalize-32-byte-secret secret)
        iv (byte-array 12)
        _ (.nextBytes (SecureRandom.) iv)
        cipher (Cipher/getInstance "AES/GCM/NoPadding")
        spec (SecretKeySpec. key-bytes "AES")
        gcm (GCMParameterSpec. 128 iv)]
    (.init cipher Cipher/ENCRYPT_MODE spec gcm)
    {:iv iv
     :ciphertext (.doFinal cipher (.getBytes key-pem StandardCharsets/UTF_8))}))

(defn decrypt-tls-key-pem
  "Decrypts `{:iv <bytes> :ciphertext <bytes>}` under `secret` using AES-256-GCM back into `key-pem` UTF-8 string."
  [secret {:keys [iv ciphertext]}]
  (let [key-bytes (normalize-32-byte-secret secret)
        cipher (Cipher/getInstance "AES/GCM/NoPadding")
        spec (SecretKeySpec. key-bytes "AES")
        gcm (GCMParameterSpec. 128 ^bytes iv)]
    (.init cipher Cipher/DECRYPT_MODE spec gcm)
    (String. (.doFinal cipher ^bytes ciphertext) StandardCharsets/UTF_8)))

;; =============================================================================
;; 3. Default `bitecho.org/infra` Policy & Atomic Pointer Snapshot Persistence
;; =============================================================================

(defn default-infra-policy
  "Constructs the canonical `\"bitecho.org/infra\"` Subnet policy map (UNIFICATION.md §6 Instance #3)
   with `:subnet/genesis-policy-cid` pinned."
  [{:keys [subnet-id trust-anchors cold-pubkey domain-pubkey threshold]}]
  (let [sid (or subnet-id "bitecho.org/infra")
        anchors (set (map #(str/lower-case (str/trim (str %))) trust-anchors))
        cold-pk (some-> cold-pubkey str str/trim str/lower-case)
        dom-pk (some-> (or domain-pubkey cold-pk (first anchors)) str str/trim str/lower-case)
        thresh (long (or threshold (max 1 (min 2 (count anchors)))))
        base {:subnet/id sid
              :subnet/parent-id "global"
              :subnet/gate {:gate/mode :permissioned
                            :gate/admission :allowlist
                            :gate/trust-anchors anchors
                            :gate/governance {:governance/type (if cold-pk :cold-key-or-quorum :quorum)
                                              :cold-pubkey cold-pk
                                              :threshold thresh}}
              :subnet/path-acl (cond-> [{:pattern "subnet/policy" :principal {:type :governance}}
                                        {:pattern "bootstrap" :principal {:type :allowlist}}
                                        {:pattern "acme/challenge/*" :principal {:type :leader}}
                                        {:pattern "tls/*" :principal {:type :leader}}
                                        {:pattern "web/*" :principal {:type :allowlist}}
                                        {:pattern "mail/*" :principal {:type :allowlist}}]
                                 dom-pk (conj {:pattern "dns/*" :principal {:type :pubkey :pubkey dom-pk}}))
              :subnet/economy {:economy/mode :none
                               :economy/burn-floor 0
                               :economy/settlement-take-bps 0}
              :subnet/replication {:replication/pointers :leader-election
                                   :replication/blobs :eager-push}}]
    (assoc base :subnet/genesis-policy-cid (subnet/policy-cid base))))

(defn- snapshot-file
  ^File [state-dir]
  (io/file state-dir "subnet-pointers.fressian"))

(defn- save-pointers-snapshot!
  [state-dir subnet-state]
  (when state-dir
    (let [f (snapshot-file state-dir)
          parent (.getParentFile f)
          _ (.mkdirs parent)
          tmp (File/createTempFile "ptrs-" ".tmp" parent)
          payload {:subnet-id (:subnet-id subnet-state)
                   :policy (:policy subnet-state)
                   :pointers (get-in subnet-state [:data :pointers] {})}]
      (try
        (Files/write (.toPath tmp) ^bytes (fressian/encode-canonical payload) (into-array OpenOption []))
        (try
          (Files/move (.toPath tmp) (.toPath f)
                      (into-array CopyOption [StandardCopyOption/ATOMIC_MOVE StandardCopyOption/REPLACE_EXISTING]))
          (catch Exception _
            (Files/move (.toPath tmp) (.toPath f)
                        (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
        (finally
          (when (.exists tmp) (.delete tmp)))))))

(defn- load-pointers-snapshot
  [state-dir]
  (when state-dir
    (let [f (snapshot-file state-dir)]
      (when (.exists f)
        (try
          (fressian/decode-wire (Files/readAllBytes (.toPath f)))
          (catch Exception _ nil))))))

;; =============================================================================
;; 4. Unified Subnet Runtime & All-7-Effect Executor (Flag F1)
;; =============================================================================

(declare resolve-path-blob!)

(defn- maybe-hot-reload-tls!
  [rt ptr]
  (when (and (= "tls/current-cert" (:pointer/path ptr))
             (some? (:pointer/target ptr))
             (:tls-manager rt)
             (:tls-secret rt))
    (try
      (let [res (resolve-path-blob! rt "tls/current-cert" (System/currentTimeMillis))]
        (when (:ok? res)
          (let [decoded (fressian/decode-wire (get-in res [:blob :blob/bytes]))
                cert-pem (:cert-pem decoded)
                enc-key (:encrypted-key decoded)
                key-pem (when enc-key (decrypt-tls-key-pem (:tls-secret rt) enc-key))
                reload-fn (:reload-fn (:tls-manager rt))]
            (when (and cert-pem key-pem (fn? reload-fn))
              (reload-fn cert-pem key-pem)))))
      (catch Exception e
        (apply-shell-event! (:shell-atom rt)
                            {:type :diagnose :reason :tls-hot-reload-failed :message (.getMessage e)})))))

(defn- execute-subnet-effects!
  "Executes all 7 `bitecho.core.subnet/reduce-subnet` effects outside the pure state transition (Rule 4 & Flag F1)."
  [rt effects event]
  (let [{:keys [state-dir shell-atom subnet-atom send-to-peers! on-leader-elected on-fetch-blob]} rt]
    ;; Persist any direct :put-blob to disk CAS immediately
    (when (and state-dir (= :put-blob (:type event)) (:blob event))
      (let [w (blob-fs/write-blob! state-dir (:blob event))]
        (when-not (:ok? w)
          (doseq [d (:effects w)]
            (apply-shell-event! shell-atom (assoc d :type :diagnose))))))

    (doseq [eff effects]
      (case (:effect eff)
        :diagnose
        (apply-shell-event! shell-atom (assoc eff :type :diagnose))

        :fetch-blob
        (let [cid (:cid eff)
              disk-res (when state-dir (blob-fs/read-blob! state-dir cid))]
          (if (:ok? disk-res)
            (swap! subnet-atom
                   (fn [inst]
                     (let [put-res (data/put-data-blob (:data inst) (:blob disk-res) (System/currentTimeMillis))]
                       (assoc inst :data (:state put-res)))))
            (do
              (doseq [d (:effects disk-res)]
                (apply-shell-event! shell-atom (assoc d :type :diagnose)))
              (when (fn? on-fetch-blob)
                (try (on-fetch-blob eff) (catch Exception _ nil))))))

        :eager-push-blob
        (do
          (when state-dir
            (blob-fs/write-blob! state-dir (:blob eff)))
          (when (and (fn? send-to-peers!) (not (:from-peer? event)))
            (try
              (send-to-peers! {:type :peer-put-blob
                               :subnet (:subnet eff)
                               :sender (or (:sender event) (:default-sender rt))
                               :blob (:blob eff)})
              (catch Exception e
                (apply-shell-event! shell-atom {:type :diagnose :reason :peer-blob-push-failed :message (.getMessage e)})))))

        :replicate-pointer
        (let [ptr (:pointer eff)]
          (save-pointers-snapshot! state-dir @subnet-atom)
          (maybe-hot-reload-tls! rt ptr)
          (when (and (fn? send-to-peers!) (not (:from-peer? event)))
            (try
              (send-to-peers! {:type :peer-publish-pointer
                               :subnet (:subnet eff)
                               :sender (or (:sender event) (:pointer/authority ptr))
                               :pointer ptr})
              (catch Exception e
                (apply-shell-event! shell-atom {:type :diagnose :reason :peer-pointer-push-failed :message (.getMessage e)})))))

        :leader-elected
        (when (fn? on-leader-elected)
          (try (on-leader-elected eff) (catch Exception _ nil)))

        :broadcast-heartbeat
        (when (fn? send-to-peers!)
          (try
            (send-to-peers! {:type :peer-heartbeat
                             :subnet (:subnet-id @subnet-atom)
                             :from (:from eff)
                             :term (:term eff)
                             :leader-id (:leader-id eff)})
            (catch Exception e
              (apply-shell-event! shell-atom {:type :diagnose :reason :heartbeat-send-failed :message (.getMessage e)}))))

        :policy-updated
        (save-pointers-snapshot! state-dir @subnet-atom)

        nil))))

(defn submit-event!
  "Atomically runs `subnet/reduce-subnet` on `(:subnet-atom rt)` and executes all resulting effects."
  [rt event]
  (let [res-box (atom nil)]
    (swap! (:subnet-atom rt)
           (fn [inst]
             (let [r (subnet/reduce-subnet inst event)]
               (reset! res-box r)
               (:state r))))
    (let [res @res-box]
      (execute-subnet-effects! rt (:effects res) event)
      res)))

(defn receive-peer-message!
  "Applies an inbound peer replication or heartbeat message to `rt`."
  [rt msg]
  (let [now-ms (long (or (:now-ms msg) (System/currentTimeMillis)))]
    (case (:type msg)
      :peer-heartbeat
      (submit-event! rt {:type :leader-heartbeat
                         :from (:from msg)
                         :term (:term msg)
                         :leader-id (:leader-id msg)
                         :now-ms now-ms
                         :from-peer? true})

      :peer-put-blob
      (submit-event! rt {:type :put-blob
                         :sender (:sender msg)
                         :blob (:blob msg)
                         :now-ms now-ms
                         :from-peer? true})

      :peer-publish-pointer
      (submit-event! rt {:type :publish-pointer
                         :sender (:sender msg)
                         :pointer (:pointer msg)
                         :now-ms now-ms
                         :from-peer? true})

      (do
        (apply-shell-event! (:shell-atom rt)
                            {:type :drop :reason :unknown-peer-message :detail (:type msg)})
        {:applied? false :error :unknown-peer-message}))))

(defn tick-runtime!
  "Advances leader-election liveness & broadcasts heartbeats."
  ([rt] (tick-runtime! rt (System/currentTimeMillis)))
  ([rt now-ms]
   (submit-event! rt {:type :leader-tick :now-ms now-ms})))

(defn put-blob!
  "Submits `:put-blob` to `rt` (persisting to `blob-fs` and replicating if `:eager-push`)."
  ([rt blob] (put-blob! rt blob {}))
  ([rt blob opts]
   (submit-event! rt (merge {:type :put-blob
                             :sender (or (:sender opts) (:default-sender rt))
                             :blob blob
                             :now-ms (or (:now-ms opts) (System/currentTimeMillis))}
                            opts))))

(defn publish-blob-and-pointer!
  "Convenience helper: stores `blob`, signs `Pointer` at `path` (attaching current `:leader-term` if needed),
   and submits `:publish-pointer` to `rt`."
  [rt {:keys [blob path authority-pubkey authority-privkey proof expires now-ms] seq-num :seq}]
  (let [t (long (or now-ms (System/currentTimeMillis)))
        put-res (put-blob! rt blob {:sender authority-pubkey :now-ms t})]
    (if-not (:applied? put-res)
      put-res
      (let [inst @(:subnet-atom rt)
            sid (:subnet-id inst)
            le-term (get-in inst [:leader-election :term])
            ptr-map (cond-> {:pointer/authority authority-pubkey
                             :pointer/subnet sid
                             :pointer/path path
                             :pointer/seq (long (or seq-num 1))
                             :pointer/target (:blob/cid blob)
                             :pointer/proof (or proof {:proof/type :self})}
                      (some? le-term) (assoc :pointer/leader-term (long le-term))
                      (some? expires) (assoc :pointer/expires (long expires)))
            signed-ptr (data/sign-pointer authority-privkey ptr-map)]
        (submit-event! rt {:type :publish-pointer
                           :sender authority-pubkey
                           :pointer signed-ptr
                           :now-ms t})))))

(defn resolve-path-blob!
  "Resolves `(subnet, path)` in `rt`, hydrating from `blob-fs` via `:fetch-blob` if cold-evicted from RAM.
   Returns `{:ok? true :pointer ptr :blob blob :file File}` or `{:ok? false :error <kw>}`."
  ([rt path]
   (resolve-path-blob! rt path (System/currentTimeMillis)))
  ([rt path now-ms]
   (let [inst @(:subnet-atom rt)
         sid (:subnet-id inst)
         ptr (data/resolve-pointer (:data inst) sid path now-ms)]
     (if-not ptr
       {:ok? false :error :not-found}
       (let [cid (:pointer/target ptr)
             res-box (atom nil)
             _ (swap! (:subnet-atom rt)
                      (fn [cur]
                        (let [r (data/get-blob (get-in cur [:data :blobs]) cid {:subnet sid :now-ms now-ms})]
                          (reset! res-box r)
                          (assoc-in cur [:data :blobs] (:store r)))))
             r1 @res-box]
         (if (:hit? r1)
           {:ok? true
            :pointer ptr
            :blob (:blob r1)
            :file (when (:state-dir rt) (blob-fs/blob-file (:state-dir rt) cid))}
           (do
             ;; Execute :fetch-blob effect (hydrates from blob-fs on disk if available)
             (execute-subnet-effects! rt (:effects r1) {:type :get-blob :cid cid})
             (let [r2 (data/get-blob (get-in @(:subnet-atom rt) [:data :blobs]) cid {:subnet sid :now-ms now-ms})]
               (if (:hit? r2)
                 {:ok? true
                  :pointer ptr
                  :blob (:blob r2)
                  :file (when (:state-dir rt) (blob-fs/blob-file (:state-dir rt) cid))}
                 {:ok? false :error :missing-blob :pointer ptr})))))))))

(defn start-subnet-runtime!
  "Initializes and starts a single-authority Subnet shell runtime (`:phase :running`).
   Restores any persisted pointers snapshot from `<state-dir>/subnet-pointers.fressian`."
  [opts]
  (let [state-dir (:state-dir opts)
        _ (when state-dir (.mkdirs (io/file state-dir)))
        shell-atom (atom (init-shell-state :subnet-runtime))
        _ (apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        init-res (subnet/init-subnet-instance (:policy opts) opts)]
    (if-not (:ok? init-res)
      (do
        (apply-shell-event! shell-atom {:type :failed :generation gen :error (:error init-res)})
        (throw (ex-info (str "Invalid subnet policy: " (:error init-res)) {:error (:error init-res)})))
      (let [snap (load-pointers-snapshot state-dir)
            inst0 (if (and snap (= (:subnet-id (:instance init-res)) (:subnet-id snap)))
                    (reduce (fn [acc [[_ _ :as k] ptr]]
                              (-> acc
                                  (assoc-in [:data :pointers k] ptr)
                                  (update-in [:data :blobs] #(if (:pointer/target ptr)
                                                               (data/pin-blob % (:pointer/target ptr))
                                                               %))))
                            (cond-> (:instance init-res)
                              (:policy snap) (assoc :policy (:policy snap)))
                            (:pointers snap))
                    (:instance init-res))
            subnet-atom (atom inst0)
            default-sender (or (:default-sender opts)
                               (when (string? (:node-id opts)) (:node-id opts))
                               (first (get-in (:policy opts) [:subnet/gate :gate/trust-anchors])))
            ticker (when (:heartbeat-ticker? opts)
                     (Executors/newSingleThreadScheduledExecutor))
            rt {:shell-atom shell-atom
                :subnet-atom subnet-atom
                :state-dir state-dir
                :node-id (:node-id opts)
                :node-privkey (:node-privkey opts)
                :default-sender default-sender
                :tls-manager (:tls-manager opts)
                :tls-secret (:tls-secret opts)
                :send-to-peers! (:send-to-peers! opts)
                :on-leader-elected (:on-leader-elected opts)
                :on-fetch-blob (:on-fetch-blob opts)
                :ticker ticker}]
        (when ticker
          (let [hb-ms (long (get-in inst0 [:leader-election :heartbeat-interval-ms] 2000))]
            (.scheduleAtFixedRate ^ScheduledExecutorService ticker
                                  ^Runnable (fn [] (try (tick-runtime! rt) (catch Exception _ nil)))
                                  hb-ms hb-ms TimeUnit/MILLISECONDS)))
        (apply-shell-event! shell-atom {:type :started :generation gen :resources {:ticker ticker}})
        rt))))

(defn stop-subnet-runtime!
  "Stops background heartbeat ticker (if active) and transitions runtime shell to `:stopped`."
  [rt]
  (apply-shell-event! (:shell-atom rt)
                      {:type :stop}
                      (fn [{:keys [ticker]}]
                        (when ticker
                          (try (.shutdownNow ^ScheduledExecutorService ticker) (catch Exception _ nil)))))
  rt)

(defn runtime-status
  "Returns unified shell lifecycle + Subnet diagnostics summary."
  [rt]
  (let [sh (shell-status-summary @(:shell-atom rt))
        sub @(:subnet-atom rt)]
    (assoc sh
           :subnet-id (:subnet-id sub)
           :role (get-in sub [:leader-election :role])
           :leader-id (get-in sub [:leader-election :leader-id])
           :term (get-in sub [:leader-election :term])
           :healthy-nodes (get-in sub [:leader-election :healthy-nodes])
           :subnet-diagnostics (:diagnostics sub))))
