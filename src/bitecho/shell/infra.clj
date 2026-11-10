(ns bitecho.shell.infra
  "Single-Authority Shell Lifecycle State Machine, Unified Subnet Runtime, DTLS Peer Mesh,
   and Phase C `clj-web` State Migration Engine (Rules 4, 5, Flag F1, & Flags F-B1..F-B3):
   1. Pure generation-tagged `(transition-shell state event) -> [new-state effects]` reducer
      shared across `bitecho.shell.{dns,http,smtp,acme,upnp,infra}`.
   2. AES-256-GCM authenticated encryption/decryption for `\"tls/current-cert\"` private-key Blobs
      with fail-fast shared `:tls-secret` / `:tls-secret-file` enforcement on multi-node clusters (`F-B2`).
   3. Authoritative runtime epoch tracking (`current-runtime-epoch` / `set-runtime-epoch!`) for
      fail-closed DAC admission (`F-B1`).
   4. Production shell executor (`start-subnet-runtime!`) wiring all 7 `bitecho.core.subnet/reduce-subnet`
      effects (`F1`) + real `clj-datachannel` mutual-DTLS full-mesh (`start-datachannel-peer-mesh!`).
   5. Idempotent pre-cutover `clj-web` state migration (`migrate-clj-web-state!`) and mail CLI helpers."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.acme :as acme-proto]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.shell.blob-fs :as blob-fs]
            [bitecho.shell.identity :as identity]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api])
  (:import [java.io File]
           [java.net URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file CopyOption Files OpenOption StandardCopyOption]
           [java.security SecureRandom]
           [java.time Duration]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean AtomicLong]
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
;; 2. AES-256-GCM TLS Key Bundle Encryption & Shared Secret Resolution (`F-B2`)
;; =============================================================================

(defn resolve-tls-secret
  "Resolves an explicit shared TLS bundle encryption secret from `:tls-secret` (bytes or non-blank string)
   or `:tls-secret-file` (file path on disk). Returns `nil` when neither is configured."
  [{:keys [tls-secret tls-secret-file]}]
  (cond
    (and (bytes? tls-secret) (pos? (alength ^bytes tls-secret)))
    tls-secret

    (and (string? tls-secret) (not (str/blank? tls-secret)))
    (let [s (str/trim tls-secret)]
      (if (re-matches #"[0-9a-fA-F]{64}" s)
        (basalt/hex->bytes (str/lower-case s))
        s))

    (and (some? tls-secret-file) (.exists (io/file tls-secret-file)))
    (let [s (str/trim (slurp (io/file tls-secret-file)))]
      (when-not (str/blank? s)
        (if (re-matches #"[0-9a-fA-F]{64}" s)
          (basalt/hex->bytes (str/lower-case s))
          s)))

    :else
    nil))

(defn- normalize-32-byte-secret
  ^bytes [secret]
  (cond
    (and (bytes? secret) (= 32 (alength ^bytes secret))) secret
    (bytes? secret) (crypto/sha256 secret)
    (and (string? secret) (not (str/blank? secret))) (crypto/sha256 (fressian/utf8->bytes secret))
    :else (throw (ex-info "Invalid 32-byte TLS cluster secret" {}))))

(defn encrypt-tls-key-pem
  "Encrypts `key-pem` UTF-8 string under `secret` using AES-256-GCM (`12`-byte random IV, `128`-bit auth tag)."
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
   with `:subnet/genesis-policy-cid` pinned and optional `:acme-thumbprint` (`F-B3`).
   Never elevates a hot node key to `:cold-pubkey` when `:cold-pubkey` is nil (`F-C3`)."
  [{:keys [subnet-id trust-anchors cold-pubkey domain-pubkey threshold acme-thumbprint]}]
  (let [sid (or subnet-id "bitecho.org/infra")
        anchors (set (map #(str/lower-case (str/trim (str %))) trust-anchors))
        cold-pk (when (and (string? cold-pubkey) (not (str/blank? cold-pubkey)))
                  (str/lower-case (str/trim cold-pubkey)))
        dom-pk (when (and (string? domain-pubkey) (not (str/blank? domain-pubkey)))
                 (str/lower-case (str/trim domain-pubkey)))
        thresh (long (or threshold (max 1 (min 2 (count anchors)))))
        gov (cond-> {:governance/type (if cold-pk :cold-key-or-quorum :quorum)
                     :threshold thresh}
              cold-pk (assoc :cold-pubkey cold-pk))
        gate (cond-> {:gate/mode :permissioned
                      :gate/admission :allowlist
                      :gate/trust-anchors anchors
                      :gate/governance gov}
               (and (string? acme-thumbprint) (not (str/blank? acme-thumbprint)))
               (assoc :gate/acme-thumbprint (str/trim acme-thumbprint)))
        dns-rule (if dom-pk
                   {:pattern "dns/*" :principal {:type :pubkey :pubkey dom-pk}}
                   {:pattern "dns/*" :principal {:type :allowlist}})
        base {:subnet/id sid
              :subnet/parent-id "global"
              :subnet/gate gate
              :subnet/path-acl [{:pattern "subnet/policy" :principal {:type :governance}}
                                {:pattern "bootstrap" :principal {:type :allowlist}}
                                {:pattern "dir/*" :principal {:type :allowlist}}
                                {:pattern "acme/challenge/*" :principal {:type :leader}}
                                {:pattern "tls/*" :principal {:type :leader}}
                                {:pattern "web/*" :principal {:type :allowlist}}
                                {:pattern "mail/*" :principal {:type :allowlist}}
                                dns-rule]
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
;; 4. Unified Subnet Runtime, Epoch Tracking (`F-B1`), & Effect Executor (`F1`)
;; =============================================================================

(declare resolve-path-blob!)

(defn current-runtime-epoch
  "Returns the authoritative current epoch for `rt` (from `:epoch-fn` or `:epoch-atom`),
   or `nil` when unsynced (causing DAC expiry checks to fail closed per `F-B1`)."
  [rt]
  (cond
    (nil? rt) nil
    (fn? (:epoch-fn rt)) ((:epoch-fn rt))
    (:epoch-atom rt) @(:epoch-atom rt)
    :else nil))

(defn set-runtime-epoch!
  "Sets the authoritative runtime epoch on `rt` (e.g. from finalized validator chain state)."
  [rt epoch]
  (when-let [a (:epoch-atom rt)]
    (reset! a (when (some? epoch) (long epoch)))))

(defn- fetch-validator-epoch-http
  [url]
  (try
    (let [client (-> (HttpClient/newBuilder)
                     (.connectTimeout (Duration/ofMillis 1500))
                     (.build))
          req (-> (HttpRequest/newBuilder (URI/create (str url)))
                  (.timeout (Duration/ofMillis 1500))
                  (.GET)
                  (.build))
          resp (.send client req (HttpResponse$BodyHandlers/ofString))]
      (when (= 200 (.statusCode resp))
        (let [body (str/trim (.body resp))]
          (or (when-let [[_ n] (re-find #"(?i)(?:finalized[_-]?epoch|epoch)[=:\"\s]+(\d+)" body)]
                (Long/parseLong n))
              (let [d (try (edn/read-string body) (catch Exception _ nil))]
                (when (map? d)
                  (or (:finalized-epoch d) (:epoch d))))))))
    (catch Exception _ nil)))

(defn sync-runtime-epoch-from-validators!
  "Queries `validator-urls` (using optional `fetcher-fn` `(fn [url] epoch-or-nil)` for deterministic tests),
   verifies strict BFT majority (`> n/2`) agreement on a non-regressive integer epoch, and updates `rt` (`F-C4`).
   Emits counted `:diagnose` on quorum disagreement or regressive epoch."
  ([rt validator-urls]
   (sync-runtime-epoch-from-validators! rt validator-urls fetch-validator-epoch-http))
  ([rt validator-urls fetcher-fn]
   (let [urls (vec validator-urls)
         total (count urls)]
     (if (zero? total)
       {:ok? false :error :no-validators}
       (let [quorum (inc (quot total 2))
             f (if (map? fetcher-fn) #(get fetcher-fn %) fetcher-fn)
             epochs (keep (fn [u]
                            (let [v (try (f u) (catch Exception _ nil))]
                              (when (integer? v) (long v))))
                          urls)
             freqs (frequencies epochs)
             agreed (->> freqs
                         (filter (fn [[_ cnt]] (>= cnt quorum)))
                         (map first)
                         sort
                         last)
             cur-ep (current-runtime-epoch rt)]
         (cond
           (nil? agreed)
           (do
             (apply-shell-event! (:shell-atom rt)
                                 {:type :diagnose :reason :validator-epoch-quorum-failed :responses (count epochs)})
             {:ok? false :error :validator-epoch-quorum-failed})

           (and (integer? cur-ep) (< (long agreed) (long cur-ep)))
           (do
             (apply-shell-event! (:shell-atom rt)
                                 {:type :diagnose :reason :validator-epoch-regressive :current cur-ep :proposed agreed})
             {:ok? false :error :validator-epoch-regressive})

           :else
           (do
             (set-runtime-epoch! rt agreed)
             {:ok? true :epoch agreed})))))))

(defn- active-peer-sender
  [rt]
  (or (:send-to-peers! rt)
      (when-let [a (:send-to-peers!-atom rt)] @a)))

(defn- active-blob-fetcher
  [rt]
  (or (:on-fetch-blob rt)
      (when-let [a (:on-fetch-blob-atom rt)] @a)))

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
  (let [{:keys [state-dir shell-atom subnet-atom on-leader-elected]} rt
        send-fn (active-peer-sender rt)
        fetch-fn (active-blob-fetcher rt)]
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
              (when (fn? fetch-fn)
                (try (fetch-fn eff) (catch Exception _ nil))))))

        :eager-push-blob
        (do
          (when state-dir
            (blob-fs/write-blob! state-dir (:blob eff)))
          (when (and (fn? send-fn) (not (:from-peer? event)))
            (try
              (send-fn (cond-> {:type :peer-put-blob
                                :subnet (:subnet eff)
                                :sender (or (:sender event) (:default-sender rt))
                                :blob (:blob eff)}
                         (:dac event) (assoc :dac (:dac event))))
              (catch Exception e
                (apply-shell-event! shell-atom {:type :diagnose :reason :peer-blob-push-failed :message (.getMessage e)})))))

        :replicate-pointer
        (let [ptr (:pointer eff)]
          (save-pointers-snapshot! state-dir @subnet-atom)
          (maybe-hot-reload-tls! rt ptr)
          (when (and (fn? send-fn) (not (:from-peer? event)))
            (try
              (send-fn (cond-> {:type :peer-publish-pointer
                                :subnet (:subnet eff)
                                :sender (or (:sender event) (:pointer/authority ptr))
                                :pointer ptr}
                         (:dac event) (assoc :dac (:dac event))))
              (catch Exception e
                (apply-shell-event! shell-atom {:type :diagnose :reason :peer-pointer-push-failed :message (.getMessage e)})))))

        :leader-elected
        (when (fn? on-leader-elected)
          (try (on-leader-elected eff) (catch Exception _ nil)))

        :broadcast-heartbeat
        (when (fn? send-fn)
          (try
            (send-fn {:type :peer-heartbeat
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
  "Atomically runs `subnet/reduce-subnet` on `(:subnet-atom rt)` (attaching authoritative runtime `:epoch`
   when present and not overridden) and executes all resulting effects."
  [rt event]
  (let [rt-ep (current-runtime-epoch rt)
        ev (cond-> event
             (and (nil? (:epoch event)) (some? rt-ep))
             (assoc :epoch rt-ep))
        res-box (atom nil)]
    (swap! (:subnet-atom rt)
           (fn [inst]
             (let [r (subnet/reduce-subnet inst ev)]
               (reset! res-box r)
               (:state r))))
    (let [res @res-box]
      (execute-subnet-effects! rt (:effects res) ev)
      res)))

(defn receive-peer-message!
  "Applies an inbound peer replication, blob-fetch, or heartbeat message to `rt`.
   Strictly evaluates `:dac` against local `(current-runtime-epoch rt)`, never trusting remote `:epoch` (`F-B1`)."
  [rt msg]
  (let [now-ms (long (or (:now-ms msg) (System/currentTimeMillis)))
        local-ep (current-runtime-epoch rt)]
    (case (:type msg)
      :peer-heartbeat
      (submit-event! rt {:type :leader-heartbeat
                         :from (:from msg)
                         :term (:term msg)
                         :leader-id (:leader-id msg)
                         :now-ms now-ms
                         :from-peer? true})

      :peer-put-blob
      (submit-event! rt (cond-> {:type :put-blob
                                 :sender (:sender msg)
                                 :blob (:blob msg)
                                 :now-ms now-ms
                                 :from-peer? true}
                          (:dac msg) (assoc :dac (:dac msg))
                          (some? local-ep) (assoc :epoch local-ep)))

      :peer-publish-pointer
      (submit-event! rt (cond-> {:type :publish-pointer
                                 :sender (:sender msg)
                                 :pointer (:pointer msg)
                                 :now-ms now-ms
                                 :from-peer? true}
                          (:dac msg) (assoc :dac (:dac msg))
                          (some? local-ep) (assoc :epoch local-ep)))

      :peer-fetch-blob
      (let [cid (:cid msg)
            disk-res (when (:state-dir rt) (blob-fs/read-blob! (:state-dir rt) cid))
            send-fn (active-peer-sender rt)]
        (when (and (:ok? disk-res) (fn? send-fn))
          (send-fn {:type :peer-put-blob
                    :subnet (:subnet-id @(:subnet-atom rt))
                    :sender (:default-sender rt)
                    :blob (:blob disk-res)}))
        {:applied? (:ok? disk-res)})

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
  [rt {:keys [blob path authority-pubkey authority-privkey proof expires dac epoch now-ms] seq-num :seq}]
  (let [t (long (or now-ms (System/currentTimeMillis)))
        put-res (put-blob! rt blob (cond-> {:sender authority-pubkey :now-ms t}
                                     dac (assoc :dac dac)
                                     (some? epoch) (assoc :epoch epoch)))]
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
        (submit-event! rt (cond-> {:type :publish-pointer
                                   :sender authority-pubkey
                                   :pointer signed-ptr
                                   :now-ms t}
                            dac (assoc :dac dac)
                            (some? epoch) (assoc :epoch epoch)))))))

(defn resolve-path-blob!
  "Resolves `(subnet, path)` in `rt`, hydrating from `blob-fs` via `:fetch-blob` if cold-evicted from RAM."
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
   Enforces `F-B2` fail-fast shared `:tls-secret` / `:tls-secret-file` on multi-node TLS-managed runtimes."
  [opts]
  (let [state-dir (:state-dir opts)
        _ (when state-dir (.mkdirs (io/file state-dir)))
        shell-atom (atom (init-shell-state :subnet-runtime))
        _ (apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        resolved-secret (resolve-tls-secret opts)
        multi-node? (> (count (or (:all-nodes opts) #{})) 1)
        needs-shared-secret? (and multi-node? (or (:tls-manager opts) (:require-tls-secret? opts)))]
    (if (and needs-shared-secret? (nil? resolved-secret))
      (do
        (apply-shell-event! shell-atom {:type :failed :generation gen :error :missing-shared-tls-secret})
        (throw (ex-info "Multi-node infra runtime requires explicit shared :tls-secret or :tls-secret-file"
                        {:error :missing-shared-tls-secret})))
      (let [init-res (subnet/init-subnet-instance (:policy opts) opts)]
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
                validator-urls (vec (or (:validator-urls opts) []))
                ticker (when (or (:heartbeat-ticker? opts) (seq validator-urls))
                         (Executors/newSingleThreadScheduledExecutor))
                rt {:shell-atom shell-atom
                    :subnet-atom subnet-atom
                    :epoch-atom (atom (:initial-epoch opts))
                    :epoch-fn (:epoch-fn opts)
                    :validator-urls validator-urls
                    :state-dir state-dir
                    :node-id (:node-id opts)
                    :node-privkey (:node-privkey opts)
                    :default-sender default-sender
                    :tls-manager (:tls-manager opts)
                    :tls-secret (or resolved-secret (when-not multi-node? (:node-privkey opts)))
                    :send-to-peers! (:send-to-peers! opts)
                    :send-to-peers!-atom (atom nil)
                    :on-leader-elected (:on-leader-elected opts)
                    :on-fetch-blob (:on-fetch-blob opts)
                    :on-fetch-blob-atom (atom nil)
                    :ticker ticker}]
            (when (seq validator-urls)
              (try (sync-runtime-epoch-from-validators! rt validator-urls) (catch Exception _ nil)))
            (when ticker
              (let [hb-ms (long (get-in inst0 [:leader-election :heartbeat-interval-ms] 2000))]
                (.scheduleAtFixedRate ^ScheduledExecutorService ticker
                                      ^Runnable (fn []
                                                  (try
                                                    (when (:heartbeat-ticker? opts)
                                                      (tick-runtime! rt))
                                                    (when (seq validator-urls)
                                                      (sync-runtime-epoch-from-validators! rt validator-urls))
                                                    (catch Exception _ nil)))
                                      hb-ms hb-ms TimeUnit/MILLISECONDS)))
            (apply-shell-event! shell-atom {:type :started :generation gen :resources {:ticker ticker}})
            rt))))))

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
           :epoch (current-runtime-epoch rt)
           :role (get-in sub [:leader-election :role])
           :leader-id (get-in sub [:leader-election :leader-id])
           :term (get-in sub [:leader-election :term])
           :healthy-nodes (get-in sub [:leader-election :healthy-nodes])
           :subnet-diagnostics (:diagnostics sub))))

;; =============================================================================
;; 5. Phase C: 3-Node `clj-datachannel` Mutual-DTLS Peer Mesh (`:5000..5002`)
;; =============================================================================

(defn- validate-legacy-ed25519-pair!
  [pubkey-hex privkey-hex src-path]
  (let [pub-h (some-> pubkey-hex str str/trim str/lower-case)
        priv-h (some-> privkey-hex str str/trim str/lower-case)
        pub-bs (try (when pub-h (basalt/hex->bytes pub-h)) (catch Exception _ nil))
        priv-bs (try (when priv-h (basalt/hex->bytes priv-h)) (catch Exception _ nil))
        probe (fressian/utf8->bytes "bitecho-legacy-keypair-probe")
        valid? (try
                 (and pub-bs priv-bs
                      (crypto/verify pub-bs probe (crypto/sign priv-bs probe)))
                 (catch Exception _ false))]
    (when-not valid?
      (throw (ex-info "Corrupt or mismatched Ed25519 keypair in legacy node-identity.edn"
                      {:file src-path :pubkey-hex pub-h})))
    {:pubkey-hex pub-h
     :privkey-hex priv-h
     :privkey-bytes priv-bs
     :keypair {:public pub-bs :private priv-bs}}))

(defn load-or-create-infra-peer-identity!
  "Loads or creates the persistent Ed25519 + DTLS identity for an infra node (`F-C1`):
   - If `<state-dir>/cluster/node-identity.edn` exists AND contains `:pubkey-hex` / `:privkey-hex`,
     cryptographically validates and preserves that exact Ed25519 keypair (persisting it into
     `<state-dir>/identity/` so no fresh keypair is ever generated over it), alongside its DTLS cert/fingerprint.
   - If `<state-dir>/cluster/node-identity.edn` exists with only `clj-web` DTLS keys (`:cert-pem`/`:key-pem`),
     preserves its exact DTLS cert/fingerprint alongside the persistent `<state-dir>/identity/` Ed25519 keypair."
  [state-dir node-id]
  (let [legacy-file (io/file state-dir "cluster" "node-identity.edn")]
    (if-not (.exists legacy-file)
      (let [base-id (identity/load-or-create-node-identity! state-dir node-id)
            priv-bytes (or (get-in base-id [:keypair :private])
                           (basalt/hex->bytes (:privkey-hex base-id)))]
        (assoc base-id :privkey-bytes priv-bytes))
      (let [d (edn/read-string (slurp legacy-file))
            cert (identity/parse-cert-pem (:cert-pem d))
            k (identity/parse-private-key-pem (:key-pem d))
            fp (identity/normalize-fingerprint (:fingerprint d))
            has-legacy-ed? (or (contains? d :pubkey-hex) (contains? d :privkey-hex))]
        (when (or (nil? cert) (nil? k))
          (throw (ex-info "Corrupt DTLS certificate/key in legacy node-identity.edn"
                          {:file (.getAbsolutePath legacy-file)})))
        (if has-legacy-ed?
          (let [ed (validate-legacy-ed25519-pair! (:pubkey-hex d) (:privkey-hex d) (.getAbsolutePath legacy-file))]
            (merge ed
                   {:node-id node-id
                    :fingerprint fp
                    :cert-data {:cert cert :key k :fingerprint fp}}))
          (let [base-id (identity/load-or-create-node-identity! state-dir node-id)
                priv-bytes (or (get-in base-id [:keypair :private])
                               (basalt/hex->bytes (:privkey-hex base-id)))]
            (assoc base-id
                   :privkey-bytes priv-bytes
                   :fingerprint fp
                   :cert-data {:cert cert :key k :fingerprint fp})))))))

(defn- push-anti-entropy-snapshot-to-peer!
  [rt send-one!]
  (let [inst @(:subnet-atom rt)
        sid (:subnet-id inst)
        ptrs (vals (get-in inst [:data :pointers] {}))]
    (doseq [ptr ptrs]
      (when-let [cid (:pointer/target ptr)]
        (let [disk-res (when (:state-dir rt) (blob-fs/read-blob! (:state-dir rt) cid))]
          (when (:ok? disk-res)
            (send-one! {:type :peer-put-blob
                        :subnet sid
                        :sender (:pointer/authority ptr)
                        :blob (:blob disk-res)}))))
      (send-one! {:type :peer-publish-pointer
                  :subnet sid
                  :sender (:pointer/authority ptr)
                  :pointer ptr}))))

(defn start-datachannel-peer-mesh!
  "Starts mutual-DTLS-authenticated `clj-datachannel` UDP peer connections across `[:cluster :nodes]`
   and wires `rt` to broadcast heartbeats, Blobs, Pointers, and `:fetch-blob` peer pulls."
  [config rt]
  (let [shell-atom (atom (init-shell-state :infra-peer-mesh))
        _ (apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        node-id (or (:node/id config) (:node-id rt))
        state-dir (or (:state-dir config) (:state-dir rt))
        cluster-cfg (get config :cluster {})
        nodes-cfg (get cluster-cfg :nodes {})
        peer-ids (disj (set (keys nodes-cfg)) node-id)
        hb-interval (long (get cluster-cfg :heartbeat-interval-ms 2000))
        hb-timeout (long (get cluster-cfg :heartbeat-timeout-ms 6000))
        running? (AtomicBoolean. true)
        scheduler (Executors/newSingleThreadScheduledExecutor)
        peer-conns-atom (atom {})
        local-ident (load-or-create-infra-peer-identity! state-dir node-id)
        local-fp (identity/normalize-fingerprint (:fingerprint local-ident))
        sorted-ids (vec (sort-by name (keys nodes-cfg)))
        node-idx (into {} (map-indexed (fn [i k] [k i]) sorted-ids))
        multi-peer? (> (count nodes-cfg) 2)
        send-to-conn! (fn [conn msg]
                        (when-let [dc-node (:node conn)]
                          (let [ch-id (if (= :peer-heartbeat (:type msg))
                                        (or @(:heartbeat-id conn) @(:control-id conn))
                                        @(:control-id conn))]
                            (when ch-id
                              (api/send! dc-node (fressian/encode-wire msg) ch-id)))))
        broadcast! (fn [msg]
                     (doseq [[pid conn] @peer-conns-atom]
                       (try
                         (send-to-conn! conn msg)
                         (catch Exception e
                           (apply-shell-event! shell-atom {:type :diagnose :reason :peer-dc-send-failed :peer pid :detail (.getMessage e)})))))
        connect-peer! (fn [pid]
                        (let [peer-cfg (get nodes-cfg pid)
                              peer-fp (try (identity/normalize-fingerprint (:fingerprint peer-cfg))
                                           (catch Exception _ nil))]
                          (if-not peer-fp
                            (do
                              (apply-shell-event! shell-atom {:type :failed :generation gen :error :missing-peer-dtls-fingerprint :detail pid})
                              (throw (ex-info (str "Missing or invalid DTLS fingerprint for infra peer: " pid) {:peer pid})))
                            (try
                              (when-let [old (:node (get @peer-conns-atom pid))]
                                (try (api/close! old) (catch Exception _ nil))
                                (Thread/sleep 25))
                              (let [peer-ip (or (:ip4 peer-cfg) (:ip peer-cfg) "127.0.0.1")
                                    base-peer-port (int (or (:port peer-cfg) 5000))
                                    peer-port (if multi-peer?
                                                (+ base-peer-port (int (get node-idx node-id 0)))
                                                base-peer-port)
                                    base-local-port (int (or (get-in nodes-cfg [node-id :port]) 5000))
                                    local-port (if multi-peer?
                                                 (+ base-local-port (int (get node-idx pid 0)))
                                                 base-local-port)
                                    active? (neg? (compare (name node-id) (name pid)))
                                    setup (if active? "active" "passive")
                                    local-ice (identity/deterministic-ice-creds node-id local-fp)
                                    remote-ice (identity/deterministic-ice-creds pid peer-fp)
                                    raw-node (api/create-node {:port local-port :setup setup})
                                    dc-node (assoc raw-node
                                                   :cert-data (:cert-data local-ident)
                                                   :ice-creds local-ice
                                                   :local-sdp-params (assoc (:local-sdp-params raw-node)
                                                                            :ice-ufrag (:ufrag local-ice)
                                                                            :ice-pwd (:pwd local-ice)
                                                                            :fingerprint local-fp
                                                                            :setup setup))
                                    ctrl-id (atom nil)
                                    hb-id (atom nil)
                                    conn-entry {:node dc-node
                                                :control-id ctrl-id
                                                :heartbeat-id hb-id
                                                :created-at (System/currentTimeMillis)}
                                    callbacks {:on-open
                                               (fn [evt]
                                                 (if-let [ch-id (:channel-id evt)]
                                                   ;; Passive side receives remote-initiated channel open events
                                                   (let [lbl (str (:label evt))]
                                                     (cond
                                                       (= lbl "heartbeat") (reset! hb-id ch-id)
                                                       :else (do
                                                               (reset! ctrl-id ch-id)
                                                               (submit-event! rt {:type :peer-connected :peer-id pid :now-ms (System/currentTimeMillis)})
                                                               (future
                                                                 (try
                                                                   (Thread/sleep 30)
                                                                   (push-anti-entropy-snapshot-to-peer! rt #(send-to-conn! conn-entry %))
                                                                   (catch Exception _ nil))))))
                                                   ;; SCTP association established -> active side creates channels
                                                   (when active?
                                                     (let [cid (api/create-data-channel! dc-node "control" {:ordered true})
                                                           hid (api/create-data-channel! dc-node "heartbeat" {:ordered false :max-retransmits 0})]
                                                       (reset! ctrl-id cid)
                                                       (reset! hb-id hid)
                                                       (submit-event! rt {:type :peer-connected :peer-id pid :now-ms (System/currentTimeMillis)})
                                                       (future
                                                         (try
                                                           (Thread/sleep 30)
                                                           (push-anti-entropy-snapshot-to-peer! rt #(send-to-conn! conn-entry %))
                                                           (catch Exception _ nil)))))))
                                               :on-message
                                               (fn [evt]
                                                 (try
                                                   (let [p (:payload evt)
                                                         msg (when (fressian/bytes? p) (fressian/decode-wire p))]
                                                     (if (map? msg)
                                                       (receive-peer-message! rt msg)
                                                       (apply-shell-event! shell-atom {:type :drop :reason :malformed-peer-frame :detail pid})))
                                                   (catch Exception e
                                                     (apply-shell-event! shell-atom {:type :drop :reason :peer-decode-error :detail (.getMessage e)}))))
                                               :on-error
                                               (fn [evt]
                                                 (apply-shell-event! shell-atom
                                                                     {:type :drop
                                                                      :reason :peer-dtls-error
                                                                      :peer pid
                                                                      :detail (or (:message evt) (:error evt) (str evt))}))
                                               :on-close
                                               (fn [_]
                                                 (submit-event! rt {:type :peer-disconnected :peer-id pid :now-ms (System/currentTimeMillis)}))}]
                                (api/start! dc-node {:ip peer-ip
                                                     :port peer-port
                                                     :fingerprint peer-fp
                                                     :remote-ice-ufrag (:ufrag remote-ice)
                                                     :remote-ice-pwd (:pwd remote-ice)}
                                            callbacks)
                                (api/set-max-message-size! dc-node)
                                (swap! peer-conns-atom assoc pid conn-entry))
                              (catch Exception e
                                (apply-shell-event! shell-atom {:type :diagnose :reason :peer-dial-error :peer pid :detail (.getMessage e)}))))))]
    (reset! (:send-to-peers!-atom rt) broadcast!)
    (reset! (:on-fetch-blob-atom rt)
            (fn [{:keys [cid]}]
              (broadcast! {:type :peer-fetch-blob :cid cid})))
    (doseq [pid peer-ids]
      (connect-peer! pid))
    (.scheduleWithFixedDelay scheduler
                             ^Runnable
                             (fn []
                               (when (.get running?)
                                 (try
                                   (let [now (System/currentTimeMillis)]
                                     (tick-runtime! rt now)
                                     (let [healthy (get-in @(:subnet-atom rt) [:leader-election :healthy-nodes] #{})]
                                       (doseq [pid peer-ids]
                                         (let [conn (get @peer-conns-atom pid)
                                               dc (:node conn)
                                               st (when dc (try (api/get-state dc) (catch Exception _ nil)))
                                               age (- now (long (or (:created-at conn) 0)))]
                                           (when (or (nil? conn)
                                                     (= st :closed)
                                                     (and (not (contains? healthy pid)) (>= age hb-timeout)))
                                             (connect-peer! pid))))))
                                   (catch Exception _ nil))))
                             0
                             hb-interval
                             TimeUnit/MILLISECONDS)
    (let [close-fn (fn [{:keys [sched conns]}]
                     (.set running? false)
                     (when sched (try (.shutdownNow ^ScheduledExecutorService sched) (catch Exception _ nil)))
                     (doseq [[_ c] @conns]
                       (when-let [n (:node c)]
                         (try (api/close! n) (catch Exception _ nil)))))]
      (apply-shell-event! shell-atom {:type :started :generation gen :resources {:sched scheduler :conns peer-conns-atom}})
      {:shell-atom shell-atom
       :peer-conns-atom peer-conns-atom
       :stop-fn (fn []
                  (reset! (:send-to-peers!-atom rt) nil)
                  (reset! (:on-fetch-blob-atom rt) nil)
                  (apply-shell-event! shell-atom {:type :stop} close-fn))})))

(defn stop-datachannel-peer-mesh!
  "Stops all `clj-datachannel` peer connections and scheduler cleanly."
  [mesh]
  (when-let [stop-fn (:stop-fn mesh)]
    (stop-fn))
  mesh)

;; =============================================================================
;; 6. Phase C: Pre-Cutover `clj-web` State Migration & Mail Operator Parity
;; =============================================================================

(defn- content-type-for-filename
  [name-str]
  (let [l (str/lower-case (or name-str ""))]
    (cond
      (or (str/ends-with? l ".html") (str/ends-with? l ".htm")) "text/html; charset=utf-8"
      (str/ends-with? l ".md") "text/markdown; charset=utf-8"
      (str/ends-with? l ".json") "application/json; charset=utf-8"
      (or (str/ends-with? l ".js") (str/ends-with? l ".mjs")) "application/javascript; charset=utf-8"
      (str/ends-with? l ".css") "text/css; charset=utf-8"
      (or (str/ends-with? l ".edn") (str/ends-with? l ".txt")) "text/plain; charset=utf-8"
      :else "application/octet-stream")))

(defn- parse-eml-headers-and-body
  [^String raw-eml]
  (let [[hdr-block body-part] (str/split (or raw-eml "") #"\r?\n\r?\n" 2)
        lines (str/split (or hdr-block "") #"\r?\n")
        hdrs (reduce (fn [acc line]
                       (cond
                         (re-matches #"(?i)^From:\s*(.*)$" line)
                         (assoc acc :from (str/trim (second (re-matches #"(?i)^From:\s*(.*)$" line))))
                         (re-matches #"(?i)^To:\s*(.*)$" line)
                         (assoc acc :to (str/trim (second (re-matches #"(?i)^To:\s*(.*)$" line))))
                         (re-matches #"(?i)^Subject:\s*(.*)$" line)
                         (assoc acc :subject (str/trim (second (re-matches #"(?i)^Subject:\s*(.*)$" line))))
                         :else acc))
                     {}
                     lines)
        clean-to (when-let [t (:to hdrs)]
                   (str/lower-case (or (second (re-find #"<([^>]+)>" t)) t)))]
    (assoc hdrs
           :recipient clean-to
           :body (str/trim (or body-part "")))))

(defn- next-seq-for-path
  [rt path]
  (let [inst @(:subnet-atom rt)
        sid (:subnet-id inst)
        existing (get-in inst [:data :pointers [sid path]])]
    (inc (long (or (:pointer/seq existing) 0)))))

(defn migrate-clj-web-state!
  "Idempotently migrates a `clj-web` node's disk state (`certs/`, `mail/*.eml`, authored `:content-root`
   files & directory descriptors, and static DNS records) into `rt`'s `Blob` + `Pointer` store."
  ([rt config]
   (migrate-clj-web-state! rt config {}))
  ([rt config opts]
   (let [state-dir (io/file (or (:state-dir config) (:state-dir rt)))
         content-root (some-> (get-in config [:http :content-root]) io/file)
         domain (or (:domain config) "bitecho.org")
         auth-pub (:default-sender rt)
         auth-priv (:node-privkey rt)
         tls-secret (or (resolve-tls-secret opts) (:tls-secret rt))
         max-asset-bytes (long (or (:max-asset-bytes opts) (* 2 1024 1024)))
         now-ms (System/currentTimeMillis)
         sid (:subnet-id @(:subnet-atom rt))
         tls-migrated? (atom false)
         emails-cnt (atom 0)
         web-cnt (atom 0)
         dns-cnt (atom 0)]

     ;; 1. Migrate TLS bundle (certs/bundle.edn or fullchain.pem + privkey.pem)
     (let [bundle-edn (io/file state-dir "certs" "bundle.edn")
           fullchain (io/file state-dir "certs" "fullchain.pem")
           privkey (io/file state-dir "certs" "privkey.pem")
           {:keys [cert-pem key-pem]}
           (cond
             (.exists bundle-edn) (try (edn/read-string (slurp bundle-edn)) (catch Exception _ nil))
             (and (.exists fullchain) (.exists privkey)) {:cert-pem (slurp fullchain) :key-pem (slurp privkey)}
             :else nil)]
       (when (and cert-pem key-pem tls-secret)
         (when-let [leaf-der (acme-proto/extract-first-pem-cert-der cert-pem)]
           (let [fp (acme-proto/cert-der-sha256-hex leaf-der)
                 existing (data/resolve-pointer (:data @(:subnet-atom rt)) sid "tls/current-cert" now-ms)]
             (when-not (= fp (get-in existing [:pointer/proof :fingerprint]))
               (let [enc-key (encrypt-tls-key-pem tls-secret key-pem)
                     b (data/make-blob (fressian/encode-canonical {:cert-pem cert-pem
                                                                   :encrypted-key enc-key})
                                       "application/fressian")
                     r (publish-blob-and-pointer! rt {:blob b
                                                      :path "tls/current-cert"
                                                      :seq (next-seq-for-path rt "tls/current-cert")
                                                      :authority-pubkey auth-pub
                                                      :authority-privkey auth-priv
                                                      :proof {:proof/type :cert :fingerprint fp}
                                                      :now-ms now-ms})]
                 (when (:applied? r)
                   (reset! tls-migrated? true))))))))

     ;; 2. Migrate mail/*.eml -> message/rfc822 Blobs + mail/<rcpt>/<stem> Pointers
     (let [mail-dir (io/file state-dir "mail")]
       (when (.exists mail-dir)
         (doseq [^File f (sort-by #(.getName ^File %) (.listFiles mail-dir))
                 :when (and (.isFile f) (str/ends-with? (.getName f) ".eml"))]
           (let [raw (slurp f)
                 parsed (parse-eml-headers-and-body raw)
                 rcpt (or (:recipient parsed) (str "postmaster@" domain))
                 stem (str/replace (.getName f) #"\.eml$" "")
                 path (str "mail/" rcpt "/" stem)]
             (when-not (data/resolve-pointer (:data @(:subnet-atom rt)) sid path now-ms)
               (let [b (data/make-blob (fressian/utf8->bytes raw) "message/rfc822")
                     r (publish-blob-and-pointer! rt {:blob b
                                                      :path path
                                                      :seq (next-seq-for-path rt path)
                                                      :authority-pubkey auth-pub
                                                      :authority-privkey auth-priv
                                                      :now-ms now-ms})]
                 (when (:applied? r)
                   (swap! emails-cnt inc))))))))

     ;; 3. Migrate authored static web files & directory/bootstrap descriptors under content-root
     (when (and content-root (.exists content-root))
       (let [root-path (.toRealPath (.toPath content-root) (into-array java.nio.file.LinkOption []))]
         (doseq [^File f (file-seq (.toFile root-path))
                 :when (and (.isFile f) (<= (.length f) max-asset-bytes))]
           (let [rel (str/replace (str (.relativize root-path (.toPath f))) "\\" "/")]
             ;; Skip bare git repositories & hidden files (served zero-copy via content-root fallback)
             (when-not (or (str/starts-with? rel "git/")
                           (str/starts-with? rel ".")
                           (str/includes? rel "/."))
               (let [bs (Files/readAllBytes (.toPath f))
                     b (data/make-blob bs (content-type-for-filename rel))
                     web-path (str "web/" rel)
                     cur-ptr (data/resolve-pointer (:data @(:subnet-atom rt)) sid web-path now-ms)]
                 (when-not (= (:blob/cid b) (:pointer/target cur-ptr))
                   (let [r (publish-blob-and-pointer! rt {:blob b
                                                          :path web-path
                                                          :seq (next-seq-for-path rt web-path)
                                                          :authority-pubkey auth-pub
                                                          :authority-privkey auth-priv
                                                          :now-ms now-ms})]
                     (when (:applied? r)
                       (swap! web-cnt inc))))
                 ;; Also publish canonical "dir/<nick>" or "bootstrap" aliases!
                 (when-let [[_ nick] (re-matches #"directory/([a-z0-9_-]+)\.json" rel)]
                   (let [dir-path (str "dir/" nick)
                         dp (data/resolve-pointer (:data @(:subnet-atom rt)) sid dir-path now-ms)]
                     (when-not (= (:blob/cid b) (:pointer/target dp))
                       (publish-blob-and-pointer! rt {:blob b
                                                      :path dir-path
                                                      :seq (next-seq-for-path rt dir-path)
                                                      :authority-pubkey auth-pub
                                                      :authority-privkey auth-priv
                                                      :now-ms now-ms}))))
                 (when (= rel "devnet/bootstrap.edn")
                   (let [bp (data/resolve-pointer (:data @(:subnet-atom rt)) sid "bootstrap" now-ms)]
                     (when-not (= (:blob/cid b) (:pointer/target bp))
                       (publish-blob-and-pointer! rt {:blob b
                                                      :path "bootstrap"
                                                      :seq (next-seq-for-path rt "bootstrap")
                                                      :authority-pubkey auth-pub
                                                      :authority-privkey auth-priv
                                                      :now-ms now-ms}))))))))))

     ;; 4. Migrate static DNS TXT / MX / CAA records from config
     (let [serial (AtomicLong. 1)
           publish-dns! (fn [rr-type rel records]
                          (when (seq records)
                            (let [path (str "dns/" rr-type "/" rel)
                                  b (data/make-blob (fressian/encode-canonical {:records (vec records)}) "application/fressian")
                                  cur (data/resolve-pointer (:data @(:subnet-atom rt)) sid path now-ms)]
                              (when-not (= (:blob/cid b) (:pointer/target cur))
                                (let [r (publish-blob-and-pointer! rt {:blob b
                                                                       :path path
                                                                       :seq (next-seq-for-path rt path)
                                                                       :authority-pubkey auth-pub
                                                                       :authority-privkey auth-priv
                                                                       :proof {:proof/type :zone :serial (.getAndIncrement serial)}
                                                                       :now-ms now-ms})]
                                  (when (:applied? r)
                                    (swap! dns-cnt inc)))))))]
       (doseq [[rel v] (get-in config [:dns :txt-records] {})]
         (publish-dns! "TXT" (if (keyword? rel) (name rel) (str rel)) (if (coll? v) v [v])))
       (when-let [mxs (seq (get-in config [:dns :mx-records]))]
         (publish-dns! "MX" "@" mxs))
       (when-let [caas (seq (get-in config [:dns :caa-records]))]
         (publish-dns! "CAA" "@" caas)))

     {:ok? true
      :tls-migrated? @tls-migrated?
      :emails-migrated @emails-cnt
      :web-assets-migrated @web-cnt
      :dns-records-migrated @dns-cnt})))

(defn list-subnet-emails
  "Lists active `mail/<rcpt>/<id>` Pointers in `rt` in chronological path order."
  [rt]
  (let [now-ms (System/currentTimeMillis)
        inst @(:subnet-atom rt)
        sid (:subnet-id inst)
        ptrs (->> (get-in inst [:data :pointers] {})
                  (keep (fn [[[psub ppath] _]]
                          (when (and (= psub sid)
                                     (str/starts-with? ppath "mail/")
                                     (some? (data/resolve-pointer (:data inst) sid ppath now-ms)))
                            ppath)))
                  sort)]
    (mapv (fn [path]
            (let [res (resolve-path-blob! rt path now-ms)
                  raw (when (:ok? res) (fressian/bytes->utf8 (get-in res [:blob :blob/bytes])))
                  parsed (parse-eml-headers-and-body raw)
                  parts (str/split path #"/" 3)
                  mail-id (nth parts 2 path)]
              {:id mail-id
               :path path
               :cid (get-in res [:blob :blob/cid])
               :from (or (:from parsed) "unknown")
               :to (or (:to parsed) (nth parts 1 "unknown"))
               :subject (or (:subject parsed) "(no subject)")
               :body (or (:body parsed) "")
               :raw-eml raw}))
          ptrs)))

(defn read-subnet-email
  "Reads a specific email by `:id` / `:path` (or `\"latest\"` when `target` is nil/blank/`\"latest\"`)."
  [rt target]
  (let [emails (list-subnet-emails rt)
        t (when-not (str/blank? (str (or target ""))) (str/trim (str target)))]
    (when (seq emails)
      (if (or (nil? t) (= t "latest"))
        (last emails)
        (first (filter #(or (= (:id %) t) (= (:path %) t)) emails))))))

(defn delete-subnet-emails!
  "Tombstones (`:pointer/target nil`) matching `mail/*` Pointers in `rt` (`\"all\"`, `\"latest\"`, or specific ID)."
  [rt target]
  (let [emails (list-subnet-emails rt)
        t (when-not (str/blank? (str (or target ""))) (str/trim (str target)))
        selected (cond
                   (empty? emails) []
                   (= t "all") emails
                   (or (nil? t) (= t "latest")) [(last emails)]
                   :else (filterv #(or (= (:id %) t) (= (:path %) t)) emails))
        inst @(:subnet-atom rt)
        sid (:subnet-id inst)
        le-term (get-in inst [:leader-election :term])
        auth-pub (:default-sender rt)
        auth-priv (:node-privkey rt)]
    (doseq [m selected]
      (let [tomb (data/sign-pointer auth-priv
                                    (cond-> {:pointer/authority auth-pub
                                             :pointer/subnet sid
                                             :pointer/path (:path m)
                                             :pointer/seq (next-seq-for-path rt (:path m))
                                             :pointer/target nil
                                             :pointer/proof {:proof/type :self}}
                                      (some? le-term) (assoc :pointer/leader-term (long le-term))))]
        (submit-event! rt {:type :publish-pointer
                           :sender auth-pub
                           :pointer tomb
                           :now-ms (System/currentTimeMillis)})))
    {:deleted (mapv :id selected)
     :count (count selected)}))
