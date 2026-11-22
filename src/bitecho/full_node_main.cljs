(ns bitecho.full-node-main
  "Milestone D36 (`BIP-010 / BIP-011: P-NODE-1`): Standalone Node.js Full / Infra Node Boundary Shell (`dist/bitecho-full-node.cjs`).
   Full JVM infra-node parity (`bitecho.shell.{infra,dns,http,smtp,blob-fs}`) on Node.js v22+ with zero JVM:
   - Authoritative UDP DNS (`:53` via `node:dgram`) delegated to `bitecho.core.protocol.dns`
   - Edge HTTP (`:80`), Port `:443` Passthrough Multiplexer (`HTTP CONNECT` allowlist, DTLS/STUN/SNI ingress, mTLS HTTPS),
     and localhost diagnostics server (`127.0.0.1:8080`)
   - Relay API (`/relay/v1/{send,poll,ack,chain-state,health,status}`), Artifact API (`/artifact/v1/{blob,pointer,list}`),
     Directory API (`/directory/v1/*`), ACME HTTP-01 (`/.well-known/acme-challenge/*`), Static/Git/Pointer serving
   - Inbound SMTP (`:25` via `node:net`) delegated to `bitecho.core.protocol.smtp`
   - Byte-for-byte on-disk compatibility with `/var/lib/clj-web/{subnet-pointers.fressian,blobs/,certs/,identity/,mail/}`
     and AES-256-GCM decryption of `tls/current-cert` via `/etc/clj-web/tls-secret.key`
   - Single-authority generation-tagged lifecycle state (`bitecho.core.infra/transition-shell`, Rules 4 & 5)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.infra :as core-infra]
            [bitecho.core.mesh :as core-mesh]
            [bitecho.core.protocol.acme :as acme-proto]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.core.protocol.smtp :as smtp-proto]
            [bitecho.core.storage :as storage]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.defense.core :as defense]
            [bitecho.deploy.core :as deploy]
            [bitecho.economy.account :as account]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.host.core :as host]
            [bitecho.light-node.core :as light-core]
            [bitecho.observability.core :as obs]
            [bitecho.ops.incident :as incident]
            [bitecho.snapshot.core :as snap]
            [bitecho.state-machine :as sm]
            [bitecho.storage.app-release :as app-release]
            [bitecho.storage.chunk-constants :as chunk-const]
            [cljs.reader :as edn]
            [clojure.string :as str]
            [datachannel.api :as api]
            [datachannel.dtls :as dtls]))

(def ^:private node-fs (js/require "node:fs"))
(def ^:private node-fsp (.-promises node-fs))
(def ^:private node-path (js/require "node:path"))
(def ^:private node-http (js/require "node:http"))
(def ^:private node-https (js/require "node:https"))
(def ^:private node-child-process (js/require "node:child_process"))
(def ^:private node-tls (js/require "node:tls"))
(def ^:private node-net (js/require "node:net"))
(def ^:private node-dgram (js/require "node:dgram"))
(def ^:private node-crypto (js/require "node:crypto"))
(def ^:private node-zlib (js/require "node:zlib"))

(def full-node-version
  "Current Node.js Full / Infra Node release version."
  "0.23.21")

(def ^:private obs-router-atom (atom (obs/init-sink-router {:node-id "full-node"})))
(def ^:private defense-state-atom (atom (defense/init-defense-state)))
(def ^:private status-rate-limiter-atom (atom (incident/init-status-rate-limiter)))
(def ^:private status-snapshot-cache-atom (atom {:json nil :updated-at-ms 0}))
(def ^:private poll-telemetry-atom (atom {:poll-count 0 :last-sample-ms 0 :last-heap-used 0}))
(def ^:private validator-event-error-count (atom 0))
(def ^:private runtime-metrics-atom
  (atom {:loop-lag-samples []
         :last-snapshot-encode-ms 0
         :http-5xx-count 0
         :heap-samples []
         :loop-sampler-started? false}))
(def ^:private running-bundle-sha256-atom (atom nil))

(defn- running-bundle-sha256
  "Computes and caches the SHA-256 hex digest of the currently executing Node.js bundle once."
  []
  (or @running-bundle-sha256-atom
      (let [sha (try
                  (let [fp (when (exists? js/__filename) js/__filename)]
                    (when (and fp (.existsSync node-fs fp))
                      (let [h (.createHash node-crypto "sha256")]
                        (.update h (.readFileSync node-fs fp))
                        (.digest h "hex"))))
                  (catch :default _ nil))]
        (reset! running-bundle-sha256-atom (or sha "unknown"))
        @running-bundle-sha256-atom)))

(defn- start-event-loop-lag-sampler!
  "Starts a lightweight 1s event-loop lag probe (bounded to last 60 samples)."
  []
  (when-not (:loop-sampler-started? @runtime-metrics-atom)
    (swap! runtime-metrics-atom assoc :loop-sampler-started? true)
    (let [expected-atom (atom (+ (.now js/Date) 1000))
          iv (js/setInterval
              (fn []
                (let [now (.now js/Date)
                      lag (max 0 (- now @expected-atom))]
                  (reset! expected-atom (+ now 1000))
                  (swap! runtime-metrics-atom update :loop-lag-samples
                         (fn [v]
                           (let [v' (conj (vec (or v [])) lag)]
                             (if (> (count v') 60) (subvec v' (- (count v') 60)) v'))))))
              1000)]
      (when (.-unref iv) (.unref iv)))))

(defn- sample-v8-heap-headroom-pct
  "Returns remaining V8 heap headroom as a percentage [0.0..100.0] of heap_size_limit."
  []
  (try
    (let [v8 (js/require "v8")
          stats (.getHeapStatistics v8)
          used (double (.-used_heap_size stats))
          limit (double (.-heap_size_limit stats))]
      (if (pos? limit)
        (/ (Math/round (* 1000.0 (max 0.0 (* 100.0 (- 1.0 (/ used limit)))))) 1000.0)
        0.0))
    (catch :default _ 0.0)))

(defn- record-heap-sample!
  [now-ms heap-used]
  (let [updated (swap! runtime-metrics-atom update :heap-samples
                       (fn [v]
                         (let [v' (conj (vec (or v [])) {:ts-ms now-ms :heap-used heap-used})]
                           (if (> (count v') 10) (subvec v' (- (count v') 10)) v'))))]
    (obs/compute-heap-slope-bytes-per-min (:heap-samples updated))))

(defn- sample-node-runtime-telemetry!
  "P-OBS-5 / F-SOAK-1 runtime telemetry hook: samples process RSS/heap, event-loop lag, and
   poll-route counts into the P-OBS-2 sink router without blocking the request path."
  [node-id active-waiters]
  (try
    (let [now-ms (.now js/Date)
          last-ms (:last-sample-ms @poll-telemetry-atom 0)]
      (when (>= (- now-ms last-ms) 15000)
        (let [mem (.memoryUsage js/process)
              rt-rec (obs/collect-nodejs-runtime
                      {:node-id node-id
                       :rss-bytes (.-rss mem)
                       :heap-used-bytes (.-heapUsed mem)
                       :heap-total-bytes (.-heapTotal mem)
                       :external-bytes (.-external mem)
                       :event-loop-lag-ms 0.0})
              relay-rec (obs/collect-relay-metric
                         {:node-id node-id
                          :poll-queue-depth (long (:poll-count @poll-telemetry-atom 0))
                          :active-waiters (long (or active-waiters 0))
                          :dropped (long (:dropped @obs-router-atom 0))})]
          (swap! poll-telemetry-atom assoc :last-sample-ms now-ms :last-heap-used (.-heapUsed mem))
          (swap! obs-router-atom
                 (fn [r]
                   (first (obs/route-records r [rt-rec relay-rec] {:disk {:ok? true} :network {:ok? true}})))))))
    (catch :default _ nil)))

(declare fetch-validator-chain-state-snapshots! forward-gossip-to-agents! start-validator-mesh-node! step-validator-event!)

;; =============================================================================
;; 1. Byte / Buffer / Crypto / Diagnostic Helpers
;; =============================================================================

(defn- kp->pk-hex [kp]
  (let [pub (or (:public-key kp) (:public kp))]
    (if (string? pub) pub (basalt/bytes->hex pub))))

(defn- kp->sk [kp]
  (or (:private-key kp) (:private kp)))

(defn- buf->u8 ^js [buf]
  (if (instance? js/Uint8Array buf)
    (js/Uint8Array. (.-buffer buf) (.-byteOffset buf) (.-byteLength buf))
    (let [b (.from js/Buffer buf)]
      (js/Uint8Array. (.-buffer b) (.-byteOffset b) (.-byteLength b)))))

(defn- u8->buf ^js [u8]
  (if (.isBuffer js/Buffer u8)
    u8
    (.from js/Buffer (.-buffer u8) (.-byteOffset u8) (.-byteLength u8))))

(defn- sha256-buf-hex [buf]
  (-> (.createHash node-crypto "sha256")
      (.update buf)
      (.digest "hex")))

(defn- raw-byte-array?
  [v]
  (or (instance? js/Uint8Array v)
      (.isBuffer js/Buffer v)))

(defn- safe-map-get
  "Safe lookup that never throws CompareError when probing keyword keys on string-keyed sorted-maps."
  [m k]
  (try (get m k) (catch :default _ nil)))

(defn- sanitize-log-payload
  "Strips raw byte arrays (`:bytes`, `:blob/bytes`, `Uint8Array`, `Buffer`) from stdout/stderr JSON logs,
   preserving only `{:cid :size_bytes :media_type}` metadata (BIP-018 Track 2)."
  [v]
  (cond
    (raw-byte-array? v)
    {:size_bytes (.-length v)}

    (map? v)
    (let [raw-bs (or (safe-map-get v :blob/bytes)
                     (safe-map-get v :bytes)
                     (safe-map-get v "blob/bytes")
                     (safe-map-get v "bytes"))]
      (if (and (some? raw-bs) (raw-byte-array? raw-bs))
        (let [cid-val (or (safe-map-get v :blob/cid) (safe-map-get v :cid) (safe-map-get v "cid"))
              mt-val (or (safe-map-get v :blob/media-type) (safe-map-get v :media-type) (safe-map-get v :media_type) (safe-map-get v "media_type"))]
          (cond-> {:size_bytes (.-length raw-bs)}
            cid-val (assoc :cid cid-val)
            mt-val (assoc :media_type mt-val)))
        (reduce-kv (fn [acc k val]
                     (if (contains? #{:bytes :blob/bytes "bytes" "blob/bytes"} k)
                       (if (raw-byte-array? val)
                         (assoc acc :size_bytes (.-length val))
                         acc)
                       (assoc acc k (sanitize-log-payload val))))
                   {}
                   v)))

    (vector? v)
    (mapv sanitize-log-payload v)

    (sequential? v)
    (mapv sanitize-log-payload v)

    :else v))

(defn- log-diagnostic!
  [diag]
  (try
    (.write (.-stderr js/process)
            (str (js/JSON.stringify (clj->js (sanitize-log-payload (assoc diag :ts (.now js/Date))))) "\n"))
    (catch :default _ nil)))

(defn- apply-shell-event!
  ([shell-atom event]
   (apply-shell-event! shell-atom event nil))
  ([shell-atom event close-fn]
   (let [effs-box (atom [])]
     (swap! shell-atom
            (fn [st]
              (let [[st' effs] (core-infra/transition-shell st event)]
                (reset! effs-box effs)
                st')))
     (doseq [eff @effs-box]
       (cond
         (and (= :close-resources (:effect eff)) close-fn)
         (try (close-fn (:resources eff)) (catch :default _ nil))

         (= :diagnose (:effect eff))
         (log-diagnostic! eff)))
     @shell-atom)))

(defn- atomic-write-file!
  "Explicit boot/SIGTERM-only synchronous atomic write helper (BIP-014 exception).
   All runtime hot paths MUST use `atomic-write-file-async!`."
  [dest-path data-buf-or-str mode]
  (let [parent (.dirname node-path dest-path)
        _ (when-not (.existsSync node-fs parent)
            (.mkdirSync node-fs parent #js {:recursive true}))
        rand-hex (.toString (.randomBytes node-crypto 6) "hex")
        tmp-path (str dest-path ".tmp-" (.-pid js/process) "-" rand-hex)]
    (try
      (.writeFileSync node-fs tmp-path data-buf-or-str)
      (when mode
        (try (.chmodSync node-fs tmp-path mode) (catch :default _ nil)))
      (.renameSync node-fs tmp-path dest-path)
      (catch :default e
        (try (when (.existsSync node-fs tmp-path) (.unlinkSync node-fs tmp-path)) (catch :default _ nil))
        (throw e)))))

(defn- atomic-write-file-async!
  "Zero-Sync-IO async atomic write via `fs.promises`: mkdir -> writeFile -> chmod -> rename.
   Returns a JS Promise resolving to `dest-path` (BIP-014 / P-ASYNC-2)."
  [dest-path data-buf-or-str mode]
  (let [parent (.dirname node-path dest-path)
        rand-hex (.toString (.randomBytes node-crypto 6) "hex")
        tmp-path (str dest-path ".tmp-" (.-pid js/process) "-" rand-hex)]
    (-> (.mkdir node-fsp parent #js {:recursive true})
        (.then (fn [_] (.writeFile node-fsp tmp-path data-buf-or-str)))
        (.then (fn [_]
                 (if mode
                   (-> (.chmod node-fsp tmp-path mode)
                       (.catch (fn [_] nil)))
                   nil)))
        (.then (fn [_] (.rename node-fsp tmp-path dest-path)))
        (.then (fn [_] dest-path))
        (.catch (fn [e]
                  (-> (.unlink node-fsp tmp-path)
                      (.catch (fn [_] nil))
                      (.then (fn [_] (js/Promise.reject e)))))))))

;; =============================================================================
;; 2. AES-256-GCM TLS Secret & Decryption (Exact JVM Parity with shell/infra.clj)
;; =============================================================================

(defn- resolve-tls-secret
  [{:keys [tls-secret tls-secret-file]}]
  (cond
    (and (some? tls-secret) (fressian/bytes? tls-secret) (pos? (fressian/count-bytes tls-secret)))
    (u8->buf tls-secret)

    (and (string? tls-secret) (not (str/blank? tls-secret)))
    (let [s (str/trim tls-secret)]
      (if (re-matches #"[0-9a-fA-F]{64}" s)
        (.from js/Buffer (str/lower-case s) "hex")
        (.from js/Buffer s "utf8")))

    (and (string? tls-secret-file) (.existsSync node-fs tls-secret-file))
    (let [s (str/trim (.readFileSync node-fs tls-secret-file "utf8"))]
      (when-not (str/blank? s)
        (if (re-matches #"[0-9a-fA-F]{64}" s)
          (.from js/Buffer (str/lower-case s) "hex")
          (.from js/Buffer s "utf8"))))

    :else nil))

(defn- normalize-32-byte-secret
  [secret-buf]
  (cond
    (and secret-buf (= 32 (.-length secret-buf))) secret-buf
    secret-buf (-> (.createHash node-crypto "sha256") (.update secret-buf) (.digest))
    :else (throw (ex-info "Invalid 32-byte TLS cluster secret" {}))))

(defn- decrypt-tls-key-pem
  "Decrypts JVM-encrypted `{:iv <bytes> :ciphertext <bytes-with-16B-gcm-tag>}` using Node `aes-256-gcm`."
  [secret-buf {:keys [iv ciphertext]}]
  (let [key-buf (normalize-32-byte-secret secret-buf)
        iv-buf (u8->buf iv)
        ct-all (u8->buf ciphertext)
        ct-len (.-length ct-all)]
    (when (< ct-len 16)
      (throw (ex-info "AES-GCM ciphertext too short" {:len ct-len})))
    (let [ct-body (.subarray ct-all 0 (- ct-len 16))
          auth-tag (.subarray ct-all (- ct-len 16))
          decipher (.createDecipheriv node-crypto "aes-256-gcm" key-buf iv-buf)]
      (.setAuthTag decipher auth-tag)
      (let [p1 (.update decipher ct-body)
            p2 (.final decipher)]
        (.toString (.concat js/Buffer #js [p1 p2]) "utf8")))))

(defn- compute-relay-auth-hmac
  [secret-buf endpoint body-buf]
  (when (and secret-buf (pos? (.-length secret-buf)))
    (let [hmac (.createHmac node-crypto "sha256" secret-buf)]
      (.update hmac (.from js/Buffer (str endpoint ":") "utf8"))
      (when (and body-buf (pos? (.-length body-buf)))
        (.update hmac body-buf))
      (.digest hmac "hex"))))

;; =============================================================================
;; 3. Disk-Backed Blob CAS (`blobs/<2>/<cid>`) & Fressian Pointer Snapshot
;; =============================================================================

(defn- blob-file-path [state-dir cid]
  (let [ncid (core-infra/normalize-cid cid)]
    (when (core-infra/valid-cid? ncid)
      (.join node-path state-dir "blobs" (subs ncid 0 2) ncid))))

(defn- blob-meta-path [state-dir cid]
  (let [ncid (core-infra/normalize-cid cid)]
    (when (core-infra/valid-cid? ncid)
      (.join node-path state-dir "blobs" (subs ncid 0 2) (str ncid ".meta.edn")))))

(defn- write-disk-blob-async!
  "Zero-Sync-IO async CAS blob persistence (`fs.promises`) returning a JS Promise
   that resolves to `{:ok? true :cid ... :path ...}` or `{:ok? false :error ... :detail ...}`.
   Emits Rule 5 `:diagnose` on failure."
  [state-dir blob shell-atom]
  (let [ncid (core-infra/normalize-cid (:blob/cid blob))
        bs (:blob/bytes blob)
        mt (str (or (:blob/media-type blob) "application/octet-stream"))]
    (if-not (and (core-infra/valid-cid? ncid) (fressian/bytes? bs))
      (do
        (apply-shell-event! shell-atom {:type :diagnose :reason :blob-fs-malformed-write :cid ncid})
        (js/Promise.resolve {:ok? false :error :malformed-blob :detail "malformed-blob"}))
      (let [actual (data/compute-cid bs)]
        (if (not= ncid actual)
          (do
            (apply-shell-event! shell-atom {:type :diagnose :reason :blob-cid-mismatch :expected ncid :actual actual})
            (js/Promise.resolve {:ok? false :error :blob-cid-mismatch :detail "blob-cid-mismatch"}))
          (let [dest (blob-file-path state-dir ncid)
                mdest (blob-meta-path state-dir ncid)
                buf (u8->buf bs)
                meta-str (pr-str {:media-type mt :size (.-length buf)})]
            (-> (.access node-fsp dest)
                (.catch (fn [_] (atomic-write-file-async! dest buf nil)))
                (.then (fn [_]
                         (-> (.access node-fsp mdest)
                             (.catch (fn [_] (atomic-write-file-async! mdest meta-str nil))))))
                (.then (fn [_] {:ok? true :cid ncid :path dest}))
                (.catch (fn [e]
                          (let [msg (or (.-message e) (str e))]
                            (apply-shell-event! shell-atom
                                                {:type :diagnose
                                                 :reason :blob-fs-async-write-failed
                                                 :cid ncid
                                                 :detail msg})
                            {:ok? false :error :blob-fs-async-write-failed :detail msg}))))))))))

(defn- write-disk-blob!
  "Fire-and-forget wrapper over `write-disk-blob-async!` for non-HTTP gossip ingestion paths."
  [state-dir blob shell-atom]
  (write-disk-blob-async! state-dir blob shell-atom)
  {:ok? true :cid (core-infra/normalize-cid (:blob/cid blob))})

(defn- read-disk-blob-async!
  "Zero-Sync-IO async CAS blob read (`fs.promises`), invoking `(cb result-map)`."
  [state-dir cid shell-atom cb]
  (let [ncid (core-infra/normalize-cid cid)
        fpath (blob-file-path state-dir ncid)
        mpath (blob-meta-path state-dir ncid)]
    (if-not fpath
      (cb {:ok? false :error :blob-not-found})
      (-> (.readFile node-fsp fpath)
          (.then (fn [buf]
                   (let [u8 (buf->u8 buf)
                         actual (data/compute-cid u8)]
                     (if (not= ncid actual)
                       (do
                         (apply-shell-event! shell-atom {:type :diagnose :reason :blob-fs-corrupt :expected ncid :actual actual})
                         (cb {:ok? false :error :blob-cid-mismatch}))
                       (-> (if mpath
                             (-> (.readFile node-fsp mpath "utf8")
                                 (.then (fn [s] (try (edn/read-string s) (catch :default _ nil))))
                                 (.catch (fn [_] nil)))
                             (js/Promise.resolve nil))
                           (.then (fn [meta-map]
                                    (cb {:ok? true
                                         :path fpath
                                         :blob {:blob/cid ncid
                                                :blob/media-type (or (:media-type meta-map) "application/octet-stream")
                                                :blob/bytes u8}}))))))))
          (.catch (fn [e]
                    (if (= "ENOENT" (.-code e))
                      (cb {:ok? false :error :blob-not-found})
                      (do
                        (apply-shell-event! shell-atom {:type :diagnose :reason :blob-fs-io-error :cid ncid :detail (or (.-message e) (str e))})
                        (cb {:ok? false :error :blob-io-error})))))))))

(defn- read-disk-blob!
  "Boot-only synchronous CAS blob reader (used during initial TLS cert load).
   Runtime HTTP handlers use `read-disk-blob-async!`."
  [state-dir cid shell-atom]
  (let [ncid (core-infra/normalize-cid cid)
        fpath (blob-file-path state-dir ncid)
        mpath (blob-meta-path state-dir ncid)]
    (if-not (and fpath (.existsSync node-fs fpath))
      {:ok? false :error :blob-not-found}
      (try
        (let [buf (.readFileSync node-fs fpath)
              u8 (buf->u8 buf)
              actual (data/compute-cid u8)]
          (if (not= ncid actual)
            (do
              (apply-shell-event! shell-atom {:type :diagnose :reason :blob-fs-corrupt :expected ncid :actual actual})
              {:ok? false :error :blob-cid-mismatch})
            (let [meta-map (when (and mpath (.existsSync node-fs mpath))
                             (try (edn/read-string (.readFileSync node-fs mpath "utf8"))
                                  (catch :default _ nil)))]
              {:ok? true
               :path fpath
               :blob {:blob/cid ncid
                      :blob/media-type (or (:media-type meta-map) "application/octet-stream")
                      :blob/bytes u8}})))
        (catch :default e
          (apply-shell-event! shell-atom {:type :diagnose :reason :blob-fs-io-error :cid ncid :detail (.-message e)})
          {:ok? false :error :blob-io-error})))))

(defn- save-pointers-snapshot!
  "Zero-Sync-IO async pointer snapshot persistence via `atomic-write-file-async!`."
  [state-dir subnet-state shell-atom]
  (when state-dir
    (try
      (let [dest (.join node-path state-dir "subnet-pointers.fressian")
            payload {:subnet-id (:subnet-id subnet-state)
                     :policy (:policy subnet-state)
                     :pointers (get-in subnet-state [:data :pointers] {})}
            encoded (fressian/encode-canonical payload)]
        (-> (atomic-write-file-async! dest (u8->buf encoded) nil)
            (.catch (fn [e]
                      (apply-shell-event! shell-atom
                                          {:type :diagnose
                                           :reason :snapshot-save-failed
                                           :detail (or (.-message e) (str e))})))))
      (catch :default e
        (apply-shell-event! shell-atom {:type :diagnose :reason :snapshot-save-failed :detail (.-message e)})))))

(defn- load-pointers-snapshot
  [state-dir shell-atom]
  (when state-dir
    (let [fpath (.join node-path state-dir "subnet-pointers.fressian")]
      (when (.existsSync node-fs fpath)
        (try
          (let [buf (.readFileSync node-fs fpath)]
            (fressian/decode-wire (buf->u8 buf)))
          (catch :default e
            (apply-shell-event! shell-atom {:type :diagnose :reason :snapshot-load-failed :detail (.-message e)})
            nil))))))

;; =============================================================================
;; 4. Node Identity Loading (`<state-dir>/identity/node-identity.edn` & `cluster/node-identity.edn`)
;; =============================================================================

(defn- generate-random-ice-creds
  []
  {:ufrag (.toString (.randomBytes node-crypto 4) "hex")
   :pwd (.toString (.randomBytes node-crypto 12) "hex")})

(defn- load-or-create-node-identity!
  ([state-dir node-id]
   (load-or-create-node-identity! state-dir node-id nil))
  ([state-dir node-id shell-atom]
   (let [id-file (.join node-path state-dir "identity" "node-identity.edn")
         legacy-file (.join node-path state-dir "cluster" "node-identity.edn")
         read-ed-map (fn [f]
                       (when (.existsSync node-fs f)
                         (try
                           (let [m (edn/read-string (.readFileSync node-fs f "utf8"))]
                             (when (map? m) m))
                           (catch :default e
                             (when shell-atom
                               (apply-shell-event! shell-atom {:type :diagnose :reason :identity-read-failed :file f :detail (.-message e)}))
                             nil))))
         id-map (read-ed-map id-file)
         legacy-map (read-ed-map legacy-file)
         combined (merge id-map legacy-map)
         has-ed? (and (string? (:pubkey-hex combined)) (string? (:privkey-hex combined)))
         kp (when-not has-ed? (crypto/generate-keypair))
         pk-hex (if has-ed?
                  (str/lower-case (str/trim (:pubkey-hex combined)))
                  (str/lower-case (kp->pk-hex kp)))
         sk-hex (if has-ed?
                  (str/lower-case (str/trim (:privkey-hex combined)))
                  (str/lower-case (basalt/bytes->hex (kp->sk kp))))
         pk-bytes (basalt/hex->bytes pk-hex)
         sk-bytes (basalt/hex->bytes sk-hex)
         has-dtls? (and (string? (:cert-pem combined))
                        (string? (:key-pem combined))
                        (string? (:fingerprint combined)))
         gen-cert (when-not has-dtls? (dtls/generate-cert))
         cert-pem (if has-dtls? (:cert-pem combined) (:cert-pem gen-cert))
         key-pem (if has-dtls? (:key-pem combined) (:key-pem gen-cert))
         fp (core-mesh/normalize-fingerprint (if has-dtls? (:fingerprint combined) (:fingerprint gen-cert)))
         persisted-ice (or (:ice-creds combined)
                           (when (and (:ice-ufrag combined) (:ice-pwd combined))
                             {:ufrag (:ice-ufrag combined) :pwd (:ice-pwd combined)}))
         ice-creds (if (and (map? persisted-ice)
                            (string? (:ufrag persisted-ice))
                            (string? (:pwd persisted-ice))
                            (not (str/blank? (:ufrag persisted-ice)))
                            (not (str/blank? (:pwd persisted-ice))))
                     persisted-ice
                     (generate-random-ice-creds))
         needs-write? (or (not (and (map? id-map)
                                    (:pubkey-hex id-map)
                                    (:privkey-hex id-map)
                                    (:cert-pem id-map)
                                    (:key-pem id-map)
                                    (:fingerprint id-map)
                                    (:ice-creds id-map)))
                          (not= ice-creds (:ice-creds id-map)))]
     (when needs-write?
       (try
         (atomic-write-file! id-file
                             (pr-str {:pubkey-hex pk-hex
                                      :privkey-hex sk-hex
                                      :cert-pem cert-pem
                                      :key-pem key-pem
                                      :fingerprint fp
                                      :ice-creds ice-creds})
                             0600)
         (catch :default e
           (when shell-atom
             (apply-shell-event! shell-atom {:type :diagnose :reason :identity-write-failed :detail (.-message e)})))))
     {:node-id node-id
      :pubkey-hex pk-hex
      :privkey-hex sk-hex
      :pubkey-bytes pk-bytes
      :privkey-bytes sk-bytes
      :keypair {:public pk-bytes :private sk-bytes}
      :cert-pem cert-pem
      :key-pem key-pem
      :fingerprint fp
      :ice-creds ice-creds
      :cert-data {:cert cert-pem
                  :key key-pem
                  :fingerprint fp}})))

;; =============================================================================
;; 5. Unified Subnet Runtime Helpers
;; =============================================================================

(defn- resolve-cid-blob-async!
  "Zero-Sync-IO async CID blob resolver: hits in-memory cache synchronously, offloads disk reads to `read-disk-blob-async!`."
  [rt cid now-ms cb]
  (if (or (nil? cid) (str/blank? (str cid)))
    (cb {:ok? false :error :not-found})
    (let [ncid (core-infra/normalize-cid cid)
          inst @(:subnet-atom rt)
          sid (:subnet-id inst)
          denied (into #{} (map core-infra/normalize-cid) (get-in inst [:policy :subnet/denied-cids] #{}))]
      (if (contains? denied ncid)
        (cb {:ok? false :denied? true :error :denied-cid :cid ncid})
        (let [r-box (atom nil)
              _ (swap! (:subnet-atom rt)
                       (fn [cur]
                         (let [r (data/get-blob (get-in cur [:data :blobs]) ncid {:subnet sid :now-ms now-ms})]
                           (reset! r-box r)
                           (assoc-in cur [:data :blobs] (:store r)))))
              r1 @r-box]
          (if (:hit? r1)
            (cb {:ok? true
                 :cid ncid
                 :blob (:blob r1)
                 :file-path (blob-file-path (:state-dir rt) ncid)})
            (read-disk-blob-async!
             (:state-dir rt) ncid (:shell-atom rt)
             (fn [disk-res]
               (if (:ok? disk-res)
                 (do
                   (swap! (:subnet-atom rt)
                          (fn [cur]
                            (assoc cur :data (:state (data/put-data-blob (:data cur) (:blob disk-res) now-ms)))))
                   (cb {:ok? true
                        :cid ncid
                        :blob (:blob disk-res)
                        :file-path (:path disk-res)}))
                 (cb {:ok? false :error :missing-blob :cid ncid}))))))))))

(defn- resolve-cid-blob!
  [rt cid now-ms]
  (if (or (nil? cid) (str/blank? (str cid)))
    {:ok? false :error :not-found}
    (let [ncid (core-infra/normalize-cid cid)
          inst @(:subnet-atom rt)
          sid (:subnet-id inst)
          denied (into #{} (map core-infra/normalize-cid) (get-in inst [:policy :subnet/denied-cids] #{}))]
      (if (contains? denied ncid)
        {:ok? false :denied? true :error :denied-cid :cid ncid}
        (let [r-box (atom nil)
              _ (swap! (:subnet-atom rt)
                       (fn [cur]
                         (let [r (data/get-blob (get-in cur [:data :blobs]) ncid {:subnet sid :now-ms now-ms})]
                           (reset! r-box r)
                           (assoc-in cur [:data :blobs] (:store r)))))
              r1 @r-box]
          (if (:hit? r1)
            {:ok? true
             :cid ncid
             :blob (:blob r1)
             :file-path (blob-file-path (:state-dir rt) ncid)}
            (let [disk-res (read-disk-blob! (:state-dir rt) ncid (:shell-atom rt))]
              (if (:ok? disk-res)
                (do
                  (swap! (:subnet-atom rt)
                         (fn [cur]
                           (assoc cur :data (:state (data/put-data-blob (:data cur) (:blob disk-res) now-ms)))))
                  {:ok? true
                   :cid ncid
                   :blob (:blob disk-res)
                   :file-path (:path disk-res)})
                {:ok? false :error :missing-blob :cid ncid}))))))))

(defn- resolve-path-blob!
  [rt path now-ms]
  (let [inst @(:subnet-atom rt)
        sid (:subnet-id inst)
        path-str (str path)
        raw-ptr (or (get-in inst [:data :pointers [(str sid) path-str]])
                    (get-in inst [:pointers [(str sid) path-str]])
                    (get-in inst [:pointers path-str]))
        tombstoned? (boolean (or (contains? (:tombstones inst) path-str)
                                 (contains? (get-in inst [:data :tombstones]) path-str)
                                 (and raw-ptr (nil? (:pointer/target raw-ptr)))))
        denied (into #{} (map core-infra/normalize-cid) (get-in inst [:policy :subnet/denied-cids] #{}))
        raw-cid (when-let [t (:pointer/target raw-ptr)] (core-infra/normalize-cid t))
        denied-cid? (boolean (and raw-cid (contains? denied raw-cid)))]
    (if (or tombstoned? denied-cid?)
      {:ok? false :denied? true :tombstoned? tombstoned?
       :error (if tombstoned? :tombstoned :denied-cid) :pointer raw-ptr :cid raw-cid}
      (let [ptr (data/resolve-pointer (:data inst) sid path-str now-ms)]
        (if-not ptr
          {:ok? false :error :not-found}
          (assoc (resolve-cid-blob! rt (:pointer/target ptr) now-ms) :pointer ptr))))))

(defn- load-tls-cert-key-from-disk-or-subnet!
  [rt]
  (let [state-dir (:state-dir rt)
        tls-secret (:tls-secret rt)
        shell-atom (:shell-atom rt)
        ;; 1. Try subnet pointer "tls/current-cert" (Fressian + AES-256-GCM)
        from-subnet
        (when tls-secret
          (try
            (let [res (resolve-path-blob! rt "tls/current-cert" (.now js/Date))]
              (when (:ok? res)
                (let [decoded (fressian/decode-wire (get-in res [:blob :blob/bytes]))
                      cert-pem (:cert-pem decoded)
                      enc-key (:encrypted-key decoded)
                      key-pem (when enc-key (decrypt-tls-key-pem tls-secret enc-key))]
                  (when (and cert-pem key-pem)
                    {:cert-pem cert-pem :key-pem key-pem :source :subnet-fressian}))))
            (catch :default e
              (apply-shell-event! shell-atom {:type :diagnose :reason :tls-subnet-decrypt-failed :detail (.-message e)})
              nil)))
        ;; 2. Try <state-dir>/certs/bundle.edn
        bundle-edn (.join node-path state-dir "certs" "bundle.edn")
        from-bundle
        (when (and (nil? from-subnet) (.existsSync node-fs bundle-edn))
          (try
            (let [m (edn/read-string (.readFileSync node-fs bundle-edn "utf8"))]
              (when (and (:cert-pem m) (:key-pem m))
                {:cert-pem (:cert-pem m) :key-pem (:key-pem m) :source :bundle-edn}))
            (catch :default e
              (apply-shell-event! shell-atom {:type :diagnose :reason :tls-bundle-read-failed :detail (.-message e)})
              nil)))
        ;; 3. Try <state-dir>/certs/fullchain.pem + privkey.pem
        fc-path (.join node-path state-dir "certs" "fullchain.pem")
        pk-path (.join node-path state-dir "certs" "privkey.pem")
        from-pem
        (when (and (nil? from-subnet) (nil? from-bundle)
                   (.existsSync node-fs fc-path) (.existsSync node-fs pk-path))
          (try
            {:cert-pem (.readFileSync node-fs fc-path "utf8")
             :key-pem (.readFileSync node-fs pk-path "utf8")
             :source :pem-files}
            (catch :default e
              (apply-shell-event! shell-atom {:type :diagnose :reason :tls-pem-read-failed :detail (.-message e)})
              nil)))]
    (or from-subnet from-bundle from-pem)))

(defn- maybe-hot-reload-tls!
  [rt ptr]
  (when (and (= "tls/current-cert" (:pointer/path ptr))
             (some? (:pointer/target ptr))
             (:tls-ctx-atom rt)
             (:tls-secret rt))
    (when-let [{:keys [cert-pem key-pem]} (load-tls-cert-key-from-disk-or-subnet! rt)]
      (try
        (let [ctx (.createSecureContext node-tls #js {:cert cert-pem :key key-pem})]
          (reset! (:tls-ctx-atom rt) ctx)
          (reset! (:tls-pem-atom rt) {:cert-pem cert-pem :key-pem key-pem}))
        (catch :default e
          (apply-shell-event! (:shell-atom rt)
                              {:type :diagnose :reason :tls-hot-reload-failed :detail (.-message e)}))))))

(defn- eligible-http-peers
  [config]
  (let [peers (get-in config [:cluster :nodes])
        my-id (or (:node/id config) (:node-id config))]
    (when (map? peers)
      (for [[nid pinfo] peers
            :let [ip (or (:ip4 pinfo) (:ip pinfo) (:host pinfo))
                  port (or (:http-port pinfo) (get-in config [:http :http-port]) 80)]
            :when (and (not= (name (keyword nid)) (when my-id (name (keyword my-id))))
                       (some? ip))]
        {:node-id (keyword nid) :ip ip :port (long port)}))))

(defn- post-to-peer!
  [peer endpoint headers body-buf shell-atom diag-reason]
  (try
    (let [req-opts #js {:hostname (:ip peer)
                        :port (:port peer)
                        :path endpoint
                        :method "POST"
                        :timeout 10000
                        :headers (clj->js (assoc headers "Content-Length" (.-length body-buf)))}
          req (.request node-http req-opts
                        (fn [res]
                          (let [cls (core-infra/classify-peer-replication-response
                                     {:status (.-statusCode res)
                                      :peer (:node-id peer)
                                      :reason diag-reason})]
                            (when-let [diag (:diagnose cls)]
                              (apply-shell-event! shell-atom diag)))
                          (.resume res)))]
      (.on req "error"
           (fn [err]
             (when-let [diag (:diagnose (core-infra/classify-peer-replication-response
                                         {:error (or (.-message err) (str err))
                                          :peer (:node-id peer)
                                          :reason diag-reason}))]
               (apply-shell-event! shell-atom diag))))
      (.on req "timeout"
           (fn []
             (.destroy req)
             (when-let [diag (:diagnose (core-infra/classify-peer-replication-response
                                         {:error "timeout"
                                          :peer (:node-id peer)
                                          :reason diag-reason}))]
               (apply-shell-event! shell-atom diag))))
      (.write req body-buf)
      (.end req))
    (catch :default e
      (when-let [diag (:diagnose (core-infra/classify-peer-replication-response
                                  {:error (or (.-message e) (str e))
                                   :peer (:node-id peer)
                                   :reason diag-reason}))]
        (apply-shell-event! shell-atom diag)))))

(defn- replicate-artifact-to-peers!
  [rt kind payload-buf headers]
  (when (get-in (:config rt) [:cluster :enabled?] false)
    (let [endpoint (if (= kind :blob) "/artifact/v1/blob" "/artifact/v1/pointer")
          hdrs (assoc headers "X-Bitecho-Artifact-Replicated" "true")]
      (doseq [peer (eligible-http-peers (:config rt))]
        (post-to-peer! peer endpoint hdrs payload-buf (:shell-atom rt) :peer-artifact-replicate-failed)))))

(defn- replicate-relay-to-peers!
  [rt endpoint body-buf]
  (when (and (get-in (:config rt) [:cluster :enabled?] false) body-buf (pos? (.-length body-buf)))
    (let [hmac (compute-relay-auth-hmac (:tls-secret rt) endpoint body-buf)
          hdrs (cond-> {"Content-Type" "application/json"
                        "X-Bitecho-Relay-Replicated" "true"}
                 hmac (assoc "X-Bitecho-Relay-Auth" hmac))]
      (doseq [peer (eligible-http-peers (:config rt))]
        (post-to-peer! peer endpoint hdrs body-buf (:shell-atom rt) :peer-relay-replicate-failed)))))

(defn- submit-subnet-event!
  [rt event]
  (let [res-box (atom nil)]
    (swap! (:subnet-atom rt)
           (fn [inst]
             (let [r (subnet/reduce-subnet inst event)]
               (reset! res-box r)
               (:state r))))
    (let [res @res-box
          skip-disk? (boolean (:skip-disk-write? event))
          written-cids (atom #{})]
      (when (and (not skip-disk?) (= :put-blob (:type event)) (:blob event))
        (let [cid (core-infra/normalize-cid (:blob/cid (:blob event)))]
          (swap! written-cids conj cid)
          (write-disk-blob! (:state-dir rt) (:blob event) (:shell-atom rt))))
      (doseq [eff (:effects res)]
        (case (:effect eff)
          :diagnose
          (apply-shell-event! (:shell-atom rt) (assoc eff :type :diagnose))

          :eager-push-blob
          (let [b (:blob eff)
                cid (core-infra/normalize-cid (:blob/cid b))]
            (when (and (not skip-disk?) (not (contains? @written-cids cid)))
              (swap! written-cids conj cid)
              (write-disk-blob! (:state-dir rt) b (:shell-atom rt)))
            (when-not (:from-peer? event)
              (replicate-artifact-to-peers! rt :blob (u8->buf (:blob/bytes b))
                                            {"Content-Type" (or (:blob/media-type b) "application/octet-stream")
                                             "X-Bitecho-Blob-Cid" (:blob/cid b)})))

          :replicate-pointer
          (let [ptr (:pointer eff)]
            (save-pointers-snapshot! (:state-dir rt) @(:subnet-atom rt) (:shell-atom rt))
            (maybe-hot-reload-tls! rt ptr)
            (when-not (:from-peer? event)
              (replicate-artifact-to-peers! rt :pointer (.from js/Buffer (pr-str ptr) "utf8")
                                            {"Content-Type" "application/edn"})))

          :policy-updated
          (save-pointers-snapshot! (:state-dir rt) @(:subnet-atom rt) (:shell-atom rt))

          nil))
      res)))

;; =============================================================================
;; 6. Authoritative UDP DNS Server (`node:dgram` + `bitecho.core.protocol.dns`)
;; =============================================================================

(defn- hydrate-cold-dns-blobs!
  [rt now-ms]
  (let [inst @(:subnet-atom rt)
        sid (:subnet-id inst)
        ptrs (get-in inst [:data :pointers] {})
        blobs (get-in inst [:data :blobs :entries] {})]
    (doseq [[[psub ppath] ptr] ptrs
            :let [cid (:pointer/target ptr)]
            :when (and (= psub sid)
                       cid
                       (or (str/starts-with? ppath "dns/")
                           (str/starts-with? ppath "acme/challenge/"))
                       (nil? (get-in blobs [cid :bytes])))]
      (resolve-path-blob! rt ppath now-ms))))

(defn- start-dns-server!
  [config rt on-ready]
  (let [shell-atom (atom (core-infra/init-shell-state :dns-shell))
        _ (apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        bind-ip (get-in config [:dns :bind-ip] "0.0.0.0")
        bind-port (long (get-in config [:dns :port] 53))
        limiter-atom (atom (dns-proto/init-limiter {:capacity 40.0 :refill-per-sec 20.0}))
        sock (.createSocket node-dgram #js {:type "udp4" :reuseAddr true})]
    (.on sock "message"
         (fn [msg rinfo]
           (let [client-ip (or (.-address rinfo) "127.0.0.1")
                 client-port (.-port rinfo)
                 subnet-key (dns-proto/ip->subnet-key client-ip)
                 now-ms (.now js/Date)
                 allowed-box (atom false)
                 _ (swap! limiter-atom
                          (fn [st]
                            (let [r (dns-proto/check-and-consume st subnet-key 1.0 now-ms)]
                              (reset! allowed-box (:allowed? r))
                              (:state r))))]
             (if-not @allowed-box
               (apply-shell-event! shell-atom {:type :drop :reason :dns-rrl-rate-limited :detail subnet-key})
               (try
                 (let [q-pkt (dns-proto/decode-packet (buf->u8 msg))
                       _ (hydrate-cold-dns-blobs! rt now-ms)
                       resp-pkt (dns-proto/resolve-query config @(:subnet-atom rt) q-pkt now-ms)
                       resp-bytes (dns-proto/encode-packet resp-pkt {:max-bytes 512})]
                   (.send sock (u8->buf resp-bytes) client-port client-ip))
                 (catch :default e
                   (apply-shell-event! shell-atom {:type :drop :reason :dns-udp-formerr :detail (.-message e)})
                   (when-let [id (:id (ex-data e))]
                     (try
                       (let [err-resp (dns-proto/encode-packet {:id id :qr? true :opcode 0 :aa? false :tc? false :rd? false :ra? false :rcode :formerr :questions []})]
                         (.send sock (u8->buf err-resp) client-port client-ip))
                       (catch :default _ nil)))))))))
    (.on sock "error"
         (fn [err]
           (apply-shell-event! shell-atom {:type :diagnose :reason :dns-socket-error :detail (.-message err)})))
    (.bind sock bind-port bind-ip
           (fn []
             (let [bound-port (.-port (.address sock))]
               (apply-shell-event! shell-atom {:type :started :generation gen :resources {:sock sock}})
               (on-ready {:shell-atom shell-atom
                          :udp-port bound-port
                          :stop-fn (fn []
                                     (apply-shell-event! shell-atom {:type :stop}
                                                         (fn [{:keys [sock]}]
                                                           (when sock (try (.close sock) (catch :default _ nil))))))}))))))

;; =============================================================================
;; 7. HTTP / HTTPS / Relay / Artifact / Static / CONNECT Server
;; =============================================================================

(defn- read-req-body-bounded!
  [req max-bytes cb]
  (let [chunks #js []
        total (atom 0)
        done? (atom false)]
    (.on req "data"
         (fn [chunk]
           (when-not @done?
             (let [n (+ @total (.-length chunk))]
               (if (> n max-bytes)
                 (do
                   (reset! done? true)
                   (cb nil true))
                 (do
                   (reset! total n)
                   (.push chunks chunk)))))))
    (.on req "end"
         (fn []
           (when-not @done?
             (reset! done? true)
             (cb (.concat js/Buffer chunks) false))))
    (.on req "error"
         (fn [_]
           (when-not @done?
             (reset! done? true)
             (cb nil false))))))

(defn- send-json!
  [res status obj]
  (when (>= (long status) 500)
    (swap! runtime-metrics-atom update :http-5xx-count (fnil inc 0)))
  (let [body (js/JSON.stringify (clj->js obj))
        buf (.from js/Buffer body "utf8")]
    (.writeHead res status #js {"Content-Type" "application/json; charset=utf-8"
                                "Content-Length" (.-length buf)
                                "Access-Control-Allow-Origin" "*"
                                "Access-Control-Allow-Methods" "GET, HEAD, POST, OPTIONS"})
    (.end res buf)))

(defn- send-text!
  [res status text method]
  (when (>= (long status) 500)
    (swap! runtime-metrics-atom update :http-5xx-count (fnil inc 0)))
  (let [buf (.from js/Buffer (str text) "utf8")]
    (.writeHead res status #js {"Content-Type" "text/plain; charset=utf-8"
                                "Content-Length" (.-length buf)})
    (if (= method "HEAD")
      (.end res)
      (.end res buf))))

(defn- get-header
  [req k]
  (let [v (aget (.-headers req) (str/lower-case k))]
    (if (array? v) (aget v 0) v)))

(defn- current-month-key []
  (let [d (js/Date.)
        y (.getUTCFullYear d)
        m (inc (.getUTCMonth d))]
    (str y "-" (if (< m 10) (str "0" m) m))))

(defn- current-finalized-epoch
  "Returns the live consensus finalized epoch from the embedded validator state,
   falling back to `:epoch-atom` if standalone (fixes BIP-018-SOAK-F2 follower lag)."
  [rt]
  (let [vnode (:validator-node rt)
        vst (when (and vnode (:state-atom vnode)) @(:state-atom vnode))
        v-fin (long (or (:last-executed-finalized-epoch vst)
                        (:finalized-epoch vst)
                        0))
        rt-ep (long (or @(:epoch-atom rt) 0))]
    (max v-fin rt-ep)))

(defn- build-statusz-payload
  [rt limiter-atom http-shell-atom dns-shell-atom smtp-shell-atom]
  (let [sub @(:subnet-atom rt)
        le (:leader-election sub)
        fin-ep (current-finalized-epoch rt)
        egress (long (get-in @limiter-atom [:egress-by-month (current-month-key)] 0))
        mem-raw (try
                  (let [m (.memoryUsage js/process)]
                    {:rss-bytes (.-rss m)
                     :heap-used-bytes (.-heapUsed m)
                     :heap-total-bytes (.-heapTotal m)
                     :external-bytes (.-external m)
                     :array-buffers-bytes (.-arrayBuffers m)})
                  (catch :default _ nil))
        memory (core-infra/normalize-memory-telemetry mem-raw)]
    {:ok true
     :runtime "nodejs"
     :version full-node-version
     :node_id (name (or (:node-id rt) :ns3))
     :role (name (or (:role le) :standalone))
     :leader (str (or (:leader-id le) :none))
     :term (long (or (:term le) 0))
     :epoch fin-ep
     :finalized_epoch fin-ep
     :healthy (count (or (:healthy-nodes le) #{}))
     :egress_bytes egress
     :pointer_count (count (get-in sub [:data :pointers]))
     :memory memory
     :diagnostics {:runtime (core-infra/shell-status-summary @(:shell-atom rt))
                   :http (when http-shell-atom (core-infra/shell-status-summary @http-shell-atom))
                   :dns (when dns-shell-atom (core-infra/shell-status-summary @dns-shell-atom))
                   :smtp (when smtp-shell-atom (core-infra/shell-status-summary @smtp-shell-atom))}}))

(defn- resolve-safe-content-root-async!
  "Zero-Sync-IO async static content-root file resolver via `fs.promises`, invoking `(cb result-map)`."
  [content-root req-path cb]
  (if-not (and (string? content-root) (not (str/blank? content-root)))
    (cb {:ok? false :error :not-found})
    (let [subpath (core-infra/sanitize-web-subpath req-path)]
      (if (nil? subpath)
        (cb {:ok? false :error :forbidden})
        (-> (.realpath node-fsp content-root)
            (.then (fn [root-real]
                     (let [cand (.resolve node-path root-real (if (str/blank? subpath) "." subpath))]
                       (if (and (not= cand root-real)
                                (not (str/starts-with? cand (str root-real (.-sep node-path)))))
                         (js/Promise.resolve {:ok? false :error :forbidden})
                         (-> (.realpath node-fsp cand)
                             (.then (fn [real-p]
                                      (if (and (not= real-p root-real)
                                               (not (str/starts-with? real-p (str root-real (.-sep node-path)))))
                                        (js/Promise.resolve {:ok? false :error :forbidden})
                                        (-> (.stat node-fsp real-p)
                                            (.then (fn [st]
                                                     (cond
                                                       (.isFile st) (js/Promise.resolve real-p)
                                                       (.isDirectory st)
                                                       (let [idx-html (.join node-path real-p "index.html")
                                                             idx-md (.join node-path real-p "index.md")]
                                                         (-> (.access node-fsp idx-html)
                                                             (.then (fn [_] idx-html))
                                                             (.catch (fn [_]
                                                                       (-> (.access node-fsp idx-md)
                                                                           (.then (fn [_] idx-md))
                                                                           (.catch (fn [_] nil)))))))
                                                       :else (js/Promise.resolve nil))))
                                            (.then (fn [target-f]
                                                     (if-not target-f
                                                       (js/Promise.resolve {:ok? false :error :not-found})
                                                       (-> (.readFile node-fsp target-f)
                                                           (.then (fn [buf]
                                                                    (let [cid (sha256-buf-hex buf)
                                                                          ct (core-infra/content-type-for-file (.basename node-path target-f))]
                                                                      {:ok? true
                                                                       :file-path target-f
                                                                       :blob {:blob/cid cid
                                                                              :blob/media-type ct
                                                                              :blob/bytes (buf->u8 buf)}}))))))))))))))))
            (.then (fn [res] (cb res)))
            (.catch (fn [_] (cb {:ok? false :error :not-found}))))))))

(defn- parse-release-pointer-payload
  [bs]
  (let [s (fressian/bytes->utf8 bs)
        parsed (or (try (js->clj (js/JSON.parse s)) (catch :default _ nil))
                   (try (edn/read-string s) (catch :default _ nil)))]
    (when (map? parsed)
      (let [rel (or (:release parsed) (get parsed "release"))
            env (or (:envelope parsed) (get parsed "envelope"))]
        (when (and (map? rel) (map? env))
          {:release rel :envelope env})))))

(defn- hydrate-release-blobs!
  [rt release now-ms]
  (let [hdr-cid (or (:headers-config-cid release) (get release "headers_config_cid") (get release "headers-config-cid"))
        assets (or (:assets release) (get release "assets") {})
        asset-cids (keep (fn [[_ v]] (when (map? v) (or (:cid v) (get v "cid")))) assets)
        all-cids (distinct (remove nil? (cons hdr-cid asset-cids)))]
    (reduce (fn [acc cid]
              (let [res (resolve-cid-blob! rt cid now-ms)]
                (if-let [bs (and (:ok? res) (get-in res [:blob :blob/bytes]))]
                  (assoc acc (str/lower-case (str/trim (str cid))) bs)
                  acc)))
            {}
            all-cids)))

(defn- resolve-app-release-asset!
  [rt req-path now-ms]
  (let [ar-atom (:app-release-atom rt)
        ptr-res (resolve-path-blob! rt "web/app/release" now-ms)]
    (cond
      (nil? ar-atom)
      {:ok? false :fallback? true}

      (and (not (:ok? ptr-res))
           (nil? (:active-release @ar-atom)))
      {:ok? false :fallback? true}

      :else
      (do
        (when (:ok? ptr-res)
          (when-let [{:keys [release envelope]} (parse-release-pointer-payload (get-in ptr-res [:blob :blob/bytes]))]
            (let [cur-cid (get-in @ar-atom [:active-release :release-cid])
                  cand-cid (app-release/release-cid release)]
              (when (not= cand-cid cur-cid)
                (let [blobs (hydrate-release-blobs! rt release now-ms)
                      effs-box (atom [])]
                  (swap! ar-atom
                         (fn [st]
                           (let [[st' effs] (app-release/transition st {:type :apply-release
                                                                        :generation (:generation st 0)
                                                                        :release release
                                                                        :envelope envelope
                                                                        :blobs blobs})]
                             (reset! effs-box effs)
                             st')))
                  (doseq [eff @effs-box]
                    (when (= :diagnose (:type eff))
                      (apply-shell-event! (:shell-atom rt)
                                          {:type :diagnose
                                           :reason (or (:kind eff) :app-release-diagnose)
                                           :detail (:reason eff)}))))))))
        (let [st @ar-atom
              active (:active-release st)]
          (if-not active
            {:ok? false :status 503 :error (or (:last-error st) :release-not-active)}
            (let [asset-key (app-release/sanitize-app-asset-key req-path)
                  asset-cid (when asset-key (get-in active [:assets asset-key :cid]))
                  blobs (if asset-cid
                          (let [r (resolve-cid-blob! rt asset-cid now-ms)]
                            (if-let [bs (and (:ok? r) (get-in r [:blob :blob/bytes]))]
                              {asset-cid bs}
                              {}))
                          {})
                  resp (app-release/resolve-app-asset-response st req-path blobs)]
              (doseq [eff (:effects resp)]
                (when (= :diagnose (:type eff))
                  (apply-shell-event! (:shell-atom rt)
                                      {:type :diagnose
                                       :reason (or (:kind eff) :app-release-diagnose)
                                       :detail (:reason eff)})))
              resp)))))))

(defn- resolve-web-blob-async!
  "Zero-Sync-IO async web blob resolver: checks subnet pointers first, then falls back to `resolve-safe-content-root-async!`."
  [config rt req-path now-ms cb]
  (if-let [subpath (core-infra/sanitize-web-subpath req-path)]
    (let [try-paths (cond
                      (str/blank? subpath) ["web/index.html" "web/index.md"]
                      (= subpath "blog") ["web/blog/index.html" "web/blog/index.md"]
                      :else [(str "web/" subpath)
                             subpath
                             (str "web/" subpath ".html")
                             (str "web/" subpath "/index.html")
                             (str "web/" subpath "/index.md")])
          ptr-res (loop [ps try-paths]
                    (if-let [p (first ps)]
                      (let [r (resolve-path-blob! rt p now-ms)]
                        (if (or (:ok? r) (:denied? r)) r (recur (rest ps))))
                      {:ok? false :error :not-found}))]
      (cond
        (:ok? ptr-res) (cb ptr-res)
        (:denied? ptr-res) (cb ptr-res)
        :else (resolve-safe-content-root-async!
               (get-in config [:http :content-root])
               req-path
               (fn [disk-res]
                 (cb (if (:ok? disk-res) disk-res ptr-res))))))
    (cb {:ok? false :error :forbidden})))

(defn- send-resolved-blob!
  [req res resolved method extra-headers limiter-atom]
  (let [blob (:blob resolved)
        cid (:blob/cid blob)
        raw-ct (:blob/media-type blob)
        ptr (:pointer resolved)
        ptr-pk (or (:pointer/authority ptr) (:pointer/authority-pubkey ptr))
        ptr-seq (:pointer/seq ptr)
        ptr-sig (:pointer/sig ptr)
        fallback-name (or (:pointer/path ptr)
                          (when-let [fp (:file-path resolved)] (.basename node-path fp))
                          (first (str/split (or (.-url req) "/") #"\?" 2)))
        path-ct (core-infra/content-type-for-file fallback-name)
        ct (cond
             (and (string? raw-ct) (not (str/blank? raw-ct))
                  (not (contains? core-infra/default-extension-media-types raw-ct)))
             raw-ct
             (not= path-ct "application/octet-stream") path-ct
             (and (string? raw-ct) (not (str/blank? raw-ct))) raw-ct
             :else "application/octet-stream")
        raw-buf (u8->buf (:blob/bytes blob))
        total-size (.-length raw-buf)
        etag (str "\"" cid "\"")
        inm (get-header req "if-none-match")
        range-hdr (get-header req "range")
        ae (get-header req "accept-encoding")
        auth-hdrs (cond-> (merge {} extra-headers)
                    cid (assoc "X-Bitecho-Blob-Cid" cid "X-Checksum-SHA256" cid "ETag" etag)
                    ptr-pk (assoc "X-Bitecho-Pointer-Pubkey" ptr-pk)
                    ptr-seq (assoc "X-Bitecho-Pointer-Seq" (str ptr-seq))
                    ptr-sig (assoc "X-Bitecho-Pointer-Signature" ptr-sig))]
    (cond
      (and inm (= (str/trim inm) etag))
      (do
        (.writeHead res 304 (clj->js (assoc auth-hdrs "Cache-Control" "public, max-age=3600")))
        (.end res))

      range-hdr
      (if-let [[start end] (core-infra/parse-byte-range range-hdr total-size)]
        (let [slice (.subarray raw-buf start (inc end))
              hdrs (assoc auth-hdrs
                          "Content-Type" ct
                          "Content-Range" (str "bytes " start "-" end "/" total-size)
                          "Accept-Ranges" "bytes"
                          "Content-Length" (.-length slice))]
          (swap! limiter-atom #(-> (dns-proto/record-egress % (.-length slice) (current-month-key)) :state))
          (.writeHead res 206 (clj->js hdrs))
          (if (= method "HEAD") (.end res) (.end res slice)))
        (do
          (.writeHead res 416 #js {"Content-Range" (str "bytes */" total-size)})
          (.end res)))

      :else
      (let [want-gz? (and (<= total-size 16777216)
                          ae
                          (str/includes? (str/lower-case ae) "gzip")
                          (core-infra/compressible-content-type? ct))
            finish-send! (fn [out-buf use-gz?]
                           (let [hdrs (cond-> (assoc auth-hdrs
                                                     "Content-Type" ct
                                                     "Accept-Ranges" "bytes"
                                                     "Content-Length" (.-length out-buf))
                                        use-gz? (assoc "Content-Encoding" "gzip" "Vary" "Accept-Encoding"))]
                             (when (pos? (.-length out-buf))
                               (swap! limiter-atom #(-> (dns-proto/record-egress % (.-length out-buf) (current-month-key)) :state)))
                             (.writeHead res 200 (clj->js hdrs))
                             (if (= method "HEAD") (.end res) (.end res out-buf))))]
        (if want-gz?
          (.gzip node-zlib raw-buf
                 (fn [err gz-buf]
                   (let [use-gz? (and (nil? err) gz-buf (< (.-length gz-buf) total-size))]
                     (finish-send! (if use-gz? gz-buf raw-buf) use-gz?))))
          (finish-send! raw-buf false))))))

(defn- handle-dist-request!
  [req res config rt raw-path query-str method extra-headers limiter-atom]
  (let [subpath (core-infra/sanitize-web-subpath raw-path)
        rel-path (cond
                   (nil? subpath) nil
                   (str/starts-with? subpath "dist/") (subs subpath 5)
                   (= subpath "dist") ""
                   :else subpath)]
    (if (or (nil? rel-path) (str/blank? rel-path))
      (send-text! res 404 "Not Found\n" method)
      (let [now-ms (.now js/Date)
            qparams (core-infra/parse-query-params query-str)
            qcid (get qparams "cid")
            pinned-cid (when (and (string? qcid) (core-infra/valid-cid? qcid))
                         (core-infra/normalize-cid qcid))
            sha-req? (str/ends-with? rel-path ".sha256")
            target-name (if sha-req? (subs rel-path 0 (- (count rel-path) 7)) rel-path)
            direct-res (resolve-path-blob! rt (str "dist/" rel-path) now-ms)
            base-res (when sha-req? (resolve-path-blob! rt (str "dist/" target-name) now-ms))
            pinned-res (when (and (not sha-req?) pinned-cid) (resolve-cid-blob! rt pinned-cid now-ms))]
        (cond
          (or (:denied? direct-res) (:denied? base-res) (:denied? pinned-res))
          (send-text! res 404 "Not Found\n" method)

          (and sha-req? (:ok? direct-res))
          (send-resolved-blob! req res direct-res method extra-headers limiter-atom)

          (and sha-req? (:ok? base-res))
          (let [cid (get-in base-res [:blob :blob/cid])
                body (str cid "  " (.basename node-path target-name) "\n")]
            (send-text! res 200 body method))

          (and (not sha-req?) (:ok? pinned-res))
          (send-resolved-blob! req res (assoc pinned-res :pointer {:pointer/path (str "dist/" rel-path)}) method extra-headers limiter-atom)

          (and (not sha-req?) (:ok? direct-res))
          (send-resolved-blob! req res direct-res method extra-headers limiter-atom)

          :else
          (let [cr (get-in config [:http :content-root])]
            (if-not cr
              (send-text! res 404 "Not Found\n" method)
              (if sha-req?
                (resolve-safe-content-root-async!
                 cr (str "/dist/" target-name)
                 (fn [disk-target]
                   (if (:ok? disk-target)
                     (send-text! res 200 (str (get-in disk-target [:blob :blob/cid]) "  " (.basename node-path target-name) "\n") method)
                     (resolve-safe-content-root-async!
                      cr (str "/dist/" rel-path)
                      (fn [disk-direct]
                        (if (:ok? disk-direct)
                          (send-resolved-blob! req res disk-direct method extra-headers limiter-atom)
                          (send-text! res 404 "Not Found\n" method)))))))
                (resolve-safe-content-root-async!
                 cr (str "/dist/" rel-path)
                 (fn [disk-direct]
                   (if (:ok? disk-direct)
                     (send-resolved-blob! req res disk-direct method extra-headers limiter-atom)
                     (send-text! res 404 "Not Found\n" method))))))))))))

(defn- handle-artifact-endpoint!
  [req res rt clean-path query-str method]
  (let [now-ms (.now js/Date)
        replicated? (= "true" (str/lower-case (str (or (get-header req "x-bitecho-artifact-replicated") ""))))]
    (cond
      (= clean-path "/artifact/v1/blob")
      (if (not= method "POST")
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (let [req-max (long (or (get-in (:config rt) [:http :max-artifact-blob-bytes])
                                chunk-const/max-chunk-bytes))
              max-blob (:value (chunk-const/clamp-cap :max-chunk-bytes chunk-const/max-chunk-bytes req-max))]
          (read-req-body-bounded!
           req max-blob
           (fn [body-buf exceeded?]
             (if exceeded?
               (send-json! res 413 {:ok false :error "payload-too-large" :max_chunk_bytes max-blob})
               (let [ct (str (or (get-header req "content-type") ""))
                     hdr-cid (get-header req "x-bitecho-blob-cid")
                     parsed-json (when (and body-buf (pos? (.-length body-buf))
                                            (or (str/includes? (str/lower-case ct) "application/json")
                                                (= 0x7B (aget body-buf 0))))
                                   (try
                                     (let [m (js->clj (js/JSON.parse (.toString body-buf "utf8")))]
                                       (when (and (map? m) (some #(contains? m %) ["bytes_hex" "bytes-hex" "data" "bytes" "blob"]))
                                         (or (get m "blob") m)))
                                     (catch :default _ nil)))
                     blob-res (if parsed-json
                                (core-infra/normalize-artifact-blob parsed-json)
                                (core-infra/normalize-artifact-blob {:bytes (buf->u8 (or body-buf (.alloc js/Buffer 0)))
                                                                     :media-type (if (str/blank? ct) "application/octet-stream" ct)
                                                                     :cid hdr-cid}))]
                 (if-not (:ok? blob-res)
                   (send-json! res 400 {:ok false :error (name (or (:error blob-res) :invalid-blob))})
                   (let [blob (:blob blob-res)
                         blob-len (fressian/count-bytes (:blob/bytes blob))
                         inst @(:subnet-atom rt)
                         blobs (merge (get-in inst [:data :blobs] {}) (:blobs inst {}))
                         committed (reduce (fn [acc [_ b]]
                                             (+ acc (long (or (when (:blob/bytes b) (fressian/count-bytes (:blob/bytes b)))
                                                              (:blob/size b)
                                                              0))))
                                           0
                                           blobs)
                         staged (long (or (when (:staged-unhashed-bytes-atom rt) @(:staged-unhashed-bytes-atom rt))
                                          0))
                         max-quota (or (get-in (:config rt) [:http :max-chunk-store-bytes])
                                       (:max-chunk-store-bytes (:config rt))
                                       chunk-const/default-infra-chunk-quota-bytes)
                         quota-res (chunk-const/evaluate-chunk-quota
                                    {:committed-bytes committed
                                     :staged-unhashed-bytes staged
                                     :incoming-bytes blob-len
                                     :max-quota-bytes max-quota})]
                     (if-not (:ok? quota-res)
                       (send-json! res 507 {:ok false
                                            :error "chunk-store-quota-exceeded"
                                            :bytes_at_rest (:bytes-at-rest quota-res)
                                            :quota_bytes (:quota-bytes quota-res)})
                       (let [sender (or (get-header req "x-bitecho-pubkey") (:default-sender rt))]
                         (-> (write-disk-blob-async! (:state-dir rt) blob (:shell-atom rt))
                             (.then (fn [persist-res]
                                      (if-not (:ok? persist-res)
                                        (send-json! res 500 {:ok false
                                                             :error "blob-persist-failed"
                                                             :detail (or (:detail persist-res) "disk-write-failed")})
                                        (let [sub-res (submit-subnet-event! rt {:type :put-blob
                                                                                :blob blob
                                                                                :sender sender
                                                                                :now-ms now-ms
                                                                                :from-peer? replicated?
                                                                                :skip-disk-write? true})]
                                          (if-not (:applied? sub-res)
                                            (send-json! res 500 {:ok false
                                                                 :error "blob-index-failed"
                                                                 :detail (name (or (:error sub-res) :put-blob-rejected))})
                                            (send-json! res 200 {:ok true
                                                                 :cid (:blob/cid blob)
                                                                 :size_bytes blob-len}))))))
                             (.catch (fn [e]
                                       (send-json! res 500 {:ok false
                                                            :error "blob-persist-failed"
                                                            :detail (or (.-message e) (str e))}))))))))))))))

      (str/starts-with? clean-path "/artifact/v1/blob/")
      (if-not (contains? #{"GET" "HEAD"} method)
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (let [cid (subs clean-path (count "/artifact/v1/blob/"))]
          (resolve-cid-blob-async!
           rt cid now-ms
           (fn [r]
             (if (:ok? r)
               (let [b (:blob r)
                     buf (u8->buf (:blob/bytes b))
                     hdrs (chunk-const/safe-blob-response-headers
                           {:cid (:blob/cid b)
                            :content-type (or (:blob/media-type b) "application/octet-stream")
                            :content-length (.-length buf)})]
                 (.writeHead res 200 (clj->js hdrs))
                 (if (= method "HEAD") (.end res) (.end res buf)))
               (send-json! res 404 {:ok false :error "blob-not-found" :cid cid}))))))

      (= clean-path "/artifact/v1/pointer")
      (if (not= method "POST")
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (read-req-body-bounded!
         req 65536
         (fn [body-buf exceeded?]
           (if exceeded?
             (send-json! res 413 {:ok false :error "payload-too-large"})
             (let [body-str (when (and body-buf (pos? (.-length body-buf)))
                              (.toString body-buf "utf8"))
                   parsed (or (when body-str (try (js->clj (js/JSON.parse body-str)) (catch :default _ nil)))
                              (when body-str (try (edn/read-string body-str) (catch :default _ nil)))
                              (when (and body-buf (pos? (.-length body-buf)))
                                (try (fressian/decode-wire (buf->u8 body-buf)) (catch :default _ nil))))
                   raw-ptr (when (map? parsed) (or (get parsed "pointer") (:pointer parsed) parsed))
                   ptr (core-infra/normalize-artifact-pointer raw-ptr)]
               (if-not ptr
                 (send-json! res 400 {:ok false :error "invalid-pointer"})
                 (let [sub-res (submit-subnet-event! rt {:type :publish-pointer
                                                         :pointer ptr
                                                         :sender (or (:pointer/authority ptr) (:default-sender rt))
                                                         :now-ms now-ms
                                                         :from-peer? replicated?})
                       accepted? (boolean (:applied? sub-res))
                       inst @(:subnet-atom rt)
                       sid (:subnet-id inst)
                       existing (or (get-in inst [:data :pointers [(str sid) (:pointer/path ptr)]])
                                    (get-in inst [:data :pointers [(:pointer/subnet ptr) (:pointer/path ptr)]]))
                       idempotent? (boolean (and (not accepted?)
                                                 existing
                                                 (= (:pointer/target existing) (:pointer/target ptr))
                                                 (>= (long (or (:pointer/seq existing) 0))
                                                     (long (or (:pointer/seq ptr) 0)))))]
                   (cond
                     accepted?
                     (send-json! res 200 {:ok true
                                          :path (:pointer/path ptr)
                                          :cid (:pointer/target ptr)
                                          :seq (:pointer/seq ptr)
                                          :authority (:pointer/authority ptr)
                                          :tombstoned (nil? (:pointer/target ptr))})

                     idempotent?
                     (send-json! res 200 {:ok true
                                          :idempotent true
                                          :path (:pointer/path ptr)
                                          :cid (:pointer/target existing)
                                          :seq (:pointer/seq existing)
                                          :authority (:pointer/authority existing)
                                          :tombstoned (nil? (:pointer/target existing))})

                     :else
                     (send-json! res 403 {:ok false
                                          :error (name (or (:error sub-res) :pointer-rejected))
                                          :path (:pointer/path ptr)
                                          :seq (:pointer/seq ptr)})))))))))

      (= clean-path "/artifact/v1/list")
      (if-not (contains? #{"GET" "HEAD"} method)
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (let [qparams (core-infra/parse-query-params query-str)
              prefix (or (get qparams "prefix") (get qparams "path_prefix") "")
              subnet-filter (get qparams "subnet")
              st @(:subnet-atom rt)
              raw-ptrs (merge (get-in st [:data :pointers] {}) (:pointers st {}))
              ptrs (->> raw-ptrs
                        (keep (fn [[k ptr]]
                                (let [psub (when (vector? k) (str (first k)))
                                      p (if (vector? k) (str (second k)) (str k))]
                                  (when (and (some? (:pointer/target ptr))
                                             (or (str/blank? subnet-filter) (= psub subnet-filter))
                                             (or (str/blank? prefix) (str/starts-with? p prefix)))
                                    {"path" p
                                     "cid" (:pointer/target ptr)
                                     "seq" (:pointer/seq ptr)
                                     "authority" (:pointer/authority ptr)
                                     "sig" (:pointer/sig ptr)
                                     "timestamp" (:pointer/timestamp ptr)}))))
                        (sort-by #(get % "path"))
                        vec)
              tombs (->> raw-ptrs
                         (keep (fn [[k ptr]]
                                 (let [p (if (vector? k) (str (second k)) (str k))]
                                   (when (and (nil? (:pointer/target ptr))
                                              (or (str/blank? prefix) (str/starts-with? p prefix)))
                                     p))))
                         distinct
                         sort
                         vec)]
          (if (= method "HEAD")
            (do (.writeHead res 200 #js {"Content-Type" "application/json; charset=utf-8"}) (.end res))
            (send-json! res 200 {:ok true :count (count ptrs) :pointers ptrs :tombstones tombs}))))

      :else
      (send-json! res 404 {:ok false :error "not-found" :path clean-path}))))

(defn- check-relay-replication-auth
  [req rt endpoint body-buf]
  (let [rep-val (str/lower-case (str (or (get-header req "x-bitecho-relay-replicated") "")))]
    (if (not= rep-val "true")
      {:ok? true :replicated? false}
      (let [auth-hdr (str (or (get-header req "x-bitecho-relay-auth") ""))
            expected (compute-relay-auth-hmac (:tls-secret rt) endpoint body-buf)]
        (if (and expected (seq auth-hdr) (= (count auth-hdr) (count expected))
                 (.timingSafeEqual node-crypto (.from js/Buffer auth-hdr "utf8") (.from js/Buffer expected "utf8")))
          {:ok? true :replicated? true}
          {:ok? false :error :unauthorized-replication})))))

(defn- wake-relay-waiters!
  [waiters-atom recip broadcast?]
  (let [to-wake (concat (when recip (get @waiters-atom recip #{}))
                        (when (or recip broadcast?) (get @waiters-atom :broadcast #{})))]
    (doseq [wake-fn to-wake]
      (try (wake-fn) (catch :default _ nil)))))

(defn- maybe-ingest-artifact-envelope!
  [rt raw-env now-ms]
  (when rt
    (try
      (let [env-val (if (and (string? raw-env) (re-matches #"[0-9a-fA-F]+" (str/trim raw-env)))
                      (try (basalt/hex->bytes (str/trim raw-env)) (catch :default _ raw-env))
                      raw-env)
            unwrapped (or (try (light-core/unwrap-wire-message env-val) (catch :default _ nil))
                          (when (fressian/bytes? env-val) (try (fressian/decode-wire env-val) (catch :default _ nil)))
                          (when (map? env-val) env-val))]
        (when (map? unwrapped)
          (let [mtype (keyword (or (:bitecho/type unwrapped) (:type unwrapped) (get unwrapped "type")))]
            (when (contains? #{:sync-pointer :artifact-replicate :replicate-pointer} mtype)
              (let [ptr (core-infra/normalize-artifact-pointer (or (:pointer unwrapped) (get unwrapped "pointer") unwrapped))
                    blob-res (core-infra/normalize-artifact-blob (or (:blob unwrapped) (get unwrapped "blob")))
                    sender (or (:pointer/authority ptr)
                               (:sender unwrapped)
                               (get unwrapped "sender")
                               (:default-sender rt))]
                (when (and blob-res (:ok? blob-res))
                  (submit-subnet-event! rt {:type :put-blob
                                            :blob (:blob blob-res)
                                            :sender sender
                                            :now-ms now-ms}))
                (when ptr
                  (submit-subnet-event! rt {:type :publish-pointer
                                            :pointer ptr
                                            :sender (or (:pointer/authority ptr) sender)
                                            :now-ms now-ms})))))))
      (catch :default _ nil))))

(defn- forward-relay-to-validator-mesh!
  [rt eff]
  (when-let [vnode (:validator-node rt)]
    (try
      (let [raw-env (:envelope eff)
            env (if (fressian/bytes? raw-env)
                  (try (fressian/decode-wire raw-env) (catch :default _ raw-env))
                  raw-env)
            ev-type (when (map? env) (or (get-in env [:event :type]) (:type env)))
            gossip-msg (when (map? env)
                         (if (= :receive-gossip ev-type)
                           (or (get-in env [:event :message]) (:message env))
                           (or (:message env) (get-in env [:event :message]))))
            sub-id (or (when (map? env) (:subnet-id env))
                       (when (map? env) (get-in env [:event :subnet-id]))
                       "global")]
        (when gossip-msg
          (let [sender-pk (or (when (map? env) (:agent-pubkey env))
                              (:default-sender rt)
                              (get-in vnode [:identity :pubkey-hex]))
                gossip-ev {:type :receive-gossip
                           :subnet-id sub-id
                           :message gossip-msg
                           :sender sender-pk
                           :rng (crypto/make-random)}]
            (step-validator-event! vnode gossip-ev false)
            (when-let [acs (:agent-conns vnode)]
              (forward-gossip-to-agents!
               acs
               (fressian/encode-wire {:type :receive-gossip
                                      :subnet-id sub-id
                                      :message gossip-msg})
               nil)))))
      (catch :default _ nil))))

(defn- handle-relay-endpoint!
  [req res rt relay-atom waiters-atom clean-path query-str method]
  (cond
    (and (contains? #{"GET" "HEAD"} method)
         (contains? #{"/relay/v1/health" "/relay/v1/status"} clean-path))
    (send-json! res 200 {:ok true :runtime "nodejs" :version full-node-version :diagnostics (:diagnostics @relay-atom)})

    (and (= method "POST") (= clean-path "/relay/v1/send"))
    (read-req-body-bounded!
     req (long (or (:max-payload-bytes @relay-atom) 65536))
     (fn [body-buf exceeded?]
       (if exceeded?
         (send-json! res 413 {:ok false :error "payload-too-large"})
         (let [rep-auth (check-relay-replication-auth req rt "/relay/v1/send" (or body-buf (.alloc js/Buffer 0)))]
           (if-not (:ok? rep-auth)
             (do
               (swap! relay-atom update-in [:diagnostics :unauthorized-replication] (fnil inc 0))
               (send-json! res 403 {:ok false :error "unauthorized-replication"}))
             (let [ct (str (or (get-header req "content-type") ""))
                   env (try
                         (cond
                           (or (str/includes? (str/lower-case ct) "application/json")
                               (and body-buf (pos? (.-length body-buf)) (= 0x7B (aget body-buf 0))))
                           (let [m (js->clj (js/JSON.parse (.toString body-buf "utf8")))]
                             (or (get m "envelope_hex") (get m "envelope") m))
                           :else (buf->u8 body-buf))
                         (catch :default _ (buf->u8 body-buf)))
                   now-ms (.now js/Date)
                   res-box (atom nil)
                   _ (swap! relay-atom
                            (fn [st]
                              (let [r (relay/reduce-relay st {:type :relay-submit :envelope env :now-ms now-ms})]
                                (reset! res-box r)
                                (:state r))))
                   r @res-box]
               (if (:ok? r)
                 (do
                   (maybe-ingest-artifact-envelope! rt env now-ms)
                   (when-not (:replicated? rep-auth)
                     (doseq [eff (:effects r)]
                       (when (= :forward-to-validators (:effect eff))
                         (forward-relay-to-validator-mesh! rt eff)))
                     (replicate-relay-to-peers! rt "/relay/v1/send" body-buf))
                   (wake-relay-waiters! waiters-atom
                                        (or (get-in r [:response "recipient"])
                                            (some #(when (= :forward-to-validators (:effect %)) (:recipient %)) (:effects r)))
                                        (boolean (get-in r [:response "broadcast"])))
                   (send-json! res 200 (:response r)))
                 (let [status (case (:error r) :payload-too-large 413 :invalid-signature 403 400)]
                   (send-json! res status (:response r))))))))))

    (and (contains? #{"GET" "POST"} method) (= clean-path "/relay/v1/poll"))
    (let [_ (swap! poll-telemetry-atom update :poll-count (fnil inc 0))
          _ (sample-node-runtime-telemetry! (or (:node-id rt) "infra") (count @waiters-atom))
          remote-ip (or (some-> req .-socket .-remoteAddress) "unknown")
          [def-st def-dec _] (defense/evaluate-request
                              @defense-state-atom
                              {:source-id remote-ip
                               :traffic-class :unauthenticated-ingress
                               :authenticated? false
                               :route "/relay/v1/poll"
                               :now-ms (.now js/Date)})
          _ (reset! defense-state-atom def-st)
          process-poll!
          (fn [body-buf exceeded?]
            (if (contains? #{:ban :drop} (:action def-dec))
              (send-json! res 429 {:ok false :error "rate-limited" :action (name (:action def-dec))})
              (if exceeded?
                (send-json! res 413 {:ok false :error "payload-too-large"})
                (let [body-json (when (and body-buf (pos? (.-length body-buf)))
                                  (try (js->clj (js/JSON.parse (.toString body-buf "utf8"))) (catch :default _ nil)))
                      qparams (core-infra/parse-query-params query-str)
                      pubkey (or (get body-json "pubkey") (get qparams "pubkey") (get-header req "x-bitecho-pubkey"))
                      parse-int (fn [v d] (let [n (js/parseInt (str (or v d)) 10)] (long (if (js/isNaN n) d n))))
                      since-seq (parse-int (or (get body-json "since_seq") (get body-json "since-seq")
                                               (get qparams "since_seq") (get qparams "since-seq")
                                               (get-header req "x-bitecho-since-seq")) 0)
                      since-bseq (parse-int (or (get body-json "since_broadcast_seq") (get body-json "since-broadcast-seq")
                                                (get qparams "since_broadcast_seq") (get qparams "since-broadcast-seq")
                                                (get-header req "x-bitecho-since-broadcast-seq")) 0)
                      ts-ms (parse-int (or (get body-json "timestamp_ms") (get body-json "timestamp-ms")
                                           (get body-json "ts") (get-header req "x-bitecho-timestamp-ms")) 0)
                      nonce (or (get body-json "nonce") (get-header req "x-bitecho-nonce"))
                      sig (or (get body-json "signature") (get body-json "sig") (get-header req "x-bitecho-signature"))
                      raw-wait (or (get body-json "wait_ms") (get body-json "wait-ms")
                                   (get body-json "timeout_ms") (get body-json "timeout-ms")
                                   (get qparams "wait_ms") (get qparams "wait-ms")
                                   (get qparams "timeout_ms") (get qparams "timeout-ms")
                                   (get-header req "x-bitecho-wait-ms"))
                      wait-ms (min 25000 (max 0 (parse-int raw-wait 0)))
                      raw-subs (or (get body-json "subnets") (get qparams "subnets") (get-header req "x-bitecho-subnets"))
                      subs (cond
                             (coll? raw-subs) (mapv (comp str/trim str) raw-subs)
                             (and (string? raw-subs) (not (str/blank? raw-subs))) (vec (remove str/blank? (map str/trim (str/split raw-subs #","))))
                             :else nil)
                      sub-filter-set (when (seq subs) (set subs))
                      now-ms (.now js/Date)
                      poll-ev (cond-> {:type :relay-poll
                                       :pubkey pubkey
                                       :since-seq since-seq
                                       :since-broadcast-seq since-bseq
                                       :timestamp-ms ts-ms
                                       :nonce nonce
                                       :signature sig
                                       :now-ms now-ms}
                                (seq subs) (assoc :subnets subs))
                      r-box (atom nil)
                      _ (swap! relay-atom
                               (fn [st]
                                 (let [r (relay/reduce-relay st poll-ev)]
                                   (reset! r-box r)
                                   (:state r))))
                      r @r-box]
                  (if-not (:ok? r)
                    (send-json! res 403 (:response r))
                    (let [msgs (get-in r [:response "messages"] [])
                          bcasts (get-in r [:response "broadcasts"] [])
                          norm-pk (get-in r [:response "pubkey"])]
                      (if (and (pos? wait-ms) (empty? msgs) (empty? bcasts) norm-pk)
                        (let [finished? (atom false)
                              timer-id (atom nil)
                              finish! (fn []
                                        (when (compare-and-set! finished? false true)
                                          (when @timer-id (js/clearTimeout @timer-id))
                                          (let [st @relay-atom
                                                cutoff (- (.now js/Date) (long (get st :ttl-ms 86400000)))
                                                max-inbox-seq (long (get-in st [:inbox-seqs norm-pk] 0))
                                                max-bcast-seq (long (get st :next-broadcast-seq 0))
                                                eff-since-seq (if (> since-seq max-inbox-seq) 0 since-seq)
                                                eff-since-bseq (if (> since-bseq max-bcast-seq) 0 since-bseq)
                                                fresh-m (filterv #(and (> (long (:relay-seq %)) eff-since-seq)
                                                                       (>= (long (:received-at % 0)) cutoff))
                                                                 (get-in st [:inboxes norm-pk] []))
                                                all-b (filterv #(and (> (long (:broadcast-seq %)) eff-since-bseq)
                                                                     (>= (long (:received-at % 0)) cutoff))
                                                               (get st :broadcasts []))
                                                max-bseq (if (seq all-b)
                                                           (apply max (map :broadcast-seq all-b))
                                                           eff-since-bseq)
                                                fresh-b (if sub-filter-set
                                                          (filterv (fn [e]
                                                                     (let [esub (str (or (:subnet-id e) (:subnet_id e) (get e "subnet_id") "global"))]
                                                                       (or (contains? sub-filter-set esub)
                                                                           (contains? sub-filter-set "*"))))
                                                                   all-b)
                                                          all-b)]
                                            (when-not (.-writableEnded res)
                                              (send-json! res 200 {"ok" true
                                                                   "pubkey" norm-pk
                                                                   "messages" fresh-m
                                                                   "broadcasts" fresh-b
                                                                   "last_broadcast_seq" max-bseq})))))
                              wake-fn (let [self-ref (atom nil)]
                                        (letfn [(do-wake []
                                                  (let [f @self-ref]
                                                    (swap! waiters-atom
                                                           (fn [m]
                                                             (let [m1 (if-let [s (get m norm-pk)]
                                                                        (let [s' (disj s f)]
                                                                          (if (empty? s') (dissoc m norm-pk) (assoc m norm-pk s')))
                                                                        m)
                                                                   m2 (if-let [s (get m1 :broadcast)]
                                                                        (let [s' (disj s f)]
                                                                          (if (empty? s') (dissoc m1 :broadcast) (assoc m1 :broadcast s')))
                                                                        m1)]
                                                               m2))))
                                                  (try (.removeListener req "close" do-wake) (catch :default _ nil))
                                                  (finish!))]
                                          (reset! self-ref do-wake)
                                          do-wake))]
                          (swap! waiters-atom #(-> % (update norm-pk (fnil conj #{}) wake-fn) (update :broadcast (fnil conj #{}) wake-fn)))
                          (reset! timer-id (js/setTimeout wake-fn wait-ms))
                          (.on req "close" wake-fn))
                        (send-json! res 200 (:response r)))))))))]
      (if (= method "POST")
        (read-req-body-bounded! req 65536 process-poll!)
        (process-poll! nil false)))

    (and (= method "POST") (= clean-path "/relay/v1/ack"))
    (read-req-body-bounded!
     req 65536
     (fn [body-buf exceeded?]
       (if exceeded?
         (send-json! res 413 {:ok false :error "payload-too-large"})
         (let [rep-auth (check-relay-replication-auth req rt "/relay/v1/ack" (or body-buf (.alloc js/Buffer 0)))]
           (if-not (:ok? rep-auth)
             (do
               (swap! relay-atom update-in [:diagnostics :unauthorized-replication] (fnil inc 0))
               (send-json! res 403 {:ok false :error "unauthorized-replication"}))
             (let [body-json (when (and body-buf (pos? (.-length body-buf)))
                               (try (js->clj (js/JSON.parse (.toString body-buf "utf8"))) (catch :default _ nil)))
                   qparams (core-infra/parse-query-params query-str)
                   parse-int (fn [v d] (let [n (js/parseInt (str (or v d)) 10)] (if (js/isNaN n) d n)))
                   pubkey (or (get body-json "pubkey") (get qparams "pubkey") (get-header req "x-bitecho-pubkey"))
                   ack-seq (parse-int (or (get body-json "ack_seq") (get body-json "ack-seq")
                                          (get body-json "up_to_seq") (get qparams "ack_seq")) 0)
                   ack-bseq (parse-int (or (get body-json "ack_broadcast_seq") (get body-json "ack-broadcast-seq")) 0)
                   ts-ms (parse-int (or (get body-json "timestamp_ms") (get body-json "ts") (get-header req "x-bitecho-timestamp-ms")) 0)
                   nonce (or (get body-json "nonce") (get-header req "x-bitecho-nonce"))
                   sig (or (get body-json "signature") (get body-json "sig") (get-header req "x-bitecho-signature"))
                   ack-ev (cond-> {:type :relay-ack
                                   :pubkey pubkey
                                   :ack-seq ack-seq
                                   :timestamp-ms ts-ms
                                   :nonce nonce
                                   :signature sig
                                   :now-ms (.now js/Date)}
                            (pos? ack-bseq) (assoc :ack-broadcast-seq ack-bseq))
                   r-box (atom nil)
                   _ (swap! relay-atom
                            (fn [st]
                              (let [r (relay/reduce-relay st ack-ev)]
                                (reset! r-box r)
                                (:state r))))
                   r @r-box]
               (if-not (:ok? r)
                 (send-json! res 403 (:response r))
                 (do
                   (when-not (:replicated? rep-auth)
                     (replicate-relay-to-peers! rt "/relay/v1/ack" body-buf))
                   (send-json! res 200 (:response r))))))))))

    (and (contains? #{"GET" "POST"} method) (= clean-path "/relay/v1/chain-state"))
    (let [process-chain-state!
          (fn [body-buf exceeded?]
            (if exceeded?
              (send-json! res 413 {:ok false :error "payload-too-large"})
              (let [body-json (when (and body-buf (pos? (.-length body-buf)))
                                (try (js->clj (js/JSON.parse (.toString body-buf "utf8"))) (catch :default _ nil)))
                    qparams (core-infra/parse-query-params query-str)
                    pubkey (or (get body-json "pubkey") (get qparams "pubkey") (get-header req "x-bitecho-pubkey"))
                    nonce (or (get body-json "nonce") (get qparams "nonce"))
                    local-only? (contains? #{"true" "1"}
                                           (str/lower-case (str (or (get body-json "local_only")
                                                                    (get body-json "local-only")
                                                                    (get qparams "local_only")
                                                                    (get qparams "local-only")
                                                                    ""))))
                    valid-pk? (or (nil? pubkey)
                                  (and (string? pubkey)
                                       (re-matches #"^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{88}$" (str/trim pubkey))))]
                (if-not valid-pk?
                  (send-json! res 400 {:ok false :error "invalid-pubkey"})
                  (let [effective-pk (or pubkey (:default-sender rt))
                        eff-nonce (or nonce (str (.now js/Date)))
                        burn-fl (long (or (get-in (:config rt) [:burn-floor])
                                          (get-in (:config rt) [:min-signaling-burn])
                                          100))
                        bootstrap-dom (or (:bootstrap (:config rt)) (:domain (:config rt)) "bitecho.org")
                        vnode (:validator-node rt)]
                    (if (and vnode effective-pk)
                      (fetch-validator-chain-state-snapshots!
                       rt effective-pk eff-nonce {:local-only? local-only?}
                       (fn [snapshots]
                         (let [fin-ep (long (or (:last-executed-finalized-epoch @(:state-atom vnode))
                                                @(:epoch-atom rt)
                                                1))]
                           (reset! (:epoch-atom rt) fin-ep)
                           (send-json! res 200 {:ok true
                                                :pubkey effective-pk
                                                :snapshots (vec (or snapshots []))
                                                :epoch fin-ep
                                                :min_signaling_burn burn-fl
                                                :bootstrap bootstrap-dom}))))
                      (send-json! res 200 {:ok true
                                           :pubkey effective-pk
                                           :snapshots []
                                           :epoch (long (or @(:epoch-atom rt) 1))
                                           :min_signaling_burn burn-fl
                                           :bootstrap bootstrap-dom})))))))]
      (if (= method "POST")
        (read-req-body-bounded! req 65536 process-chain-state!)
        (process-chain-state! nil false)))

    :else
    (send-json! res 404 {:ok false :error "not-found" :path clean-path})))

(defn- lookup-acme-http01
  [rt token now-ms]
  (when (and (string? token) (not (str/blank? token)))
    (let [r (resolve-path-blob! rt (str "acme/challenge/" token) now-ms)]
      (if (:ok? r)
        (let [bs (get-in r [:blob :blob/bytes])
              mt (get-in r [:blob :blob/media-type])]
          (if (= mt "application/fressian")
            (let [d (try (fressian/decode-wire bs) (catch :default _ nil))]
              (when (map? d) (:key-auth d)))
            (fressian/bytes->utf8 bs)))
        (let [acme-file (.join node-path (:state-dir rt) "acme" (.basename node-path token))]
          (when (.existsSync node-fs acme-file)
            (str/trim (.readFileSync node-fs acme-file "utf8"))))))))

(defn- handle-directory-endpoint!
  [res rt clean-path method]
  (if-not (contains? #{"GET" "HEAD"} method)
    (send-json! res 405 {:ok false :error "method-not-allowed"})
    (let [subpath (subs clean-path (count "/directory/v1/"))
          segs (remove str/blank? (str/split subpath #"/"))
          [net-uri nick] (if (>= (count segs) 2)
                           [(first segs) (second segs)]
                           [(or (:domain (:config rt)) "bitecho.org") (first segs)])
          now-ms (.now js/Date)
          r (when nick
              (let [r1 (resolve-path-blob! rt (str "dir/" net-uri "/" nick) now-ms)]
                (if (:ok? r1) r1 (resolve-path-blob! rt (str "dir/" nick) now-ms))))]
      (if (and r (:ok? r))
        (let [buf (u8->buf (get-in r [:blob :blob/bytes]))]
          (.writeHead res 200 #js {"Content-Type" "application/json; charset=utf-8"
                                   "Cache-Control" "public, max-age=60"
                                   "Content-Length" (.-length buf)})
          (if (= method "HEAD") (.end res) (.end res buf)))
        (send-json! res 404 {:ok false :error "nickname-not-found" :nickname nick :network_uri net-uri})))))

(defn- handle-faucet-endpoint!
  [req res rt faucet-atom clean-path query-str method]
  (let [now-ms (.now js/Date)
        config (:config rt)]
    (cond
      (= clean-path "/faucet/v1/challenge")
      (let [qparams (core-infra/parse-query-params query-str)
            issue! (fn [body-buf _]
                     (let [body-json (when (and body-buf (pos? (.-length body-buf)))
                                       (try (js->clj (js/JSON.parse (.toString body-buf "utf8"))) (catch :default _ nil)))
                           net-uri (or (get body-json "network_uri")
                                       (get qparams "network_uri")
                                       (:network-uri config)
                                       "devnet.bitecho.org")
                           res-box (atom nil)
                           _ (swap! faucet-atom
                                    (fn [st]
                                      (let [r (faucet/issue-faucet-challenge st {:network-uri net-uri} now-ms)]
                                        (reset! res-box r)
                                        (:state r))))
                           ch (:challenge @res-box)]
                       (send-json! res 200 {:ok true :challenge ch})))]
        (if (= method "POST")
          (read-req-body-bounded! req 16384 issue!)
          (issue! nil false)))

      (= clean-path "/faucet/v1/claim")
      (if (not= method "POST")
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (read-req-body-bounded!
         req 65536
         (fn [body-buf exceeded?]
           (if exceeded?
             (send-json! res 413 {:ok false :error "payload-too-large"})
             (let [body-json (when (and body-buf (pos? (.-length body-buf)))
                               (try (js->clj (js/JSON.parse (.toString body-buf "utf8"))) (catch :default _ nil)))
                   nonce (get body-json "nonce")
                   cred-hash (or (get body-json "credential_id_hash") (get body-json "credential_hash"))
                   claimant-pk (or (get body-json "claimant_pubkey") (get body-json "pubkey"))
                   claim-net (or (get body-json "network_uri") (:network-uri config) "devnet.bitecho.org")
                   auth-ver (get body-json "authenticator_verified?" (get body-json "authenticator_verified" true))
                   claim-req {:nonce nonce
                              :credential-id-hash cred-hash
                              :claimant-pubkey claimant-pk
                              :network-uri claim-net
                              :authenticator-verified? auth-ver}
                   res-box (atom nil)
                   _ (swap! faucet-atom
                            (fn [st]
                              (let [r (faucet/reduce-faucet-claim st claim-req now-ms)]
                                (reset! res-box r)
                                (:state r))))
                   claim-res @res-box]
               (if-not (:ok? claim-res)
                 (send-json! res 400 {:ok false
                                      :error (name (or (:error claim-res) :faucet-claim-rejected))
                                      :reason (:reason claim-res)})
                 (do
                   (when (and (:receipt-blob claim-res) (:receipt-pointer claim-res))
                     (submit-subnet-event! rt {:type :put-blob
                                               :blob (:receipt-blob claim-res)
                                               :sender (:default-sender rt)
                                               :now-ms now-ms})
                     (submit-subnet-event! rt {:type :publish-pointer
                                               :pointer (:receipt-pointer claim-res)
                                               :sender (:default-sender rt)
                                               :now-ms now-ms}))
                   (send-json! res 200 (cond-> {:ok true
                                                :transfer_intent (:transfer-intent claim-res)
                                                :receipt_path (:receipt-path claim-res)
                                                :receipt_cid (:receipt-cid claim-res)}
                                         (:signed-transfer claim-res)
                                         (assoc :signed_transfer (:signed-transfer claim-res)))))))))))

      :else
      (send-json! res 404 {:ok false :error "not-found" :path clean-path}))))

(defn- handle-web-or-api-request!
  [req res {:keys [config rt relay-atom waiters-atom faucet-atom limiter-atom http-shell-atom dns-shell-atom smtp-shell-atom https? bound-https-port]}]
  (let [raw-url (or (.-url req) "/")
        [raw-path query-str] (str/split raw-url #"\?" 2)
        clean-path (let [p (str/replace raw-path #"/+$" "")] (if (str/blank? p) "/" p))
        method (str/upper-case (or (.-method req) "GET"))
        now-ms (.now js/Date)
        extra-hdrs (if https? {"Strict-Transport-Security" "max-age=31536000; includeSubDomains"} {})]
    (cond
      (= method "OPTIONS")
      (do
        (.writeHead res 204 #js {"Access-Control-Allow-Origin" "*"
                                 "Access-Control-Allow-Methods" "GET, HEAD, POST, OPTIONS"
                                 "Access-Control-Allow-Headers" "Content-Type, Range, If-None-Match, If-Match, X-Bitecho-DAC, X-Bitecho-Pubkey, X-Bitecho-Signature, X-Bitecho-Nonce, X-Bitecho-Timestamp-Ms"})
        (.end res))

      (str/starts-with? raw-path "/relay/v1/")
      (handle-relay-endpoint! req res rt relay-atom waiters-atom clean-path query-str method)

      (str/starts-with? raw-path "/artifact/v1/")
      (handle-artifact-endpoint! req res rt clean-path query-str method)

      (str/starts-with? raw-path "/directory/v1/")
      (handle-directory-endpoint! res rt clean-path method)

      (and faucet-atom (str/starts-with? raw-path "/faucet/v1/"))
      (handle-faucet-endpoint! req res rt faucet-atom clean-path query-str method)

      (and (contains? #{"GET" "HEAD"} method) (= clean-path "/healthz"))
      (send-json! res 200 {:ok true
                           :runtime "nodejs"
                           :version full-node-version
                           :node_id (name (or (:node-id rt) :ns3))})

      (and (contains? #{"GET" "HEAD"} method) (= clean-path "/statusz"))
      (send-json! res 200 (build-statusz-payload rt limiter-atom http-shell-atom dns-shell-atom smtp-shell-atom))

      (and (contains? #{"GET" "HEAD"} method) (= clean-path "/status"))
      (let [client-ip (or (some-> (get-header req "x-forwarded-for") (str/split #",") first str/trim)
                          (some-> (.-socket req) .-remoteAddress)
                          "unknown")
            rl-box (atom nil)
            _ (swap! status-rate-limiter-atom
                     (fn [st]
                       (let [r (incident/check-status-rate-limit st client-ip now-ms)]
                         (reset! rl-box r)
                         (:state r))))
            rl-res @rl-box]
        (if-not (:allowed? rl-res)
          (do
            (when (:diagnose rl-res)
              (apply-shell-event! http-shell-atom (:diagnose rl-res)))
            (let [body-str (js/JSON.stringify #js {:ok false :error "rate-limited" :retry_after_sec (:retry-after-sec rl-res)})
                  buf (.from js/Buffer body-str "utf8")]
              (.writeHead res 429 #js {"Content-Type" "application/json"
                                       "Content-Length" (.-length buf)
                                       "Retry-After" (str (:retry-after-sec rl-res))
                                       "Cache-Control" "no-store"})
              (if (= method "HEAD") (.end res) (.end res buf))))
          (let [cached @status-snapshot-cache-atom
                fresh-json (if (and (:json cached) (< (- now-ms (long (:updated-at-ms cached 0))) 5000))
                             (:json cached)
                             (let [sub @(:subnet-atom rt)
                                   le (:leader-election sub)
                                   peers (get-in (:config rt) [:cluster :nodes] {})
                                   fin-ep (current-finalized-epoch rt)
                                   relays (mapv (fn [[nid cfg]]
                                                  {:url (or (:http-url cfg) (str "https://" (name nid) ".bitecho.org"))
                                                   :status (if (contains? (or (:healthy-nodes le) #{}) nid) :healthy :degraded)
                                                   :ewma-rtt-ms 0.0
                                                   :finalized-epoch fin-ep})
                                                peers)
                                   rel-seq (long (or (get-in sub [:data :pointers ["bitecho.org/infra" "web/app/release"] :pointer/seq]) 0))
                                   snap (incident/build-status-snapshot
                                         {:finalized-epoch fin-ep
                                          :release-seq rel-seq
                                          :relays relays
                                          :updated-at-ms now-ms})
                                   j (js/JSON.stringify (clj->js snap))]
                               (reset! status-snapshot-cache-atom {:json j :updated-at-ms now-ms})
                               j))
                buf (.from js/Buffer fresh-json "utf8")]
            (.writeHead res 200 #js {"Content-Type" "application/json"
                                     "Content-Length" (.-length buf)
                                     "Cache-Control" "public, max-age=5, stale-while-revalidate=10"
                                     "Access-Control-Allow-Origin" "*"})
            (if (= method "HEAD") (.end res) (.end res buf)))))

      (and (contains? #{"GET" "HEAD"} method) (= clean-path "/favicon.ico"))
      (let [rel-st @(:app-release-atom rt)
            fav-cid (get-in rel-st [:active-release :assets "favicon.ico" :cid])
            fav-res (when fav-cid (resolve-cid-blob! rt fav-cid now-ms))
            fav-bytes (when (and fav-res (:ok? fav-res)) (get-in fav-res [:blob :blob/bytes]))]
        (if fav-bytes
          (let [buf (u8->buf fav-bytes)]
            (.writeHead res 200 #js {"Content-Type" "image/x-icon"
                                     "Content-Length" (.-length buf)
                                     "Cache-Control" "public, max-age=3600"})
            (if (= method "HEAD") (.end res) (.end res buf)))
          (send-text! res 404 "Not Found" method)))

      (and (contains? #{"GET" "HEAD"} method)
           (or (str/starts-with? clean-path "/incidents/")
               (str/starts-with? clean-path "/infra/incidents/")))
      (let [prefix (if (str/starts-with? clean-path "/infra/incidents/")
                     "/infra/incidents/"
                     "/incidents/")
            fname (subs clean-path (count prefix))
            safe? (and (not (str/blank? fname))
                       (not (str/includes? fname ".."))
                       (not (str/includes? fname "/"))
                       (not (str/includes? fname "\\")))]
        (if-not safe?
          (send-text! res 400 "Invalid incident path" method)
          (let [ptr-path (str "incidents/" fname)
                sub @(:subnet-atom rt)
                ptr (or (get-in sub [:data :pointers [(str (:subnet-id sub)) ptr-path]])
                        (get-in sub [:data :pointers ["bitecho.org/infra" ptr-path]])
                        (some (fn [[[_ p] v]] (when (= p ptr-path) v))
                              (get-in sub [:data :pointers])))
                cid (:pointer/target ptr)
                ct (cond
                     (str/ends-with? fname ".md") "text/markdown; charset=utf-8"
                     (str/ends-with? fname ".edn") "application/edn; charset=utf-8"
                     (str/ends-with? fname ".json") "application/json; charset=utf-8"
                     :else "text/plain; charset=utf-8")]
            (if-not cid
              (send-text! res 404 "Not Found" method)
              (resolve-cid-blob-async!
               rt cid now-ms
               (fn [bres]
                 (if (and (:ok? bres) (get-in bres [:blob :blob/bytes]))
                   (let [buf (u8->buf (get-in bres [:blob :blob/bytes]))]
                     (.writeHead res 200 #js {"Content-Type" ct
                                              "Content-Length" (.-length buf)
                                              "Cache-Control" "public, max-age=60"
                                              "Access-Control-Allow-Origin" "*"
                                              "X-Bitecho-Blob-Cid" cid})
                     (if (= method "HEAD") (.end res) (.end res buf)))
                   (send-text! res 404 "Not Found" method))))))))

      (and (contains? #{"GET" "HEAD"} method) (str/starts-with? raw-path "/.well-known/acme-challenge/"))
      (let [token (subs raw-path (count "/.well-known/acme-challenge/"))
            ka (lookup-acme-http01 rt token now-ms)]
        (if ka
          (let [buf (.from js/Buffer ka "utf8")]
            (.writeHead res 200 #js {"Content-Type" "application/octet-stream" "Content-Length" (.-length buf)})
            (if (= method "HEAD") (.end res) (.end res buf)))
          (send-text! res 404 "Not Found\n" method)))

      ;; On plain HTTP (:80) when HTTPS is active, redirect remaining paths with 308
      (and (not https?) bound-https-port (pos? bound-https-port)
           (get-in config [:http :redirect-http-to-https?] true))
      (let [host-hdr (or (get-header req "host") (:domain config) "localhost")
            host (first (str/split host-hdr #":"))
            port-suf (if (not= bound-https-port 443) (str ":" bound-https-port) "")
            loc (str "https://" host port-suf raw-url)]
        (.writeHead res 308 #js {"Location" loc "Connection" "close"})
        (.end res))

      (not (contains? #{"GET" "HEAD"} method))
      (send-text! res 405 "Method Not Allowed\n" method)

      :else
      (let [subpath (core-infra/sanitize-web-subpath raw-path)]
        (if (nil? subpath)
          (do
            (apply-shell-event! http-shell-atom {:type :drop :reason :http-forbidden-path :detail raw-path})
            (send-text! res 403 "Forbidden\n" method))
          (cond
            (str/starts-with? subpath "dist/")
            (handle-dist-request! req res config rt raw-path query-str method extra-hdrs limiter-atom)

            (or (= subpath "app") (str/starts-with? subpath "app/"))
            (let [rel-res (resolve-app-release-asset! rt raw-path now-ms)]
              (cond
                (:ok? rel-res)
                (let [buf (u8->buf (:body rel-res))
                      hdrs (assoc (merge {} extra-hdrs (:headers rel-res))
                                  "Content-Length" (.-length buf))]
                  (swap! limiter-atom #(-> (dns-proto/record-egress % (.-length buf) (current-month-key)) :state))
                  (.writeHead res (int (:status rel-res 200)) (clj->js hdrs))
                  (if (= method "HEAD") (.end res) (.end res buf)))

                (:fallback? rel-res)
                (resolve-web-blob-async!
                 config rt raw-path now-ms
                 (fn [resolved]
                   (cond
                     (= :forbidden (:error resolved))
                     (do
                       (apply-shell-event! http-shell-atom {:type :drop :reason :http-forbidden-path :detail raw-path})
                       (send-text! res 403 "Forbidden\n" method))

                     (:ok? resolved)
                     (send-resolved-blob! req res resolved method extra-hdrs limiter-atom)

                     :else
                     (send-text! res 404 "Not Found\n" method))))

                :else
                (do
                  (apply-shell-event! http-shell-atom {:type :drop :reason (or (:error rel-res) :http-app-release-error) :detail raw-path})
                  (send-text! res (int (or (:status rel-res) 404))
                              (case (int (or (:status rel-res) 404))
                                403 "Forbidden\n"
                                503 "Service Unavailable\n"
                                "Not Found\n")
                              method))))

            :else
            (resolve-web-blob-async!
             config rt raw-path now-ms
             (fn [resolved]
               (cond
                 (= :forbidden (:error resolved))
                 (do
                   (apply-shell-event! http-shell-atom {:type :drop :reason :http-forbidden-path :detail raw-path})
                   (send-text! res 403 "Forbidden\n" method))

                 (:ok? resolved)
                 (send-resolved-blob! req res resolved method extra-hdrs limiter-atom)

                 :else
                 (send-text! res 404 "Not Found\n" method))))))))))

(defn- find-header-end-idx
  [buf]
  (let [len (.-length buf)]
    (loop [i 0]
      (when (<= (+ i 4) len)
        (if (and (= 13 (aget buf i))
                 (= 10 (aget buf (+ i 1)))
                 (= 13 (aget buf (+ i 2)))
                 (= 10 (aget buf (+ i 3))))
          (+ i 4)
          (recur (inc i)))))))

(defn- splice-sockets!
  [client-sock backend-sock shell-atom]
  (.on client-sock "error" (fn [e]
                             (apply-shell-event! shell-atom {:type :drop :reason :passthrough-client-error :detail (.-message e)})
                             (.destroy backend-sock)))
  (.on backend-sock "error" (fn [e]
                              (apply-shell-event! shell-atom {:type :drop :reason :passthrough-backend-error :detail (.-message e)})
                              (.destroy client-sock)))
  (.pipe client-sock backend-sock)
  (.pipe backend-sock client-sock))

(defn- handle-passthrough-socket!
  [client-sock {:keys [domain internal-https-port ingress-target connect-targets connect-routes peek-timeout-ms shell-atom]}]
  (let [chunks #js []
        handled? (atom false)
        dispatch! (fn []
                    (when (compare-and-set! handled? false true)
                      (.setTimeout client-sock 0)
                      (let [buf (.concat js/Buffer chunks)
                            n (.-length buf)]
                        (if-not (pos? n)
                          (.destroy client-sock)
                          (let [u8 (buf->u8 buf)
                                conn-req (dns-proto/parse-http-connect-request u8 n)]
                            (if conn-req
                              ;; 1. Allowlisted HTTP CONNECT tunnel (fail-closed 403 otherwise)
                              (let [target-key (str (:host conn-req) ":" (:port conn-req))
                                    backend (core-infra/resolve-connect-backend conn-req connect-targets connect-routes ingress-target)]
                                (if-not backend
                                  (do
                                    (apply-shell-event! shell-atom {:type :drop :reason :http-connect-denied :detail target-key})
                                    (.end client-sock "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
                                  (let [bsock (.createConnection node-net #js {:host (:host backend) :port (long (:port backend))})
                                        hdr-end (or (find-header-end-idx buf) n)]
                                    (.setNoDelay client-sock true)
                                    (.setNoDelay bsock true)
                                    (.once bsock "connect"
                                           (fn []
                                             (.write client-sock "HTTP/1.1 200 Connection Established\r\n\r\n")
                                             (when (< hdr-end n)
                                               (.write bsock (.subarray buf hdr-end n)))
                                             (splice-sockets! client-sock bsock shell-atom)))
                                    (.on bsock "error"
                                         (fn [e]
                                           (apply-shell-event! shell-atom {:type :drop :reason :http-connect-dial-failed :detail (.-message e)})
                                           (when-not (.-destroyed client-sock)
                                             (.end client-sock "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")))))))
                              ;; 2. Ingress stream (DTLS/STUN/SNI *.ingress.<domain>) vs internal HTTPS server
                              (let [ingress? (and (some? ingress-target) (dns-proto/ingress-stream? u8 n domain))
                                    target (if ingress? ingress-target {:host "127.0.0.1" :port internal-https-port})
                                    bsock (.createConnection node-net #js {:host (:host target) :port (long (:port target))})]
                                (.setNoDelay client-sock true)
                                (.setNoDelay bsock true)
                                (.once bsock "connect"
                                       (fn []
                                         (.write bsock buf)
                                         (splice-sockets! client-sock bsock shell-atom)))
                                (.on bsock "error"
                                     (fn [e]
                                       (apply-shell-event! shell-atom {:type :drop :reason :passthrough-dial-failed :detail (.-message e)})
                                       (.destroy client-sock))))))))))]
    (.setTimeout client-sock (long (or peek-timeout-ms 2000)))
    (.once client-sock "timeout" (fn [] (when-not @handled? (.destroy client-sock))))
    (.on client-sock "error" (fn [_] (reset! handled? true)))
    (.once client-sock "data"
           (fn [chunk]
             (.pause client-sock)
             (.push chunks chunk)
             (dispatch!)))))

;; =============================================================================
;; 8. Inbound SMTP Server (`node:net` + `bitecho.core.protocol.smtp`)
;; =============================================================================

(defn- deliver-smtp-mail!
  [rt domain remote-ip deliver-eff seq-counter]
  (let [now-ms (.now js/Date)
        msg-id (.toString (.randomBytes node-crypto 8) "hex")
        date-str (.toUTCString (js/Date. now-ms))
        full-eml (core-infra/build-received-eml {:id msg-id
                                                 :domain domain
                                                 :remote-ip remote-ip
                                                 :helo (:helo deliver-eff)
                                                 :date-str date-str
                                                 :raw-eml (:data-str deliver-eff)})
        mail-dir (.join node-path (:state-dir rt) "mail")
        _ (-> (atomic-write-file-async! (.join node-path mail-dir (str now-ms "-" msg-id ".eml")) full-eml 0600)
              (.catch (fn [e]
                        (apply-shell-event! (:shell-atom rt)
                                            {:type :diagnose :reason :smtp-disk-write-failed :detail (or (.-message e) (str e))}))))
        blob (data/make-blob (fressian/utf8->bytes full-eml) "message/rfc822")
        cid8 (subs (:blob/cid blob) 0 8)
        auth-pub (:default-sender rt)
        auth-priv (:node-privkey rt)]
    (when (and auth-pub auth-priv)
      (submit-subnet-event! rt {:type :put-blob :blob blob :sender auth-pub :now-ms now-ms})
      (doseq [rcpt (:to deliver-eff)]
        (let [path (str "mail/" rcpt "/" now-ms "-" cid8)
              s (swap! seq-counter inc)
              ptr (data/sign-pointer auth-priv {:pointer/authority auth-pub
                                                :pointer/subnet (:subnet-id @(:subnet-atom rt))
                                                :pointer/path path
                                                :pointer/seq s
                                                :pointer/target (:blob/cid blob)
                                                :pointer/proof {:proof/type :self}})]
          (submit-subnet-event! rt {:type :publish-pointer :sender auth-pub :pointer ptr :now-ms now-ms}))))))

(defn- start-smtp-server!
  [config rt on-ready]
  (let [shell-atom (atom (core-infra/init-shell-state :smtp-shell))
        _ (apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        smtp-cfg (get config :smtp {})
        bind-ip (get smtp-cfg :bind-ip "0.0.0.0")
        port (long (get smtp-cfg :port 25))
        domain (or (:domain config) "localhost")
        max-bytes (long (get smtp-cfg :max-message-bytes 131072))
        allowed (get smtp-cfg :allowed-recipients #{})
        seq-counter (atom 0)
        srv (.createServer
             node-net
             (fn [sock]
               (let [remote-ip (or (.-remoteAddress sock) "127.0.0.1")
                     greet (smtp-proto/greeting (smtp-proto/init-session {:domain domain
                                                                          :max-message-bytes max-bytes
                                                                          :allowed-recipients allowed
                                                                          :tls-active? false}))
                     st-atom (atom (:state greet))
                     buf-atom (atom "")]
                 (.setTimeout sock (long (get smtp-cfg :socket-timeout-ms 30000)))
                 (doseq [r (:responses greet)]
                   (.write sock (str r "\r\n")))
                 (.on sock "data"
                      (fn [chunk]
                        (swap! buf-atom str (.toString chunk "utf8"))
                        (loop []
                          (let [s @buf-atom
                                idx (.indexOf s "\n")]
                            (when (>= idx 0)
                              (let [raw-line (subs s 0 idx)
                                    line (if (str/ends-with? raw-line "\r")
                                           (subs raw-line 0 (dec (count raw-line)))
                                           raw-line)]
                                (reset! buf-atom (subs s (inc idx)))
                                (let [res (smtp-proto/handle-smtp-line @st-atom line)]
                                  (reset! st-atom (:state res))
                                  (doseq [eff (:effects res)]
                                    (when (= :diagnose (:effect eff))
                                      (apply-shell-event! shell-atom {:type :drop :reason (:reason eff)})))
                                  (doseq [resp (:responses res)]
                                    (.write sock (str resp "\r\n")))
                                  (when-let [deliv (first (filter #(= :deliver-mail (:type %)) (:effects res)))]
                                    (deliver-smtp-mail! rt domain remote-ip deliv seq-counter))
                                  (if (some #(= :close (:type %)) (:effects res))
                                    (.end sock)
                                    (recur)))))))))
                 (.on sock "timeout" (fn []
                                       (apply-shell-event! shell-atom {:type :drop :reason :smtp-timeout})
                                       (.destroy sock)))
                 (.on sock "error" (fn [e]
                                     (apply-shell-event! shell-atom {:type :drop :reason :smtp-socket-error :detail (.-message e)}))))))]
    (.on srv "error" (fn [e]
                       (apply-shell-event! shell-atom {:type :diagnose :reason :smtp-server-error :detail (.-message e)})))
    (.listen srv port bind-ip
             (fn []
               (let [bound-port (.-port (.address srv))]
                 (apply-shell-event! shell-atom {:type :started :generation gen :resources {:srv srv}})
                 (on-ready {:shell-atom shell-atom
                            :port bound-port
                            :stop-fn (fn []
                                       (apply-shell-event! shell-atom {:type :stop}
                                                           (fn [{:keys [srv]}]
                                                             (when srv (try (.close srv) (catch :default _ nil))))))}))))))

;; =============================================================================
;; 9. Full Validator Mesh & Fressian State Persistence Engine (Node.js Parity)
;; =============================================================================

(defonce ^:private last-saved-snapshots (atom {}))
(defonce ^:private validator-writer-atoms (atom {}))

(defn- get-validator-writer-atom
  [state-dir node-id keep-epochs min-keep]
  (let [k (str state-dir "::" (snap/sanitize-node-id node-id))]
    (or (get @validator-writer-atoms k)
        (let [a (atom (snap/init-writer-state {:node-id node-id
                                               :keep-epochs (or keep-epochs snap/default-keep-epochs)
                                               :min-keep (or min-keep snap/default-min-keep)}))]
          (swap! validator-writer-atoms assoc k a)
          (get @validator-writer-atoms k)))))

(defn- prune-validator-snapshots-async!
  [state-dir writer-atom eff]
  (let [gen (:generation eff)
        nid (:node-id eff)
        cur-ep (:current-epoch eff)
        keep-epochs (:keep-epochs eff)
        min-keep (:min-keep eff)]
    (-> (.readdir node-fsp state-dir)
        (.then (fn [entries]
                 (let [filenames (vec (array-seq entries))
                       {:keys [delete]} (snap/plan-snapshot-retention
                                         nid filenames cur-ep
                                         {:keep-epochs keep-epochs :min-keep min-keep})]
                   (js/Promise.all
                    (clj->js
                     (mapv (fn [fname]
                             (-> (.unlink node-fsp (.join node-path state-dir fname))
                                 (.catch (fn [_] nil))))
                           delete)))
                   (count delete))))
        (.then (fn [del-count]
                 (let [effs-box (atom [])]
                   (swap! writer-atom
                          (fn [wst]
                            (let [[wst' effs] (snap/transition-writer
                                               wst
                                               {:type :prune-succeeded
                                                :generation gen
                                                :deleted-count del-count})]
                              (reset! effs-box effs)
                              wst')))
                   (doseq [d @effs-box]
                     (when (= :diagnose (:effect d))
                       (log-diagnostic! d))))))
        (.catch (fn [e]
                  (let [effs-box (atom [])]
                    (swap! writer-atom
                           (fn [wst]
                             (let [[wst' effs] (snap/transition-writer
                                                wst
                                                {:type :prune-failed
                                                 :generation gen
                                                 :error (or (.-message e) (str e))})]
                               (reset! effs-box effs)
                               wst')))
                    (doseq [d @effs-box]
                      (when (= :diagnose (:effect d))
                        (log-diagnostic! d)))))))))

(declare execute-validator-writer-effects!)

(defn- execute-validator-writer-effects!
  [state-dir path-key writer-atom effects]
  (doseq [eff effects]
    (case (:effect eff)
      :diagnose
      (log-diagnostic! eff)

      :prune-snapshots
      (prune-validator-snapshots-async! state-dir writer-atom eff)

      :write-snapshot
      (let [gen (:generation eff)
            ep (:epoch eff)
            fname (:filename eff)
            dest-path (.join node-path state-dir fname)
            st-to-save (:payload eff)]
        ;; Yield via setImmediate so active UDP/STUN/ICE keepalives & DataChannel callbacks run first
        (js/setImmediate
         (fn []
           (try
             (let [encode-t0 (.now js/Date)
                   safe-state (core-mesh/strip-unserializable-state st-to-save)
                   encoded-u8 (fressian/write-standard-fressian safe-state)
                   encode-ms (max 0 (- (.now js/Date) encode-t0))
                   _ (swap! runtime-metrics-atom assoc :last-snapshot-encode-ms encode-ms)
                   buf (u8->buf encoded-u8)]
               (-> (atomic-write-file-async! dest-path buf 0600)
                   (.then (fn [_]
                            (let [now-ms (.now js/Date)
                                  next-effs (atom [])]
                              (swap! last-saved-snapshots
                                     (fn [m]
                                       (-> m
                                           (assoc-in [path-key :saved-at-ms] now-ms)
                                           (assoc-in [path-key :finalized-epoch] ep)
                                           (assoc-in [path-key :filename] fname)
                                           (update-in [path-key :saved-count] (fnil inc 0)))))
                              (swap! writer-atom
                                     (fn [wst]
                                       (let [[wst' effs] (snap/transition-writer
                                                          wst
                                                          {:type :write-succeeded
                                                           :generation gen
                                                           :epoch ep
                                                           :filename fname})]
                                         (reset! next-effs effs)
                                         wst')))
                              (execute-validator-writer-effects! state-dir path-key writer-atom @next-effs))))
                   (.catch (fn [e]
                             (let [next-effs (atom [])]
                               (swap! writer-atom
                                      (fn [wst]
                                        (let [[wst' effs] (snap/transition-writer
                                                           wst
                                                           {:type :write-failed
                                                            :generation gen
                                                            :epoch ep
                                                            :error (or (.-message e) (str e))})]
                                          (reset! next-effs effs)
                                          wst')))
                               (execute-validator-writer-effects! state-dir path-key writer-atom @next-effs))))))
             (catch :default e
               (let [next-effs (atom [])]
                 (swap! writer-atom
                        (fn [wst]
                          (let [[wst' effs] (snap/transition-writer
                                             wst
                                             {:type :write-failed
                                              :generation gen
                                              :epoch ep
                                              :error (or (.-message e) (str e))})]
                            (reset! next-effs effs)
                            wst')))
                 (execute-validator-writer-effects! state-dir path-key writer-atom @next-effs)))))))

      nil)))

(defn- save-validator-state-to-disk!
  "Persists validator state to immutable epoch-addressed Fressian snapshots
   (`snapshot-<node>-epoch-<012d>.fressian`) via `bitecho.snapshot.core` coalescing async writer
   (`fs.promises` + `setImmediate`, BIP-014 / P-ASYNC-2).
   On runtime ticks (`force? false`), throttles via `obs/should-persist-validator-snapshot?` (60s)
   and performs zero synchronous disk I/O.
   On shutdown (`force? true`), performs an explicit synchronous final flush (BIP-014 exception)."
  ([filepath state]
   (save-validator-state-to-disk! filepath state false nil))
  ([filepath state force?]
   (save-validator-state-to-disk! filepath state force? nil))
  ([filepath state force? {:keys [node-id keep-epochs min-keep]}]
   (when (and filepath (map? state))
     (try
       (let [path-key (str filepath)
             state-dir (.dirname node-path path-key)
             nid (or node-id (:node-id state) (:node/id state) "node")
             now-ms (.now js/Date)
             prev-entry (get @last-saved-snapshots path-key)
             last-saved-ms (long (or (:saved-at-ms prev-entry) 0))
             curr-fin-ep (long (or (:last-executed-finalized-epoch state) (:epoch state) 0))
             should-save? (obs/should-persist-validator-snapshot?
                           {:force? force?
                            :last-saved-ms last-saved-ms
                            :now-ms now-ms
                            :min-interval-ms 60000})]
         (if-not should-save?
           (do
             (swap! last-saved-snapshots update-in [path-key :skipped-clean] (fnil inc 0))
             true)
           (if force?
             ;; Explicit boot/SIGTERM synchronous flush exception (BIP-014)
             (let [fname (snap/snapshot-filename nid curr-fin-ep)
                   dest-path (.join node-path state-dir fname)
                   safe-state (core-mesh/strip-unserializable-state state)
                   encoded-u8 (fressian/write-standard-fressian safe-state)]
               (atomic-write-file! dest-path (u8->buf encoded-u8) 0600)
               (swap! last-saved-snapshots
                      (fn [m]
                        (-> m
                            (assoc-in [path-key :saved-at-ms] now-ms)
                            (assoc-in [path-key :finalized-epoch] curr-fin-ep)
                            (assoc-in [path-key :filename] fname)
                            (update-in [path-key :saved-count] (fnil inc 0)))))
               true)
             ;; Zero-Sync-IO runtime coalesced async write + retention pruning
             (let [writer-atom (get-validator-writer-atom state-dir nid keep-epochs min-keep)
                   effs-box (atom [])]
               (swap! writer-atom
                      (fn [wst]
                        (let [[wst' effs] (snap/transition-writer
                                           wst
                                           {:type :request-write
                                            :epoch curr-fin-ep
                                            :payload state
                                            :force? false
                                            :node-id nid})]
                          (reset! effs-box effs)
                          wst')))
               (execute-validator-writer-effects! state-dir path-key writer-atom @effs-box)
               true))))
       (catch :default e
         (log-diagnostic! {:effect :diagnose :reason :validator-snapshot-save-failed :file filepath :detail (.-message e)})
         false)))))

(defn- load-validator-state-from-disk
  "Boot-time validator snapshot loader (explicit BIP-014 boot exception).
   Scans the state directory via `bitecho.snapshot.core/select-latest-snapshot` to load the
   highest-epoch immutable `snapshot-<node>-epoch-<012d>.fressian`, falling back seamlessly
   to legacy `snapshot-<node>.edn` when present. Rejects legacy Nippy ('NPY') fail-closed."
  ([filepath]
   (load-validator-state-from-disk filepath nil))
  ([filepath node-id]
   (when filepath
     (try
       (let [state-dir (.dirname node-path (str filepath))
             legacy-name (.basename node-path (str filepath))
             selected-path (if (and node-id (.existsSync node-fs state-dir))
                             (let [entries (vec (array-seq (.readdirSync node-fs state-dir)))
                                   sel (snap/select-latest-snapshot node-id entries legacy-name)]
                               (when sel (.join node-path state-dir sel)))
                             (when (.existsSync node-fs filepath) filepath))]
         (when (and selected-path (.existsSync node-fs selected-path))
           (let [buf (.readFileSync node-fs selected-path)
                 u8 (buf->u8 buf)]
             (core-mesh/decode-snapshot-bytes u8))))
       (catch :default e
         (log-diagnostic! {:effect :diagnose :reason :validator-snapshot-load-failed :file filepath :detail (.-message e)})
         nil)))))

(defn- execute-mesh-conn-effects!
  [effects]
  (doseq [eff effects]
    (case (:effect eff)
      :close-node
      (when-let [n (:node eff)]
        (try (api/close! n) (catch :default _ nil)))

      (:diagnose :ignore-stale)
      (log-diagnostic! eff)

      nil)))

(defn- apply-mesh-conn-event!
  [conns-atom k event]
  (let [effects-ref (atom [])]
    (swap! conns-atom
           (fn [conns]
             (let [conn (get conns k)
                   [new-conn effects] (core-mesh/transition-mesh-conn conn event)
                   updated (assoc conns k new-conn)]
               (reset! effects-ref effects)
               (core-mesh/prune-closed-conn-tombstones updated))))
    (execute-mesh-conn-effects! @effects-ref)
    (get @conns-atom k)))

(defn- apply-agent-sender-rebind!
  [agent-conns anon-key sender-hex cid now-ms]
  (let [effects-ref (atom [])]
    (swap! agent-conns
           (fn [conns]
             (let [[new-conns effects] (core-mesh/rebind-agent-conn-sender conns anon-key sender-hex cid now-ms)]
               (reset! effects-ref effects)
               (core-mesh/prune-closed-conn-tombstones new-conns))))
    (execute-mesh-conn-effects! @effects-ref)
    (get @agent-conns sender-hex)))

(defn- reap-idle-anon-agent-conns!
  ([agent-conns]
   (reap-idle-anon-agent-conns! agent-conns 10000))
  ([agent-conns max-age-ms]
   (when agent-conns
     (let [now-ms (.now js/Date)
           max-age (long (or max-age-ms 10000))
           stale-keys (->> @agent-conns
                           (keep (fn [[k c]]
                                   (when (and (core-mesh/anon-conn-key? k)
                                              (not= :down (:phase c))
                                              (not= :failed (:phase c)))
                                     (let [ts (long (or (:last-rx-at c) (:connected-at c) (:created-at c) 0))]
                                       (when (>= (- now-ms ts) max-age)
                                         k))))))]
       (doseq [k stale-keys]
         (apply-mesh-conn-event! agent-conns k {:type :reap :now-ms now-ms}))))))

(defn- forward-gossip-to-agents!
  [agent-conns frozen-evt exclude-sender]
  (when agent-conns
    (if-let [wire-bytes (core-mesh/ensure-fressian-wire-bytes frozen-evt)]
      (let [msg-id (core-mesh/extract-gossip-msg-id wire-bytes)]
        (doseq [[pk conn] @agent-conns
                :when (and (not= pk exclude-sender)
                           (not (core-mesh/anon-conn-key? pk)))]
          (let [sent-ids (core-mesh/conn-sent-msg-ids conn)]
            (when-not (and msg-id (contains? sent-ids msg-id))
              (when-let [cid (or (core-mesh/conn-channel-id conn) 0)]
                (if-let [on-msg (:on-message conn)]
                  (try
                    (on-msg wire-bytes)
                    (when msg-id
                      (apply-mesh-conn-event! agent-conns pk {:type :record-sent-msg :msg-id msg-id}))
                    (catch :default e
                      (apply-mesh-conn-event! agent-conns pk
                                              {:type :send-failed :error (or (.-message e) "send-failed")})
                      nil))
                  (when-let [node (:node conn)]
                    (try
                      (api/send! node wire-bytes cid)
                      (when msg-id
                        (apply-mesh-conn-event! agent-conns pk {:type :record-sent-msg :msg-id msg-id}))
                      (catch :default e
                        (apply-mesh-conn-event! agent-conns pk
                                                {:type :send-failed :error (or (.-message e) "send-failed")})
                        nil)))))))))
      (doseq [[pk _] @agent-conns
              :when (not= pk exclude-sender)]
        (apply-mesh-conn-event! agent-conns pk
                                {:type :invalid-frame :error "garbage-wire-bytes-dropped"})))))

(defn- replay-cached-gossip-to-agent!
  [state-atom agent-conns conn-key]
  (when-let [st (when state-atom @state-atom)]
    (let [messages-map (or (:messages st) {})
          epochs-map (or (:message-epochs st) {})
          sorted-msgs (sort-by (fn [[mid _]] [(long (get epochs-map mid 0)) (str mid)]) messages-map)]
      (doseq [[mid message] sorted-msgs]
        (let [conn (when agent-conns (get @agent-conns conn-key))]
          (when-let [node (:node conn)]
            (let [sent-ids (core-mesh/conn-sent-msg-ids conn)]
              (when-not (contains? sent-ids mid)
                (let [cid (or (core-mesh/conn-channel-id conn) 0)
                      frozen (fressian/encode-wire {:type :receive-gossip :message message})]
                  (try
                    (api/send! node frozen cid)
                    (apply-mesh-conn-event! agent-conns conn-key {:type :record-sent-msg :msg-id mid})
                    (catch :default e
                      (when agent-conns
                        (apply-mesh-conn-event! agent-conns conn-key
                                                {:type :send-failed :error (or (.-message e) "send-failed")}))
                      nil)))))))))))

(defn- send-net-out-cmd!
  [ctx cmd]
  (try
    (let [{:keys [identity peer-conns agent-conns]} ctx
          targets (core-mesh/extract-command-target-hexes cmd)
          sender-hex (:pubkey-hex identity)
          evt (core-mesh/command->network-event cmd sender-hex)
          frozen (fressian/encode-wire evt)]
      (doseq [target targets]
        (when-let [conn (or (when peer-conns (get @peer-conns target))
                            (when agent-conns (get @agent-conns target)))]
          (when-let [cid (core-mesh/conn-channel-id conn)]
            (try
              (when-let [node (:node conn)]
                (api/send! node frozen cid))
              (catch :default e
                (let [target-conns (if (and peer-conns (get @peer-conns target)) peer-conns agent-conns)]
                  (when target-conns
                    (apply-mesh-conn-event! target-conns target
                                            {:type :send-failed :peer target :error (or (.-message e) "send-failed")}))))))))
      (when (and (or (= (:type cmd) :send-gossip)
                     (= (:type evt) :receive-gossip))
                 agent-conns)
        (forward-gossip-to-agents! agent-conns frozen nil)))
    (catch :default e
      (log-diagnostic! {:effect :diagnose :reason :net-out-error :detail (.-message e)}))))

(defn- step-validator-event!
  [ctx event from-network?]
  (let [{:keys [state-atom snapshot-file persist?]} ctx]
    (if (and from-network? (not (core-mesh/valid-network-event? event)))
      (do
        (swap! state-atom update :dropped-network-events-count (fnil inc 0))
        (log-diagnostic! {:effect :diagnose :reason :dropped-network-event :event-type (:type event)}))
      (let [queue-atom (atom (conj #queue [] event))
            tick? (= (:type event) :tick)]
        (loop [steps 0]
          (when (and (seq @queue-atom) (< steps 256))
            (let [ev (peek @queue-atom)
                  _ (swap! queue-atom pop)
                  st @state-atom
                  res (try
                        (sm/handle-event st ev)
                        (catch :default t
                          {:exception t}))]
              (if-let [t (:exception res)]
                (do
                  (swap! state-atom
                         (fn [s]
                           (-> s
                               (update :event-errors-count (fnil inc 0))
                               (assoc :last-event-error (or (.-message t) (str t))))))
                  (swap! validator-event-error-count inc)
                  (log-diagnostic! {:effect :diagnose :reason :validator-event-error :event-type (:type ev) :detail (or (.-message t) (str t))}))
                (let [{new-state :state commands :commands} res]
                  (reset! state-atom new-state)
                  (doseq [cmd commands]
                    (cond
                      (= (:type cmd) :app-event) nil
                      (or (= (:type cmd) :diagnose) (= (:effect cmd) :diagnose))
                      (log-diagnostic! cmd)
                      (core-mesh/is-network-command? cmd)
                      (send-net-out-cmd! ctx cmd)
                      :else
                      (swap! queue-atom conj cmd)))))
              (recur (inc steps)))))
        (when (and persist? snapshot-file tick?)
          (save-validator-state-to-disk!
           snapshot-file @state-atom false
           {:node-id (:node-id ctx)
            :keep-epochs (get-in ctx [:config :snapshot-keep-epochs])
            :min-keep (get-in ctx [:config :snapshot-min-keep])}))))))

(defn- create-peer-datachannel-node
  [local-port setup cert-data local-ice _local-fp turn-config]
  (api/create-node
   (cond-> {:port local-port
            :setup setup
            :cert-data cert-data
            :ice-creds local-ice}
     turn-config (assoc :turn-config turn-config)
     (and turn-config (some? (:use-turn-relay? turn-config)))
     (assoc :use-turn-relay? (boolean (:use-turn-relay? turn-config)))
     (and turn-config (nil? (:use-turn-relay? turn-config)) (true? (:force-relay? turn-config)))
     (assoc :use-turn-relay? true))))

(defn- init-datachannel-peer!
  [ctx pid peer-cfg]
  (try
    (let [peer-hex (:pubkey peer-cfg)
          raw-fp (:fingerprint peer-cfg)
          peer-fp (when (core-mesh/verify-peer-fingerprint? raw-fp raw-fp)
                    (core-mesh/normalize-fingerprint raw-fp))
          {:keys [node-id identity node-idx nodes-cfg state-atom peer-conns agent-conns peer-snapshot-waiters]} ctx
          local-fp (:fingerprint identity)
          local-ice (or (:ice-creds identity)
                        (when (and (:ice-ufrag identity) (:ice-pwd identity))
                          {:ufrag (:ice-ufrag identity) :pwd (:ice-pwd identity)}))
          remote-ice (or (:ice-creds peer-cfg)
                         (when (and (:ice-ufrag peer-cfg) (:ice-pwd peer-cfg))
                           {:ufrag (:ice-ufrag peer-cfg) :pwd (:ice-pwd peer-cfg)}))]
      (cond
        (not peer-fp)
        (when peer-hex
          (apply-mesh-conn-event! peer-conns peer-hex
                                  {:type :dial-failed :peer pid :error "invalid-peer-fingerprint"}))

        (or (nil? (:ufrag local-ice)) (nil? (:pwd local-ice))
            (nil? (:ufrag remote-ice)) (nil? (:pwd remote-ice)))
        (when peer-hex
          (apply-mesh-conn-event! peer-conns peer-hex
                                  {:type :dial-failed :peer pid :error "missing-ice-credentials"}))

        :else
        (let [next-gen (inc (long (get-in @peer-conns [peer-hex :generation] 0)))
              peer-ip (or (:ip peer-cfg) (:ip4 peer-cfg) "127.0.0.1")
              base-peer-port (int (or (:port peer-cfg) 5000))
              peer-port (+ base-peer-port (int (get node-idx node-id 0)))
              base-local-port (int (or (get-in nodes-cfg [node-id :port]) 5000))
              local-port (+ base-local-port (int (get node-idx pid 0)))
              setup (if (neg? (compare (name node-id) (name pid))) "active" "passive")
              turn-cfg (or (:turn-config peer-cfg) (get-in ctx [:config :cluster :turn-config]))
              node (create-peer-datachannel-node local-port setup (:cert-data identity) local-ice local-fp turn-cfg)
              _ (apply-mesh-conn-event! peer-conns peer-hex
                                        {:type :dial-started :generation next-gen :node node :peer pid})
              remote-sdp {:ip peer-ip
                          :port peer-port
                          :fingerprint peer-fp
                          :remote-ice-ufrag (:ufrag remote-ice)
                          :remote-ice-pwd (:pwd remote-ice)}
              callbacks {:on-open
                         (fn [evt]
                           (let [curr-conn (get @peer-conns peer-hex)]
                             (if (or (< next-gen (long (:generation curr-conn 0)))
                                     (not= node (:node curr-conn)))
                               (apply-mesh-conn-event! peer-conns peer-hex
                                                       {:type :on-open :generation next-gen :node node :peer pid})
                               (let [cid (or (:channel-id evt)
                                             (try (api/create-data-channel! node "bitecho" {:ordered true})
                                                  (catch :default _ 0)))]
                                 (apply-mesh-conn-event! peer-conns peer-hex
                                                         {:type :on-open :generation next-gen :node node :channel-id cid :peer pid})))))
                         :on-message
                         (fn [evt]
                           (let [updated (apply-mesh-conn-event!
                                          peer-conns peer-hex
                                          (cond-> {:type :on-message :generation next-gen :node node :peer pid}
                                            (:channel-id evt) (assoc :channel-id (:channel-id evt))))]
                             (when (= node (:node updated))
                               (let [msg (fressian/decode-wire (:payload evt))]
                                 (if-not (map? msg)
                                   (apply-mesh-conn-event! peer-conns peer-hex
                                                           {:type :invalid-frame :generation next-gen :node node :peer pid :error "malformed-peer-frame"})
                                   (case (:type msg)
                                     :keepalive nil
                                     :peer-chain-state-query
                                     (try
                                       (let [st @state-atom
                                             tpk (:target-pubkey msg)
                                             n (:nonce msg)
                                             snap (when (and (map? st) (seq st) tpk)
                                                    (core-mesh/build-validator-chain-state-snapshot st identity tpk n))
                                             cid (or (:channel-id evt) (core-mesh/conn-channel-id updated) 0)]
                                         (when (and (map? snap) (string? (:signature snap)))
                                           (api/send! node
                                                      (fressian/encode-wire {:type :peer-chain-state-response
                                                                             :target-pubkey tpk
                                                                             :nonce (or n "")
                                                                             :snapshot snap})
                                                      cid)))
                                       (catch :default _ nil))
                                     :peer-chain-state-response
                                     (try
                                       (when peer-snapshot-waiters
                                         (let [k [(:target-pubkey msg) (or (:nonce msg) "")]
                                               snap (:snapshot msg)]
                                           (when-let [waiter (and (map? snap) (get @peer-snapshot-waiters k))]
                                             (let [snaps (swap! (:snapshots-atom waiter) conj snap)]
                                               (when (>= (count snaps) (long (or (:target-count waiter) 5)))
                                                 (when-let [done-fn (:done-fn waiter)]
                                                   (done-fn)))))))
                                       (catch :default _ nil))
                                     (let [event (assoc msg
                                                        :sender peer-hex
                                                        :sender-pubkey-bytes (basalt/hex->bytes peer-hex)
                                                        :rng (crypto/make-random))]
                                       (step-validator-event! ctx event true)
                                       (when (= :receive-gossip (:type msg))
                                         (forward-gossip-to-agents! agent-conns (fressian/encode-wire msg) nil)))))))))
                         :on-close
                         (fn [_]
                           (apply-mesh-conn-event! peer-conns peer-hex
                                                   {:type :on-close :generation next-gen :node node :peer pid}))}]
          (try
            (api/start! node remote-sdp callbacks)
            (api/set-max-message-size! node)
            (catch :default e
              (apply-mesh-conn-event! peer-conns peer-hex
                                      {:type :dial-failed :generation next-gen :node node :peer pid :error (or (.-message e) "start-failed")})
              (throw e))))))
    (catch :default e
      (log-diagnostic! {:effect :diagnose :reason :peer-init-failed :peer pid :detail (.-message e)})
      nil)))

(defn- send-peer-keepalives!
  [peer-conns]
  (when peer-conns
    (let [keepalive-bytes (fressian/encode-wire {:type :keepalive})]
      (doseq [[peer-hex conn] @peer-conns
              :let [cid (core-mesh/conn-channel-id conn)]
              :when (some? cid)]
        (try
          (when-let [node (:node conn)]
            (api/send! node keepalive-bytes cid))
          (catch :default e
            (apply-mesh-conn-event! peer-conns peer-hex
                                    {:type :send-failed :peer peer-hex :error (or (.-message e) "send-failed")})))))))

(defn- check-and-reconnect-peers!
  [ctx timeout-ms now-ms]
  (let [{:keys [nodes-cfg node-id peer-conns state-atom]} ctx
        active-peers-map (when state-atom (:peers-map @state-atom))
        enforce-active? (boolean (seq active-peers-map))]
    (when (and enforce-active? peer-conns)
      (doseq [[peer-hex conn] @peer-conns
              :when (and (not (contains? active-peers-map peer-hex))
                         (not= :down (:phase conn)))]
        (apply-mesh-conn-event! peer-conns peer-hex {:type :shutdown})))
    (doseq [[pid pcfg] nodes-cfg
            :when (not= pid node-id)
            :let [peer-hex (:pubkey pcfg)]
            :when (or (not enforce-active?) (contains? active-peers-map peer-hex))
            :let [conn (get @peer-conns peer-hex)
                  node (:node conn)
                  st (when node (try (api/get-state node) (catch :default _ :closed)))
                  cid (when conn (core-mesh/conn-channel-id conn))
                  created-at (long (get conn :created-at 0))
                  last-rx (long (or (when conn (core-mesh/conn-last-rx-at conn)) now-ms))
                  stalled-unconnected? (and (nil? cid) (> (- (long now-ms) created-at) 12000))
                  timed-out-connected? (and (some? cid) (> (- (long now-ms) last-rx) (long timeout-ms)))]]
      (when (or (nil? conn)
                (= st :closed)
                stalled-unconnected?
                timed-out-connected?)
        (try
          (init-datachannel-peer! ctx pid pcfg)
          (catch :default e
            (log-diagnostic! {:effect :diagnose :reason :peer-reconnect-error :peer pid :detail (.-message e)})))))))

(defonce ^:private anon-agent-id-seq (atom 0))

(defn- make-agent-connection-handler
  [ctx peer-ice-pwds]
  (let [{:keys [state-atom agent-conns identity]} ctx]
    (fn [agent-node]
      (let [conn-key (atom [:anon (swap! anon-agent-id-seq inc)])
            init-gen (inc (long (reduce max 0 (map #(long (or (:generation %) 0)) (vals (or (when agent-conns @agent-conns) {}))))))
            node-gen (atom init-gen)]
        (try (api/set-max-message-size! agent-node) (catch :default _ nil))
        (when agent-conns
          (apply-mesh-conn-event! agent-conns @conn-key
                                  {:type :accept-started :generation @node-gen :node agent-node :channel-id 0}))
        (api/set-callbacks!
         agent-node
         {:on-open (fn [evt]
                     (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                           has-cid? (or (contains? evt :channel-id)
                                        (contains? evt :stream-id)
                                        (some? (get-in evt [:channel :id])))
                           updated (when agent-conns
                                     (apply-mesh-conn-event! agent-conns @conn-key
                                                             {:type :on-open :generation @node-gen :node agent-node :channel-id cid}))]
                       (when (and has-cid? (or (nil? agent-conns) (= agent-node (:node updated))))
                         (when-not (core-mesh/anon-conn-key? @conn-key)
                           (replay-cached-gossip-to-agent! state-atom agent-conns @conn-key)))))
          :on-data-channel (fn [evt]
                             (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                                   updated (when agent-conns
                                             (apply-mesh-conn-event! agent-conns @conn-key
                                                                     {:type :on-data-channel :generation @node-gen :node agent-node :channel-id cid}))]
                               (when (or (nil? agent-conns) (= agent-node (:node updated)))
                                 (when-not (core-mesh/anon-conn-key? @conn-key)
                                   (replay-cached-gossip-to-agent! state-atom agent-conns @conn-key)))))
          :on-message
          (fn [evt]
            (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                  active? (or (nil? agent-conns)
                              (= agent-node (:node (get @agent-conns @conn-key))))]
              (if-not active?
                (when agent-conns
                  (apply-mesh-conn-event! agent-conns @conn-key
                                          {:type :on-message :generation @node-gen :node agent-node :channel-id cid}))
                (let [unwrapped (core-mesh/unwrap-authenticated-agent-event (:payload evt))]
                  (if-not unwrapped
                    (when agent-conns
                      (apply-mesh-conn-event! agent-conns @conn-key
                                              {:type :invalid-frame :generation @node-gen :node agent-node :error "invalid-agent-envelope"}))
                    (do
                      (when (and (= :register-home-set (:type unwrapped))
                                 (:ice-ufrag unwrapped)
                                 (:ice-pwd unwrapped))
                        (let [ufrag (:ice-ufrag unwrapped)
                              pwd (:ice-pwd unwrapped)
                              sender (:sender unwrapped)
                              node-ufrag (when-let [sa (:state-atom agent-node)] (:remote-ice-ufrag @sa))
                              can-set? (and (or (nil? node-ufrag) (= node-ufrag ufrag))
                                            (or (nil? peer-ice-pwds)
                                                (let [curr-pwds @peer-ice-pwds
                                                      owner (get curr-pwds [:owner ufrag])]
                                                  (or (nil? owner) (= owner sender)))))]
                          (when can-set?
                            (when peer-ice-pwds
                              (swap! peer-ice-pwds (fn [m]
                                                     (-> (assoc m ufrag pwd)
                                                         (assoc [:owner ufrag] sender)))))
                            (try
                              (api/set-remote-ice-credentials! agent-node ufrag pwd)
                              (catch :default _
                                (when-let [st-atom (:state-atom agent-node)]
                                  (swap! st-atom assoc
                                         :remote-ice-ufrag ufrag
                                         :remote-ice-pwd pwd)))))))
                      (let [sender (:sender unwrapped)
                            query-only? (= (:type unwrapped) :query-chain-state)]
                        (when (and sender (not query-only?) (core-mesh/anon-conn-key? @conn-key) (not= sender @conn-key))
                          (let [old-key @conn-key]
                            (if agent-conns
                              (let [rebound (apply-agent-sender-rebind! agent-conns old-key sender cid (.now js/Date))]
                                (when (= agent-node (:node rebound))
                                  (reset! conn-key sender)
                                  (reset! node-gen (long (or (:generation rebound) @node-gen)))
                                  (replay-cached-gossip-to-agent! state-atom agent-conns sender)))
                              (reset! conn-key sender))))
                        (let [updated (when (and agent-conns (not query-only?))
                                        (apply-mesh-conn-event! agent-conns @conn-key
                                                                {:type :on-message :generation @node-gen :node agent-node :channel-id cid}))]
                          (when (or (nil? agent-conns) query-only? (= agent-node (:node updated)))
                            (if query-only?
                              (let [st @state-atom
                                    snapshot (when (and (map? st) (seq st))
                                               (core-mesh/build-validator-chain-state-snapshot st identity (:pubkey unwrapped) (:nonce unwrapped)))]
                                (when (and (map? snapshot) (string? (:signature snapshot)) (not (str/blank? (:signature snapshot))))
                                  (try
                                    (api/send! agent-node (fressian/encode-wire snapshot) cid)
                                    (catch :default e
                                      (log-diagnostic! {:effect :diagnose :reason :agent-snapshot-send-failed :detail (.-message e)}))))
                                (when (core-mesh/anon-conn-key? @conn-key)
                                  (when agent-conns
                                    (apply-mesh-conn-event! agent-conns @conn-key
                                                            {:type :on-close :generation @node-gen :node agent-node}))
                                  (try (api/close! agent-node) (catch :default _ nil))))
                              (do
                                (step-validator-event! ctx unwrapped true)
                                (when (and (= (:type unwrapped) :receive-gossip) agent-conns)
                                  (let [fressian-payload (if (and (fressian/bytes? (:payload evt)) (fressian/nippy-payload? (:payload evt)))
                                                           (fressian/encode-wire {:type :receive-gossip :message (:message unwrapped)})
                                                           (:payload evt))]
                                    (forward-gossip-to-agents! agent-conns fressian-payload (:sender unwrapped)))))))))))))))
          :on-close (fn [_]
                      (when agent-conns
                        (apply-mesh-conn-event! agent-conns @conn-key
                                                {:type :on-close :generation @node-gen :node agent-node})))})))))

(defn- start-validator-http-server!
  "Starts embedded validator HTTP server (`127.0.0.1:8080`) serving `/healthz`, `/statusz`, `/connz`, `/burnsz`, `/accountz`."
  [http-cfg ctx total-peers fallback-state on-ready]
  (if-not (get http-cfg :enabled? true)
    (when on-ready (on-ready nil 0))
    (let [port (long (get http-cfg :port 8080))
          host (str (get http-cfg :host "127.0.0.1"))
          {:keys [state-atom peer-conns agent-conns identity]} ctx
          srv (.createServer
               node-http
               (fn [req res]
                 (let [raw-url (or (.-url req) "/")
                       [path query] (str/split raw-url #"\?" 2)
                       method (str/upper-case (or (.-method req) "GET"))
                       st (or (when state-atom @state-atom) fallback-state)]
                   (cond
                     (= path "/healthz")
                     (send-text! res 200 "ok\n" method)

                     (= path "/statusz")
                     (let [connected (count (filter (fn [[_ c]] (some? (core-mesh/conn-channel-id c)))
                                                    (when peer-conns @peer-conns)))
                           conn-diag (core-mesh/mesh-conn-diagnostics-summary
                                      (when peer-conns @peer-conns)
                                      (when agent-conns @agent-conns))]
                       (send-text! res 200 (core-mesh/render-statusz st connected total-peers conn-diag) method))

                     (= path "/connz")
                     (let [conn-diag (core-mesh/mesh-conn-diagnostics-summary
                                      (when peer-conns @peer-conns)
                                      (when agent-conns @agent-conns))]
                       (send-text! res 200 (str (pr-str conn-diag) "\n") method))

                     (= path "/burnsz")
                     (send-text! res 200 (str (pr-str (sm/extract-burn-window st)) "\n") method)

                     (= path "/accountz")
                     (let [qparams (core-infra/parse-query-params query)
                           pubkey (get qparams "pubkey")
                           nonce (get qparams "nonce")
                           include-escrows? (= "true" (get qparams "include-escrows"))
                           snap (when (and pubkey nonce identity (map? st))
                                  (try
                                    (core-mesh/build-validator-chain-state-snapshot st identity pubkey nonce)
                                    (catch :default _ nil)))
                           resp (cond
                                  pubkey
                                  (cond-> {:pubkey pubkey
                                           :account (when-let [a (get (:ledger st) pubkey)] (into (sorted-map) a))
                                           :spendable (sm/spendable-balance st pubkey)
                                           :finalized-epoch (long (or (:last-executed-finalized-epoch st) 0))}
                                    snap (assoc :snapshot snap))

                                  include-escrows?
                                  {:accounts (into (sorted-map) (map (fn [[k v]] [k (into (sorted-map) v)]) (:ledger st)))
                                   :escrows (into (sorted-map) (map (fn [[k v]] [k (into (sorted-map) v)]) (:escrows st)))
                                   :failed-receipts-count (long (or (:failed-receipts-count st) 0))
                                   :pending-receipts-count (long (count (or (:pending-receipts st) [])))
                                   :epoch (long (or (:epoch st) 0))
                                   :finalized-epoch (long (or (:last-executed-finalized-epoch st) 0))}

                                  :else
                                  {:accounts (into (sorted-map) (map (fn [[k v]] [k (into (sorted-map) v)]) (:ledger st)))
                                   :finalized-epoch (long (or (:last-executed-finalized-epoch st) 0))})]
                       (send-text! res 200 (str (pr-str resp) "\n") method))

                     :else
                     (send-text! res 404 "not found\n" method)))))]
      (.listen srv port host
               (fn []
                 (let [bound-port (.-port (.address srv))]
                   (when on-ready
                     (on-ready srv bound-port)))))
      srv)))

(defn- post-https-artifact!
  "Best-effort HTTPS POST to an infra node `/artifact/v1/*` endpoint with bounded timeout and
   counted `:diagnose` on failure (`Rule 5`)."
  [hostname path content-type body-buf on-done]
  (try
    (let [req (.request node-https
                        #js {:hostname hostname
                             :port 443
                             :path path
                             :method "POST"
                             :timeout 5000
                             :headers #js {"Content-Type" content-type
                                           "Content-Length" (.-length body-buf)}}
                        (fn [res]
                          (.resume res)
                          (let [sc (.-statusCode res)]
                            (on-done (and (>= sc 200) (< sc 300)) sc))))]
      (.on req "error" (fn [e] (on-done false (.-message e))))
      (.on req "timeout" (fn [] (.destroy req)))
      (.end req body-buf))
    (catch :default e
      (on-done false (.-message e)))))

(defn- telemetry-lifecycle-path
  [state-dir nid]
  (when state-dir
    (.join node-path (str state-dir) (str "telemetry-lifecycle-" nid ".edn"))))

(defn- load-telemetry-lifecycle-ledger!
  [state-dir nid now-ms]
  (let [p (telemetry-lifecycle-path state-dir nid)
        prev (when (and p (.existsSync node-fs p))
               (try
                 (edn/read-string (.readFileSync node-fs p "utf8"))
                 (catch :default _ nil)))
        next-ledger (obs/record-startup-event prev {:node-id nid :now-ms now-ms})]
    (when p
      (try
        (let [tmp (str p ".tmp")]
          (-> (.writeFile (.-promises node-fs) tmp (pr-str next-ledger) "utf8")
              (.then #(.rename (.-promises node-fs) tmp p))
              (.catch (fn [_] nil))))
        (catch :default _ nil)))
    next-ledger))

(defn- persist-telemetry-lifecycle-async!
  [state-dir nid ledger]
  (when-let [p (telemetry-lifecycle-path state-dir nid)]
    (try
      (let [tmp (str p ".tmp")]
        (-> (.writeFile (.-promises node-fs) tmp (pr-str ledger) "utf8")
            (.then #(.rename (.-promises node-fs) tmp p))
            (.catch (fn [_] nil))))
      (catch :default _ nil))))

(defn- persist-telemetry-shutdown-marker!
  [state-dir nid ledger-atom]
  (let [now-ms (.now js/Date)
        marked (swap! ledger-atom obs/record-shutdown-marker {:now-ms now-ms :cause :planned-deploy})]
    (when-let [p (telemetry-lifecycle-path state-dir nid)]
      (try
        (let [tmp (str p ".tmp")]
          (.writeFileSync node-fs tmp (pr-str marked) "utf8")
          (.renameSync node-fs tmp p))
        (catch :default _ nil)))))

(defn- start-validator-telemetry-publisher!
  "P-OBS-4 / D38.1 / D39.5 / D39.6: Periodically publishes signed privacy-preserving
   `telemetry/<node-id>/digest.edn` blobs & pointers from standalone validator nodes
   (`node1..node3`) with real restart/stall downtime tracking, peer-conn diagnostics,
   and all 6 priority operational metrics."
  [node-id identity state-atom peer-conns state-dir]
  (start-event-loop-lag-sampler!)
  (let [started-ms (.now js/Date)
        nid (if (keyword? node-id) (name node-id) (str node-id))
        auth-pub (:pubkey-hex identity)
        auth-priv (:privkey-bytes identity)
        targets ["ns1.bitecho.org" "ns2.bitecho.org" "ns3.bitecho.org"]
        seq-atom (atom 0)
        ledger-atom (atom (load-telemetry-lifecycle-ledger! state-dir nid started-ms))
        prev-rates-atom (atom nil)
        publish-once!
        (fn []
          (when (and auth-pub auth-priv)
            (try
              (let [now-ms (.now js/Date)
                    st @state-atom
                    mem (.memoryUsage js/process)
                    heap-used (.-heapUsed mem)
                    heap-slope (record-heap-sample! now-ms heap-used)
                    rtm @runtime-metrics-atom
                    lag-samples (:loop-lag-samples rtm)
                    lag-p99 (obs/p99-ms lag-samples)
                    lag-max (if (seq lag-samples) (double (apply max lag-samples)) 0.0)
                    head-ep (long (or (:epoch st) 0))
                    fin-ep (long (or (:last-executed-finalized-epoch st) 0))
                    peers-up (count (filter (fn [[_ v]] (= :open (:phase v))) @peer-conns))
                    conn-diag (core-mesh/mesh-conn-diagnostics-summary @peer-conns nil)
                    failed-now (long (or (:failed-receipts-count st) 0))
                    verr-now (long @validator-event-error-count)
                    prev-r @prev-rates-atom
                    failed-delta (if prev-r (max 0 (- failed-now (:failed prev-r))) 0)
                    verr-delta (if prev-r (max 0 (- verr-now (:verr prev-r))) 0)
                    _ (reset! prev-rates-atom {:failed failed-now :verr verr-now})
                    ledger (swap! ledger-atom obs/record-stall-sample
                                  {:node-id nid
                                   :now-ms now-ms
                                   :head-epoch head-ep
                                   :finalized-epoch fin-ep})
                    _ (persist-telemetry-lifecycle-async! state-dir nid ledger)
                    pub (obs/prepare-telemetry-publication
                         {:node-id nid
                          :version full-node-version
                          :bundle-sha256 (running-bundle-sha256)
                          :uptime-ms (max 0 (- now-ms started-ms))
                          :restart-count (:restart-count ledger)
                          :restart-causes (:restart-causes ledger)
                          :downtime-events (obs/effective-downtime-events ledger now-ms)
                          :head-epoch head-ep
                          :finalized-epoch fin-ep
                          :runtime-summary {:rss-bytes (.-rss mem)
                                            :heap-used-bytes heap-used
                                            :heap-total-bytes (.-heapTotal mem)
                                            :heap-slope-bytes-per-min (Math/round heap-slope)
                                            :v8-heap-headroom-pct (sample-v8-heap-headroom-pct)
                                            :event-loop-lag-p99-ms lag-p99
                                            :event-loop-lag-max-ms lag-max
                                            :last-snapshot-encode-ms (long (or (:last-snapshot-encode-ms rtm) 0))
                                            :runtime "nodejs"}
                          :service-counters {:peers-connected peers-up
                                             :pending-receipts (count (:pending-receipts st))
                                             :failed-receipts failed-now
                                             :failed-receipts-last-60s failed-delta
                                             :validator-event-errors verr-now
                                             :validator-event-errors-last-60s verr-delta
                                             :notarized-count (+ (count (:notarized-blocks st))
                                                                 (long (or (:pruned-notarized-count st) 0)))
                                             :finalized-count (+ (count (:finalized-blocks st))
                                                                 (long (or (:pruned-finalized-count st) 0)))}
                          :defense-counters {:conn-dropped (long (or (:dropped conn-diag) 0))
                                             :conn-stale (long (or (:ignored-stale conn-diag) 0))}})
                    blob (data/make-blob (:edn-bytes pub) "application/edn")
                    next-seq (swap! seq-atom (fn [prev] (max (inc (long prev)) (quot now-ms 1000))))
                    ptr (data/sign-pointer auth-priv
                                           {:pointer/authority auth-pub
                                            :pointer/subnet "bitecho.org/infra"
                                            :pointer/path (:path pub)
                                            :pointer/seq next-seq
                                            :pointer/target (:blob/cid blob)
                                            :pointer/proof {:proof/type :self}})
                    blob-buf (u8->buf (:blob/bytes blob))
                    ptr-buf (.from js/Buffer (pr-str ptr) "utf8")
                    try-host! (fn try-host! [idx]
                                (if (>= idx (count targets))
                                  (log-diagnostic! {:effect :diagnose
                                                    :reason :telemetry-digest-publish-failed
                                                    :node-id nid
                                                    :path (:path pub)})
                                  (let [h (nth targets idx)]
                                    (post-https-artifact!
                                     h "/artifact/v1/blob" "application/edn" blob-buf
                                     (fn [ok1 _]
                                       (if-not ok1
                                         (try-host! (inc idx))
                                         (post-https-artifact!
                                          h "/artifact/v1/pointer" "application/edn" ptr-buf
                                          (fn [ok2 _]
                                            (when-not ok2
                                              (try-host! (inc idx)))))))))))]
                (try-host! 0))
              (catch :default e
                (log-diagnostic! {:effect :diagnose
                                  :reason :telemetry-digest-build-failed
                                  :node-id nid
                                  :detail (.-message e)})))))
        t0 (js/setTimeout publish-once! 15000)
        iv (js/setInterval publish-once! 60000)]
    (fn []
      (js/clearTimeout t0)
      (js/clearInterval iv)
      (persist-telemetry-shutdown-marker! state-dir nid ledger-atom))))

(defn- fetch-url-bytes-async!
  "Fetches raw bytes from an HTTP/HTTPS URL asynchronously for P-UPD-1 auto-updates."
  [url-str timeout-ms cb]
  (let [settled? (atom false)
        done! (fn [res]
                (when (compare-and-set! settled? false true)
                  (cb res)))]
    (try
      (let [https? (str/starts-with? (str/lower-case (str url-str)) "https://")
            url-obj (js/URL. url-str)
            client (if https? node-https node-http)
            req (.request client
                          #js {:protocol (.-protocol url-obj)
                               :hostname (.-hostname url-obj)
                               :port (or (not-empty (str (.-port url-obj))) (if https? 443 80))
                               :path (str (.-pathname url-obj) (.-search url-obj))
                               :method "GET"
                               :timeout (or timeout-ms 15000)}
                          (fn [res]
                            (let [status-code (.-statusCode res)
                                  chunks #js []]
                              (.on res "data" (fn [c] (.push chunks c)))
                              (.on res "end" (fn []
                                               (let [buf (js/Buffer.concat chunks)
                                                     u8 (js/Uint8Array. (.-buffer buf) (.-byteOffset buf) (.-byteLength buf))]
                                                 (done! {:ok? (and (>= status-code 200) (< status-code 300))
                                                         :status status-code
                                                         :bytes u8}))))
                              (.on res "error" (fn [err] (done! {:ok? false :status status-code :error (str err)}))))))]
        (.on req "timeout" (fn [] (.destroy req) (done! {:ok? false :status 408 :error "timeout"})))
        (.on req "error" (fn [err] (done! {:ok? false :status 500 :error (str err)})))
        (.end req))
      (catch :default e
        (done! {:ok? false :status 500 :error (str e)})))))

(defn- start-full-node-auto-updater!
  "P-UPD-1 / D40.1: Generation-tagged `deploy/reduce-light-update-tick` self-update loop
   for Node.js full & infra nodes (`:artifact-role :full-node`).
   Verifies pointer authority + monotonic version + SHA-256 == CID, runs pre-swap
   `node <tmp> --self-test` gate, atomically swaps bundle with `.lkg` rollback backup,
   and exits cleanly (`0`) so OpenRC `supervise-daemon` respawns on the new bundle."
  [node-id config stop-fn!]
  (when-let [pointer-url (:auto-update-pointer config)]
    (let [nid (if (keyword? node-id) (name node-id) (str node-id))
          bundle-path (when (exists? js/__filename) js/__filename)
          poll-ms (max 5000 (long (or (:auto-update-interval-ms config) 60000)))
          updater-atom (atom (deploy/init-light-updater-state
                              {:node-id nid
                               :artifact-role :full-node
                               :current-version full-node-version
                               :current-cid (running-bundle-sha256)
                               :trusted-deploy-authorities (:trusted-deploy-authorities config)
                               :pinned-version (:pin-version config)
                               :poll-interval-ms poll-ms}))
          staged-bytes-atom (atom nil)
          staged-path-atom (atom nil)
          fsp (.-promises node-fs)
          dispatch! (fn dispatch! [ev]
                      (let [effs-box (atom [])]
                        (swap! updater-atom
                               (fn [st]
                                 (let [[st' effs] (deploy/reduce-light-update-tick st ev)]
                                   (reset! effs-box effs)
                                   st')))
                        (doseq [eff @effs-box]
                          (case (:effect eff)
                            :fetch-pointer
                            (let [gen (:generation eff)]
                              (fetch-url-bytes-async!
                               pointer-url 15000
                               (fn [res]
                                 (if (:ok? res)
                                   (let [txt (fressian/bytes->utf8 (:bytes res))
                                         ptr (try (edn/read-string txt) (catch :default _ nil))]
                                     (if (map? ptr)
                                       (dispatch! {:type :pointer-seen :pointer ptr :generation gen})
                                       (log-diagnostic! {:effect :diagnose :reason :full-update-malformed-pointer :node-id nid})))
                                   (log-diagnostic! {:effect :diagnose :reason :full-update-fetch-pointer-failed :node-id nid :error (:error res)})))))

                            :fetch-bundle-blob
                            (let [gen (:generation eff)
                                  cid (:cid eff)
                                  blob-url (deploy/build-blob-fetch-url pointer-url cid)]
                              (fetch-url-bytes-async!
                               blob-url 30000
                               (fn [res]
                                 (if (:ok? res)
                                   (do
                                     (reset! staged-bytes-atom (:bytes res))
                                     (dispatch! {:type :blob-fetched :cid cid :bytes (:bytes res) :generation gen}))
                                   (log-diagnostic! {:effect :diagnose :reason :full-update-fetch-blob-failed :node-id nid :cid cid :error (:error res)})))))

                            :stage-light-bundle
                            (when (and bundle-path @staged-bytes-atom)
                              (let [dir (.dirname node-path bundle-path)
                                    cid8 (subs (str (:cid eff)) 0 (min 8 (count (str (:cid eff)))))
                                    tmp-p (.join node-path dir (str ".bitecho-full-update-" cid8 ".cjs.tmp"))
                                    buf (u8->buf @staged-bytes-atom)]
                                (reset! staged-path-atom tmp-p)
                                (-> (.writeFile fsp tmp-p buf #js {:mode 0755})
                                    (.catch (fn [e]
                                              (log-diagnostic! {:effect :diagnose :reason :full-update-stage-failed :node-id nid :detail (.-message e)}))))))

                            :atomic-swap-and-restart-light-node
                            (let [gen (:generation eff)
                                  cid (:cid eff)
                                  tmp-p @staged-path-atom]
                              (when (and bundle-path tmp-p)
                                (.execFile node-child-process
                                           (.-execPath js/process)
                                           #js [tmp-p "--self-test"]
                                           #js {:timeout 15000}
                                           (fn [err stdout _stderr]
                                             (let [ok? (and (nil? err)
                                                            (try
                                                              (true? (aget (js/JSON.parse (str stdout)) "ok"))
                                                              (catch :default _ false)))]
                                               (if-not ok?
                                                 (dispatch! {:type :health-check-result :healthy? false :generation gen})
                                                 (let [lkg-p (str bundle-path ".lkg")]
                                                   (-> (.copyFile fsp bundle-path lkg-p)
                                                       (.catch (fn [_] nil))
                                                       (.then (fn [_] (.rename fsp tmp-p bundle-path)))
                                                       (.then (fn [_]
                                                                (log-diagnostic! {:effect :auto-update-applied :node-id nid :cid cid :restarting true})
                                                                (when stop-fn! (try (stop-fn!) (catch :default _ nil)))
                                                                (.exit js/process 0)))
                                                       (.catch (fn [e]
                                                                 (log-diagnostic! {:effect :diagnose :reason :full-update-swap-failed :node-id nid :detail (.-message e)})
                                                                 (dispatch! {:type :health-check-result :healthy? false :generation gen})))))))))))

                            :restore-lkg-light-bundle
                            (do
                              (when-let [tmp-p @staged-path-atom]
                                (-> (.unlink fsp tmp-p) (.catch (fn [_] nil))))
                              (log-diagnostic! {:effect :diagnose :reason :full-update-rolled-back :node-id nid :lkg-version (:lkg-version eff)}))

                            :diagnose
                            (log-diagnostic! (assoc eff :node-id nid))

                            nil))))
          t0 (js/setTimeout #(dispatch! {:type :poll-tick}) 20000)
          iv (js/setInterval #(dispatch! {:type :poll-tick}) poll-ms)]
      (fn []
        (js/clearTimeout t0)
        (js/clearInterval iv)))))

(defn start-validator-mesh-node!
  "Starts a full Bitecho validator & mesh node on Node.js (`:5000..5005` DataChannel peer mesh,
   `:5010` UDP+TCP agent ingress, `127.0.0.1:8080` validator diagnostics, and Fressian snapshot persistence)."
  ([config]
   (start-validator-mesh-node! config {}))
  ([config opts]
   (let [node-id (let [nid (or (:node/id config) (:node-id config) :node1)]
                   (if (keyword? nid) nid (keyword (str nid))))
         state-dir (or (:state-dir config) "data")
         _ (when-not (.existsSync node-fs state-dir)
             (.mkdirSync node-fs state-dir #js {:recursive true}))
         identity (or (:identity opts) (load-or-create-node-identity! state-dir node-id))
         transport (or (:transport opts) (:transport config) :datachannel)
         snapshot-file (or (:snapshot-file opts)
                           (.join node-path state-dir "state" (str "snapshot-" (snap/sanitize-node-id node-id) ".edn")))
         loaded-state (load-validator-state-from-disk snapshot-file node-id)
         initial-state (if loaded-state
                         (core-mesh/rebind-restored-state loaded-state config identity)
                         (core-mesh/build-initial-node-state config identity))
         state-atom (atom initial-state)
         peer-conns (atom {})
         agent-conns (atom {})
         peer-snapshot-waiters (atom {})
         cluster-cfg (get config :cluster {})
         nodes-cfg (get cluster-cfg :nodes {})
         sorted-ids (vec (sort-by name (keys nodes-cfg)))
         node-idx (into {} (map-indexed (fn [i k] [k i]) sorted-ids))
         persist? (get opts :persist? true)
         ctx {:node-id node-id
              :config config
              :identity identity
              :transport transport
              :state-atom state-atom
              :snapshot-file snapshot-file
              :persist? persist?
              :peer-conns peer-conns
              :agent-conns agent-conns
              :peer-snapshot-waiters peer-snapshot-waiters
              :node-idx node-idx
              :nodes-cfg nodes-cfg}
         _ (when persist?
             (if loaded-state
               (swap! last-saved-snapshots assoc (str snapshot-file)
                      {:saved-at-ms (.now js/Date)
                       :finalized-epoch (long (or (:last-executed-finalized-epoch initial-state) 0))
                       :saved-count 0})
               (save-validator-state-to-disk!
                snapshot-file @state-atom true
                {:node-id node-id
                 :keep-epochs (:snapshot-keep-epochs config)
                 :min-keep (:snapshot-min-keep config)})))
         _ (when (= transport :datachannel)
             (doseq [[pid pcfg] nodes-cfg :when (not= pid node-id)]
               (try
                 (init-datachannel-peer! ctx pid pcfg)
                 (catch :default e
                   (log-diagnostic! {:effect :diagnose :reason :peer-init-error :peer pid :detail (.-message e)})))))
         tick-interval (long (or (get-in config [:protocol :tick-interval-ms])
                                 (get-in initial-state [:config :tick-interval-ms])
                                 (:tick-interval-ms config/devnet-config)
                                 10000))
         timeout-ms (max 20000 (* 2 tick-interval))
         rem-ms (mod (.now js/Date) tick-interval)
         initial-delay (if (zero? rem-ms) tick-interval (- tick-interval rem-ms))
         interval-atom (atom nil)
         tick-fn! (fn []
                    (try
                      (step-validator-event! ctx {:type :tick :rng (crypto/make-random)} false)
                      (when (= transport :datachannel)
                        (send-peer-keepalives! peer-conns)
                        (check-and-reconnect-peers! ctx timeout-ms (.now js/Date)))
                      (reap-idle-anon-agent-conns! agent-conns 10000)
                      (catch :default e
                        (log-diagnostic! {:effect :diagnose :reason :ticker-loop-error :detail (.-message e)}))))
         init-timer (js/setTimeout
                     (fn []
                       (tick-fn!)
                       (reset! interval-atom (js/setInterval tick-fn! tick-interval)))
                     initial-delay)
         listen-agents? (and (= transport :datachannel)
                             (boolean (get-in config [:cluster :listen-agents?] false)))
         agent-port (int (get-in config [:cluster :agent-port] 5010))
         agent-tcp-port (int (or (get-in config [:cluster :agent-tcp-port]) agent-port 5010))
         peer-ice-pwds (atom {})
         agent-listener (when listen-agents?
                          (api/listen! {:port agent-port
                                        :cert-data (:cert-data identity)
                                        :ice-creds (:ice-creds identity)
                                        :peer-ice-pwds peer-ice-pwds}
                                       {:on-connection (make-agent-connection-handler ctx peer-ice-pwds)}))
         agent-tcp-listener (when listen-agents?
                              (api/listen-tcp! {:port agent-tcp-port
                                                :cert-data (:cert-data identity)
                                                :ice-creds (:ice-creds identity)
                                                :peer-ice-pwds peer-ice-pwds}
                                               {:on-connection (make-agent-connection-handler ctx peer-ice-pwds)}))
         http-srv-atom (atom nil)
         _ (start-validator-http-server!
            (get config :http {})
            ctx
            (count (disj (set (keys nodes-cfg)) node-id))
            initial-state
            (fn [srv bound-port]
              (reset! http-srv-atom srv)
              (when-let [cb (:on-ready opts)]
                (cb {:http-port bound-port}))))
         stop-telemetry! (when (and (not (:embedded? opts))
                                    (not (false? (:publish-telemetry? config))))
                           (start-validator-telemetry-publisher! node-id identity state-atom peer-conns state-dir))
         stop-updater-atom (atom nil)
         stop! (fn []
                 (when-let [su @stop-updater-atom] (try (su) (catch :default _ nil)))
                 (when stop-telemetry! (stop-telemetry!))
                 (js/clearTimeout init-timer)
                 (when-let [iv @interval-atom] (js/clearInterval iv))
                 (when-let [srv @http-srv-atom] (try (.close srv) (catch :default _ nil)))
                 (when agent-listener (try (api/close! agent-listener) (catch :default _ nil)))
                 (when agent-tcp-listener (try (api/close! agent-tcp-listener) (catch :default _ nil)))
                 (doseq [[peer-hex _] @peer-conns]
                   (apply-mesh-conn-event! peer-conns peer-hex {:type :shutdown}))
                 (doseq [[k _] @agent-conns]
                   (apply-mesh-conn-event! agent-conns k {:type :shutdown}))
                 (when (and persist? snapshot-file)
                   (save-validator-state-to-disk!
                    snapshot-file @state-atom true
                    {:node-id node-id
                     :keep-epochs (:snapshot-keep-epochs config)
                     :min-keep (:snapshot-min-keep config)})))
         _ (when (and (not (:embedded? opts)) (:auto-update-pointer config))
             (reset! stop-updater-atom (start-full-node-auto-updater! node-id config stop!)))]
     {:node-id node-id
      :identity identity
      :transport transport
      :state-atom state-atom
      :snapshot-file snapshot-file
      :peer-conns peer-conns
      :agent-conns agent-conns
      :peer-snapshot-waiters peer-snapshot-waiters
      :agent-listener agent-listener
      :agent-tcp-listener agent-tcp-listener
      :http-server-atom http-srv-atom
      :config config
      :stop! stop!})))

(defn- query-peer-validators-chain-state!
  "Queries connected validator peers over the persistent in-band `peer-conns` mesh
   for signed chain-state snapshots of `target-pubkey` with `nonce` (`P-NET-1`).
   Invokes `(cb snapshots-vec)` within `timeout-ms` (default 800ms)."
  [vnode target-pubkey nonce timeout-ms cb]
  (let [pconns-atom (:peer-conns vnode)
        w-atom (:peer-snapshot-waiters vnode)
        open-conns (when pconns-atom
                     (->> (vals @pconns-atom)
                          (filter (fn [c] (and (= :open (:phase c)) (:node c))))
                          vec))]
    (if-not (and target-pubkey w-atom (seq open-conns))
      (cb [])
      (let [n-str (str (or nonce ""))
            k [target-pubkey n-str]
            snaps-atom (atom [])
            settled? (atom false)
            timer-id (atom nil)
            finish! (fn []
                      (when (compare-and-set! settled? false true)
                        (when-let [t @timer-id] (js/clearTimeout t))
                        (swap! w-atom dissoc k)
                        (cb @snaps-atom)))
            target-cnt (count open-conns)
            payload (fressian/encode-wire {:type :peer-chain-state-query
                                           :target-pubkey target-pubkey
                                           :nonce n-str})]
        (swap! w-atom assoc k {:snapshots-atom snaps-atom
                               :done-fn finish!
                               :target-count target-cnt})
        (reset! timer-id (js/setTimeout finish! (long (or timeout-ms 800))))
        (doseq [c open-conns]
          (try
            (api/send! (:node c) payload (or (core-mesh/conn-channel-id c) 0))
            (catch :default _ nil)))))))

(defn- normalize-http-chain-state-snapshot
  [s]
  (when (map? s)
    (let [val-pub (or (:validator-pubkey s) (get s "validator_pubkey") (get s "validator-pubkey") (:validator s) (get s "validator"))
          pk (or (:pubkey s) (get s "pubkey"))
          fin-ep (long (or (:finalized-epoch s) (get s "finalized_epoch") (get s "finalized-epoch") 0))
          bal (long (or (:balance s) (get s "balance") 0))
          spd (long (or (:spendable s) (get s "spendable") bal 0))
          sq (long (or (:seq s) (get s "seq") 0))
          deps (vec (or (:deps s) (get s "deps") []))
          escrows (vec (or (:escrows s) (get s "escrows") []))
          nonce (str (or (:nonce s) (get s "nonce") ""))
          sig (or (:signature s) (get s "signature"))
          snap {:bitecho/type :chain-state-snapshot
                :type :chain-state-snapshot
                :validator-pubkey val-pub
                :validator_pubkey val-pub
                :pubkey pk
                :finalized-epoch fin-ep
                :finalized_epoch fin-ep
                :balance bal
                :spendable spd
                :seq sq
                :deps deps
                :escrows escrows
                :nonce nonce
                :signature sig}]
      (when (relay/verify-chain-state-snapshot-signature snap)
        snap))))

(defn- query-peer-http-local-snapshot!
  [node target-pubkey nonce cb]
  (let [ip (or (:ip4 node) (:ip node) (:host node))
        http-port (or (:http-port node)
                      (when (or (contains? #{:ns1 :ns2 :ns3 "ns1" "ns2" "ns3"} (:node-id node))
                                (contains? #{"35.212.172.159" "35.209.253.119" "35.211.30.106"} ip))
                        80))]
    (if-not (and ip http-port target-pubkey)
      (cb nil)
      (let [settled? (atom false)
            done! (fn [v] (when (compare-and-set! settled? false true) (cb v)))
            path (str "/relay/v1/chain-state?pubkey=" (js/encodeURIComponent (str target-pubkey))
                      "&nonce=" (js/encodeURIComponent (str (or nonce "")))
                      "&local_only=true")
            req (.request node-http
                          #js {:hostname ip
                               :port (long http-port)
                               :path path
                               :method "GET"
                               :timeout 1200}
                          (fn [res]
                            (if (not= 200 (.-statusCode res))
                              (do (.resume res) (done! nil))
                              (let [chunks #js []]
                                (.on res "data" (fn [c] (.push chunks c)))
                                (.on res "end"
                                     (fn []
                                       (try
                                         (let [txt (.toString (.concat js/Buffer chunks) "utf8")
                                               parsed (js->clj (js/JSON.parse txt))
                                               raw-snaps (get parsed "snapshots" [])]
                                           (done! (first (keep normalize-http-chain-state-snapshot raw-snaps))))
                                         (catch :default _ (done! nil)))))
                                (.on res "error" (fn [_] (done! nil)))))))]
        (.on req "timeout" (fn [] (.destroy req) (done! nil)))
        (.on req "error" (fn [_] (done! nil)))
        (.end req)))))

(defn- fetch-validator-chain-state-snapshots!
  [rt target-pubkey nonce opts cb]
  (let [vnode (:validator-node rt)
        local-snap (when (and vnode target-pubkey)
                     (try
                       (let [st @(:state-atom vnode)
                             vid (:identity vnode)]
                         (when (and (map? st) (seq st))
                           (core-mesh/build-validator-chain-state-snapshot st vid target-pubkey nonce)))
                       (catch :default _ nil)))]
    (if (:local-only? opts)
      (cb (if local-snap [local-snap] []))
      (query-peer-validators-chain-state!
       vnode target-pubkey nonce 800
       (fn [mesh-raw-snaps]
         (let [mesh-snaps (vec (keep normalize-http-chain-state-snapshot mesh-raw-snaps))
               base-snaps (cond-> []
                            local-snap (conj local-snap)
                            (seq mesh-snaps) (into mesh-snaps))
               seen-pks (set (keep #(light-core/normalize-pubkey-hex (:validator-pubkey %)) base-snaps))
               val-nodes (get-in (:config vnode) [:cluster :nodes] {})
               infra-nodes (get-in (:config rt) [:cluster :nodes] {})
               all-nodes (merge val-nodes infra-nodes)
               rem-http-nodes (->> (for [[nid ncfg] all-nodes]
                                     (assoc ncfg :node-id nid))
                                   (filter (fn [ncfg]
                                             (let [pk (light-core/normalize-pubkey-hex (:pubkey ncfg))]
                                               (and pk (not (contains? seen-pks pk))))))
                                   vec)]
           (if (or (>= (count seen-pks) 4) (empty? rem-http-nodes))
             (cb base-snaps)
             (let [rem-cnt (atom (count rem-http-nodes))
                   http-acc (atom base-snaps)]
               (doseq [n rem-http-nodes]
                 (query-peer-http-local-snapshot!
                  n target-pubkey nonce
                  (fn [s]
                    (when s
                      (swap! http-acc conj s))
                    (when (zero? (swap! rem-cnt dec))
                      (cb @http-acc)))))))))))))

;; =============================================================================
;; 10. Full Infra-Node Orchestrator (`start-infra-node!`)
;; =============================================================================

(defn- collect-published-telemetry-digests
  "Reads all replicated `telemetry/*/digest.edn` blobs from the local infra subnet instance."
  [inst]
  (let [pointers (get-in inst [:data :pointers] {})
        blobs (get-in inst [:data :blobs :entries] {})]
    (reduce-kv
     (fn [acc [_ path] ptr]
       (if (and (string? path)
                (str/starts-with? path "telemetry/")
                (str/ends-with? path "/digest.edn"))
         (if-let [blob (get blobs (:pointer/target ptr))]
           (let [bs (or (:bytes blob) (:blob/bytes blob))
                 parsed (try
                          (when bs
                            (edn/read-string (fressian/bytes->utf8 bs)))
                          (catch :default _ nil))]
             (if (map? parsed) (conj acc parsed) acc))
           acc)
         acc))
     []
     pointers)))

(defn- start-infra-telemetry-publisher!
  "P-OBS-4 / D38.1 / D39.5 / D39.6: Periodically publishes signed privacy-preserving
   `telemetry/<node-id>/digest.edn` AND rolling `sla/latest.edn` reports from infra nodes
   (`ns1..ns3`) directly into the local subnet instance."
  [node-id rt waiters-atom]
  (start-event-loop-lag-sampler!)
  (let [started-ms (.now js/Date)
        nid (if (keyword? node-id) (name node-id) (str node-id))
        state-dir (:state-dir rt)
        seq-atom (atom 0)
        sla-seq-atom (atom 0)
        ledger-atom (atom (load-telemetry-lifecycle-ledger! state-dir nid started-ms))
        prev-rates-atom (atom nil)
        publish-once!
        (fn []
          (let [auth-pub (:default-sender rt)
                auth-priv (:node-privkey rt)]
            (when (and auth-pub auth-priv)
              (try
                (let [now-ms (.now js/Date)
                      inst @(:subnet-atom rt)
                      sid (or (:subnet-id inst) "bitecho.org/infra")
                      vnode (:validator-node rt)
                      vst (when-let [sa (:state-atom vnode)] @sa)
                      v-peer-conns (when-let [pc (:peer-conns vnode)] @pc)
                      conn-diag (when v-peer-conns
                                  (core-mesh/mesh-conn-diagnostics-summary v-peer-conns nil))
                      mem (.memoryUsage js/process)
                      heap-used (.-heapUsed mem)
                      heap-slope (record-heap-sample! now-ms heap-used)
                      rtm @runtime-metrics-atom
                      lag-samples (:loop-lag-samples rtm)
                      lag-p99 (obs/p99-ms lag-samples)
                      lag-max (if (seq lag-samples) (double (apply max lag-samples)) 0.0)
                      head-ep (long (or (:epoch vst) (:epoch inst) 0))
                      fin-ep (long (or (:last-executed-finalized-epoch vst) (:epoch inst) 0))
                      rt-shell (when-let [sa (:shell-atom rt)] @sa)
                      active-waiters (if waiters-atom
                                       (reduce-kv (fn [acc _ s] (+ acc (count s))) 0 @waiters-atom)
                                       0)
                      failed-now (long (or (:failed-receipts-count vst) 0))
                      verr-now (long @validator-event-error-count)
                      http-5xx-now (long (or (:http-5xx-count rtm) 0))
                      prev-r @prev-rates-atom
                      failed-delta (if prev-r (max 0 (- failed-now (:failed prev-r))) 0)
                      verr-delta (if prev-r (max 0 (- verr-now (:verr prev-r))) 0)
                      http-5xx-delta (if prev-r (max 0 (- http-5xx-now (:http-5xx prev-r))) 0)
                      _ (reset! prev-rates-atom {:failed failed-now :verr verr-now :http-5xx http-5xx-now})
                      ledger (swap! ledger-atom obs/record-stall-sample
                                    {:node-id nid
                                     :now-ms now-ms
                                     :head-epoch head-ep
                                     :finalized-epoch fin-ep})
                      _ (persist-telemetry-lifecycle-async! state-dir nid ledger)
                      pub (obs/prepare-telemetry-publication
                           {:node-id nid
                            :version full-node-version
                            :bundle-sha256 (running-bundle-sha256)
                            :uptime-ms (max 0 (- now-ms started-ms))
                            :restart-count (:restart-count ledger)
                            :restart-causes (:restart-causes ledger)
                            :downtime-events (obs/effective-downtime-events ledger now-ms)
                            :head-epoch head-ep
                            :finalized-epoch fin-ep
                            :runtime-summary {:rss-bytes (.-rss mem)
                                              :heap-used-bytes heap-used
                                              :heap-total-bytes (.-heapTotal mem)
                                              :heap-slope-bytes-per-min (Math/round heap-slope)
                                              :v8-heap-headroom-pct (sample-v8-heap-headroom-pct)
                                              :event-loop-lag-p99-ms lag-p99
                                              :event-loop-lag-max-ms lag-max
                                              :last-snapshot-encode-ms (long (or (:last-snapshot-encode-ms rtm) 0))
                                              :runtime "nodejs"}
                            :service-counters {:pointer-count (count (get-in inst [:data :pointers] {}))
                                               :poll-count (long (or (:poll-count @poll-telemetry-atom) 0))
                                               :active-waiters active-waiters
                                               :http-5xx-last-60s http-5xx-delta
                                               :validator-event-errors verr-now
                                               :validator-event-errors-last-60s verr-delta
                                               :failed-receipts failed-now
                                               :failed-receipts-last-60s failed-delta}
                            :defense-counters {:conn-dropped (long (or (:dropped conn-diag) (:dropped rt-shell) 0))
                                               :conn-stale (long (or (:ignored-stale conn-diag) (:ignored-stale rt-shell) 0))}})
                      existing (get-in inst [:data :pointers [(str sid) (:path pub)]])
                      prev-on-chain (long (or (:pointer/seq existing) 0))
                      next-seq (swap! seq-atom (fn [prev] (max (inc (long prev)) (inc prev-on-chain) (quot now-ms 1000))))
                      blob (data/make-blob (:edn-bytes pub) "application/edn")
                      ptr (data/sign-pointer auth-priv
                                             {:pointer/authority auth-pub
                                              :pointer/subnet (str sid)
                                              :pointer/path (:path pub)
                                              :pointer/seq next-seq
                                              :pointer/target (:blob/cid blob)
                                              :pointer/proof {:proof/type :self}})]
                  (submit-subnet-event! rt {:type :put-blob :blob blob :sender auth-pub :now-ms now-ms})
                  (let [res (submit-subnet-event! rt {:type :publish-pointer :pointer ptr :sender auth-pub :now-ms now-ms})]
                    (when-not (:applied? res)
                      (apply-shell-event! (:shell-atom rt)
                                          {:type :diagnose
                                           :reason :telemetry-digest-publish-rejected
                                           :error (:error res)
                                           :path (:path pub)})))
                  ;; Publish rolling 24h six-nines SLA rollup (`sla/latest.edn`)
                  (let [fresh-inst @(:subnet-atom rt)
                        digests (collect-published-telemetry-digests fresh-inst)]
                    (when (seq digests)
                      (let [sla-pub (obs/prepare-sla-publication digests {:window-ms 86400000 :now-ms now-ms})
                            sla-existing (get-in fresh-inst [:data :pointers [(str sid) (:path sla-pub)]])
                            prev-sla-seq (long (or (:pointer/seq sla-existing) 0))
                            next-sla-seq (swap! sla-seq-atom (fn [prev] (max (inc (long prev)) (inc prev-sla-seq) (quot now-ms 1000))))
                            sla-blob (data/make-blob (:edn-bytes sla-pub) "application/edn")
                            sla-ptr (data/sign-pointer auth-priv
                                                       {:pointer/authority auth-pub
                                                        :pointer/subnet (str sid)
                                                        :pointer/path (:path sla-pub)
                                                        :pointer/seq next-sla-seq
                                                        :pointer/target (:blob/cid sla-blob)
                                                        :pointer/proof {:proof/type :self}})]
                        (submit-subnet-event! rt {:type :put-blob :blob sla-blob :sender auth-pub :now-ms now-ms})
                        (let [sla-res (submit-subnet-event! rt {:type :publish-pointer :pointer sla-ptr :sender auth-pub :now-ms now-ms})]
                          (when-not (:applied? sla-res)
                            (apply-shell-event! (:shell-atom rt)
                                                {:type :diagnose
                                                 :reason :sla-report-publish-rejected
                                                 :error (:error sla-res)
                                                 :path (:path sla-pub)})))))))
                (catch :default e
                  (apply-shell-event! (:shell-atom rt)
                                      {:type :diagnose
                                       :reason :telemetry-digest-build-failed
                                       :detail (.-message e)}))))))
        t0 (js/setTimeout publish-once! 10000)
        iv (js/setInterval publish-once! 60000)]
    (fn []
      (js/clearTimeout t0)
      (js/clearInterval iv)
      (persist-telemetry-shutdown-marker! state-dir nid ledger-atom))))

(defn- start-peer-heartbeat-loop!
  [config rt]
  (when (get-in config [:cluster :enabled?] false)
    (let [peers (vec (eligible-http-peers config))
          hb-ms (long (get-in config [:cluster :heartbeat-interval-ms] 5000))]
      (when (seq peers)
        (js/setInterval
         (fn []
           (let [now-ms (.now js/Date)]
             (submit-subnet-event! rt {:type :leader-tick :now-ms now-ms})
             (doseq [peer peers]
               (try
                 (let [req (.request node-http
                                     #js {:hostname (:ip peer)
                                          :port (:port peer)
                                          :path "/healthz"
                                          :method "GET"
                                          :timeout 1500}
                                     (fn [res]
                                       (.resume res)
                                       (when (= 200 (.-statusCode res))
                                         (let [le (get @(:subnet-atom rt) :leader-election)]
                                           (submit-subnet-event! rt {:type :leader-heartbeat
                                                                     :from (:node-id peer)
                                                                     :term (long (or (:term le) 1))
                                                                     :leader-id (or (:leader-id le) (:node-id peer))
                                                                     :now-ms (.now js/Date)
                                                                     :from-peer? true})))))]
                   (.on req "error" (fn [e]
                                      (apply-shell-event! (:shell-atom rt)
                                                          {:type :diagnose :reason :peer-heartbeat-probe-failed :peer (:node-id peer) :detail (.-message e)})))
                   (.on req "timeout" (fn [] (.destroy req)))
                   (.end req))
                 (catch :default _ nil)))))
         hb-ms)))))

(defn start-infra-node!
  "Starts the complete Node.js infra-node stack (`runtime`, `dns`, `http`, `https`+`CONNECT`, `smtp`, `diag`, `heartbeat`)."
  [config]
  (let [state-dir (or (:state-dir config) ".bitecho-node-infra")
        _ (when-not (.existsSync node-fs state-dir)
            (.mkdirSync node-fs state-dir #js {:recursive true}))
        node-id (let [nid (or (:node/id config) (:node-id config) :ns3)]
                  (if (keyword? nid) nid (keyword (str nid))))
        rt-shell-atom (atom (core-infra/init-shell-state :subnet-runtime))
        _ (apply-shell-event! rt-shell-atom {:type :start})
        rt-gen (:generation @rt-shell-atom)
        ident (load-or-create-node-identity! state-dir node-id rt-shell-atom)
        pk (:pubkey-hex ident)
        sk (:privkey-bytes ident)
        cluster-nodes (get-in config [:cluster :nodes] {})
        all-nodes (if (seq cluster-nodes) (set (keys cluster-nodes)) #{node-id})
        trust-anchors (into #{pk} (keep :pubkey (vals cluster-nodes)))
        default-pol (core-infra/default-infra-policy {:trust-anchors trust-anchors
                                                      :cold-pubkey (:cold-pubkey config)
                                                      :threshold (max 1 (min 2 (count trust-anchors)))})
        init-res (subnet/init-subnet-instance
                  default-pol
                  {:node-id node-id
                   :all-nodes all-nodes
                   :max-hot-bytes (or (get-in config [:http :max-hot-bytes])
                                      (* 16 1024 1024))
                   :max-hot-blob-bytes (or (get-in config [:http :max-hot-blob-bytes])
                                           data/default-infra-max-hot-blob-bytes)
                   :max-pinned-app-bytes (or (get-in config [:http :max-pinned-app-bytes])
                                             data/default-pinned-app-max-bytes)})
        snap (load-pointers-snapshot state-dir rt-shell-atom)
        inst0 (if (and snap (= (:subnet-id (:instance init-res)) (:subnet-id snap)))
                (reduce (fn [acc [k ptr]]
                          (-> acc
                              (assoc-in [:data :pointers k] ptr)
                              (update-in [:data :blobs] #(if (:pointer/target ptr)
                                                           (data/pin-blob % (:pointer/target ptr))
                                                           %))))
                        (cond-> (:instance init-res)
                          (:policy snap) (assoc :policy (core-infra/merge-upgraded-policy default-pol (:policy snap))))
                        (:pointers snap))
                (:instance init-res))
        tls-secret (resolve-tls-secret config)
        tls-ctx-atom (atom nil)
        tls-pem-atom (atom nil)
        raw-val-cfg (or (:validator config) (when (:enable-validator? config) {}))
        has-embedded-val? (and (map? raw-val-cfg)
                               (or (seq (:cluster raw-val-cfg))
                                   (seq (:genesis-ledger raw-val-cfg))
                                   (seq (:validators raw-val-cfg))
                                   (:enable-validator? config)))
        rt-atom (atom nil)
        rt {:config config
            :node-id node-id
            :state-dir state-dir
            :shell-atom rt-shell-atom
            :subnet-atom (atom inst0)
            :app-release-atom (atom (app-release/init-release-state
                                     {:genesis-anchor-cid (or (:genesis-anchor-cid config)
                                                              (get-in inst0 [:policy :subnet/genesis-policy-cid]))
                                      :trusted-signers (or (:release-signers config)
                                                           (get-in inst0 [:policy :subnet/gate :gate/trust-anchors]))
                                      :threshold (or (:release-threshold config) 2)
                                      :max-bytes (:app-release-max-bytes config)}))
            :epoch-atom (atom 1)
            :default-sender pk
            :node-privkey sk
            :tls-secret tls-secret
            :tls-ctx-atom tls-ctx-atom
            :tls-pem-atom tls-pem-atom}
        _ (reset! rt-atom rt)
        _ (when-let [{:keys [cert-pem key-pem]} (load-tls-cert-key-from-disk-or-subnet! rt)]
            (try
              (reset! tls-ctx-atom (.createSecureContext node-tls #js {:cert cert-pem :key key-pem}))
              (reset! tls-pem-atom {:cert-pem cert-pem :key-pem key-pem})
              (catch :default e
                (apply-shell-event! rt-shell-atom {:type :diagnose :reason :tls-init-failed :detail (.-message e)}))))
        _ (apply-shell-event! rt-shell-atom {:type :started :generation rt-gen :resources {:state-dir state-dir}})
        relay-atom (atom (relay/init-relay-state (get-in config [:http :relay])))
        waiters-atom (atom {})
        faucet-atom (atom (faucet/init-faucet-state (or (:faucet config) {})))
        limiter-atom (atom (dns-proto/init-limiter {:capacity 100.0
                                                    :refill-per-sec 20.0
                                                    :monthly-egress-limit-bytes (get-in config [:http :monthly-egress-limit-bytes] 900000000)}))
        http-shell-atom (atom (core-infra/init-shell-state :http-shell))
        _ (apply-shell-event! http-shell-atom {:type :start})
        http-gen (:generation @http-shell-atom)
        dns-handle-atom (atom nil)
        smtp-handle-atom (atom nil)
        ports-atom (atom {:http-port 0 :https-port 0 :dns-udp-port 0 :smtp-port 0 :diag-port 0})
        pending-atom (atom 0)
        stop-fns (atom [])
        maybe-emit-ready! (fn []
                            (when (zero? (swap! pending-atom dec))
                              (let [ps @ports-atom]
                                (println (js/JSON.stringify
                                          (clj->js {:event "infra-node-ready"
                                                    :ok true
                                                    :runtime "nodejs"
                                                    :version full-node-version
                                                    :node_id (name node-id)
                                                    :http_port (:http-port ps)
                                                    :https_port (:https-port ps)
                                                    :dns_udp_port (:dns-udp-port ps)
                                                    :smtp_port (:smtp-port ps)
                                                    :diag_port (:diag-port ps)
                                                    :tls_loaded (some? @tls-ctx-atom)}))))))
        http-enabled? (get-in config [:http :enabled?] true)
        https-enabled? (and http-enabled? (some? @tls-ctx-atom))
        dns-enabled? (get-in config [:dns :enabled?] false)
        smtp-enabled? (get-in config [:smtp :enabled?] false)
        diag-enabled? (boolean (get-in config [:validator :http :enabled?] false))
        bind-ip (get-in config [:http :bind-ip] "0.0.0.0")
        http-port (long (get-in config [:http :http-port] 80))
        https-port (long (get-in config [:http :https-port] 443))
        total-listeners (+ (if http-enabled? 1 0)
                           (if https-enabled? 1 0)
                           (if dns-enabled? 1 0)
                           (if smtp-enabled? 1 0)
                           (if diag-enabled? 1 0))]
    (reset! pending-atom (max 1 total-listeners))
    ;; Co-located Validator Mesh Engine (when :validator is configured) + bi-directional Relay<->Validator bridge
    (when has-embedded-val?
      (let [val-cfg (assoc raw-val-cfg
                           :node/id (or (:node/id raw-val-cfg) (:node-id raw-val-cfg) node-id)
                           :node-id (or (:node-id raw-val-cfg) (:node/id raw-val-cfg) node-id)
                           :state-dir (or (:state-dir raw-val-cfg) state-dir)
                           :http (merge {:enabled? diag-enabled? :host "127.0.0.1" :port 8080}
                                        (:http raw-val-cfg)))
            vnode (start-validator-mesh-node!
                   val-cfg
                   {:identity ident
                    :embedded? true
                    :on-ready (fn [{:keys [http-port]}]
                                (when diag-enabled?
                                  (swap! ports-atom assoc :diag-port (or http-port 0))
                                  (maybe-emit-ready!)))})
            on-bridge-msg (fn [payload]
                            (try
                              (let [now-ms (.now js/Date)
                                    cur-rt @rt-atom]
                                (maybe-ingest-artifact-envelope! cur-rt payload now-ms)
                                (let [res-box (atom nil)
                                      _ (swap! relay-atom
                                               (fn [st]
                                                 (let [r (relay/reduce-relay st {:type :relay-submit
                                                                                 :envelope payload
                                                                                 :from-validator? true
                                                                                 :now-ms now-ms})]
                                                   (reset! res-box r)
                                                   (:state r))))
                                      res @res-box]
                                  (when (:ok? res)
                                    (let [recip (or (get-in res [:response "recipient"])
                                                    (get-in res [:response "pubkey"]))
                                          broadcast? (boolean (get-in res [:response "broadcast"]))]
                                      (when (and recip (not broadcast?))
                                        (try
                                          (let [payload-bytes (if (fressian/bytes? payload) payload (fressian/encode-wire payload))
                                                wire-hex (basalt/bytes->hex payload-bytes)
                                                body-buf (.from js/Buffer (js/JSON.stringify #js {:envelope_hex wire-hex}) "utf8")]
                                            (replicate-relay-to-peers! cur-rt "/relay/v1/send" body-buf))
                                          (catch :default _ nil)))
                                      (when (or recip broadcast?)
                                        (wake-relay-waiters! waiters-atom recip broadcast?))))))
                              (catch :default _ nil)))
            bridge-key (keyword (str "colocated-bridge-" (name node-id)))]
        (when-let [acs (:agent-conns vnode)]
          (swap! acs assoc bridge-key {:channel-id 0
                                       :phase :open
                                       :ok? true
                                       :on-message on-bridge-msg
                                       :node nil
                                       :generation 1
                                       :sent-msg-ids #{}
                                       :sent-msg-order []}))
        (swap! rt-atom assoc :validator-node vnode)
        (swap! stop-fns conj (:stop! vnode))))
    (let [rt @rt-atom]
      ;; Heartbeat loop
      (when-let [hb-timer (start-peer-heartbeat-loop! config rt)]
        (swap! stop-fns conj #(js/clearInterval hb-timer)))

      ;; P-OBS-4 / D38.1 / D39.5: 60s signed observability digest & rolling SLA publisher
      (when-not (false? (:publish-telemetry? config))
        (swap! stop-fns conj (start-infra-telemetry-publisher! node-id rt waiters-atom)))

      ;; P-UPD-1 / D40.1: Optional pointer-driven self-update loop for infra nodes
      (when (:auto-update-pointer config)
        (when-let [stop-upd (start-full-node-auto-updater!
                             node-id config
                             #(doseq [f @stop-fns] (try (f) (catch :default _ nil))))]
          (swap! stop-fns conj stop-upd)))

      ;; 1. DNS (:53)
      (when dns-enabled?
        (start-dns-server! config rt
                           (fn [h]
                             (reset! dns-handle-atom h)
                             (swap! ports-atom assoc :dns-udp-port (:udp-port h))
                             (swap! stop-fns conj (:stop-fn h))
                             (maybe-emit-ready!))))

      ;; 2. SMTP (:25)
      (when smtp-enabled?
        (start-smtp-server! config rt
                            (fn [h]
                              (reset! smtp-handle-atom h)
                              (swap! ports-atom assoc :smtp-port (:port h))
                              (swap! stop-fns conj (:stop-fn h))
                              (maybe-emit-ready!))))

      ;; 3. HTTPS (:443) internal TLS server + Port 443 Passthrough Multiplexer
      (when https-enabled?
        (let [https-srv (.createServer
                         node-https
                         #js {:SNICallback (fn [_servername cb] (cb nil @tls-ctx-atom))
                              :cert (:cert-pem @tls-pem-atom)
                              :key (:key-pem @tls-pem-atom)
                              :requestCert true
                              :rejectUnauthorized false}
                         (fn [req res]
                           (handle-web-or-api-request!
                            req res
                            {:config config :rt rt :relay-atom relay-atom :waiters-atom waiters-atom
                             :faucet-atom faucet-atom
                             :limiter-atom limiter-atom :http-shell-atom http-shell-atom
                             :dns-shell-atom (:shell-atom @dns-handle-atom)
                             :smtp-shell-atom (:shell-atom @smtp-handle-atom)
                             :https? true :bound-https-port (:https-port @ports-atom)})))]
          (.listen https-srv 0 "127.0.0.1"
                   (fn []
                     (let [internal-port (.-port (.address https-srv))
                           front-srv (.createServer
                                      node-net
                                      (fn [sock]
                                        (handle-passthrough-socket!
                                         sock
                                         {:domain (or (:domain config) "bitecho.org")
                                          :internal-https-port internal-port
                                          :ingress-target (get-in config [:http :ingress-target])
                                          :connect-targets (get-in config [:http :connect-targets])
                                          :connect-routes (get-in config [:http :connect-routes])
                                          :peek-timeout-ms (get-in config [:http :peek-timeout-ms] 2000)
                                          :shell-atom http-shell-atom})))]
                       (.listen front-srv https-port bind-ip
                                (fn []
                                  (let [bp (.-port (.address front-srv))]
                                    (swap! ports-atom assoc :https-port bp)
                                    (swap! stop-fns conj #(do (.close front-srv) (.close https-srv)))
                                    (maybe-emit-ready!)))))))))

      ;; 4. HTTP (:80)
      (when http-enabled?
        (let [http-srv (.createServer
                        node-http
                        (fn [req res]
                          (handle-web-or-api-request!
                           req res
                           {:config config :rt rt :relay-atom relay-atom :waiters-atom waiters-atom
                            :faucet-atom faucet-atom
                            :limiter-atom limiter-atom :http-shell-atom http-shell-atom
                            :dns-shell-atom (:shell-atom @dns-handle-atom)
                            :smtp-shell-atom (:shell-atom @smtp-handle-atom)
                            :https? false :bound-https-port (:https-port @ports-atom)})))]
          (.listen http-srv http-port bind-ip
                   (fn []
                     (let [bp (.-port (.address http-srv))]
                       (swap! ports-atom assoc :http-port bp)
                       (apply-shell-event! http-shell-atom {:type :started :generation http-gen :resources {:http http-srv}})
                       (swap! stop-fns conj #(.close http-srv))
                       (maybe-emit-ready!))))))

      ;; 5. Localhost Diagnostics HTTP (`127.0.0.1:8080`) when no embedded validator is present
      (when (and diag-enabled? (not has-embedded-val?))
        (let [d-host (get-in config [:validator :http :host] "127.0.0.1")
              d-port (long (get-in config [:validator :http :port] 8080))
              d-srv (.createServer
                     node-http
                     (fn [req res]
                       (let [u (or (.-url req) "/")]
                         (cond
                           (str/starts-with? u "/healthz")
                           (send-json! res 200 {:ok true :runtime "nodejs" :version full-node-version :node_id (name node-id)})

                           (str/starts-with? u "/statusz")
                           (send-json! res 200 (build-statusz-payload rt limiter-atom http-shell-atom
                                                                      (:shell-atom @dns-handle-atom)
                                                                      (:shell-atom @smtp-handle-atom)))

                           :else
                           (send-json! res 404 {:ok false :error "not-found" :path u})))))]
          (.listen d-srv d-port d-host
                   (fn []
                     (swap! ports-atom assoc :diag-port (.-port (.address d-srv)))
                     (swap! stop-fns conj #(.close d-srv))
                     (maybe-emit-ready!)))))

      (when (zero? total-listeners)
        (maybe-emit-ready!))

      ;; Graceful shutdown on SIGTERM / SIGINT
      (let [shutdown! (fn []
                        (doseq [f @stop-fns]
                          (try (f) (catch :default _ nil)))
                        (.exit js/process 0))]
        (.on js/process "SIGTERM" shutdown!)
        (.on js/process "SIGINT" shutdown!)))))

;; =============================================================================
;; 10. Deterministic `--self-test` & CLI Entry Point
;; =============================================================================

(defn run-self-test
  "Executes an end-to-end deterministic self-test on Node.js proving:
   1. `bitecho.state-machine` initializes, stages a `deploy/core` config pointer, and activates it at an epoch boundary.
   2. `bitecho.fressian` encodes and decodes `subnet-pointers.fressian` identically to JVM infra nodes.
   3. `bitecho.core.subnet`, `bitecho.core.protocol.{dns,smtp,relay}`, and `bitecho.core.infra` execute cleanly on Node.js.
   4. `bitecho.economy.spend-dac` issues and validates a holder-signed spend-DAC debit.
   5. `bitecho.deploy.core` verifies hash-chained `P-DEPLOY-5` audit records."
  []
  (let [auth-kp (crypto/generate-keypair "node-full-self-test-auth")
        holder-kp (crypto/generate-keypair "node-full-self-test-holder")
        auth-pk (kp->pk-hex auth-kp)
        auth-sk (kp->sk auth-kp)
        holder-pk (kp->pk-hex holder-kp)
        holder-sk (kp->sk holder-kp)
        sm0 (-> (sm/init-state [] auth-pk (config/devnet-6-config))
                (assoc :epoch 10 :trusted-deploy-authorities #{auth-pk}))
        ptr (deploy/sign-config-pointer
             auth-sk
             {:network "devnet"
              :seq 1
              :activate-at-epoch 11
              :code-target-cid (deploy/sha256-hex "dist/bitecho-full-node.cjs")
              :domains {:economy {:min-signaling-burn 125}}
              :policy-theta (assoc deploy/ratified-theta-star :min-signaling-burn 125)
              :author-pubkey auth-pk})
        staged (:state (deploy/stage-config-pointer sm0 ptr))
        ticked (:state (sm/handle-event staged {:type :tick :rng (crypto/make-random 42)}))
        audit-check (deploy/reconstruct-cluster-history-from-audit-trail (:audit-trail ticked) 11)
        policy (core-infra/default-infra-policy {:trust-anchors #{auth-pk} :threshold 1})
        sub-init (subnet/init-subnet-instance
                  policy
                  {:node-id :ns3
                   :all-nodes #{:ns1 :ns2 :ns3}
                   :max-hot-bytes data/default-infra-max-hot-bytes
                   :max-pinned-app-bytes data/default-pinned-app-max-bytes})
        blob (data/make-blob (pr-str ptr) "application/edn")
        c-ptr (data/sign-pointer auth-sk {:pointer/authority auth-pk
                                          :pointer/subnet "bitecho.org/infra"
                                          :pointer/path "config/devnet/active.edn"
                                          :pointer/seq 1
                                          :pointer/target (:blob/cid blob)
                                          :pointer/proof {:proof/type :self}})
        sub1 (:state (subnet/reduce-subnet (:instance sub-init) {:type :put-blob :sender auth-pk :blob blob :now-ms 1000}))
        sub2 (:state (subnet/reduce-subnet sub1 {:type :publish-pointer :sender auth-pk :pointer c-ptr :now-ms 1000}))
        snap-bytes (fressian/encode-canonical {:subnet-id (:subnet-id sub2)
                                               :pointers (get-in sub2 [:data :pointers])})
        snap-decoded (fressian/decode-wire snap-bytes)
        dac (spend-dac/issue-spend-dac auth-pk auth-sk {:dac-id "node-dac-1" :holder holder-pk :cap 1000000 :issued-epoch 10 :expiry-epoch 1000})
        intent (spend-dac/sign-spend-dac-intent holder-sk {:spend-dac-id "node-dac-1" :holder holder-pk :op :transfer :amount 50000 :burn-fee 100 :epoch 11 :nonce "n1"})
        spend-res (spend-dac/validate-and-apply-spend-dac-debit
                   {:epoch 11
                    :ledger {auth-pk (account/map->AccountState {:balance 25000000 :seq 0 :deps []})}
                    :spend-dacs {"node-dac-1" dac}}
                   intent)
        dns-pkt (dns-proto/decode-packet (dns-proto/encode-packet {:id 1 :qr? false :opcode 0 :rd? false
                                                                   :questions [{:qname "bitecho.org" :qtype :A :qclass :IN}]}))
        smtp-s (smtp-proto/greeting (smtp-proto/init-session {:domain "bitecho.org" :allowed-recipients #{"@bitecho.org"}}))
        relay-st (relay/init-relay-state)
        gov-st (gov/init-governance-state)
        sym-key (storage/derive-storage-key auth-sk "infra-test")
        host-manifest (host/build-system-merkle-manifest
                       {:arch "amd64"
                        :stage3-cid (deploy/sha256-hex "stage3-amd64-hardened-openrc")
                        :profile-cid (deploy/sha256-hex "default/linux/amd64/23.0/no-multilib/hardened")
                        :os-packages [{:atom "sys-apps/openrc" :version "0.55.1" :cid (deploy/sha256-hex "openrc-0.55.1")}]
                        :runtimes [{:name "nodejs" :version (.-version js/process) :cid (deploy/sha256-hex (.-version js/process))}]
                        :app-artifacts [{:artifact "bitecho-full-node.cjs" :version full-node-version :cid (deploy/sha256-hex full-node-version)}]})
        host-proof (host/generate-layer-proof host-manifest :os-subtree)
        host-proof-ok? (true? (:valid? (host/verify-layer-proof host-proof (:system-merkle-root host-manifest))))
        ok? (and (= 11 (:epoch ticked))
                 (= 125 (get-in ticked [:config :min-signaling-burn]))
                 (true? (:chain-valid? audit-check))
                 (= (:blob/cid blob)
                    (get-in snap-decoded [:pointers ["bitecho.org/infra" "config/devnet/active.edn"] :pointer/target]))
                 (true? (:ok? spend-res))
                 (= 50100 (:spent spend-res))
                 (= 1 (:id dns-pkt))
                 (some #(str/starts-with? % "220") (:responses smtp-s))
                 (map? relay-st)
                 (map? gov-st)
                 (= 32 (fressian/count-bytes sym-key))
                 (true? (light-core/valid-pubkey-hex? auth-pk))
                 host-proof-ok?
                 (some? acme-proto/base64url-encode))]
    {:ok ok?
     :runtime "nodejs"
     :node_version (.-version js/process)
     :version full-node-version
     :epoch (:epoch ticked)
     :active_config_hash (:active-config-hash ticked)
     :system_merkle_root (:system-merkle-root host-manifest)
     :audit_records (count (:audit-trail ticked))
     :fressian_roundtrip_ok (= "bitecho.org/infra" (:subnet-id snap-decoded))
     :spend_dac_ok (true? (:ok? spend-res))}))

(defn- read-config-file-or-exit!
  [config-file]
  (when-not (and config-file (.existsSync node-fs config-file))
    (.write (.-stderr js/process) (str "Error: config file not found: " config-file "\n"))
    (.exit js/process 1))
  (try
    (edn/read-string (.readFileSync node-fs config-file "utf8"))
    (catch :default e
      (.write (.-stderr js/process) (str "Error: failed to parse EDN in " config-file ": " (.-message e) "\n"))
      (.exit js/process 1))))

(defn- cmd-run!
  [config-file]
  (let [cfg (read-config-file-or-exit! config-file)
        node (start-validator-mesh-node!
              cfg
              {:on-ready (fn [{:keys [http-port]}]
                           (let [node-id (or (:node/id cfg) (:node-id cfg) :node1)
                                 state-dir (or (:state-dir cfg) "data")
                                 ident (load-or-create-node-identity! state-dir node-id)
                                 pubkey (:pubkey-hex ident)
                                 fp (:fingerprint ident)]
                             (println (str "Bitecho node started: id=" (name node-id)
                                           " pubkey=" pubkey
                                           " fingerprint=" fp
                                           " http=:" (or http-port (get-in cfg [:http :port] 8080))))))})
        shutdown! (fn []
                    (println "Shutting down Bitecho node...")
                    (try ((:stop! node)) (catch :default _ nil))
                    (.exit js/process 0))]
    (.on js/process "SIGTERM" shutdown!)
    (.on js/process "SIGINT" shutdown!)))

(defn- cmd-print-identity!
  [config-file]
  (let [cfg (read-config-file-or-exit! config-file)
        node-id (or (:node/id cfg) (:node-id cfg) :node-1)
        state-dir (or (:state-dir cfg) "data")
        id-data (load-or-create-node-identity! state-dir node-id)]
    (println (str "Node: " (name node-id)))
    (println (str "State directory: " state-dir))
    (println (str "Ed25519 Pubkey: " (:pubkey-hex id-data)))
    (println (str "SHA-256 Fingerprint: " (:fingerprint id-data)))
    (println (str "ICE ufrag: " (get-in id-data [:ice-creds :ufrag])))
    (println (str "ICE pwd: " (get-in id-data [:ice-creds :pwd])))))

(defn- cmd-validate-config!
  [config-file]
  (let [cfg (read-config-file-or-exit! config-file)
        res (core-mesh/validate-node-config cfg)]
    (if (:valid? res)
      (do
        (println (str "Config valid: " config-file))
        (.exit js/process 0))
      (do
        (.write (.-stderr js/process) (str "Config invalid: " (:error res) "\n"))
        (.exit js/process 1)))))

(defn- cmd-gen-keypair!
  [output-file]
  (let [kp (crypto/generate-keypair)
        pub-hex (str/lower-case (kp->pk-hex kp))
        priv-hex (str/lower-case (basalt/bytes->hex (kp->sk kp)))
        kp-map {:pubkey-hex pub-hex :privkey-hex priv-hex}]
    (if output-file
      (do
        (atomic-write-file! output-file (pr-str kp-map) 0600)
        (println (str "Wrote keypair to " output-file))
        (println (str "Ed25519 Pubkey: " pub-hex)))
      (do
        (println (str "Ed25519 Pubkey: " pub-hex))
        (println "Pass an output file path (e.g. bitecho gen-keypair <path>) to persist private key securely with 0600 permissions.")))))

(defn- parse-infra-cli-config
  [argv]
  (let [second-arg (second argv)
        base-cfg (if (and second-arg (not (str/starts-with? second-arg "--")) (.existsSync node-fs second-arg))
                   (edn/read-string (.readFileSync node-fs second-arg "utf8"))
                   {:http {:enabled? true :bind-ip "127.0.0.1" :http-port 18080 :redirect-http-to-https? false}})
        flag-val (fn [flag]
                   (let [idx (.indexOf argv flag)]
                     (when (and (>= idx 0) (< (inc idx) (count argv)))
                       (nth argv (inc idx)))))
        node-id (flag-val "--node-id")
        state-dir (flag-val "--state-dir")
        http-port (flag-val "--http-port")
        https-port (flag-val "--https-port")
        dns-port (flag-val "--dns-port")
        smtp-port (flag-val "--smtp-port")]
    (cond-> base-cfg
      node-id (assoc :node/id (keyword node-id))
      state-dir (assoc :state-dir state-dir)
      http-port (assoc-in [:http :http-port] (js/parseInt http-port 10))
      https-port (assoc-in [:http :https-port] (js/parseInt https-port 10))
      dns-port (assoc-in [:dns :port] (js/parseInt dns-port 10))
      smtp-port (assoc-in [:smtp :port] (js/parseInt smtp-port 10)))))

(defn- cmd-check-pointer!
  "Verifies a signed `config/<network>/active.edn` pointer file (and optional `:host-target` schema)
   per BIP-011 `P-HOST-2` / `P-HOST-6`."
  [pointer-file]
  (let [ptr (read-config-file-or-exit! pointer-file)
        v (deploy/verify-config-pointer {:active-config-seq 0} ptr)
        ht (:host-target ptr)
        ht-v (if ht (host/validate-host-target ht) {:ok? true :errors []})
        ok? (and (:ok? v) (:ok? ht-v))]
    (println (js/JSON.stringify
              (clj->js {:ok ok?
                        :version full-node-version
                        :pointer_seq (:seq ptr)
                        :code_target_cid (:code-target-cid ptr)
                        :host_target_valid (:ok? ht-v)
                        :system_merkle_root (or (:system-merkle-root ptr) (:system-merkle-root ht))
                        :error (or (:error v) (first (:errors ht-v)))})))
    (when-not ok?
      (.exit js/process 1))))

(defn- cmd-attest-root!
  "Recomputes the P-HOST-5 3-subtree system Merkle root from a manifest EDN file (or emits a
   local runtime attestation manifest when no path is provided).
   F-SADV1-1 (BIP-013): fails closed with `invalid-manifest-missing-layers` (exit 1) when
   `:layers` is missing/non-map or any of `:os-subtree`/`:runtime-subtree`/`:app-subtree` is empty."
  [manifest-file]
  (let [manifest (if (and manifest-file (.existsSync node-fs manifest-file))
                   (try
                     (edn/read-string (.readFileSync node-fs manifest-file "utf8"))
                     (catch :default _ nil))
                   (host/build-system-merkle-manifest
                    {:arch (case (.-arch js/process)
                             "x64" "amd64"
                             "arm64" "arm64"
                             (str (.-arch js/process)))
                     :os-packages [{:atom "sys-apps/openrc" :version "openrc" :cid (deploy/sha256-hex "openrc")}]
                     :runtimes [{:name "nodejs" :version (.-version js/process) :cid (deploy/sha256-hex (.-version js/process))}]
                     :app-artifacts [{:artifact "bitecho-full-node.cjs" :version full-node-version :cid (deploy/sha256-hex full-node-version)}]}))
        validation (host/validate-attestation-manifest manifest)]
    (if-not (:ok? validation)
      (do
        (println (js/JSON.stringify
                  (clj->js {:ok false
                            :version full-node-version
                            :error (:error validation)
                            :missing_layers (mapv name (:missing-layers validation))})))
        (.exit js/process 1))
      (let [recomputed (host/compute-system-merkle-root manifest)]
        (println (js/JSON.stringify
                  (clj->js {:ok true
                            :version full-node-version
                            :arch (:arch manifest)
                            :system_merkle_root (:system-merkle-root recomputed)
                            :subtree_roots (:subtree-roots recomputed)})))))))

(defn -main
  "CLI entry point for the Node.js full validator & infrastructure node."
  [& args]
  (let [argv (vec args)
        first-arg (first argv)]
    (cond
      (some #{"--self-test"} argv)
      (let [res (run-self-test)]
        (println (js/JSON.stringify (clj->js res)))
        (when-not (:ok res)
          (.exit js/process 1)))

      (some #{"--check-pointer"} argv)
      (let [idx (.indexOf argv "--check-pointer")
            ptr-file (when (< (inc idx) (count argv)) (nth argv (inc idx)))]
        (cmd-check-pointer! ptr-file))

      (some #{"--attest-root"} argv)
      (let [idx (.indexOf argv "--attest-root")
            m-file (when (< (inc idx) (count argv)) (nth argv (inc idx)))]
        (cmd-attest-root! m-file))

      (some #{"--version" "-v"} argv)
      (println (js/JSON.stringify #js {:ok true :runtime "nodejs" :version full-node-version}))

      (or (empty? argv) (some #{"--help" "-h" "help"} argv))
      (println (js/JSON.stringify
                #js {:ok true
                     :help true
                     :runtime "nodejs"
                     :version full-node-version
                     :commands #js ["run" "infra-node" "print-identity" "print-fingerprint" "validate-config" "gen-keypair" "--check-pointer" "--attest-root" "--self-test" "--version" "--help"]}))

      (= first-arg "run")
      (cmd-run! (second argv))

      (= first-arg "infra-node")
      (start-infra-node! (parse-infra-cli-config argv))

      (or (= first-arg "print-identity") (= first-arg "print-fingerprint"))
      (cmd-print-identity! (second argv))

      (= first-arg "validate-config")
      (cmd-validate-config! (second argv))

      (= first-arg "gen-keypair")
      (cmd-gen-keypair! (second argv))

      :else
      (let [res (run-self-test)]
        (println (js/JSON.stringify (clj->js res)))))))

(set! *main-cli-fn* -main)
