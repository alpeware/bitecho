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
            [bitecho.core.protocol.acme :as acme-proto]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.core.protocol.smtp :as smtp-proto]
            [bitecho.core.storage :as storage]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.economy.account :as account]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.light-node.core :as light-core]
            [bitecho.state-machine :as sm]
            [cljs.reader :as edn]
            [clojure.string :as str]))

(def ^:private node-fs (js/require "node:fs"))
(def ^:private node-path (js/require "node:path"))
(def ^:private node-http (js/require "node:http"))
(def ^:private node-https (js/require "node:https"))
(def ^:private node-tls (js/require "node:tls"))
(def ^:private node-net (js/require "node:net"))
(def ^:private node-dgram (js/require "node:dgram"))
(def ^:private node-crypto (js/require "node:crypto"))
(def ^:private node-zlib (js/require "node:zlib"))

(def full-node-version
  "Current Node.js Full / Infra Node release version."
  "0.23.14")

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

(defn- log-diagnostic!
  [diag]
  (try
    (.write (.-stderr js/process)
            (str (js/JSON.stringify (clj->js (assoc diag :ts (.now js/Date)))) "\n"))
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

(defn- write-disk-blob!
  [state-dir blob shell-atom]
  (let [ncid (core-infra/normalize-cid (:blob/cid blob))
        bs (:blob/bytes blob)
        mt (str (or (:blob/media-type blob) "application/octet-stream"))]
    (if-not (and (core-infra/valid-cid? ncid) (fressian/bytes? bs))
      (do
        (apply-shell-event! shell-atom {:type :diagnose :reason :blob-fs-malformed-write :cid ncid})
        {:ok? false :error :malformed-blob})
      (let [actual (data/compute-cid bs)]
        (if (not= ncid actual)
          (do
            (apply-shell-event! shell-atom {:type :diagnose :reason :blob-cid-mismatch :expected ncid :actual actual})
            {:ok? false :error :blob-cid-mismatch})
          (let [dest (blob-file-path state-dir ncid)
                mdest (blob-meta-path state-dir ncid)
                buf (u8->buf bs)]
            (when-not (.existsSync node-fs dest)
              (atomic-write-file! dest buf nil))
            (when-not (.existsSync node-fs mdest)
              (atomic-write-file! mdest (pr-str {:media-type mt :size (.-length buf)}) nil))
            {:ok? true :cid ncid :path dest}))))))

(defn- read-disk-blob!
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
  [state-dir subnet-state shell-atom]
  (when state-dir
    (try
      (let [dest (.join node-path state-dir "subnet-pointers.fressian")
            payload {:subnet-id (:subnet-id subnet-state)
                     :policy (:policy subnet-state)
                     :pointers (get-in subnet-state [:data :pointers] {})}
            encoded (fressian/encode-canonical payload)]
        (atomic-write-file! dest (u8->buf encoded) nil))
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
;; 4. Node Identity Loading (`<state-dir>/identity/node-identity.edn`)
;; =============================================================================

(defn- load-or-create-node-identity!
  [state-dir node-id shell-atom]
  (let [id-file (.join node-path state-dir "identity" "node-identity.edn")
        legacy-file (.join node-path state-dir "cluster" "node-identity.edn")
        read-ed (fn [f]
                  (when (.existsSync node-fs f)
                    (try
                      (let [m (edn/read-string (.readFileSync node-fs f "utf8"))]
                        (when (and (map? m) (:pubkey-hex m) (:privkey-hex m))
                          {:node-id node-id
                           :pubkey-hex (str/lower-case (str/trim (:pubkey-hex m)))
                           :privkey-hex (str/lower-case (str/trim (:privkey-hex m)))
                           :privkey-bytes (basalt/hex->bytes (str/lower-case (str/trim (:privkey-hex m))))
                           :pubkey-bytes (basalt/hex->bytes (str/lower-case (str/trim (:pubkey-hex m))))}))
                      (catch :default e
                        (apply-shell-event! shell-atom {:type :diagnose :reason :identity-read-failed :file f :detail (.-message e)})
                        nil))))]
    (or (read-ed id-file)
        (read-ed legacy-file)
        (let [kp (crypto/generate-keypair (str "nodejs-infra-" (name (or node-id :ns3))))
              pk-hex (str/lower-case (kp->pk-hex kp))
              sk-bytes (kp->sk kp)
              sk-hex (str/lower-case (basalt/bytes->hex sk-bytes))
              rec {:pubkey-hex pk-hex :privkey-hex sk-hex}]
          (try
            (atomic-write-file! id-file (pr-str rec) 0600)
            (catch :default e
              (apply-shell-event! shell-atom {:type :diagnose :reason :identity-write-failed :detail (.-message e)})))
          {:node-id node-id
           :pubkey-hex pk-hex
           :privkey-hex sk-hex
           :privkey-bytes sk-bytes
           :pubkey-bytes (basalt/hex->bytes pk-hex)}))))

;; =============================================================================
;; 5. Unified Subnet Runtime Helpers
;; =============================================================================

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
                        :timeout 2500
                        :headers (clj->js (assoc headers "Content-Length" (.-length body-buf)))}
          req (.request node-http req-opts (fn [res] (.resume res)))]
      (.on req "error"
           (fn [err]
             (apply-shell-event! shell-atom {:type :diagnose :reason diag-reason :peer (:node-id peer) :detail (.-message err)})))
      (.on req "timeout"
           (fn []
             (.destroy req)
             (apply-shell-event! shell-atom {:type :diagnose :reason diag-reason :peer (:node-id peer) :detail "timeout"})))
      (.write req body-buf)
      (.end req))
    (catch :default e
      (apply-shell-event! shell-atom {:type :diagnose :reason diag-reason :peer (:node-id peer) :detail (.-message e)}))))

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
    (let [res @res-box]
      (when (and (= :put-blob (:type event)) (:blob event))
        (write-disk-blob! (:state-dir rt) (:blob event) (:shell-atom rt)))
      (doseq [eff (:effects res)]
        (case (:effect eff)
          :diagnose
          (apply-shell-event! (:shell-atom rt) (assoc eff :type :diagnose))

          :eager-push-blob
          (do
            (write-disk-blob! (:state-dir rt) (:blob eff) (:shell-atom rt))
            (when-not (:from-peer? event)
              (let [b (:blob eff)]
                (replicate-artifact-to-peers! rt :blob (u8->buf (:blob/bytes b))
                                              {"Content-Type" (or (:blob/media-type b) "application/octet-stream")
                                               "X-Bitecho-Blob-Cid" (:blob/cid b)}))))

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
  (let [body (js/JSON.stringify (clj->js obj))
        buf (.from js/Buffer body "utf8")]
    (.writeHead res status #js {"Content-Type" "application/json; charset=utf-8"
                                "Content-Length" (.-length buf)})
    (.end res buf)))

(defn- send-text!
  [res status text method]
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

(defn- build-statusz-payload
  [rt limiter-atom http-shell-atom dns-shell-atom smtp-shell-atom]
  (let [sub @(:subnet-atom rt)
        le (:leader-election sub)
        egress (long (get-in @limiter-atom [:egress-by-month (current-month-key)] 0))]
    {:ok true
     :runtime "nodejs"
     :version full-node-version
     :node_id (name (or (:node-id rt) :ns3))
     :role (name (or (:role le) :standalone))
     :leader (str (or (:leader-id le) :none))
     :term (long (or (:term le) 0))
     :epoch (long (or @(:epoch-atom rt) 0))
     :healthy (count (or (:healthy-nodes le) #{}))
     :egress_bytes egress
     :pointer_count (count (get-in sub [:data :pointers]))
     :diagnostics {:runtime (core-infra/shell-status-summary @(:shell-atom rt))
                   :http (when http-shell-atom (core-infra/shell-status-summary @http-shell-atom))
                   :dns (when dns-shell-atom (core-infra/shell-status-summary @dns-shell-atom))
                   :smtp (when smtp-shell-atom (core-infra/shell-status-summary @smtp-shell-atom))}}))

(defn- resolve-safe-content-root
  [content-root req-path]
  (when (and (string? content-root) (not (str/blank? content-root)))
    (try
      (let [subpath (core-infra/sanitize-web-subpath req-path)]
        (if (nil? subpath)
          {:ok? false :error :forbidden}
          (if-not (.existsSync node-fs content-root)
            {:ok? false :error :not-found}
            (let [root-real (.realpathSync node-fs content-root)
                  cand (.resolve node-path root-real (if (str/blank? subpath) "." subpath))]
              (if (and (not= cand root-real)
                       (not (str/starts-with? cand (str root-real (.-sep node-path)))))
                {:ok? false :error :forbidden}
                (if-not (.existsSync node-fs cand)
                  {:ok? false :error :not-found}
                  (let [real-p (.realpathSync node-fs cand)]
                    (if (and (not= real-p root-real)
                             (not (str/starts-with? real-p (str root-real (.-sep node-path)))))
                      {:ok? false :error :forbidden}
                      (let [st (.statSync node-fs real-p)
                            target-f (cond
                                       (.isFile st) real-p
                                       (.isDirectory st)
                                       (let [idx-html (.join node-path real-p "index.html")
                                             idx-md (.join node-path real-p "index.md")]
                                         (cond
                                           (.existsSync node-fs idx-html) idx-html
                                           (.existsSync node-fs idx-md) idx-md
                                           :else nil))
                                       :else nil)]
                        (if-not target-f
                          {:ok? false :error :not-found}
                          (let [buf (.readFileSync node-fs target-f)
                                cid (sha256-buf-hex buf)
                                ct (core-infra/content-type-for-file (.basename node-path target-f))]
                            {:ok? true
                             :file-path target-f
                             :blob {:blob/cid cid
                                    :blob/media-type ct
                                    :blob/bytes (buf->u8 buf)}})))))))))))
      (catch :default _
        {:ok? false :error :not-found}))))

(defn- resolve-web-blob!
  [config rt req-path now-ms]
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
        (:ok? ptr-res) ptr-res
        (:denied? ptr-res) ptr-res
        :else (or (resolve-safe-content-root (get-in config [:http :content-root]) req-path)
                  ptr-res)))
    {:ok? false :error :forbidden}))

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
            gz-buf (when want-gz? (try (.gzipSync node-zlib raw-buf) (catch :default _ nil)))
            use-gz? (and gz-buf (< (.-length gz-buf) total-size))
            out-buf (if use-gz? gz-buf raw-buf)
            hdrs (cond-> (assoc auth-hdrs
                                "Content-Type" ct
                                "Accept-Ranges" "bytes"
                                "Content-Length" (.-length out-buf))
                   use-gz? (assoc "Content-Encoding" "gzip" "Vary" "Accept-Encoding"))]
        (when (pos? (.-length out-buf))
          (swap! limiter-atom #(-> (dns-proto/record-egress % (.-length out-buf) (current-month-key)) :state)))
        (.writeHead res 200 (clj->js hdrs))
        (if (= method "HEAD") (.end res) (.end res out-buf))))))

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
          (let [cr (get-in config [:http :content-root])
                disk-target (when cr (resolve-safe-content-root cr (str "/dist/" target-name)))
                disk-direct (when cr (resolve-safe-content-root cr (str "/dist/" rel-path)))]
            (cond
              (and sha-req? (:ok? disk-target))
              (send-text! res 200 (str (get-in disk-target [:blob :blob/cid]) "  " (.basename node-path target-name) "\n") method)

              (:ok? disk-direct)
              (send-resolved-blob! req res disk-direct method extra-headers limiter-atom)

              :else
              (send-text! res 404 "Not Found\n" method))))))))

(defn- handle-artifact-endpoint!
  [req res rt clean-path query-str method]
  (let [now-ms (.now js/Date)
        replicated? (= "true" (str/lower-case (str (or (get-header req "x-bitecho-artifact-replicated") ""))))]
    (cond
      (= clean-path "/artifact/v1/blob")
      (if (not= method "POST")
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (read-req-body-bounded!
         req (long (or (get-in (:config rt) [:http :max-artifact-blob-bytes]) 16777216))
         (fn [body-buf exceeded?]
           (if exceeded?
             (send-json! res 413 {:ok false :error "payload-too-large"})
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
                       sender (or (get-header req "x-bitecho-pubkey") (:default-sender rt))]
                   (submit-subnet-event! rt {:type :put-blob
                                             :blob blob
                                             :sender sender
                                             :now-ms now-ms
                                             :from-peer? replicated?})
                   (send-json! res 200 {:ok true
                                        :cid (:blob/cid blob)
                                        :size_bytes (fressian/count-bytes (:blob/bytes blob))}))))))))

      (str/starts-with? clean-path "/artifact/v1/blob/")
      (if-not (contains? #{"GET" "HEAD"} method)
        (send-json! res 405 {:ok false :error "method-not-allowed"})
        (let [cid (subs clean-path (count "/artifact/v1/blob/"))
              r (resolve-cid-blob! rt cid now-ms)]
          (if (:ok? r)
            (let [b (:blob r)
                  buf (u8->buf (:blob/bytes b))]
              (.writeHead res 200 #js {"Content-Type" (or (:blob/media-type b) "application/octet-stream")
                                       "Content-Length" (.-length buf)
                                       "ETag" (str "\"" (:blob/cid b) "\"")
                                       "X-Bitecho-Blob-Cid" (:blob/cid b)})
              (if (= method "HEAD") (.end res) (.end res buf)))
            (send-json! res 404 {:ok false :error "blob-not-found" :cid cid}))))

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
                   (when-not (:replicated? rep-auth)
                     (replicate-relay-to-peers! rt "/relay/v1/send" body-buf))
                   (wake-relay-waiters! waiters-atom
                                        (get-in r [:response "recipient"])
                                        (boolean (get-in r [:response "broadcast"])))
                   (send-json! res 200 (:response r)))
                 (let [status (case (:error r) :payload-too-large 413 :invalid-signature 403 400)]
                   (send-json! res status (:response r))))))))))

    (and (contains? #{"GET" "POST"} method) (= clean-path "/relay/v1/poll"))
    (let [process-poll!
          (fn [body-buf exceeded?]
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
                    wait-ms (min 30000 (max 0 (parse-int (or (get body-json "wait_ms") (get qparams "wait_ms")) 0)))
                    raw-subs (or (get body-json "subnets") (get qparams "subnets") (get-header req "x-bitecho-subnets"))
                    subs (cond
                           (coll? raw-subs) (vec raw-subs)
                           (and (string? raw-subs) (not (str/blank? raw-subs))) (vec (remove str/blank? (str/split raw-subs #",")))
                           :else nil)
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
                                              fresh-m (filterv #(and (> (long (:relay-seq %)) since-seq)
                                                                     (>= (long (:received-at % 0)) cutoff))
                                                               (get-in st [:inboxes norm-pk] []))
                                              fresh-b (filterv #(and (> (long (:broadcast-seq %)) since-bseq)
                                                                     (>= (long (:received-at % 0)) cutoff))
                                                               (get st :broadcasts []))]
                                          (when-not (.-writableEnded res)
                                            (send-json! res 200 {"ok" true "pubkey" norm-pk "messages" fresh-m "broadcasts" fresh-b})))))
                            wake-fn (fn []
                                      (swap! waiters-atom #(-> % (update norm-pk disj finish!) (update :broadcast disj finish!)))
                                      (finish!))]
                        (swap! waiters-atom #(-> % (update norm-pk (fnil conj #{}) wake-fn) (update :broadcast (fnil conj #{}) wake-fn)))
                        (reset! timer-id (js/setTimeout wake-fn wait-ms))
                        (.on req "close" wake-fn))
                      (send-json! res 200 (:response r))))))))]
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
    (send-json! res 200 {:ok true
                         :pubkey (:default-sender rt)
                         :snapshots []
                         :epoch (long (or @(:epoch-atom rt) 1))
                         :min_signaling_burn (long (or (get-in (:config rt) [:min-signaling-burn]) 100))
                         :bootstrap (or (:domain (:config rt)) "bitecho.org")})

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

(defn- handle-web-or-api-request!
  [req res {:keys [config rt relay-atom waiters-atom limiter-atom http-shell-atom dns-shell-atom smtp-shell-atom https? bound-https-port]}]
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

      (and (contains? #{"GET" "HEAD"} method) (= clean-path "/healthz"))
      (send-json! res 200 {:ok true
                           :runtime "nodejs"
                           :version full-node-version
                           :node_id (name (or (:node-id rt) :ns3))})

      (and (contains? #{"GET" "HEAD"} method) (= clean-path "/statusz"))
      (send-json! res 200 (build-statusz-payload rt limiter-atom http-shell-atom dns-shell-atom smtp-shell-atom))

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
          (if (str/starts-with? subpath "dist/")
            (handle-dist-request! req res config rt raw-path query-str method extra-hdrs limiter-atom)
            (let [resolved (resolve-web-blob! config rt raw-path now-ms)]
              (cond
                (= :forbidden (:error resolved))
                (do
                  (apply-shell-event! http-shell-atom {:type :drop :reason :http-forbidden-path :detail raw-path})
                  (send-text! res 403 "Forbidden\n" method))

                (:ok? resolved)
                (send-resolved-blob! req res resolved method extra-hdrs limiter-atom)

                :else
                (send-text! res 404 "Not Found\n" method)))))))))

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
        _ (try
            (atomic-write-file! (.join node-path mail-dir (str now-ms "-" msg-id ".eml")) full-eml 0600)
            (catch :default e
              (apply-shell-event! (:shell-atom rt) {:type :diagnose :reason :smtp-disk-write-failed :detail (.-message e)})))
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
;; 9. Full Infra-Node Orchestrator (`start-infra-node!`)
;; =============================================================================

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
        init-res (subnet/init-subnet-instance default-pol {:node-id node-id :all-nodes all-nodes})
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
        rt {:config config
            :node-id node-id
            :state-dir state-dir
            :shell-atom rt-shell-atom
            :subnet-atom (atom inst0)
            :epoch-atom (atom 1)
            :default-sender pk
            :node-privkey sk
            :tls-secret tls-secret
            :tls-ctx-atom tls-ctx-atom
            :tls-pem-atom tls-pem-atom}
        _ (when-let [{:keys [cert-pem key-pem]} (load-tls-cert-key-from-disk-or-subnet! rt)]
            (try
              (reset! tls-ctx-atom (.createSecureContext node-tls #js {:cert cert-pem :key key-pem}))
              (reset! tls-pem-atom {:cert-pem cert-pem :key-pem key-pem})
              (catch :default e
                (apply-shell-event! rt-shell-atom {:type :diagnose :reason :tls-init-failed :detail (.-message e)}))))
        _ (apply-shell-event! rt-shell-atom {:type :started :generation rt-gen :resources {:state-dir state-dir}})
        relay-atom (atom (relay/init-relay-state (get-in config [:http :relay])))
        waiters-atom (atom {})
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
    ;; Heartbeat loop
    (when-let [hb-timer (start-peer-heartbeat-loop! config rt)]
      (swap! stop-fns conj #(js/clearInterval hb-timer)))

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

    ;; 5. Localhost Diagnostics HTTP (`127.0.0.1:8080`)
    (when diag-enabled?
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
      (.on js/process "SIGINT" shutdown!))))

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
        sub-init (subnet/init-subnet-instance policy {:node-id :ns3 :all-nodes #{:ns1 :ns2 :ns3}})
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
                 (some? acme-proto/base64url-encode))]
    {:ok ok?
     :runtime "nodejs"
     :node_version (.-version js/process)
     :version full-node-version
     :epoch (:epoch ticked)
     :active_config_hash (:active-config-hash ticked)
     :audit_records (count (:audit-trail ticked))
     :fressian_roundtrip_ok (= "bitecho.org/infra" (:subnet-id snap-decoded))
     :spend_dac_ok (true? (:ok? spend-res))}))

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

(defn -main
  "CLI entry point for the Node.js infrastructure full node."
  [& args]
  (let [argv (vec args)
        first-arg (first argv)]
    (cond
      (some #{"--self-test"} argv)
      (let [res (run-self-test)]
        (println (js/JSON.stringify (clj->js res)))
        (when-not (:ok res)
          (.exit js/process 1)))

      (some #{"--version" "-v"} argv)
      (println (js/JSON.stringify #js {:ok true :runtime "nodejs" :version full-node-version}))

      (or (empty? argv) (some #{"--help" "-h" "help"} argv))
      (println (js/JSON.stringify
                #js {:ok true
                     :help true
                     :runtime "nodejs"
                     :version full-node-version
                     :commands #js ["infra-node" "--self-test" "--version" "--help"]}))

      (= first-arg "infra-node")
      (start-infra-node! (parse-infra-cli-config argv))

      :else
      (let [res (run-self-test)]
        (println (js/JSON.stringify (clj->js res)))))))

(set! *main-cli-fn* -main)
