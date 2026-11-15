(ns bitecho.stress.live-testnet
  "Live 6-Node Testnet E2E Runner & Dynamic Validator Reconfiguration Tool (Milestone D15).
   Supports:
   1. `reconfigure-live-validator!` (invoked by `scripts/cluster.sh add-validator` / `remove-validator`)
      to dynamically add or remove mesh/BFT validators using treasury-signed `:reconfigure-membership`
      receipts without resetting the chain, optionally broadcasting live over UDP DataChannel (`:5010`).
   2. `run-live-testnet-e2e!` to execute the Full-Surface E2E workload through the Fressian wire boundary
      and verify normalized balance-delta and escrow parity against `compute-golden-expected-state` (A-D15-6).
   3. `run-live-gcp-cluster-e2e!` (`--live-network`) to execute the 6-stage workload over real UDP WebRTC
      DataChannels (`:5010`) against the live 6-node GCP cluster (`node1..3` + `ns1..3`)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [bitecho.stress.e2e-workload :as workload]
            [bitecho.stress.harness :as harness]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [datachannel.api :as api])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.time Duration]))

(defn- read-edn-file
  [path]
  (let [f (io/file path)]
    (when (.exists f)
      (edn/read-string (slurp f)))))

(defn- fetch-http-edn
  [url timeout-ms]
  (try
    (let [client (-> (HttpClient/newBuilder)
                     (.connectTimeout (Duration/ofMillis (long (or timeout-ms 1500))))
                     (.build))
          req (-> (HttpRequest/newBuilder (URI/create url))
                  (.timeout (Duration/ofMillis (long (or timeout-ms 1500))))
                  (.GET)
                  (.build))
          resp (.send client req (HttpResponse$BodyHandlers/ofString))]
      (when (= 200 (.statusCode resp))
        (edn/read-string (.body resp))))
    (catch Exception _ nil)))

(defn- resolve-node-pubkey
  [nodes-map node-kw]
  (or (get-in nodes-map [node-kw :pubkey])
      (get-in nodes-map [(name node-kw) :pubkey])
      (name node-kw)))

;; =============================================================================
;; 1. Live WebRTC DataChannel (:5010) & SSH Diagnostic Helpers
;; =============================================================================

(defn connect-live-agent-channel!
  "Connects a WebRTC DataChannel client to a validator's agent ingress port (:5010).
   Returns {:node node :channel-id channel-id :connected? boolean}."
  [node-cfg timeout-ms]
  (try
    (let [node (api/create-node {:port 0 :setup "active"})
          channel-id (atom nil)
          ready-prom (promise)
          remote-sdp {:ip (:ip node-cfg)
                      :port (int (or (:agent-port node-cfg) 5010))
                      :fingerprint (identity/normalize-fingerprint (:fingerprint node-cfg))
                      :remote-ice-ufrag (:ice-ufrag node-cfg)
                      :remote-ice-pwd (:ice-pwd node-cfg)}
          callbacks {:on-open (fn [evt]
                                (let [cid (or (:channel-id evt)
                                              (api/create-data-channel! node "bitecho" {:ordered true}))]
                                  (reset! channel-id cid)
                                  (deliver ready-prom true)))
                     :on-close (fn [_]
                                 (reset! channel-id nil))
                     :on-message (fn [_] nil)}]
      (api/start! node remote-sdp callbacks)
      (let [ok? (deref ready-prom (long (or timeout-ms 8000)) false)]
        {:node node
         :channel-id channel-id
         :connected? (boolean (and ok? (some? @channel-id)))}))
    (catch Exception e
      {:node nil
       :channel-id (atom nil)
       :connected? false
       :error (.getMessage e)})))

(defn close-live-agent-channel!
  "Cleanly closes a WebRTC DataChannel client connection."
  [conn]
  (when-let [n (:node conn)]
    (try
      (api/close! n)
      (catch Exception _ nil))))

(defn send-agent-envelope-to-live-node!
  "Signs `event` with `signer-priv-bytes`, encodes the envelope with `fressian/encode-wire`,
   and transmits it over WebRTC DataChannel (`:5010`).
   `conn-or-node-cfg` may be either an open connection map from `connect-live-agent-channel!`
   or a validator node config map `{:ip ... :agent-port ... :fingerprint ... :ice-ufrag ... :ice-pwd ...}`."
  [conn-or-node-cfg signer-pub-hex signer-priv-bytes event]
  (let [clean-ev (dissoc event :signer-pubkey)
        wrapped (mesh/wrap-agent-event clean-ev signer-pub-hex signer-priv-bytes)
        wire-bytes (fressian/encode-wire wrapped)
        existing-conn? (and (map? conn-or-node-cfg) (contains? conn-or-node-cfg :channel-id))
        conn (if existing-conn?
               conn-or-node-cfg
               (connect-live-agent-channel! conn-or-node-cfg 8000))]
    (try
      (if-let [cid (and (:connected? conn) @(:channel-id conn))]
        (do
          (api/send! (:node conn) wire-bytes cid)
          (when-not existing-conn?
            (Thread/sleep 150))
          true)
        false)
      (catch Exception _
        false)
      (finally
        (when-not existing-conn?
          (close-live-agent-channel! conn))))))

(defn fetch-live-node-statusz-ssh
  "Queries `http://127.0.0.1:8080/statusz` on `node-ip` via SSH and parses the statusz map."
  ([node-ip] (fetch-live-node-statusz-ssh node-ip ".ssh/bitecho_cluster_ed25519" "bitecho"))
  ([node-ip ssh-key ssh-user]
   (try
     (let [res (sh/sh "ssh"
                      "-o" "StrictHostKeyChecking=accept-new"
                      "-o" "ConnectTimeout=5"
                      "-o" "LogLevel=ERROR"
                      "-i" (str ssh-key)
                      (str ssh-user "@" node-ip)
                      "curl -fsSL --max-time 3 http://127.0.0.1:8080/statusz")]
       (when (zero? (:exit res))
         (mesh/parse-statusz-line (:out res))))
     (catch Exception _ nil))))

(defn fetch-live-node-accountz-ssh
  "Queries `http://127.0.0.1:8080/accountz?include-escrows=true` on `node-ip` via SSH."
  ([node-ip] (fetch-live-node-accountz-ssh node-ip ".ssh/bitecho_cluster_ed25519" "bitecho"))
  ([node-ip ssh-key ssh-user]
   (try
     (let [res (sh/sh "ssh"
                      "-o" "StrictHostKeyChecking=accept-new"
                      "-o" "ConnectTimeout=5"
                      "-o" "LogLevel=ERROR"
                      "-i" (str ssh-key)
                      (str ssh-user "@" node-ip)
                      "curl -fsSL --max-time 3 'http://127.0.0.1:8080/accountz?include-escrows=true'")]
       (when (zero? (:exit res))
         (edn/read-string (:out res))))
     (catch Exception _ nil))))

;; =============================================================================
;; 2. Dynamic Validator Reconfiguration (`add-validator` / `remove-validator`)
;; =============================================================================

(defn- render-bootstrap-txt
  "Renders a human-readable bootstrap.txt string matching the structure of `boot-cfg`."
  [boot-cfg]
  (let [cluster (if (map? (:cluster boot-cfg)) (:cluster boot-cfg) boot-cfg)
        net (name (or (:network cluster) :devnet))
        dom (or (:domain cluster) "bitecho.org")
        auth-pk (:authority-pubkey cluster)
        issued-ep (:issued-epoch cluster)
        expires-ep (:expires-epoch cluster)
        sig (:signature cluster)
        treasury-pk (:treasury-pubkey cluster)
        custody-pk (:custody-pubkey cluster)
        dir-pk (:directory-pubkey cluster)
        nodes (:nodes cluster)
        n-cnt (count nodes)
        q-cnt (int (Math/ceil (/ (* 2.0 (max 1 n-cnt)) 3.0)))]
    (str
     "================================================================================\n"
     "Bitecho Genesis Devnet - Bootstrap Peer & WebRTC Connection Descriptor\n"
     "================================================================================\n\n"
     "Network: " net " (" n-cnt "-node Streamlet BFT validator quorum, N=" n-cnt ", quorum=" q-cnt " of " n-cnt ")\n"
     (when dom (str "Domain: " dom "\n"))
     (when auth-pk (str "Authority Pubkey: " auth-pk "\n"))
     (when (some? issued-ep) (str "Issued Epoch: " issued-ep "\n"))
     (when (some? expires-ep) (str "Expires Epoch: " expires-ep "\n"))
     (when sig (str "Authority Signature: " sig "\n"))
     (when treasury-pk (str "Treasury Public Key: " treasury-pk "\n"))
     (when custody-pk (str "Custody Public Key:  " custody-pk "\n"))
     (when dir-pk (str "Directory Authority Public Key: " dir-pk "\n"))
     "\nBootstrap Validators:\n"
     "--------------------------------------------------------------------------------\n"
     (apply str
            (for [[nid n] nodes]
              (str "Node: " (name nid) "\n"
                   "  Cluster Address:   " (:ip n) ":" (:port n) " (UDP DataChannel)\n"
                   "  Agent Ingress:     " (:ip n) ":" (:agent-port n) " (UDP DataChannel)\n"
                   (when (:agent-tcp-port n)
                     (str "  Agent TCP Ingress: " (:ip n) ":" (:agent-tcp-port n) " (TCP DataChannel)\n"))
                   (when (and (:ingress-host n) (:ingress-port n))
                     (str "  Agent HTTPS/Proxy Ingress: " (:ingress-host n) ":" (:ingress-port n) " (TCP DataChannel)\n"))
                   "  HTTP Diagnostics:  http://127.0.0.1:8080/healthz, /statusz, /burnsz (bound to localhost)\n"
                   "  Ed25519 Pubkey:    " (:pubkey n) "\n"
                   "  DTLS Fingerprint:  " (:fingerprint n) "\n"
                   "  ICE Credentials:   ufrag=" (:ice-ufrag n) " pwd=" (:ice-pwd n) "\n\n"))))))

(defn reconfigure-live-validator!
  "Dynamically adds or removes `node-id` in `bootstrap-file` and signs an on-chain
   `:reconfigure-membership` receipt with the treasury private key from `keys-file` / `treasury-key-file`.
   When `:submit-live?` is true, also broadcasts the signed `:reconfigure-membership` envelope
   over UDP WebRTC DataChannels (`:5010`) to the active bootstrap validators."
  [{:keys [action node-id role promote-bft? submit-live? bootstrap-file keys-file treasury-key-file effective-epoch]
    :or {bootstrap-file "devnet/bootstrap.edn"}}]
  (let [eff-keys-file (or treasury-key-file keys-file "devnet/keys.edn")
        eff-role (cond
                   (some? promote-bft?) (if promote-bft? "bft" "mesh")
                   (some? role) role
                   :else "mesh")
        node-kw (if (keyword? node-id) node-id (keyword (str/replace (str node-id) #"^:" "")))
        role-str (str/lower-case (str eff-role))
        boot-cfg (read-edn-file bootstrap-file)
        keys-cfg (read-edn-file eff-keys-file)]
    (cond
      (nil? boot-cfg)
      {:ok? false :error :missing-bootstrap-file :path bootstrap-file}

      (nil? keys-cfg)
      {:ok? false :error :missing-keys-file :path eff-keys-file}

      (not (contains? #{:add :remove} action))
      {:ok? false :error :invalid-action :action action}

      (not (contains? #{"mesh" "bft"} role-str))
      {:ok? false :error :invalid-role :role eff-role}

      :else
      (let [nested-cluster? (map? (:cluster boot-cfg))
            cluster (if nested-cluster? (:cluster boot-cfg) boot-cfg)
            nodes-map (or (:nodes cluster) {})
            curr-vals (vec (or (:validators cluster)
                               (let [core-ks (filter #{:node1 :node2 :node3} (keys nodes-map))]
                                 (if (= 3 (count core-ks))
                                   [:node1 :node2 :node3]
                                   (keys nodes-map)))))
            raw-mesh (or (:mesh-nodes cluster)
                         (into {} (map (fn [k] [k 1.0]) (keys nodes-map))))
            curr-mesh (if (map? raw-mesh)
                        raw-mesh
                        (into {} (map (fn [k] [k 1.0]) raw-mesh)))
            next-vals (case action
                        :add (if (= role-str "bft")
                               (vec (distinct (conj curr-vals node-kw)))
                               curr-vals)
                        :remove (vec (remove #(= % node-kw) curr-vals)))
            next-mesh (case action
                        :add (assoc curr-mesh node-kw 1.0)
                        :remove (dissoc curr-mesh node-kw))]
        (if (empty? next-vals)
          {:ok? false :error :cannot-empty-streamlet-validators}
          (let [val-hexes (vec (sort (map #(resolve-node-pubkey nodes-map %) next-vals)))
                mesh-hex-map (into (sorted-map)
                                   (map (fn [[k w]]
                                          [(resolve-node-pubkey nodes-map k) (double (or w 1.0))])
                                        next-mesh))
                t-priv-hex (or (:privkey-hex keys-cfg)
                               (get-in keys-cfg [:treasury :private])
                               (get-in keys-cfg [:treasury :privkey-hex])
                               (:treasury-privkey keys-cfg))
                t-pub-hex (or (:pubkey-hex keys-cfg)
                              (get-in keys-cfg [:treasury :public])
                              (get-in keys-cfg [:treasury :pubkey-hex])
                              (get-in boot-cfg [:cluster :treasury-pubkey])
                              (:treasury-pubkey boot-cfg))
                live-ep (when submit-live?
                          (when-let [n1-ip (get-in nodes-map [:node1 :ip])]
                            (:epoch (fetch-live-node-statusz-ssh n1-ip))))
                eff-ep (long (or effective-epoch (when live-ep (inc (long live-ep))) 1))
                rid (str "reconfig:" (name action) ":" (name node-kw) ":" eff-ep)
                sig (when (and (string? t-priv-hex) (not (str/blank? t-priv-hex)))
                      (sm/sign-reconfigure-membership
                       (basalt/hex->bytes t-priv-hex)
                       rid
                       eff-ep
                       val-hexes
                       mesh-hex-map))
                target-pk (resolve-node-pubkey nodes-map node-kw)
                new-peers-map (when (and (= action :add)
                                         (string? target-pk)
                                         (re-matches #"^[0-9a-fA-F]+$" target-pk)
                                         (even? (count target-pk)))
                                {target-pk (basalt/hex->bytes target-pk)})
                receipt (cond-> {:receipt-id rid
                                 :type :reconfigure-membership
                                 :effective-epoch eff-ep
                                 :validators val-hexes
                                 :mesh-nodes mesh-hex-map
                                 :signature sig}
                          (seq new-peers-map)
                          (assoc :new-peers-map new-peers-map))
                updated-boot (if nested-cluster?
                               (-> boot-cfg
                                   (assoc-in [:cluster :validators] next-vals)
                                   (assoc-in [:cluster :mesh-nodes] next-mesh))
                               (-> boot-cfg
                                   (assoc :validators next-vals)
                                   (assoc :mesh-nodes next-mesh)))
                live-submitted (if (and submit-live? sig t-pub-hex t-priv-hex)
                                 (let [priv-bytes (basalt/hex->bytes t-priv-hex)
                                       ev {:type :reconfigure-membership :receipt receipt}]
                                   (count (filter true?
                                                  (pmap (fn [[_ ncfg]]
                                                          (send-agent-envelope-to-live-node! ncfg t-pub-hex priv-bytes ev))
                                                        nodes-map))))
                                 0)]
            (spit bootstrap-file (with-out-str (pprint/pprint updated-boot)))
            (when (str/ends-with? (str bootstrap-file) "devnet/bootstrap.edn")
              (let [txt-file (io/file (.getParentFile (io/file bootstrap-file)) "bootstrap.txt")]
                (when (.exists txt-file)
                  (spit txt-file (render-bootstrap-txt updated-boot)))))
            {:ok? (boolean sig)
             :action action
             :node-id node-kw
             :role (keyword role-str)
             :validators next-vals
             :mesh-nodes next-mesh
             :receipt receipt
             :live-submitted-nodes live-submitted
             :treasury-pubkey t-pub-hex}))))))

;; =============================================================================
;; 3. Golden Parity Verification & Live GCP Cluster E2E Runner
;; =============================================================================

(defn verify-normalized-live-parity
  "Compares pre-workload and post-workload account snapshots from a live or simulated
   6-node cluster against `golden`, normalizing out background validator epoch mints (A-D15-6)."
  [pre-balances post-balances post-escrows golden]
  (let [expected-deltas (:deltas-by-pubkey golden)
        expected-escrows (:escrow-statuses golden)
        actual-deltas (into {}
                            (map (fn [[pk _]]
                                   (let [b0 (long (get pre-balances pk 0))
                                         b1 (long (get post-balances pk 0))]
                                     [pk (- b1 b0)]))
                                 expected-deltas))
        actual-escrows (select-keys post-escrows (keys expected-escrows))
        deltas-match? (= expected-deltas actual-deltas)
        escrows-match? (= expected-escrows actual-escrows)]
    {:parity? (and deltas-match? escrows-match?)
     :deltas-match? deltas-match?
     :escrows-match? escrows-match?
     :expected-deltas expected-deltas
     :actual-deltas actual-deltas
     :expected-escrows expected-escrows
     :actual-escrows actual-escrows}))

(defn- extract-balances-map
  [accountz-resp]
  (into {}
        (map (fn [[pk v]]
               [pk (long (or (if (map? v) (:balance v) v) 0))])
             (:accounts accountz-resp))))

(defn- extract-escrow-statuses-map
  [accountz-resp]
  (into {}
        (map (fn [[eid e]]
               [eid (:status e)])
             (:escrows accountz-resp))))

(defn- wait-for-live-condition!
  "Polls `fetch-live-node-accountz-ssh` on `node1-ip` until `(pred-fn ac)` returns true,
   re-running `rebroadcast-fn` every 35 seconds if not yet satisfied."
  [node1-ip label pred-fn rebroadcast-fn timeout-ms]
  (let [start-ms (System/currentTimeMillis)
        deadline (+ start-ms (long timeout-ms))
        last-rebroadcast (atom start-ms)]
    (loop [last-ac nil]
      (let [ac (or (fetch-live-node-accountz-ssh node1-ip) last-ac)]
        (if (and ac (pred-fn ac))
          ac
          (let [now (System/currentTimeMillis)]
            (if (>= now deadline)
              (do
                (println (str "[LIVE-TIMEOUT] " label
                              " epoch=" (:epoch ac)
                              " finalized-epoch=" (:finalized-epoch ac)
                              " pending=" (:pending-receipts-count ac)
                              " failed=" (:failed-receipts-count ac)))
                ac)
              (do
                (when (and rebroadcast-fn (>= (- now @last-rebroadcast) 35000))
                  (reset! last-rebroadcast now)
                  (println (str "[LIVE-RETRY] Re-broadcasting pending intents for " label "..."))
                  (rebroadcast-fn))
                (Thread/sleep 2000)
                (recur ac)))))))))

(defn run-live-gcp-cluster-e2e!
  "Executes the Full-Surface 6-stage workload over real UDP WebRTC DataChannels (`:5010`)
   against the live 6-node GCP cluster (`node1..3` + `ns1..3`) defined in `bootstrap-file`,
   verifying 100% golden balance-delta and escrow-status parity."
  ([] (run-live-gcp-cluster-e2e! "devnet/bootstrap.edn"))
  ([bootstrap-file]
   (let [boot-cfg (read-edn-file bootstrap-file)
         cluster (if (map? (:cluster boot-cfg)) (:cluster boot-cfg) boot-cfg)
         nodes-map (:nodes cluster)
         node1-ip (get-in nodes-map [:node1 :ip])
         _ (println "=== [D15 LIVE GCP E2E] Polling initial /accountz on node1 (" node1-ip ") ===")
         pre-ac (wait-for-live-condition!
                 node1-ip
                 "initial-genesis-ready"
                 (fn [ac] (and (seq (:accounts ac)) (pos? (long (or (:finalized-epoch ac) 0)))))
                 nil
                 60000)
         pre-balances (extract-balances-map pre-ac)
         v-epoch (max 1 (long (or (:finalized-epoch pre-ac) 1)))
         scenario (workload/build-workload-scenario)
         golden (workload/compute-golden-expected-state scenario)
         topo (:topology scenario)
         privkey-by-pub (harness/build-privkey-by-pub topo)
         ids (:identities-by-id topo)
         vals-by-id (:validators-by-id topo)
         funder (:treasury-funder ids)
         founder (:subnet-founder ids)
         author (:kernel-author ids)
         oracle (:oracle-verifier ids)
         buyer1 (:agent-buyer-1 ids)
         buyer2 (:agent-buyer-2 ids)
         {:keys [tx1 tx2 tx3]} (:transfers scenario)
         ns1-hex (get-in vals-by-id [:ns1 :pubkey-hex])
         ns2-hex (get-in vals-by-id [:ns2 :pubkey-hex])
         voucher1 (rendezvous/create-delivery-ack
                   (:private buyer1) (:pubkey-hex buyer1) ns1-hex v-epoch "offer-msg-buyer1-1" 2 100)
         voucher2 (rendezvous/create-delivery-ack
                   (:private buyer2) (:pubkey-hex buyer2) ns2-hex v-epoch "offer-msg-buyer2-1" 3 150)
         _ (println "=== [D15 LIVE GCP E2E] Connecting UDP WebRTC DataChannels (:5010) to 6 GCP Validators ===")
         conns-by-vid (into {}
                            (pmap (fn [[vid ncfg]]
                                    [vid (connect-live-agent-channel! ncfg 10000)])
                                  nodes-map))
         connected-vids (vec (keep (fn [[vid c]] (when (:connected? c) vid)) conns-by-vid))
         _ (println "Connected UDP (:5010) DataChannels:" connected-vids)
         dispatch-live!
         (fn [primary-vid ev]
           (let [signer-pub (or (:signer-pubkey ev) (:sender ev) (:payer ev) (:callee ev))
                 signer-priv (get privkey-by-pub signer-pub)
                 target-vids (distinct (into [primary-vid] [:node1 :node2 :node3]))]
             (doseq [vid target-vids]
               (when-let [conn (get conns-by-vid vid)]
                 (when (:connected? conn)
                   (send-agent-envelope-to-live-node! conn signer-pub signer-priv ev)
                   (Thread/sleep 20))))))]
     (try
       ;; Batch 1: 8 Home-Set Registrations + tx1 + settle-intent + 2 signaling-burns
       (let [entry-vids [:ns1 :ns2 :ns3 :node1 :node2]
             send-batch-1!
             (fn []
               (doseq [[idx [_ id-map]] (map-indexed vector (:identities-by-id topo))]
                 (let [target-vid (nth entry-vids (mod idx (count entry-vids)))
                       candidates (mapv (fn [vid]
                                          {:node-id (get-in vals-by-id [vid :pubkey-hex])
                                           :price (:home-price id-map)})
                                        (:home-set id-map))]
                   (dispatch-live!
                    target-vid
                    {:type :register-home-set
                     :callee (:pubkey-hex id-map)
                     :sender (:pubkey-hex id-map)
                     :epoch v-epoch
                     :price (:home-price id-map)
                     :price-max (:home-price id-map)
                     :candidates candidates})))
               (dispatch-live!
                :ns1
                {:type :on-deliver
                 :message-id "msg-tx1"
                 :sender (:sender tx1)
                 :payload (fressian/encode-canonical {:transfer (into {} tx1)})})
               (dispatch-live!
                :ns1
                {:type :settle-intent
                 :receipt-id "intent:d15-founder-oracle-2000"
                 :payer (:pubkey-hex founder)
                 :receiver (:pubkey-hex oracle)
                 :sender (:pubkey-hex founder)
                 :amount 2000})
               (dispatch-live!
                :ns2
                {:type :signaling-burn
                 :receipt-id "burn:d15-founder-500"
                 :sender (:pubkey-hex founder)
                 :burn-amount 500})
               (dispatch-live!
                :ns3
                {:type :signaling-burn
                 :receipt-id "burn:d15-author-300"
                 :sender (:pubkey-hex author)
                 :burn-amount 300}))]
         (println "=== [D15 LIVE GCP E2E] Submitting Batch 1 (Home-Sets, tx1, settle-intent, signaling-burns) ===")
         (send-batch-1!)
         (let [ac-after-b1
               (wait-for-live-condition!
                node1-ip
                "batch-1-finalized"
                (fn [ac]
                  (let [bals (extract-balances-map ac)]
                    (and (= 950000 (get bals (:pubkey-hex funder)))
                         (= 151990 (get bals (:pubkey-hex oracle)))
                         (= 199700 (get bals (:pubkey-hex author))))))
                send-batch-1!
                120000)
               curr-ep (long (or (:epoch ac-after-b1) (:finalized-epoch ac-after-b1) 5))
               contracts (:contracts scenario)
               royalty (:royalty contracts)
               multisig (:multisig contracts)
               htlc (:htlc contracts)
               timeout-c (:timeout contracts)
               royalty-exp (+ curr-ep 40)
               multisig-exp (+ curr-ep 40)
               htlc-exp (+ curr-ep 40)
               timeout-exp (+ curr-ep 1)
               send-batch-2!
               (fn []
                 (dispatch-live!
                  :ns2
                  {:type :on-deliver
                   :message-id "msg-tx2"
                   :sender (:sender tx2)
                   :payload (fressian/encode-canonical {:transfer (into {} tx2)})})
                 (dispatch-live!
                  :ns3
                  {:type :on-deliver
                   :message-id "msg-tx3"
                   :sender (:sender tx3)
                   :payload (fressian/encode-canonical {:transfer (into {} tx3)})})
                 (dispatch-live!
                  :ns1
                  {:type :submit-vouchers
                   :signer-pubkey (:pubkey-hex buyer1)
                   :vouchers [voucher1 voucher2]})
                 (dispatch-live!
                  :ns1
                  {:type :lock-intent
                   :escrow-id (:escrow-id royalty)
                   :payer (:payer royalty)
                   :receiver (:receiver royalty)
                   :sender (:payer royalty)
                   :amount (:amount royalty)
                   :puzzle-hash (:puzzle-hash royalty)
                   :created-epoch curr-ep
                   :expires-epoch royalty-exp
                   :nonce (:nonce royalty)})
                 (dispatch-live!
                  :ns2
                  {:type :lock-intent
                   :escrow-id (:escrow-id multisig)
                   :payer (:payer multisig)
                   :receiver (:receiver multisig)
                   :sender (:payer multisig)
                   :amount (:amount multisig)
                   :puzzle-hash (:puzzle-hash multisig)
                   :created-epoch curr-ep
                   :expires-epoch multisig-exp
                   :nonce (:nonce multisig)})
                 (dispatch-live!
                  :ns3
                  {:type :lock-intent
                   :escrow-id (:escrow-id htlc)
                   :payer (:payer htlc)
                   :receiver (:receiver htlc)
                   :sender (:payer htlc)
                   :amount (:amount htlc)
                   :deliverable-hash (:deliverable-hash htlc)
                   :created-epoch curr-ep
                   :expires-epoch htlc-exp
                   :nonce (:nonce htlc)})
                 (dispatch-live!
                  :node1
                  {:type :lock-intent
                   :escrow-id (:escrow-id timeout-c)
                   :payer (:payer timeout-c)
                   :receiver (:receiver timeout-c)
                   :sender (:payer timeout-c)
                   :amount (:amount timeout-c)
                   :deliverable-hash (:deliverable-hash timeout-c)
                   :created-epoch curr-ep
                   :expires-epoch timeout-exp
                   :nonce (:nonce timeout-c)}))]
           (println "=== [D15 LIVE GCP E2E] Submitting Batch 2 (tx2, tx3, vouchers, 4 smart-contract locks) ===")
           (send-batch-2!)
           (wait-for-live-condition!
            node1-ip
            "batch-2-locks-finalized"
            (fn [ac]
              (let [bals (extract-balances-map ac)
                    escs (extract-escrow-statuses-map ac)]
                (and (= 920000 (get bals (:pubkey-hex funder)))
                     (= 328850 (get bals (:pubkey-hex buyer2)))
                     (= :locked (get escs (:escrow-id royalty)))
                     (= :locked (get escs (:escrow-id multisig)))
                     (= :locked (get escs (:escrow-id htlc)))
                     (= :locked (get escs (:escrow-id timeout-c)))
                     (> (long (or (:epoch ac) 0)) (inc timeout-exp)))))
            send-batch-2!
            120000)
           (let [send-batch-3!
                 (fn []
                   (dispatch-live!
                    :ns1
                    {:type :release-intent
                     :escrow-id (:escrow-id royalty)
                     :puzzle-source (:puzzle-source royalty)
                     :solution (:solution royalty)
                     :sender (:receiver royalty)})
                   (dispatch-live!
                    :ns2
                    {:type :release-intent
                     :escrow-id (:escrow-id multisig)
                     :puzzle-source (:puzzle-source multisig)
                     :solution (:solution multisig)
                     :sender (:receiver multisig)})
                   (dispatch-live!
                    :ns3
                    {:type :release-intent
                     :escrow-id (:escrow-id htlc)
                     :preimage (:preimage htlc)
                     :sender (:receiver htlc)})
                   (dispatch-live!
                    :ns1
                    {:type :refund-intent
                     :escrow-id (:escrow-id timeout-c)
                     :sender (:payer timeout-c)}))]
             (println "=== [D15 LIVE GCP E2E] Submitting Batch 3 (3 SCI/HTLC releases + 1 timeout refund) ===")
             (send-batch-3!)
             (let [post-ac
                   (wait-for-live-condition!
                    node1-ip
                    "batch-3-settlements-finalized"
                    (fn [ac]
                      (let [escs (extract-escrow-statuses-map ac)]
                        (and (= :released (get escs (:escrow-id royalty)))
                             (= :released (get escs (:escrow-id multisig)))
                             (= :released (get escs (:escrow-id htlc)))
                             (= :refunded (get escs (:escrow-id timeout-c))))))
                    send-batch-3!
                    120000)
                   post-balances (extract-balances-map post-ac)
                   post-escrows (extract-escrow-statuses-map post-ac)
                   norm-parity (verify-normalized-live-parity pre-balances post-balances post-escrows golden)]
               (assoc norm-parity
                      :live-gcp-network? true
                      :connected-validators connected-vids
                      :finalized-epoch (:finalized-epoch post-ac)
                      :failed-receipts-count (:failed-receipts-count post-ac))))))
       (finally
         (doseq [[_ c] conns-by-vid]
           (close-live-agent-channel! c)))))))

(defn run-live-testnet-e2e!
  "Executes the Full-Surface E2E workload through the full Fressian wire & authenticated
   agent-ingress boundary (`harness/run-wire-boundary-e2e`) and verifies normalized
   balance-delta and escrow parity against `compute-golden-expected-state` (A-D15-6, B-OPUS-D15-3).
   If a live HTTP cluster is reachable at `http-urls`, queries `/accountz` across the cluster."
  ([] (run-live-testnet-e2e! {}))
  ([{:keys [http-urls]}]
   (let [scenario (workload/build-workload-scenario)
         golden (workload/compute-golden-expected-state scenario)
         live-accountz (when (seq http-urls)
                         (some #(fetch-http-edn (str % "/accountz") 1000) http-urls))
         wire-res (harness/run-wire-boundary-e2e)
         n1-hex (get-in scenario [:topology :validators-by-id :node1 :pubkey-hex])
         n1-state (get (:states wire-res) n1-hex)
         pre-balances (into {}
                            (map (fn [[pk v]] [pk (:balance v)])
                                 (get-in scenario [:topology :genesis-ledger])))
         post-balances (into {}
                             (map (fn [[pk v]] [pk (:balance v)])
                                  (:ledger n1-state)))
         post-escrows (into {}
                            (map (fn [[eid e]] [eid (:status e)])
                                 (:escrows n1-state)))
         norm-parity (verify-normalized-live-parity pre-balances post-balances post-escrows golden)]
     (assoc norm-parity
            :wire-boundary? (:wire-boundary? wire-res)
            :live-http-probed? (boolean live-accountz)
            :fressian-roundtrip-ok? (:fressian-roundtrip-ok? wire-res)
            :adversarial-rejections (:adversarial-rejections wire-res)))))

(defn -main
  "CLI entrypoint for running the Full-Surface E2E stress verification.
   Pass `--live-network` to execute over real UDP WebRTC DataChannels (:5010) against the live GCP cluster."
  [& args]
  (let [live-net? (some #(= "--live-network" %) args)
        res (if live-net?
              (run-live-gcp-cluster-e2e! "devnet/bootstrap.edn")
              (run-live-testnet-e2e!))]
    (println (pr-str (dissoc res :expected-deltas :actual-deltas)))
    (System/exit (if (:parity? res) 0 1))))
