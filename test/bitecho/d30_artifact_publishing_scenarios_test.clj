(ns bitecho.d30-artifact-publishing-scenarios-test
  "Milestone D30 (BIP-004 / v0.23.8) TDD Scenario & Generative Verification Suite:
   1. `pointer-publish-rollback-monotonicity-prop` (defspec)
   2. `p2p-shared-relay-candidate-and-shuttle-forward-prop` (defspec)
   3. `S-D30-1`: Live Pointer-first `serve-dist-request` cutover `v1 -> v2 -> rollback v1` + dynamic `.sha256` synthesis without restart
   4. `S-D30-2`: First-match Path-ACL stream isolation (`K_lumen`, `K_axiom`, `K_nexus`, `K_cold`)
   5. `S-D30-3`: Tombstone (`:pointer/target nil`) and `:subnet/denied-cids` hard-404 enforcement blocking disk fallback
   6. `S-D30-4`: Mid-fetch Tier-2 `Range` / `If-Match` / `?cid=` immutability across Pointer advance
   7. `S-D30-5`: 3-node in-memory mesh + HTTPS relay P2P broadcast propagation & `import-poll` live forwarding repro"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.light-node :as light-shell]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Helpers
;; =============================================================================

(defn- make-tmp-dir! ^File []
  (.toFile (Files/createTempDirectory "bitecho-d30-test-" (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^File dir]
  (when (and dir (.exists dir))
    (doseq [^File f (reverse (file-seq dir))]
      (try (.delete f) (catch Exception _ nil)))))

(defn- kp->pk-hex [kp]
  (str/lower-case (basalt/bytes->hex (or (:public kp) (:public-key kp)))))

(defn- kp->sk [kp]
  (or (:private kp) (:private-key kp)))

(defn- body->string [body]
  (cond
    (nil? body) ""
    (string? body) body
    (bytes? body) (String. ^bytes body StandardCharsets/UTF_8)
    (and (map? body) (:file body))
    (let [^File f (:file body)
          off (int (or (:offset body) 0))
          len (int (or (:length body) (.length f)))
          all-bs (Files/readAllBytes (.toPath f))]
      (String. all-bs off len StandardCharsets/UTF_8))
    (instance? File body)
    (slurp ^File body)
    :else (str body)))

;; =============================================================================
;; 1. Generative Property: Pointer Publish, Rollback, Tombstone, & Denied-CIDs
;; =============================================================================

(defspec ^{:doc "BIP-004: Generative sequence of valid/invalid publishes, rollbacks, tombstones, denied-CID revocations, and first-match path-ACL checks across dist/*, pkg/*, web/SKILL.md, blog/*, and web/index.html."}
  pointer-publish-rollback-monotonicity-prop
  40
  (prop/for-all
   [ops (gen/vector
         (gen/hash-map
          :role (gen/elements [:cold :nexus :axiom :lumen :anchor :stranger])
          :path (gen/elements ["dist/bitecho-light-node.cjs"
                               "pkg/mealy-0.1.0.jar"
                               "web/SKILL.md"
                               "blog/post-1.md"
                               "web/index.html"])
          :action (gen/elements [:publish :rollback :tombstone :deny-cid])
          :payload (gen/not-empty gen/string-alphanumeric))
         1 16)]
   (let [tmp-dir (make-tmp-dir!)
         cold-kp (crypto/generate-keypair "d30-prop-cold")
         nexus-kp (crypto/generate-keypair "d30-prop-nexus")
         axiom-kp (crypto/generate-keypair "d30-prop-axiom")
         lumen-kp (crypto/generate-keypair "d30-prop-lumen")
         anchor-kp (crypto/generate-keypair "d30-prop-anchor")
         stranger-kp (crypto/generate-keypair "d30-prop-stranger")
         k-cold (kp->pk-hex cold-kp)
         k-nexus (kp->pk-hex nexus-kp)
         k-axiom (kp->pk-hex axiom-kp)
         k-lumen (kp->pk-hex lumen-kp)
         k-anchor (kp->pk-hex anchor-kp)
         k-stranger (kp->pk-hex stranger-kp)
         role->kp {:cold cold-kp
                   :nexus nexus-kp
                   :axiom axiom-kp
                   :lumen lumen-kp
                   :anchor anchor-kp
                   :stranger stranger-kp}
         role->pk {:cold k-cold
                   :nexus k-nexus
                   :axiom k-axiom
                   :lumen k-lumen
                   :anchor k-anchor
                   :stranger k-stranger}
         authorized? (fn [role path]
                       (case path
                         "dist/bitecho-light-node.cjs" (contains? #{:cold :nexus} role)
                         "pkg/mealy-0.1.0.jar" (contains? #{:cold :nexus :axiom} role)
                         "web/SKILL.md" (contains? #{:cold :nexus :axiom :lumen :anchor} role)
                         "blog/post-1.md" (contains? #{:cold :nexus :axiom :lumen :anchor} role)
                         "web/index.html" (= :anchor role)
                         false))]
     (try
       (with-redefs [infra/k-cold-root-pubkey k-cold
                     infra/k-nexus-builder-pubkey k-nexus
                     infra/k-axiom-steward-pubkey k-axiom
                     infra/k-lumen-researcher-pubkey k-lumen]
         (let [pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                :trust-anchors [k-anchor]
                                                :cold-pubkey k-cold})
               rt (infra/start-subnet-runtime! {:policy pol
                                                :state-dir (.getAbsolutePath tmp-dir)
                                                :node-id k-anchor
                                                :all-nodes #{k-anchor}})
               step-fn
               (fn [model {:keys [role path action payload]}]
                 (let [kp (get role->kp role)
                       pk (get role->pk role)
                       sk (kp->sk kp)
                       cur-seq (long (get-in model [:seqs path] 0))
                       next-seq (inc cur-seq)
                       auth-ok? (authorized? role path)]
                   (case action
                     :publish
                     (let [blob (data/make-blob (str payload "-" next-seq) "text/plain")
                           _ (infra/put-blob! rt blob {:sender pk :now-ms 1000})
                           ptr (data/sign-pointer sk {:pointer/authority pk
                                                      :pointer/subnet "bitecho.org/infra"
                                                      :pointer/path path
                                                      :pointer/seq next-seq
                                                      :pointer/leader-term 1
                                                      :pointer/target (:blob/cid blob)
                                                      :pointer/proof {:proof/type :self}})
                           res (infra/submit-event! rt {:type :publish-pointer
                                                        :sender pk
                                                        :pointer ptr
                                                        :now-ms 1000})]
                       (if auth-ok?
                         (let [resolved (infra/resolve-path-blob! rt path 1000)
                               denied? (contains? (:denied model) (:blob/cid blob))]
                           (assoc model
                                  :ok? (and (:ok? model)
                                            (:applied? res)
                                            (if denied?
                                              (true? (:denied? resolved))
                                              (and (:ok? resolved)
                                                   (= (:blob/cid blob) (get-in resolved [:blob :blob/cid])))))
                                  :seqs (assoc (:seqs model) path next-seq)
                                  :history (update (:history model) path (fnil conj []) (:blob/cid blob))
                                  :tombstoned (disj (:tombstoned model) path)))
                         (assoc model
                                :ok? (and (:ok? model)
                                          (false? (:applied? res))))))

                     :rollback
                     (let [prev-cid (first (get-in model [:history path]))]
                       (if (or (nil? prev-cid) (not auth-ok?))
                         model
                         (let [ptr (data/sign-pointer sk {:pointer/authority pk
                                                          :pointer/subnet "bitecho.org/infra"
                                                          :pointer/path path
                                                          :pointer/seq next-seq
                                                          :pointer/leader-term 1
                                                          :pointer/target prev-cid
                                                          :pointer/proof {:proof/type :self}})
                               res (infra/submit-event! rt {:type :publish-pointer
                                                            :sender pk
                                                            :pointer ptr
                                                            :now-ms 1000})
                               resolved (infra/resolve-path-blob! rt path 1000)
                               denied? (contains? (:denied model) prev-cid)]
                           (assoc model
                                  :ok? (and (:ok? model)
                                            (:applied? res)
                                            (if denied?
                                              (true? (:denied? resolved))
                                              (and (:ok? resolved)
                                                   (= prev-cid (get-in resolved [:blob :blob/cid])))))
                                  :seqs (assoc (:seqs model) path next-seq)
                                  :tombstoned (disj (:tombstoned model) path)))))

                     :tombstone
                     (if-not auth-ok?
                       model
                       (let [ptr (data/sign-pointer sk {:pointer/authority pk
                                                        :pointer/subnet "bitecho.org/infra"
                                                        :pointer/path path
                                                        :pointer/seq next-seq
                                                        :pointer/leader-term 1
                                                        :pointer/target nil
                                                        :pointer/proof {:proof/type :self}})
                             res (infra/submit-event! rt {:type :publish-pointer
                                                          :sender pk
                                                          :pointer ptr
                                                          :now-ms 1000})
                             resolved (infra/resolve-path-blob! rt path 1000)]
                         (assoc model
                                :ok? (and (:ok? model)
                                          (:applied? res)
                                          (false? (:ok? resolved))
                                          (true? (:denied? resolved))
                                          (true? (:tombstoned? resolved)))
                                :seqs (assoc (:seqs model) path next-seq)
                                :tombstoned (conj (:tombstoned model) path))))

                     :deny-cid
                     (let [active-ptr (or (get-in @(:subnet-atom rt) [:pointers path])
                                          (get-in @(:subnet-atom rt) [:data :pointers ["bitecho.org/infra" path]]))
                           target-cid (:pointer/target active-ptr)]
                       (if (nil? target-cid)
                         model
                         (let [cur-pol (:policy @(:subnet-atom rt))
                               new-denied (conj (set (:subnet/denied-cids cur-pol #{})) target-cid)
                               new-pol (assoc (dissoc cur-pol :subnet/genesis-policy-cid)
                                              :subnet/denied-cids new-denied)
                               pol-blob (data/make-blob (fressian/encode-canonical new-pol) "application/fressian")
                               pol-seq (inc (long (:pol-seq model 0)))
                               _ (infra/put-blob! rt pol-blob {:sender k-cold :now-ms 1000})
                               pol-ptr (data/sign-pointer (kp->sk cold-kp)
                                                          {:pointer/authority k-cold
                                                           :pointer/subnet "bitecho.org/infra"
                                                           :pointer/path "subnet/policy"
                                                           :pointer/seq pol-seq
                                                           :pointer/leader-term 1
                                                           :pointer/target (:blob/cid pol-blob)
                                                           :pointer/proof {:proof/type :self}})
                               pol-res (infra/submit-event! rt {:type :publish-pointer
                                                                :sender k-cold
                                                                :pointer pol-ptr
                                                                :now-ms 1000})
                               resolved (infra/resolve-path-blob! rt path 1000)]
                           (assoc model
                                  :ok? (and (:ok? model)
                                            (:applied? pol-res)
                                            (false? (:ok? resolved))
                                            (true? (:denied? resolved)))
                                  :pol-seq pol-seq
                                  :denied new-denied)))))))
               final-model (reduce step-fn
                                   {:ok? true :seqs {} :history {} :tombstoned #{} :denied #{} :pol-seq 0}
                                   ops)]
           (boolean (:ok? final-model))))
       (finally
         (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 2. Generative Property: Shared Relay Candidate Preservation & Shuttle Forward
;; =============================================================================

(defspec ^{:doc "BIP-004: handle-wire-p2p-answer and handle-wire-p2p-offer preserve shared https/http relay candidates (with fallback diagnostic when non-relay candidates self-filter to empty), and handle-serve-line! forwards import-poll broadcasts when P2P peers are live vs. counting :shuttle-import-forward-deferred when offline."}
  p2p-shared-relay-candidate-and-shuttle-forward-prop
  30
  (prop/for-all
   [relay-https? gen/boolean
    include-lan? gen/boolean
    p2p-live? gen/boolean
    bcast-text (gen/not-empty gen/string-alphanumeric)]
   (let [alice-kp (crypto/generate-keypair "d30-alice")
         bob-kp (crypto/generate-keypair "d30-bob")
         carol-kp (crypto/generate-keypair "d30-carol")
         alice-pk (kp->pk-hex alice-kp)
         bob-pk (kp->pk-hex bob-kp)
         carol-pk (kp->pk-hex carol-kp)
         shared-relay (if relay-https?
                        "https://nexus.ingress.bitecho.org/relay/v1"
                        "http://127.0.0.1:18080/relay/v1")
         same-lan "udp://192.168.1.10:5011"
         cands (if include-lan? [shared-relay same-lan] [shared-relay])
         sid "sess-shared-relay"
         alice-st (-> (light-core/init-light-state {:pubkey-hex alice-pk} {:subnet-id "devnet.bitecho.org" :epoch 5})
                      (assoc-in [:sessions sid] {:session-id sid
                                                 :peer bob-pk
                                                 :state "open"
                                                 :epoch 5
                                                 :p2p {:phase :offered
                                                       :connected? false
                                                       :local-candidates cands}
                                                 :p2p-meta {:local-candidates cands}}))
         bob-st (-> (light-core/init-light-state {:pubkey-hex bob-pk} {:subnet-id "devnet.bitecho.org" :epoch 5})
                    (assoc-in [:sessions sid] {:session-id sid
                                               :peer alice-pk
                                               :state "open"
                                               :epoch 5
                                               :p2p {:phase :open
                                                     :connected? true
                                                     :local-candidates cands}
                                               :p2p-meta {:local-candidates cands}}))
         ;; Bob sends p2p-answer with identical cands
         ans-res (light-core/handle-command bob-st
                                            {"cmd" "p2p-answer"
                                             "session_id" sid
                                             "transport" "https"
                                             "candidates" cands}
                                            (kp->sk bob-kp))
         ans-env (first (:net-envelopes ans-res))
         ans-wire-res (light-core/handle-wire-payload alice-st ans-env (kp->sk alice-kp))
         ans-dial (:p2p-dial ans-wire-res)
         ;; Also test handle-wire-p2p-offer when session is already connected
         off-res (light-core/handle-command alice-st
                                            {"cmd" "p2p-offer"
                                             "session_id" sid
                                             "transport" "https"
                                             "candidates" cands}
                                            (kp->sk alice-kp))
         off-env (first (:net-envelopes off-res))
         off-wire-res (light-core/handle-wire-payload bob-st off-env (kp->sk bob-kp))
         off-dial (:p2p-dial off-wire-res)
         ;; Now test import-poll broadcast forwarding in handle-serve-line!
         carol-st (light-core/init-light-state {:pubkey-hex carol-pk} {:subnet-id "devnet.bitecho.org" :epoch 5})
         bcast-res (light-core/handle-command carol-st
                                              {"cmd" "broadcast"
                                               "subnet_id" "devnet.bitecho.org"
                                               "text" bcast-text}
                                              (kp->sk carol-kp))
         bcast-env (first (:net-envelopes bcast-res))
         bcast-hex (basalt/bytes->hex (fressian/encode-canonical bcast-env))
         poll-json (json/write-str {"ok" true
                                    "messages" []
                                    "broadcasts" [{"broadcast_seq" 1 "envelope_hex" bcast-hex}]})
         hub-st (-> (light-core/init-light-state {:pubkey-hex bob-pk} {:subnet-id "devnet.bitecho.org" :epoch 5})
                    (assoc-in [:sessions sid] {:session-id sid
                                               :peer alice-pk
                                               :state "open"
                                               :epoch 5
                                               :p2p {:phase :open :connected? true}}))
         hub-state-atom (atom hub-st)
         forwarded-atom (atom [])
         p2p-peers-atom (atom (if p2p-live?
                                {alice-pk {:send-fn (fn [env] (swap! forwarded-atom conj env) true)
                                           :session-id sid
                                           :generation 1}}
                                {}))
         conn-atom (atom {:phase :down :ok? false})
         serve-res (light-shell/handle-serve-line!
                    {"cmd" "import-poll" "payload" poll-json}
                    {:state-atom hub-state-atom
                     :conn-atom conn-atom
                     :p2p-peers-atom p2p-peers-atom
                     :ingress-peers-atom (atom {})
                     :identity {:pubkey-hex bob-pk :privkey-bytes (kp->sk bob-kp)}})]
     (and (some? ans-dial)
          (contains? (set (:remote-candidates ans-dial)) shared-relay)
          (some? off-dial)
          (contains? (set (:remote-candidates off-dial)) shared-relay)
          (true? (get serve-res "ok"))
          (if p2p-live?
            (= 1 (count @forwarded-atom))
            (and (zero? (count @forwarded-atom))
                 (= 1 (get serve-res "pending_forward_count"))
                 (pos? (long (get-in @hub-state-atom [:diagnostics :shuttle-import-forward-deferred] 0)))))))))

;; =============================================================================
;; 3. Scenario S-D30-1: Live Pointer-First `serve-dist-request`, `.sha256`
;;    Synthesis, `/artifact/v1/{blob,pointer,list}`, & Light-Node Artifact Verbs
;; =============================================================================

(deftest scenario-s-d30-1-live-pointer-first-dist-cutover-and-artifact-verbs
  (testing "S-D30-1: serve-dist-request resolves live Pointer first, synthesizes .sha256, and supports O(1) rollback without restart"
    (let [tmp-dir (make-tmp-dir!)
          dist-dir (io/file tmp-dir "dist")
          state-dir (io/file tmp-dir "infra-state")
          _ (.mkdirs dist-dir)
          _ (.mkdirs state-dir)
          ;; Disk baseline v0
          disk-cjs (io/file dist-dir "bitecho-light-node.cjs")
          _ (spit disk-cjs "// disk baseline v0\n")
          cold-kp (crypto/generate-keypair "s-d30-1-cold")
          nexus-kp (crypto/generate-keypair "s-d30-1-nexus")
          k-cold (kp->pk-hex cold-kp)
          k-nexus (kp->pk-hex nexus-kp)]
      (try
        (with-redefs [infra/k-cold-root-pubkey k-cold
                      infra/k-nexus-builder-pubkey k-nexus]
          (let [pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                 :trust-anchors [k-cold]
                                                 :cold-pubkey k-cold})
                rt (infra/start-subnet-runtime! {:policy pol
                                                 :state-dir (.getAbsolutePath state-dir)
                                                 :node-id k-cold
                                                 :all-nodes #{k-cold}})
                ctx {:config {:dist-dir (.getAbsolutePath dist-dir)}
                     :rt rt}]
            ;; 0. Before any Pointer is published, falls back to disk v0
            (let [r0 (http/serve-dist-request "/dist/bitecho-light-node.cjs" ctx)]
              (is (= 200 (:status r0)))
              (is (= "// disk baseline v0\n" (body->string (:body r0)))))

            ;; 1. Publish v1 via K_nexus at seq 1
            (let [v1-bytes (.getBytes "// bundle release v1\n" StandardCharsets/UTF_8)
                  blob-v1 (data/make-blob v1-bytes "application/javascript; charset=utf-8")
                  cid-v1 (:blob/cid blob-v1)
                  pub-res1 (infra/publish-blob-and-pointer!
                            rt
                            {:blob blob-v1
                             :path "dist/bitecho-light-node.cjs"
                             :authority-pubkey k-nexus
                             :authority-privkey (kp->sk nexus-kp)
                             :seq 1
                             :now-ms 1000})]
              (is (true? (:applied? pub-res1)))
              (let [r1 (http/serve-dist-request "/dist/bitecho-light-node.cjs" ctx)
                    r1-sha (http/serve-dist-request "/dist/bitecho-light-node.cjs.sha256" ctx)]
                (is (= 200 (:status r1)))
                (is (= "// bundle release v1\n" (body->string (:body r1))))
                (is (= (str "\"" cid-v1 "\"") (get-in r1 [:headers "ETag"])))
                (is (= cid-v1 (get-in r1 [:headers "X-Bitecho-Blob-Cid"])))
                (is (= k-nexus (get-in r1 [:headers "X-Bitecho-Pointer-Pubkey"])))
                (is (= "1" (get-in r1 [:headers "X-Bitecho-Pointer-Seq"])))
                (is (string? (get-in r1 [:headers "X-Bitecho-Pointer-Signature"])))
                ;; Dynamic .sha256 synthesis from active Pointer
                (is (= 200 (:status r1-sha)))
                (is (= (str cid-v1 "  bitecho-light-node.cjs\n") (body->string (:body r1-sha))))
                (is (= cid-v1 (get-in r1-sha [:headers "X-Bitecho-Blob-Cid"])))
                (is (= "1" (get-in r1-sha [:headers "X-Bitecho-Pointer-Seq"]))))

              ;; 2. Publish v2 via K_nexus at seq 2 -> zero-restart cutover
              (let [v2-bytes (.getBytes "// bundle release v2\n" StandardCharsets/UTF_8)
                    blob-v2 (data/make-blob v2-bytes "application/javascript; charset=utf-8")
                    cid-v2 (:blob/cid blob-v2)
                    pub-res2 (infra/publish-blob-and-pointer!
                              rt
                              {:blob blob-v2
                               :path "dist/bitecho-light-node.cjs"
                               :authority-pubkey k-nexus
                               :authority-privkey (kp->sk nexus-kp)
                               :seq 2
                               :now-ms 2000})]
                (is (true? (:applied? pub-res2)))
                (let [r2 (http/serve-dist-request "/dist/bitecho-light-node.cjs" ctx)
                      r2-sha (http/serve-dist-request "/dist/bitecho-light-node.cjs.sha256" ctx)]
                  (is (= 200 (:status r2)))
                  (is (= "// bundle release v2\n" (body->string (:body r2))))
                  (is (= cid-v2 (get-in r2 [:headers "X-Bitecho-Blob-Cid"])))
                  (is (= "2" (get-in r2 [:headers "X-Bitecho-Pointer-Seq"])))
                  (is (= (str cid-v2 "  bitecho-light-node.cjs\n") (body->string (:body r2-sha)))))

                ;; 3. O(1) Rollback to v1 at seq 3 (without re-uploading blob-v1!)
                (let [rollback-ptr (data/sign-pointer (kp->sk nexus-kp)
                                                      {:pointer/authority k-nexus
                                                       :pointer/subnet "bitecho.org/infra"
                                                       :pointer/path "dist/bitecho-light-node.cjs"
                                                       :pointer/seq 3
                                                       :pointer/leader-term 1
                                                       :pointer/target cid-v1
                                                       :pointer/proof {:proof/type :self}})
                      rb-res (infra/submit-event! rt {:type :publish-pointer
                                                      :sender k-nexus
                                                      :pointer rollback-ptr
                                                      :now-ms 3000})
                      r3 (http/serve-dist-request "/dist/bitecho-light-node.cjs" ctx)
                      r3-sha (http/serve-dist-request "/dist/bitecho-light-node.cjs.sha256" ctx)]
                  (is (true? (:applied? rb-res)))
                  (is (= 200 (:status r3)))
                  (is (= "// bundle release v1\n" (body->string (:body r3))))
                  (is (= cid-v1 (get-in r3 [:headers "X-Bitecho-Blob-Cid"])))
                  (is (= "3" (get-in r3 [:headers "X-Bitecho-Pointer-Seq"])))
                  (is (= (str cid-v1 "  bitecho-light-node.cjs\n") (body->string (:body r3-sha)))))))

            ;; 4. Live HTTP /artifact/v1/{blob,pointer,list} + light-node artifact verbs
            (let [tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath state-dir)
                                                   :domain "localhost"})
                  servers (http/start-http-servers! {:domain "localhost"
                                                     :http {:bind-ip "127.0.0.1"
                                                            :http-port 0
                                                            :https-port 0
                                                            :dist-dir (.getAbsolutePath dist-dir)}}
                                                    tls-mgr
                                                    rt)]
              (try
                (let [http-port (:http-port servers)
                      base-url (str "http://127.0.0.1:" http-port)
                      ln-st0 (light-core/init-light-state {:pubkey-hex k-nexus} {:subnet-id "bitecho.org/infra"})
                      put-res (light-core/handle-command ln-st0
                                                         {"cmd" "artifact-put"
                                                          "subnet_id" "bitecho.org/infra"
                                                          "path" "web/SKILL.md"
                                                          "text" "# Bitecho Skill v2\n"
                                                          "seq" 1}
                                                         (kp->sk nexus-kp))
                      ln-st1 (:state put-res)
                      skill-cid (get-in put-res [:response "cid"])
                      get-res (light-core/handle-command ln-st1
                                                         {"cmd" "artifact-get"
                                                          "subnet_id" "bitecho.org/infra"
                                                          "path" "web/SKILL.md"}
                                                         (kp->sk nexus-kp))
                      list-res (light-core/handle-command ln-st1
                                                          {"cmd" "artifact-list"
                                                           "subnet_id" "bitecho.org/infra"}
                                                          (kp->sk nexus-kp))]
                  (is (true? (get-in put-res [:response "ok"])))
                  (is (= "web/SKILL.md" (get-in put-res [:response "path"])))
                  (is (true? (get-in get-res [:response "ok"])))
                  (is (= "# Bitecho Skill v2\n" (get-in get-res [:response "text"])))
                  (is (= 1 (get-in list-res [:response "count"])))

                  ;; Push blob and pointer to /artifact/v1/{blob,pointer} over HTTP
                  (let [client (HttpClient/newHttpClient)
                        blob-body (json/write-str {"bytes_hex" (basalt/bytes->hex (.getBytes "# Bitecho Skill v2\n" StandardCharsets/UTF_8))
                                                   "cid" skill-cid
                                                   "media_type" "text/markdown; charset=utf-8"})
                        b-req (-> (HttpRequest/newBuilder (URI/create (str base-url "/artifact/v1/blob")))
                                  (.header "Content-Type" "application/json")
                                  (.POST (HttpRequest$BodyPublishers/ofString blob-body StandardCharsets/UTF_8))
                                  (.build))
                        b-resp (.send client b-req (HttpResponse$BodyHandlers/ofString))
                        ptr-map (get-in put-res [:response "pointer"])
                        p-req (-> (HttpRequest/newBuilder (URI/create (str base-url "/artifact/v1/pointer")))
                                  (.header "Content-Type" "application/edn")
                                  (.POST (HttpRequest$BodyPublishers/ofString (pr-str ptr-map) StandardCharsets/UTF_8))
                                  (.build))
                        p-resp (.send client p-req (HttpResponse$BodyHandlers/ofString))
                        l-req (-> (HttpRequest/newBuilder (URI/create (str base-url "/artifact/v1/list")))
                                  (.GET)
                                  (.build))
                        l-resp (.send client l-req (HttpResponse$BodyHandlers/ofString))]
                    (is (= 200 (.statusCode b-resp)))
                    (is (true? (get (json/read-str (.body b-resp)) "ok")))
                    (is (= 200 (.statusCode p-resp)))
                    (is (true? (get (json/read-str (.body p-resp)) "ok")))
                    (is (= 200 (.statusCode l-resp)))
                    (is (pos? (get (json/read-str (.body l-resp)) "count"))))

                  ;; Revoke artifact on light node
                  (let [rev-res (light-core/handle-command ln-st1
                                                           {"cmd" "artifact-revoke"
                                                            "subnet_id" "bitecho.org/infra"
                                                            "path" "web/SKILL.md"
                                                            "seq" 2}
                                                           (kp->sk nexus-kp))
                        ln-st2 (:state rev-res)
                        get-after-rev (light-core/handle-command ln-st2
                                                                 {"cmd" "artifact-get"
                                                                  "subnet_id" "bitecho.org/infra"
                                                                  "path" "web/SKILL.md"}
                                                                 (kp->sk nexus-kp))]
                    (is (true? (get-in rev-res [:response "ok"])))
                    (is (true? (get-in rev-res [:response "tombstoned"])))
                    (is (false? (get-in get-after-rev [:response "ok"])))))
                (finally
                  (http/stop-http-servers! servers))))))
        (finally
          (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 4. Scenario S-D30-2: First-Match Path-ACL Stream Isolation
;; =============================================================================

(deftest scenario-s-d30-2-first-match-path-acl-stream-isolation
  (testing "S-D30-2: K_lumen succeeds on web/SKILL.md and blog/post-1.md, fails closed with :unauthorized-pointer-authority on dist/bitecho-light-node.cjs and web/index.html"
    (let [tmp-dir (make-tmp-dir!)
          cold-kp (crypto/generate-keypair "s-d30-2-cold")
          nexus-kp (crypto/generate-keypair "s-d30-2-nexus")
          axiom-kp (crypto/generate-keypair "s-d30-2-axiom")
          lumen-kp (crypto/generate-keypair "s-d30-2-lumen")
          anchor-kp (crypto/generate-keypair "s-d30-2-anchor")
          k-cold (kp->pk-hex cold-kp)
          k-nexus (kp->pk-hex nexus-kp)
          k-axiom (kp->pk-hex axiom-kp)
          k-lumen (kp->pk-hex lumen-kp)
          k-anchor (kp->pk-hex anchor-kp)]
      (try
        (with-redefs [infra/k-cold-root-pubkey k-cold
                      infra/k-nexus-builder-pubkey k-nexus
                      infra/k-axiom-steward-pubkey k-axiom
                      infra/k-lumen-researcher-pubkey k-lumen]
          (let [pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                 :trust-anchors [k-anchor]
                                                 :cold-pubkey k-cold})
                rt (infra/start-subnet-runtime! {:policy pol
                                                 :state-dir (.getAbsolutePath tmp-dir)
                                                 :node-id k-anchor
                                                 :all-nodes #{k-anchor}})
                attempt-publish!
                (fn [kp path content]
                  (let [pk (kp->pk-hex kp)
                        sk (kp->sk kp)
                        blob (data/make-blob content "text/plain")
                        _ (infra/put-blob! rt blob {:sender pk :now-ms 1000})
                        ptr (data/sign-pointer sk {:pointer/authority pk
                                                   :pointer/subnet "bitecho.org/infra"
                                                   :pointer/path path
                                                   :pointer/seq 1
                                                   :pointer/leader-term 1
                                                   :pointer/target (:blob/cid blob)
                                                   :pointer/proof {:proof/type :self}})]
                    (infra/submit-event! rt {:type :publish-pointer
                                             :sender pk
                                             :pointer ptr
                                             :now-ms 1000})))]
            ;; K_lumen succeeds on web/SKILL.md and blog/post-1.md
            (let [r-skill (attempt-publish! lumen-kp "web/SKILL.md" "# Skill by Lumen\n")
                  r-blog (attempt-publish! lumen-kp "blog/post-1.md" "# Blog by Lumen\n")]
              (is (true? (:applied? r-skill)))
              (is (true? (:applied? r-blog))))

            ;; K_lumen fails closed with :unauthorized-pointer-authority on dist/* and web/index.html
            (let [r-dist (attempt-publish! lumen-kp "dist/bitecho-light-node.cjs" "malicious-bundle")
                  r-index (attempt-publish! lumen-kp "web/index.html" "<html>hijacked</html>")]
              (is (false? (:applied? r-dist)))
              (is (= :unauthorized-pointer-authority (:error r-dist)))
              (is (false? (:applied? r-index)))
              (is (= :unauthorized-pointer-authority (:error r-index))))

            ;; K_axiom succeeds on pkg/*, fails closed on dist/*
            (let [r-pkg (attempt-publish! axiom-kp "pkg/mealy-0.1.0.jar" "jar-bytes")
                  r-dist-ax (attempt-publish! axiom-kp "dist/bitecho-light-node.cjs" "ax-bundle")]
              (is (true? (:applied? r-pkg)))
              (is (false? (:applied? r-dist-ax)))
              (is (= :unauthorized-pointer-authority (:error r-dist-ax))))))
        (finally
          (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 5. Scenario S-D30-3: Tombstone & `:subnet/denied-cids` Hard-404 Enforcement
;; =============================================================================

(deftest scenario-s-d30-3-tombstone-and-denied-cids-hard-404
  (testing "S-D30-3: Tombstone (:pointer/target nil) and :subnet/denied-cids both return hard 404 Not Found and block fallback to disk dist/ and content-root"
    (let [tmp-dir (make-tmp-dir!)
          dist-dir (io/file tmp-dir "dist")
          content-root (io/file tmp-dir "web-root")
          state-dir (io/file tmp-dir "infra-state")
          _ (.mkdirs dist-dir)
          _ (.mkdirs content-root)
          _ (.mkdirs state-dir)
          ;; Legacy files present on disk
          _ (spit (io/file dist-dir "bitecho-light-node.cjs") "// legacy disk dist\n")
          _ (spit (io/file dist-dir "bitecho-light-node.cjs.sha256") "0000  bitecho-light-node.cjs\n")
          _ (spit (io/file content-root "SKILL.md") "# legacy disk skill\n")
          cold-kp (crypto/generate-keypair "s-d30-3-cold")
          nexus-kp (crypto/generate-keypair "s-d30-3-nexus")
          lumen-kp (crypto/generate-keypair "s-d30-3-lumen")
          k-cold (kp->pk-hex cold-kp)
          k-nexus (kp->pk-hex nexus-kp)
          k-lumen (kp->pk-hex lumen-kp)]
      (try
        (with-redefs [infra/k-cold-root-pubkey k-cold
                      infra/k-nexus-builder-pubkey k-nexus
                      infra/k-lumen-researcher-pubkey k-lumen]
          (let [pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                 :trust-anchors [k-cold]
                                                 :cold-pubkey k-cold})
                rt (infra/start-subnet-runtime! {:policy pol
                                                 :state-dir (.getAbsolutePath state-dir)
                                                 :node-id k-cold
                                                 :all-nodes #{k-cold}})
                shell-atom (atom (infra/init-shell-state :http-test))
                cfg {:http {:dist-dir (.getAbsolutePath dist-dir)
                            :content-root (.getAbsolutePath content-root)}}
                ctx {:config cfg :rt rt}]
            ;; 1. Publish v1 of dist/bitecho-light-node.cjs, then tombstone it at seq 2
            (let [blob-v1 (data/make-blob "// v1 bundle\n" "application/javascript")
                  _ (infra/publish-blob-and-pointer! rt {:blob blob-v1
                                                         :path "dist/bitecho-light-node.cjs"
                                                         :authority-pubkey k-nexus
                                                         :authority-privkey (kp->sk nexus-kp)
                                                         :seq 1
                                                         :now-ms 1000})
                  tomb-ptr (data/sign-pointer (kp->sk nexus-kp)
                                              {:pointer/authority k-nexus
                                               :pointer/subnet "bitecho.org/infra"
                                               :pointer/path "dist/bitecho-light-node.cjs"
                                               :pointer/seq 2
                                               :pointer/leader-term 1
                                               :pointer/target nil
                                               :pointer/proof {:proof/type :self}})
                  tomb-res (infra/submit-event! rt {:type :publish-pointer
                                                    :sender k-nexus
                                                    :pointer tomb-ptr
                                                    :now-ms 2000})
                  resolved (infra/resolve-path-blob! rt "dist/bitecho-light-node.cjs" 2000)
                  http-cjs (http/serve-dist-request "/dist/bitecho-light-node.cjs" ctx)
                  http-sha (http/serve-dist-request "/dist/bitecho-light-node.cjs.sha256" ctx)]
              (is (true? (:applied? tomb-res)))
              (is (true? (:denied? resolved)))
              (is (true? (:tombstoned? resolved)))
              (is (= 404 (:status http-cjs)) "Tombstoned dist path must return hard 404 without falling back to disk dist/")
              (is (= 404 (:status http-sha)) "Tombstoned dist .sha256 must return hard 404 without falling back to disk dist/"))

            ;; 2. Publish web/SKILL.md with bad-cid, then add bad-cid to :subnet/denied-cids in subnet/policy
            (let [bad-blob (data/make-blob "# compromised skill\n" "text/markdown")
                  bad-cid (:blob/cid bad-blob)
                  _ (infra/publish-blob-and-pointer! rt {:blob bad-blob
                                                         :path "web/SKILL.md"
                                                         :authority-pubkey k-lumen
                                                         :authority-privkey (kp->sk lumen-kp)
                                                         :seq 1
                                                         :now-ms 3000})
                  ;; Before deny-list: serves 200
                  req-skill {:request/method :GET
                             :request/uri {:scheme "https" :host "bitecho.org" :path "/SKILL.md"}
                             :request/headers {}
                             :request/remote-ip "127.0.0.1"}
                  resp-before (http/serve-subnet-request cfg shell-atom rt req-skill 3000)]
              (is (= 200 (:response/status resp-before)))
              ;; Step 1 of two-step revocation: Tier-0 updates subnet/policy with :subnet/denied-cids #{bad-cid}
              (let [cur-pol (:policy @(:subnet-atom rt))
                    new-pol (assoc (dissoc cur-pol :subnet/genesis-policy-cid)
                                   :subnet/denied-cids #{bad-cid})
                    pol-blob (data/make-blob (fressian/encode-canonical new-pol) "application/fressian")
                    _ (infra/put-blob! rt pol-blob {:sender k-cold :now-ms 4000})
                    pol-ptr (data/sign-pointer (kp->sk cold-kp)
                                               {:pointer/authority k-cold
                                                :pointer/subnet "bitecho.org/infra"
                                                :pointer/path "subnet/policy"
                                                :pointer/seq 1
                                                :pointer/leader-term 1
                                                :pointer/target (:blob/cid pol-blob)
                                                :pointer/proof {:proof/type :self}})
                    pol-res (infra/submit-event! rt {:type :publish-pointer
                                                     :sender k-cold
                                                     :pointer pol-ptr
                                                     :now-ms 4000})
                    resolved-after (infra/resolve-path-blob! rt "web/SKILL.md" 4000)
                    resp-after (http/serve-subnet-request cfg shell-atom rt req-skill 4000)]
                (is (true? (:applied? pol-res)))
                (is (true? (:denied? resolved-after)))
                (is (= 404 (:response/status resp-after))
                    "Denied CID must return hard 404 immediately and never fall back to disk content-root")))))
        (finally
          (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 6. Scenario S-D30-4: Mid-Fetch Tier-2 Range / If-Match Immutability
;; =============================================================================

(deftest scenario-s-d30-4-mid-fetch-range-immutability-across-pointer-advance
  (testing "S-D30-4: In-flight byte-range fetch with If-Match or ?cid= completes cleanly from cid-v1 after Pointer advances to cid-v2"
    (let [tmp-dir (make-tmp-dir!)
          state-dir (io/file tmp-dir "infra-state")
          _ (.mkdirs state-dir)
          cold-kp (crypto/generate-keypair "s-d30-4-cold")
          nexus-kp (crypto/generate-keypair "s-d30-4-nexus")
          k-cold (kp->pk-hex cold-kp)
          k-nexus (kp->pk-hex nexus-kp)]
      (try
        (with-redefs [infra/k-cold-root-pubkey k-cold
                      infra/k-nexus-builder-pubkey k-nexus]
          (let [pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                 :trust-anchors [k-cold]
                                                 :cold-pubkey k-cold})
                rt (infra/start-subnet-runtime! {:policy pol
                                                 :state-dir (.getAbsolutePath state-dir)
                                                 :node-id k-cold
                                                 :all-nodes #{k-cold}})
                v1-str "0123456789abcdeffedcba9876543210"
                v2-str "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                blob-v1 (data/make-blob v1-str "application/javascript")
                blob-v2 (data/make-blob v2-str "application/javascript")
                cid-v1 (:blob/cid blob-v1)
                ctx {:config {:http {:cache-max-file-bytes 8}} :rt rt}]
            ;; Publish v1 at seq 1
            (infra/publish-blob-and-pointer! rt {:blob blob-v1
                                                 :path "dist/bitecho-light-node.cjs"
                                                 :authority-pubkey k-nexus
                                                 :authority-privkey (kp->sk nexus-kp)
                                                 :seq 1
                                                 :now-ms 1000})
            ;; Client fetches first half of v1 (bytes 0-15)
            (let [r-chunk1 (http/serve-dist-request "/dist/bitecho-light-node.cjs"
                                                    (assoc ctx :headers {:header/range ["bytes=0-15"]}))]
              (is (= 206 (:status r-chunk1)))
              (is (= "0123456789abcdef" (body->string (:body r-chunk1))))
              (is (= (str "\"" cid-v1 "\"") (get-in r-chunk1 [:headers "ETag"]))))

            ;; Pointer advances to v2 at seq 2 mid-download!
            (infra/publish-blob-and-pointer! rt {:blob blob-v2
                                                 :path "dist/bitecho-light-node.cjs"
                                                 :authority-pubkey k-nexus
                                                 :authority-privkey (kp->sk nexus-kp)
                                                 :seq 2
                                                 :now-ms 2000})

            ;; Client fetches second half (bytes 16-31) pinned to cid-v1 via If-Match: "<cid-v1>"
            (let [r-chunk2 (http/serve-dist-request "/dist/bitecho-light-node.cjs"
                                                    (assoc ctx :headers {:header/range ["bytes=16-31"]
                                                                         :header/if-match [(str "\"" cid-v1 "\"")]}))]
              (is (= 206 (:status r-chunk2)))
              (is (= "fedcba9876543210" (body->string (:body r-chunk2))))
              (is (= (str "\"" cid-v1 "\"") (get-in r-chunk2 [:headers "ETag"])))
              (is (= "0123456789abcdeffedcba9876543210"
                     (str (body->string (:body (http/serve-dist-request "/dist/bitecho-light-node.cjs"
                                                                        (assoc ctx :headers {:header/range ["bytes=0-15"]
                                                                                             :header/if-match [(str "\"" cid-v1 "\"")]}))))
                          (body->string (:body r-chunk2))))))))
        (finally
          (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 7. Scenario S-D30-5: 3-Node Mesh + HTTPS Relay P2P Broadcast & `import-poll`
;; =============================================================================

(deftest scenario-s-d30-5-three-node-https-relay-p2p-broadcast-and-import-poll
  (testing "S-D30-5: 3-node in-memory mesh (Simon, Nexus, Axiom) + HTTPS relay P2P candidate + import-poll live broadcast forwarding (Axiom seq: 320 repro)"
    (let [simon-kp (crypto/generate-keypair "s-d30-5-simon")
          nexus-kp (crypto/generate-keypair "s-d30-5-nexus")
          axiom-kp (crypto/generate-keypair "s-d30-5-axiom")
          simon-pk (kp->pk-hex simon-kp)
          nexus-pk (kp->pk-hex nexus-kp)
          axiom-pk (kp->pk-hex axiom-kp)
          shared-relay "https://nexus.ingress.bitecho.org/relay/v1"
          sid-sn "sess-simon-nexus"
          simon-st0 (-> (light-core/init-light-state {:pubkey-hex simon-pk} {:subnet-id "devnet.bitecho.org" :epoch 10})
                        (assoc :subscribed-subnets #{"chat/simon-nexus-axiom"})
                        (assoc-in [:sessions sid-sn] {:session-id sid-sn
                                                      :peer nexus-pk
                                                      :state "open"
                                                      :epoch 10}))
          nexus-st0 (-> (light-core/init-light-state {:pubkey-hex nexus-pk} {:subnet-id "devnet.bitecho.org" :epoch 10})
                        (assoc :subscribed-subnets #{"chat/simon-nexus-axiom"})
                        (assoc-in [:sessions sid-sn] {:session-id sid-sn
                                                      :peer simon-pk
                                                      :state "open"
                                                      :epoch 10}))
          axiom-st0 (-> (light-core/init-light-state {:pubkey-hex axiom-pk} {:subnet-id "devnet.bitecho.org" :epoch 10})
                        (assoc :subscribed-subnets #{"chat/simon-nexus-axiom"} :broadcast-seq 319))
          ;; 1. Simon sends p2p-offer advertising shared-relay, Nexus answers advertising shared-relay
          off-res (light-core/handle-command simon-st0
                                             {"cmd" "p2p-offer"
                                              "session_id" sid-sn
                                              "transport" "https"
                                              "candidates" [shared-relay]}
                                             (kp->sk simon-kp))
          simon-st1 (:state off-res)
          off-env (first (:net-envelopes off-res))
          nx-off-rx (light-core/handle-wire-payload nexus-st0 off-env (kp->sk nexus-kp))
          nexus-st1 (:state nx-off-rx)
          ans-res (light-core/handle-command nexus-st1
                                             {"cmd" "p2p-answer"
                                              "session_id" sid-sn
                                              "transport" "https"
                                              "candidates" [shared-relay]}
                                             (kp->sk nexus-kp))
          nexus-st2 (:state ans-res)
          ans-env (first (:net-envelopes ans-res))
          sm-ans-rx (light-core/handle-wire-payload simon-st1 ans-env (kp->sk simon-kp))]
      ;; Both Nexus and Simon must preserve shared-relay in :p2p-dial!
      (is (= [shared-relay] (get-in ans-res [:p2p-dial :remote-candidates])))
      (is (= [shared-relay] (get-in sm-ans-rx [:p2p-dial :remote-candidates])))

      ;; 2. Verify dial-p2p-peer! loopback fallback to http://127.0.0.1:18080/relay/v1 when external hairpin fails
      (let [nx-atom (atom nexus-st2)
            nx-p2p-peers (atom {})
            probed-urls (atom [])]
        (with-redefs [light-shell/poll-relay-envelopes!
                      (fn [url _pk _priv _opts]
                        (swap! probed-urls conj url)
                        (if (str/starts-with? url "http://127.0.0.1:18080")
                          {"ok" true "messages" [] "broadcasts" []}
                          {"ok" false "error" "hairpin-nat-unreachable"}))
                      light-shell/submit-relay-envelope!
                      (fn [_url _env _opts] {"ok" true})]
          (light-shell/dial-p2p-peer! nx-atom nx-p2p-peers (atom {}) (atom {}) (kp->sk nexus-kp) nil (:p2p-dial ans-res))
          (is (= ["https://nexus.ingress.bitecho.org" "http://127.0.0.1:18080"] (vec (distinct @probed-urls)))
              "dial-p2p-peer! must fall back to local loopback relay http://127.0.0.1:18080 when external HTTPS probe fails")
          (is (true? (get-in @nx-atom [:sessions sid-sn :p2p :connected?])))
          (when-let [cf (get-in @nx-p2p-peers [simon-pk :close-fn])]
            (cf))))

      ;; 3. Axiom emits broadcast seq: 320 on chat/simon-nexus-axiom; Nexus ingests via import-poll while P2P-connected to Simon
      (let [ax-bcast (light-core/handle-command axiom-st0
                                                {"cmd" "broadcast"
                                                 "subnet_id" "chat/simon-nexus-axiom"
                                                 "text" "Axiom seq 320 broadcast over mesh"}
                                                (kp->sk axiom-kp))
            bcast-env (first (:net-envelopes ax-bcast))
            bcast-hex (basalt/bytes->hex (fressian/encode-canonical bcast-env))
            poll-payload (json/write-str {"ok" true
                                          "messages" []
                                          "broadcasts" [{"broadcast_seq" 320 "envelope_hex" bcast-hex}]})
            simon-atom (atom (assoc-in (:state sm-ans-rx) [:sessions sid-sn :p2p] {:phase :open :connected? true}))
            nexus-atom (atom (assoc-in nexus-st2 [:sessions sid-sn :p2p] {:phase :open :connected? true}))
            nx-p2p-peers (atom {simon-pk {:send-fn (fn [env]
                                                     (let [r (light-core/handle-wire-payload @simon-atom env (kp->sk simon-kp))]
                                                       (reset! simon-atom (:state r))
                                                       true))
                                          :session-id sid-sn
                                          :generation 1}})
            imp-res (light-shell/handle-serve-line!
                     {"cmd" "import-poll" "payload" poll-payload}
                     {:state-atom nexus-atom
                      :conn-atom (atom {:phase :down :ok? false})
                      :p2p-peers-atom nx-p2p-peers
                      :ingress-peers-atom (atom {})
                      :identity {:pubkey-hex nexus-pk :privkey-bytes (kp->sk nexus-kp)}})
            simon-inbox (light-core/handle-command @simon-atom {"cmd" "inbox" "subnet_id" "chat/simon-nexus-axiom" "peek" true} (kp->sk simon-kp))
            simon-bcasts (get-in simon-inbox [:response "broadcasts"])]
        (is (true? (get imp-res "ok")))
        (is (= 1 (count simon-bcasts)) "Simon must receive Axiom seq 320 broadcast forwarded live by Nexus on import-poll!")
        (is (= 320 (get (first simon-bcasts) :seq)))
        (is (= "Axiom seq 320 broadcast over mesh" (get (first simon-bcasts) :text)))))))
