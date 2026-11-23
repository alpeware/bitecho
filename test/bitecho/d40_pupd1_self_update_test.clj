(ns bitecho.d40-pupd1-self-update-test
  "Milestone D40 (P-UPD-1 All-Nodes Self-Update Wiring) Strict TDD Suite:
   - Pure `.cljc` multi-role target CID resolution (`:light-node`, `:full-node`, `:jvm-jar`, `:browser`)
   - Blob fetch URL resolution & signed pointer verification
   - Generation-tagged `reduce-light-update-tick` lifecycle (pin, stale-gen, hash mismatch, LKG rollback)
   - Shell wiring assertions for Node.js light node (`node_main.cljs`) and full/infra node (`full_node_main.cljs`)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.shell.light-node :as jvm-light]
            [bitecho.shell.updater :as jvm-updater]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private gen-hex-64
  (gen/fmap #(apply str %)
            (gen/vector (gen/elements (vec "0123456789abcdef")) 64)))

(defspec ^{:doc "Property: resolve-bundle-target-cid selects role-specific CID when present and falls back to :code-target-cid, and build-blob-fetch-url always emits an HTTPS /artifact/v1/blob/<cid> URL."}
  prop-pupd1-multi-role-pointer-cid-and-url-invariants
  100
  (prop/for-all [code-cid gen-hex-64
                 light-cid gen-hex-64
                 full-cid gen-hex-64
                 jvm-cid gen-hex-64
                 browser-cid gen-hex-64
                 role (gen/elements [:light-node :full-node :jvm-jar :browser])]
                (let [ptr {:code-target-cid code-cid
                           :light-node-cid light-cid
                           :full-node-cid full-cid
                           :jvm-jar-cid jvm-cid
                           :browser-cid browser-cid}
                      expected (case role
                                 :light-node light-cid
                                 :full-node full-cid
                                 :jvm-jar jvm-cid
                                 :browser browser-cid)
                      resolved (deploy/resolve-bundle-target-cid ptr role)
                      fallback (deploy/resolve-bundle-target-cid {:code-target-cid code-cid} role)
                      blob-url (deploy/build-blob-fetch-url "https://bitecho.org/config/devnet/active.edn" resolved)]
                  (and (= expected resolved)
                       (= code-cid fallback)
                       (= (str "https://bitecho.org/artifact/v1/blob/" resolved) blob-url)))))

(defn- make-signed-update-pointer
  [kp {:keys [seq target-version code-target-cid light-node-cid full-node-cid]}]
  (let [pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
        priv-bytes (:private kp)
        base (cond-> {:seq (long seq)
                      :activate-at-epoch 100
                      :target-version target-version
                      :code-target-cid code-target-cid
                      :author-pubkey pub-hex
                      :params {}}
               light-node-cid (assoc :light-node-cid light-node-cid)
               full-node-cid (assoc :full-node-cid full-node-cid))
        canon (deploy/canonical-config-pointer-map base)
        sig (basalt/bytes->hex (crypto/sign-canonical priv-bytes (deploy/canonical-config-pointer-signing-payload canon)))]
    (assoc base :signature sig)))

(deftest s-d40-1-pupd1-lifecycle-pin-rollback-and-node-wiring-test
  (testing "S-D40-1: pure P-UPD-1 reducer enforces pin-version, hash verification, stale-gen rejection, and LKG rollback"
    (let [kp (crypto/generate-keypair "d40-pupd1-test-seed")
          pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
          payload-bytes (fressian/utf8->bytes "// bitecho v0.23.18 bundle")
          good-cid (deploy/sha256-hex payload-bytes)
          bad-bytes (fressian/utf8->bytes "// tampered bundle")
          ptr (make-signed-update-pointer kp {:seq 2 :target-version "0.23.18" :code-target-cid good-cid})
          ;; 1. Pinned node refuses upgrade cleanly
          st-pin (deploy/init-light-updater-state {:node-id "axiom"
                                                   :current-version "0.23.17"
                                                   :current-cid "0000000000000000000000000000000000000000000000000000000000000001"
                                                   :pinned-version "0.23.17"
                                                   :trusted-deploy-authorities #{pub-hex}})
          [st-pin' effs-pin] (deploy/reduce-light-update-tick st-pin {:type :pointer-seen :pointer ptr :generation 1})
          ;; 2. Unpinned node stages -> swaps -> rolls back on failed health check
          st0 (deploy/init-light-updater-state {:node-id "axiom"
                                                :current-version "0.23.17"
                                                :current-cid "0000000000000000000000000000000000000000000000000000000000000001"
                                                :trusted-deploy-authorities #{pub-hex}})
          [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr :generation 1})
          ;; Stale generation callback is ignored with counted :diagnose
          [st-stale effs-stale] (deploy/reduce-light-update-tick st1 {:type :blob-fetched :bytes payload-bytes :generation 1})
          ;; Tampered blob rejected with :light-update-hash-mismatch
          [st-bad effs-bad] (deploy/reduce-light-update-tick st1 {:type :blob-fetched :bytes bad-bytes :generation (:generation st1)})
          ;; Good blob stages & triggers atomic swap
          [st2 effs2] (deploy/reduce-light-update-tick st1 {:type :blob-fetched :bytes payload-bytes :generation (:generation st1)})
          ;; Failed health check triggers automatic LKG rollback
          [st3 effs3] (deploy/reduce-light-update-tick st2 {:type :health-check-result :healthy? false :generation (:generation st2)})]
      (is (= :watching (:phase st-pin')))
      (is (= :pinned (get-in (first effs-pin) [:record :data :transition])))
      (is (= :fetching-https (:phase st1)))
      (is (some #(= :fetch-bundle-blob (:effect %)) effs1))
      (is (= 1 (:dropped st-stale)))
      (is (= :stale-generation-callback (:reason (first effs-stale))))
      (is (= :light-update-hash-mismatch (:last-error st-bad)))
      (is (some #(= :light-update-hash-mismatch (:reason %)) effs-bad))
      (is (= :health-checking (:phase st2)))
      (is (some #(= :atomic-swap-and-restart-light-node (:effect %)) effs2))
      (is (= :watching (:phase st3)))
      (is (= 1 (:rollback-count st3)))
      (is (contains? (:quarantined-cids st3) good-cid))
      (is (= "0.23.17" (:current-version st3)))
      (is (some #(= :restore-lkg-light-bundle (:effect %)) effs3))))
  (testing "S-D40-1: Node.js light node and full/infra node wire deploy/reduce-light-update-tick"
    (let [node-src (slurp "src/bitecho/node_main.cljs")
          full-src (slurp "src/bitecho/full_node_main.cljs")]
      (is (str/includes? node-src "deploy/reduce-light-update-tick")
          "node_main.cljs must wire pure deploy/reduce-light-update-tick in serve mode")
      (is (str/includes? full-src "deploy/reduce-light-update-tick")
          "full_node_main.cljs must wire pure deploy/reduce-light-update-tick for validator/infra nodes"))))

(deftest s-d40-2-jvm-and-browser-pupd1-parity-test
  (testing "S-D40-2: JVM light-node CLI parses --auto-update-pointer / --auto-update-interval-ms / --pin-version and JVM updater starts/stops cleanly"
    (let [parsed (jvm-light/parse-light-node-args
                  ["serve" "--auto-update-pointer" "https://bitecho.org/config/devnet/active.edn"
                   "--auto-update-interval-ms" "30000" "--pin-version" "0.23.17"])]
      (is (= "https://bitecho.org/config/devnet/active.edn" (:auto-update-pointer parsed)))
      (is (= 30000 (:auto-update-interval-ms parsed)))
      (is (= "0.23.17" (:pin-version parsed))))
    (is (nil? (jvm-updater/start-jvm-auto-updater! {:pointer-url nil})))
    (let [stop! (jvm-updater/start-jvm-auto-updater!
                 {:node-id "test-jvm"
                  :pointer-url "https://127.0.0.1:1/config/devnet/active.edn"
                  :poll-interval-ms 600000
                  :pinned-version "0.23.17"})]
      (is (fn? stop!))
      (stop!)))
  (testing "S-D40-2: JVM main.clj and Browser browser_main.cljs wire P-UPD-1 self-update parity"
    (let [jvm-main (slurp "src/bitecho/main.clj")
          browser-src (slurp "src/bitecho/browser_main.cljs")]
      (is (str/includes? jvm-main "updater/start-jvm-auto-updater!"))
      (is (str/includes? browser-src "deploy/reduce-light-update-tick"))
      (is (str/includes? browser-src "\"startAutoUpdater\""))))
  (testing "S-D40-2: equal version with different CID upgrades cleanly while equal version + equal CID and downgrade still refuse"
    (let [kp (crypto/generate-keypair "d40-same-ver-cid-seed")
          pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
          cur-cid "0000000000000000000000000000000000000000000000000000000000000001"
          new-cid "0000000000000000000000000000000000000000000000000000000000000002"
          st0 (deploy/init-light-updater-state {:node-id "axiom"
                                                :current-version "0.23.17"
                                                :current-cid cur-cid
                                                :trusted-deploy-authorities #{pub-hex}})
          ptr-same-cid (make-signed-update-pointer kp {:seq 2 :target-version "0.23.17" :code-target-cid cur-cid})
          ptr-new-cid  (make-signed-update-pointer kp {:seq 3 :target-version "0.23.17" :code-target-cid new-cid})
          ptr-downgrade (make-signed-update-pointer kp {:seq 4 :target-version "0.23.16" :code-target-cid new-cid})
          [st-noop effs-noop] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-same-cid :generation 1})
          [st-hotfix effs-hotfix] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-new-cid :generation 1})
          [st-down effs-down] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-downgrade :generation 1})]
      (is (= :watching (:phase st-noop)))
      (is (some #(= :light-update-non-monotonic-version (:reason %)) effs-noop))
      (is (= :fetching-https (:phase st-hotfix)))
      (is (some #(= :fetch-bundle-blob (:effect %)) effs-hotfix))
      (is (= :watching (:phase st-down)))
      (is (some #(= :light-update-non-monotonic-version (:reason %)) effs-down)))))
