(ns bitecho.v02322-hotfix-test
  "Strict TDD (`Rule 1`) generative + unit tests for the client-only v0.23.22 hotfix:
   1. Sticky `--subnet-id` startup authority override (`:subnet-id-startup-override` Rule 5 `:diagnose`).
   2. Subscribed-subnet admission in `handle-wire-payload` for BOTH directed and broadcast envelopes.
   3. Monotonic `:pointer/seq` auto-updater gate (`reduce-light-update-tick`) with legacy semver fallback.
   4. `/ctl` server socket `error` listener guard (`ECONNRESET` resilience) and `v0.23.22` version bump."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            [clojure.string :as str]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private gen-subnet
  (gen/elements ["global"
                 "devnet.bitecho.org"
                 "devnet.bitecho.org/team"
                 "devnet.bitecho.org/dev"
                 "devnet.bitecho.org/infra"
                 "bitecho.org/team"
                 "bitecho.org/dev"
                 "chat/simon-nexus-axiom"]))

(def ^:private gen-semver
  (gen/elements ["0.23.20" "0.23.21" "0.23.22" "0.23.23" "0.24.0"]))

(defn- make-cid-64
  [n]
  (let [hex #?(:clj (format "%064x" (biginteger (abs (long n))))
               :cljs (let [s (.toString (js/Math.abs (long n)) 16)]
                       (str (apply str (repeat (max 0 (- 64 (count s))) "0")) s)))]
    (subs hex (max 0 (- (count hex) 64)))))

(defn- make-signed-pointer
  [kp {:keys [seq target-version code-target-cid target-cid light-node-cid include-seq?]
       :or {include-seq? true}}]
  (let [pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
        base (cond-> {:network "devnet"
                      :author-pubkey pub-hex
                      :params {}}
               include-seq? (assoc :seq seq)
               (some? target-version) (assoc :target-version target-version)
               (some? code-target-cid) (assoc :code-target-cid code-target-cid)
               (some? target-cid) (assoc :target-cid target-cid)
               (some? light-node-cid) (assoc :light-node-cid light-node-cid))
        canon (deploy/canonical-config-pointer-map base)
        sig (str/lower-case
             (basalt/bytes->hex
              (crypto/sign-canonical (:private kp)
                                     (deploy/canonical-config-pointer-signing-payload canon))))]
    (assoc base :signature sig)))

;; =============================================================================
;; 1. Sticky --subnet-id Startup Authority Override (Rule 1 + Rule 5)
;; =============================================================================

(defspec ^{:doc "Startup --subnet-id overrides differing persisted :subnet-id with counted Rule 5 :diagnose while preserving petnames/sessions."}
  sticky-subnet-id-startup-override-spec 40
  (prop/for-all [persisted-sub gen-subnet
                 explicit-sub (gen/one-of [(gen/return nil) (gen/return "") gen-subnet])
                 extra-sub gen-subnet]
                (let [kp (crypto/generate-keypair "v02322-subnet-override-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      st0 (-> (light-core/init-light-state {:pubkey-hex pub-hex}
                                                           {:subnet-id persisted-sub})
                              (assoc :petnames {"nexus" "302a300506032b65700321000000000000000000000000000000000000000000000000000000000000000001"}
                                     :sessions {"sess-1" {:state "open" :peer-pubkey "aa"}}))
                      res (light-core/reconcile-startup-subnet-id st0 explicit-sub [extra-sub])
                      st1 (:state res)
                      trimmed (when (and (string? explicit-sub) (not (str/blank? explicit-sub)))
                                (str/trim explicit-sub))
                      override? (and (some? trimmed) (not= trimmed persisted-sub))
                      status-res (light-core/handle-command st1 {"cmd" "status"} (:private kp))
                      resp (:response status-res)]
                  (and (true? (:ok? res))
                       (= (:petnames st0) (:petnames st1))
                       (= (:sessions st0) (:sessions st1))
                       (contains? (:subscribed-subnets st1) extra-sub)
                       (= config/version (get resp "version"))
                       (if override?
                         (and (true? (:reconciled? res))
                              (= trimmed (:subnet-id st1))
                              (= trimmed (get resp "subnet_id"))
                              (contains? (:subscribed-subnets st1) trimmed)
                              (= 1 (get-in st1 [:diagnostics :subnet-id-reconciled]))
                              (some #(and (= :diagnose (:effect %))
                                          (= :subnet-id-reconciled (:reason %)))
                                    (:effects res)))
                         (and (false? (:reconciled? res))
                              (= persisted-sub (:subnet-id st1))
                              (= persisted-sub (get resp "subnet_id"))
                              (zero? (long (or (get-in st1 [:diagnostics :subnet-id-reconciled]) 0)))
                              (empty? (:effects res))))))))

;; =============================================================================
;; 2. Subscribed-Subnet Admission (Directed + Broadcast)
;; =============================================================================

(defspec ^{:doc "handle-wire-payload admits both directed and broadcast envelopes matching primary :subnet-id or :subscribed-subnets."}
  subscribed-subnet-admission-directed-and-broadcast-spec 30
  (prop/for-all [directed? gen/boolean
                 target-case (gen/elements [:primary :subscribed :unsubscribed])]
                (let [alice-kp (crypto/generate-keypair "v02322-alice-sub-seed")
                      bob-kp (crypto/generate-keypair "v02322-bob-sub-seed")
                      alice-pub (str/lower-case (basalt/bytes->hex (:public alice-kp)))
                      bob-pub (str/lower-case (basalt/bytes->hex (:public bob-kp)))
                      primary-sub "devnet.bitecho.org"
                      subscribed-sub "bitecho.org/team"
                      unsubscribed-sub "bitecho.org/other-unsubscribed"
                      env-sub (case target-case
                                :primary primary-sub
                                :subscribed subscribed-sub
                                :unsubscribed unsubscribed-sub)
                      bob-st (-> (light-core/init-light-state {:pubkey-hex bob-pub}
                                                              {:subnet-id primary-sub})
                                 (assoc :subscribed-subnets #{primary-sub subscribed-sub}))
                      wire-env (if directed?
                                 {:subnet-id env-sub
                                  :event {:bitecho/type :session-ack
                                          :protocol-version 1
                                          :session-id "sess-test-1"
                                          :seq 1
                                          :from alice-pub
                                          :to bob-pub
                                          :subnet-id env-sub}}
                                 {:subnet-id env-sub
                                  :event {:bitecho/type :p2p-broadcast
                                          :protocol-version 1
                                          :sender alice-pub
                                          :seq 1
                                          :msg-id "bcast-test-1"
                                          :subnet-id env-sub
                                          :text "hello"}})
                      res (light-core/handle-wire-payload bob-st wire-env (:private bob-kp))
                      dropped-mismatch? (= "subnet-mismatch" (get-in res [:response "error"]))]
                  (if (= target-case :unsubscribed)
                    (and dropped-mismatch?
                         (= 1 (long (or (get-in res [:state :diagnostics :subnet-mismatch-dropped]) 0))))
                    (and (not dropped-mismatch?)
                         (zero? (long (or (get-in res [:state :diagnostics :subnet-mismatch-dropped]) 0))))))))

;; =============================================================================
;; 3. Monotonic :pointer/seq Auto-Updater Gate (RELEASE.md §5)
;; =============================================================================

(defspec ^{:doc "Monotonic :pointer/seq auto-updater gate accepts higher :seq + distinct CID regardless of semver, no-ops equal :seq + same CID, and refuses lower :seq."}
  monotonic-pointer-seq-updater-gate-spec 50
  (prop/for-all [last-seq (gen/choose 1 50)
                 seq-delta (gen/choose -5 5)
                 cur-ver gen-semver
                 target-ver gen-semver
                 same-cid? gen/boolean]
                (let [kp (crypto/generate-keypair "v02322-updater-seq-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      cur-cid (make-cid-64 1001)
                      new-cid (if same-cid? cur-cid (make-cid-64 2002))
                      ptr-seq (max 0 (+ last-seq seq-delta))
                      ptr (make-signed-pointer kp {:seq ptr-seq
                                                   :target-version target-ver
                                                   :code-target-cid new-cid})
                      st0 (deploy/init-light-updater-state {:node-id "v02322-test-node"
                                                            :artifact-role :light-node
                                                            :current-version cur-ver
                                                            :current-cid cur-cid
                                                            :last-applied-seq last-seq
                                                            :trusted-deploy-authorities #{pub-hex}})
                      [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen
                                                                        :pointer ptr
                                                                        :generation 1})]
                  (cond
        ;; Lower :seq -> strict downgrade refusal with :light-update-non-monotonic-seq
                    (< ptr-seq last-seq)
                    (and (= :watching (:phase st1))
                         (not (some #(= :fetch-bundle-blob (:effect %)) effs1))
                         (= 1 (get-in st1 [:diagnostics :light-update-non-monotonic-seq]))
                         (some #(and (= :diagnose (:effect %))
                                     (= :light-update-non-monotonic-seq (:reason %)))
                               effs1))

        ;; Equal :seq + same CID -> clean no-op (zero fetch, zero diagnose)
                    (and (= ptr-seq last-seq) same-cid?)
                    (and (= :watching (:phase st1))
                         (not (some #(= :fetch-bundle-blob (:effect %)) effs1))
                         (not (some #(= :diagnose (:effect %)) effs1)))

        ;; Equal :seq + different CID -> sequence reuse refused
                    (and (= ptr-seq last-seq) (not same-cid?))
                    (and (= :watching (:phase st1))
                         (not (some #(= :fetch-bundle-blob (:effect %)) effs1))
                         (some #(and (= :diagnose (:effect %))
                                     (= :light-update-non-monotonic-seq (:reason %)))
                               effs1))

        ;; Higher :seq + same CID -> clean no-op, advances last-applied-seq
                    (and (> ptr-seq last-seq) same-cid?)
                    (and (= :watching (:phase st1))
                         (= ptr-seq (:last-applied-seq st1))
                         (= ptr-seq (:active-config-seq st1))
                         (not (some #(= :fetch-bundle-blob (:effect %)) effs1))
                         (not (some #(= :diagnose (:effect %)) effs1)))

        ;; Higher :seq + distinct 64-char CID -> triggers update REGARDLESS of semver!
                    :else
                    (and (= :fetching-https (:phase st1))
                         (some #(and (= :fetch-bundle-blob (:effect %))
                                     (= new-cid (:cid %)))
                               effs1))))))

(deftest legacy-pointer-without-seq-falls-back-to-semver-test
  (testing "Legacy pointer without :seq falls back cleanly to semver check"
    (let [kp (crypto/generate-keypair "v02322-legacy-ptr-seed")
          pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
          cur-cid (make-cid-64 111)
          new-cid (make-cid-64 222)
          st0 (deploy/init-light-updater-state {:node-id "legacy-test"
                                                :artifact-role :light-node
                                                :current-version "0.23.21"
                                                :current-cid cur-cid
                                                :trusted-deploy-authorities #{pub-hex}})
          ptr-up (make-signed-pointer kp {:include-seq? false
                                          :target-version "0.23.22"
                                          :code-target-cid new-cid})
          ptr-down (make-signed-pointer kp {:include-seq? false
                                            :target-version "0.23.20"
                                            :code-target-cid new-cid})
          [st-up effs-up] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-up :generation 1})
          [st-down effs-down] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr-down :generation 1})]
      (is (= :fetching-https (:phase st-up)))
      (is (some #(= :fetch-bundle-blob (:effect %)) effs-up))
      (is (= :watching (:phase st-down)))
      (is (some #(= :light-update-non-monotonic-version (:reason %)) effs-down)))))

(deftest v02322-version-and-persistence-whitelist-test
  (testing "config/version is bumped to 0.23.24"
    (is (= "0.23.24" config/version)))
  (testing "browser persistence sanitizer preserves :subnet-id-startup-override diagnostic"
    (let [sanitized (browser/sanitize-state-for-persistence
                     {:subnet-id "devnet.bitecho.org"
                      :light-state {:subnet-id "devnet.bitecho.org"
                                    :diagnostics {:subnet-id-startup-override 1}}})]
      (is (= 1 (get-in sanitized [:light-state :diagnostics :subnet-id-startup-override])))))
  #?(:clj
     (testing "/ctl server socket error listener guard is present in node_main.cljs"
       (let [node-src (slurp "src/bitecho/node_main.cljs")]
         (is (str/includes? node-src "ctl-socket-error"))
         (is (str/includes? node-src "(.on server \"connection\""))))))
