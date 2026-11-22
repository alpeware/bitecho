(ns bitecho.browser-cli-and-webrtc-diagnostics-test
  "Strict TDD (Rule 1) generative, model-based, and inventory test suite for:
   1. Single-authority multi-peer WebRTC lifecycle & zero-silent-loss diagnostics (Rules 4 & 5).
   2. Browser Light Node Console CLI parity (`BitechoLightNode`) and automated verb inventory (Rule 6)."
  (:require [bitecho.browser-cli :as browser-cli]
            #?(:cljs [bitecho.browser-main :as browser-main])
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            [clojure.set :as set]
            #?(:clj [clojure.string :as str])
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; 1. Generators for Multi-Peer WebRTC Lifecycle Model (Rule 1)
;; =============================================================================

(def ^:private validator-peer-ids
  ["node1" "node2" "node3" "ns1" "ns2" "ns3"])

(def ^:private gen-peer-id
  (gen/elements validator-peer-ids))

(def ^:private gen-ice-state
  (gen/elements ["new" "checking" "connected" "completed" "disconnected" "failed" "closed"]))

(def ^:private gen-conn-state
  (gen/elements ["new" "connecting" "connected" "disconnected" "failed" "closed"]))

(def ^:private gen-mesh-cmd
  (gen/one-of
   [(gen/hash-map :op (gen/return :dial)
                  :peer-id gen-peer-id)
    (gen/hash-map :op (gen/return :open)
                  :peer-id gen-peer-id)
    (gen/hash-map :op (gen/return :send)
                  :peer-id gen-peer-id)
    (gen/hash-map :op (gen/return :message-valid)
                  :peer-id gen-peer-id)
    (gen/hash-map :op (gen/return :message-invalid)
                  :peer-id gen-peer-id)
    (gen/hash-map :op (gen/return :ice-state-change)
                  :peer-id gen-peer-id
                  :ice-state gen-ice-state
                  :stale? gen/boolean)
    (gen/hash-map :op (gen/return :connection-state-change)
                  :peer-id gen-peer-id
                  :connection-state gen-conn-state
                  :stale? gen/boolean)
    (gen/hash-map :op (gen/return :close)
                  :peer-id gen-peer-id
                  :cause (gen/elements ["datachannel-closed" "peer-reset" "keepalive-detected-closed"])
                  :stale? gen/boolean)
    (gen/hash-map :op (gen/return :dial-failed)
                  :peer-id gen-peer-id
                  :error (gen/elements ["sdp-error" "datachannel-error" "ice-timeout"])
                  :stale? gen/boolean)
    (gen/hash-map :op (gen/return :visibility)
                  :state (gen/elements ["visible" "hidden"]))]))

;; =============================================================================
;; 2. Rule 1 Generative Model-Based Property: Multi-Peer WebRTC Lifecycle
;; =============================================================================

(defspec ^{:doc "Rule 1/4/5 Model-Based Property: Multi-peer mesh connection reducer preserves
                 every dialed peer's diagnostics (zero silent dissoc/loss), rejects stale
                 generations with counted :diagnose effects, bounds :recent-events <= 64,
                 and keeps aggregate summary counts strictly equal to per-peer sums."}
  prop-mesh-conns-multi-peer-lifecycle-model 60
  (prop/for-all [cmds (gen/vector gen-mesh-cmd 10 50)]
                (let [init (browser/initial-mesh-conns-state {:max-events 64})
                      result
                      (reduce
                       (fn [{:keys [mesh seen-peers ts valid?] :as acc} cmd]
                         (if-not valid?
                           acc
                           (let [ts' (+ ts 100)]
                             (if (= :visibility (:op cmd))
                               (let [[mesh' _effs] (browser/transition-mesh-visibility mesh (:state cmd))
                                     summary (browser/summarize-mesh-diagnostics mesh')]
                                 (if (and (= (:state cmd) (:visibility-state mesh'))
                                          (= seen-peers (set (keys (:peers mesh'))))
                                          (= (count seen-peers) (:total-peers summary)))
                                   (assoc acc :mesh mesh' :ts ts')
                                   (assoc acc :valid? false :reason :visibility-invariant-failed)))
                               (let [pid (:peer-id cmd)
                                     prev-peer (get-in mesh [:peers pid])
                                     curr-gen (long (or (:generation prev-peer) 0))
                                     stale? (and (:stale? cmd) (pos? curr-gen))
                                     ev-gen (if stale? (dec curr-gen) curr-gen)
                                     event (case (:op cmd)
                                             :dial {:type :dial :peer-id pid :target-url (str "rtc://" pid ":5010") :timestamp-ms ts'}
                                             :open {:type :open :generation curr-gen :peer-id pid :channel :mock-dc :timestamp-ms ts'}
                                             :send {:type :send :generation curr-gen :envelope {:type :ping :wire-format "fressian-v1"} :timestamp-ms ts'}
                                             :message-valid {:type :message :generation curr-gen :envelope {:type :pong :wire-format "fressian-v1"} :timestamp-ms ts'}
                                             :message-invalid {:type :message :generation curr-gen :envelope {:type :bad :wire-format "bad-fmt"} :timestamp-ms ts'}
                                             :ice-state-change {:type :ice-state-change :generation ev-gen :ice-state (:ice-state cmd) :timestamp-ms ts'}
                                             :connection-state-change {:type :connection-state-change :generation ev-gen :connection-state (:connection-state cmd) :timestamp-ms ts'}
                                             :close {:type :close :generation ev-gen :cause (:cause cmd) :timestamp-ms ts'}
                                             :dial-failed {:type :dial-failed :generation ev-gen :error (:error cmd) :timestamp-ms ts'})
                                     [mesh' effs] (browser/transition-mesh-peer mesh pid event)
                                     seen' (conj seen-peers pid)
                                     peer' (get-in mesh' [:peers pid])
                                     summary (browser/summarize-mesh-diagnostics mesh')
                                     sum-of (fn [k] (reduce + 0 (map #(long (or (get-in % [:diagnostics k]) 0)) (vals (:peers mesh')))))
                                     no-peer-lost? (= seen' (set (keys (:peers mesh'))))
                                     gen-monotonic? (>= (long (:generation peer' 0)) curr-gen)
                                     bounded-events? (<= (count (:recent-events mesh')) 64)
                                     stale-ok? (if stale?
                                                 (and (= (inc (long (or (get-in prev-peer [:diagnostics :ignored-stale]) 0)))
                                                         (long (get-in peer' [:diagnostics :ignored-stale])))
                                                      (some #(and (= :diagnose (:type %))
                                                                  (= :ignored-stale (:kind %))
                                                                  (= pid (:peer-id %)))
                                                            effs))
                                                 true)
                                     sums-match? (and (= (:total-peers summary) (count seen'))
                                                      (= (:dropped summary) (sum-of :dropped))
                                                      (= (:ignored-stale summary) (sum-of :ignored-stale))
                                                      (= (:ice-disconnects summary) (sum-of :ice-disconnects))
                                                      (= (:ice-reconnects summary) (sum-of :ice-reconnects))
                                                      (= (:close-count summary) (sum-of :close-count))
                                                      (= (:dial-failures summary) (sum-of :dial-failures))
                                                      (= (count (:peers summary)) (count seen')))]
                                 (if (and no-peer-lost? gen-monotonic? bounded-events? stale-ok? sums-match?)
                                   (assoc acc :mesh mesh' :seen-peers seen' :ts ts')
                                   (assoc acc :valid? false :reason {:no-peer-lost? no-peer-lost?
                                                                     :gen-monotonic? gen-monotonic?
                                                                     :bounded-events? bounded-events?
                                                                     :stale-ok? stale-ok?
                                                                     :sums-match? sums-match?})))))))
                       {:mesh init :seen-peers #{} :ts 1700000000000 :valid? true}
                       cmds)]
                  (:valid? result))))

;; =============================================================================
;; 3. Deterministic Regression: 4-of-6 Validator WebRTC Peer Loss (Rules 4 & 5)
;; =============================================================================

(deftest test-four-of-six-validator-peer-loss-zero-silent-failures
  (testing "Losing 4 of 6 validator connections leaves full per-peer & ring-buffer trace in diagnostics"
    (let [t0 1795200000000
          ;; 1. Dial and open all 6 validators through single-authority mesh-conns
          m-all-open
          (reduce
           (fn [m nid]
             (let [[m1 eff1] (browser/transition-mesh-peer m nid {:type :dial :peer-id nid :target-url (str "rtc://" nid ":5010") :timestamp-ms t0})
                   gen1 (:generation (first eff1))
                   [m2 _] (browser/transition-mesh-peer m1 nid {:type :open :generation gen1 :peer-id nid :channel :mock-dc :timestamp-ms (+ t0 50)})
                   [m3 _] (browser/transition-mesh-peer m2 nid {:type :ice-state-change :generation gen1 :ice-state "connected" :timestamp-ms (+ t0 60)})]
               m3))
           (browser/initial-mesh-conns-state)
           validator-peer-ids)
          s-healthy (browser/summarize-mesh-diagnostics m-all-open)]
      (is (= 6 (:total-peers s-healthy)))
      (is (= validator-peer-ids (:open-peers s-healthy)))
      (is (empty? (:closed-peers s-healthy)))
      (is (false? (:degraded? s-healthy)))
      (is (= :open (:phase s-healthy)))

      ;; 2. Lose 4 of 6 validators via distinct realistic failure modes while node1 & node2 survive
      (let [g (fn [m nid] (get-in m [:peers nid :generation]))
            ;; node3: ICE disconnected -> ICE failed -> datachannel close
            [m1 _] (browser/transition-mesh-peer m-all-open "node3" {:type :ice-state-change :generation (g m-all-open "node3") :ice-state "disconnected" :timestamp-ms (+ t0 1000)})
            [m2 _] (browser/transition-mesh-peer m1 "node3" {:type :ice-state-change :generation (g m1 "node3") :ice-state "failed" :timestamp-ms (+ t0 2000)})
            [m3 _] (browser/transition-mesh-peer m2 "node3" {:type :close :generation (g m2 "node3") :cause "datachannel-closed" :timestamp-ms (+ t0 2100)})
            ;; ns1: connectionState failed -> datachannel close
            [m4 _] (browser/transition-mesh-peer m3 "ns1" {:type :connection-state-change :generation (g m3 "ns1") :connection-state "failed" :timestamp-ms (+ t0 3000)})
            [m5 _] (browser/transition-mesh-peer m4 "ns1" {:type :close :generation (g m4 "ns1") :cause "datachannel-closed" :timestamp-ms (+ t0 3100)})
            ;; ns2: ICE closed -> datachannel close
            [m6 _] (browser/transition-mesh-peer m5 "ns2" {:type :ice-state-change :generation (g m5 "ns2") :ice-state "closed" :timestamp-ms (+ t0 4000)})
            [m7 _] (browser/transition-mesh-peer m6 "ns2" {:type :close :generation (g m6 "ns2") :cause "keepalive-detected-closed" :timestamp-ms (+ t0 4100)})
            ;; ns3: datachannel error (dial-failed)
            [m8 _] (browser/transition-mesh-peer m7 "ns3" {:type :dial-failed :generation (g m7 "ns3") :error "datachannel-error:sctp-reset" :timestamp-ms (+ t0 5000)})
            summary (browser/summarize-mesh-diagnostics m8)
            event-peers (set (map :peer-id (:recent-events summary)))]
        ;; Zero silent disappearance: all 6 peers are still tracked!
        (is (= 6 (:total-peers summary)))
        (is (= ["node1" "node2"] (:open-peers summary)))
        (is (= ["node3" "ns1" "ns2" "ns3"] (:closed-peers summary)))
        (is (true? (:degraded? summary)))
        (is (= 3 (:ice-disconnects summary)))
        (is (= 3 (:close-count summary)))
        (is (= 1 (:dial-failures summary)))
        (is (some? (:last-error summary)))
        ;; Per-peer diagnostics preserve exact state of all 4 lost validators
        (is (= :open (get-in summary [:peers "node1" :phase])))
        (is (= :open (get-in summary [:peers "node2" :phase])))
        (is (= :closed (get-in summary [:peers "node3" :phase])))
        (is (= "failed" (get-in summary [:peers "node3" :last-ice-state])))
        (is (= "datachannel-closed" (get-in summary [:peers "node3" :last-error])))
        (is (= :closed (get-in summary [:peers "ns1" :phase])))
        (is (= "failed" (get-in summary [:peers "ns1" :last-connection-state])))
        (is (= :closed (get-in summary [:peers "ns2" :phase])))
        (is (= "closed" (get-in summary [:peers "ns2" :last-ice-state])))
        (is (= :closed (get-in summary [:peers "ns3" :phase])))
        (is (= "datachannel-error:sctp-reset" (get-in summary [:peers "ns3" :last-error])))
        ;; Recent events ring buffer contains trace for all 4 lost peers
        (is (set/subset? #{"node3" "ns1" "ns2" "ns3"} event-peers))
        ;; Rule 4: Persistence sanitization MUST strip :mesh-conns (runtime liveness)
        (let [sanitized (browser/sanitize-state-for-persistence {:peer-id "browser-test" :mesh-conns m8})]
          (is (nil? (:mesh-conns sanitized))))))))

;; =============================================================================
;; 4. Rule 1 & Rule 6 Generative Property: Browser CLI Parity & Normalization
;; =============================================================================

(def ^:private all-cli-verbs-vec
  (vec (sort cli/all-recognized-cli-verbs-set)))

(defspec ^{:doc "Rule 1/6 Property: Every recognized CLI verb has a reversible camelCase JS method
                 name, normalizes cleanly via browser-cli/normalize-cli-invocation, and either
                 maps to a supported browser command or returns an explicit counted
                 :unsupported-in-browser diagnostic (never silently omitted)."}
  prop-browser-cli-verb-normalization-and-parity 100
  (prop/for-all [verb (gen/elements all-cli-verbs-vec)
                 use-camel? gen/boolean]
                (let [js-name (browser-cli/verb->js-method-name verb)
                      back (browser-cli/js-method-name->verb js-name)
                      invoked (if use-camel? js-name verb)
                      norm (browser-cli/normalize-cli-invocation invoked {:sessionId "sess-1" :subnetId "global"})]
                  (and (= verb back)
                       (if (contains? browser-cli/browser-unsupported-verbs verb)
                         (and (false? (:ok? norm))
                              (= :unsupported-in-browser (:error norm))
                              (= :diagnose (get-in norm [:diagnose :type]))
                              (= verb (:verb norm)))
                         (and (true? (:ok? norm))
                              (= verb (:verb norm))
                              (= "sess-1" (get-in norm [:cmd-map "session_id"]))
                              (= "global" (get-in norm [:cmd-map "subnet_id"]))))))))

;; =============================================================================
;; 5. Rule 6 Automated CLI Verb-Parity Inventory Test
;; =============================================================================

(deftest test-browser-cli-verb-parity-inventory
  (testing "100% of cli/all-recognized-cli-verbs-set is accounted for in browser-cli/browser-cli-verb-inventory"
    (let [inv browser-cli/browser-cli-verb-inventory
          inv-verbs (set (keys inv))
          js-names (mapv :js-method (vals inv))]
      (is (= cli/all-recognized-cli-verbs-set inv-verbs)
          "Every Node/JVM CLI verb must be tracked in browser-cli-verb-inventory")
      (is (= (count js-names) (count (distinct js-names)))
          "Every CLI verb must map to a unique camelCase JS method name")
      ;; Only genuinely OS-impossible verbs are marked unsupported-in-browser
      (is (= #{"serve" "daemon" "mcp"} browser-cli/browser-unsupported-verbs))
      (doseq [v browser-cli/browser-unsupported-verbs]
        (is (= :unsupported-in-browser (get-in inv [v :support])))
        (is (string? (get-in inv [v :reason]))))
      (doseq [v (set/difference cli/all-recognized-cli-verbs-set browser-cli/browser-unsupported-verbs)]
        (is (= :supported (get-in inv [v :support])) (str "Verb should be supported in browser: " v)))))

  (testing "Pure browser-cli/dispatch-browser-cli executes core light-node verbs with camelCase params"
    (let [kp (crypto/generate-keypair)
          pub-hex (fressian/bytes->hex (:public-key kp))
          priv (:private-key kp)
          st0 {:peer-id "browser-cli-test"
               :subnet-id "global"
               :mesh-conns (browser/initial-mesh-conns-state)
               :light-state (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id "global"})}
          ;; status
          r-status (browser-cli/dispatch-browser-cli st0 "status" {} priv)
          ;; help
          r-help (browser-cli/dispatch-browser-cli st0 "help" {} priv)
          ;; petname-set via camelCase verb + camelCase params
          r-pn-set (browser-cli/dispatch-browser-cli st0 "petnameSet" {:petname "alice" :pubkey pub-hex :overwrite true} priv)
          ;; petname-list on updated state
          r-pn-list (browser-cli/dispatch-browser-cli (:state r-pn-set) "petname-list" {} priv)
          ;; subscribe-subnets via camelCase
          r-sub (browser-cli/dispatch-browser-cli (:state r-pn-list) "subscribeSubnets" {:subnets ["devnet" "ops"]} priv)
          ;; unsupported OS daemon verb fails explicitly with counted diagnose
          r-serve (browser-cli/dispatch-browser-cli st0 "serve" {} priv)
          ;; unknown verb fails closed with counted diagnose
          r-unknown (browser-cli/dispatch-browser-cli st0 "nonexistent-verb-xyz" {} priv)]
      (is (true? (:ok? r-status)))
      (is (true? (get-in r-status [:response "ok"])))
      (is (true? (:ok? r-help)))
      (is (vector? (get-in r-help [:response "verbs"])))
      (is (true? (:ok? r-pn-set)))
      (is (true? (:ok? r-pn-list)))
      (is (= pub-hex (get-in r-pn-list [:response "petnames" "alice"])))
      (is (true? (:ok? r-sub)))
      (is (false? (:ok? r-serve)))
      (is (= "unsupported-in-browser" (get-in r-serve [:response "error"])))
      (is (some #(= :unsupported-in-browser (:kind %)) (:effects r-serve)))
      (is (false? (:ok? r-unknown)))
      (is (= "invalid-verb" (get-in r-unknown [:response "error"])))
      (is (some #(= :invalid-verb (:kind %)) (:effects r-unknown)))))

  #?(:clj
     (testing "JVM source audit: browser_main.cljs wires BitechoLightNode and single-authority mesh-conns (no orphaned aux-conn-atom)"
       (let [bm-src (slurp "src/bitecho/browser_main.cljs")
             sh-src (slurp "src/bitecho/shell/browser.cljc")]
         (is (str/includes? bm-src "BitechoLightNode"))
         (is (str/includes? bm-src "summarize-mesh-diagnostics"))
         (is (str/includes? bm-src "transition-mesh-peer"))
         (is (not (str/includes? bm-src "aux-conn-atom"))
             "Orphaned local aux-conn-atom must be removed in favor of single-authority :mesh-conns")
         (is (str/includes? sh-src "transition-mesh-peer"))
         (is (str/includes? sh-src "summarize-mesh-diagnostics")))))

  #?(:cljs
     (testing "CLJS runtime: BitechoLightNode exposes all CLI verbs + exec/cli/help/verbs/peers on globalThis"
       (let [na (browser-main/init-node {:peer-id "cljs-parity-node"})
             ln (aget js/globalThis "BitechoLightNode")
             bb (aget js/globalThis "BitechoBrowser")
             st (browser-main/get-status na)]
         (is (some? na))
         (is (some? st))
         (is (some? ln) "BitechoLightNode must be exposed on globalThis")
         (is (some? bb) "BitechoBrowser must remain exposed on globalThis")
         (is (fn? (aget ln "exec")))
         (is (fn? (aget ln "cli")))
         (is (fn? (aget ln "help")))
         (is (fn? (aget ln "verbs")))
         (is (fn? (aget ln "peers")))
         (is (fn? (aget ln "reconnect")))
         (is (fn? (aget ln "autoUpdaterStatus")))
         (doseq [[_verb {:keys [js-method]}] browser-cli/browser-cli-verb-inventory]
           (is (fn? (aget ln js-method))
               (str "Missing BitechoLightNode." js-method)))
         (browser-main/stop-node na)))))

;; =============================================================================
;; 6. D40.4 Strict TDD Generative & Runtime Tests (Headless Browser API v1.0.0)
;; =============================================================================

(def ^:private gen-hex-char
  (gen/elements (seq "0123456789abcdef")))

(def ^:private gen-raw-pubkey-hex
  (gen/fmap #(apply str %) (gen/vector gen-hex-char 64)))

(def ^:private gen-valid-petname
  (gen/fmap (fn [[prefix suffix]] (str prefix "-" suffix))
            (gen/tuple (gen/elements ["alice" "bob" "carol" "axiom" "nexus" "vector" "hive"])
                       (gen/choose 1 999))))

(def ^:private gen-optional-voice-id
  (gen/elements [nil "af_heart" "af_bella" "bm_lewis" "am_adam" "ef_dora"]))

(def ^:private gen-optional-color
  (gen/elements [nil "#ff6b6b" "#4ecdc4" "#ffe66d" "#6366f1" "#10b981"]))

(def ^:private gen-multiline-utf8
  (gen/fmap (fn [[a b c d]]
              (str a "\n" b "\r\n" c " — " d))
            (gen/tuple (gen/elements ["Hello 🌍" "Line 1: \"quoted\"" "  leading space" "日本語テスト" "```clojure\n(+ 1 2)\n```"])
                       (gen/elements ["Second line ✨" "café résumé" "tab\there" "emoji 🚀🔥"])
                       (gen/elements ["Third line" "--flag-like" "key=value" "end\n"])
                       gen/string-alphanumeric)))

(defspec ^{:doc "D40.4 Rule 1 Property: Event normalization resolves fromPetname, voiceId, and color
                 from local Rolodex/petname metadata when set, returns nil otherwise, and always
                 emits all 11 canonical JS event fields."}
  prop-d40-4-event-normalization-and-petname-resolution 100
  (prop/for-all [raw-pk gen-raw-pubkey-hex
                 other-pk gen-raw-pubkey-hex
                 pname gen-valid-petname
                 voice-id gen-optional-voice-id
                 color gen-optional-color
                 ev-type (gen/elements ["message-received" "broadcast-received" "status" "diagnose"])
                 text gen-multiline-utf8
                 seq-num (gen/choose 0 10000)
                 ts-ms (gen/choose 1700000000000 1800000000000)
                 known-sender? gen/boolean]
                (let [norm-pk (light-core/normalize-pubkey-hex raw-pk)
                      norm-other (light-core/normalize-pubkey-hex other-pk)
                      st0 {:peer-id "browser-d40-test"
                           :petnames {}
                           :petname-meta {}
                           :light-state (light-core/init-light-state {:pubkey-hex norm-pk} {:subnet-id "global"})}
                      merged (browser-cli/merge-petname-entry st0 raw-pk {:petname pname
                                                                          :voice-id voice-id
                                                                          :color color})
                      st1 (:state merged)
                      sender (if known-sender? norm-pk norm-other)
                      same-pk? (= sender norm-pk)
                      ev (browser-cli/normalize-browser-event
                          st1
                          {:type ev-type
                           :session-id "sess-1"
                           :subnet-id "chat/test"
                           :from sender
                           :seq seq-num
                           :text text
                           :timestamp-ms ts-ms})
                      js-map (browser-cli/event->js-map ev)
                      required-keys #{"eventId" "type" "sessionId" "subnetId" "from"
                                      "fromPetname" "voiceId" "color" "seq" "text" "timestampMs"}]
                  (and (true? (:ok? merged))
                       (set/subset? required-keys (set (keys js-map)))
                       (string? (get js-map "eventId"))
                       (= ev-type (get js-map "type"))
                       (= text (get js-map "text"))
                       (= seq-num (get js-map "seq"))
                       (= ts-ms (get js-map "timestampMs"))
                       (if same-pk?
                         (and (= pname (get js-map "fromPetname"))
                              (= voice-id (get js-map "voiceId"))
                              (= color (get js-map "color")))
                         (and (nil? (get js-map "fromPetname"))
                              (nil? (get js-map "voiceId"))
                              (nil? (get js-map "color"))))))))

(defspec ^{:doc "D40.4 Rule 1 Property: Petname/Rolodex metadata roundtrips cleanly through
                 merge-petname-entry, resolve-petname-entry, list-petname-entries, preserves
                 existing :petnames compatibility, and survives sanitize-state-for-persistence."}
  prop-d40-4-petname-metadata-roundtrip 100
  (prop/for-all [raw-pk gen-raw-pubkey-hex
                 pname gen-valid-petname
                 voice-id gen-optional-voice-id
                 color gen-optional-color
                 new-color gen-optional-color]
                (let [norm-pk (light-core/normalize-pubkey-hex raw-pk)
                      st0 {:peer-id "browser-d40-test"
                           :petnames {}
                           :petname-meta {}
                           :light-state (light-core/init-light-state {:pubkey-hex norm-pk} {:subnet-id "global"})}
                      r1 (browser-cli/merge-petname-entry st0 raw-pk {:petname pname
                                                                      :voiceId voice-id
                                                                      :color color})
                      st1 (:state r1)
                      resolved1 (browser-cli/resolve-petname-entry st1 norm-pk)
                      listed1 (browser-cli/list-petname-entries st1)
                      ;; Updating only :color must preserve existing :petname and :voice-id
                      r2 (browser-cli/merge-petname-entry st1 norm-pk {:color new-color})
                      st2 (:state r2)
                      resolved2 (browser-cli/resolve-petname-entry st2 norm-pk)
                      ;; Persistence sanitization (Rule 4) must keep :petnames and :petname-meta
                      persisted (browser/sanitize-state-for-persistence st2)
                      resolved-persisted (browser-cli/resolve-petname-entry persisted norm-pk)]
                  (and (true? (:ok? r1))
                       (= norm-pk (:pubkey resolved1))
                       (= pname (:petname resolved1))
                       (= voice-id (:voice-id resolved1))
                       (= color (:color resolved1))
                       (= norm-pk (get-in st1 [:petnames pname]))
                       (= norm-pk (get-in st1 [:light-state :petnames pname]))
                       (some #(= resolved1 %) listed1)
                       (true? (:ok? r2))
                       (= pname (:petname resolved2))
                       (= voice-id (:voice-id resolved2))
                       (= new-color (:color resolved2))
                       (= resolved2 resolved-persisted)))))

(defspec ^{:doc "D40.4 Rule 1 Property: sendMessage and sendBroadcast argument normalization
                 accepts both positional (id, text) and object ({sessionId/subnetId, text}) forms
                 and preserves multi-line UTF-8 text byte-for-byte verbatim."}
  prop-d40-4-multiline-utf8-message-and-broadcast-args 100
  (prop/for-all [target-id (gen/such-that #(not (empty? %)) gen/string-alphanumeric)
                 text gen-multiline-utf8
                 use-object? gen/boolean]
                (let [msg-res (if use-object?
                                (browser-cli/normalize-send-message-args {:sessionId target-id :text text} nil)
                                (browser-cli/normalize-send-message-args target-id text))
                      bcast-res (if use-object?
                                  (browser-cli/normalize-send-broadcast-args {:subnetId target-id :text text} nil)
                                  (browser-cli/normalize-send-broadcast-args target-id text))]
                  (and (true? (:ok? msg-res))
                       (= target-id (:session-id msg-res))
                       (= text (:text msg-res))
                       (true? (:ok? bcast-res))
                       (= target-id (:subnet-id bcast-res))
                       (= text (:text bcast-res))))))

(defspec ^{:doc "D40.4 Rule 1 & Rule 5 Property: Artifact CID verification succeeds on matching
                 SHA-256 bytes and fails closed with cid-mismatch + counted :diagnose on corruption."}
  prop-d40-4-artifact-cid-verification-and-diagnose 100
  (prop/for-all [payload-str gen-multiline-utf8]
                (let [payload-bytes (fressian/utf8->bytes payload-str)
                      true-cid (fressian/bytes->hex (crypto/sha256 payload-bytes))
                      tampered-bytes (fressian/utf8->bytes (str payload-str "!"))
                      ok-res (browser-cli/verify-artifact-bytes true-cid payload-bytes)
                      bad-res (browser-cli/verify-artifact-bytes true-cid tampered-bytes)
                      plan (browser-cli/build-artifact-fetch-plan {:cid true-cid})]
                  (and (true? (:ok? ok-res))
                       (= true-cid (:cid ok-res))
                       (false? (:ok? bad-res))
                       (= "cid-mismatch" (:error bad-res))
                       (= :diagnose (get-in bad-res [:diagnose :type]))
                       (= :cid-mismatch (get-in bad-res [:diagnose :kind]))
                       (= true-cid (:expected-cid bad-res))
                       (not= true-cid (:actual-cid bad-res))
                       (true? (:ok? plan))
                       (= [(str "https://bitecho.org/artifact/v1/blob/" true-cid)
                           (str "https://ns1.bitecho.org/artifact/v1/blob/" true-cid)]
                          (:urls plan))))))

(deftest test-d40-4-headless-browser-api-contract
  (testing "Pure API version constant (v1.1.0 additive over v1.0.0) and fail-closed artifact/messaging edge cases"
    (is (= "1.1.0" browser-cli/api-version))
    (is (false? (:ok? (browser-cli/normalize-send-message-args "" "hello"))))
    (is (false? (:ok? (browser-cli/normalize-send-message-args "sess-1" nil))))
    (is (false? (:ok? (browser-cli/normalize-send-broadcast-args "" "hello"))))
    (is (false? (:ok? (browser-cli/normalize-send-broadcast-args "sub-1" nil))))
    (let [bad-cid (browser-cli/build-artifact-fetch-plan {:cid "not-a-hex-cid"})
          bad-path (browser-cli/build-artifact-fetch-plan {:subnet "hive" :path "../etc/passwd"})
          sub-plan (browser-cli/build-artifact-fetch-plan {:subnet "hive" :path "voicepacks/en.bin" :baseUrl "https://custom.bitecho.org/"})]
      (is (false? (:ok? bad-cid)))
      (is (= :invalid-cid (:error bad-cid)))
      (is (= :diagnose (get-in bad-cid [:diagnose :type])))
      (is (false? (:ok? bad-path)))
      (is (= :invalid-artifact-path (:error bad-path)))
      (is (true? (:ok? sub-plan)))
      (is (= ["https://custom.bitecho.org/hive/voicepacks/en.bin"] (:urls sub-plan))))
    ;; BIP-017a CLI verbs & flags inventory check (Rule 6)
    (doseq [v ["artifact-put-chunked" "artifact-get-chunked" "artifact-manifest-verify"]]
      (is (contains? cli/all-recognized-cli-verbs-set v))
      (is (contains? browser-cli/browser-cli-verb-inventory v))
      (is (= :supported (get-in browser-cli/browser-cli-verb-inventory [v :support]))))
    (doseq [f ["--chunk-size" "--concurrency" "--resume-dir" "--grace-epochs" "--max-bytes"]]
      (is (some #{f} cli/known-command-flags)))
    (let [put-cmd (cli/build-cmd-map "artifact-put-chunked"
                                     ["--file" "af_heart.bin" "--chunk-size" "65536"
                                      "--concurrency" "2" "--grace-epochs" "4" "--max-bytes" "523264"])
          get-cmd (cli/build-cmd-map "artifact-get-chunked"
                                     ["--cid" (apply str (repeat 64 "a")) "--resume-dir" "/tmp/r"
                                      "--concurrency" "3" "--max-bytes" "523264"])
          ver-cmd (cli/build-cmd-map "artifact-manifest-verify"
                                     ["--cid" (apply str (repeat 64 "b")) "--grace-epochs" "4"])]
      (is (= "artifact-put-chunked" (get put-cmd "cmd")))
      (is (= 65536 (get put-cmd "chunk_size")))
      (is (= 2 (get put-cmd "concurrency")))
      (is (= 4 (get put-cmd "grace_epochs")))
      (is (= 523264 (get put-cmd "max_bytes")))
      (is (= "artifact-get-chunked" (get get-cmd "cmd")))
      (is (= "/tmp/r" (get get-cmd "resume_dir")))
      (is (= 3 (get get-cmd "concurrency")))
      (is (= "artifact-manifest-verify" (get ver-cmd "cmd")))
      (is (= 4 (get ver-cmd "grace_epochs")))))

  #?(:cljs
     (testing "CLJS runtime: BitechoLightNode v1.1.0 exposes all v1.0.0 + v1.1.0 additive methods, apiVersion, and error-isolated onEvent"
       (let [na (browser-main/init-node {:peer-id "cljs-d40-4-node"})
             ln (aget js/globalThis "BitechoLightNode")
             received (atom [])
             unsub-bad ((aget ln "onEvent") (fn [_ev] (throw (js/Error. "boom-listener"))))
             unsub-good ((aget ln "onEvent") (fn [ev] (swap! received conj ev)))]
         (is (= "1.1.0" (aget ln "apiVersion")))
         ;; v1.0.0 backwards-compatible contract
         (is (fn? (aget ln "getStatus")))
         (is (fn? (aget ln "onEvent")))
         (is (fn? (aget ln "listPetnames")))
         (is (fn? (aget ln "setPetname")))
         (is (fn? (aget ln "listSessions")))
         (is (fn? (aget ln "listSubnets")))
         (is (fn? (aget ln "sendMessage")))
         (is (fn? (aget ln "sendBroadcast")))
         (is (fn? (aget ln "getArtifact")))
         ;; v1.1.0 additive facade methods (BIP-017a)
         (is (fn? (aget ln "openChannel")))
         (is (fn? (aget ln "openSession")))
         (is (fn? (aget ln "acceptOffer")))
         (is (fn? (aget ln "approveOffer")))
         (is (fn? (aget ln "denyOffer")))
         (is (fn? (aget ln "listPendingOffers")))
         (is (fn? (aget ln "registerYubiKey")))
         (is (fn? (aget ln "recoverYubiKey")))
         (is (fn? (aget ln "saveIdentity")))
         (is (fn? (aget ln "getChunkedArtifact")))
         (is (fn? unsub-bad))
         (is (fn? unsub-good))
         ;; Emit a normalized event; throwing listener must not break subsequent listener
         ;; and must emit a counted :diagnose (:event-listener-error)
         (browser-main/emit-browser-event! na {:type "status" :text "ready" :timestamp-ms 1795200000000})
         (is (some #(= "status" (aget % "type")) @received)
             "Good listener must receive event even when an earlier listener throws")
         (is (pos? (long (or (get-in @na [:conn :diagnostics :event-listener-errors]) 0)))
             "Throwing listener must increment counted :event-listener-errors diagnostic")
         (unsub-bad)
         (unsub-good)
         (browser-main/stop-node na)))))

(defspec ^{:doc "Rule 1 Property: classify-accept-offer-target routes matching live mesh
                 pending-offers to :mesh-channel regardless of offerHash/signature/x25519
                 fields, and never allows nil caller-x25519 into :p2p-direct."}
  prop-accept-offer-mesh-vs-p2p-classification-never-derefs-null-x25519 50
  (prop/for-all [sid (gen/not-empty gen/string-alphanumeric)
                 key-variant (gen/elements [:session-id :sessionId :session_id :offer-id :offerId :id])
                 has-sig? gen/boolean
                 has-x25519? gen/boolean
                 in-pending? gen/boolean]
                (let [pending (if in-pending? {sid {:session-id sid :caller "aa" :price 10}} {})
                      base-offer (cond-> {key-variant sid :caller "aa"}
                                   has-sig? (assoc :offer-hash "deadbeef" :signature "cafebabe")
                                   has-x25519? (assoc :caller-x25519 (apply str (repeat 64 "1"))))
                      res (browser/classify-accept-offer-target base-offer pending)]
                  (cond
                    in-pending?
                    (and (= :mesh-channel (:mode res))
                         (= sid (:session-id res)))

                    has-x25519?
                    (= :p2p-direct (:mode res))

                    :else
                    (and (= :invalid (:mode res))
                         (= "missing-x25519-key" (:error res)))))))

(deftest accept-offer-and-query-chain-state-regression-test
  (testing "classify-accept-offer-target handles string session-id, nil, and mesh counter-offers without x25519"
    (is (= {:mode :invalid :error "invalid-offer"}
           (browser/classify-accept-offer-target nil {})))
    (is (= {:mode :mesh-channel :session-id "15dacb0f"}
           (browser/classify-accept-offer-target "15dacb0f" {"15dacb0f" {:session-id "15dacb0f"}})))
    (is (= {:mode :mesh-channel :session-id "15dacb0f"}
           (browser/classify-accept-offer-target
            {:sessionId "15dacb0f" :offerHash "abc" :signature "def" :caller-x25519 nil}
            {"15dacb0f" {:session-id "15dacb0f"}})))
    (is (= :invalid (:mode (browser/classify-accept-offer-target
                            {:offerHash "abc" :signature "def" :caller-x25519 nil}
                            {})))))
  (testing "inbound :query-chain-state with epoch 0 does not emit spurious epoch-skew-dropped diagnostic"
    (let [kp (crypto/generate-keypair)
          pub-hex (fressian/bytes->hex (:public-key kp))
          st (-> (light-core/init-light-state pub-hex {})
                 (assoc :epoch 72278 :epoch-initialized? true))
          res (light-core/handle-wire-payload
               st
               {:type :query-chain-state :pubkey pub-hex :epoch 0 :nonce "n1"}
               (:private-key kp))]
      (is (zero? (long (or (get-in res [:state :diagnostics :epoch-skew-dropped]) 0))))
      (is (not-any? #(= "epoch-skew-dropped" (get % "reason")) (:stdout-events res))))))
