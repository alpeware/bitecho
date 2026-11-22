(ns bitecho.d45-bip018-hardening-and-failover-test
  "BIP-018 (D45 / v0.23.21) Hardening, Multi-Relay Failover, Hot-Cache Cap & Incident Schema Tests.
   Strict TDD (Rules 1-6): Generative test.check properties for relay pool failover/cooldown/stale-gen/
   stale-epoch, 32 MiB infra hot-cache cap & <=16 MiB pinned app isolation, mechanical stall vs relay-down
   classification, postmortem schema validation & /status rate limiter, plus concrete repository gates."
  (:require [bitecho.core.data :as data]
            [bitecho.core.infra :as core-infra]
            [bitecho.light-node.cli :as cli]
            [bitecho.net.relay-pool :as relay-pool]
            [bitecho.ops.incident :as incident]
            #?(:clj [clojure.edn :as edn])
            #?(:clj [clojure.java.io :as io])
            #?(:clj [clojure.string :as str])
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Generators
;; =============================================================================

(def ^:private gen-relay-urls
  (gen/elements [["https://ns1.bitecho.org" "https://ns2.bitecho.org" "https://ns3.bitecho.org"]
                 ["https://ns2.bitecho.org" "https://ns3.bitecho.org" "https://ns1.bitecho.org"]
                 ["https://relay-a.example.org" "https://relay-b.example.org" "https://relay-c.example.org"]]))

(def ^:private gen-cid64
  (gen/fmap #(apply str %)
            (gen/vector (gen/elements (vec "0123456789abcdef")) 64)))

;; =============================================================================
;; 1. Property: Relay Pool Failover, Exponential Cooldown, Stale Gen & Stale Epoch
;; =============================================================================

(defspec ^{:doc "BIP-018 Track 3: Relay pool applies exponential cooldown (5s->15s->60s), fails over to next healthy relay with counted :diagnose, ignores stale generations with counted :ignored-stale, and demotes stale-epoch relays (>6 behind max peer)."}
  prop-relay-pool-failover-cooldown-stale-gen-and-stale-epoch 50
  (prop/for-all [urls gen-relay-urls
                 base-ts (gen/choose 100000 500000)
                 peer-epoch (gen/choose 100 5000)
                 stale-lag (gen/choose 7 50)
                 chunk-idx (gen/choose 0 64)]
                (let [pool0 (relay-pool/init-relay-pool urls {:generation 2 :max-epoch-lag 6})
                      u0 (nth urls 0)
                      u1 (nth urls 1)
                      u2 (nth urls 2)
                      ;; 1. Stale generation event must be ignored and counted
                      [pool-stale effs-stale]
                      (relay-pool/transition pool0 {:type :request-failed
                                                    :url u0
                                                    :status 503
                                                    :error "down"
                                                    :chunk-idx chunk-idx
                                                    :generation 1
                                                    :now-ms base-ts})
                      ;; 2. 3 consecutive failures on u0 -> exponential cooldowns 5000, 15000, 60000
                      [p1 e1] (relay-pool/transition pool-stale {:type :request-failed :url u0 :status 503 :error "timeout" :chunk-idx chunk-idx :generation 2 :now-ms base-ts})
                      [p2 e2] (relay-pool/transition p1 {:type :request-failed :url u0 :status 502 :error "bad-gw" :chunk-idx chunk-idx :generation 2 :now-ms (+ base-ts 5001)})
                      [p3 e3] (relay-pool/transition p2 {:type :request-failed :url u0 :status 504 :error "gw-timeout" :chunk-idx chunk-idx :generation 2 :now-ms (+ base-ts 20002)})
                      cd1 (- (get-in p1 [:relays u0 :cooldown-until-ms]) base-ts)
                      cd2 (- (get-in p2 [:relays u0 :cooldown-until-ms]) (+ base-ts 5001))
                      cd3 (- (get-in p3 [:relays u0 :cooldown-until-ms]) (+ base-ts 20002))
                      next-healthy (relay-pool/select-healthy-relay p3 (+ base-ts 20003) #{})
                      ;; 3. u1 reports healthy epoch = peer-epoch; u2 reports stale epoch = peer-epoch - stale-lag (>6 behind)
                      [p4 _] (relay-pool/transition p3 {:type :request-ok :url u1 :rtt-ms 40 :finalized-epoch peer-epoch :generation 2 :now-ms (+ base-ts 20010)})
                      [p5 e5] (relay-pool/transition p4 {:type :request-ok :url u2 :rtt-ms 25 :finalized-epoch (- peer-epoch stale-lag) :generation 2 :now-ms (+ base-ts 20020)})]
                  (and (= 1 (get-in pool-stale [:diagnostics :ignored-stale]))
                       (= 0 (get-in pool-stale [:relays u0 :failures]))
                       (some #(= :ignored-stale (:reason %)) effs-stale)
                       (= 5000 cd1)
                       (= 15000 cd2)
                       (= 60000 cd3)
                       (= 3 (get-in p3 [:diagnostics :relay-failover]))
                       (every? #(some (fn [e] (and (= :diagnose (:type e)) (= :relay-failover (:reason e)))) %) [e1 e2 e3])
                       (not= u0 next-healthy)
                       (contains? #{u1 u2} next-healthy)
                       (= :stale-epoch (get-in p5 [:relays u2 :status]))
                       (= 1 (get-in p5 [:diagnostics :relay-stale-epoch]))
                       (some #(and (= :diagnose (:type %)) (= :relay-stale-epoch (:reason %))) e5)))))

;; =============================================================================
;; 2. Property: 32 MiB Infra Hot-Cache Cap & <= 16 MiB Pinned App Isolation
;; =============================================================================

(defspec ^{:doc "BIP-018 Track 2: Blob store enforces max-hot-bytes strictly, emits counted :blob-hot-evicted diagnostics, and keeps pinned app blobs isolated under <= max-pinned-app-bytes."}
  prop-blob-store-32mb-hot-cap-and-pinned-app-isolation 40
  (prop/for-all [blob-sizes (gen/vector (gen/choose 200 600) 8 16)
                 app-size (gen/choose 200 400)]
                (let [max-hot 2048
                      max-app 1024
                      st0 (data/init-blob-store {:max-hot-bytes max-hot
                                                 :max-unpinned-bytes 100000
                                                 :max-pinned-app-bytes max-app})
                      app-blob (data/make-blob (apply str (repeat app-size "a")) "application/javascript")
                      put-app (data/put-blob st0 app-blob 1)
                      pin-res (data/pin-app-blob (:store put-app) (:blob/cid app-blob))
                      ;; Insert regular blobs exceeding max-hot
                      {:keys [store evict-diags]}
                      (reduce (fn [{:keys [store evict-diags idx]} sz]
                                (let [b (data/make-blob (str idx "-" (apply str (repeat sz "x"))) "application/octet-stream")
                                      r (data/put-blob store b (+ 10 idx))]
                                  {:store (:store r)
                                   :evict-diags (into evict-diags (filter #(= :blob-hot-evicted (:reason %)) (:effects r)))
                                   :idx (inc idx)}))
                              {:store (:store pin-res) :evict-diags [] :idx 0}
                              blob-sizes)
                      ;; Attempting to pin an app blob that exceeds max-pinned-app-bytes must fail closed
                      big-app (data/make-blob (apply str (repeat (inc max-app) "b")) "application/javascript")
                      put-big (data/put-blob store big-app 999)
                      pin-big (data/pin-app-blob (:store put-big) (:blob/cid big-app))]
                  (and (= (* 32 1024 1024) data/default-infra-max-hot-bytes)
                       (= (* 16 1024 1024) data/default-pinned-app-max-bytes)
                       (true? (:ok? pin-res))
                       (<= (:hot-bytes store) max-hot)
                       (<= (:pinned-app-bytes store) max-app)
                       ;; Pinned app blob remained hot while regular blobs were evicted
                       (some? (get-in store [:entries (:blob/cid app-blob) :bytes]))
                       (pos? (count evict-diags))
                       (= (count evict-diags) (get-in store [:diagnostics :blob-hot-evicted]))
                       ;; Oversized pinned app rejected with counted :diagnose
                       (false? (:ok? pin-big))
                       (some #(= :pinned-app-cap-exceeded (:reason %)) (:effects pin-big))))))

;; =============================================================================
;; 3. Property: Mechanical Stall vs Relay-Down Classification
;; =============================================================================

(defspec ^{:doc "BIP-018 Track 3: Mechanical classifier separates :healthy, :relay-degraded (some relays down/stale while healthy quorum advances), and :chain-stalled (healthy quorum stalled at/near local-epoch)."}
  prop-stall-vs-relay-down-classification 50
  (prop/for-all [local-epoch (gen/choose 100 10000)
                 advance (gen/choose 1 50)
                 stale-gap (gen/choose 7 40)]
                (let [adv-epoch (+ local-epoch advance)
                      healthy-obs [{:url "https://ns1.bitecho.org" :ok? true :finalized-epoch adv-epoch}
                                   {:url "https://ns2.bitecho.org" :ok? true :finalized-epoch adv-epoch}
                                   {:url "https://ns3.bitecho.org" :ok? true :finalized-epoch adv-epoch}]
                      degraded-down-obs [{:url "https://ns1.bitecho.org" :ok? false :finalized-epoch nil}
                                         {:url "https://ns2.bitecho.org" :ok? true :finalized-epoch adv-epoch}
                                         {:url "https://ns3.bitecho.org" :ok? true :finalized-epoch adv-epoch}]
                      degraded-stale-obs [{:url "https://ns1.bitecho.org" :ok? true :finalized-epoch (- adv-epoch stale-gap)}
                                          {:url "https://ns2.bitecho.org" :ok? true :finalized-epoch adv-epoch}
                                          {:url "https://ns3.bitecho.org" :ok? true :finalized-epoch adv-epoch}]
                      stalled-obs [{:url "https://ns1.bitecho.org" :ok? true :finalized-epoch local-epoch}
                                   {:url "https://ns2.bitecho.org" :ok? true :finalized-epoch local-epoch}
                                   {:url "https://ns3.bitecho.org" :ok? true :finalized-epoch local-epoch}]
                      r-healthy (relay-pool/classify-sync-stall local-epoch healthy-obs 6)
                      r-down (relay-pool/classify-sync-stall local-epoch degraded-down-obs 6)
                      r-stale (relay-pool/classify-sync-stall local-epoch degraded-stale-obs 6)
                      r-stalled (relay-pool/classify-sync-stall local-epoch stalled-obs 6)]
                  (and (= :healthy (:classification r-healthy))
                       (= :relay-degraded (:classification r-down))
                       (= :relay-degraded (:classification r-stale))
                       (= :chain-stalled (:classification r-stalled))))))

;; =============================================================================
;; 4. Property: Postmortem Schema Validation & /status Sliding-Window Rate Limiter
;; =============================================================================

(defspec ^{:doc "BIP-018 Track 4: Postmortem schema validator rejects missing tracks/unfalsified claims and /status rate limiter enforces 60 req/min/IP with Retry-After: 5 and counted :diagnose."}
  prop-postmortem-record-schema-and-status-rate-limit 40
  (prop/for-all [cid1 gen-cid64
                 cid2 gen-cid64
                 sev (gen/elements [:sev-1 :sev-2 :sev-3])
                 lag (gen/choose 0 180)
                 base-ts (gen/choose 100000 900000)]
                (let [valid-rec {:schema :bitecho/incident-postmortem-v1
                                 :incident-id "INC-2026-11-22-test"
                                 :severity sev
                                 :window-utc "2026-11-22T11:09:25Z/2026-11-22T12:44:08Z"
                                 :window-cst "2026-11-22 05:09:25..06:44:08 CST"
                                 :detection-lag-min lag
                                 :slo-breakdown {:consensus-finality {:target-pct 99.9999 :error-budget-burn-pct 0.0}
                                                 :edge-fleet {:target-pct 99.99 :error-budget-burn-pct 12.5}
                                                 :single-relay-client {:target-pct 99.9 :error-budget-burn-pct 100.0}}
                                 :hypotheses [{:claim "Memory cap too high" :status :verified}
                                              {:claim "Chain halted" :status :falsified :falsifier "ns2/ns3 finalized epochs continuously"}]
                                 :action-items [{:bip-id "BIP-018" :invariant-test "prop-relay-pool-failover-cooldown-stale-gen-and-stale-epoch"}]
                                 :evidence-cids [cid1 cid2]}
                      ok-res (incident/validate-postmortem-record valid-rec)
                      bad-slo (incident/validate-postmortem-record (update valid-rec :slo-breakdown dissoc :edge-fleet))
                      bad-hyp (incident/validate-postmortem-record
                               (assoc valid-rec :hypotheses [{:claim "Unproven" :status :falsified}]))
                      ;; 60 requests within 1 min allowed, 61st rejected with retry-after-sec 5 & :diagnose
                      rl0 (incident/init-status-rate-limiter)
                      after-60 (reduce (fn [acc i]
                                         (let [r (incident/check-status-rate-limit (:state acc) "203.0.113.10" (+ base-ts i))]
                                           {:state (:state r) :all-ok? (and (:all-ok? acc) (:allowed? r))}))
                                       {:state rl0 :all-ok? true}
                                       (range 60))
                      req-61 (incident/check-status-rate-limit (:state after-60) "203.0.113.10" (+ base-ts 100))
                      ;; After window slides (>60000ms), request is allowed again
                      req-after-window (incident/check-status-rate-limit (:state req-61) "203.0.113.10" (+ base-ts 60001))]
                  (and (true? (:ok? ok-res))
                       (false? (:ok? bad-slo))
                       (pos? (count (:diagnostics bad-slo)))
                       (false? (:ok? bad-hyp))
                       (pos? (count (:diagnostics bad-hyp)))
                       (true? (:all-ok? after-60))
                       (false? (:allowed? req-61))
                       (= 5 (:retry-after-sec req-61))
                       (= :status-rate-limited (get-in req-61 [:diagnose :reason]))
                       (true? (:allowed? req-after-window))))))

;; =============================================================================
;; 5. Concrete Repository Gate Tests (Rule 6: Co-Committed Spec, Ops, CLI, Postmortem)
;; =============================================================================

(deftest test-bip018-cli-flag-inventory-and-cmd-map
  (testing "--relay-urls and --quorum are registered in cli/known-command-flags and parsed by build-cmd-map"
    (is (some #{"--relay-urls"} cli/known-command-flags))
    (is (some #{"--quorum"} cli/known-command-flags))
    (let [get-cmd (cli/build-cmd-map "artifact-get-chunked"
                                     ["--cid" "abc123"
                                      "--relay-urls" "https://ns2.bitecho.org,https://ns3.bitecho.org,https://ns1.bitecho.org"
                                      "--quorum" "2"])]
      (is (= ["https://ns2.bitecho.org" "https://ns3.bitecho.org" "https://ns1.bitecho.org"]
             (get get-cmd "relay_urls")))
      (is (= 2 (get get-cmd "quorum"))))))

(deftest test-bip018-status-snapshot-compact-shape
  (testing "build-status-snapshot produces compact JSON-ready payload with required keys"
    (let [snap (incident/build-status-snapshot
                {:finalized-epoch 14200
                 :release-seq 42
                 :relays [{:url "https://ns1.bitecho.org" :status :healthy :ewma-rtt-ms 28.5 :finalized-epoch 14200}
                          {:url "https://ns2.bitecho.org" :status :healthy :ewma-rtt-ms 31.2 :finalized-epoch 14200}
                          {:url "https://ns3.bitecho.org" :status :healthy :ewma-rtt-ms 34.0 :finalized-epoch 14200}]
                 :error-budget {:consensus-finality-pct 100.0 :edge-fleet-pct 99.95 :single-relay-client-pct 82.0}
                 :updated-at-ms 1795353500000})]
      (is (true? (:ok snap)))
      (is (= 14200 (:finalized_epoch snap)))
      (is (= 42 (:release_seq snap)))
      (is (= 3 (count (:relays snap))))
      (is (map? (:error_budget snap)))
      (is (= 1795353500000 (:updated_at_ms snap)))
      (is (< (count (pr-str snap)) 2048)))))

#?(:clj
   (deftest test-bip018-canonical-postmortem-and-hardening-script
     (testing "docs/postmortems/INC-2026-11-22-ns1.edn passes validate-postmortem-record and closes all 3 Axiom Stage 1 flags"
       (let [edn-file (io/file "docs/postmortems/INC-2026-11-22-ns1.edn")
             md-file (io/file "docs/postmortems/INC-2026-11-22-ns1.md")
             idx-file (io/file "docs/postmortems/index.edn")]
         (is (.exists edn-file) "INC-2026-11-22-ns1.edn must exist")
         (is (.exists md-file) "INC-2026-11-22-ns1.md must exist")
         (is (.exists idx-file) "docs/postmortems/index.edn must exist")
         (let [rec (edn/read-string (slurp edn-file))
               val-res (incident/validate-postmortem-record rec)
               md-str (slurp md-file)
               idx (edn/read-string (slurp idx-file))]
           (is (true? (:ok? val-res)) (str "Postmortem validation errors: " (:errors val-res)))
           ;; MEDIUM 1: 94.7 min single-relay client downtime reported separately from 45.6 s cluster telemetry breach
           (is (str/includes? md-str "94.7"))
           (is (str/includes? md-str "45.6"))
           (is (str/includes? md-str "86 ms"))
           ;; LOW 1: ns1 unreachable (88.6 min) distinguished from end-to-end client recovery (94.7 min)
           (is (str/includes? md-str "88.6"))
           (is (str/includes? md-str "06:38:02"))
           (is (str/includes? md-str "06:44:08"))
           ;; LOW 2: Twin-circle receipt link CIDs recorded
           (is (str/includes? md-str "567a6113"))
           (is (str/includes? md-str "75ce46a03d02bad388ec87bf7a5b94d0c236da61230822258e83d5a75a9e74bb"))
           (is (some #(= "INC-2026-11-22-ns1" (:incident-id %)) (:incidents idx))))))

     (testing "scripts/harden-fleet-ssh-and-watchdog.sh exists, is executable, and asserts all SSH/OOM/watchdog invariants"
       (let [f (io/file "scripts/harden-fleet-ssh-and-watchdog.sh")
             body (slurp f)]
         (is (.exists f) "harden-fleet-ssh-and-watchdog.sh must exist")
         (is (.canExecute f) "harden-fleet-ssh-and-watchdog.sh must be executable")
         (doseq [needle ["set -euo pipefail"
                         "PasswordAuthentication no"
                         "KbdInteractiveAuthentication no"
                         "ChallengeResponseAuthentication no"
                         "PermitRootLogin prohibit-password"
                         "MaxAuthTries 3"
                         "MaxStartups 10:30:60"
                         "sshd -t"
                         "BatchMode=yes"
                         "PasswordAuthentication=no"
                         "/statusz"
                         "bitecho-infra"
                         "OOMScoreAdjust"
                         "-500"
                         "200"]]
           (is (str/includes? body needle)
               (str "Hardening script missing required directive/assertion: " needle)))))))

;; =============================================================================
;; 6. BIP-018-SOAK-F3: Artifact Blob Upload Fail-Closed & Peer Replication Tests
;; =============================================================================

(defspec ^{:doc "Every failed, non-2xx, malformed, or CID-mismatched POST /artifact/v1/blob response fails closed."}
  prop-artifact-blob-upload-never-silently-succeeds 100
  (prop/for-all [status (gen/one-of [(gen/return nil)
                                     (gen/choose 200 204)
                                     (gen/choose 400 429)
                                     (gen/choose 500 507)])
                 body-ok? (gen/one-of [(gen/return nil) gen/boolean])
                 transport-err (gen/one-of [(gen/return nil)
                                            (gen/elements ["timeout" "ECONNRESET" "socket hang up"])])
                 cid-match? gen/boolean]
                (let [expected-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      returned-cid (if cid-match? expected-cid "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                      parsed-body (when (some? body-ok?)
                                    {"ok" body-ok? "cid" returned-cid})
                      res (core-infra/evaluate-artifact-blob-upload-response
                           {:status status
                            :parsed-body parsed-body
                            :transport-error transport-err
                            :expected-cid expected-cid})
                      should-succeed? (and (nil? transport-err)
                                           (integer? status)
                                           (<= 200 status 299)
                                           (true? body-ok?)
                                           cid-match?)]
                  (and (= should-succeed? (boolean (:ok? res)))
                       (if should-succeed?
                         (= expected-cid (:cid res))
                         (and (keyword? (:error res))
                              (boolean? (:retryable? res))))))))

(defspec ^{:doc "Every non-2xx or transport-error peer replication outcome produces a counted :diagnose event."}
  prop-peer-replication-non-2xx-always-diagnoses 100
  (prop/for-all [status (gen/one-of [(gen/return nil)
                                     (gen/choose 200 204)
                                     (gen/choose 400 599)])
                 err-msg (gen/one-of [(gen/return nil) (gen/elements ["timeout" "socket hang up" "ECONNREFUSED"])])
                 peer-id (gen/elements [:ns1 :ns2 :ns3])]
                (let [res (core-infra/classify-peer-replication-response
                           {:status status
                            :error err-msg
                            :peer peer-id
                            :reason :peer-artifact-replicate-failed})
                      ok-2xx? (and (nil? err-msg) (integer? status) (<= 200 status 299))]
                  (if ok-2xx?
                    (and (true? (:ok? res)) (nil? (:diagnose res)))
                    (and (false? (:ok? res))
                         (= :diagnose (get-in res [:diagnose :type]))
                         (= :peer-artifact-replicate-failed (get-in res [:diagnose :reason]))
                         (= peer-id (get-in res [:diagnose :peer])))))))

#?(:clj
   (deftest test-bip018-soak-f3-durability-and-fail-closed-wiring
     (testing "full_node_main.cljs awaits disk persistence before 200 on POST /artifact/v1/blob and checks peer status"
       (let [src (slurp (io/file "src/bitecho/full_node_main.cljs"))]
         (is (str/includes? src "write-disk-blob-async!")
             "full_node_main.cljs must define async promise-returning write-disk-blob-async!")
         (is (str/includes? src "blob-persist-failed")
             "POST /artifact/v1/blob must return 500 blob-persist-failed on disk write failure")
         (is (str/includes? src "classify-peer-replication-response")
             "post-to-peer! must classify non-2xx HTTP status codes via core-infra/classify-peer-replication-response")))
     (testing "node_main.cljs sends raw binary blobs and fails closed on artifact blob upload errors"
       (let [src (slurp (io/file "src/bitecho/node_main.cljs"))]
         (is (str/includes? src "evaluate-artifact-blob-upload-response")
             "node_main.cljs must validate POST /artifact/v1/blob responses via core-infra/evaluate-artifact-blob-upload-response")
         (is (str/includes? src "X-Bitecho-Blob-Cid")
             "post-artifact-to-relay! must upload raw binary blobs with X-Bitecho-Blob-Cid header instead of 2x JSON hex")
         (is (str/includes? src "artifact-blob-upload-failed")
             "one-shot/serve artifact-put must fail closed with artifact-blob-upload-failed instead of returning ok=true")))))

;; =============================================================================
;; 7. BIP-018-SOAK-F1: Cold-on-Disk Large-Blob Threshold & Native SHA-256 / glibc RSS Bounds
;; =============================================================================

(defspec ^{:doc "BIP-018-SOAK-F1: Blobs exceeding :max-hot-blob-bytes are stored cold (:bytes nil, :hot-bytes unchanged) with counted :blob-stored-cold :diagnose, while small blobs (<= cap) and app-pinned blobs remain hot."}
  prop-large-blobs-stored-cold-and-hot-bytes-bounded 50
  (prop/for-all [small-sizes (gen/vector (gen/choose 16 128) 2 6)
                 large-sizes (gen/vector (gen/choose 257 640) 3 8)]
                (let [max-entry 256
                      st0 (data/init-blob-store {:max-hot-bytes 4096
                                                 :max-hot-blob-bytes max-entry
                                                 :max-unpinned-bytes 100000
                                                 :max-pinned-app-bytes 2048})
                      ;; Insert small blobs -> must stay hot
                      {:keys [store small-cids]}
                      (reduce (fn [{:keys [store small-cids idx]} sz]
                                (let [b (data/make-blob (str "s" idx "-" (apply str (repeat sz "a"))) "application/octet-stream")
                                      r (data/put-blob store b (+ 10 idx))]
                                  {:store (:store r)
                                   :small-cids (conj small-cids (:blob/cid b))
                                   :idx (inc idx)}))
                              {:store st0 :small-cids [] :idx 0}
                              small-sizes)
                      hot-after-small (:hot-bytes store)
                      ;; Insert large blobs (> max-entry) -> must be stored cold (:bytes nil) with counted :blob-stored-cold
                      {:keys [store large-cids cold-diags]}
                      (reduce (fn [{:keys [store large-cids cold-diags idx]} sz]
                                (let [b (data/make-blob (str "L" idx "-" (apply str (repeat sz "z"))) "application/octet-stream")
                                      r (data/put-blob store b (+ 100 idx))]
                                  {:store (:store r)
                                   :large-cids (conj large-cids (:blob/cid b))
                                   :cold-diags (into cold-diags (filter #(= :blob-stored-cold (:reason %)) (:effects r)))
                                   :idx (inc idx)}))
                              {:store store :large-cids [] :cold-diags [] :idx 0}
                              large-sizes)
                      ;; App-pinned large blob still stays hot if within max-pinned-app-bytes
                      app-big (data/make-blob (apply str (repeat 300 "p")) "application/javascript")
                      pin-pre (data/pin-app-blob store (:blob/cid app-big))
                      put-app-big (data/put-blob (:store pin-pre) app-big 500)
                      first-large-cid (first large-cids)
                      first-large-entry (get-in store [:entries first-large-cid])]
                  (and (= (* 64 1024) data/default-infra-max-hot-blob-bytes)
                       (= hot-after-small (:hot-bytes store))
                       (every? #(some? (get-in store [:entries % :bytes])) small-cids)
                       (every? #(nil? (get-in store [:entries % :bytes])) large-cids)
                       (every? #(pos? (long (or (get-in store [:entries % :size]) 0))) large-cids)
                       (some? first-large-entry)
                       (= (count large-cids) (count cold-diags))
                       (= (count large-cids) (get-in store [:diagnostics :blob-stored-cold]))
                       (some? (get-in (:store put-app-big) [:entries (:blob/cid app-big) :bytes]))))))

#?(:clj
   (deftest test-bip018-soak-f1-rss-bounds-wiring
     (testing "crypto.cljc uses native node-crypto SHA-256 on Node.js instead of allocating 512 KiB Uint32Arrays"
       (let [src (slurp (io/file "src/bitecho/crypto.cljc"))]
         (is (str/includes? src "(.createHash node-crypto \"sha256\")")
             "crypto/sha256 must use node:crypto on Node.js to avoid 512 KiB Uint32Array allocations per chunk")))
     (testing "full_node_main.cljs configures :max-hot-blob-bytes on infra nodes"
       (let [src (slurp (io/file "src/bitecho/full_node_main.cljs"))]
         (is (str/includes? src ":max-hot-blob-bytes")
             "start-infra-node! must pass :max-hot-blob-bytes to subnet/init-subnet-instance")
         (is (str/includes? src "default-infra-max-hot-blob-bytes")
             "start-infra-node! must default :max-hot-blob-bytes to data/default-infra-max-hot-blob-bytes")))
     (testing "scripts/run-infra-node.sh bounds glibc mmap threshold to 16 KiB for Node.js HTTP/TLS chunks"
       (let [src (slurp (io/file "scripts/run-infra-node.sh"))]
         (is (str/includes? src "MALLOC_MMAP_THRESHOLD_:-16384")
             "run-infra-node.sh must set MALLOC_MMAP_THRESHOLD_ default to 16384 (16 KiB)")
         (is (str/includes? src "MALLOC_TRIM_THRESHOLD_:-16384")
             "run-infra-node.sh must set MALLOC_TRIM_THRESHOLD_ default to 16384 (16 KiB)")))))
