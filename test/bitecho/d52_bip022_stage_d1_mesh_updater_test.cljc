(ns bitecho.d52-bip022-stage-d1-mesh-updater-test
  "Strict TDD generative & integration tests for BIP-022 Stage D.1:
   Mesh-First Self-Update Fetch & Large-Body HTTP Fallback Hardening.
   - 5 `clojure.test.check` `defspec` properties (JVM + CLJS):
     1. `prop-stale-generation-zero-mutation`
     2. `prop-mid-transfer-chunk-corruption-fail-closed`
     3. `prop-mesh-timeout-to-http-failover`
     4. `prop-http-abort-to-range-resume-and-relay-failover`
     5. `prop-zero-silent-drops-invariant`
   - Cross-relay ETag normalization (quoted / unquoted / weak `W/\"...\"`)
   - Simulated mid-body HTTP abort -> `206 Range` resume & multi-relay failover
   - `--auto-update-force-http` (`:force-http? true`)
   - Server-side `206 Partial Content` & `416` on `/artifact/v1/blob/<cid>`
   - Bounded positional disk CAS chunk read + semaphore (`max=2`)
   - Closure `:advanced` safety & 3-runtime wiring invariants."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.storage.chunk-constants :as cc]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            #?@(:clj [[bitecho.core.data :as data]
                      [bitecho.shell.blob-fs :as blob-fs]
                      [bitecho.shell.http :as http-shell]
                      [bitecho.shell.infra :as infra]
                      [bitecho.shell.mesh :as mesh-shell]
                      [clojure.java.io :as io]]))
  #?(:clj (:import [java.net URI]
                   [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
                   [java.nio.file Files]
                   [java.nio.file.attribute FileAttribute])))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- gen-kp
  [seed]
  (let [kp (crypto/generate-keypair seed)]
    {:pub (:public kp)
     :priv (:private kp)
     :pub-hex (basalt/bytes->hex (:public kp))}))

(defn- make-signed-ptr
  [auth-kp {:keys [seq target-version light-node-cid full-node-cid jvm-jar-cid artifact-size-bytes]}]
  (deploy/sign-config-pointer
   (:priv auth-kp)
   (cond-> {:seq (long (or seq 2))
            :author-pubkey (:pub-hex auth-kp)
            :target-version (or target-version "0.23.24")}
     light-node-cid (assoc :light-node-cid light-node-cid)
     full-node-cid (assoc :full-node-cid full-node-cid)
     jvm-jar-cid (assoc :jvm-jar-cid jvm-jar-cid)
     artifact-size-bytes (assoc :artifact-size-bytes (long artifact-size-bytes)))))

(defn- make-payload
  [n fill-ch]
  (fressian/utf8->bytes (apply str (repeat n fill-ch))))

(defn- flip-byte-at
  [bs idx]
  #?(:clj (let [copy (java.util.Arrays/copyOf ^bytes bs (alength ^bytes bs))
                pos (mod (long idx) (alength copy))]
            (aset-byte copy (int pos) (unchecked-byte (bit-xor (aget copy (int pos)) 0x55)))
            copy)
     :cljs (let [n (.-byteLength bs)
                 copy (js/Uint8Array. n)
                 pos (mod (long idx) n)]
             (.set copy bs 0)
             (aset copy pos (bit-xor (aget copy pos) 0x55))
             copy)))

(defn- slice-bs
  [bs start end]
  #?(:clj (java.util.Arrays/copyOfRange ^bytes bs (int start) (int end))
     :cljs (crypto/compact-u8 (.subarray bs start end))))

(defn- causes-sum
  [st]
  (reduce + 0 (vals (get-in st [:diagnostics :causes] {}))))

(defn- init-test-updater
  [auth-kp & [opts]]
  (deploy/init-light-updater-state
   (merge {:node-id "d52-node"
           :artifact-role :light-node
           :current-version "0.23.22"
           :current-cid (deploy/sha256-hex (fressian/utf8->bytes "old-bundle"))
           :pointer-url "https://bitecho.org/pointer.edn"
           :relay-origins ["https://ns1.bitecho.org"
                           "https://ns2.bitecho.org"
                           "https://ns3.bitecho.org"]
           :trusted-deploy-authorities #{(:pub-hex auth-kp)}}
          opts)))

;; =============================================================================
;; 1. Rule 1 Generative Property 1: Stale-Generation Zero Mutation
;; =============================================================================

(defspec ^{:doc "BIP-022 Stage D.1 Prop 1: Stale-generation callbacks (ev-gen < cur-gen) NEVER mutate
                 :phase, :pending-update, :current-cid, :last-applied-seq, or :http-fallback,
                 and ALWAYS emit exactly one :stale-generation-callback :diagnose + increment :dropped."}
  prop-stale-generation-zero-mutation 60
  (prop/for-all [ops (gen/vector
                      (gen/elements [:poll-tick
                                     :pointer-seen-mesh
                                     :pointer-seen-http
                                     :mesh-fetch-failed
                                     :blob-fetch-failed-abort
                                     :blob-fetch-failed-503
                                     :http-retry-timer-fired
                                     :http-range-chunk-fetched
                                     :blob-fetched-good
                                     :health-check-ok
                                     :stale-callback])
                      5 25)]
                (let [auth-kp (gen-kp 5201)
                      payload (make-payload 2048 "A")
                      target-cid (deploy/sha256-hex payload)
                      ptr (make-signed-ptr auth-kp {:seq 10 :light-node-cid target-cid :artifact-size-bytes 2048})
                      st0 (init-test-updater auth-kp {:range-chunk-bytes 1024})]
                  (loop [st st0
                         rem-ops ops
                         ok? true]
                    (if (or (not ok?) (empty? rem-ops))
                      ok?
                      (let [op (first rem-ops)
                            cur-gen (long (:generation st 1))]
                        (if (= op :stale-callback)
                          (if (> cur-gen 1)
                            (let [stale-gen (dec cur-gen)
                                  ev {:type :blob-fetched
                                      :cid target-cid
                                      :bytes payload
                                      :generation stale-gen}
                                  [st' effs] (deploy/reduce-light-update-tick st ev)
                                  stale-ok? (and (= (:phase st) (:phase st'))
                                                 (= (:pending-update st) (:pending-update st'))
                                                 (= (:current-cid st) (:current-cid st'))
                                                 (= (:last-applied-seq st) (:last-applied-seq st'))
                                                 (= (:http-fallback st) (:http-fallback st'))
                                                 (= (inc (long (:dropped st 0))) (long (:dropped st' 0)))
                                                 (= 1 (count effs))
                                                 (= :diagnose (:effect (first effs)))
                                                 (= :stale-generation-callback (:reason (first effs))))]
                              (recur st' (rest rem-ops) stale-ok?))
                            (recur st (rest rem-ops) ok?))
                          (let [ev (case op
                                     :poll-tick {:type :poll-tick :generation cur-gen}
                                     :pointer-seen-mesh {:type :pointer-seen :pointer ptr :mesh-connected? true :generation cur-gen}
                                     :pointer-seen-http {:type :pointer-seen :pointer ptr :mesh-connected? false :generation cur-gen}
                                     :mesh-fetch-failed {:type :mesh-fetch-failed :reason :mesh-chunk-timeout :generation cur-gen}
                                     :blob-fetch-failed-abort {:type :blob-fetch-failed :reason "aborted" :aborted-mid-body? true :received-bytes 512 :total-bytes 2048 :generation cur-gen}
                                     :blob-fetch-failed-503 {:type :blob-fetch-failed :status 503 :reason "503" :generation cur-gen}
                                     :http-retry-timer-fired {:type :http-retry-timer-fired :generation cur-gen}
                                     :http-range-chunk-fetched {:type :http-range-chunk-fetched
                                                                :status 206
                                                                :start (long (get-in st [:http-fallback :range-offset] 0))
                                                                :end (min 2047 (+ (long (get-in st [:http-fallback :range-offset] 0)) 1023))
                                                                :total-bytes 2048
                                                                :bytes (slice-bs payload
                                                                                 (long (get-in st [:http-fallback :range-offset] 0))
                                                                                 (min 2048 (+ (long (get-in st [:http-fallback :range-offset] 0)) 1024)))
                                                                :etag (str "\"" target-cid "\"")
                                                                :generation cur-gen}
                                     :blob-fetched-good {:type :blob-fetched :cid target-cid :bytes payload :generation cur-gen}
                                     :health-check-ok {:type :health-check-result :healthy? true :generation cur-gen})
                                [st' _effs] (deploy/reduce-light-update-tick st ev)]
                            (recur st' (rest rem-ops) ok?)))))))))

;; =============================================================================
;; 2. Rule 1 Generative Property 2: Mid-Transfer Chunk Corruption Fail-Closed
;; =============================================================================

(defspec ^{:doc "BIP-022 Stage D.1 Prop 2: Random byte-flips in mesh chunks or HTTP 206 Range chunks
                 (first, middle, or final chunk) NEVER emit :stage-light-bundle or
                 :atomic-swap-and-restart-light-node, and fail closed with :mesh-cid-mismatch
                 or :light-update-hash-mismatch."}
  prop-mid-transfer-chunk-corruption-fail-closed 50
  (prop/for-all [corrupt-chunk-idx (gen/choose 0 2)
                 flip-offset (gen/choose 0 1023)
                 mode (gen/elements [:mesh :http-range])]
                (let [auth-kp (gen-kp 5202)
                      chunk-sz 1024
                      total-sz (* 3 chunk-sz)
                      payload (make-payload total-sz "B")
                      target-cid (deploy/sha256-hex payload)
                      ptr (make-signed-ptr auth-kp {:seq 3 :light-node-cid target-cid :artifact-size-bytes total-sz})]
                  (if (= mode :mesh)
                    (let [loop-res (loop [asm (deploy/init-mesh-chunk-assembly target-cid chunk-sz)
                                          req (deploy/build-mesh-chunk-request target-cid 0 chunk-sz "c0")
                                          idx 0]
                                     (let [resp (deploy/serve-mesh-blob-chunk payload req)
                                           resp' (if (= idx corrupt-chunk-idx)
                                                   (update resp :bytes flip-byte-at flip-offset)
                                                   resp)
                                           step (deploy/reduce-mesh-chunk-response asm resp')]
                                       (if (:done? step)
                                         step
                                         (recur (:state step) (:next-req step) (inc idx)))))]
                      (and (true? (:done? loop-res))
                           (false? (:ok? loop-res))
                           (= :mesh-cid-mismatch (:error loop-res))))
                    ;; HTTP Range mode with single relay so exhaustion returns cleanly to :watching
                    (let [st0 (init-test-updater auth-kp {:relay-origins [] :range-chunk-bytes chunk-sz})
                          [st1 _] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr :mesh-connected? false :generation 1})
                          ;; Mid-body abort switches to :fetching-https-range
                          [st2 _] (deploy/reduce-light-update-tick st1 {:type :blob-fetch-failed
                                                                        :aborted-mid-body? true
                                                                        :received-bytes 100
                                                                        :total-bytes total-sz
                                                                        :reason "aborted"
                                                                        :generation (:generation st1)})
                          [st3 _] (deploy/reduce-light-update-tick st2 {:type :http-retry-timer-fired :generation (:generation st2)})
                          [final-st all-effs]
                          (loop [st st3
                                 idx 0
                                 effs-acc []]
                            (if (or (not= :fetching-https-range (:phase st)) (>= idx 3))
                              [st effs-acc]
                              (let [s (* idx chunk-sz)
                                    e (dec (+ s chunk-sz))
                                    raw-chunk (slice-bs payload s (inc e))
                                    chunk-bs (if (= idx corrupt-chunk-idx)
                                               (flip-byte-at raw-chunk flip-offset)
                                               raw-chunk)
                                    [st' effs'] (deploy/reduce-light-update-tick
                                                 st
                                                 {:type :http-range-chunk-fetched
                                                  :status 206
                                                  :start s
                                                  :end e
                                                  :total-bytes total-sz
                                                  :bytes chunk-bs
                                                  :etag (str "\"" target-cid "\"")
                                                  :generation (:generation st)})]
                                (recur st' (inc idx) (into effs-acc effs')))))]
                      (and (= :watching (:phase final-st))
                           (not-any? #(= :stage-light-bundle (:effect %)) all-effs)
                           (not-any? #(= :atomic-swap-and-restart-light-node (:effect %)) all-effs)
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-hash-mismatch (:reason %)))
                                 all-effs)))))))

;; =============================================================================
;; 3. Rule 1 Generative Property 3: Mesh Timeout -> HTTP Failover
;; =============================================================================

(defspec ^{:doc "BIP-022 Stage D.1 Prop 3: Any mesh failure mode deterministically transitions
                 :fetching-mesh -> :fetching-https, increments :generation, emits counted
                 :auto-update-mesh-fallback, and emits :fetch-bundle-blob."}
  prop-mesh-timeout-to-http-failover 50
  (prop/for-all [fail-reason (gen/elements [:mesh-chunk-timeout
                                            :mesh-total-timeout
                                            :not-found
                                            :mesh-disconnected
                                            :mesh-cid-mismatch
                                            :busy])]
                (let [auth-kp (gen-kp 5203)
                      payload (make-payload 512 "M")
                      target-cid (deploy/sha256-hex payload)
                      ptr (make-signed-ptr auth-kp {:seq 4 :light-node-cid target-cid :artifact-size-bytes 512})
                      st0 (init-test-updater auth-kp)
                      [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen
                                                                        :pointer ptr
                                                                        :mesh-connected? true
                                                                        :generation 1})
                      [st2 effs2] (deploy/reduce-light-update-tick st1 {:type :mesh-fetch-failed
                                                                        :cid target-cid
                                                                        :reason fail-reason
                                                                        :generation (:generation st1)})
                      fetch-eff (first (filter #(= :fetch-bundle-blob (:effect %)) effs2))]
                  (and (= :fetching-mesh (:phase st1))
                       (some #(= :fetch-bundle-mesh-chunks (:effect %)) effs1)
                       (= :fetching-https (:phase st2))
                       (= (inc (long (:generation st1))) (long (:generation st2)))
                       (= 1 (get-in st2 [:diagnostics :causes :auto-update-mesh-fallback]))
                       (= 1 (get-in st2 [:diagnostics :auto-update-mesh-fallback]))
                       (some #(and (= :diagnose (:effect %))
                                   (= :auto-update-mesh-fallback (:reason %))
                                   (= fail-reason (:cause %)))
                             effs2)
                       (some? fetch-eff)
                       (= (str "https://bitecho.org/artifact/v1/blob/" target-cid) (:url fetch-eff))
                       (= (:generation st2) (:generation fetch-eff))))))

;; =============================================================================
;; 4. Rule 1 Generative Property 4: HTTP Abort -> Range Resume & Relay Failover
;; =============================================================================

(defspec ^{:doc "BIP-022 Stage D.1 Prop 4: Mid-body HTTP abort at arbitrary offset transitions
                 to :fetching-https-range, emits :light-update-http-range-fallback +
                 :light-update-http-retry, fails over across relays on 502/503/404, and
                 completes with verified SHA-256 == target-cid (or terminates cleanly in :watching
                 when all relays are exhausted)."}
  prop-http-abort-to-range-resume-and-relay-failover 50
  (prop/for-all [abort-offset (gen/choose 1 3071)
                 primary-fail-status (gen/elements [502 503 404])
                 exhaust-all? gen/boolean]
                (let [auth-kp (gen-kp 5204)
                      chunk-sz 1024
                      total-sz 3072
                      payload (make-payload total-sz "R")
                      target-cid (deploy/sha256-hex payload)
                      ptr (make-signed-ptr auth-kp {:seq 5 :light-node-cid target-cid :artifact-size-bytes total-sz})
                      st0 (init-test-updater auth-kp {:range-chunk-bytes chunk-sz
                                                      :max-retries-per-relay 2})
                      [st1 _] (deploy/reduce-light-update-tick st0 {:type :pointer-seen
                                                                    :pointer ptr
                                                                    :mesh-connected? false
                                                                    :generation 1})
                      ;; Trigger mid-body abort on primary origin
                      [st2 effs2] (deploy/reduce-light-update-tick st1 {:type :blob-fetch-failed
                                                                        :aborted-mid-body? true
                                                                        :received-bytes abort-offset
                                                                        :total-bytes total-sz
                                                                        :reason "Error: aborted"
                                                                        :generation (:generation st1)})]
                  (if exhaust-all?
                    ;; Exhaust every relay with repeated failures -> must cleanly terminate in :watching
                    (let [[final-st final-effs]
                          (loop [st st2
                                 effs-acc effs2
                                 steps 0]
                            (if (or (= :watching (:phase st)) (> steps 30))
                              [st effs-acc]
                              (let [[st' e'] (if (some #(= :schedule-http-retry (:effect %)) effs-acc)
                                               (let [[sa ea] (deploy/reduce-light-update-tick st {:type :http-retry-timer-fired :generation (:generation st)})
                                                     [sb eb] (deploy/reduce-light-update-tick sa {:type :blob-fetch-failed :status primary-fail-status :reason "relay-down" :generation (:generation sa)})]
                                                 [sb (into ea eb)])
                                               (deploy/reduce-light-update-tick st {:type :blob-fetch-failed :status primary-fail-status :reason "relay-down" :generation (:generation st)}))]
                                (recur st' (into effs-acc e') (inc steps)))))]
                      (and (= :fetching-https-range (:phase st2))
                           (= :watching (:phase final-st))
                           (nil? (:pending-update final-st))
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-http-range-fallback (:reason %)))
                                 final-effs)
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-relay-failover (:reason %)))
                                 final-effs)
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-blob-fetch-failed (:reason %)))
                                 final-effs)))
                    ;; Failover from relay 0 (bitecho.org) to relay 1 (ns1) after primary-fail-status,
                    ;; then serve all 3 x 1024-byte 206 chunks cleanly
                    (let [[st3 _] (deploy/reduce-light-update-tick st2 {:type :http-retry-timer-fired :generation (:generation st2)})
                          ;; Fail relay 0 until failover to relay 1
                          [st-r1 effs-fo]
                          (loop [st st3
                                 effs-acc []
                                 steps 0]
                            (if (or (>= (long (get-in st [:http-fallback :relay-index] 0)) 1) (> steps 10))
                              [st effs-acc]
                              (let [[sa ea] (deploy/reduce-light-update-tick st {:type :blob-fetch-failed
                                                                                 :status primary-fail-status
                                                                                 :reason "primary-down"
                                                                                 :generation (:generation st)})
                                    [sb eb] (if (some #(= :schedule-http-retry (:effect %)) ea)
                                              (deploy/reduce-light-update-tick sa {:type :http-retry-timer-fired :generation (:generation sa)})
                                              [sa []])]
                                (recur sb (into (into effs-acc ea) eb) (inc steps)))))
                          ;; Serve 3 chunks from relay 1
                          [st-done effs-done]
                          (loop [st st-r1
                                 effs-acc []
                                 steps 0]
                            (if (or (not= :fetching-https-range (:phase st)) (> steps 5))
                              [st effs-acc]
                              (let [off (long (get-in st [:http-fallback :range-offset] 0))
                                    end (min (dec total-sz) (+ off chunk-sz -1))
                                    [st' e'] (deploy/reduce-light-update-tick
                                              st
                                              {:type :http-range-chunk-fetched
                                               :status 206
                                               :start off
                                               :end end
                                               :total-bytes total-sz
                                               :bytes (slice-bs payload off (inc end))
                                               :etag (str "\"" target-cid "\"")
                                               :generation (:generation st)})]
                                (recur st' (into effs-acc e') (inc steps)))))]
                      (and (= :fetching-https-range (:phase st2))
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-http-range-fallback (:reason %)))
                                 effs2)
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-http-retry (:reason %)))
                                 effs2)
                           (some #(and (= :diagnose (:effect %))
                                       (= :light-update-relay-failover (:reason %)))
                                 effs-fo)
                           (= :health-checking (:phase st-done))
                           (some #(= :stage-light-bundle (:effect %)) effs-done)
                           (some #(= :atomic-swap-and-restart-light-node (:effect %)) effs-done)))))))

;; =============================================================================
;; 5. Rule 1 Generative Property 5: Zero Silent Drops Invariant (Rule 5)
;; =============================================================================

(defspec ^{:doc "BIP-022 Stage D.1 Prop 5 (Rule 5): Across all generated command sequences
                 (including wrong-phase, stale-gen, aborts, failovers, corrupted chunks, rollbacks),
                 (:dropped st) == (get-in st [:diagnostics :dropped]) == sum(vals(causes))
                 and every increment corresponds 1-to-1 with an emitted :diagnose effect."}
  prop-zero-silent-drops-invariant 60
  (prop/for-all [ops (gen/vector
                      (gen/elements [:poll-tick
                                     :pointer-seen-mesh
                                     :pointer-seen-http
                                     :mesh-fetch-failed
                                     :blob-fetch-failed-abort
                                     :blob-fetch-failed-503
                                     :blob-fetch-failed-404
                                     :http-retry-timer-fired
                                     :http-range-chunk-ok
                                     :http-range-chunk-bad-bounds
                                     :blob-fetched-bad
                                     :blob-fetched-good
                                     :health-check-fail
                                     :health-check-ok
                                     :stale-gen])
                      5 30)]
                (let [auth-kp (gen-kp 5205)
                      payload (make-payload 2048 "Z")
                      bad-payload (make-payload 2048 "X")
                      target-cid (deploy/sha256-hex payload)
                      ptr (make-signed-ptr auth-kp {:seq 7 :light-node-cid target-cid :artifact-size-bytes 2048})
                      st0 (init-test-updater auth-kp {:range-chunk-bytes 1024})]
                  (loop [st st0
                         rem-ops ops
                         total-diag-effs 0
                         ok? true]
                    (if (or (not ok?) (empty? rem-ops))
                      ok?
                      (let [op (first rem-ops)
                            cur-gen (long (:generation st 1))
                            off (long (get-in st [:http-fallback :range-offset] 0))
                            ev (case op
                                 :poll-tick {:type :poll-tick :generation cur-gen}
                                 :pointer-seen-mesh {:type :pointer-seen :pointer ptr :mesh-connected? true :generation cur-gen}
                                 :pointer-seen-http {:type :pointer-seen :pointer ptr :mesh-connected? false :generation cur-gen}
                                 :mesh-fetch-failed {:type :mesh-fetch-failed :reason :mesh-chunk-timeout :generation cur-gen}
                                 :blob-fetch-failed-abort {:type :blob-fetch-failed :aborted-mid-body? true :received-bytes 256 :total-bytes 2048 :reason "aborted" :generation cur-gen}
                                 :blob-fetch-failed-503 {:type :blob-fetch-failed :status 503 :reason "503" :generation cur-gen}
                                 :blob-fetch-failed-404 {:type :blob-fetch-failed :status 404 :reason "404" :generation cur-gen}
                                 :http-retry-timer-fired {:type :http-retry-timer-fired :generation cur-gen}
                                 :http-range-chunk-ok {:type :http-range-chunk-fetched
                                                       :status 206
                                                       :start off
                                                       :end (min 2047 (+ off 1023))
                                                       :total-bytes 2048
                                                       :bytes (slice-bs payload off (min 2048 (+ off 1024)))
                                                       :etag target-cid
                                                       :generation cur-gen}
                                 :http-range-chunk-bad-bounds {:type :http-range-chunk-fetched
                                                               :status 206
                                                               :start (+ off 99)
                                                               :end (+ off 199)
                                                               :total-bytes 2048
                                                               :bytes (make-payload 101 "Z")
                                                               :generation cur-gen}
                                 :blob-fetched-bad {:type :blob-fetched :cid target-cid :bytes bad-payload :generation cur-gen}
                                 :blob-fetched-good {:type :blob-fetched :cid target-cid :bytes payload :generation cur-gen}
                                 :health-check-fail {:type :health-check-result :healthy? false :generation cur-gen}
                                 :health-check-ok {:type :health-check-result :healthy? true :generation cur-gen}
                                 :stale-gen {:type :poll-tick :generation (dec cur-gen)})
                            [st' effs] (deploy/reduce-light-update-tick st ev)
                            diag-cnt (count (filter #(= :diagnose (:effect %)) effs))
                            next-total (+ total-diag-effs diag-cnt)
                            inv-ok? (and (= (long (:dropped st' 0)) next-total)
                                         (= (long (get-in st' [:diagnostics :dropped] 0)) next-total)
                                         (= (causes-sum st') next-total))]
                        (recur st' (rest rem-ops) next-total inv-ok?)))))))

;; =============================================================================
;; 6. Cross-Relay ETag Normalization & Multi-Relay URL Derivation Tests
;; =============================================================================

(deftest cross-relay-etag-normalization-test
  (testing "Quoted, unquoted, weak W/\"...\", and uppercase CID ETags normalize identically across ns1 -> ns2 Range failover"
    (let [auth-kp (gen-kp 5206)
          chunk-sz 1024
          total-sz 2048
          payload (make-payload total-sz "E")
          target-cid (deploy/sha256-hex payload)
          ptr (make-signed-ptr auth-kp {:seq 8 :light-node-cid target-cid :artifact-size-bytes total-sz})
          st0 (init-test-updater auth-kp {:range-chunk-bytes chunk-sz :max-retries-per-relay 1})
          [st1 _] (deploy/reduce-light-update-tick st0 {:type :pointer-seen :pointer ptr :mesh-connected? false :generation 1})
          ;; Mid-body abort switches to :fetching-https-range
          [st2 _] (deploy/reduce-light-update-tick st1 {:type :blob-fetch-failed
                                                        :aborted-mid-body? true
                                                        :received-bytes 128
                                                        :total-bytes total-sz
                                                        :reason "aborted"
                                                        :generation (:generation st1)})
          [st3 _] (deploy/reduce-light-update-tick st2 {:type :http-retry-timer-fired :generation (:generation st2)})
          ;; Chunk 0 from bitecho.org with quoted ETag "\"<cid>\""
          [st4 _] (deploy/reduce-light-update-tick st3 {:type :http-range-chunk-fetched
                                                        :status 206
                                                        :start 0
                                                        :end 1023
                                                        :total-bytes total-sz
                                                        :bytes (slice-bs payload 0 1024)
                                                        :etag (str "\"" target-cid "\"")
                                                        :generation (:generation st3)})
          ;; Failover to ns1 (status 404 -> immediate relay failover preserving range-offset 1024!)
          [st5 effs5] (deploy/reduce-light-update-tick st4 {:type :blob-fetch-failed
                                                            :status 404
                                                            :reason "404"
                                                            :generation (:generation st4)})
          ;; Chunk 1 from ns1 with unquoted uppercase ETag (or W/"<cid>")
          [st6 effs6] (deploy/reduce-light-update-tick st5 {:type :http-range-chunk-fetched
                                                            :status 206
                                                            :start 1024
                                                            :end 2047
                                                            :total-bytes total-sz
                                                            :bytes (slice-bs payload 1024 2048)
                                                            :etag (str "W/\"" (str/upper-case target-cid) "\"")
                                                            :generation (:generation st5)})]
      (is (= target-cid (deploy/normalize-etag-cid (str "\"" target-cid "\""))))
      (is (= target-cid (deploy/normalize-etag-cid target-cid)))
      (is (= target-cid (deploy/normalize-etag-cid (str "W/\"" (str/upper-case target-cid) "\""))))
      (is (= 1024 (get-in st5 [:http-fallback :range-offset]))
          "Cross-relay failover must preserve range-offset")
      (is (some #(and (= :diagnose (:effect %)) (= :light-update-relay-failover (:reason %))) effs5))
      (is (= :health-checking (:phase st6))
          "Quoted vs weak/unquoted CID ETag across relays must NOT false-reject identical content")
      (is (some #(= :stage-light-bundle (:effect %)) effs6)))))

(deftest force-http-and-build-blob-fetch-urls-test
  (testing ":force-http? true bypasses :fetching-mesh even when :mesh-connected? true"
    (let [auth-kp (gen-kp 5207)
          payload (make-payload 256 "F")
          target-cid (deploy/sha256-hex payload)
          ptr (make-signed-ptr auth-kp {:seq 9 :light-node-cid target-cid})
          st0 (init-test-updater auth-kp {:force-http? true})
          [st1 effs1] (deploy/reduce-light-update-tick st0 {:type :pointer-seen
                                                            :pointer ptr
                                                            :mesh-connected? true
                                                            :generation 1})]
      (is (= :fetching-https (:phase st1)))
      (is (not-any? #(= :fetch-bundle-mesh-chunks (:effect %)) effs1))
      (is (some #(= :fetch-bundle-blob (:effect %)) effs1))))

  (testing "build-blob-fetch-urls deduplicates origins and preserves pointer-url first"
    (let [cid (deploy/sha256-hex (fressian/utf8->bytes "urls-test"))
          urls (deploy/build-blob-fetch-urls "https://ns1.bitecho.org/pointer.edn"
                                             ["https://bitecho.org"
                                              "https://ns1.bitecho.org/"
                                              "https://ns2.bitecho.org"
                                              "https://ns3.bitecho.org"]
                                             cid)]
      (is (= [(str "https://ns1.bitecho.org/artifact/v1/blob/" cid)
              (str "https://bitecho.org/artifact/v1/blob/" cid)
              (str "https://ns2.bitecho.org/artifact/v1/blob/" cid)
              (str "https://ns3.bitecho.org/artifact/v1/blob/" cid)]
             urls))))

  (testing "safe-blob-response-headers includes Accept-Ranges: bytes and optional Content-Range"
    (let [cid (apply str (repeat 64 "a"))
          h200 (cc/safe-blob-response-headers {:cid cid :content-type "application/octet-stream" :content-length 1024})
          h206 (cc/safe-blob-response-headers {:cid cid :content-type "application/octet-stream" :content-length 256 :content-range "bytes 0-255/1024"})]
      (is (= "bytes" (get h200 "Accept-Ranges")))
      (is (nil? (get h200 "Content-Range")))
      (is (= "bytes" (get h206 "Accept-Ranges")))
      (is (= "bytes 0-255/1024" (get h206 "Content-Range")))
      (is (= "256" (get h206 "Content-Length"))))))

;; =============================================================================
;; 7. JVM Integration Tests: HTTP 206 Range on /artifact/v1/blob/<cid>,
;;    Positional FileChannel Chunk Read + Semaphore, and Closure/Wiring Audit
;; =============================================================================

#?(:clj
   (deftest jvm-http-artifact-blob-206-range-test
     (testing "JVM /artifact/v1/blob/<cid> serves Accept-Ranges: bytes, 206 Partial Content, and 416 Range Not Satisfiable"
       (let [tmp-dir (.toFile (Files/createTempDirectory "bitecho-d52-http-" (into-array FileAttribute [])))
             kp1 (crypto/generate-keypair 5211)
             pk1 (basalt/bytes->hex (:public-key kp1))
             pol (infra/default-infra-policy {:subnet-id "bitecho.org/d52"
                                              :trust-anchors #{pk1}
                                              :threshold 1})
             payload (make-payload 4096 "H")
             blob (data/make-blob payload {:mime "application/octet-stream"})
             cid (:blob/cid blob)
             rt (infra/start-subnet-runtime! {:policy pol
                                              :state-dir (str tmp-dir)
                                              :node-id pk1
                                              :node-privkey (:private-key kp1)
                                              :all-nodes #{pk1}})
             _ (infra/put-blob! rt blob)
             tls-mgr (http-shell/init-tls-manager! {:state-dir (str tmp-dir) :domain "localhost"})
             http-srv (http-shell/start-http-servers!
                       {:domain "bitecho.org"
                        :state-dir (str tmp-dir)
                        :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0 :redirect-http-to-https? false}}
                       tls-mgr
                       rt)]
         (try
           (let [port (:http-port http-srv)
                 url (str "http://127.0.0.1:" port "/artifact/v1/blob/" cid)
                 client (HttpClient/newHttpClient)
                 ;; 1. Full 200 GET includes Accept-Ranges: bytes
                 r200 (.send client
                             (-> (HttpRequest/newBuilder (URI/create url)) (.GET) (.build))
                             (HttpResponse$BodyHandlers/ofByteArray))
                 ;; 2. 206 Partial Content Range: bytes=1024-2047
                 r206 (.send client
                             (-> (HttpRequest/newBuilder (URI/create url))
                                 (.header "Range" "bytes=1024-2047")
                                 (.GET)
                                 (.build))
                             (HttpResponse$BodyHandlers/ofByteArray))
                 ;; 3. 416 Range Not Satisfiable
                 r416 (.send client
                             (-> (HttpRequest/newBuilder (URI/create url))
                                 (.header "Range" "bytes=99999-100000")
                                 (.GET)
                                 (.build))
                             (HttpResponse$BodyHandlers/ofByteArray))]
             (is (= 200 (.statusCode r200)))
             (is (= "bytes" (.orElse (.firstValue (.headers r200) "Accept-Ranges") nil)))
             (is (= 4096 (alength ^bytes (.body r200))))
             (is (= 206 (.statusCode r206)))
             (is (= "bytes 1024-2047/4096" (.orElse (.firstValue (.headers r206) "Content-Range") nil)))
             (is (= "bytes" (.orElse (.firstValue (.headers r206) "Accept-Ranges") nil)))
             (is (= 1024 (alength ^bytes (.body r206))))
             (is (= (vec (slice-bs payload 1024 2048)) (vec ^bytes (.body r206))))
             (is (= 416 (.statusCode r416)))
             (is (= "bytes */4096" (.orElse (.firstValue (.headers r416) "Content-Range") nil))))
           (finally
             (http-shell/stop-http-servers! http-srv)
             (infra/stop-subnet-runtime! rt)
             (try (run! io/delete-file (reverse (file-seq tmp-dir))) (catch Exception _ nil))))))))

#?(:clj
   (deftest jvm-positional-disk-blob-chunk-read-test
     (testing "JVM positional FileChannel chunk read serves exact slice from disk CAS without full-file allocation"
       (let [tmp-dir (.toFile (Files/createTempDirectory "bitecho-d52-cas-" (into-array FileAttribute [])))
             payload (byte-array (map #(unchecked-byte (mod % 251)) (range 4096)))
             blob (data/make-blob payload {:mime "application/octet-stream"})
             cid (:blob/cid blob)]
         (try
           (let [wres (blob-fs/write-blob! (str tmp-dir) blob)]
             (is (:ok? wres))
             (let [sres (mesh-shell/read-disk-blob-chunk-positional (str tmp-dir) cid 1024 512)]
               (is (true? (:ok? sres)))
               (is (= 4096 (:total-bytes sres)))
               (is (= 512 (alength ^bytes (:bytes sres))))
               (is (= (vec (slice-bs payload 1024 1536)) (vec ^bytes (:bytes sres)))))
             (let [oob (mesh-shell/read-disk-blob-chunk-positional (str tmp-dir) cid 5000 512)]
               (is (false? (:ok? oob)))
               (is (= :offset-out-of-range (:error oob)))))
           (finally
             (try (run! io/delete-file (reverse (file-seq tmp-dir))) (catch Exception _ nil))))))))

#?(:clj
   (deftest stage-d1-closure-advanced-and-wiring-audit-test
     (testing "full_node_main.cljs uses bounded positional fh.read + semaphore (not full-file read-disk-blob-async!) on :artifact-blob-chunk-req"
       (let [full-src (slurp "src/bitecho/full_node_main.cljs")]
         (is (str/includes? full-src "read-disk-blob-slice-async!"))
         (is (str/includes? full-src ":mesh-chunk-read-throttled"))
         (is (str/includes? full-src "keepAliveTimeout"))
         (is (str/includes? full-src "headersTimeout"))
         (is (str/includes? full-src "requestTimeout"))
         (is (str/includes? full-src ":fetch-bundle-mesh-chunks")
             "Full node auto-updater must wire :fetch-bundle-mesh-chunks")))
     (testing "node_main.cljs hardens http-get-bytes! with agent: false, Connection: close, aborted/complete checks, and req-id-only mesh dispatch"
       (let [node-src (slurp "src/bitecho/node_main.cljs")]
         (is (str/includes? node-src "\"aborted\""))
         (is (str/includes? node-src ":schedule-http-retry"))
         (is (str/includes? node-src ":http-range-chunk-fetched"))
         (is (str/includes? node-src "--auto-update-force-http"))))
     (testing "JVM callers (shell/light_node.clj & main.clj) wire :mesh-connected-fn and :mesh-chunk-fetch-fn"
       (let [ln-src (slurp "src/bitecho/shell/light_node.clj")
             main-src (slurp "src/bitecho/main.clj")
             upd-src (slurp "src/bitecho/shell/updater.clj")]
         (is (str/includes? ln-src ":mesh-connected-fn"))
         (is (str/includes? ln-src ":mesh-chunk-fetch-fn"))
         (is (str/includes? main-src ":mesh-connected-fn"))
         (is (str/includes? main-src ":mesh-chunk-fetch-fn"))
         (is (str/includes? upd-src ":schedule-http-retry"))
         (is (str/includes? upd-src ":http-range-chunk-fetched"))))))
