(ns bitecho.storage.chunk-fetch-test
  "Strict-TDD generative & model-based tests for BIP-017a chunked large-artifact storage
   (Rules 1, 2, 4, 5, 6). Runs on both JVM and ClojureScript Node.js."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.storage.chunk-constants :as cc]
            [bitecho.storage.chunk-fetch :as cf]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- make-chunk-specs
  "Builds deterministic chunk metadata for `total-bytes` split by `chunk-size`."
  [total-bytes chunk-size seed]
  (let [n-chunks (long (Math/ceil (/ (double total-bytes) (double chunk-size))))]
    (loop [idx 0
           rem-bytes total-bytes
           acc []]
      (if (>= idx n-chunks)
        acc
        (let [sz (min chunk-size rem-bytes)
              cid (crypto/sha256-hex (str "chunk-" seed "-" idx "-" sz))]
          (recur (inc idx)
                 (- rem-bytes sz)
                 (conj acc {"index" idx "cid" cid "size" sz})))))))

(defn- make-valid-manifest
  [{:keys [total-bytes chunk-size owner-pubkey grace-epochs seed artifact-name]
    :or {total-bytes 523264
         chunk-size 65536
         grace-epochs 4
         seed 1
         artifact-name "af_heart.bin"}}]
  (let [kp (or owner-pubkey
               (fressian/bytes->hex (:public (crypto/generate-keypair 42))))
        chunks (make-chunk-specs total-bytes chunk-size seed)
        total-sha256 (crypto/sha256-hex (str "total-" seed "-" total-bytes))]
    {"version" 1
     "artifact_name" artifact-name
     "content_type" "application/octet-stream"
     "chunk_size" chunk-size
     "total_bytes" total-bytes
     "total_sha256" total-sha256
     "chunks" chunks
     "state_owner" kp
     "retention_policy" {"grace_epochs" grace-epochs}}))

(defn- causes-sum
  [state]
  (reduce + 0 (vals (get-in state [:diagnostics :causes] {}))))

;; =============================================================================
;; 1. RFC 8785 JCS Canonicalization & Cross-Runtime Manifest CID Golden Vectors
;; =============================================================================

(deftest test-jcs-canonicalization-and-manifest-cid
  (testing "RFC 8785 JCS produces deterministic sorted-key compact JSON with identical manifest-cid across JVM and CLJS"
    (let [m1 {"version" 1
              "total_bytes" 131072
              "chunk_size" 65536
              "total_sha256" (apply str (repeat 64 "a"))
              "state_owner" (apply str (repeat 64 "b"))
              "retention_policy" {"grace_epochs" 4}
              "chunks" [{"size" 65536 "index" 0 "cid" (apply str (repeat 64 "1"))}
                        {"cid" (apply str (repeat 64 "2")) "size" 65536 "index" 1}]}
          ;; Same logical manifest with different map insertion order
          m2 (array-map
              "chunks" [(array-map "cid" (apply str (repeat 64 "1")) "index" 0 "size" 65536)
                        (array-map "index" 1 "size" 65536 "cid" (apply str (repeat 64 "2")))]
              "retention_policy" {"grace_epochs" 4}
              "state_owner" (apply str (repeat 64 "b"))
              "total_sha256" (apply str (repeat 64 "a"))
              "chunk_size" 65536
              "total_bytes" 131072
              "version" 1)
          jcs1 (cc/jcs-canonicalize m1)
          jcs2 (cc/jcs-canonicalize m2)
          cid1 (cc/manifest-cid m1)
          cid2 (cc/manifest-cid m2)]
      (is (= jcs1 jcs2))
      (is (= cid1 cid2))
      (is (= 64 (count cid1)))
      (is (re-matches #"^[0-9a-f]{64}$" cid1))
      ;; Verify domain tag prefix is strictly included
      (is (= cid1 (crypto/sha256-hex (str cc/manifest-domain-tag jcs1))))
      ;; Golden vector check: exact canonical string
      (is (= (str "{\"chunk_size\":65536,"
                  "\"chunks\":[{\"cid\":\"" (apply str (repeat 64 "1")) "\",\"index\":0,\"size\":65536},"
                  "{\"cid\":\"" (apply str (repeat 64 "2")) "\",\"index\":1,\"size\":65536}],"
                  "\"retention_policy\":{\"grace_epochs\":4},"
                  "\"state_owner\":\"" (apply str (repeat 64 "b")) "\","
                  "\"total_bytes\":131072,"
                  "\"total_sha256\":\"" (apply str (repeat 64 "a")) "\","
                  "\"version\":1}")
             jcs1))))

  (testing "RFC 8785 JCS rejects non-integer floats fail-closed"
    (is (thrown? #?(:clj Exception :cljs js/Error)
                 (cc/jcs-canonicalize {"version" 1.5})))))

;; =============================================================================
;; 2. Constants, Cap Clamping, Manifest Validation & Detached Owner Envelopes
;; =============================================================================

(deftest test-constants-and-cap-clamping
  (testing "BIP-017a required constants match specification"
    (is (= "bitecho/chunk-manifest/v1" cc/manifest-domain-tag))
    (is (= 65536 cc/min-chunk-bytes))
    (is (= 1048576 cc/default-chunk-bytes))
    (is (= 4194304 cc/max-chunk-bytes))
    (is (= 8192 cc/max-chunks-per-manifest))
    (is (= 2 cc/default-fetch-concurrency))
    (is (= 3 cc/max-fetch-concurrency-940mb))
    (is (= 4 cc/min-grace-epochs))
    (is (= 2147483648 cc/default-infra-chunk-quota-bytes)))

  (testing "Pure (min constant config) clamp emits :cap-ceiling-clamped when config exceeds constant"
    (let [res-over (cc/clamp-cap :concurrency cc/max-fetch-concurrency-940mb 16)
          res-ok (cc/clamp-cap :concurrency cc/max-fetch-concurrency-940mb 2)]
      (is (= 3 (:value res-over)))
      (is (true? (:clamped? res-over)))
      (is (= :cap-ceiling-clamped (get-in res-over [:effects 0 :kind])))
      (is (= 2 (:value res-ok)))
      (is (false? (:clamped? res-ok)))
      (is (empty? (:effects res-ok))))))

(deftest test-manifest-validation-fail-closed
  (testing "Valid manifest passes"
    (let [m (make-valid-manifest {})
          res (cc/validate-manifest m)]
      (is (true? (:ok? res)))
      (is (= 64 (count (:manifest-cid res))))
      (is (empty? (:effects res)))))

  (testing "Missing state_owner emits :missing-state-owner"
    (let [m (dissoc (make-valid-manifest {}) "state_owner")
          res (cc/validate-manifest m)]
      (is (false? (:ok? res)))
      (is (= :missing-state-owner (:error res)))
      (is (= :missing-state-owner (get-in res [:effects 0 :kind])))))

  (testing "Missing or undersized retention_policy emits :missing-retention-policy"
    (let [m1 (dissoc (make-valid-manifest {}) "retention_policy")
          m2 (assoc-in (make-valid-manifest {}) ["retention_policy" "grace_epochs"] 3)
          r1 (cc/validate-manifest m1)
          r2 (cc/validate-manifest m2)]
      (is (= :missing-retention-policy (:error r1)))
      (is (= :missing-retention-policy (get-in r1 [:effects 0 :kind])))
      (is (= :missing-retention-policy (:error r2)))
      (is (= :missing-retention-policy (get-in r2 [:effects 0 :kind])))))

  (testing "Sum of chunk sizes != total_bytes emits :storage-accounting-mismatch"
    (let [m (assoc (make-valid-manifest {}) "total_bytes" 999999)
          res (cc/validate-manifest m)]
      (is (false? (:ok? res)))
      (is (= :storage-accounting-mismatch (:error res)))
      (is (= :storage-accounting-mismatch (get-in res [:effects 0 :kind])))))

  (testing "total_bytes exceeding configured :max-bytes emits :max-bytes-exceeded"
    (let [m (make-valid-manifest {:total-bytes 523264})
          res (cc/validate-manifest m {:max-bytes 100000})]
      (is (false? (:ok? res)))
      (is (= :max-bytes-exceeded (:error res)))
      (is (= :max-bytes-exceeded (get-in res [:effects 0 :kind]))))))

(deftest test-detached-owner-envelope-verification
  (let [kp1 (crypto/generate-keypair 101)
        kp2 (crypto/generate-keypair 202)
        pub1 (fressian/bytes->hex (:public kp1))
        priv1 (:private kp1)
        pub2 (fressian/bytes->hex (:public kp2))
        priv2 (:private kp2)
        manifest (make-valid-manifest {:owner-pubkey pub1})
        mcid (cc/manifest-cid manifest)
        valid-env (cc/sign-detached-owner-envelope mcid pub1 priv1)]

    (testing "Valid single detached owner envelope verifies"
      (let [res (cc/verify-detached-owner-envelope manifest valid-env)]
        (is (true? (:ok? res)))
        (is (= mcid (:manifest-cid res)))
        (is (= pub1 (:owner-pubkey res)))
        (is (empty? (:effects res)))))

    (testing "Missing state_owner or owner-pubkey fails closed with :missing-state-owner"
      (let [res (cc/verify-detached-owner-envelope (dissoc manifest "state_owner") valid-env)]
        (is (false? (:ok? res)))
        (is (= :missing-state-owner (:error res)))
        (is (= :missing-state-owner (get-in res [:effects 0 :kind])))))

    (testing "Tampered signature or wrong signer fails closed with :owner-signature-invalid"
      (let [bad-env (assoc valid-env :sig (apply str (repeat 128 "0")))
            wrong-signer-env (cc/sign-detached-owner-envelope mcid pub2 priv2)
            r1 (cc/verify-detached-owner-envelope manifest bad-env)
            r2 (cc/verify-detached-owner-envelope manifest wrong-signer-env)]
        (is (= :owner-signature-invalid (:error r1)))
        (is (= :owner-signature-invalid (get-in r1 [:effects 0 :kind])))
        (is (= :owner-signature-invalid (:error r2)))
        (is (= :owner-signature-invalid (get-in r2 [:effects 0 :kind])))))

    (testing "Multiple (>1) verifying owner signatures fail closed with :owner-signature-ambiguous"
      (let [env2 (cc/sign-detached-owner-envelope mcid pub1 priv1)
            res (cc/verify-detached-owner-envelope manifest [valid-env env2])]
        (is (false? (:ok? res)))
        (is (= :owner-signature-ambiguous (:error res)))
        (is (= :owner-signature-ambiguous (get-in res [:effects 0 :kind])))))))

;; =============================================================================
;; 3. Quota Accounting (Including Staged-But-Unhashed Bytes) & Refcounted GC
;; =============================================================================

(deftest test-chunk-quota-and-refcounted-gc
  (testing "Staged-but-unhashed bytes are counted toward :bytes-at-rest and HTTP 507 quota"
    (let [r-ok (cc/evaluate-chunk-quota {:committed-bytes 1000
                                         :staged-unhashed-bytes 500
                                         :incoming-bytes 400
                                         :max-quota-bytes 2000})
          r-507 (cc/evaluate-chunk-quota {:committed-bytes 1000
                                          :staged-unhashed-bytes 800
                                          :incoming-bytes 300
                                          :max-quota-bytes 2000})]
      (is (true? (:ok? r-ok)))
      (is (= 1500 (:bytes-at-rest r-ok)))
      (is (= 200 (:http-status r-ok)))
      (is (false? (:ok? r-507)))
      (is (= 507 (:http-status r-507)))
      (is (= 1800 (:bytes-at-rest r-507)))
      (is (= :chunk-store-quota-exceeded (:error r-507)))
      (is (= :chunk-store-quota-exceeded (get-in r-507 [:effects 0 :kind])))))

  (testing "Refcounted GC is only eligible when refcount == 0 and elapsed >= grace-epochs >= 4"
    (is (false? (:eligible? (cc/refcounted-gc-eligible? {:refcount 1 :unreferenced-since-epoch 10 :current-epoch 20 :grace-epochs 4}))))
    (is (false? (:eligible? (cc/refcounted-gc-eligible? {:refcount 0 :unreferenced-since-epoch 10 :current-epoch 13 :grace-epochs 4}))))
    (is (true? (:eligible? (cc/refcounted-gc-eligible? {:refcount 0 :unreferenced-since-epoch 10 :current-epoch 14 :grace-epochs 4}))))
    ;; Even if caller passes grace-epochs < 4, min-grace-epochs (4) is enforced
    (let [r-under (cc/refcounted-gc-eligible? {:refcount 0 :unreferenced-since-epoch 10 :current-epoch 12 :grace-epochs 2})]
      (is (false? (:eligible? r-under)))
      (is (= :missing-retention-policy (get-in r-under [:effects 0 :kind]))))))

(deftest test-safe-blob-response-headers
  (testing "Safe headers for binary, wasm, json, text, and sandboxed html blobs"
    (let [cid (apply str (repeat 64 "a"))
          h-bin (cc/safe-blob-response-headers {:cid cid :content-type "application/octet-stream" :content-length 65536})
          h-html (cc/safe-blob-response-headers {:cid cid :content-type "text/html; charset=utf-8" :content-length 128})
          h-svg (cc/safe-blob-response-headers {:cid cid :content-type "image/svg+xml" :content-length 128})]
      (is (= "public, max-age=31536000, immutable" (get h-bin "Cache-Control")))
      (is (= "*" (get h-bin "Access-Control-Allow-Origin")))
      (is (= "application/octet-stream" (get h-bin "Content-Type")))
      (is (nil? (get h-bin "Content-Security-Policy")))
      ;; text/html MUST have CSP: sandbox without allow-same-origin
      (is (= "sandbox" (get h-html "Content-Security-Policy")))
      ;; Unknown/unsafe MIME (e.g. image/svg+xml) falls back to application/octet-stream
      (is (= "application/octet-stream" (get h-svg "Content-Type")))))

  (testing "Allowlisted safe content types are preserved"
    (doseq [ct ["application/octet-stream"
                "application/wasm"
                "application/json"
                "text/plain; charset=utf-8"
                "text/markdown; charset=utf-8"]]
      (let [h (cc/safe-blob-response-headers {:cid (apply str (repeat 64 "c")) :content-type ct :content-length 10})]
        (is (= ct (get h "Content-Type")))))))

;; =============================================================================
;; 4. Pure Sans-IO Chunk Fetch State Machine: af_heart Interrupt/Resume & Faults
;; =============================================================================

(deftest test-af-heart-interrupt-and-resume-zero-redundant-fetches
  (testing "af_heart 511 KiB (523264 bytes) at 65536 chunk-size (8 chunks): interrupt at 4/8 + resume"
    (let [manifest (make-valid-manifest {:total-bytes 523264 :chunk-size 65536 :artifact-name "af_heart.bin"})
          chunks (get manifest "chunks")
          _ (is (= 8 (count chunks)))
          init-res (cf/init-fetch-state {:manifest manifest
                                         :mirrors ["https://m1.bitecho.org" "https://m2.bitecho.org"]
                                         :concurrency 2})
          st0 (:state init-res)
          [st1 effs1] (cf/transition st0 {:type :start :generation 1 :cached-indices #{}})
          ;; Fetch first 4 chunks (indices 0..3) and digest them
          st-after-4
          (loop [st st1
                 effs effs1
                 fetched 0]
            (if (>= fetched 4)
              st
              (let [fetch-eff (first (filter #(= :fetch-chunk (:type %)) effs))
                    idx (:index fetch-eff)
                    ch (nth chunks idx)
                    [st-f effs-f] (cf/transition st {:type :chunk-fetched
                                                     :generation (:generation st)
                                                     :index idx
                                                     :mirror (:mirror fetch-eff)
                                                     :cid (get ch "cid")
                                                     :size (get ch "size")})
                    ;; Process any digest-chunk effects immediately
                    [st-d effs-d] (reduce (fn [[s acc] e]
                                            (if (= :digest-chunk (:type e))
                                              (let [[s2 e2] (cf/transition s {:type :digest-result
                                                                              :generation (:generation s)
                                                                              :index (:index e)
                                                                              :ok? true})]
                                                [s2 (into acc e2)])
                                              [s (conj acc e)]))
                                          [st-f []]
                                          effs-f)]
                (recur st-d (concat (rest (filter #(= :fetch-chunk (:type %)) effs)) effs-d) (inc fetched)))))]
      (is (= 4 (count (:staged-chunks st-after-4))))
      ;; Interrupt (pause) and resume in generation 2 with cached indices #{0 1 2 3}
      (let [[st-paused _] (cf/transition st-after-4 {:type :pause :generation 1})
            fetches-before-resume (:network-fetches st-paused)
            _ (is (= :paused (:phase st-paused)))
            [st-resumed effs-r] (cf/transition st-paused {:type :resume :generation 2 :cached-indices #{0 1 2 3}})
            resumed-fetches (filter #(= :fetch-chunk (:type %)) effs-r)]
        (is (= 2 (:generation st-resumed)))
        ;; ZERO redundant network fetches for cached chunks 0..3
        (is (every? #(>= (:index %) 4) resumed-fetches))
        ;; Complete remaining 4 chunks (4..7) + final digest
        (let [[st-done resumed-fetched-indices]
              (loop [st st-resumed
                     pending-effs (vec effs-r)
                     fetched-idxs []
                     steps 0]
                (if (or (= :complete (:phase st)) (= :failed (:phase st)) (> steps 50))
                  [st fetched-idxs]
                  (if-let [e (first pending-effs)]
                    (let [rest-e (subvec pending-effs 1)]
                      (case (:type e)
                        :fetch-chunk
                        (let [ch (nth chunks (:index e))
                              [s2 e2] (cf/transition st {:type :chunk-fetched
                                                         :generation (:generation st)
                                                         :index (:index e)
                                                         :mirror (:mirror e)
                                                         :cid (get ch "cid")
                                                         :size (get ch "size")})]
                          (recur s2 (into rest-e e2) (conj fetched-idxs (:index e)) (inc steps)))

                        :digest-chunk
                        (let [[s2 e2] (cf/transition st {:type :digest-result
                                                         :generation (:generation st)
                                                         :index (:index e)
                                                         :ok? true})]
                          (recur s2 (into rest-e e2) fetched-idxs (inc steps)))

                        :digest-final
                        (let [[s2 e2] (cf/transition st {:type :digest-final
                                                         :generation (:generation st)
                                                         :sha256 (get manifest "total_sha256")})]
                          (recur s2 (into rest-e e2) fetched-idxs (inc steps)))

                        (recur st rest-e fetched-idxs (inc steps))))
                    [st fetched-idxs])))]
          (is (= :complete (:phase st-done)))
          (is (= 8 (:hash-cursor st-done)))
          ;; ZERO redundant network fetches for cached chunks 0..3 during resume
          (is (= [4 5 6 7] (vec (sort resumed-fetched-indices))))
          (is (= 4 (- (:network-fetches st-done) fetches-before-resume)))
          (is (= (get-in st-done [:diagnostics :dropped]) (causes-sum st-done))))))))

(deftest test-fault-injection-and-diagnostics-invariants
  (let [manifest (make-valid-manifest {:total-bytes 131072 :chunk-size 65536})
        chunks (get manifest "chunks")
        st0 (:state (cf/init-fetch-state {:manifest manifest
                                          :mirrors ["https://m1" "https://m2"]
                                          :concurrency 2
                                          :max-retries 2}))]
    (testing "Corrupt chunk CID/size blacklists mirror in current generation and retries on healthy mirror"
      (let [[st1 effs1] (cf/transition st0 {:type :start :generation 1})
            f0 (first (filter #(= :fetch-chunk (:type %)) effs1))
            [st2 effs2] (cf/transition st1 {:type :chunk-fetched
                                            :generation 1
                                            :index (:index f0)
                                            :mirror (:mirror f0)
                                            :cid (apply str (repeat 64 "0"))
                                            :size 65536})
            retry-eff (first (filter #(= :fetch-chunk (:type %)) effs2))]
        (is (contains? (:blacklisted-mirrors st2) (:mirror f0)))
        (is (= 1 (get-in st2 [:diagnostics :causes :chunk-cid-mismatch])))
        (is (some? retry-eff))
        (is (not= (:mirror f0) (:mirror retry-eff)))
        ;; Second mirror returns wrong size -> exhausts mirrors -> loud :failed
        (let [[st3 _] (cf/transition st2 {:type :chunk-fetched
                                          :generation 1
                                          :index (:index retry-eff)
                                          :mirror (:mirror retry-eff)
                                          :cid (get (nth chunks (:index retry-eff)) "cid")
                                          :size 1234})]
          (is (= :failed (:phase st3)))
          (is (= 1 (get-in st3 [:diagnostics :causes :chunk-size-mismatch])))
          (is (= (get-in st3 [:diagnostics :dropped]) (causes-sum st3))))))

    (testing "HTTP 410 emits :chunk-gone and :grace-expired, NEVER blacklists mirror, NEVER counts :chunk-fetch-failed"
      (let [[st1 effs1] (cf/transition st0 {:type :start :generation 1})
            f0 (first (filter #(= :fetch-chunk (:type %)) effs1))
            [st2 effs2] (cf/transition st1 {:type :chunk-http-error
                                            :generation 1
                                            :index (:index f0)
                                            :mirror (:mirror f0)
                                            :status 410
                                            :reason "gone"})]
        (is (= :failed (:phase st2)))
        (is (empty? (:blacklisted-mirrors st2)))
        (is (nil? (get-in st2 [:diagnostics :causes :chunk-fetch-failed])))
        (is (= 1 (get-in st2 [:diagnostics :causes :chunk-gone])))
        (is (= 1 (get-in st2 [:diagnostics :causes :grace-expired])))
        (is (some #(= :chunk-gone (:kind %)) effs2))
        (is (some #(= :grace-expired (:kind %)) effs2))
        (is (= (get-in st2 [:diagnostics :dropped]) (causes-sum st2)))))

    (testing "OPFS cache eviction emits :cache-evicted and re-queues chunk"
      (let [[st1 _] (cf/transition st0 {:type :start :generation 1 :cached-indices #{0}})
            [st2 effs2] (cf/transition st1 {:type :cache-evicted :generation 1 :index 0})]
        (is (= 1 (get-in st2 [:diagnostics :causes :cache-evicted])))
        (is (not (contains? (:staged-chunks st2) 0)))
        (is (some #(and (= :fetch-chunk (:type %)) (= 0 (:index %))) effs2))
        (is (= (get-in st2 [:diagnostics :dropped]) (causes-sum st2)))))

    (testing "Stale-generation callback emits :ignored-stale-chunk with zero operational state mutation"
      (let [[st1 _] (cf/transition st0 {:type :start :generation 2})
            [st2 effs2] (cf/transition st1 {:type :chunk-fetched
                                            :generation 1
                                            :index 0
                                            :mirror "https://m1"
                                            :cid (get (nth chunks 0) "cid")
                                            :size 65536})]
        (is (= (dissoc st1 :diagnostics) (dissoc st2 :diagnostics)))
        (is (= 1 (get-in st2 [:diagnostics :causes :ignored-stale-chunk])))
        (is (some #(= :ignored-stale-chunk (:kind %)) effs2))
        (is (= (get-in st2 [:diagnostics :dropped]) (causes-sum st2)))))

    (testing "Staged chunk corruption during hashing emits :staged-chunk-corrupt and re-queues; total SHA-256 mismatch emits :total-sha256-mismatch"
      (let [[st1 _] (cf/transition st0 {:type :start :generation 1 :cached-indices #{0 1}})
            [st2 effs2] (cf/transition st1 {:type :digest-result :generation 1 :index 0 :ok? false :reason "corrupt-on-disk"})]
        (is (= 1 (get-in st2 [:diagnostics :causes :staged-chunk-corrupt])))
        (is (some #(and (= :fetch-chunk (:type %)) (= 0 (:index %))) effs2))
        ;; Now test total SHA-256 mismatch
        (let [[sa _] (cf/transition st1 {:type :digest-result :generation 1 :index 0 :ok? true})
              [sb effs-b] (cf/transition sa {:type :digest-result :generation 1 :index 1 :ok? true})
              _ (is (some #(= :digest-final (:type %)) effs-b))
              [sc effs-c] (cf/transition sb {:type :digest-final :generation 1 :sha256 (apply str (repeat 64 "f"))})]
          (is (= :failed (:phase sc)))
          (is (= 1 (get-in sc [:diagnostics :causes :total-sha256-mismatch])))
          (is (some #(= :total-sha256-mismatch (:kind %)) effs-c))
          (is (= (get-in sc [:diagnostics :dropped]) (causes-sum sc))))))))

;; =============================================================================
;; 5. Generative & Model-Based Command-Sequence Property Tests (Rule 1)
;; =============================================================================

(defspec ^{:doc "Property: RFC 8785 JCS canonicalization and manifest-cid are deterministic and order-independent."}
  prop-jcs-manifest-cid-deterministic
  50
  (prop/for-all [total-chunks (gen/choose 1 12)
                 chunk-size (gen/elements [65536 131072 262144 1048576])
                 seed (gen/choose 1 100000)]
                (let [total-bytes (* total-chunks chunk-size)
                      m (make-valid-manifest {:total-bytes total-bytes :chunk-size chunk-size :seed seed})
                      m-rev (into {} (reverse (seq m)))]
                  (and (= (cc/jcs-canonicalize m) (cc/jcs-canonicalize m-rev))
                       (= (cc/manifest-cid m) (cc/manifest-cid m-rev))
                       (true? (:ok? (cc/validate-manifest m)))))))

(defspec ^{:doc "Property: Pure (min constant config) cap clamp never exceeds ceiling and always emits :cap-ceiling-clamped when clamped."}
  prop-cap-ceiling-clamp-invariant
  100
  (prop/for-all [ceiling (gen/choose 1 1000000)
                 requested (gen/choose 1 2000000)]
                (let [res (cc/clamp-cap :test-cap ceiling requested)]
                  (and (<= (:value res) ceiling)
                       (= (:value res) (min ceiling requested))
                       (if (> requested ceiling)
                         (and (true? (:clamped? res))
                              (= :cap-ceiling-clamped (get-in res [:effects 0 :kind])))
                         (and (false? (:clamped? res))
                              (empty? (:effects res))))))))

(defspec ^{:doc "Model-based command-sequence test for chunk-fetch/transition: preserves generation monotonicity, RAM backpressure, hash-cursor strict order, staged-bytes accounting, and :dropped == sum(causes)."}
  prop-chunk-fetch-command-sequence-invariants
  40
  (prop/for-all [n-chunks (gen/choose 2 8)
                 concurrency (gen/choose 1 5)
                 cmds (gen/vector
                       (gen/one-of
                        [(gen/tuple (gen/return :fetch-ok) (gen/choose 0 7))
                         (gen/tuple (gen/return :fetch-corrupt) (gen/choose 0 7))
                         (gen/tuple (gen/return :http-410) (gen/choose 0 7))
                         (gen/tuple (gen/return :cache-evict) (gen/choose 0 7))
                         (gen/tuple (gen/return :stale-callback) (gen/choose 0 7))
                         (gen/tuple (gen/return :digest-ok) (gen/choose 0 7))
                         (gen/tuple (gen/return :pause-resume) (gen/choose 0 7))])
                       5 25)]
                (let [chunk-size 65536
                      manifest (make-valid-manifest {:total-bytes (* n-chunks chunk-size) :chunk-size chunk-size :seed 7})
                      chunks (get manifest "chunks")
                      {:keys [state]} (cf/init-fetch-state {:manifest manifest
                                                            :mirrors ["https://m1" "https://m2" "https://m3"]
                                                            :concurrency concurrency})
                      [st0 _] (cf/transition state {:type :start :generation 1})
                      final-state
                      (reduce
                       (fn [st [op raw-idx]]
                         (let [idx (mod raw-idx n-chunks)
                               gen (:generation st)
                               ch (nth chunks idx)
                               in-flight-entry (get (:in-flight st) idx)
                               mirror (or (:mirror in-flight-entry) "https://m1")
                               [next-st _]
                               (case op
                                 :fetch-ok
                                 (if in-flight-entry
                                   (cf/transition st {:type :chunk-fetched :generation gen :index idx :mirror mirror :cid (get ch "cid") :size (get ch "size")})
                                   [st []])

                                 :fetch-corrupt
                                 (if in-flight-entry
                                   (cf/transition st {:type :chunk-fetched :generation gen :index idx :mirror mirror :cid (apply str (repeat 64 "0")) :size (get ch "size")})
                                   [st []])

                                 :http-410
                                 (if in-flight-entry
                                   (cf/transition st {:type :chunk-http-error :generation gen :index idx :mirror mirror :status 410 :reason "gone"})
                                   [st []])

                                 :cache-evict
                                 (if (contains? (:staged-chunks st) idx)
                                   (cf/transition st {:type :cache-evicted :generation gen :index idx})
                                   [st []])

                                 :stale-callback
                                 (cf/transition st {:type :chunk-fetched :generation (dec gen) :index idx :mirror mirror :cid (get ch "cid") :size (get ch "size")})

                                 :digest-ok
                                 (if (and (:hash-in-flight? st) (< (:hash-cursor st) n-chunks))
                                   (cf/transition st {:type :digest-result :generation gen :index (:hash-cursor st) :ok? true})
                                   [st []])

                                 :pause-resume
                                 (if (= :fetching (:phase st))
                                   (let [[sp _] (cf/transition st {:type :pause :generation gen})]
                                     (cf/transition sp {:type :resume :generation (inc gen) :cached-indices (set (keys (:staged-chunks sp)))}))
                                   [st []]))]
                           next-st))
                       st0
                       cmds)]
                  (and (<= (:concurrency final-state) cc/max-fetch-concurrency-940mb)
                       (<= (count (:in-flight final-state)) (:concurrency final-state))
                       (<= (:hash-cursor final-state) n-chunks)
                       (= (:bytes-at-rest final-state)
                          (+ (:hashed-bytes final-state) (:staged-unhashed-bytes final-state)))
                       (= (get-in final-state [:diagnostics :dropped])
                          (causes-sum final-state))))))
