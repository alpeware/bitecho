(ns bitecho.d49-bip022-stage-a-operator-safety-test
  "Strict TDD (Rule 1) generative + unit tests for BIP-022 Stage A: Operator Safety (Rows 3, 7, 9).
   - Row 3: Unified CLI flag inventory (`bitecho.config.flags`), startup & status security-flag echo,
            `--trusted-dac-anchors` explicit flag-clearance semantics, and `artifact-get --out <file>`.
   - Row 7: Fail-closed `storage-put` (verified network receipt required unless explicit `--local-only`).
   - Row 9: Canonical send-path error taxonomy (`bitecho.errors.core`) with counted Rule 5 `:diagnose`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config.flags :as flags]
            [bitecho.crypto :as crypto]
            [bitecho.errors.core :as errors]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            #?(:clj [bitecho.core.data :as data])
            #?(:clj [bitecho.shell.light-node :as jvm-shell])
            #?(:clj [clojure.java.io :as io])
            [clojure.string :as str]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  #?(:clj (:import [java.nio.file Files]
                   [java.nio.file.attribute FileAttribute])))

(def ^:private gen-hex-char
  (gen/elements (vec "0123456789abcdef")))

(def ^:private gen-pubkey-64
  (gen/fmap #(apply str %) (gen/vector gen-hex-char 64)))

(def ^:private gen-subnet
  (gen/elements ["global" "devnet.bitecho.org" "bitecho.org/team" "bitecho.org/dev" "lab-01"]))

(def ^:private gen-slot
  (gen/elements ["prefs" "notes" "backup-v1" "profile" "session-meta"]))

;; =============================================================================
;; ROW 3: Unified CLI Flag Inventory, Security-Flag Echo,
;;        --trusted-dac-anchors Explicit Clearance, & artifact-get --out
;; =============================================================================

(defspec ^{:doc "Row 3 Property: Every entry in bitecho.config.flags/flag-registry has valid schema and is present in cli/known-command-flags."}
  prop-row3-flag-registry-schema-and-parity 30
  (prop/for-all [idx (gen/choose 0 (dec (count flags/flag-registry)))]
                (let [spec (nth flags/flag-registry idx)
                      known-set (set cli/known-command-flags)]
                  (and (string? (:flag spec))
                       (str/starts-with? (:flag spec) "--")
                       (keyword? (:config-key spec))
                       (contains? #{:string :long :boolean :string-list :path} (:type spec))
                       (set? (:shells spec))
                       (seq (:shells spec))
                       (every? #{:browser :node-light :jvm-light :full-node} (:shells spec))
                       (boolean? (:security-relevant? spec))
                       (contains? known-set (:flag spec))))))

(defspec ^{:doc "Row 3 Property: --trusted-dac-anchors explicit flag-clearance never silently retains stale anchors without counted Rule 5 :diagnose."}
  prop-row3-trusted-dac-anchors-clearance-spec 50
  (prop/for-all [persisted-anchors (gen/vector gen-pubkey-64 0 3)
                 cli-mode (gen/elements [:omit :set :clear-flag :clear-empty-string])
                 cli-anchors (gen/vector gen-pubkey-64 1 2)]
                (let [kp (crypto/generate-keypair "bip022-row3-dac-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      persisted-set (set persisted-anchors)
                      st0 (-> (light-core/init-light-state {:pubkey-hex pub-hex}
                                                           {:subnet-id "devnet.bitecho.org"})
                              (assoc :trusted-dac-anchors persisted-set))
                      argv (case cli-mode
                             :omit ["serve" "--subnet-id" "devnet.bitecho.org"]
                             :set ["serve" "--trusted-dac-anchors" (str/join "," cli-anchors)]
                             :clear-flag ["serve" "--clear-trusted-dac-anchors"]
                             :clear-empty-string ["serve" "--trusted-dac-anchors" ""])
                      cli-spec (flags/parse-trusted-dac-anchors-arg argv)
                      rec (flags/reconcile-trusted-dac-anchors st0 cli-spec nil)
                      st1 (:state rec)
                      effs (:effects rec)
                      echo (flags/build-security-flags-echo
                            {:subnet-id (:subnet-id st1)
                             :subnet-id-overridden? false
                             :trusted-dac-anchors (:trusted-dac-anchors st1)
                             :trusted-dac-anchors-provenance (:trusted-dac-anchors-provenance st1)})]
                  (case cli-mode
                    :set
                    (and (= (set cli-anchors) (:trusted-dac-anchors st1))
                         (= :cli (:trusted-dac-anchors-provenance st1))
                         (= :cli (:trusted-dac-anchors-provenance echo))
                         (empty? effs))

                    (:clear-flag :clear-empty-string)
                    (and (empty? (:trusted-dac-anchors st1))
                         (= :cleared (:trusted-dac-anchors-provenance st1))
                         (= :none (:trusted-dac-anchors echo))
                         (= :cleared (:trusted-dac-anchors-provenance echo))
                         (= 1 (long (get-in st1 [:diagnostics :cleared-trusted-dac-anchors] 0)))
                         (some #(and (= :diagnose (:effect %))
                                     (= :cleared-trusted-dac-anchors (:reason %)))
                               effs))

                    :omit
                    (if (seq persisted-set)
                      (and (= persisted-set (:trusted-dac-anchors st1))
                           (= :config (:trusted-dac-anchors-provenance st1))
                           (= :config (:trusted-dac-anchors-provenance echo))
                           (= (vec (sort persisted-set)) (:trusted-dac-anchors echo))
                           (= 1 (long (get-in st1 [:diagnostics :inherited-trusted-dac-anchors] 0)))
                           (some #(and (= :diagnose (:effect %))
                                       (= :inherited-trusted-dac-anchors (:reason %)))
                                 effs))
                      (and (empty? (:trusted-dac-anchors st1))
                           (= :default (:trusted-dac-anchors-provenance st1))
                           (= :none (:trusted-dac-anchors echo))
                           (= :default (:trusted-dac-anchors-provenance echo))
                           (empty? effs)))))))

(defspec ^{:doc "Row 3 Property: exec-status always surfaces security_flags with subnet, DAC anchors + provenance, updater flags, and keystore tier."}
  prop-row3-status-security-flags-echo-spec 30
  (prop/for-all [sub gen-subnet
                 overridden? gen/boolean
                 pin-ver (gen/elements [nil "0.23.22" "0.24.0"])
                 ptr-url (gen/elements [nil "https://ns1.bitecho.org/config/devnet/active.edn"])]
                (let [kp (crypto/generate-keypair "bip022-row3-status-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      st (-> (light-core/init-light-state {:pubkey-hex pub-hex}
                                                          {:subnet-id sub})
                             (assoc :subnet-id-overridden? overridden?
                                    :trusted-dac-anchors-provenance :default
                                    :pin-version pin-ver
                                    :auto-update-pointer ptr-url))
                      resp (:response (light-core/exec-status st))
                      sf (get resp "security_flags")]
                  (and (map? sf)
                       (= sub (get sf "subnet_id"))
                       (= overridden? (get sf "subnet_id_overridden"))
                       (= "none" (get sf "trusted_dac_anchors"))
                       (= "default" (get sf "trusted_dac_anchors_provenance"))
                       (= pin-ver (get sf "pin_version"))
                       (= ptr-url (get sf "auto_update_pointer"))
                       (= "legacy-file-0600" (get sf "keystore_security_tier"))))))

(defspec ^{:doc "Row 3 Property: artifact-get --out <file> parses cleanly and compact receipt strips hex/text bloat while preserving metadata."}
  prop-row3-artifact-get-out-compact-receipt-spec 40
  (prop/for-all [cid gen-pubkey-64
                 fname (gen/not-empty gen/string-alphanumeric)
                 nbytes (gen/choose 0 65536)]
                (let [out-path (str "/tmp/" fname ".bin")
                      cmd (cli/build-cmd-map "artifact-get" ["--cid" cid "--out" out-path])
                      bloated-resp {"ok" true
                                    "cid" cid
                                    "path" "artifacts/test.bin"
                                    "subnet_id" "devnet.bitecho.org"
                                    "size_bytes" nbytes
                                    "hex" "deadbeef"
                                    "data_hex" "deadbeef"
                                    "text" "some huge payload"
                                    "data" "some huge payload"}
                      compact (flags/format-artifact-get-out-receipt bloated-resp out-path nbytes)]
                  (and (= out-path (get cmd "out_file"))
                       (true? (get compact "ok"))
                       (= cid (get compact "cid"))
                       (= nbytes (get compact "bytes"))
                       (= nbytes (get compact "size_bytes"))
                       (= out-path (get compact "out"))
                       (= out-path (get compact "out_file"))
                       (not (contains? compact "hex"))
                       (not (contains? compact "data_hex"))
                       (not (contains? compact "text"))
                       (not (contains? compact "data"))))))

#?(:clj
   (deftest test-row3-jvm-artifact-get-out-atomic-write-and-fail-closed
     (testing "JVM artifact-get --out writes raw bytes atomically and returns compact metadata JSON without hex/text bloat"
       (let [temp-dir (.toFile (Files/createTempDirectory "bip022-art-out-" (into-array FileAttribute [])))
             out-file (io/file temp-dir "downloaded.bin")
             kp (crypto/generate-keypair "bip022-art-out-seed")
             pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
             payload-bytes (.getBytes "BIP-022 Stage A raw artifact payload!" "UTF-8")
             blob (data/make-blob payload-bytes)
             cid (:blob/cid blob)
             st0 (-> (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id "devnet.bitecho.org"})
                     (assoc-in [:artifact-blobs cid] blob)
                     (assoc-in [:blobs cid] blob))
             state-atom (atom st0)
             ctx {:state-atom state-atom
                  :identity {:pubkey-hex pub-hex :privkey-bytes (:private kp)}
                  :conn-opts {}}
             cmd-map (cli/build-cmd-map "artifact-get" ["--cid" cid "--out" (.getAbsolutePath out-file)])
             resp (jvm-shell/handle-serve-line! cmd-map ctx)]
         (try
           (is (true? (get resp "ok")))
           (is (= cid (get resp "cid")))
           (is (= (alength payload-bytes) (get resp "bytes")))
           (is (= (alength payload-bytes) (get resp "size_bytes")))
           (is (= (.getAbsolutePath out-file) (get resp "out")))
           (is (not (contains? resp "hex")))
           (is (not (contains? resp "data_hex")))
           (is (not (contains? resp "text")))
           (is (.exists out-file))
           (is (= (vec payload-bytes) (vec (Files/readAllBytes (.toPath out-file)))))

           ;; Writing to an existing directory path must fail closed with canonical error + counted diagnose
           (let [bad-cmd (cli/build-cmd-map "artifact-get" ["--cid" cid "--out" (.getAbsolutePath temp-dir)])
                 bad-resp (jvm-shell/handle-serve-line! bad-cmd ctx)]
             (is (false? (get bad-resp "ok")))
             (is (= "artifact-out-write-failed" (get bad-resp "error")))
             (is (= "storage" (get bad-resp "category")))
             (is (pos? (long (get-in @state-atom [:diagnostics :artifact-out-write-failed] 0)))))
           (finally
             (run! io/delete-file (reverse (file-seq temp-dir)))))))))

;; =============================================================================
;; ROW 7: Fail-Closed storage-put (Verified Network Receipt or --local-only)
;; =============================================================================

(defspec ^{:doc "Row 7 Property: storage-put without --local-only or verified network receipt ALWAYS fails closed with zero pointer advance and counted :diagnose."}
  prop-row7-storage-put-fails-closed-without-network-receipt 40
  (prop/for-all [sub gen-subnet
                 slot gen-slot
                 payload (gen/not-empty gen/string-alphanumeric)]
                (let [kp (crypto/generate-keypair "bip022-row7-fail-closed-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      st0 (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id sub})
                      res (light-core/handle-command st0
                                                     {"cmd" "storage-put"
                                                      "subnet_id" sub
                                                      "slot" slot
                                                      "data" payload}
                                                     (:private kp))
                      st1 (:state res)
                      resp (:response res)]
                  (and (false? (get resp "ok"))
                       (= "storage-publish-failed" (get resp "error"))
                       (= "storage" (get resp "category"))
                       (true? (get resp "recoverable"))
                       (map? (get resp "detail"))
                       (empty? (:storage-pointers st1))
                       (empty? (:storage-min-seqs st1))
                       (= 1 (long (get-in st1 [:diagnostics :storage-publish-failed] 0)))
                       (some #(and (= :diagnose (:effect %))
                                   (= :storage-publish-failed (:reason %)))
                             (:effects res))))))

(defspec ^{:doc "Row 7 Property: prepare-storage-put + commit-storage-put-outcome commits ONLY on verified network receipt and fails closed on HTTP/transport error."}
  prop-row7-storage-put-prepare-and-commit-lifecycle 40
  (prop/for-all [sub gen-subnet
                 slot gen-slot
                 payload (gen/not-empty gen/string-alphanumeric)
                 net-ok? gen/boolean]
                (let [kp (crypto/generate-keypair "bip022-row7-commit-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      st0 (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id sub})
                      prep (light-core/prepare-storage-put st0
                                                           {"cmd" "storage-put"
                                                            "subnet_id" sub
                                                            "slot" slot
                                                            "data" payload}
                                                           (:private kp)
                                                           sub)
                      ;; Prepare itself must NOT advance local pointers before network receipt
                      no-premature-commit? (and (true? (:ok? prep))
                                                (true? (:pending-publish? prep))
                                                (empty? (:storage-pointers (:state prep)))
                                                (empty? (:storage-min-seqs (:state prep))))
                      outcome (if net-ok?
                                {:ok? true :endpoints ["https://ns1.bitecho.org"]}
                                {:ok? false :status 503 :error "relay-unavailable"})
                      committed (light-core/commit-storage-put-outcome st0 (:publish-intent prep) outcome)
                      st1 (:state committed)
                      resp (:response committed)]
                  (and no-premature-commit?
                       (if net-ok?
                         (and (true? (get resp "ok"))
                              (true? (get resp "replicated"))
                              (= ["https://ns1.bitecho.org"] (get resp "endpoints"))
                              (= 1 (get resp "seq"))
                              (seq (:storage-pointers st1))
                              (seq (:storage-min-seqs st1)))
                         (and (false? (get resp "ok"))
                              (= "storage-publish-failed" (get resp "error"))
                              (= "storage" (get resp "category"))
                              (empty? (:storage-pointers st1))
                              (empty? (:storage-min-seqs st1))
                              (= 1 (long (get-in st1 [:diagnostics :storage-publish-failed] 0)))))))))

(defspec ^{:doc "Row 7 Property: storage-put --local-only writes locally, sets replicated=false, local_only=true, and emits counted :storage-put-local-only :diagnose."}
  prop-row7-storage-put-explicit-local-only 40
  (prop/for-all [sub gen-subnet
                 slot gen-slot
                 payload (gen/not-empty gen/string-alphanumeric)]
                (let [kp (crypto/generate-keypair "bip022-row7-local-only-seed")
                      pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
                      st0 (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id sub})
                      cmd (cli/build-cmd-map "storage-put" ["--subnet-id" sub "--slot" slot "--data" payload "--local-only"])
                      res (light-core/handle-command st0 cmd (:private kp))
                      st1 (:state res)
                      resp (:response res)]
                  (and (true? (get cmd "local_only"))
                       (true? (get resp "ok"))
                       (false? (get resp "replicated"))
                       (true? (get resp "local_only"))
                       (= 1 (get resp "seq"))
                       (= 1 (long (get-in st1 [:diagnostics :storage-put-local-only] 0)))
                       (some #(and (= :diagnose (:effect %))
                                   (= :storage-put-local-only (:reason %)))
                             (:effects res))))))

;; =============================================================================
;; ROW 9: Canonical Send-Path Error Taxonomy (bitecho.errors.core)
;; =============================================================================

(defspec ^{:doc "Row 9 Property: Every canonical error code constructs a valid structured error envelope, wire map, and Rule 5 :diagnose effect."}
  prop-row9-canonical-error-envelope-invariants 50
  (prop/for-all [code (gen/elements (vec errors/canonical-error-codes))
                 detail-msg (gen/not-empty gen/string-alphanumeric)]
                (let [err (errors/canonical-error code {:context detail-msg})
                      wire (errors/canonical-error->wire err)
                      diag (errors/diagnose-effect err)]
                  (and (false? (:ok err))
                       (= code (:error err))
                       (contains? errors/valid-categories (:category err))
                       (boolean? (:recoverable? err))
                       (map? (:detail err))
                       (false? (get wire "ok"))
                       (= (name code) (get wire "error"))
                       (= (name (:category err)) (get wire "category"))
                       (= (:recoverable? err) (get wire "recoverable"))
                       (map? (get wire "detail"))
                       (= :diagnose (:effect diag))
                       (= :diagnose (:type diag))
                       (= code (:reason diag))))))

(defspec ^{:doc "Row 9 Property: Legacy/shell error strings and raw exception text classify cleanly into canonical error codes without leaking raw stack traces."}
  prop-row9-classify-legacy-and-raw-errors 50
  (prop/for-all [raw-err (gen/elements ["not-connected"
                                        "hardware-unlock-required"
                                        "send-failed:ECONNRESET"
                                        "mesh-send-failed"
                                        "session-not-open"
                                        "session-quarantined"
                                        "insufficient-balance"
                                        "subnet-mismatch"
                                        "replay-detected"
                                        "replay-rejected"
                                        "storage-publish-failed"
                                        "duplicate-instance"
                                        "dial-failed"
                                        "p2p-no-candidates"
                                        "payload-too-large"
                                        "java.net.ConnectException: Connection refused\n\tat Foo.bar(Foo.java:42)"
                                        "TypeError: Cannot read properties of undefined"])]
                (let [classified (errors/classify-error raw-err)
                      err (errors/canonical-error classified {:raw-hint "sanitized"})]
                  (and (keyword? classified)
                       (contains? errors/canonical-error-codes classified)
                       (false? (:ok err))
                       (not (str/includes? (name (:error err)) "\n"))
                       (not (str/includes? (name (:error err)) "Exception"))))))

(deftest test-row9-core-send-path-emits-canonical-errors-and-diagnostics
  (testing "exec-send on missing/closed session returns canonical error taxonomy with counted Rule 5 :diagnose"
    (let [kp (crypto/generate-keypair "bip022-row9-send-seed")
          pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
          st0 (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id "devnet.bitecho.org"})
          res (light-core/handle-command st0 {"cmd" "send" "session_id" "missing-sess" "text" "hello"} (:private kp))
          resp (:response res)
          st1 (:state res)]
      (is (false? (get resp "ok")))
      (is (= "session-not-open" (get resp "error")))
      (is (= "session" (get resp "category")))
      (is (true? (get resp "recoverable")))
      (is (map? (get resp "detail")))
      (is (pos? (long (get-in st1 [:diagnostics :session-not-open] 0))))
      (is (some #(and (= :diagnose (:effect %)) (= :session-not-open (:reason %))) (:effects res)))))

  (testing "exec-broadcast with insufficient balance returns canonical validation error with counted Rule 5 :diagnose"
    (let [kp (crypto/generate-keypair "bip022-row9-bcast-seed")
          pub-hex (str/lower-case (basalt/bytes->hex (:public kp)))
          st0 (assoc (light-core/init-light-state {:pubkey-hex pub-hex} {:subnet-id "devnet.bitecho.org"})
                     :account {:balance 10 :spendable 10 :seq 0})
          res (light-core/handle-command st0 {"cmd" "broadcast" "subnet_id" "devnet.bitecho.org" "text" "hi" "burn" 500} (:private kp))
          resp (:response res)
          st1 (:state res)]
      (is (false? (get resp "ok")))
      (is (= "insufficient-balance" (get resp "error")))
      (is (= "validation" (get resp "category")))
      (is (false? (get resp "recoverable")))
      (is (pos? (long (get-in st1 [:diagnostics :insufficient-balance] 0)))))))
