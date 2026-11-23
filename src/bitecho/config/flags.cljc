(ns bitecho.config.flags
  "Canonical CLI/Config Flag Inventory, Startup Security-Flag Echo, `--trusted-dac-anchors`
   Explicit Flag-Clearance Semantics, and `artifact-get --out <file>` Receipt Formatter
   (BIP-022 Stage A, Row 3; Rules 2, 5, 6)."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]))

(def all-shells
  "All 4 Bitecho runtime shells."
  #{:browser :node-light :jvm-light :full-node})

(def light-cli-shells
  "Node.js and JVM light-node CLI shells."
  #{:node-light :jvm-light})

(def flag-registry
  "Single `.cljc` registry of canonical security-relevant and operator-safety CLI/config flags
   with types, defaults, shell applicability, and `:security-relevant?` metadata."
  [{:flag "--subnet-id"
    :config-key :subnet-id
    :type :string
    :default "global"
    :shells all-shells
    :security-relevant? true}
   {:flag "--subscribe-subnets"
    :config-key :subscribe-subnets
    :type :string-list
    :default []
    :shells #{:browser :node-light :jvm-light}
    :security-relevant? false}
   {:flag "--trusted-dac-anchors"
    :config-key :trusted-dac-anchors
    :type :string-list
    :default #{}
    :shells all-shells
    :security-relevant? true}
   {:flag "--clear-trusted-dac-anchors"
    :config-key :clear-trusted-dac-anchors
    :type :boolean
    :default false
    :shells light-cli-shells
    :security-relevant? true}
   {:flag "--trusted-deploy-authorities"
    :config-key :trusted-deploy-authorities
    :type :string-list
    :default #{}
    :shells all-shells
    :security-relevant? true}
   {:flag "--pin-version"
    :config-key :pin-version
    :type :string
    :default nil
    :shells #{:node-light :jvm-light :full-node}
    :security-relevant? true}
   {:flag "--auto-update-pointer"
    :config-key :auto-update-pointer
    :type :string
    :default nil
    :shells #{:node-light :jvm-light :full-node}
    :security-relevant? true}
   {:flag "--auto-update-interval-ms"
    :config-key :auto-update-interval-ms
    :type :long
    :default 60000
    :shells #{:node-light :jvm-light :full-node}
    :security-relevant? true}
   {:flag "--max-epoch-skew"
    :config-key :max-epoch-skew
    :type :long
    :default 15
    :shells #{:browser :node-light :jvm-light}
    :security-relevant? true}
   {:flag "--out"
    :config-key :out-file
    :type :path
    :default nil
    :shells light-cli-shells
    :security-relevant? false}
   {:flag "--local-only"
    :config-key :local-only
    :type :boolean
    :default false
    :shells #{:browser :node-light :jvm-light}
    :security-relevant? true}
   {:flag "--state-dir"
    :config-key :state-dir
    :type :path
    :default nil
    :shells #{:node-light :jvm-light :full-node}
    :security-relevant? false}
   {:flag "--control-port"
    :config-key :control-port
    :type :long
    :default 5020
    :shells light-cli-shells
    :security-relevant? false}
   {:flag "--bootstrap"
    :config-key :bootstrap
    :type :string
    :default "https://bitecho.org/devnet/bootstrap.txt"
    :shells all-shells
    :security-relevant? false}
   {:flag "--relay-url"
    :config-key :relay-url
    :type :string
    :default nil
    :shells #{:browser :node-light :jvm-light}
    :security-relevant? false}
   {:flag "--sync-interval-ms"
    :config-key :sync-interval-ms
    :type :long
    :default 15000
    :shells #{:browser :node-light :jvm-light}
    :security-relevant? false}])

(def security-relevant-flags
  "Filtered vector of all `:security-relevant? true` flag specs."
  (filterv :security-relevant? flag-registry))

(def registry-flag-names
  "Vector of flag strings registered in `flag-registry`."
  (mapv :flag flag-registry))

(defn- normalize-anchor-token
  [s]
  (when (some? s)
    (let [t (str/lower-case (str/trim (str s)))]
      (when (not (str/blank? t))
        t))))

(defn parse-anchor-list
  "Parses a CSV or EDN vector/set string (or collection) of pubkey hex strings into a normalized set."
  [raw]
  (cond
    (nil? raw) #{}
    (coll? raw) (into #{} (keep normalize-anchor-token raw))
    (string? raw)
    (let [trimmed (str/trim raw)]
      (if (str/blank? trimmed)
        #{}
        (let [items (if (or (str/starts-with? trimmed "[")
                            (str/starts-with? trimmed "#{"))
                      (try
                        (let [parsed (edn/read-string trimmed)]
                          (if (coll? parsed) parsed (str/split trimmed #",")))
                        (catch #?(:clj Exception :cljs :default) _
                          (str/split trimmed #",")))
                      (str/split trimmed #","))]
          (into #{} (keep normalize-anchor-token items)))))
    :else #{}))

(defn parse-trusted-dac-anchors-arg
  "Purely parses `--trusted-dac-anchors` and `--clear-trusted-dac-anchors` from CLI `args`.
   Distinguishes explicit clear (`--clear-trusted-dac-anchors` or `--trusted-dac-anchors \"\"`),
   explicit set (`--trusted-dac-anchors <list>`), and omitted (`:omit`)."
  [args]
  (let [argv (vec (or args []))
        has-clear-flag? (boolean (some #{"--clear-trusted-dac-anchors"} argv))
        idx (loop [i 0]
              (cond
                (>= i (count argv)) nil
                (= (nth argv i) "--trusted-dac-anchors") i
                :else (recur (inc i))))
        has-value-slot? (and (some? idx) (< (inc idx) (count argv)))
        raw-val (when has-value-slot? (nth argv (inc idx)))
        explicit-empty? (and (some? idx)
                             (or (not has-value-slot?)
                                 (str/blank? (str raw-val))
                                 (str/starts-with? (str raw-val) "--")))]
    (cond
      (or has-clear-flag? explicit-empty?)
      {:action :clear
       :anchors #{}
       :provenance :cleared}

      (some? idx)
      (let [parsed (parse-anchor-list raw-val)]
        (if (empty? parsed)
          {:action :clear
           :anchors #{}
           :provenance :cleared}
          {:action :set
           :anchors parsed
           :provenance :cli}))

      :else
      {:action :omit
       :anchors nil
       :provenance :omitted})))

(defn reconcile-trusted-dac-anchors
  "Pure Sans-IO startup reconciler for `--trusted-dac-anchors` (BIP-022 §4.1 A.1 / Lumen `seq 7`).
   - `:set`   -> overwrites anchors with CLI set, provenance `:cli`, 0 warning diagnostics.
   - `:clear` -> clears anchors to `#{}`, provenance `:cleared`, increments
                 `[:diagnostics :cleared-trusted-dac-anchors]`, emits counted `:diagnose`.
   - `:omit`  -> if persisted or config anchors exist, inherits them loudly with provenance `:config`,
                 increments `[:diagnostics :inherited-trusted-dac-anchors]`, and emits counted
                 `:diagnose`; if none exist, sets `#{}` with provenance `:default`."
  ([state cli-dac-spec]
   (reconcile-trusted-dac-anchors state cli-dac-spec nil))
  ([state cli-dac-spec config-anchors]
   (let [persisted (parse-anchor-list (:trusted-dac-anchors state))
         cfg (parse-anchor-list config-anchors)
         inherited (if (seq persisted) persisted cfg)
         action (or (:action cli-dac-spec) :omit)]
     (case action
       :set
       (let [anchors (parse-anchor-list (:anchors cli-dac-spec))
             st1 (-> state
                     (assoc :trusted-dac-anchors anchors
                            :trusted-dac-anchors-provenance :cli)
                     (assoc-in [:account :trusted-dac-anchors] anchors))]
         {:ok? true
          :action :set
          :provenance :cli
          :anchors anchors
          :state st1
          :effects []
          :stdout-events []})

       :clear
       (let [diag {:effect :diagnose
                   :type :diagnose
                   :reason :cleared-trusted-dac-anchors
                   :previous-count (count inherited)
                   :previous (vec (sort inherited))}
             evt {"event" "cleared-trusted-dac-anchors"
                  "previous_count" (count inherited)
                  "provenance" "cleared"}
             st1 (-> state
                     (assoc :trusted-dac-anchors #{}
                            :trusted-dac-anchors-provenance :cleared)
                     (assoc-in [:account :trusted-dac-anchors] #{})
                     (update-in [:diagnostics :cleared-trusted-dac-anchors] (fnil inc 0)))]
         {:ok? true
          :action :clear
          :provenance :cleared
          :anchors #{}
          :state st1
          :effects [diag]
          :stdout-events [evt]})

       ;; :omit
       (if (seq inherited)
         (let [sorted-anchors (vec (sort inherited))
               diag {:effect :diagnose
                     :type :diagnose
                     :reason :inherited-trusted-dac-anchors
                     :anchors sorted-anchors
                     :provenance :config
                     :hint "Pass --clear-trusted-dac-anchors or --trusted-dac-anchors \"\" to clear."}
               evt {"event" "inherited-trusted-dac-anchors"
                    "anchors" sorted-anchors
                    "provenance" "config"}
               st1 (-> state
                       (assoc :trusted-dac-anchors inherited
                              :trusted-dac-anchors-provenance :config)
                       (assoc-in [:account :trusted-dac-anchors] inherited)
                       (update-in [:diagnostics :inherited-trusted-dac-anchors] (fnil inc 0)))]
           {:ok? true
            :action :inherit
            :provenance :config
            :anchors inherited
            :state st1
            :effects [diag]
            :stdout-events [evt]})
         (let [st1 (-> state
                       (assoc :trusted-dac-anchors #{}
                              :trusted-dac-anchors-provenance :default)
                       (assoc-in [:account :trusted-dac-anchors] #{}))]
           {:ok? true
            :action :default
            :provenance :default
            :anchors #{}
            :state st1
            :effects []
            :stdout-events []}))))))

(defn build-security-flags-echo
  "Constructs the canonical EDN `:security-flags` echo map required at startup and in
   `ctl/status` / `/statusz` (BIP-022 §4.1 A.1)."
  [{:keys [subnet-id subnet-id-overridden? trusted-dac-anchors trusted-dac-anchors-provenance
           trusted-deploy-authorities pin-version auto-update-pointer keystore-security-tier]}]
  (let [dac-set (parse-anchor-list trusted-dac-anchors)
        dep-set (parse-anchor-list trusted-deploy-authorities)
        prov (or trusted-dac-anchors-provenance
                 (if (seq dac-set) :config :default))]
    {:subnet-id (str (or subnet-id "global"))
     :subnet-id-overridden? (boolean subnet-id-overridden?)
     :trusted-dac-anchors (if (seq dac-set) (vec (sort dac-set)) :none)
     :trusted-dac-anchors-provenance prov
     :trusted-deploy-authorities (if (seq dep-set) (vec (sort dep-set)) :none)
     :pin-version (when (and (string? pin-version) (not (str/blank? pin-version))) pin-version)
     :auto-update-pointer (when (and (string? auto-update-pointer) (not (str/blank? auto-update-pointer))) auto-update-pointer)
     :keystore-security-tier (or keystore-security-tier :legacy-file-0600)}))

(defn security-flags->wire
  "Serializes a `:security-flags` echo map to canonical snake_case JSON/wire keys."
  [sf]
  (let [echo (if (contains? sf :keystore-security-tier) sf (build-security-flags-echo sf))
        dac (:trusted-dac-anchors echo)
        dep (:trusted-deploy-authorities echo)]
    {"subnet_id" (:subnet-id echo)
     "subnet_id_overridden" (boolean (:subnet-id-overridden? echo))
     "trusted_dac_anchors" (if (= dac :none) "none" (vec dac))
     "trusted_dac_anchors_provenance" (name (or (:trusted-dac-anchors-provenance echo) :default))
     "trusted_deploy_authorities" (if (= dep :none) "none" (vec dep))
     "pin_version" (:pin-version echo)
     "auto_update_pointer" (:auto-update-pointer echo)
     "keystore_security_tier" (name (or (:keystore-security-tier echo) :legacy-file-0600))}))

(defn format-artifact-get-out-receipt
  "Formats the compact JSON metadata receipt for `artifact-get --out <file>` (BIP-022 §4.1 A.1),
   stripping hex/text payload fields to eliminate 2x stdout bloat."
  [resp out-file byte-count]
  (let [cid (or (get resp "cid") (:cid resp))
        path (or (get resp "path") (:path resp))
        sub (or (get resp "subnet_id") (:subnet-id resp))
        seq-num (or (get resp "seq") (:seq resp))
        nbytes (long (or byte-count (get resp "size_bytes") (:size-bytes resp) 0))]
    (cond-> {"ok" true
             "cid" cid
             "bytes" nbytes
             "size_bytes" nbytes
             "out" (str out-file)
             "out_file" (str out-file)}
      (and (string? path) (not (str/blank? path))) (assoc "path" path)
      (and (string? sub) (not (str/blank? sub))) (assoc "subnet_id" sub)
      (some? seq-num) (assoc "seq" seq-num))))
