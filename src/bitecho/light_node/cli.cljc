(ns bitecho.light-node.cli
  "Shared pure Sans-IO CLI parser and verb inventory for Bitecho light-node and browser shells.
   Provides canonical verb list, pure string tokenizer, and structured command parser conforming
   to Rules 1, 2, 5, and 6."
  (:require [clojure.string :as str]))

;; =============================================================================
;; 1. Canonical Supported CLI Verbs Inventory (Rule 6)
;; =============================================================================

(def supported-cli-verbs
  "Canonical sorted vector of all 68 supported CLI verbs across Bitecho shells."
  ["accept"
   "account"
   "ack"
   "anchor-subnet"
   "artifact-get"
   "artifact-list"
   "artifact-put"
   "artifact-revoke"
   "bip-consent"
   "bip-object"
   "bip-status"
   "bip-submit"
   "bounties"
   "bounty-create"
   "bounty-settle"
   "broadcast"
   "capability-list"
   "capability-publish"
   "capability-resolve"
   "close"
   "dac-attach"
   "dac-revoke"
   "directory-lookup"
   "directory-register"
   "directory-verify"
   "discover"
   "epoch-tick"
   "escrows"
   "export-ack"
   "export-offer"
   "export-poll"
   "export-send"
   "help"
   "identity"
   "import"
   "import-poll"
   "inbox"
   "lock-intent"
   "offer"
   "p2p-answer"
   "p2p-channel-state"
   "p2p-offer"
   "petname-list"
   "petname-remove"
   "petname-resolve"
   "petname-set"
   "puzzle-eval"
   "puzzle-hash"
   "query-chain-state"
   "refund-intent"
   "register-home-set"
   "release-intent"
   "rendezvous-accept"
   "rendezvous-offer"
   "rendezvous-policy"
   "retransmit-outbox"
   "send"
   "settle-intent"
   "status"
   "storage-get"
   "storage-list"
   "storage-put"
   "submit-vouchers"
   "subscribe-subnets"
   "sync-account"
   "transfer"
   "verify-subnet-anchor"
   "wait"])

(def supported-cli-verbs-set
  "Set of all 68 legacy/domain CLI verbs for O(1) membership check."
  (set supported-cli-verbs))

(def canonical-cli-verbs
  "Canonical sorted vector of the 12 unified CLI verbs (BIP-005 / Milestone D31)."
  ["connect"
   "ctl"
   "get"
   "inbox"
   "list"
   "lock"
   "put"
   "send"
   "serve"
   "spend"
   "transfer"
   "wait"])

(def canonical-cli-verbs-set
  "Set of the 12 canonical CLI verbs (BIP-005)."
  (set canonical-cli-verbs))

(def legacy-verb-desugar-table
  "Complete 68/68 desugaring table mapping every legacy verb in `supported-cli-verbs`
   to its canonical 1-of-12 verb (`F-U1`)."
  {"accept"               {:canonical "connect"  :domain-cmd "accept"}
   "account"              {:canonical "get"      :domain-cmd "account"}
   "ack"                  {:canonical "inbox"    :domain-cmd "ack"}
   "anchor-subnet"        {:canonical "put"      :domain-cmd "anchor-subnet"}
   "artifact-get"         {:canonical "get"      :domain-cmd "artifact-get"}
   "artifact-list"        {:canonical "list"     :domain-cmd "artifact-list"}
   "artifact-put"         {:canonical "put"      :domain-cmd "artifact-put"}
   "artifact-revoke"      {:canonical "put"      :domain-cmd "artifact-revoke"}
   "bip-consent"          {:canonical "put"      :domain-cmd "bip-consent"}
   "bip-object"           {:canonical "put"      :domain-cmd "bip-object"}
   "bip-status"           {:canonical "get"      :domain-cmd "bip-status"}
   "bip-submit"           {:canonical "put"      :domain-cmd "bip-submit"}
   "bounties"             {:canonical "list"     :domain-cmd "bounties"}
   "bounty-create"        {:canonical "lock"     :domain-cmd "bounty-create"}
   "bounty-settle"        {:canonical "spend"    :domain-cmd "bounty-settle"}
   "broadcast"            {:canonical "send"     :domain-cmd "broadcast"}
   "capability-list"      {:canonical "list"     :domain-cmd "capability-list"}
   "capability-publish"   {:canonical "put"      :domain-cmd "capability-publish"}
   "capability-resolve"   {:canonical "get"      :domain-cmd "capability-resolve"}
   "close"                {:canonical "connect"  :domain-cmd "close"}
   "dac-attach"           {:canonical "ctl"      :domain-cmd "dac-attach"}
   "dac-revoke"           {:canonical "ctl"      :domain-cmd "dac-revoke"}
   "directory-lookup"     {:canonical "get"      :domain-cmd "directory-lookup"}
   "directory-register"   {:canonical "put"      :domain-cmd "directory-register"}
   "directory-verify"     {:canonical "get"      :domain-cmd "directory-verify"}
   "discover"             {:canonical "list"     :domain-cmd "discover"}
   "epoch-tick"           {:canonical "ctl"      :domain-cmd "epoch-tick"}
   "escrows"              {:canonical "list"     :domain-cmd "escrows"}
   "export-ack"           {:canonical "inbox"    :domain-cmd "export-ack"}
   "export-offer"         {:canonical "connect"  :domain-cmd "export-offer"}
   "export-poll"          {:canonical "inbox"    :domain-cmd "export-poll"}
   "export-send"          {:canonical "send"     :domain-cmd "export-send"}
   "help"                 {:canonical "ctl"      :domain-cmd "help"}
   "identity"             {:canonical "get"      :domain-cmd "identity"}
   "import"               {:canonical "inbox"    :domain-cmd "import"}
   "import-poll"          {:canonical "inbox"    :domain-cmd "import-poll"}
   "inbox"                {:canonical "inbox"    :domain-cmd "inbox"}
   "lock-intent"          {:canonical "lock"     :domain-cmd "lock-intent"}
   "offer"                {:canonical "connect"  :domain-cmd "offer"}
   "p2p-answer"           {:canonical "connect"  :domain-cmd "p2p-answer"}
   "p2p-channel-state"    {:canonical "connect"  :domain-cmd "p2p-channel-state"}
   "p2p-offer"            {:canonical "connect"  :domain-cmd "p2p-offer"}
   "petname-list"         {:canonical "list"     :domain-cmd "petname-list"}
   "petname-remove"       {:canonical "put"      :domain-cmd "petname-remove"}
   "petname-resolve"      {:canonical "get"      :domain-cmd "petname-resolve"}
   "petname-set"          {:canonical "put"      :domain-cmd "petname-set"}
   "puzzle-eval"          {:canonical "spend"    :domain-cmd "puzzle-eval"}
   "puzzle-hash"          {:canonical "spend"    :domain-cmd "puzzle-hash"}
   "query-chain-state"    {:canonical "get"      :domain-cmd "query-chain-state"}
   "refund-intent"        {:canonical "spend"    :domain-cmd "refund-intent"}
   "register-home-set"    {:canonical "connect"  :domain-cmd "register-home-set"}
   "release-intent"       {:canonical "spend"    :domain-cmd "release-intent"}
   "rendezvous-accept"    {:canonical "connect"  :domain-cmd "rendezvous-accept"}
   "rendezvous-offer"     {:canonical "connect"  :domain-cmd "rendezvous-offer"}
   "rendezvous-policy"    {:canonical "connect"  :domain-cmd "rendezvous-policy"}
   "retransmit-outbox"    {:canonical "send"     :domain-cmd "retransmit-outbox"}
   "send"                 {:canonical "send"     :domain-cmd "send"}
   "settle-intent"        {:canonical "spend"    :domain-cmd "settle-intent"}
   "status"               {:canonical "get"      :domain-cmd "status"}
   "storage-get"          {:canonical "get"      :domain-cmd "storage-get"}
   "storage-list"         {:canonical "list"     :domain-cmd "storage-list"}
   "storage-put"          {:canonical "put"      :domain-cmd "storage-put"}
   "submit-vouchers"      {:canonical "spend"    :domain-cmd "submit-vouchers"}
   "subscribe-subnets"    {:canonical "list"     :domain-cmd "subscribe-subnets"}
   "sync-account"         {:canonical "get"      :domain-cmd "sync-account"}
   "transfer"             {:canonical "transfer" :domain-cmd "transfer"}
   "verify-subnet-anchor" {:canonical "get"      :domain-cmd "verify-subnet-anchor"}
   "wait"                 {:canonical "wait"     :domain-cmd "wait"}})

(def runner-alias-desugar-table
  "Complete runner & shell alias desugaring table (`F-U1` & `BIP-006`)."
  {"serve"             {:canonical "serve"   :domain-cmd "serve"}
   "mcp"               {:canonical "serve"   :domain-cmd "mcp"}
   "ctl"               {:canonical "ctl"     :domain-cmd "ctl"}
   "daemon"            {:canonical "serve"   :domain-cmd "daemon"}
   "wait-event"        {:canonical "wait"    :domain-cmd "wait"}
   "export-p2p-offer"  {:canonical "connect" :domain-cmd "export-p2p-offer"}
   "export-p2p-answer" {:canonical "connect" :domain-cmd "export-p2p-answer"}
   "export-reveal"     {:canonical "connect" :domain-cmd "export-reveal"}
   "import-envelope"   {:canonical "inbox"   :domain-cmd "import-envelope"}})

(def memento-verb-desugar-table
  "BIP-016 Rolodex & Memento domain verbs mapped to canonical 1-of-12 CLI verbs (Rule 6)."
  {"rolodex-status"  {:canonical "get" :domain-cmd "rolodex-status"}
   "rolodex-put"     {:canonical "put" :domain-cmd "rolodex-put"}
   "rolodex-rotate"  {:canonical "ctl" :domain-cmd "rolodex-rotate"}
   "rolodex-restore" {:canonical "put" :domain-cmd "rolodex-restore"}
   "memento-head"    {:canonical "get" :domain-cmd "memento-head"}
   "memento-put"     {:canonical "put" :domain-cmd "memento-put"}
   "memento-walk"    {:canonical "get" :domain-cmd "memento-walk"}})

(def chunked-artifact-verb-desugar-table
  "BIP-017a chunked large-artifact domain verbs mapped to canonical 1-of-12 CLI verbs (Rule 6)."
  {"artifact-put-chunked"     {:canonical "put" :domain-cmd "artifact-put-chunked"}
   "artifact-get-chunked"     {:canonical "get" :domain-cmd "artifact-get-chunked"}
   "artifact-manifest-verify" {:canonical "get" :domain-cmd "artifact-manifest-verify"}})

(def web-release-verb-desugar-table
  "BIP-017b atomic `web/app/release` domain verbs mapped to canonical 1-of-12 CLI verbs (Rule 6)."
  {"web-release-publish"  {:canonical "put" :domain-cmd "web-release-publish"}
   "web-release-rollback" {:canonical "put" :domain-cmd "web-release-rollback"}
   "web-release-verify"   {:canonical "get" :domain-cmd "web-release-verify"}})

(def all-recognized-cli-verbs-set
  "Union of all 68 legacy verbs, 12 canonical verbs, shell/runner aliases, BIP-016 Rolodex/Memento verbs,
   BIP-017a chunked-artifact verbs, and BIP-017b web-release verbs."
  (-> supported-cli-verbs-set
      (into canonical-cli-verbs-set)
      (into (keys runner-alias-desugar-table))
      (into (keys memento-verb-desugar-table))
      (into (keys chunked-artifact-verb-desugar-table))
      (into (keys web-release-verb-desugar-table))))

(def known-command-flags
  "Inventory of all supported CLI flags across Bitecho shells (Rule 6)."
  ["--state-dir" "--control-port" "--bootstrap" "--relay-url" "--relay-urls" "--quorum" "--subnet-id" "--subnet"
   "--subscribe-subnets" "--subnets" "--transport" "--proxy" "--timeout-ms" "--max-epoch-skew"
   "--cmd-file" "--events-out" "--session-id" "--session" "--min-seq" "--min-broadcast-seq"
   "--cursor" "--after-ts" "--min-balance" "--non-destructive"
   "--ingress-tcp-port" "--trusted-dac-anchors" "--clear-trusted-dac-anchors" "--trusted-deploy-authorities"
   "--turn-server" "--turn-username"
   "--turn-password" "--turn-realm" "--turn-force-relay" "--sync-interval-ms" "--price"
   "--price-max" "--burn" "--to" "--from" "--callee" "--peer" "--receiver" "--recipient"
   "--amount" "--text" "--message" "--payload-hex" "--peek" "--poll" "--sync" "--no-poll"
   "--autonomous" "--auto-sync" "--auto-register-home-set" "--no-auto-register-home-set"
   "--wait-open-ms" "--block" "--until-event" "--help" "--mcp"
   "--invariant-diff-edn" "--jurisdiction-map" "--human-anchor-sunset" "--bip-cid"
   "--path" "--cid" "--file" "--out" "--local-only" "--hex" "--seq" "--authority" "--prefix" "--endpoint" "--candidates"
   "--nickname" "--name" "--domain"
   "--pin-version" "--auto-update-pointer" "--auto-update-interval-ms"
   "--node-role" "--retention-max-entries" "--retention-max-bytes" "--rotate-every"
   "--grace-epochs" "--lkg-cid" "--walk-depth-cap" "--owner-pubkey" "--cache-incentive"
   "--chunk-size" "--concurrency" "--resume-dir" "--max-bytes"
   "--release-cid" "--genesis-anchor-cid" "--lkg-release-cid" "--headers-config-cid"])

;; =============================================================================
;; 2. Pure CLI Tokenizer & JSONL Command Splitter (Rule 2)
;; =============================================================================

(defn split-jsonl-commands
  "Splits a text containing one or more JSON objects (possibly concatenated without newlines,
   e.g. '{\"cmd\":\"status\"}{\"cmd\":\"identity\"}') into a vector of separate JSON strings."
  [text]
  (if (str/blank? text)
    []
    (let [chars (vec text)
          n (count chars)]
      (loop [idx 0
             start 0
             brace-depth 0
             in-string? false
             escape? false
             objs []]
        (if (>= idx n)
          (let [tail (str/trim (subs text start n))]
            (if (and (zero? brace-depth) (seq tail))
              (conj objs tail)
              objs))
          (let [ch (nth chars idx)]
            (cond
              escape?
              (recur (inc idx) start brace-depth in-string? false objs)

              (and in-string? (= ch \\))
              (recur (inc idx) start brace-depth in-string? true objs)

              (= ch \")
              (recur (inc idx) start brace-depth (not in-string?) false objs)

              in-string?
              (recur (inc idx) start brace-depth in-string? false objs)

              (= ch \{)
              (recur (inc idx)
                     (if (zero? brace-depth)
                       (let [skipped-ws (subs text start idx)]
                         (if (str/blank? skipped-ws) idx start))
                       start)
                     (inc brace-depth)
                     false false objs)

              (= ch \})
              (let [new-depth (dec brace-depth)]
                (if (zero? new-depth)
                  (let [cand (str/trim (subs text start (inc idx)))]
                    (recur (inc idx) (inc idx) 0 false false (if (seq cand) (conj objs cand) objs)))
                  (recur (inc idx) start new-depth false false objs)))

              :else
              (recur (inc idx) start brace-depth in-string? false objs))))))))

(defn- whitespace-char?
  [ch]
  (or (= ch \space) (= ch \tab) (= ch \newline) (= ch \return)))

(defn tokenize-cli-string
  "Pure tokenizer for CLI string inputs.
   Handles single/double quoted strings, escaped characters, and whitespace."
  [s]
  (if (or (nil? s) (str/blank? s))
    []
    (let [chars (vec (str/trim s))
          n (count chars)]
      (loop [idx 0
             current []
             in-quote nil
             tokens []]
        (if (>= idx n)
          (if (seq current)
            (conj tokens (apply str current))
            tokens)
          (let [ch (nth chars idx)]
            (cond
              in-quote
              (cond
                (= ch in-quote)
                (recur (inc idx) current nil tokens)

                (and (= ch \\) (< (inc idx) n) (= (nth chars (inc idx)) in-quote))
                (recur (+ idx 2) (conj current in-quote) in-quote tokens)

                :else
                (recur (inc idx) (conj current ch) in-quote tokens))

              (or (= ch \") (= ch \'))
              (recur (inc idx) current ch tokens)

              (whitespace-char? ch)
              (if (seq current)
                (recur (inc idx) [] nil (conj tokens (apply str current)))
                (recur (inc idx) [] nil tokens))

              :else
              (recur (inc idx) (conj current ch) nil tokens))))))))

;; =============================================================================
;; 3. Pure Flag and Option Extraction Helpers
;; =============================================================================

(defn- flag->kw [flag]
  (keyword (if (str/starts-with? flag "--") (subs flag 2) flag)))

(defn- flag->str-k [flag]
  (if (str/starts-with? flag "--") (subs flag 2) flag))

(defn- flag->snake-k [flag]
  (str/replace (flag->str-k flag) "-" "_"))

(defn- extract-flag-value
  [tokens flag default-val]
  (if (map? tokens)
    (or (get tokens (flag->kw flag))
        (get tokens (flag->str-k flag))
        (get tokens (flag->snake-k flag))
        (get tokens flag)
        default-val)
    (loop [toks tokens]
      (if (empty? toks)
        default-val
        (if (= (first toks) flag)
          (if (and (seq (rest toks)) (not (str/starts-with? (second toks) "--")))
            (second toks)
            default-val)
          (recur (rest toks)))))))

(defn- extract-long-flag
  [tokens flag default-val]
  (let [v (extract-flag-value tokens flag nil)]
    (if (nil? v)
      default-val
      (try
        #?(:clj (Long/parseLong (str v))
           :cljs (let [n (js/parseInt (str v) 10)]
                   (if (js/isNaN n) default-val n)))
        (catch #?(:clj Exception :cljs :default) _ default-val)))))

(defn- has-flag?
  [tokens flag]
  (if (map? tokens)
    (boolean (or (get tokens (flag->kw flag))
                 (get tokens (flag->str-k flag))
                 (get tokens (flag->snake-k flag))
                 (get tokens flag)))
    (boolean (some #{flag} tokens))))

(defn- parse-tokens-into-opts-and-args
  [tokens]
  (loop [rem-tokens tokens
         opts {}
         args []]
    (if (empty? rem-tokens)
      {:opts opts :args args}
      (let [tok (first rem-tokens)]
        (if (str/starts-with? tok "--")
          (let [flag-name (subs tok 2)
                has-val? (and (seq (rest rem-tokens))
                              (not (str/starts-with? (second rem-tokens) "--")))
                val (if has-val? (second rem-tokens) true)
                next-rem (if has-val? (drop 2 rem-tokens) (rest rem-tokens))]
            (recur next-rem (assoc opts flag-name val) args))
          (recur (rest rem-tokens) opts (conj args tok)))))))

(defn- extract-relay-urls
  [tokens]
  (let [raw (extract-flag-value tokens "--relay-urls" nil)]
    (cond
      (sequential? raw) (vec (remove str/blank? (map #(str/trim (str %)) raw)))
      (and (string? raw) (not (str/blank? raw)))
      (vec (remove str/blank? (map str/trim (str/split raw #","))))
      :else nil)))

(defn- assoc-relay-pool-flags
  [m tokens]
  (let [relay-urls (extract-relay-urls tokens)
        quorum (extract-long-flag tokens "--quorum" nil)]
    (cond-> m
      (seq relay-urls) (assoc "relay_urls" relay-urls)
      (some? quorum) (assoc "quorum" quorum))))

;; =============================================================================
;; 4. Command Map Construction
;; =============================================================================

(defn build-cmd-map
  "Pure helper constructing a JSON command map from verb and arg tokens."
  [verb tokens]
  (let [clean-tokens (if (and (seq tokens) (= (first tokens) verb))
                       (rest tokens)
                       tokens)]
    (case verb
      "status"   (assoc-relay-pool-flags {"cmd" "status"} clean-tokens)
      "identity" {"cmd" "identity"}
      "discover" {"cmd" "discover"}
      "help"     {"cmd" "help"}
      "inbox"
      (cond
        (has-flag? clean-tokens "--hex")
        (assoc (build-cmd-map "import" clean-tokens) "canonical_cmd" "inbox")

        (or (has-flag? clean-tokens "--payload")
            (has-flag? clean-tokens "--json")
            (has-flag? clean-tokens "--file"))
        (assoc (build-cmd-map "import-poll" clean-tokens) "canonical_cmd" "inbox")

        (and (or (has-flag? clean-tokens "--up-to-seq")
                 (has-flag? clean-tokens "--ack-seq")
                 (has-flag? clean-tokens "--up-to-broadcast-seq"))
             (has-flag? clean-tokens "--offline"))
        (assoc (build-cmd-map "export-ack" clean-tokens) "canonical_cmd" "inbox")

        (or (has-flag? clean-tokens "--up-to-seq")
            (has-flag? clean-tokens "--ack-seq")
            (has-flag? clean-tokens "--up-to-broadcast-seq"))
        (assoc (build-cmd-map "ack" clean-tokens) "canonical_cmd" "inbox")

        (or (has-flag? clean-tokens "--since-seq")
            (has-flag? clean-tokens "--since-relay-seq")
            (has-flag? clean-tokens "--since-broadcast-seq"))
        (assoc (build-cmd-map "export-poll" clean-tokens) "canonical_cmd" "inbox")

        :else
        (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                      (extract-flag-value clean-tokens "--subnet" nil))
              peek? (has-flag? clean-tokens "--peek")]
          (cond-> {"cmd" "inbox"}
            sub (assoc "subnet_id" sub)
            peek? (assoc "peek" true))))

      "subscribe-subnets"
      (let [subnets-raw (or (extract-flag-value clean-tokens "--subnets" nil)
                            (extract-flag-value clean-tokens "--subscribe-subnets" nil)
                            (extract-flag-value clean-tokens "--subnet-id" nil)
                            (extract-flag-value clean-tokens "--subnet" nil))
            subnets (if subnets-raw
                      (mapv str/trim (str/split subnets-raw #","))
                      [])]
        {"cmd" "subscribe-subnets"
         "subnets" subnets})

      "offer"
      (let [to-val (extract-flag-value clean-tokens "--to" nil)
            callee (or (extract-flag-value clean-tokens "--callee" nil)
                       (extract-flag-value clean-tokens "--peer" nil)
                       to-val)
            price (extract-long-flag clean-tokens "--price" 0)
            burn (extract-long-flag clean-tokens "--burn" 500)
            min-bal (extract-long-flag clean-tokens "--min-balance" nil)
            hn (extract-flag-value clean-tokens "--home-node" nil)
            wait-open-ms (extract-long-flag clean-tokens "--wait-open-ms" nil)
            m {"cmd" "offer" "callee" callee "price" price "burn" burn}]
        (cond-> m
          to-val (assoc "to" to-val)
          hn (assoc "home_node" hn)
          (some? wait-open-ms) (assoc "wait_open_ms" wait-open-ms)
          min-bal (assoc "min_balance" min-bal)))

      "accept"
      {"cmd" "accept"
       "session_id" (or (extract-flag-value clean-tokens "--session-id" nil)
                        (extract-flag-value clean-tokens "--session" nil))}

      "close"
      {"cmd" "close"
       "session_id" (or (extract-flag-value clean-tokens "--session-id" nil)
                        (extract-flag-value clean-tokens "--session" nil))}

      "send"
      (cond
        (has-flag? clean-tokens "--retransmit")
        (assoc (build-cmd-map "retransmit-outbox" clean-tokens) "canonical_cmd" "send")

        (has-flag? clean-tokens "--offline")
        (assoc (build-cmd-map "export-send" clean-tokens) "canonical_cmd" "send")

        (and (or (has-flag? clean-tokens "--subnet-id")
                 (has-flag? clean-tokens "--subnet"))
             (not (has-flag? clean-tokens "--to"))
             (not (has-flag? clean-tokens "--peer"))
             (not (has-flag? clean-tokens "--session-id"))
             (not (has-flag? clean-tokens "--session")))
        (assoc (build-cmd-map "broadcast" clean-tokens) "canonical_cmd" "send")

        :else
        (let [to (or (extract-flag-value clean-tokens "--to" nil)
                     (extract-flag-value clean-tokens "--peer" nil))
              sid (or (extract-flag-value clean-tokens "--session-id" nil)
                      (extract-flag-value clean-tokens "--session" nil)
                      to)
              t (extract-flag-value clean-tokens "--text" nil)
              msg (extract-flag-value clean-tokens "--message" nil)
              hex (extract-flag-value clean-tokens "--payload-hex" nil)
              burn (extract-long-flag clean-tokens "--burn" 500)
              min-bal (extract-long-flag clean-tokens "--min-balance" nil)
              m {"cmd" "send" "session_id" sid "burn" burn}]
          (cond-> m
            to (assoc "to" to)
            t (assoc "text" t)
            msg (assoc "message" msg "text" (or t msg))
            hex (assoc "payload_hex" hex)
            min-bal (assoc "min_balance" min-bal))))

      "transfer"
      (let [recv (or (extract-flag-value clean-tokens "--receiver" nil)
                     (extract-flag-value clean-tokens "--recipient" nil)
                     (extract-flag-value clean-tokens "--to" nil))
            amt (extract-long-flag clean-tokens "--amount" 0)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            burn (extract-long-flag clean-tokens "--burn" 500)
            min-bal (extract-long-flag clean-tokens "--min-balance" nil)
            m {"cmd" "transfer" "receiver" recv "recipient" recv "to" recv "amount" amt "burn" burn}]
        (cond-> m
          seq-num (assoc "seq" seq-num)
          min-bal (assoc "min_balance" min-bal)))

      "account"
      (let [sync? (has-flag? clean-tokens "--sync")
            b (extract-long-flag clean-tokens "--balance" nil)
            s (extract-long-flag clean-tokens "--seq" nil)
            m {"cmd" "account"}]
        (cond-> m
          sync? (assoc "sync" true)
          b (assoc "balance" b)
          s (assoc "seq" s)))

      "sync-account"
      (let [b (extract-long-flag clean-tokens "--balance" nil)
            s (extract-long-flag clean-tokens "--seq" nil)
            m {"cmd" "sync-account"}]
        (cond-> m
          b (assoc "balance" b)
          s (assoc "seq" s)))

      "settle-intent"
      (let [recv (or (extract-flag-value clean-tokens "--receiver" nil)
                     (extract-flag-value clean-tokens "--recipient" nil)
                     (extract-flag-value clean-tokens "--to" nil))
            amt (extract-long-flag clean-tokens "--amount" 0)]
        {"cmd" "settle-intent" "receiver" recv "recipient" recv "to" recv "amount" amt})

      "lock-intent"
      (let [recv (or (extract-flag-value clean-tokens "--receiver" nil)
                     (extract-flag-value clean-tokens "--recipient" nil)
                     (extract-flag-value clean-tokens "--to" nil))
            amt (extract-long-flag clean-tokens "--amount" nil)
            dh (extract-flag-value clean-tokens "--deliverable-hash" nil)
            ph (extract-flag-value clean-tokens "--puzzle-hash" nil)
            psrc (extract-flag-value clean-tokens "--puzzle-source" nil)
            ep (or (extract-long-flag clean-tokens "--timeout-epoch" nil)
                   (extract-long-flag clean-tokens "--expires-epoch" nil))
            eid (or (extract-flag-value clean-tokens "--intent-id" nil)
                    (extract-flag-value clean-tokens "--escrow-id" nil))
            m {"cmd" "lock-intent"}]
        (cond-> m
          recv (assoc "receiver" recv "recipient" recv)
          amt (assoc "amount" amt)
          dh (assoc "deliverable_hash" dh)
          ph (assoc "puzzle_hash" ph)
          psrc (assoc "puzzle_source" psrc)
          ep (assoc "expires_epoch" ep "timeout_epoch" ep)
          eid (assoc "escrow_id" eid "intent_id" eid)))

      "release-intent"
      (let [eid (or (extract-flag-value clean-tokens "--intent-id" nil)
                    (extract-flag-value clean-tokens "--escrow-id" nil))
            pre (extract-flag-value clean-tokens "--preimage" nil)
            psrc (extract-flag-value clean-tokens "--puzzle-source" nil)
            sol (extract-flag-value clean-tokens "--solution" nil)
            m {"cmd" "release-intent"}]
        (cond-> m
          eid (assoc "escrow_id" eid "intent_id" eid)
          pre (assoc "preimage" pre)
          psrc (assoc "puzzle_source" psrc)
          sol (assoc "solution" sol)))

      "refund-intent"
      (let [eid (or (extract-flag-value clean-tokens "--intent-id" nil)
                    (extract-flag-value clean-tokens "--escrow-id" nil))
            m {"cmd" "refund-intent"}]
        (cond-> m
          eid (assoc "escrow_id" eid "intent_id" eid)))

      "escrows"
      (let [sync? (has-flag? clean-tokens "--sync")]
        (cond-> {"cmd" "escrows"}
          sync? (assoc "sync" true)))

      "submit-vouchers" {"cmd" "submit-vouchers"}
      "query-chain-state" {"cmd" "query-chain-state"}

      "register-home-set"
      (let [nodes (extract-flag-value clean-tokens "--nodes" nil)
            p (extract-long-flag clean-tokens "--price" 0)
            p-max (extract-long-flag clean-tokens "--price-max" nil)
            b (extract-long-flag clean-tokens "--burn" 500)
            m {"cmd" "register-home-set"
               "price" p
               "home_nodes" (if nodes (mapv str/trim (str/split nodes #",")) [])
               "burn" b}]
        (cond-> m
          p-max (assoc "price_max" p-max)))

      "broadcast"
      (let [t (or (extract-flag-value clean-tokens "--text" nil)
                  (extract-flag-value clean-tokens "--message" nil))
            sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            b (extract-long-flag clean-tokens "--burn" nil)
            min-bal (extract-long-flag clean-tokens "--min-balance" nil)
            m {"cmd" "broadcast"}]
        (cond-> m
          t (assoc "text" t)
          sub (assoc "subnet_id" sub)
          (some? b) (assoc "burn" b)
          min-bal (assoc "min_balance" min-bal)))

      "rendezvous-policy"
      (let [min-burn (extract-long-flag clean-tokens "--min-burn" nil)
            price (extract-long-flag clean-tokens "--price" nil)
            allowlist (extract-flag-value clean-tokens "--allowlist" nil)
            hn (extract-flag-value clean-tokens "--home-node" nil)
            auto-acc (extract-flag-value clean-tokens "--auto-accept" nil)
            auto-acc-bool (if (has-flag? clean-tokens "--auto-accept")
                            (if (and auto-acc (re-matches #"(?i)false" auto-acc)) false true)
                            nil)
            m {"cmd" "rendezvous-policy"}]
        (cond-> m
          min-burn (assoc "min_burn" min-burn)
          price (assoc "price" price)
          allowlist (assoc "allowlist" (if (str/includes? allowlist ",")
                                         (mapv str/trim (str/split allowlist #","))
                                         [(str/trim allowlist)]))
          hn (assoc "home_node" hn)
          (some? auto-acc-bool) (assoc "auto_accept" auto-acc-bool)))

      "rendezvous-offer"
      (let [callee (or (extract-flag-value clean-tokens "--callee" nil)
                       (extract-flag-value clean-tokens "--to" nil))
            burn (extract-long-flag clean-tokens "--burn" nil)
            min-bal (extract-long-flag clean-tokens "--min-balance" nil)
            topic (extract-flag-value clean-tokens "--topic" nil)
            hn (extract-flag-value clean-tokens "--home-node" nil)
            text (extract-flag-value clean-tokens "--text" nil)
            m {"cmd" "rendezvous-offer" "callee" callee}]
        (cond-> m
          burn (assoc "burn" burn)
          topic (assoc "topic" topic)
          hn (assoc "home_node" hn)
          text (assoc "text" text)
          min-bal (assoc "min_balance" min-bal)))

      "rendezvous-accept"
      (let [oh (extract-flag-value clean-tokens "--offer-hash" nil)
            from (extract-flag-value clean-tokens "--from" nil)
            m {"cmd" "rendezvous-accept"}]
        (cond-> m
          oh (assoc "offer_hash" oh)
          from (assoc "from" from)))

      "p2p-offer"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil))
            to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--peer" nil)
                   (extract-flag-value clean-tokens "--callee" nil))
            cands (or (extract-flag-value clean-tokens "--candidates" nil)
                      (extract-flag-value clean-tokens "--endpoint" nil))
            tr (extract-flag-value clean-tokens "--transport" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "p2p-offer"}]
        (cond-> m
          sid (assoc "session_id" sid)
          to (assoc "to" to "peer" to)
          cands (assoc "candidates" (vec (remove str/blank? (map str/trim (str/split cands #",")))))
          tr (assoc "transport" tr)
          (some? b) (assoc "burn" b)))

      "p2p-answer"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil))
            to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--peer" nil)
                   (extract-flag-value clean-tokens "--callee" nil))
            cands (or (extract-flag-value clean-tokens "--candidates" nil)
                      (extract-flag-value clean-tokens "--endpoint" nil))
            tr (extract-flag-value clean-tokens "--transport" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "p2p-answer"}]
        (cond-> m
          sid (assoc "session_id" sid)
          to (assoc "to" to "peer" to)
          cands (assoc "candidates" (vec (remove str/blank? (map str/trim (str/split cands #",")))))
          tr (assoc "transport" tr)
          (some? b) (assoc "burn" b)))

      "p2p-channel-state"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil))
            conn-raw (extract-flag-value clean-tokens "--connected" nil)
            conn? (if (some? conn-raw)
                    (not= (str/lower-case (str/trim (str conn-raw))) "false")
                    (has-flag? clean-tokens "--connected"))
            tr (extract-flag-value clean-tokens "--transport" nil)
            err (extract-flag-value clean-tokens "--error" nil)
            m {"cmd" "p2p-channel-state" "session_id" sid "connected" conn?}]
        (cond-> m
          tr (assoc "transport" tr)
          err (assoc "error" err)))

      "petname-set"
      (let [pn (extract-flag-value clean-tokens "--petname" nil)
            pk (extract-flag-value clean-tokens "--pubkey" nil)
            ow? (has-flag? clean-tokens "--overwrite")]
        {"cmd" "petname-set" "petname" pn "pubkey" pk "overwrite" ow?})

      "petname-list"
      {"cmd" "petname-list"}

      "petname-remove"
      (let [pn (extract-flag-value clean-tokens "--petname" nil)
            pk (extract-flag-value clean-tokens "--pubkey" nil)]
        {"cmd" "petname-remove" "petname" pn "pubkey" pk})

      "petname-resolve"
      (let [pn (extract-flag-value clean-tokens "--petname" nil)
            pk (extract-flag-value clean-tokens "--pubkey" nil)]
        {"cmd" "petname-resolve" "petname" pn "pubkey" pk})

      "dac-attach" {"cmd" "dac-attach"}
      "dac-revoke" {"cmd" "dac-revoke"}

      "directory-verify"
      (let [raw-nick (or (extract-flag-value clean-tokens "--nickname" nil)
                         (extract-flag-value clean-tokens "--name" nil))
            raw-dom (extract-flag-value clean-tokens "--domain" nil)
            slash-idx (when (string? raw-nick) (.lastIndexOf (str/trim raw-nick) "/"))
            nick (if (and slash-idx (pos? slash-idx))
                   (subs (str/trim raw-nick) (inc slash-idx))
                   raw-nick)
            dom (or raw-dom
                    (when (and slash-idx (pos? slash-idx))
                      (subs (str/trim raw-nick) 0 slash-idx)))
            pk (extract-flag-value clean-tokens "--directory-pubkey" nil)
            m {"cmd" "directory-verify"}]
        (cond-> m
          nick (assoc "nickname" nick)
          dom (assoc "domain" dom)
          pk (assoc "directory_pubkey" pk)))

      "directory-register"
      (let [raw-nick (or (extract-flag-value clean-tokens "--nickname" nil)
                         (extract-flag-value clean-tokens "--name" nil))
            raw-dom (extract-flag-value clean-tokens "--domain" nil)
            slash-idx (when (string? raw-nick) (.lastIndexOf (str/trim raw-nick) "/"))
            nick (if (and slash-idx (pos? slash-idx))
                   (subs (str/trim raw-nick) (inc slash-idx))
                   raw-nick)
            dom (or raw-dom
                    (when (and slash-idx (pos? slash-idx))
                      (subs (str/trim raw-nick) 0 slash-idx)))
            mb (extract-flag-value clean-tokens "--mailbox" nil)
            prev-pk (extract-flag-value clean-tokens "--prev-pubkey" nil)
            prev-sk (extract-flag-value clean-tokens "--prev-privkey" nil)
            m {"cmd" "directory-register"}]
        (cond-> m
          nick (assoc "nickname" nick)
          dom (assoc "domain" dom)
          mb (assoc "mailbox" mb)
          prev-pk (assoc "prev_pubkey" prev-pk)
          prev-sk (assoc "prev_privkey" prev-sk)))

      "directory-lookup"
      (let [raw-nick (or (extract-flag-value clean-tokens "--nickname" nil)
                         (extract-flag-value clean-tokens "--name" nil))
            raw-dom (extract-flag-value clean-tokens "--domain" nil)
            slash-idx (when (string? raw-nick) (.lastIndexOf (str/trim raw-nick) "/"))
            nick (if (and slash-idx (pos? slash-idx))
                   (subs (str/trim raw-nick) (inc slash-idx))
                   raw-nick)
            dom (or raw-dom
                    (when (and slash-idx (pos? slash-idx))
                      (subs (str/trim raw-nick) 0 slash-idx)))
            dir-pk (extract-flag-value clean-tokens "--directory-pubkey" nil)
            m {"cmd" "directory-lookup"}]
        (cond-> m
          nick (assoc "nickname" nick)
          dom (assoc "domain" dom)
          dir-pk (assoc "directory_pubkey" dir-pk)))

      "anchor-subnet"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    (extract-flag-value clean-tokens "--child-subnet" nil))
            psub (or (extract-flag-value clean-tokens "--parent-subnet" nil)
                     (extract-flag-value clean-tokens "--parent" nil))
            ce (extract-long-flag clean-tokens "--child-epoch" nil)
            m {"cmd" "anchor-subnet"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          psub (assoc "parent_subnet" psub)
          ce (assoc "child_epoch" ce)))

      "epoch-tick"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            ep (extract-long-flag clean-tokens "--epoch" nil)
            m {"cmd" "epoch-tick"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          ep (assoc "epoch" ep)))

      "verify-subnet-anchor"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    (extract-flag-value clean-tokens "--child-subnet" nil))
            psub (or (extract-flag-value clean-tokens "--parent-subnet" nil)
                     (extract-flag-value clean-tokens "--parent" nil))
            m {"cmd" "verify-subnet-anchor"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          psub (assoc "parent_subnet" psub)))

      "wait"
      (let [t (or (extract-long-flag clean-tokens "--timeout-ms" nil)
                  (extract-long-flag clean-tokens "--timeout" nil))
            ms (extract-long-flag clean-tokens "--min-seq" nil)
            bcast-seq (extract-long-flag clean-tokens "--min-broadcast-seq" nil)
            cursor (extract-long-flag clean-tokens "--cursor" nil)
            sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil))
            after-ts (extract-long-flag clean-tokens "--after-ts" nil)
            block? (or (has-flag? clean-tokens "--block")
                       (has-flag? clean-tokens "--until-event"))
            peek? (has-flag? clean-tokens "--peek")
            non-destructive? (has-flag? clean-tokens "--non-destructive")
            m {"cmd" "wait" "timeout_ms" (or t 30000)}]
        (cond-> m
          ms (assoc "min_seq" ms)
          bcast-seq (assoc "min_broadcast_seq" bcast-seq)
          cursor (assoc "cursor" cursor)
          sub (assoc "subnet_id" sub)
          sid (assoc "session_id" sid)
          after-ts (assoc "after_ts" after-ts)
          block? (assoc "block" true)
          peek? (assoc "peek" true)
          non-destructive? (assoc "non_destructive" true)))

      "retransmit-outbox"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil))
            m {"cmd" "retransmit-outbox"}]
        (cond-> m
          sid (assoc "session_id" sid)))

      "export-poll"
      (let [mseq (or (extract-long-flag clean-tokens "--since-seq" nil)
                     (extract-long-flag clean-tokens "--since-relay-seq" nil))
            bseq (extract-long-flag clean-tokens "--since-broadcast-seq" nil)
            now (or (extract-long-flag clean-tokens "--now-ms" nil)
                    (extract-long-flag clean-tokens "--now" nil)
                    #?(:clj (System/currentTimeMillis) :cljs (.now js/Date)))
            m {"cmd" "export-poll" "now_ms" now}]
        (cond-> m
          mseq (assoc "since_seq" mseq)
          bseq (assoc "since_broadcast_seq" bseq)))

      "import-poll"
      (let [f (extract-flag-value clean-tokens "--file" nil)
            pos-arg (first (remove #(str/starts-with? (str %) "-") clean-tokens))
            payload (or (extract-flag-value clean-tokens "--json" nil)
                        (extract-flag-value clean-tokens "--payload" nil)
                        f
                        pos-arg)]
        (cond-> {"cmd" "import-poll" "file_content" (or payload "")}
          f (assoc "file" f)))

      "import"
      (let [f (extract-flag-value clean-tokens "--file" nil)
            pos-arg (first (remove #(str/starts-with? (str %) "-") clean-tokens))
            h (or (extract-flag-value clean-tokens "--hex" nil)
                  f
                  pos-arg)]
        (cond-> {"cmd" "import" "hex" (or h "")}
          f (assoc "file" f)))

      "import-envelope"
      (let [f (extract-flag-value clean-tokens "--file" nil)
            pos-arg (first (remove #(str/starts-with? (str %) "-") clean-tokens))
            h (or (extract-flag-value clean-tokens "--hex" nil)
                  f
                  pos-arg)]
        (cond-> {"cmd" "import-envelope" "hex" (or h "")}
          f (assoc "file" f)))

      "export-offer"
      (let [to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--callee" nil))
            ep (extract-long-flag clean-tokens "--epoch" nil)
            p (extract-long-flag clean-tokens "--price" 0)
            b (extract-long-flag clean-tokens "--burn" 500)
            hn (extract-flag-value clean-tokens "--home-node" nil)
            m {"cmd" "export-offer" "callee" to "price" p "burn" b}]
        (cond-> m
          to (assoc "to" to)
          ep (assoc "epoch" ep)
          hn (assoc "home_node" hn)))

      "export-reveal"
      (let [oh (extract-flag-value clean-tokens "--offer-hash" nil)
            from (extract-flag-value clean-tokens "--from" nil)
            m {"cmd" "export-reveal"}]
        (cond-> m
          oh (assoc "offer_hash" oh)
          from (assoc "from" from)))

      "export-p2p-offer"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil)
                    (extract-flag-value clean-tokens "--to" nil)
                    (extract-flag-value clean-tokens "--peer" nil))
            cands (extract-flag-value clean-tokens "--candidates" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "export-p2p-offer"}]
        (cond-> m
          sid (assoc "session_id" sid "to" sid)
          cands (assoc "candidates" cands)
          (some? b) (assoc "burn" b)))

      "export-p2p-answer"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil)
                    (extract-flag-value clean-tokens "--to" nil)
                    (extract-flag-value clean-tokens "--peer" nil))
            cands (extract-flag-value clean-tokens "--candidates" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "export-p2p-answer"}]
        (cond-> m
          sid (assoc "session_id" sid "to" sid)
          cands (assoc "candidates" cands)
          (some? b) (assoc "burn" b)))

      "export-send"
      (let [to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--peer" nil)
                   (extract-flag-value clean-tokens "--session-id" nil)
                   (extract-flag-value clean-tokens "--session" nil))
            msg (or (extract-flag-value clean-tokens "--message" nil)
                    (extract-flag-value clean-tokens "--text" nil))
            b (extract-long-flag clean-tokens "--burn" 500)
            m {"cmd" "export-send" "to" to "message" msg "burn" b}]
        (cond-> m
          to (assoc "session_id" to)))

      "ack"
      (let [s (or (extract-long-flag clean-tokens "--up-to-seq" nil)
                  (extract-long-flag clean-tokens "--seq" nil)
                  (extract-long-flag clean-tokens "--ack-seq" nil))
            bs (or (extract-long-flag clean-tokens "--up-to-broadcast-seq" nil)
                   (extract-long-flag clean-tokens "--broadcast-seq" nil)
                   (extract-long-flag clean-tokens "--ack-broadcast-seq" nil))
            to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--peer" nil)
                   (extract-flag-value clean-tokens "--session-id" nil)
                   (extract-flag-value clean-tokens "--session" nil))
            m {"cmd" "ack"}]
        (cond-> m
          s (assoc "up_to_seq" s "ack_seq" s)
          bs (assoc "up_to_broadcast_seq" bs "ack_broadcast_seq" bs)
          to (assoc "to" to "session_id" to)))

      "export-ack"
      (let [s (or (extract-long-flag clean-tokens "--up-to-seq" nil)
                  (extract-long-flag clean-tokens "--seq" nil)
                  (extract-long-flag clean-tokens "--ack-seq" nil))
            bs (or (extract-long-flag clean-tokens "--up-to-broadcast-seq" nil)
                   (extract-long-flag clean-tokens "--broadcast-seq" nil)
                   (extract-long-flag clean-tokens "--ack-broadcast-seq" nil))
            to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--peer" nil)
                   (extract-flag-value clean-tokens "--session-id" nil)
                   (extract-flag-value clean-tokens "--session" nil))
            now (or (extract-long-flag clean-tokens "--now-ms" nil)
                    (extract-long-flag clean-tokens "--now" nil)
                    #?(:clj (System/currentTimeMillis) :cljs (.now js/Date)))
            m {"cmd" "export-ack" "now_ms" now}]
        (cond-> m
          s (assoc "up_to_seq" s "ack_seq" s)
          bs (assoc "up_to_broadcast_seq" bs "ack_broadcast_seq" bs)
          to (assoc "to" to "session_id" to)))

      "storage-put"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            slot (or (extract-flag-value clean-tokens "--slot-id" nil)
                     (extract-flag-value clean-tokens "--slot" nil)
                     "default")
            data (extract-flag-value clean-tokens "--data" nil)
            data-hex (extract-flag-value clean-tokens "--data-hex" nil)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            min-seq (extract-long-flag clean-tokens "--min-seq" nil)
            out-file (or (extract-flag-value clean-tokens "--out" nil)
                         (extract-flag-value clean-tokens "--out-file" nil))
            local-only? (has-flag? clean-tokens "--local-only")
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "storage-put" "subnet_id" sub "slot" slot "slot_id" slot}]
        (cond-> m
          data (assoc "data" data)
          data-hex (assoc "data_hex" data-hex)
          seq-num (assoc "seq" seq-num)
          min-seq (assoc "min_seq" min-seq)
          out-file (assoc "out_file" out-file)
          local-only? (assoc "local_only" true)
          (some? b) (assoc "burn" b)))

      "storage-get"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            slot (or (extract-flag-value clean-tokens "--slot-id" nil)
                     (extract-flag-value clean-tokens "--slot" nil)
                     "default")
            min-seq (or (extract-long-flag clean-tokens "--min-seq" nil)
                        (extract-long-flag clean-tokens "--min-expected-seq" nil))
            out-file (extract-flag-value clean-tokens "--out-file" nil)
            m {"cmd" "storage-get" "subnet_id" sub "slot" slot "slot_id" slot}]
        (cond-> m
          min-seq (assoc "min_seq" min-seq "min_expected_seq" min-seq)
          out-file (assoc "out_file" out-file)))

      "storage-list"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            m {"cmd" "storage-list"}]
        (cond-> m
          sub (assoc "subnet_id" sub)))

      "capability-publish"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            cap-id (or (extract-flag-value clean-tokens "--capability-id" nil)
                       (extract-flag-value clean-tokens "--cap-id" nil))
            cap-type (or (extract-flag-value clean-tokens "--capability-type" nil)
                         (extract-flag-value clean-tokens "--type" nil))
            cap-path (or (extract-flag-value clean-tokens "--capability-path" nil)
                         (extract-flag-value clean-tokens "--path" nil))
            cap-terms (or (extract-flag-value clean-tokens "--capability-terms" nil)
                          (extract-flag-value clean-tokens "--terms" nil))
            price (extract-long-flag clean-tokens "--price-echo"
                                     (extract-long-flag clean-tokens "--price" nil))
            burn-floor (extract-long-flag clean-tokens "--burn-floor" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            target-cid (extract-flag-value clean-tokens "--target-cid" nil)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            meta (extract-flag-value clean-tokens "--metadata" nil)
            m {"cmd" "capability-publish" "subnet_id" sub}]
        (cond-> m
          cap-id (assoc "capability_id" cap-id)
          cap-type (assoc "capability_type" cap-type)
          cap-path (assoc "capability_path" cap-path)
          cap-terms (assoc "capability_terms" cap-terms)
          price (assoc "price_echo" price)
          burn-floor (assoc "burn_floor" burn-floor)
          (some? b) (assoc "burn" b)
          target-cid (assoc "target_cid" target-cid)
          seq-num (assoc "seq" seq-num)
          meta (assoc "metadata" meta)))

      "capability-resolve"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            cap-id (or (extract-flag-value clean-tokens "--capability-id" nil)
                       (extract-flag-value clean-tokens "--cap-id" nil))
            auth (or (extract-flag-value clean-tokens "--authority" nil)
                     (extract-flag-value clean-tokens "--pubkey" nil))
            path (extract-flag-value clean-tokens "--path" nil)
            min-seq (or (extract-long-flag clean-tokens "--min-seq" nil)
                        (extract-long-flag clean-tokens "--min-expected-seq" nil))
            m {"cmd" "capability-resolve" "subnet_id" sub}]
        (cond-> m
          cap-id (assoc "capability_id" cap-id)
          auth (assoc "authority" auth)
          path (assoc "path" path)
          min-seq (assoc "min_seq" min-seq "min_expected_seq" min-seq)))

      "capability-list"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            cap-type (or (extract-flag-value clean-tokens "--capability-type" nil)
                         (extract-flag-value clean-tokens "--type" nil))
            auth (or (extract-flag-value clean-tokens "--authority" nil)
                     (extract-flag-value clean-tokens "--pubkey" nil))
            m {"cmd" "capability-list"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          cap-type (assoc "capability_type" cap-type)
          auth (assoc "authority" auth)))

      "puzzle-hash"
      (let [psrc (extract-flag-value clean-tokens "--puzzle-source" nil)
            m {"cmd" "puzzle-hash"}]
        (cond-> m
          psrc (assoc "puzzle_source" psrc)))

      "puzzle-eval"
      (let [psrc (extract-flag-value clean-tokens "--puzzle-source" nil)
            sol (extract-flag-value clean-tokens "--solution" nil)
            amt (extract-long-flag clean-tokens "--amount" nil)
            recv (or (extract-flag-value clean-tokens "--receiver" nil)
                     (extract-flag-value clean-tokens "--recipient" nil)
                     (extract-flag-value clean-tokens "--to" nil))
            payer (extract-flag-value clean-tokens "--payer" nil)
            dh (extract-flag-value clean-tokens "--deliverable-hash" nil)
            ph (extract-flag-value clean-tokens "--puzzle-hash" nil)
            to-ep (or (extract-long-flag clean-tokens "--timeout-epoch" nil)
                      (extract-long-flag clean-tokens "--expires-epoch" nil))
            ep (extract-long-flag clean-tokens "--epoch" nil)
            iid (or (extract-flag-value clean-tokens "--intent-id" nil)
                    (extract-flag-value clean-tokens "--escrow-id" nil))
            sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            m {"cmd" "puzzle-eval"}]
        (cond-> m
          psrc (assoc "puzzle_source" psrc)
          sol (assoc "solution" sol)
          amt (assoc "amount" amt)
          recv (assoc "receiver" recv)
          payer (assoc "payer" payer)
          dh (assoc "deliverable_hash" dh)
          ph (assoc "puzzle_hash" ph)
          to-ep (assoc "timeout_epoch" to-ep)
          ep (assoc "epoch" ep)
          iid (assoc "intent_id" iid)
          sub (assoc "subnet_id" sub)))

      "bip-submit"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            bip-id (extract-flag-value clean-tokens "--bip-id" nil)
            title (extract-flag-value clean-tokens "--title" nil)
            spec-edn (extract-flag-value clean-tokens "--spec-edn" nil)
            spec-file (extract-flag-value clean-tokens "--spec-file" nil)
            policy-edn (extract-flag-value clean-tokens "--policy-edn" nil)
            defspec-vars (extract-flag-value clean-tokens "--defspec-vars" nil)
            oracle-edn (extract-flag-value clean-tokens "--oracle-receipts-edn" nil)
            act-ep (extract-long-flag clean-tokens "--activate-at-epoch" nil)
            inv-diff (or (extract-flag-value clean-tokens "--invariant-diff-edn" nil)
                         (extract-flag-value clean-tokens "--invariant-diff" nil))
            juris-map (or (extract-flag-value clean-tokens "--jurisdiction-map" nil)
                          (extract-flag-value clean-tokens "--jurisdiction" nil))
            sunset (or (extract-long-flag clean-tokens "--human-anchor-sunset" nil)
                       (extract-long-flag clean-tokens "--sunset" nil))
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "bip-submit"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          bip-id (assoc "bip_id" bip-id)
          title (assoc "title" title)
          spec-edn (assoc "spec_edn" spec-edn)
          spec-file (assoc "spec_file" spec-file)
          policy-edn (assoc "policy_edn" policy-edn)
          defspec-vars (assoc "defspec_vars" defspec-vars)
          oracle-edn (assoc "oracle_receipts_edn" oracle-edn)
          (some? act-ep) (assoc "activate_at_epoch" act-ep)
          inv-diff (assoc "invariant-diff-edn" inv-diff "invariant_diff_edn" inv-diff)
          juris-map (assoc "jurisdiction-map" juris-map "jurisdiction_map" juris-map)
          (some? sunset) (assoc "human-anchor-sunset" sunset "human_anchor_sunset" sunset)
          (some? b) (assoc "burn" b)))

      "bip-consent"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            bip-id (extract-flag-value clean-tokens "--bip-id" nil)
            circle (extract-flag-value clean-tokens "--circle" nil)
            w (extract-long-flag clean-tokens "--weight" nil)
            comment-str (extract-flag-value clean-tokens "--comment" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "bip-consent"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          bip-id (assoc "bip_id" bip-id)
          circle (assoc "circle" circle)
          (some? w) (assoc "weight" w)
          comment-str (assoc "comment" comment-str)
          (some? b) (assoc "burn" b)))

      "bip-object"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            bip-id (extract-flag-value clean-tokens "--bip-id" nil)
            circle (extract-flag-value clean-tokens "--circle" nil)
            ce-edn (extract-flag-value clean-tokens "--counterexample-edn" nil)
            w (extract-long-flag clean-tokens "--weight" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "bip-object"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          bip-id (assoc "bip_id" bip-id)
          circle (assoc "circle" circle)
          ce-edn (assoc "counterexample_edn" ce-edn)
          (some? w) (assoc "weight" w)
          (some? b) (assoc "burn" b)))

      "bip-status"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            bip-id (extract-flag-value clean-tokens "--bip-id" nil)
            m {"cmd" "bip-status"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          bip-id (assoc "bip_id" bip-id)))

      "bounties"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            st (extract-flag-value clean-tokens "--status" nil)
            m {"cmd" "bounties"}]
        (cond-> m
          sub (assoc "subnet_id" sub "subnet-id" sub)
          st (assoc "status" st)))

      "bounty-create"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            bounty-id (extract-flag-value clean-tokens "--bounty-id" nil)
            target-cid (or (extract-flag-value clean-tokens "--bip-cid" nil)
                           (extract-flag-value clean-tokens "--target-bip-cid" nil)
                           (extract-flag-value clean-tokens "--bip-id" nil))
            gross (or (extract-long-flag clean-tokens "--gross-amount" nil)
                      (extract-long-flag clean-tokens "--amount" nil))
            m-pub (extract-flag-value clean-tokens "--maintainer-pubkey" nil)
            take-bps (extract-long-flag clean-tokens "--take-bps" nil)
            builder-bps (extract-long-flag clean-tokens "--builder-bps" nil)
            auditor-bps (extract-long-flag clean-tokens "--auditor-bps" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "bounty-create"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          bounty-id (assoc "bounty_id" bounty-id)
          target-cid (assoc "target_bip_cid" target-cid "bip_id" target-cid "bip-cid" target-cid "bip_cid" target-cid)
          (some? gross) (assoc "gross_amount" gross "amount" gross)
          m-pub (assoc "maintainer_pubkey" m-pub)
          (some? take-bps) (assoc "take_bps" take-bps)
          (some? builder-bps) (assoc "builder_bps" builder-bps)
          (some? auditor-bps) (assoc "auditor_bps" auditor-bps)
          (some? b) (assoc "burn" b)))

      "bounty-settle"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            bounty-id (extract-flag-value clean-tokens "--bounty-id" nil)
            claim-edn (extract-flag-value clean-tokens "--claim-edn" nil)
            claim-file (extract-flag-value clean-tokens "--claim-file" nil)
            builder (extract-flag-value clean-tokens "--builder" nil)
            auditor (extract-flag-value clean-tokens "--auditor" nil)
            patch-cid (extract-flag-value clean-tokens "--patch-cid" nil)
            sha256 (extract-flag-value clean-tokens "--sha256" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            m {"cmd" "bounty-settle"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          bounty-id (assoc "bounty_id" bounty-id)
          claim-edn (assoc "claim_edn" claim-edn)
          claim-file (assoc "claim_file" claim-file)
          builder (assoc "builder" builder)
          auditor (assoc "auditor" auditor)
          patch-cid (assoc "patch_cid" patch-cid)
          sha256 (assoc "sha256" sha256)
          (some? b) (assoc "burn" b)))

      "artifact-put-chunked"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            path (extract-flag-value clean-tokens "--path" nil)
            file (extract-flag-value clean-tokens "--file" nil)
            chunk-size (extract-long-flag clean-tokens "--chunk-size" nil)
            concurrency (extract-long-flag clean-tokens "--concurrency" nil)
            grace-epochs (extract-long-flag clean-tokens "--grace-epochs" nil)
            max-bytes (extract-long-flag clean-tokens "--max-bytes" nil)
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            owner-pk (extract-flag-value clean-tokens "--owner-pubkey" nil)
            m {"cmd" "artifact-put-chunked" "subnet_id" sub}]
        (-> (cond-> m
              path (assoc "path" path)
              file (assoc "file" file)
              chunk-size (assoc "chunk_size" chunk-size)
              concurrency (assoc "concurrency" concurrency)
              grace-epochs (assoc "grace_epochs" grace-epochs)
              max-bytes (assoc "max_bytes" max-bytes)
              relay-url (assoc "relay_url" relay-url)
              owner-pk (assoc "owner_pubkey" owner-pk))
            (assoc-relay-pool-flags clean-tokens)))

      "artifact-get-chunked"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            cid (extract-flag-value clean-tokens "--cid" nil)
            path (extract-flag-value clean-tokens "--path" nil)
            out-file (or (extract-flag-value clean-tokens "--out" nil)
                         (extract-flag-value clean-tokens "--out-file" nil)
                         (extract-flag-value clean-tokens "--file" nil))
            chunk-size (extract-long-flag clean-tokens "--chunk-size" nil)
            concurrency (extract-long-flag clean-tokens "--concurrency" nil)
            resume-dir (extract-flag-value clean-tokens "--resume-dir" nil)
            max-bytes (extract-long-flag clean-tokens "--max-bytes" nil)
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            m {"cmd" "artifact-get-chunked" "subnet_id" sub}]
        (-> (cond-> m
              cid (assoc "cid" cid)
              path (assoc "path" path)
              out-file (assoc "out_file" out-file)
              chunk-size (assoc "chunk_size" chunk-size)
              concurrency (assoc "concurrency" concurrency)
              resume-dir (assoc "resume_dir" resume-dir)
              max-bytes (assoc "max_bytes" max-bytes)
              relay-url (assoc "relay_url" relay-url))
            (assoc-relay-pool-flags clean-tokens)))

      "artifact-manifest-verify"
      (let [cid (extract-flag-value clean-tokens "--cid" nil)
            file (extract-flag-value clean-tokens "--file" nil)
            owner-pk (extract-flag-value clean-tokens "--owner-pubkey" nil)
            max-bytes (extract-long-flag clean-tokens "--max-bytes" nil)
            grace-epochs (extract-long-flag clean-tokens "--grace-epochs" nil)
            m {"cmd" "artifact-manifest-verify"}]
        (cond-> m
          cid (assoc "cid" cid)
          file (assoc "file" file)
          owner-pk (assoc "owner_pubkey" owner-pk)
          max-bytes (assoc "max_bytes" max-bytes)
          grace-epochs (assoc "grace_epochs" grace-epochs)))

      "web-release-publish"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "bitecho.org/infra")
            file (extract-flag-value clean-tokens "--file" nil)
            release-cid (extract-flag-value clean-tokens "--release-cid" nil)
            genesis-cid (extract-flag-value clean-tokens "--genesis-anchor-cid" nil)
            lkg-cid (extract-flag-value clean-tokens "--lkg-release-cid" nil)
            headers-cid (extract-flag-value clean-tokens "--headers-config-cid" nil)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            max-bytes (extract-long-flag clean-tokens "--max-bytes" nil)
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            m {"cmd" "web-release-publish" "subnet_id" sub}]
        (cond-> m
          file (assoc "file" file)
          release-cid (assoc "release_cid" release-cid)
          genesis-cid (assoc "genesis_anchor_cid" genesis-cid)
          lkg-cid (assoc "lkg_release_cid" lkg-cid)
          headers-cid (assoc "headers_config_cid" headers-cid)
          seq-num (assoc "seq" seq-num)
          max-bytes (assoc "max_bytes" max-bytes)
          relay-url (assoc "relay_url" relay-url)))

      "web-release-rollback"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "bitecho.org/infra")
            file (extract-flag-value clean-tokens "--file" nil)
            release-cid (extract-flag-value clean-tokens "--release-cid" nil)
            genesis-cid (extract-flag-value clean-tokens "--genesis-anchor-cid" nil)
            lkg-cid (extract-flag-value clean-tokens "--lkg-release-cid" nil)
            headers-cid (extract-flag-value clean-tokens "--headers-config-cid" nil)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            m {"cmd" "web-release-rollback" "subnet_id" sub}]
        (cond-> m
          file (assoc "file" file)
          release-cid (assoc "release_cid" release-cid)
          genesis-cid (assoc "genesis_anchor_cid" genesis-cid)
          lkg-cid (assoc "lkg_release_cid" lkg-cid)
          headers-cid (assoc "headers_config_cid" headers-cid)
          seq-num (assoc "seq" seq-num)
          relay-url (assoc "relay_url" relay-url)))

      "web-release-verify"
      (let [file (extract-flag-value clean-tokens "--file" nil)
            release-cid (extract-flag-value clean-tokens "--release-cid" nil)
            genesis-cid (extract-flag-value clean-tokens "--genesis-anchor-cid" nil)
            lkg-cid (extract-flag-value clean-tokens "--lkg-release-cid" nil)
            headers-cid (extract-flag-value clean-tokens "--headers-config-cid" nil)
            max-bytes (extract-long-flag clean-tokens "--max-bytes" nil)
            m {"cmd" "web-release-verify"}]
        (cond-> m
          file (assoc "file" file)
          release-cid (assoc "release_cid" release-cid)
          genesis-cid (assoc "genesis_anchor_cid" genesis-cid)
          lkg-cid (assoc "lkg_release_cid" lkg-cid)
          headers-cid (assoc "headers_config_cid" headers-cid)
          max-bytes (assoc "max_bytes" max-bytes)))

      "artifact-put"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            path (extract-flag-value clean-tokens "--path" nil)
            file (extract-flag-value clean-tokens "--file" nil)
            text (or (extract-flag-value clean-tokens "--text" nil)
                     (extract-flag-value clean-tokens "--data" nil))
            hex (or (extract-flag-value clean-tokens "--hex" nil)
                    (extract-flag-value clean-tokens "--data-hex" nil))
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            auth (or (extract-flag-value clean-tokens "--authority" nil)
                     (extract-flag-value clean-tokens "--pubkey" nil))
            cid (extract-flag-value clean-tokens "--cid" nil)
            m {"cmd" "artifact-put" "subnet_id" sub}]
        (-> (cond-> m
              path (assoc "path" path)
              file (assoc "file" file)
              text (assoc "text" text "data" text)
              hex (assoc "hex" hex "data_hex" hex)
              seq-num (assoc "seq" seq-num)
              (some? b) (assoc "burn" b)
              relay-url (assoc "relay_url" relay-url)
              auth (assoc "authority" auth)
              cid (assoc "cid" cid))
            (assoc-relay-pool-flags clean-tokens)))

      "artifact-get"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            path (extract-flag-value clean-tokens "--path" nil)
            cid (extract-flag-value clean-tokens "--cid" nil)
            auth (or (extract-flag-value clean-tokens "--authority" nil)
                     (extract-flag-value clean-tokens "--pubkey" nil))
            out-file (or (extract-flag-value clean-tokens "--out" nil)
                         (extract-flag-value clean-tokens "--out-file" nil)
                         (extract-flag-value clean-tokens "--file" nil))
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            m {"cmd" "artifact-get" "subnet_id" sub}]
        (-> (cond-> m
              path (assoc "path" path)
              cid (assoc "cid" cid)
              auth (assoc "authority" auth)
              out-file (assoc "out_file" out-file)
              relay-url (assoc "relay_url" relay-url))
            (assoc-relay-pool-flags clean-tokens)))

      "artifact-list"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            prefix (or (extract-flag-value clean-tokens "--prefix" nil)
                       (extract-flag-value clean-tokens "--path" nil))
            auth (or (extract-flag-value clean-tokens "--authority" nil)
                     (extract-flag-value clean-tokens "--pubkey" nil))
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            m {"cmd" "artifact-list"}]
        (cond-> m
          sub (assoc "subnet_id" sub)
          prefix (assoc "prefix" prefix "path" prefix)
          auth (assoc "authority" auth)
          relay-url (assoc "relay_url" relay-url)))

      "artifact-revoke"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "global")
            path (extract-flag-value clean-tokens "--path" nil)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            b (extract-long-flag clean-tokens "--burn" nil)
            relay-url (extract-flag-value clean-tokens "--relay-url" nil)
            auth (or (extract-flag-value clean-tokens "--authority" nil)
                     (extract-flag-value clean-tokens "--pubkey" nil))
            m {"cmd" "artifact-revoke" "subnet_id" sub}]
        (cond-> m
          path (assoc "path" path)
          seq-num (assoc "seq" seq-num)
          (some? b) (assoc "burn" b)
          relay-url (assoc "relay_url" relay-url)
          auth (assoc "authority" auth)))

      ;; -----------------------------------------------------------------------
      ;; Canonical 12 Verbs Flag-Driven Desugaring (BIP-005 / Milestone D31)
      ;; -----------------------------------------------------------------------
      "put"
      (let [domain-verb
            (cond
              (and (has-flag? clean-tokens "--bip-id")
                   (has-flag? clean-tokens "--circle")
                   (has-flag? clean-tokens "--counterexample-edn"))
              "bip-object"

              (and (has-flag? clean-tokens "--bip-id")
                   (has-flag? clean-tokens "--circle"))
              "bip-consent"

              (has-flag? clean-tokens "--bip-id")
              "bip-submit"

              (or (has-flag? clean-tokens "--capability-id")
                  (has-flag? clean-tokens "--cap-id"))
              "capability-publish"

              (or (has-flag? clean-tokens "--slot-id")
                  (has-flag? clean-tokens "--slot"))
              "storage-put"

              (and (has-flag? clean-tokens "--petname")
                   (has-flag? clean-tokens "--remove"))
              "petname-remove"

              (has-flag? clean-tokens "--petname")
              "petname-set"

              (or (has-flag? clean-tokens "--nickname")
                  (has-flag? clean-tokens "--name"))
              "directory-register"

              (or (has-flag? clean-tokens "--child-subnet")
                  (has-flag? clean-tokens "--parent-subnet")
                  (has-flag? clean-tokens "--child-epoch"))
              "anchor-subnet"

              (or (has-flag? clean-tokens "--tombstone")
                  (has-flag? clean-tokens "--revoke"))
              "artifact-revoke"

              :else
              "artifact-put")]
        (assoc (build-cmd-map domain-verb clean-tokens) "canonical_cmd" "put"))

      "get"
      (let [domain-verb
            (cond
              (has-flag? clean-tokens "--bip-id")
              "bip-status"

              (or (has-flag? clean-tokens "--capability-id")
                  (has-flag? clean-tokens "--cap-id"))
              "capability-resolve"

              (or (has-flag? clean-tokens "--slot-id")
                  (has-flag? clean-tokens "--slot"))
              "storage-get"

              (has-flag? clean-tokens "--petname")
              "petname-resolve"

              (and (or (has-flag? clean-tokens "--nickname")
                       (has-flag? clean-tokens "--name"))
                   (has-flag? clean-tokens "--verify"))
              "directory-verify"

              (or (has-flag? clean-tokens "--nickname")
                  (has-flag? clean-tokens "--name"))
              "directory-lookup"

              (or (has-flag? clean-tokens "--child-subnet")
                  (has-flag? clean-tokens "--parent-subnet"))
              "verify-subnet-anchor"

              (or (has-flag? clean-tokens "--path")
                  (has-flag? clean-tokens "--cid"))
              "artifact-get"

              (or (has-flag? clean-tokens "--sync")
                  (has-flag? clean-tokens "--balance")
                  (has-flag? clean-tokens "--account"))
              "account"

              (has-flag? clean-tokens "--identity")
              "identity"

              (has-flag? clean-tokens "--chain-state")
              "query-chain-state"

              :else
              "status")]
        (assoc (build-cmd-map domain-verb clean-tokens) "canonical_cmd" "get"))

      "list"
      (let [domain-verb
            (cond
              (or (has-flag? clean-tokens "--subnets")
                  (has-flag? clean-tokens "--subscribe-subnets"))
              "subscribe-subnets"

              (or (has-flag? clean-tokens "--capability-type")
                  (has-flag? clean-tokens "--capabilities"))
              "capability-list"

              (has-flag? clean-tokens "--bounties")
              "bounties"

              (has-flag? clean-tokens "--escrows")
              "escrows"

              (has-flag? clean-tokens "--petnames")
              "petname-list"

              (has-flag? clean-tokens "--slots")
              "storage-list"

              (has-flag? clean-tokens "--discover")
              "discover"

              :else
              "artifact-list")]
        (assoc (build-cmd-map domain-verb clean-tokens) "canonical_cmd" "list"))

      "lock"
      (let [domain-verb (if (has-flag? clean-tokens "--bounty-id")
                          "bounty-create"
                          "lock-intent")]
        (assoc (build-cmd-map domain-verb clean-tokens) "canonical_cmd" "lock"))

      "spend"
      (let [domain-verb
            (cond
              (has-flag? clean-tokens "--bounty-id")
              "bounty-settle"

              (has-flag? clean-tokens "--refund")
              "refund-intent"

              (has-flag? clean-tokens "--eval-only")
              "puzzle-eval"

              (has-flag? clean-tokens "--hash-only")
              "puzzle-hash"

              (has-flag? clean-tokens "--vouchers")
              "submit-vouchers"

              (or (has-flag? clean-tokens "--escrow-id")
                  (has-flag? clean-tokens "--intent-id")
                  (has-flag? clean-tokens "--preimage")
                  (has-flag? clean-tokens "--solution"))
              "release-intent"

              :else
              "settle-intent")]
        (assoc (build-cmd-map domain-verb clean-tokens) "canonical_cmd" "spend"))

      "connect"
      (let [domain-verb
            (cond
              (has-flag? clean-tokens "--connected")
              "p2p-channel-state"

              (and (or (has-flag? clean-tokens "--candidates")
                       (has-flag? clean-tokens "--endpoint"))
                   (has-flag? clean-tokens "--answer"))
              "p2p-answer"

              (or (has-flag? clean-tokens "--candidates")
                  (has-flag? clean-tokens "--endpoint"))
              "p2p-offer"

              (has-flag? clean-tokens "--close")
              "close"

              (or (has-flag? clean-tokens "--session-id")
                  (has-flag? clean-tokens "--session"))
              "accept"

              (has-flag? clean-tokens "--nodes")
              "register-home-set"

              (has-flag? clean-tokens "--offer-hash")
              "rendezvous-accept"

              (or (has-flag? clean-tokens "--allowlist")
                  (has-flag? clean-tokens "--min-burn")
                  (has-flag? clean-tokens "--auto-accept"))
              "rendezvous-policy"

              (has-flag? clean-tokens "--topic")
              "rendezvous-offer"

              (has-flag? clean-tokens "--offline")
              "export-offer"

              :else
              "offer")]
        (assoc (build-cmd-map domain-verb clean-tokens) "canonical_cmd" "connect"))

      "serve"
      {"cmd" "serve" "canonical_cmd" "serve"}

      "ctl"
      {"cmd" "ctl" "canonical_cmd" "ctl"}

      "daemon"
      {"cmd" "daemon" "canonical_cmd" "serve"}

      "wait-event"
      (assoc (build-cmd-map "wait" clean-tokens) "canonical_cmd" "wait")

      {"cmd" verb})))

(defn desugar-cli-cmd-map
  "Pure desugaring transformation (`F-U1`): maps any command map (using one of the 12
   canonical verbs, 68 legacy verbs, or 8 runner aliases) to a normalized command map
   containing both `\"cmd\"` (domain handler verb) and `\"canonical_cmd\"` (1-of-12 canonical verb)."
  [cmd-map]
  (let [m (into {} (map (fn [[k v]] [(if (keyword? k) (name k) (str k)) v]) (or cmd-map {})))
        raw-verb (str/lower-case (str/trim (str (or (get m "cmd") (get m "verb") "status"))))
        legacy-entry (get legacy-verb-desugar-table raw-verb)
        runner-entry (get runner-alias-desugar-table raw-verb)
        memento-entry (get memento-verb-desugar-table raw-verb)
        chunked-entry (get chunked-artifact-verb-desugar-table raw-verb)
        web-release-entry (get web-release-verb-desugar-table raw-verb)]
    (cond
      (some? (get m "canonical_cmd"))
      m

      legacy-entry
      (assoc m
             "cmd" (:domain-cmd legacy-entry)
             "canonical_cmd" (:canonical legacy-entry))

      runner-entry
      (assoc m
             "cmd" (:domain-cmd runner-entry)
             "canonical_cmd" (:canonical runner-entry))

      memento-entry
      (assoc m
             "cmd" (:domain-cmd memento-entry)
             "canonical_cmd" (:canonical memento-entry))

      chunked-entry
      (assoc m
             "cmd" (:domain-cmd chunked-entry)
             "canonical_cmd" (:canonical chunked-entry))

      web-release-entry
      (assoc m
             "cmd" (:domain-cmd web-release-entry)
             "canonical_cmd" (:canonical web-release-entry))

      (contains? canonical-cli-verbs-set raw-verb)
      (let [inferred-domain
            (case raw-verb
              "put"      (cond
                           (and (get m "bip_id") (get m "circle") (get m "counterexample_edn")) "bip-object"
                           (and (get m "bip_id") (get m "circle")) "bip-consent"
                           (get m "bip_id") "bip-submit"
                           (get m "capability_id") "capability-publish"
                           (or (get m "slot") (get m "slot_id")) "storage-put"
                           (and (get m "petname") (get m "remove")) "petname-remove"
                           (get m "petname") "petname-set"
                           (or (get m "nickname") (get m "name")) "directory-register"
                           (get m "parent_subnet") "anchor-subnet"
                           (or (get m "tombstone") (get m "revoke")) "artifact-revoke"
                           :else "artifact-put")
              "get"      (cond
                           (get m "bip_id") "bip-status"
                           (get m "capability_id") "capability-resolve"
                           (or (get m "slot") (get m "slot_id")) "storage-get"
                           (get m "petname") "petname-resolve"
                           (and (or (get m "nickname") (get m "name")) (get m "verify")) "directory-verify"
                           (or (get m "nickname") (get m "name")) "directory-lookup"
                           (get m "parent_subnet") "verify-subnet-anchor"
                           (or (get m "path") (get m "cid")) "artifact-get"
                           (or (get m "sync") (get m "balance")) "account"
                           (get m "identity") "identity"
                           :else "status")
              "list"     (cond
                           (get m "subnets") "subscribe-subnets"
                           (get m "capability_type") "capability-list"
                           (get m "bounties") "bounties"
                           (get m "escrows") "escrows"
                           (get m "petnames") "petname-list"
                           (get m "slots") "storage-list"
                           :else "artifact-list")
              "lock"     (if (get m "bounty_id") "bounty-create" "lock-intent")
              "spend"    (cond
                           (get m "bounty_id") "bounty-settle"
                           (get m "refund") "refund-intent"
                           (get m "eval_only") "puzzle-eval"
                           (get m "hash_only") "puzzle-hash"
                           (or (get m "escrow_id") (get m "intent_id")) "release-intent"
                           :else "settle-intent")
              "connect"  (cond
                           (some? (get m "connected")) "p2p-channel-state"
                           (and (get m "candidates") (get m "answer")) "p2p-answer"
                           (get m "candidates") "p2p-offer"
                           (get m "close") "close"
                           (get m "session_id") "accept"
                           (get m "home_nodes") "register-home-set"
                           (get m "offer_hash") "rendezvous-accept"
                           (or (get m "allowlist") (get m "min_burn")) "rendezvous-policy"
                           :else "offer")
              "send"     (cond
                           (get m "retransmit") "retransmit-outbox"
                           (get m "offline") "export-send"
                           (and (get m "subnet_id") (not (get m "to")) (not (get m "session_id"))) "broadcast"
                           :else "send")
              "inbox"    (cond
                           (get m "hex") "import"
                           (get m "file_content") "import-poll"
                           (get m "up_to_seq") "ack"
                           (get m "since_seq") "export-poll"
                           :else "inbox")
              "transfer" "transfer"
              "wait"     "wait"
              "serve"    "serve"
              "ctl"      "ctl"
              raw-verb)]
        (assoc m
               "cmd" inferred-domain
               "canonical_cmd" raw-verb))

      :else
      (assoc m "canonical_cmd" raw-verb))))

;; =============================================================================
;; 5. Pure CLI Command Parser (Entry Point)
;; =============================================================================

(defn parse-cli-command
  "Parses a CLI command from string, vector of token strings, or map.
   Returns {:ok? true :verb ... :cmd ... :args [...] :opts {...} :cmd-map {...}}
   or {:ok? false :error :invalid-verb :verb ... :supported-verbs supported-cli-verbs} (Rule 5 & 6)."
  [input]
  (cond
    (map? input)
    (let [verb (str (or (get input "cmd") (:cmd input) (get input "verb") (:verb input)))
          verb (if (str/blank? verb) "status" (str/lower-case (str/trim verb)))]
      (if (all-recognized-cli-verbs-set verb)
        (let [str-map (into {} (map (fn [[k v]] [(if (keyword? k) (name k) (str k)) v]) input))
              cmd-map (assoc str-map "cmd" verb)]
          {:ok? true
           :verb verb
           :cmd verb
           :args []
           :opts (dissoc str-map "cmd")
           :cmd-map cmd-map})
        {:ok? false
         :error :invalid-verb
         :verb verb
         :supported-verbs supported-cli-verbs}))

    (or (string? input) (vector? input) (sequential? input))
    (let [tokens (if (string? input)
                   (tokenize-cli-string input)
                   (vec (map str input)))]
      (if (empty? tokens)
        {:ok? true
         :verb "status"
         :cmd "status"
         :args []
         :opts {}
         :cmd-map {"cmd" "status"}}
        (let [first-tok (str/lower-case (first tokens))
              verb (if (str/starts-with? first-tok "--")
                     ;; Check if verb follows flags, or default to status
                     (let [non-flag (first (remove #(str/starts-with? % "--") tokens))]
                       (if non-flag (str/lower-case non-flag) "status"))
                     first-tok)]
          (if (all-recognized-cli-verbs-set verb)
            (let [subargs (if (= first-tok verb) (vec (rest tokens)) tokens)
                  {:keys [opts args]} (parse-tokens-into-opts-and-args subargs)
                  cmd-map (build-cmd-map verb tokens)]
              {:ok? true
               :verb verb
               :cmd verb
               :args args
               :opts opts
               :cmd-map cmd-map})
            {:ok? false
             :error :invalid-verb
             :verb verb
             :supported-verbs supported-cli-verbs}))))

    :else
    {:ok? false
     :error :invalid-input
     :supported-verbs supported-cli-verbs}))
