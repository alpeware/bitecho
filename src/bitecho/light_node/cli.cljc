(ns bitecho.light-node.cli
  "Shared pure Sans-IO CLI parser and verb inventory for Bitecho light-node and browser shells.
   Provides canonical verb list, pure string tokenizer, and structured command parser conforming
   to Rules 1, 2, 5, and 6."
  (:require [clojure.string :as str]))

;; =============================================================================
;; 1. Canonical Supported CLI Verbs Inventory (Rule 6)
;; =============================================================================

(def supported-cli-verbs
  "Canonical sorted vector of all 55 supported CLI verbs across Bitecho shells."
  ["accept"
   "account"
   "ack"
   "anchor-subnet"
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
   "sync-account"
   "transfer"
   "verify-subnet-anchor"
   "wait"])

(def supported-cli-verbs-set
  "Set of all canonical CLI verbs for O(1) membership check."
  (set supported-cli-verbs))

;; =============================================================================
;; 2. Pure CLI Tokenizer (Rule 2)
;; =============================================================================

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

(defn- extract-flag-value
  [tokens flag default-val]
  (loop [toks tokens]
    (if (empty? toks)
      default-val
      (if (= (first toks) flag)
        (if (and (seq (rest toks)) (not (str/starts-with? (second toks) "--")))
          (second toks)
          default-val)
        (recur (rest toks))))))

(defn- extract-long-flag
  [tokens flag default-val]
  (if-let [v (extract-flag-value tokens flag nil)]
    (try
      #?(:clj (Long/parseLong (str v))
         :cljs (let [n (js/parseInt (str v) 10)]
                 (if (js/isNaN n) default-val n)))
      (catch #?(:clj Exception :cljs :default) _ default-val))
    default-val))

(defn- has-flag?
  [tokens flag]
  (boolean (some #{flag} tokens)))

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
      "status"   {"cmd" "status"}
      "identity" {"cmd" "identity"}
      "discover" {"cmd" "discover"}
      "inbox"    {"cmd" "inbox"}

      "offer"
      (let [callee (or (extract-flag-value clean-tokens "--callee" nil)
                       (extract-flag-value clean-tokens "--to" nil))
            price (extract-long-flag clean-tokens "--price" 0)
            burn (extract-long-flag clean-tokens "--burn" 500)
            hn (extract-flag-value clean-tokens "--home-node" nil)
            m {"cmd" "offer" "callee" callee "price" price "burn" burn}]
        (cond-> m
          callee (assoc "to" callee)
          hn (assoc "home_node" hn)))

      "accept"
      {"cmd" "accept"
       "session_id" (or (extract-flag-value clean-tokens "--session-id" nil)
                        (extract-flag-value clean-tokens "--session" nil))}

      "close"
      {"cmd" "close"
       "session_id" (or (extract-flag-value clean-tokens "--session-id" nil)
                        (extract-flag-value clean-tokens "--session" nil))}

      "send"
      (let [to (or (extract-flag-value clean-tokens "--to" nil)
                   (extract-flag-value clean-tokens "--peer" nil))
            sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil)
                    to)
            msg (or (extract-flag-value clean-tokens "--message" nil)
                    (extract-flag-value clean-tokens "--text" nil))
            hex (extract-flag-value clean-tokens "--payload-hex" nil)
            burn (extract-long-flag clean-tokens "--burn" 500)
            m {"cmd" "send" "session_id" sid "burn" burn}]
        (cond-> m
          to (assoc "to" to)
          msg (assoc "text" msg "message" msg)
          hex (assoc "payload_hex" hex)))

      "transfer"
      (let [recv (or (extract-flag-value clean-tokens "--receiver" nil)
                     (extract-flag-value clean-tokens "--recipient" nil)
                     (extract-flag-value clean-tokens "--to" nil))
            amt (extract-long-flag clean-tokens "--amount" 0)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            burn (extract-long-flag clean-tokens "--burn" 500)
            m {"cmd" "transfer" "receiver" recv "recipient" recv "amount" amt "burn" burn}]
        (cond-> m
          seq-num (assoc "seq" seq-num)))

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
        {"cmd" "settle-intent" "receiver" recv "recipient" recv "amount" amt})

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
      (let [t (extract-flag-value clean-tokens "--text" nil)
            sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil))
            m {"cmd" "broadcast"}]
        (cond-> m
          t (assoc "text" t)
          sub (assoc "subnet_id" sub)))

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
            topic (extract-flag-value clean-tokens "--topic" nil)
            hn (extract-flag-value clean-tokens "--home-node" nil)
            text (extract-flag-value clean-tokens "--text" nil)
            m {"cmd" "rendezvous-offer" "callee" callee}]
        (cond-> m
          burn (assoc "burn" burn)
          topic (assoc "topic" topic)
          hn (assoc "home_node" hn)
          text (assoc "text" text)))

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
            cands (extract-flag-value clean-tokens "--candidates" nil)
            tr (extract-flag-value clean-tokens "--transport" nil)
            m {"cmd" "p2p-offer"}]
        (cond-> m
          sid (assoc "session_id" sid)
          cands (assoc "candidates" (vec (remove str/blank? (map str/trim (str/split cands #",")))))
          tr (assoc "transport" tr)))

      "p2p-answer"
      (let [sid (or (extract-flag-value clean-tokens "--session-id" nil)
                    (extract-flag-value clean-tokens "--session" nil))
            cands (extract-flag-value clean-tokens "--candidates" nil)
            tr (extract-flag-value clean-tokens "--transport" nil)
            m {"cmd" "p2p-answer"}]
        (cond-> m
          sid (assoc "session_id" sid)
          cands (assoc "candidates" (vec (remove str/blank? (map str/trim (str/split cands #",")))))
          tr (assoc "transport" tr)))

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
      (let [nick (extract-flag-value clean-tokens "--nickname" nil)
            dom (extract-flag-value clean-tokens "--domain" nil)
            pk (extract-flag-value clean-tokens "--directory-pubkey" nil)
            m {"cmd" "directory-verify"}]
        (cond-> m
          nick (assoc "nickname" nick)
          dom (assoc "domain" dom)
          pk (assoc "directory_pubkey" pk)))

      "directory-register"
      (let [nick (extract-flag-value clean-tokens "--nickname" nil)
            dom (extract-flag-value clean-tokens "--domain" nil)
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
      (let [nick (extract-flag-value clean-tokens "--nickname" nil)
            dom (extract-flag-value clean-tokens "--domain" nil)
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
            block? (or (has-flag? clean-tokens "--block")
                       (has-flag? clean-tokens "--until-event"))
            m {"cmd" "wait" "timeout_ms" (or t 30000)}]
        (cond-> m
          ms (assoc "min_seq" ms)
          block? (assoc "block" true)))

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
            m {"cmd" "export-poll"}]
        (cond-> m
          mseq (assoc "since_seq" mseq)
          bseq (assoc "since_broadcast_seq" bseq)))

      "import-poll"
      (let [payload (or (extract-flag-value clean-tokens "--json" nil)
                        (extract-flag-value clean-tokens "--payload" nil)
                        (extract-flag-value clean-tokens "--file" nil))]
        {"cmd" "import-poll" "file_content" (or payload "")})

      "import"
      (let [h (or (extract-flag-value clean-tokens "--hex" nil)
                  (extract-flag-value clean-tokens "--file" nil))]
        {"cmd" "import" "hex" (or h "")})

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
            m {"cmd" "export-ack"}]
        (cond-> m
          s (assoc "up_to_seq" s "ack_seq" s)
          bs (assoc "up_to_broadcast_seq" bs "ack_broadcast_seq" bs)
          to (assoc "to" to "session_id" to)))

      "storage-put"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "nexus")
            slot (or (extract-flag-value clean-tokens "--slot-id" nil)
                     (extract-flag-value clean-tokens "--slot" nil)
                     "default")
            data (extract-flag-value clean-tokens "--data" nil)
            data-hex (extract-flag-value clean-tokens "--data-hex" nil)
            seq-num (extract-long-flag clean-tokens "--seq" nil)
            min-seq (extract-long-flag clean-tokens "--min-seq" nil)
            out-file (extract-flag-value clean-tokens "--out-file" nil)
            m {"cmd" "storage-put" "subnet_id" sub "slot" slot "slot_id" slot}]
        (cond-> m
          data (assoc "data" data)
          data-hex (assoc "data_hex" data-hex)
          seq-num (assoc "seq" seq-num)
          min-seq (assoc "min_seq" min-seq)
          out-file (assoc "out_file" out-file)))

      "storage-get"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "nexus")
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
                    "nexus")
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
          target-cid (assoc "target_cid" target-cid)
          seq-num (assoc "seq" seq-num)
          meta (assoc "metadata" meta)))

      "capability-resolve"
      (let [sub (or (extract-flag-value clean-tokens "--subnet-id" nil)
                    (extract-flag-value clean-tokens "--subnet" nil)
                    "nexus")
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

      {"cmd" verb})))

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
      (if (supported-cli-verbs-set verb)
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
          (if (supported-cli-verbs-set verb)
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
