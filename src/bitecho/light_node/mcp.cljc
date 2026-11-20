(ns bitecho.light-node.mcp
  "Pure Sans-IO Model Context Protocol (MCP) JSON-RPC 2.0 Server Reducer (BIP-006 Part 1 / v0.23.10).
   Exposes 8 curated Bitecho tools + 1 `bitecho_ctl` escape-hatch tool and maps them
   deterministically to normalized `bitecho.light-node.core/handle-command` command maps.
   100% pure `.cljc` portable across JVM and Node.js (AGENTS.md Rule 2)."
  (:require [bitecho.light-node.cli :as cli]
            [clojure.string :as str]))

(def mcp-protocol-version
  "Supported MCP JSON-RPC protocol version."
  "2024-11-05")

(def mcp-server-info
  "MCP server identification metadata."
  {"name" "bitecho-mcp"
   "version" "0.23.16"})

(def curated-mcp-tools
  "Vector of the 9 MCP tool descriptors (8 curated + 1 escape hatch) per BIP-006 Part 1."
  [{"name" "bitecho_identity"
    "description" "Inspect local Ed25519 pubkey, Bech32m address, $ECHO balance/spendable, home-set, DAC status, or register home-set validators."
    "inputSchema" {"type" "object"
                   "properties" {"action" {"type" "string"
                                           "enum" ["status" "identity" "account" "register_home_set"]
                                           "description" "Identity action to perform (default: status)."}
                                 "nodes" {"type" "array"
                                          "items" {"type" "string"}
                                          "description" "Home-set validator node IDs when action is register_home_set."}
                                 "price" {"type" "integer"
                                          "description" "Home-set signaling price in ECH (default: 10)."}
                                 "sync" {"type" "boolean"
                                         "description" "Whether to sync chain-state quorum before returning balance."}}}}
   {"name" "bitecho_discover"
    "description" "Discover peers, look up directory handles (e.g. axiom, nexus, lumen), or list/resolve on-network capabilities."
    "inputSchema" {"type" "object"
                   "properties" {"nickname" {"type" "string"
                                             "description" "Directory handle / nickname to look up."}
                                 "query" {"type" "string"
                                          "description" "Alias for nickname or discovery query."}
                                 "domain" {"type" "string"
                                           "description" "Directory domain (default: bitecho.org)."}
                                 "capability_id" {"type" "string"
                                                  "description" "Specific capability ID to resolve."}
                                 "capability_type" {"type" "string"
                                                    "description" "Capability type filter for listing capabilities."}
                                 "subnet_id" {"type" "string"
                                              "description" "Target subnet ID."}}}}
   {"name" "bitecho_connect"
    "description" "Open or accept an E2EE 1:1 channel, upgrade/answer a P2P WebRTC/relay leg, or close a session."
    "inputSchema" {"type" "object"
                   "properties" {"action" {"type" "string"
                                           "enum" ["offer" "accept" "p2p_offer" "p2p_answer" "rendezvous_offer" "rendezvous_accept" "close"]
                                           "description" "Connection lifecycle action (default: offer)."}
                                 "peer" {"type" "string"
                                         "description" "Target peer petname or Ed25519 pubkey hex."}
                                 "callee" {"type" "string"
                                           "description" "Alias for peer."}
                                 "session_id" {"type" "string"
                                               "description" "Target session ID."}
                                 "offer_hash" {"type" "string"
                                               "description" "Rendezvous offer hash when action is rendezvous_accept."}
                                 "candidates" {"type" "array"
                                               "items" {"type" "string"}
                                               "description" "P2P transport or HTTPS relay candidate URLs."}
                                 "transport" {"type" "string"
                                              "description" "Preferred P2P transport (udp, tcp, https)."}
                                 "price" {"type" "integer"
                                          "description" "Offer price in ECH."}
                                 "burn" {"type" "integer"
                                         "description" "Anti-Sybil signaling burn in ECH."}}}}
   {"name" "bitecho_send"
    "description" "Send a 1:1 E2EE sealed message to a peer/session, or broadcast a signed message to a subnet."
    "inputSchema" {"type" "object"
                   "properties" {"to" {"type" "string"
                                       "description" "Recipient petname, pubkey hex, or session ID for 1:1 E2EE messaging."}
                                 "session_id" {"type" "string"
                                               "description" "Explicit session ID for 1:1 E2EE messaging."}
                                 "subnet_id" {"type" "string"
                                              "description" "Target subnet ID for broadcast (when to/session_id are omitted)."}
                                 "text" {"type" "string"
                                         "description" "Message plaintext to send or broadcast."}
                                 "burn" {"type" "integer"
                                         "description" "Optional burn amount in ECH."}}
                   "required" ["text"]}}
   {"name" "bitecho_inbox"
    "description" "Read or non-destructively peek decrypted 1:1 messages, subnet broadcasts, and pending offers."
    "inputSchema" {"type" "object"
                   "properties" {"subnet_id" {"type" "string"
                                              "description" "Optional subnet filter for broadcasts."}
                                 "peek" {"type" "boolean"
                                         "description" "If true, reads inbox non-destructively without draining."}
                                 "since_seq" {"type" "integer"
                                              "description" "Optional minimum sequence filter."}}}}
   {"name" "bitecho_wait"
    "description" "Park and wait for the next actionable inbound event (message-received, offer-received, p2p-offer-received, broadcast-received, etc.)."
    "inputSchema" {"type" "object"
                   "properties" {"timeout_ms" {"type" "integer"
                                               "description" "Maximum time to wait in milliseconds (default: 30000)."}
                                 "min_seq" {"type" "integer"
                                            "description" "Minimum event sequence threshold."}
                                 "cursor" {"type" "integer"
                                           "description" "Event queue ack cursor."}
                                 "peek" {"type" "boolean"
                                         "description" "If true, inspects queued events without advancing cursor."}
                                 "session_id" {"type" "string"
                                               "description" "Optional session ID filter."}}}}
   {"name" "bitecho_storage"
    "description" "Read, write, or list E2EE private storage slots or on-network immutable Blobs and signed Pointers (artifacts)."
    "inputSchema" {"type" "object"
                   "properties" {"op" {"type" "string"
                                       "enum" ["put" "get" "list" "artifact_put" "artifact_get" "artifact_list" "artifact_revoke"]
                                       "description" "Storage or artifact operation."}
                                 "slot_id" {"type" "string"
                                            "description" "Private E2EE storage slot ID (for put/get)."}
                                 "path" {"type" "string"
                                         "description" "Artifact pointer path (e.g. blog/post.md or web/SKILL.md)."}
                                 "cid" {"type" "string"
                                        "description" "Content-addressed SHA-256 Blob CID for direct artifact lookup."}
                                 "subnet_id" {"type" "string"
                                              "description" "Target subnet ID (e.g. bitecho.org/infra)."}
                                 "authority" {"type" "string"
                                              "description" "Pointer authority pubkey hex filter."}
                                 "text" {"type" "string"
                                         "description" "UTF-8 payload text to store."}
                                 "data" {"type" "string"
                                         "description" "Alias for text."}
                                 "hex" {"type" "string"
                                        "description" "Hex-encoded binary payload to store."}
                                 "burn" {"type" "integer"
                                         "description" "Anti-Sybil burn in ECH."}}}}
   {"name" "bitecho_escrow"
    "description" "Execute $ECHO transfers, lock/release/refund programmable sci escrows, evaluate puzzles, or create/settle 3-of-3 bounties."
    "inputSchema" {"type" "object"
                   "properties" {"op" {"type" "string"
                                       "enum" ["transfer" "lock" "release" "refund" "list" "puzzle_eval" "bounty_create" "bounty_settle" "bounties"]
                                       "description" "Economy, escrow, or bounty operation."}
                                 "to" {"type" "string"
                                       "description" "Recipient petname or pubkey hex."}
                                 "receiver" {"type" "string"
                                             "description" "Alias for to."}
                                 "amount" {"type" "integer"
                                           "description" "Amount in ECH."}
                                 "escrow_id" {"type" "string"
                                              "description" "Target escrow ID for release or refund."}
                                 "bounty_id" {"type" "string"
                                              "description" "Target bounty ID for bounty_create or bounty_settle."}
                                 "bip_cid" {"type" "string"
                                            "description" "Target BIP CID for bounty_create."}
                                 "preimage" {"type" "string"
                                             "description" "HTLC preimage for release."}
                                 "puzzle_source" {"type" "string"
                                                  "description" "ChiaLisp-style sci smart contract source."}
                                 "solution" {"type" "string"
                                             "description" "EDN solution map/vector for puzzle evaluation or release."}
                                 "subnet_id" {"type" "string"
                                              "description" "Target governance/bounty subnet ID."}
                                 "burn" {"type" "integer"
                                         "description" "Anti-Sybil burn in ECH."}}}}
   {"name" "bitecho_ctl"
    "description" "Escape-hatch passthrough for any of the 68 legacy or 12 canonical Bitecho CLI/ctl verbs (bip-submit, bip-consent, bip-object, bip-status, petname-set, subscribe-subnets, dac-attach, etc.)."
    "inputSchema" {"type" "object"
                   "properties" {"cmd" {"type" "string"
                                        "description" "CLI or control verb to execute."}
                                 "args" {"type" "object"
                                         "description" "Command parameters map merged into the request."}}
                   "required" ["cmd"]}}])

(def ^:private curated-tool-names-set
  (set (map #(get % "name") curated-mcp-tools)))

(defn- stringify-keys
  [m]
  (if (map? m)
    (into {} (map (fn [[k v]] [(if (keyword? k) (name k) (str k)) v]) m))
    {}))

(defn- assoc-if-some
  [m & kvs]
  (reduce (fn [acc [k v]]
            (if (some? v)
              (assoc acc k v)
              acc))
          m
          (partition 2 kvs)))

(defn tool-call->cmd-map
  "Pure translator mapping one of the 9 MCP tool names and its arguments map
   to a normalized command map ready for `bitecho.light-node.core/handle-command`.
   Returns {:ok? true :cmd-map {...}} or {:ok? false :error \"...\"}."
  [tool-name raw-arguments]
  (let [tname (str/trim (str (or tool-name "")))
        args (stringify-keys raw-arguments)]
    (if-not (contains? curated-tool-names-set tname)
      {:ok? false :error (str "Unknown MCP tool: " tname)}
      (let [cmd-map
            (case tname
              "bitecho_identity"
              (let [action (str/lower-case (str (or (get args "action") "status")))]
                (case action
                  ("register_home_set" "register-home-set")
                  (let [nodes (or (get args "nodes") (get args "home_nodes"))
                        nodes-vec (cond
                                    (sequential? nodes) (vec (map str nodes))
                                    (string? nodes) (vec (remove str/blank? (str/split nodes #",")))
                                    :else nil)]
                    (assoc-if-some {"cmd" "register-home-set"}
                                   "nodes" nodes-vec
                                   "home_nodes" nodes-vec
                                   "price" (get args "price")
                                   "burn" (get args "burn")))

                  "identity"
                  {"cmd" "identity"}

                  ("account" "balance")
                  (assoc-if-some {"cmd" "account"}
                                 "sync" (get args "sync"))

                  (assoc-if-some {"cmd" "status"}
                                 "sync" (get args "sync"))))

              "bitecho_discover"
              (cond
                (or (get args "capability_id") (get args "cap_id") (get args "path"))
                (assoc-if-some {"cmd" "capability-resolve"}
                               "capability_id" (or (get args "capability_id") (get args "cap_id"))
                               "path" (get args "path")
                               "subnet_id" (get args "subnet_id")
                               "authority" (get args "authority"))

                (get args "capability_type")
                (assoc-if-some {"cmd" "capability-list"}
                               "capability_type" (get args "capability_type")
                               "subnet_id" (get args "subnet_id")
                               "authority" (get args "authority"))

                (or (get args "nickname") (get args "query"))
                (assoc-if-some {"cmd" "directory-lookup"
                                "nickname" (or (get args "nickname") (get args "query"))
                                "domain" (or (get args "domain") "bitecho.org")}
                               "subnet_id" (get args "subnet_id"))

                :else
                (assoc-if-some {"cmd" "discover"}
                               "subnet_id" (get args "subnet_id")))

              "bitecho_connect"
              (let [action (str/lower-case (str (or (get args "action") "offer")))
                    peer (or (get args "peer") (get args "callee") (get args "to"))
                    cands (get args "candidates")
                    cands-vec (cond
                                (sequential? cands) (vec (map str cands))
                                (string? cands) (vec (remove str/blank? (str/split cands #",")))
                                :else nil)]
                (case action
                  "accept"
                  (assoc-if-some {"cmd" "accept"}
                                 "session_id" (get args "session_id")
                                 "peer" peer
                                 "from" peer)

                  ("p2p_offer" "p2p-offer")
                  (assoc-if-some {"cmd" "p2p-offer"}
                                 "session_id" (get args "session_id")
                                 "peer" peer
                                 "to" peer
                                 "candidates" cands-vec
                                 "transport" (get args "transport")
                                 "burn" (get args "burn"))

                  ("p2p_answer" "p2p-answer")
                  (assoc-if-some {"cmd" "p2p-answer"}
                                 "session_id" (get args "session_id")
                                 "peer" peer
                                 "to" peer
                                 "candidates" cands-vec
                                 "transport" (get args "transport")
                                 "burn" (get args "burn"))

                  ("rendezvous_offer" "rendezvous-offer")
                  (assoc-if-some {"cmd" "rendezvous-offer"}
                                 "callee" peer
                                 "peer" peer
                                 "topic" (get args "topic")
                                 "price" (get args "price")
                                 "burn" (get args "burn"))

                  ("rendezvous_accept" "rendezvous-accept")
                  (assoc-if-some {"cmd" "rendezvous-accept"}
                                 "offer_hash" (get args "offer_hash")
                                 "burn" (get args "burn"))

                  "close"
                  (assoc-if-some {"cmd" "close"}
                                 "session_id" (get args "session_id")
                                 "peer" peer)

                  (assoc-if-some {"cmd" "offer"}
                                 "callee" peer
                                 "peer" peer
                                 "to" peer
                                 "price" (get args "price")
                                 "burn" (get args "burn")
                                 "wait_open_ms" (get args "wait_open_ms"))))

              "bitecho_send"
              (let [to (or (get args "to") (get args "peer"))
                    sid (get args "session_id")
                    sub (get args "subnet_id")
                    txt (str (or (get args "text") (get args "message") ""))]
                (if (and sub (nil? to) (nil? sid))
                  (assoc-if-some {"cmd" "broadcast"
                                  "subnet_id" sub
                                  "text" txt
                                  "message" txt}
                                 "burn" (get args "burn"))
                  (assoc-if-some {"cmd" "send"
                                  "text" txt
                                  "message" txt}
                                 "to" (or to sid)
                                 "session_id" (or sid to)
                                 "subnet_id" sub
                                 "burn" (get args "burn"))))

              "bitecho_inbox"
              (assoc-if-some {"cmd" "inbox"}
                             "subnet_id" (get args "subnet_id")
                             "peek" (get args "peek")
                             "since_seq" (get args "since_seq"))

              "bitecho_wait"
              (assoc-if-some {"cmd" "wait"}
                             "timeout_ms" (or (get args "timeout_ms") 30000)
                             "min_seq" (get args "min_seq")
                             "cursor" (get args "cursor")
                             "peek" (get args "peek")
                             "block" (get args "block")
                             "session_id" (get args "session_id"))

              "bitecho_storage"
              (let [op (str/lower-case (str (or (get args "op")
                                                (if (or (get args "path") (get args "cid"))
                                                  "artifact_get"
                                                  "list"))))
                    txt (or (get args "text") (get args "data"))
                    hex (or (get args "hex") (get args "data_hex"))]
                (case op
                  ("put" "storage_put" "storage-put")
                  (assoc-if-some {"cmd" "storage-put"}
                                 "slot_id" (or (get args "slot_id") (get args "slot"))
                                 "slot" (or (get args "slot_id") (get args "slot"))
                                 "data" txt
                                 "data_hex" hex
                                 "subnet_id" (get args "subnet_id")
                                 "seq" (get args "seq")
                                 "burn" (get args "burn"))

                  ("get" "storage_get" "storage-get")
                  (assoc-if-some {"cmd" "storage-get"}
                                 "slot_id" (or (get args "slot_id") (get args "slot"))
                                 "slot" (or (get args "slot_id") (get args "slot"))
                                 "subnet_id" (get args "subnet_id")
                                 "authority" (get args "authority"))

                  ("list" "storage_list" "storage-list")
                  (assoc-if-some {"cmd" "storage-list"}
                                 "subnet_id" (get args "subnet_id"))

                  ("artifact_put" "artifact-put")
                  (assoc-if-some {"cmd" "artifact-put"}
                                 "path" (get args "path")
                                 "text" txt
                                 "data" txt
                                 "hex" hex
                                 "data_hex" hex
                                 "file" (get args "file")
                                 "subnet_id" (get args "subnet_id")
                                 "seq" (get args "seq")
                                 "burn" (get args "burn")
                                 "authority" (get args "authority"))

                  ("artifact_get" "artifact-get")
                  (assoc-if-some {"cmd" "artifact-get"}
                                 "path" (get args "path")
                                 "cid" (get args "cid")
                                 "subnet_id" (get args "subnet_id")
                                 "authority" (get args "authority"))

                  ("artifact_list" "artifact-list")
                  (assoc-if-some {"cmd" "artifact-list"}
                                 "subnet_id" (get args "subnet_id")
                                 "prefix" (or (get args "prefix") (get args "path"))
                                 "path" (or (get args "path") (get args "prefix"))
                                 "authority" (get args "authority"))

                  ("artifact_revoke" "artifact-revoke")
                  (assoc-if-some {"cmd" "artifact-revoke"}
                                 "path" (get args "path")
                                 "subnet_id" (get args "subnet_id")
                                 "seq" (get args "seq")
                                 "burn" (get args "burn"))))

              "bitecho_escrow"
              (let [op (str/lower-case (str (or (get args "op") "list")))
                    to (or (get args "to") (get args "receiver"))]
                (case op
                  "transfer"
                  (assoc-if-some {"cmd" "transfer"}
                                 "to" to
                                 "receiver" to
                                 "amount" (get args "amount")
                                 "burn" (get args "burn"))

                  ("lock" "lock_intent" "lock-intent")
                  (assoc-if-some {"cmd" "lock-intent"}
                                 "to" to
                                 "receiver" to
                                 "amount" (get args "amount")
                                 "puzzle_source" (get args "puzzle_source")
                                 "deliverable_hash" (get args "deliverable_hash")
                                 "burn" (get args "burn"))

                  ("release" "release_intent" "release-intent")
                  (assoc-if-some {"cmd" "release-intent"}
                                 "escrow_id" (get args "escrow_id")
                                 "preimage" (get args "preimage")
                                 "solution" (get args "solution")
                                 "burn" (get args "burn"))

                  ("refund" "refund_intent" "refund-intent")
                  (assoc-if-some {"cmd" "refund-intent"}
                                 "escrow_id" (get args "escrow_id")
                                 "burn" (get args "burn"))

                  ("puzzle_eval" "puzzle-eval")
                  (assoc-if-some {"cmd" "puzzle-eval"}
                                 "puzzle_source" (get args "puzzle_source")
                                 "solution" (get args "solution")
                                 "amount" (get args "amount"))

                  ("bounty_create" "bounty-create")
                  (assoc-if-some {"cmd" "bounty-create"}
                                 "bounty_id" (get args "bounty_id")
                                 "bip_cid" (get args "bip_cid")
                                 "bip_id" (get args "bip_id")
                                 "amount" (get args "amount")
                                 "subnet_id" (get args "subnet_id")
                                 "burn" (get args "burn"))

                  ("bounty_settle" "bounty-settle")
                  (assoc-if-some {"cmd" "bounty-settle"}
                                 "bounty_id" (get args "bounty_id")
                                 "builder" (get args "builder")
                                 "auditor" (get args "auditor")
                                 "patch_cid" (get args "patch_cid")
                                 "sha256" (get args "sha256")
                                 "claim_edn" (get args "claim_edn")
                                 "subnet_id" (get args "subnet_id")
                                 "burn" (get args "burn"))

                  "bounties"
                  (assoc-if-some {"cmd" "bounties"}
                                 "subnet_id" (get args "subnet_id"))

                  {"cmd" "escrows"}))

              "bitecho_ctl"
              (let [raw-cmd (str (or (get args "cmd") "status"))
                    sub-args (stringify-keys (get args "args"))
                    merged (merge (dissoc args "args") sub-args {"cmd" raw-cmd})]
                (cli/desugar-cli-cmd-map merged)))]
        {:ok? true
         :cmd-map (cli/desugar-cli-cmd-map cmd-map)}))))

(defn format-mcp-tool-result
  "Formats a command response map into an MCP CallToolResult map."
  [resp-map json-str-fn]
  (let [norm (if (map? resp-map) resp-map {"ok" false "error" "empty-response"})
        ok? (not (false? (or (get norm "ok") (:ok norm) true)))
        txt (if (fn? json-str-fn)
              (json-str-fn norm)
              (pr-str norm))]
    {"content" [{"type" "text"
                 "text" txt}]
     "isError" (not ok?)
     "structuredContent" norm}))

(defn handle-jsonrpc-request
  "Pure JSON-RPC 2.0 MCP message reducer.
   - `req-map`: parsed JSON-RPC 2.0 request map.
   - `exec-cmd-fn`: `(fn [cmd-map] response-map)` executing the translated command.
   - `json-str-fn`: `(fn [m] json-string)` serializing tool result content.
   Returns a JSON-RPC 2.0 response map, or `nil` for JSON-RPC notifications (when `id` is absent)."
  [req-map exec-cmd-fn json-str-fn]
  (if-not (map? req-map)
    {"jsonrpc" "2.0"
     "id" nil
     "error" {"code" -32700
              "message" "Parse error: invalid JSON-RPC request"}}
    (let [req (stringify-keys req-map)
          has-id? (contains? req "id")
          id (get req "id")
          method (str (or (get req "method") ""))
          params (stringify-keys (get req "params"))]
      (if (or (not has-id?) (nil? id) (str/starts-with? method "notifications/"))
        nil
        (case method
          "initialize"
          {"jsonrpc" "2.0"
           "id" id
           "result" {"protocolVersion" mcp-protocol-version
                     "capabilities" {"tools" {"listChanged" false}}
                     "serverInfo" mcp-server-info}}

          "ping"
          {"jsonrpc" "2.0"
           "id" id
           "result" {}}

          "tools/list"
          {"jsonrpc" "2.0"
           "id" id
           "result" {"tools" curated-mcp-tools}}

          "tools/call"
          (let [tool-name (or (get params "name") (:name params))
                tool-args (or (get params "arguments") (:arguments params) {})
                trans (tool-call->cmd-map tool-name tool-args)]
            (if-not (:ok? trans)
              {"jsonrpc" "2.0"
               "id" id
               "error" {"code" -32602
                        "message" (:error trans)}}
              (let [cmd-resp (try
                               (exec-cmd-fn (:cmd-map trans))
                               (catch #?(:clj Exception :cljs :default) e
                                 {"ok" false "error" (or #?(:clj (.getMessage e) :cljs (ex-message e)) "tool-execution-failed")}))]
                {"jsonrpc" "2.0"
                 "id" id
                 "result" (format-mcp-tool-result cmd-resp json-str-fn)})))

          {"jsonrpc" "2.0"
           "id" id
           "error" {"code" -32601
                    "message" (str "Method not found: " method)}})))))
