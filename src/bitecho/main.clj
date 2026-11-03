(ns bitecho.main
  "CLI entrypoint for Bitecho node."
  (:gen-class)
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.demo.angels :as angels]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.light-node :as light-node]
            [bitecho.shell.mesh :as mesh]
            [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(defn- print-usage
  "Prints CLI usage guide."
  []
  (println "Bitecho Node CLI")
  (println "Usage:")
  (println "  bitecho run <config.edn>")
  (println "  bitecho print-identity <config.edn>")
  (println "  bitecho gen-keypair [output-file.edn]")
  (println "  bitecho validate-config <config.edn>")
  (println "  bitecho simulate-agents <bootstrap.edn> <keypair.edn> [--agents N] [--messages M] [--burn B]")
  (println "  bitecho fund-agent <bootstrap.edn> <keypair.edn> <recipient-pubkey-hex> <amount> [--seq S] [--deps D] [--burn B]")
  (println "  bitecho light-node <serve|verb> [options]")
  (println "  bitecho sign-directory-pop <dir-identity-dir-or-file> <pop-json-or-file> [issued-epoch] [expires-epoch] [mailbox]")
  (println "  bitecho demo-angels"))

(defn- cmd-run
  "Runs a Bitecho mesh node given a config EDN file."
  [config-file]
  (let [f (io/file config-file)]
    (when-not (.exists f)
      (binding [*out* *err*]
        (println (str "Error: config file not found: " config-file)))
      (System/exit 1))
    (let [cfg (edn/read-string (slurp f))
          node (mesh/start-mesh-node! cfg)
          node-id (:node-id node)
          pubkey (get-in node [:identity :pubkey-hex])
          fp (get-in node [:identity :fingerprint])
          http-port (get-in cfg [:http :port] 8080)]
      (println (format "Bitecho node started: id=%s pubkey=%s fingerprint=%s http=:%d"
                       (name node-id) pubkey fp http-port))
      (.addShutdownHook (Runtime/getRuntime)
                        (Thread. ^Runnable (fn []
                                             (println "Shutting down Bitecho node...")
                                             ((:stop! node)))))
      (let [lock (Object.)]
        (locking lock
          (.wait lock))))))

(defn- cmd-print-identity
  "Prints the persistent node identity for a given config EDN file."
  [config-file]
  (let [f (io/file config-file)]
    (when-not (.exists f)
      (binding [*out* *err*]
        (println (str "Error: config file not found: " config-file)))
      (System/exit 1))
    (let [cfg (edn/read-string (slurp f))
          node-id (or (:node/id cfg) (:node-id cfg) :node-1)
          state-dir (or (:state-dir cfg) "data")
          id-data (identity/load-or-create-node-identity! state-dir node-id)]
      (println (str "Node: " (name node-id)))
      (println (str "State directory: " state-dir))
      (println (str "Ed25519 Pubkey: " (:pubkey-hex id-data)))
      (println (str "SHA-256 Fingerprint: " (:fingerprint id-data)))
      (println (str "ICE ufrag: " (get-in id-data [:ice-creds :ufrag])))
      (println (str "ICE pwd: " (get-in id-data [:ice-creds :pwd]))))))

(defn- cmd-gen-keypair
  "Generates an Ed25519 keypair and optionally saves to output file."
  [& [output-file]]
  (let [kp-map (identity/generate-ed25519-keypair-map)]
    (if output-file
      (do
        (identity/write-keypair-file! output-file kp-map)
        (println (str "Wrote keypair to " output-file))
        (println (str "Ed25519 Pubkey: " (:pubkey-hex kp-map))))
      (do
        (println (str "Ed25519 Pubkey: " (:pubkey-hex kp-map)))
        (println "Pass an output file path (e.g. bitecho gen-keypair <path>) to persist private key securely with 0600 permissions.")))))

(defn- cmd-validate-config
  "Validates a Bitecho node configuration EDN file."
  [config-file]
  (let [f (io/file config-file)]
    (when-not (.exists f)
      (binding [*out* *err*]
        (println (str "Error: config file not found: " config-file)))
      (System/exit 1))
    (let [cfg (try
                (edn/read-string (slurp f))
                (catch Exception e
                  (binding [*out* *err*]
                    (println (str "Error: failed to parse EDN in " config-file ": " (.getMessage e))))
                  (System/exit 1)))
          res (mesh/validate-node-config cfg)]
      (if (:valid? res)
        (do
          (println (str "Config valid: " config-file))
          (System/exit 0))
        (do
          (binding [*out* *err*]
            (println (str "Config invalid: " (:error res))))
          (System/exit 1))))))

(defn- cmd-simulate-agents
  "Runs light agent swarm simulation against bootstrap nodes."
  [args]
  (try
    (let [{:keys [bootstrap-file keypair-file opts]} (agent-sim/parse-sim-args args)]
      (agent-sim/run-agent-simulation! bootstrap-file keypair-file opts)
      (shutdown-agents)
      (System/exit 0))
    (catch Exception e
      (binding [*out* *err*]
        (println (str "Error: " (.getMessage e))))
      (System/exit 1))))

(defn- cmd-fund-agent
  "Sends a signed transfer from keypair to recipient across bootstrap nodes."
  [args]
  (try
    (let [{:keys [bootstrap-file keypair-file recipient amount opts]} (agent-sim/parse-fund-args args)]
      (agent-sim/run-fund-agent! bootstrap-file keypair-file recipient amount opts)
      (shutdown-agents)
      (System/exit 0))
    (catch Exception e
      (binding [*out* *err*]
        (println (str "Error: " (.getMessage e))))
      (System/exit 1))))

(defn- cmd-sign-directory-pop
  "Signs a directory attestation descriptor from a PoP JSON string or file under a cold Directory Authority key."
  [args]
  (let [[dir-identity-path pop-json-str issued-epoch-str expires-epoch-str mailbox] args]
    (if-not (and dir-identity-path pop-json-str)
      (do
        (binding [*out* *err*]
          (println "Usage: bitecho sign-directory-pop <dir-identity-dir-or-file> <pop-json-or-file> [issued-epoch] [expires-epoch] [mailbox]"))
        (System/exit 1))
      (let [f (io/file dir-identity-path)]
        (when-not (.exists f)
          (binding [*out* *err*]
            (println (str "Error: Directory identity path not found: " dir-identity-path)))
          (System/exit 1))
        (let [id-file (cond
                        (.isFile f) f
                        (.exists (io/file f "identity" "node-identity.edn")) (io/file f "identity" "node-identity.edn")
                        (.exists (io/file f "node-identity.edn")) (io/file f "node-identity.edn")
                        :else nil)
              ident (if id-file
                      (let [edn-data (edn/read-string (slurp id-file))
                            pub-hex (:pubkey-hex edn-data)
                            priv-hex (:privkey-hex edn-data)
                            pub-bytes (basalt/hex->bytes pub-hex)
                            priv-bytes (basalt/hex->bytes priv-hex)]
                        {:pubkey-hex pub-hex
                         :keypair {:public pub-bytes :private priv-bytes}})
                      (identity/load-or-create-node-identity! dir-identity-path :directory))
              priv-bytes (get-in ident [:keypair :private])
              pub-hex (:pubkey-hex ident)
              pop-file (io/file pop-json-str)
              pop-raw (if (.exists pop-file) (slurp pop-file) pop-json-str)
              pop-map (try (json/read-str pop-raw) (catch Exception e
                                                     (binding [*out* *err*]
                                                       (println (str "Error: Failed to parse PoP JSON: " (.getMessage e))))
                                                     (System/exit 1)))]
          (when-not (and (map? pop-map) (light-core/verify-directory-pop pop-map))
            (binding [*out* *err*]
              (println "Error: Invalid Proof-of-Possession (PoP) structure or signature"))
            (System/exit 1))
          (let [issued-ep (when (and issued-epoch-str (not (str/blank? issued-epoch-str)))
                            (Long/parseLong (str issued-epoch-str)))
                expires-ep (when (and expires-epoch-str (not (str/blank? expires-epoch-str)))
                             (Long/parseLong (str expires-epoch-str)))
                opts (cond-> {}
                       issued-ep (assoc :issued-epoch issued-ep)
                       expires-ep (assoc :expires-epoch expires-ep)
                       mailbox (assoc :mailbox mailbox))
                desc (light-core/sign-directory-descriptor priv-bytes pub-hex pop-map opts)
                v-res (light-core/verify-directory-descriptor desc pub-hex (or issued-ep 0))]
            (if-not (:ok? v-res)
              (do
                (binding [*out* *err*]
                  (println (str "Error: Failed to verify signed descriptor: " (:error v-res))))
                (System/exit 1))
              (let [stringified (into {}
                                      (for [[k v] desc]
                                        [(if (keyword? k)
                                           (if-let [ns (namespace k)]
                                             (str ns "/" (name k))
                                             (name k))
                                           (str k))
                                         v]))]
                (println (json/write-str stringified))
                (System/exit 0)))))))))

(defn- cmd-demo-angels
  "Runs the Milestone 6 & 7 Angels Demos: Multi-Harness Neutrality Proof, Three-Device einsum Pipeline, and Testnet Readiness Gate."
  [_args]
  (try
    (let [report (angels/run-all-angels-demos)]
      (println (json/write-str report))
      (if (:ok? report)
        (System/exit 0)
        (System/exit 1)))
    (catch Exception e
      (binding [*out* *err*]
        (println (str "Error running demo-angels: " (.getMessage e))))
      (System/exit 1))))

(defn -main
  "Main CLI entrypoint."
  [& args]
  (let [[cmd & rest-args] args]
    (case cmd
      "run"
      (if (first rest-args)
        (cmd-run (first rest-args))
        (do (print-usage) (System/exit 1)))

      "print-identity"
      (if (first rest-args)
        (cmd-print-identity (first rest-args))
        (do (print-usage) (System/exit 1)))

      "gen-keypair"
      (apply cmd-gen-keypair rest-args)

      "validate-config"
      (if (first rest-args)
        (cmd-validate-config (first rest-args))
        (do (print-usage) (System/exit 1)))

      "simulate-agents"
      (cmd-simulate-agents rest-args)

      "fund-agent"
      (cmd-fund-agent rest-args)

      "light-node"
      (light-node/run-light-node-cli! rest-args)

      "sign-directory-pop"
      (cmd-sign-directory-pop rest-args)

      "demo-angels"
      (cmd-demo-angels rest-args)

      (do
        (print-usage)
        (when (seq args)
          (System/exit 1))))))
