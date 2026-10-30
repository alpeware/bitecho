(ns bitecho.main
  "CLI entrypoint for Bitecho node."
  (:gen-class)
  (:require [bitecho.shell.identity :as identity]
            [bitecho.shell.mesh :as mesh]
            [clojure.edn :as edn]
            [clojure.java.io :as io]))

(defn- print-usage
  "Prints CLI usage guide."
  []
  (println "Bitecho Node CLI")
  (println "Usage:")
  (println "  bitecho run <config.edn>")
  (println "  bitecho print-identity <config.edn>")
  (println "  bitecho gen-keypair [output-file.edn]"))

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
  (let [kp-map (identity/generate-ed25519-keypair-map)
        serialized (pr-str kp-map)]
    (when output-file
      (spit output-file serialized)
      (println (str "Wrote keypair to " output-file)))
    (println (str "Ed25519 Pubkey: " (:pubkey-hex kp-map)))
    (println (str "Ed25519 Privkey: " (:privkey-hex kp-map)))
    (println serialized)))

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

      (do
        (print-usage)
        (when (seq args)
          (System/exit 1))))))
