(ns bitecho.node-bundle-test
  "Automated verification test suite for dist/bitecho-light-node.cjs:
   - F-H2: Starts `node dist/bitecho-light-node.cjs serve --ingress-tcp-port <free-port>`,
     dials its UDP WebRTC listener on 127.0.0.1:<free-port> using `datachannel.api/start!`,
     sends a signed :p2p-link-bind Fressian envelope on open, and verifies the Node daemon
     emits {\"event\":\"p2p-connected\",\"session_id\":sid,\"peer\":...,\"transport\":\"udp\",\"zero_burn\":true}."
  (:require [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.light-node :as light-shell]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [datachannel.api :as api])
  (:import [java.net ServerSocket]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(deftest test-node-light-node-udp-p2p-link-bind-accept
  (testing "F-H2: Live Node.js daemon accepts UDP WebRTC DataChannel connection and emits p2p-connected with transport udp"
    (let [temp-dir (Files/createTempDirectory "node-bundle-test-" (into-array FileAttribute []))
          dir-node (str (.resolve temp-dir "node-daemon"))
          dir-client (str (.resolve temp-dir "client-jvm"))
          id-node (light-shell/load-or-create-light-identity! dir-node)
          id-client (light-shell/load-or-create-light-identity! dir-client)
          events-file (str (.resolve temp-dir "events.jsonl"))
          port (let [ss (ServerSocket. 0)] (try (.getLocalPort ss) (finally (.close ss))))
          st-node (light-core/init-light-state id-node {:economy-enabled? false :subnet-id "chat/simon-nexus-axiom"})
          st-client (light-core/init-light-state id-client {:economy-enabled? false :subnet-id "chat/simon-nexus-axiom"})
          off-res (light-core/handle-command st-client
                                             {"cmd" "offer" "callee" (:pubkey-hex id-node) "price" 0 "burn" 0}
                                             (:privkey-bytes id-client))
          sid (get-in off-res [:response "session_id"])
          node-off (reduce (fn [s env] (:state (light-core/handle-wire-payload s env (:privkey-bytes id-node))))
                           st-node
                           (:net-envelopes off-res))
          acc-res (light-core/handle-command node-off {"cmd" "accept" "session_id" sid} (:privkey-bytes id-node))
          node-open (:state acc-res)
          _ (light-shell/save-light-state! (str (io/file dir-node "state.fressian")) node-open)
          node-bin (or (System/getenv "NODE_BIN")
                       (let [local-node (io/file (System/getProperty "user.home") ".local/bin/node")]
                         (if (.canExecute local-node)
                           (.getAbsolutePath local-node)
                           "node")))
          bundle-path "dist/bitecho-light-node.cjs"
          pb (ProcessBuilder. ^java.util.List [node-bin bundle-path "serve"
                                               "--state-dir" dir-node
                                               "--ingress-tcp-port" (str port)
                                               "--events-out" events-file])
          proc (.start pb)
          client-node (api/create-node {:port 0 :setup "active"})
          open-prom (promise)
          cid-atom (atom 0)]
      (try
        (Thread/sleep 300)
        (let [sdp {:ip "127.0.0.1"
                   :port port
                   :ufrag (get-in id-node [:ice-creds :ufrag])
                   :pwd (get-in id-node [:ice-creds :pwd])
                   :fingerprint (identity/normalize-fingerprint (:fingerprint id-node))}
              callbacks {:on-open (fn [evt]
                                    (let [cid (or (:channel-id evt) (:stream-id evt) 0)]
                                      (reset! cid-atom cid)
                                      (deliver open-prom true)))
                         :on-message (fn [_] nil)
                         :on-close (fn [_] nil)}]
          (api/set-callbacks! client-node callbacks)
          (api/start! client-node sdp callbacks)
          (is (= true (deref open-prom 5000 :timeout)) "Client connected to Node daemon via UDP")
          (let [bind-env (light-shell/build-p2p-link-bind-envelope (:pubkey-hex id-client) (:privkey-bytes id-client) sid)]
            (api/send! client-node (fressian/encode-wire bind-env) @cid-atom))
          (let [deadline (+ (System/currentTimeMillis) 3000)
                evt (loop []
                      (let [lines (try (remove str/blank? (str/split-lines (slurp events-file))) (catch Exception _ []))
                            found (some (fn [l]
                                          (when-let [m (try (json/read-str l) (catch Exception _ nil))]
                                            (when (= "p2p-connected" (get m "event"))
                                              m)))
                                        lines)]
                        (if (or found (> (System/currentTimeMillis) deadline))
                          found
                          (do (Thread/sleep 50) (recur)))))]
            (is (some? evt) "Node daemon emitted p2p-connected event")
            (is (= "udp" (get evt "transport")) "P2P transport is UDP")
            (is (= true (get evt "zero_burn")) "P2P connection is zero_burn")
            (is (= sid (get evt "session_id")) "Session ID matches")
            (is (= (:pubkey-hex id-client) (get evt "peer")) "Peer matches client pubkey")))
        (finally
          (try (api/close! client-node) (catch Exception _ nil))
          (try (.destroyForcibly proc) (catch Exception _ nil))
          (try (.waitFor proc) (catch Exception _ nil))
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))
