(ns bitecho.shell.bootstrap-test
  "Tests for the bootstrap node entry point."
  (:require [bitecho.shell.bootstrap :as bootstrap]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]))

(deftest ^{:doc "Tests that the bootstrap node can initialize its flow without throwing exceptions."}
  test-bootstrap-init
  ;; Since -main is designed for an actual executable, we might test a core init function.
  ;; For now, we'll verify it returns a topology or starts without error given stubbed args.
  ;; We will call a helper `init-node` rather than `-main` directly to avoid System/exit or blocking.
  (let [node (bootstrap/init-node "node-pubkey-stub")]
    (is (map? node))
    (is (contains? node :events-in))
    (is (contains? node :net-out))
    (is (contains? node :stop-ch))))

(deftest test-cluster-ops-subcommand-inventory
  (testing "scripts/cluster.sh declares audit and verify-e2e subcommands, E2E deploy gates, non-custody probe recipient, and lag checks"
    (let [script (slurp "scripts/cluster.sh")]
      (is (re-find #"audit\s+Audit /statusz" script))
      (is (re-find #"cmd_audit\(\)" script))
      (is (re-find #"audit\)\s+cmd_audit" script))
      (is (re-find #"verify-e2e" script))
      (is (re-find #"run_pre_deploy_e2e_gate" script))
      (is (re-find #"Max Finalization Lag:" script))
      (is (re-find #"Max Execution Lag:" script))
      (is (re-find #"PROBE_PUB=" script))
      (is (re-find #"cmd_fund \"\$\{PROBE_PUB\}\" 1" script))
      (is (re-find #"state-backup" script)))))

(deftest test-browser-bundle-and-index-html-refresh-restore-wiring
  (testing "M1 & L7: dist/index.html calls exact BitechoBrowser.loadStateFromIndexedDB exported by dist/bitecho-browser.js and preserves identity across reload"
    (let [html (slurp "dist/index.html")
          sri-lines (str/split-lines (str/trim (slurp "dist/bitecho-browser.js.sri")))
          sri-384 (first sri-lines)]
      (is (str/includes? html "globalThis.BitechoBrowser.loadStateFromIndexedDB"))
      (is (not (str/includes? html "loadStateFromIndexedDb")))
      (is (str/includes? html sri-384))
      (let [node-res (sh/sh "node" "-e"
                            "require('./dist/bitecho-browser.js');
                             const api = globalThis.BitechoBrowser;
                             api.initNode();
                             api.initAnchor();
                             const seed = new Uint8Array(32);
                             for (let i = 0; i < 32; i++) seed[i] = i + 1;
                             const rec = api.recoverFromYubiKey(seed);
                             const origPub = rec['public-hex'] || rec.public_hex || rec.publicHex;
                             const origAddr = rec.address;
                             // Simulate browser refresh: new initNode + initAnchor, then exact page loadStateFromIndexedDB() flow
                             api.initNode();
                             api.initAnchor();
                             Promise.resolve(api.loadStateFromIndexedDB()).then(function (restored) {
                               const restoredPub = restored && (restored.pubkey || (restored['light-state'] && restored['light-state'].pubkey));
                               const dash = api.getAnchorDashboard();
                               const st = api.getStatus();
                               if (!restoredPub || restoredPub !== origPub) {
                                 console.error('MISMATCH pubkey:', restoredPub, origPub);
                                 process.exit(1);
                               }
                               if (restored.address !== origAddr || dash.identity.address !== origAddr || st.address !== origAddr) {
                                 console.error('MISMATCH address:', restored.address, dash.identity.address, st.address, origAddr);
                                 process.exit(1);
                               }
                               if (restored.hardwareLocked !== true || st.hardwareLocked !== true) {
                                 console.error('MISMATCH hardwareLocked:', restored.hardwareLocked, st.hardwareLocked);
                                 process.exit(1);
                               }
                               console.log('REFRESH_WIRING_OK:' + origAddr);
                             }).catch(function (e) {
                               console.error(e);
                               process.exit(1);
                             });")]
        (is (= 0 (:exit node-res)) (str "Node check failed: " (:err node-res) " " (:out node-res)))
        (is (str/includes? (:out node-res) "REFRESH_WIRING_OK:ech1"))))))
