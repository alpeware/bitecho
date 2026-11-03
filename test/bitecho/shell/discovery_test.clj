(ns bitecho.shell.discovery-test
  "Tests and generative invariants for bootstrap descriptor parsing and discovery."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.discovery :as discovery]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- sample-pubkey-hex
  "Returns an 88-character SubjectPublicKeyInfo hex string for testing."
  []
  (basalt/bytes->hex (:public (crypto/generate-keypair))))

(defn- sample-fingerprint
  "Generates a valid 32-byte colon-separated uppercase hex fingerprint string."
  []
  (str/join ":" (repeatedly 32 #(format "%02X" (rand-int 256)))))

(def gen-node-id
  "Generates test node IDs."
  (gen/elements [:node1 :node2 :node3 :node4]))

(def gen-ip
  "Generates valid IP address strings for test descriptors."
  (gen/elements ["10.0.0.1" "192.168.1.50" "35.212.129.138" "35.206.120.143"]))

(def gen-descriptor-data
  "Generates valid bootstrap descriptor data maps for testing."
  (gen/let [node-id gen-node-id
            ip gen-ip
            port (gen/choose 5000 5009)
            agent-port (gen/choose 5010 5019)
            ingress-host (gen/elements [nil "node1.ingress.bitecho.org" "node2.ingress.bitecho.org"])
            ingress-port (gen/elements [nil 443 8443])
            ufrag (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 8))
            pwd (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 24))]
    (let [pubkey (sample-pubkey-hex)
          fp (sample-fingerprint)
          treasury-pk (sample-pubkey-hex)
          custody-pk (sample-pubkey-hex)
          dir-pk (when (zero? (rand-int 2)) (sample-pubkey-hex))]
      (cond-> {:network :devnet
               :treasury-pubkey treasury-pk
               :custody-pubkey custody-pk
               :nodes {node-id (cond-> {:node-id node-id
                                        :ip ip
                                        :port port
                                        :agent-port agent-port
                                        :pubkey pubkey
                                        :fingerprint fp
                                        :ice-ufrag ufrag
                                        :ice-pwd pwd}
                                 ingress-host (assoc :ingress-host ingress-host
                                                     :ingress-port (or ingress-port 443)))}}
        dir-pk (assoc :directory-pubkey dir-pk)))))

(defn- descriptor->txt
  "Renders a descriptor map into bootstrap.txt format."
  [desc]
  (let [node (first (vals (:nodes desc)))
        node-id (name (:node-id node))]
    (str "Network: " (name (:network desc)) "\n"
         "Treasury Public Key: " (:treasury-pubkey desc) "\n"
         "Custody Public Key:  " (:custody-pubkey desc) "\n"
         (when-let [dp (:directory-pubkey desc)]
           (str "Directory Authority Public Key: " dp "\n"))
         "\nBootstrap Validators:\n"
         "--------------------------------------------------------------------------------\n"
         "Node: " node-id " (zone-a)\n"
         "  Cluster Address:   " (:ip node) ":" (:port node) " (UDP DataChannel)\n"
         "  Agent Ingress:     " (:ip node) ":" (:agent-port node) " (UDP DataChannel)\n"
         (when-let [ih (:ingress-host node)]
           (str "  Agent HTTPS/Proxy Ingress: " ih ":" (or (:ingress-port node) 443) " (TCP DataChannel)\n"))
         "  Ed25519 Pubkey:    " (:pubkey node) "\n"
         "  DTLS Fingerprint:  " (:fingerprint node) "\n"
         "  ICE Credentials:   ufrag=" (:ice-ufrag node) " pwd=" (:ice-pwd node) "\n")))

(defspec ^{:doc "Property: parse-bootstrap-edn and parse-bootstrap-txt produce identical normalized descriptor maps"}
  prop-descriptor-parsers-parity 25
  (prop/for-all [desc-data gen-descriptor-data]
                (let [edn-str (pr-str desc-data)
                      txt-str (descriptor->txt desc-data)
                      parsed-from-edn (discovery/parse-bootstrap-edn edn-str)
                      parsed-from-txt (discovery/parse-bootstrap-txt txt-str)
                      parsed-auto-edn (discovery/parse-bootstrap-descriptor edn-str)
                      parsed-auto-txt (discovery/parse-bootstrap-descriptor txt-str)]
                  (and (= parsed-from-edn parsed-from-txt)
                       (= parsed-from-edn parsed-auto-edn)
                       (= parsed-from-txt parsed-auto-txt)))))

(deftest test-parse-real-devnet-descriptors
  (testing "Parses actual devnet/bootstrap.edn cleanly"
    (let [edn-file (io/file "devnet/bootstrap.edn")]
      (when (.exists edn-file)
        (let [parsed (discovery/parse-bootstrap-descriptor (slurp edn-file))]
          (is (= :devnet (:network parsed)))
          (is (string? (:treasury-pubkey parsed)))
          (is (string? (:custody-pubkey parsed)))
          (is (= 3 (count (:nodes parsed))))
          (let [n1 (get-in parsed [:nodes :node1])]
            (is (= :node1 (:node-id n1)))
            (is (= "35.212.129.138" (:ip n1)))
            (is (= 5000 (:port n1)))
            (is (= 5010 (:agent-port n1)))
            (is (= "node1.ingress.bitecho.org" (:ingress-host n1)))
            (is (= 443 (:ingress-port n1)))
            (is (= "95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B"
                   (:fingerprint n1))))))))

  (testing "Parses actual devnet/bootstrap.txt cleanly"
    (let [txt-file (io/file "devnet/bootstrap.txt")]
      (when (.exists txt-file)
        (let [parsed (discovery/parse-bootstrap-descriptor (slurp txt-file))]
          (is (= :devnet (:network parsed)))
          (is (string? (:treasury-pubkey parsed)))
          (is (string? (:custody-pubkey parsed)))
          (is (= 3 (count (:nodes parsed))))
          (let [n2 (get-in parsed [:nodes :node2])]
            (is (= :node2 (:node-id n2)))
            (is (= "35.206.120.143" (:ip n2)))
            (is (= 5000 (:port n2)))
            (is (= 5010 (:agent-port n2)))
            (is (= "node2.ingress.bitecho.org" (:ingress-host n2)))
            (is (= 443 (:ingress-port n2)))
            (is (= "F8:73:94:91:1D:7B:CA:66:D9:67:9E:4B:72:B0:D0:8D:5F:5C:37:0F:FE:04:2E:ED:86:E6:8D:79:B8:07:43:78"
                   (:fingerprint n2))))))))

  (testing "Parity between devnet/bootstrap.edn and devnet/bootstrap.txt"
    (let [edn-file (io/file "devnet/bootstrap.edn")
          txt-file (io/file "devnet/bootstrap.txt")]
      (when (and (.exists edn-file) (.exists txt-file))
        (let [p-edn (discovery/parse-bootstrap-descriptor (slurp edn-file))
              p-txt (discovery/parse-bootstrap-descriptor (slurp txt-file))]
          (is (= p-edn p-txt)))))))

(deftest test-fail-closed-invalid-descriptor
  (testing "Rejects descriptor with invalid fingerprint"
    (let [invalid-edn (pr-str {:network :devnet
                               :treasury-pubkey "302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086"
                               :custody-pubkey "302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086"
                               :nodes {:node1 {:ip "127.0.0.1" :port 5000 :agent-port 5010
                                               :pubkey "302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086"
                                               :fingerprint "NOT-A-VALID-FINGERPRINT"
                                               :ice-ufrag "ufrag123" :ice-pwd "pwd123456789012345678901"}}})]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid.*descriptor"
                            (discovery/parse-bootstrap-descriptor invalid-edn)))))

  (testing "Rejects descriptor with invalid pubkey"
    (let [invalid-edn (pr-str {:network :devnet
                               :treasury-pubkey "short"
                               :custody-pubkey "302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086"
                               :nodes {:node1 {:ip "127.0.0.1" :port 5000 :agent-port 5010
                                               :pubkey "short"
                                               :fingerprint "95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B"
                                               :ice-ufrag "ufrag123" :ice-pwd "pwd123456789012345678901"}}})]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid.*descriptor"
                            (discovery/parse-bootstrap-descriptor invalid-edn))))))
