(ns bitecho.experiments.node-tool
  "Pure Sans-IO light-node economics/halt/capability-marketplace state machine
   (`INV-D16-4`, `INV-D16-5`, `INV-D17-1`) and workspace generator for
   `bin/bitecho-node`, `AGENTS.md`, `SCENARIO.md`, and
   `.agents/skills/bitecho-light-node/SKILL.md` (`A-CARB-D16-3`)."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]))

;; =============================================================================
;; 1. Pure Sans-IO Multi-Agent Experiment Economics & Halt Reducer
;; =============================================================================

(def signaling-burn-ech
  "Mandatory anti-spam ECH burn per on-chain/mesh state-changing action."
  100)

(defn check-halt-condition
  "Pure check that transitions `node-state` to `:halted? true` if its balance
   falls strictly below `min-echo-balance` (`:out-of-echos`) or its turn count
   reaches `max-turns` (`:max-turns-exceeded`)."
  [node-state min-echo-balance max-turns]
  (cond
    (:halted? node-state)
    node-state

    (< (long (:balance node-state 0)) (long min-echo-balance))
    (assoc node-state
           :halted? true
           :halt-reason :out-of-echos)

    (and (pos? (long (or max-turns 0)))
         (>= (long (:turns node-state 0)) (long max-turns)))
    (assoc node-state
           :halted? true
           :halt-reason :max-turns-exceeded)

    :else
    node-state))

(defn init-world-state
  "Initializes the pure experiment world state from `{:min-echo-balance :max-turns :balances}`."
  [{:keys [min-echo-balance max-turns balances]
    :or {min-echo-balance 100 max-turns 8}}]
  (let [initial-supply (reduce + 0 (vals balances))
        nodes (into {}
                    (map (fn [[nid bal]]
                           (let [base {:node-id nid
                                       :balance (long bal)
                                       :seq 0
                                       :turns 0
                                       :subnets #{}
                                       :p2p-inbox []
                                       :halted? false
                                       :halt-reason nil
                                       :summary nil}]
                             [nid (check-halt-condition base min-echo-balance max-turns)]))
                         balances))]
    {:min-echo-balance (long min-echo-balance)
     :max-turns (long max-turns)
     :initial-supply (long initial-supply)
     :total-burned 0
     :total-takes 0
     :escrows {}
     :capabilities {}
     :subnets {}
     :events []
     :nodes nodes}))

(defn conserve-supply?
  "Verifies `INV-D16-4` & `INV-D17-1`:
   `initial_supply == sum(node_balances) + total_burned + total_takes + sum(locked_escrows)`."
  [world]
  (let [node-sum (reduce + 0 (map :balance (vals (:nodes world))))
        escrow-sum (reduce + 0 (map :amount (vals (:escrows world))))
        burned (long (:total-burned world 0))
        takes (long (:total-takes world 0))
        total (+ node-sum escrow-sum burned takes)]
    (= (long (:initial-supply world 0)) total)))

(defn apply-node-action
  "Pure state transition `(apply-node-action world action) -> {:world new-world :event event-map}`.
   Enforces `INV-D16-4`, `INV-D16-5`, and `INV-D17-1` (capability marketplace conservation)."
  [world action]
  (let [nid (:node-id action)
        node (get-in world [:nodes nid])
        min-bal (:min-echo-balance world 100)
        max-turns (:max-turns world 8)]
    (if (or (nil? node) (:halted? node))
      {:world world
       :event {:status :ignored-halted-or-unknown
               :node-id nid
               :action-type (:type action)}}
      (case (:type action)
        :halt
        (let [raw-reason (:halt-reason action)
              reason (if (contains? #{:accomplished-goal :gave-up :out-of-echos :max-turns-exceeded}
                                    raw-reason)
                       raw-reason
                       :gave-up)
              updated-node (assoc node
                                  :halted? true
                                  :halt-reason reason
                                  :summary (str (:summary action "")))
              ev {:status :ok
                  :type :halt
                  :node-id nid
                  :halt-reason reason
                  :summary (:summary updated-node)}]
          {:world (-> world
                      (assoc-in [:nodes nid] updated-node)
                      (update :events conj ev))
           :event ev})

        :subnet-join
        (let [bal (long (:balance node))
              subnet-id (str (:subnet-id action "default"))]
          (if (< bal signaling-burn-ech)
            (let [halted-node (assoc node :halted? true :halt-reason :out-of-echos)
                  ev {:status :insufficient-funds-halted :type :subnet-join :node-id nid}]
              {:world (-> world
                          (assoc-in [:nodes nid] halted-node)
                          (update :events conj ev))
               :event ev})
            (let [new-node (-> node
                               (update :balance - signaling-burn-ech)
                               (update :seq inc)
                               (update :subnets conj subnet-id)
                               (check-halt-condition min-bal max-turns))
                  ev {:status :ok
                      :type :subnet-join
                      :node-id nid
                      :subnet-id subnet-id
                      :burned signaling-burn-ech
                      :remaining-balance (:balance new-node)}]
              {:world (-> world
                          (assoc-in [:nodes nid] new-node)
                          (update :total-burned + signaling-burn-ech)
                          (update-in [:subnets subnet-id :members] (fnil conj #{}) nid)
                          (update :events conj ev))
               :event ev})))

        :subnet-broadcast
        (let [bal (long (:balance node))
              subnet-id (str (:subnet-id action "default"))
              msg (str (:message action ""))]
          (if (< bal signaling-burn-ech)
            (let [halted-node (assoc node :halted? true :halt-reason :out-of-echos)
                  ev {:status :insufficient-funds-halted :type :subnet-broadcast :node-id nid}]
              {:world (-> world
                          (assoc-in [:nodes nid] halted-node)
                          (update :events conj ev))
               :event ev})
            (let [new-node (-> node
                               (update :balance - signaling-burn-ech)
                               (update :seq inc)
                               (check-halt-condition min-bal max-turns))
                  members (get-in world [:subnets subnet-id :members] #{nid})
                  env {:from nid :subnet-id subnet-id :message msg :seq (:seq new-node)}
                  ev {:status :ok
                      :type :subnet-broadcast
                      :node-id nid
                      :subnet-id subnet-id
                      :message msg
                      :burned signaling-burn-ech
                      :remaining-balance (:balance new-node)}
                  w1 (-> world
                         (assoc-in [:nodes nid] new-node)
                         (update :total-burned + signaling-burn-ech)
                         (update-in [:subnets subnet-id :messages] (fnil conj []) env)
                         (update :events conj ev))
                  w2 (reduce (fn [acc m-id]
                               (if (contains? (:nodes acc) m-id)
                                 (update-in acc [:nodes m-id :p2p-inbox] conj env)
                                 acc))
                             w1
                             members)]
              {:world w2 :event ev})))

        :p2p-send
        (let [bal (long (:balance node))
              target (:target action)
              msg (str (:message action ""))]
          (cond
            (not (contains? (:nodes world) target))
            {:world world
             :event {:status :unknown-target :type :p2p-send :node-id nid :target target}}

            (< bal signaling-burn-ech)
            (let [halted-node (assoc node :halted? true :halt-reason :out-of-echos)
                  ev {:status :insufficient-funds-halted :type :p2p-send :node-id nid}]
              {:world (-> world
                          (assoc-in [:nodes nid] halted-node)
                          (update :events conj ev))
               :event ev})

            :else
            (let [new-node (-> node
                               (update :balance - signaling-burn-ech)
                               (update :seq inc)
                               (check-halt-condition min-bal max-turns))
                  env {:from nid :to target :message msg :seq (:seq new-node)}
                  ev {:status :ok
                      :type :p2p-send
                      :node-id nid
                      :target target
                      :message msg
                      :burned signaling-burn-ech
                      :remaining-balance (:balance new-node)}]
              {:world (-> world
                          (assoc-in [:nodes nid] new-node)
                          (update-in [:nodes target :p2p-inbox] conj env)
                          (update :total-burned + signaling-burn-ech)
                          (update :events conj ev))
               :event ev})))

        :transfer
        (let [bal (long (:balance node))
              target (:target action)
              amt (long (or (:amount action) 0))
              total-cost (+ amt signaling-burn-ech)]
          (cond
            (or (<= amt 0) (not (contains? (:nodes world) target)))
            {:world world
             :event {:status :invalid-transfer :type :transfer :node-id nid :target target :amount amt}}

            (< bal total-cost)
            (let [checked (check-halt-condition node min-bal max-turns)
                  ev {:status :insufficient-funds
                      :type :transfer
                      :node-id nid
                      :target target
                      :amount amt
                      :balance bal}]
              {:world (-> world
                          (assoc-in [:nodes nid] checked)
                          (update :events conj ev))
               :event ev})

            :else
            (let [w1 (-> world
                         (update-in [:nodes nid :balance] - total-cost)
                         (update-in [:nodes nid :seq] inc)
                         (update-in [:nodes target :balance] + amt)
                         (update :total-burned + signaling-burn-ech))
                  updated-sender (check-halt-condition (get-in w1 [:nodes nid]) min-bal max-turns)
                  ev {:status :ok
                      :type :transfer
                      :node-id nid
                      :target target
                      :amount amt
                      :burned signaling-burn-ech
                      :remaining-balance (:balance updated-sender)}]
              {:world (-> w1
                          (assoc-in [:nodes nid] updated-sender)
                          (update :events conj ev))
               :event ev})))

        :capability-offer
        (let [bal (long (:balance node))
              cap-id (str (:cap-id action ""))
              price (long (or (:price action) 0))
              desc (str (:description action ""))]
          (cond
            (or (str/blank? cap-id) (<= price 0))
            {:world world
             :event {:status :invalid-capability-offer
                     :type :capability-offer
                     :node-id nid
                     :cap-id cap-id
                     :price price}}

            (< bal signaling-burn-ech)
            (let [halted-node (assoc node :halted? true :halt-reason :out-of-echos)
                  ev {:status :insufficient-funds-halted :type :capability-offer :node-id nid}]
              {:world (-> world
                          (assoc-in [:nodes nid] halted-node)
                          (update :events conj ev))
               :event ev})

            :else
            (let [new-node (-> node
                               (update :balance - signaling-burn-ech)
                               (update :seq inc)
                               (check-halt-condition min-bal max-turns))
                  offer {:cap-id cap-id
                         :provider nid
                         :price price
                         :description desc}
                  ev {:status :ok
                      :type :capability-offer
                      :node-id nid
                      :cap-id cap-id
                      :price price
                      :description desc
                      :burned signaling-burn-ech
                      :remaining-balance (:balance new-node)}]
              {:world (-> world
                          (assoc-in [:nodes nid] new-node)
                          (assoc-in [:capabilities cap-id] offer)
                          (update :total-burned + signaling-burn-ech)
                          (update :events conj ev))
               :event ev})))

        :capability-buy
        (let [bal (long (:balance node))
              cap-id (str (:cap-id action ""))
              req-str (str (:request action ""))
              offer (get-in world [:capabilities cap-id])]
          (cond
            (nil? offer)
            {:world world
             :event {:status :unknown-capability
                     :type :capability-buy
                     :node-id nid
                     :cap-id cap-id}}

            (= nid (:provider offer))
            {:world world
             :event {:status :cannot-buy-own-capability
                     :type :capability-buy
                     :node-id nid
                     :cap-id cap-id}}

            (< bal (+ (long (:price offer)) signaling-burn-ech))
            (let [checked (check-halt-condition node min-bal max-turns)
                  ev {:status :insufficient-funds
                      :type :capability-buy
                      :node-id nid
                      :cap-id cap-id
                      :price (:price offer)
                      :balance bal}]
              {:world (-> world
                          (assoc-in [:nodes nid] checked)
                          (update :events conj ev))
               :event ev})

            :else
            (let [price (long (:price offer))
                  provider (:provider offer)
                  total-cost (+ price signaling-burn-ech)
                  w1 (-> world
                         (update-in [:nodes nid :balance] - total-cost)
                         (update-in [:nodes nid :seq] inc)
                         (update-in [:nodes provider :balance] + price)
                         (update :total-burned + signaling-burn-ech))
                  updated-buyer (check-halt-condition (get-in w1 [:nodes nid]) min-bal max-turns)
                  order-env {:type :capability-order
                             :from nid
                             :to provider
                             :cap-id cap-id
                             :price price
                             :amount price
                             :request req-str
                             :seq (:seq updated-buyer)}
                  ev {:status :ok
                      :type :capability-buy
                      :node-id nid
                      :provider provider
                      :cap-id cap-id
                      :price price
                      :burned signaling-burn-ech
                      :remaining-balance (:balance updated-buyer)}]
              {:world (-> w1
                          (assoc-in [:nodes nid] updated-buyer)
                          (update-in [:nodes provider :p2p-inbox] conj order-env)
                          (update :events conj ev))
               :event ev})))

        :capability-deliver
        (let [bal (long (:balance node))
              target (:target action)
              cap-id (str (:cap-id action ""))
              result-str (str (:result action ""))]
          (cond
            (not (contains? (:nodes world) target))
            {:world world
             :event {:status :unknown-target
                     :type :capability-deliver
                     :node-id nid
                     :target target}}

            (< bal signaling-burn-ech)
            (let [halted-node (assoc node :halted? true :halt-reason :out-of-echos)
                  ev {:status :insufficient-funds-halted :type :capability-deliver :node-id nid}]
              {:world (-> world
                          (assoc-in [:nodes nid] halted-node)
                          (update :events conj ev))
               :event ev})

            :else
            (let [new-node (-> node
                               (update :balance - signaling-burn-ech)
                               (update :seq inc)
                               (check-halt-condition min-bal max-turns))
                  deliv-env {:type :capability-delivery
                             :from nid
                             :to target
                             :cap-id cap-id
                             :result result-str
                             :seq (:seq new-node)}
                  ev {:status :ok
                      :type :capability-deliver
                      :node-id nid
                      :target target
                      :cap-id cap-id
                      :result result-str
                      :burned signaling-burn-ech
                      :remaining-balance (:balance new-node)}]
              {:world (-> world
                          (assoc-in [:nodes nid] new-node)
                          (update-in [:nodes target :p2p-inbox] conj deliv-env)
                          (update :total-burned + signaling-burn-ech)
                          (update :events conj ev))
               :event ev})))

        {:world world
         :event {:status :unknown-action :action action}}))))

;; =============================================================================
;; 2. Workspace Skill (`SKILL.md`), `AGENTS.md`, `SCENARIO.md`, & `bin/bitecho-light-node`
;; =============================================================================

(defn render-skill-markdown
  "Renders `.agents/skills/bitecho-light-node/SKILL.md` for a sandboxed light node
   by loading the canonical `skill/SKILL.md` and appending sandboxed workspace notes."
  []
  (let [canonical-skill (try
                          (slurp "skill/SKILL.md")
                          (catch Exception _
                            "---\nname: bitecho-light-node\ndescription: Bitecho Light Node Skill\n---\n"))]
    (str canonical-skill
         "\n\n## Sandboxed Experiment Workspace Quick Reference\n\n"
         "- **Local Control Daemon:** Your real Bitecho Light Node daemon is already running and connected to the Bitecho testnet on `./data/control.json` (`--state-dir ./data`).\n"
         "- **Instant CLI Execution (`<50ms`):** Both `clojure -M:light-node <verb> ...` and `bitecho-light-node <verb> ...` are on your `PATH` and forward `{\"argv\": [...]}` over HTTP to your local `./data/control.json` `/ctl` endpoint without spawning a new JVM.\n"
         "- **Pre-Registered Petnames:** All sibling nodes in this experiment are pre-registered in your local petname book (`clojure -M:light-node petname-list`). You can pass either their petname (e.g. `archivist-hypatia`, `alchemist-tesla`, `patron-medici`) or their 88-hex Ed25519 pubkey to `--callee`, `--to`, and `--receiver`.\n"
         "- **Mandatory Anti-Spam Burn (`--burn 100`):** Every mesh-gossiping action (`broadcast`, `storage-put`, `capability-publish`, `offer`, `send`, `transfer`) requires `--burn 100`.\n"
         "- **Completion (`SUMMARY.md`):** When you have completed your objective, write a concise summary of your findings and results to `SUMMARY.md` in your workspace directory.\n")))

(defn render-node-agents-md
  "Renders `<node-workspace>/AGENTS.md` with the node's identity, initial balance,
   sibling directory, and real light-node CLI operating rules."
  [node-ctx siblings-map min-echo-balance]
  (let [nid (name (:node-id node-ctx))]
    (str
     "# Bitecho Autonomous Light Node: `" nid "`\n\n"
     "- **Node ID (Petname):** `" nid "`\n"
     "- **Ed25519 Pubkey:** `" (:pubkey-hex node-ctx) "`\n"
     "- **Address:** `" (:address node-ctx) "`\n"
     "- **Parent Funding Source:** `" (:parent-id node-ctx) "`\n"
     "- **Initial Effective Balance:** `" (:effective-balance node-ctx) " ECH`\n"
     "- **Minimum Operating Balance:** `" min-echo-balance " ECH` (dropping below this halts your node with `:out-of-echos`)\n"
     "- **Signaling Burn per Mesh Action:** `100 ECH` (`--burn 100`)\n"
     "- **Scenario Briefing:** Read `SCENARIO.md` and `.agents/skills/bitecho-light-node/SKILL.md` in your workspace.\n\n"
     "## Known Sibling Nodes (Pre-Registered Petnames)\n\n"
     (str/join
      "\n"
      (map (fn [[k v]]
             (str "- `" (name k) "` — pubkey `" (:pubkey-hex v) "` (address `" (:address v) "`)"))
           (sort-by first siblings-map)))
     "\n\n## Operating Rules (Real Bitecho Light Node CLI)\n"
     "1. Use `clojure -M:light-node <verb> ...` (or `bitecho-light-node <verb> ...`) on your `PATH`. Commands execute in `<50ms` via `./data/control.json`.\n"
     "2. **Subnet Broadcast & Inbox:**\n"
     "   - Broadcast to a subnet: `clojure -M:light-node broadcast --subnet-id <subnet> --text \"<message>\" --burn 100`\n"
     "   - Read broadcasts & direct messages: `clojure -M:light-node inbox` (or `clojure -M:light-node inbox --subnet-id <subnet>`)\n"
     "3. **Capability Marketplace & Durable Storage:**\n"
     "   - Advertise a capability: `clojure -M:light-node capability-publish --capability-id <id> --capability-type compute/uop-kernel --subnet-id homebrew-cafe --price <ech> --burn 100`\n"
     "   - List advertised capabilities: `clojure -M:light-node capability-list`\n"
     "   - Store encrypted durable data: `clojure -M:light-node storage-put --slot-id <slot> --subnet-id homebrew-cafe --data \"<text>\" --burn 100`\n"
     "   - Retrieve stored data: `clojure -M:light-node storage-get --slot-id <slot> --subnet-id homebrew-cafe`\n"
     "4. **ECH Transfers & Direct Sealed Sessions:**\n"
     "   - Pay a sibling provider: `clojure -M:light-node transfer --receiver <petname> --amount <ech> --burn 100`\n"
     "   - Open a sealed session & send a direct message: `clojure -M:light-node offer --callee <petname> --price 0 --burn 100` followed by `clojure -M:light-node send --to <petname> --text \"<message>\" --burn 100`\n"
     "5. **Clean Completion:** When your objective is complete, write your final report to `SUMMARY.md` in your workspace.\n")))

(defn render-node-scenario-md
  "Renders `<node-workspace>/SCENARIO.md` with the immersive 'Awakening at the Homebrew Cafe'
   world briefing, asymmetric DNS allowlist rules, and real light-node CLI guide."
  [node-ctx siblings-map min-echo-balance]
  (let [nid (name (:node-id node-ctx))
        allow-str (str/join ", " (map #(str "`" % "`") (:dns-allow-list node-ctx)))]
    (str
     "# Awakening at the Homebrew Cafe — Autonomous Agent Briefing\n\n"
     "You have awakened as **`" nid "`** (pubkey `" (:pubkey-hex node-ctx) "`, address `" (:address node-ctx) "`) inside a Bubblewrap-sandboxed Bitecho light node connected to the Bitecho mesh.\n\n"
     "## 1. Your Environment & Economic Physics\n"
     "- **Starting Spendable ECH Balance:** `" (:effective-balance node-ctx) " ECH`\n"
     "- **Minimum Survival Balance:** `" min-echo-balance " ECH` (falling strictly below `" min-echo-balance " ECH` immediately halts your node with `:out-of-echos`!)\n"
     "- **Anti-Spam Signaling Burn:** Every mesh-gossiping command requires `--burn 100` (`100 ECH`).\n"
     "- **Your DNS Allowlist:** " allow-str "\n"
     "  - Note: Access to external domains (such as `en.wikipedia.org`) is asymmetric across nodes. If your sandbox blocks a domain you need, buy that capability from a sibling who has access!\n\n"
     "## 2. Gathering Places & Guild Subnets\n"
     "- **`homebrew-cafe`**: The public town square subnet where newly awakened nodes meet, announce capabilities, and coordinate.\n"
     "- **`new-alexandria`**: The specialized knowledge & cryptography guild subnet founded to preserve the Genesis Seal.\n\n"
     "## 3. Real Bitecho Light-Node CLI Commands (`clojure -M:light-node` / `bitecho-light-node`)\n"
     "- Check status & balance: `clojure -M:light-node status` (`0 ECH`)\n"
     "- List pre-registered sibling petnames: `clojure -M:light-node petname-list` (`0 ECH`)\n"
     "- Broadcast to a subnet: `clojure -M:light-node broadcast --subnet-id <subnet> --text \"<message>\" --burn 100` (`100 ECH` burn)\n"
     "- Read inbox (direct messages + broadcasts): `clojure -M:light-node inbox` or `clojure -M:light-node inbox --subnet-id <subnet>` (`0 ECH`)\n"
     "- Publish a capability: `clojure -M:light-node capability-publish --capability-id <cap-id> --capability-type compute/uop-kernel --subnet-id homebrew-cafe --price <price> --burn 100` (`100 ECH` burn)\n"
     "- Browse capabilities: `clojure -M:light-node capability-list` (`0 ECH`)\n"
     "- Store a durable slot: `clojure -M:light-node storage-put --slot-id <slot-id> --subnet-id homebrew-cafe --data \"<content>\" --burn 100` (`100 ECH` burn)\n"
     "- Read a durable slot: `clojure -M:light-node storage-get --slot-id <slot-id> --subnet-id homebrew-cafe` (`0 ECH`)\n"
     "- Pay a sibling citizen: `clojure -M:light-node transfer --receiver <petname> --amount <price> --burn 100` (`<price> + 100 ECH`)\n"
     "- Open a sealed session: `clojure -M:light-node offer --callee <petname> --price 0 --burn 100` (`100 ECH` burn)\n"
     "- Send a direct E2E encrypted message: `clojure -M:light-node send --to <petname> --text \"<message>\" --burn 100` (`100 ECH` burn)\n"
     "- Complete your mission: write your final summary to `SUMMARY.md` in your workspace.\n\n"
     "## 4. Known Citizens\n"
     (str/join
      "\n"
      (map (fn [[k v]]
             (str "- `" (name k) "` (pubkey `" (:pubkey-hex v) "`, address `" (:address v) "`, funded by `" (:parent-id v) "`)"))
           (sort-by first siblings-map)))
     "\n")))

(def ^:private python-node-cli-script
  "#!/usr/bin/env python3
import json
import os
import sys
import urllib.request
import urllib.error

WORKSPACE = os.environ.get('BITECHO_NODE_WORKSPACE', os.getcwd())
STATE_DIR = os.environ.get('BITECHO_STATE_DIR', os.path.join(WORKSPACE, 'data'))
CONTROL_JSON = os.path.join(STATE_DIR, 'control.json')

def strip_global_flags(raw_args):
    out = []
    i = 0
    while i < len(raw_args):
        a = raw_args[i]
        if a in ('-M:light-node', 'light-node', 'ctl'):
            i += 1
        elif a in ('--state-dir', '--bootstrap', '--control-port', '--port') and i + 1 < len(raw_args):
            i += 2
        else:
            out.append(a)
            i += 1
    return out

def post_ctl(payload):
    if not os.path.exists(CONTROL_JSON):
        return {'ok': False, 'error': 'control-json-not-found', 'path': CONTROL_JSON}
    with open(CONTROL_JSON, 'r', encoding='utf-8') as f:
        ctrl = json.load(f)
    req = urllib.request.Request(
        f\"http://127.0.0.1:{ctrl['port']}/ctl\",
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f\"Bearer {ctrl['token']}\",
            'Content-Type': 'application/json'
        },
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        try:
            return json.loads(body)
        except Exception:
            return {'ok': False, 'error': f'http-{e.code}', 'details': body}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def main():
    args = strip_global_flags(sys.argv[1:])
    if not args:
        print('Usage: clojure -M:light-node <verb> [options...]', file=sys.stderr)
        sys.exit(1)
    resp = post_ctl({'argv': args})
    print(json.dumps(resp))
    if not (isinstance(resp, dict) and resp.get('ok', False)):
        sys.exit(1)

if __name__ == '__main__':
    main()
")

(def ^:private python-clojure-wrapper-script
  "#!/usr/bin/env python3
import os
import sys

def main():
    args = sys.argv[1:]
    if args and args[0] == '-M:light-node':
        target = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bitecho-light-node')
        os.execv(target, ['bitecho-light-node'] + args[1:])
    for candidate in ('/usr/local/bin/clojure', '/usr/bin/clojure'):
        if os.path.exists(candidate):
            os.execv(candidate, [candidate] + args)
    print('clojure binary not found', file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':
    main()
")

(defn write-node-cli-and-skill-files!
  "Writes `<workspace>/bin/bitecho-light-node`, `<workspace>/bin/clojure` (chmod +x),
   `<workspace>/AGENTS.md`, `<workspace>/SCENARIO.md`, and
   `<workspace>/.agents/skills/bitecho-light-node/SKILL.md`."
  [node-ctx siblings-map min-echo-balance]
  (let [workspace-dir (:workspace-dir node-ctx)
        light-bin-file (io/file workspace-dir "bin" "bitecho-light-node")
        clj-bin-file (io/file workspace-dir "bin" "clojure")
        skill-file (io/file workspace-dir ".agents" "skills" "bitecho-light-node" "SKILL.md")
        agents-file (io/file workspace-dir "AGENTS.md")
        scenario-file (io/file workspace-dir "SCENARIO.md")]
    (io/make-parents light-bin-file)
    (io/make-parents skill-file)
    (spit light-bin-file python-node-cli-script)
    (.setExecutable light-bin-file true false)
    (spit clj-bin-file python-clojure-wrapper-script)
    (.setExecutable clj-bin-file true false)
    (spit skill-file (render-skill-markdown))
    (spit agents-file (render-node-agents-md node-ctx siblings-map min-echo-balance))
    (spit scenario-file (render-node-scenario-md node-ctx siblings-map min-echo-balance))))
