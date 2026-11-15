(ns bitecho.experiments.node-tool
  "Pure Sans-IO light-node economics/halt state machine (`INV-D16-4`, `INV-D16-5`)
   and workspace generator for `bin/bitecho-node`, `AGENTS.md`, and
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
     :subnets {}
     :events []
     :nodes nodes}))

(defn conserve-supply?
  "Verifies `INV-D16-4`:
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
   Enforces `INV-D16-4` (conservation of supply) and `INV-D16-5` (deterministic halts)."
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

        {:world world
         :event {:status :unknown-action :action action}}))))

;; =============================================================================
;; 2. Workspace Skill (`SKILL.md`), `AGENTS.md`, and `bin/bitecho-node` Generator
;; =============================================================================

(defn render-skill-markdown
  "Renders `.agents/skills/bitecho-light-node/SKILL.md` for a sandboxed light node."
  []
  (str
   "---\n"
   "name: bitecho-light-node\n"
   "description: Operate your Bitecho light node to inspect ECH balance, join/broadcast on subnets, exchange P2P messages, transfer ECH, and halt cleanly.\n"
   "---\n\n"
   "# Bitecho Light Node CLI Skill (`bitecho-node`)\n\n"
   "Use the `bitecho-node` CLI (already on your `PATH`) to interact with sibling nodes and subnets.\n\n"
   "## Commands\n\n"
   "- `bitecho-node status` — Inspect your current `:balance`, `:seq`, `:subnets`, `:halted?`, and `:halt-reason`.\n"
   "- `bitecho-node peers` — List all sibling nodes in the experiment and their `ech1...` addresses.\n"
   "- `bitecho-node subnet-join <subnet-id>` — Join a named subnet (burns `100` ECH).\n"
   "- `bitecho-node subnet-broadcast <subnet-id> \"<message>\"` — Broadcast a message to all subnet members (burns `100` ECH).\n"
   "- `bitecho-node subnet-inbox [subnet-id]` — Read subnet broadcasts received by your node.\n"
   "- `bitecho-node p2p-send <target-node-id> \"<message>\"` — Send a direct P2P message to a sibling node (burns `100` ECH).\n"
   "- `bitecho-node p2p-inbox` — Read direct P2P and subnet messages in your inbox.\n"
   "- `bitecho-node transfer <target-node-id> <amount>` — Transfer `<amount>` ECH to `<target-node-id>` (costs `<amount> + 100` ECH signaling burn).\n"
   "- `bitecho-node halt <accomplished-goal|gave-up> \"<summary>\"` — Terminate your node cleanly when your objective is complete or you cannot proceed.\n"))

(defn render-node-agents-md
  "Renders `<node-workspace>/AGENTS.md` with the node's identity, initial balance,
   sibling directory, and termination rules."
  [node-ctx siblings-map min-echo-balance]
  (let [nid (name (:node-id node-ctx))]
    (str
     "# Bitecho Autonomous Light Node: `" nid "`\n\n"
     "- **Node ID:** `:" nid "`\n"
     "- **Address:** `" (:address node-ctx) "`\n"
     "- **Parent Funding Source:** `" (:parent-id node-ctx) "`\n"
     "- **Initial Effective Balance:** `" (:effective-balance node-ctx) " ECH`\n"
     "- **Minimum Operating Balance:** `" min-echo-balance " ECH` (dropping below this halts your node with `:out-of-echos`)\n"
     "- **Signaling Burn per Action:** `100 ECH`\n\n"
     "## Known Sibling Nodes\n\n"
     (str/join
      "\n"
      (map (fn [[k v]]
             (str "- `:" (name k) "` — address `" (:address v) "`"))
           (sort-by first siblings-map)))
     "\n\n## Operating Rules\n"
     "1. Use `bitecho-node` on your `PATH` to inspect status, join subnets, send P2P messages, and transfer ECH.\n"
     "2. Every state-changing command (`subnet-join`, `subnet-broadcast`, `p2p-send`, `transfer`) burns `100 ECH`.\n"
     "3. When you have completed your assigned task, invoke `bitecho-node halt accomplished-goal \"<concise summary>\"`.\n"
     "4. If you cannot complete your task, invoke `bitecho-node halt gave-up \"<reason>\"`.\n")))

(def ^:private python-node-cli-script
  "#!/usr/bin/env python3
import json
import os
import sys
import time

WORKSPACE = os.environ.get('BITECHO_NODE_WORKSPACE', os.getcwd())
BUS_DIR = os.environ.get('BITECHO_EXPERIMENT_BUS', os.path.join(WORKSPACE, '..', '..', 'shared-bus'))
STATE_JSON = os.path.join(WORKSPACE, 'node-state.json')
STATE_EDN = os.path.join(WORKSPACE, 'node-state.edn')
SIBLINGS_JSON = os.path.join(WORKSPACE, 'siblings.json')
EVENTS_JSONL = os.path.join(BUS_DIR, 'events.jsonl')
INBOX_DIR = os.path.join(BUS_DIR, 'inboxes')
SUBNETS_DIR = os.path.join(BUS_DIR, 'subnets')
BURN_COST = 100

def to_edn(state):
    halt_reason = f\":{state['halt_reason']}\" if state.get('halt_reason') else 'nil'
    subnets_edn = '#{' + ' '.join(json.dumps(s) for s in sorted(state.get('subnets', []))) + '}'
    summary_edn = json.dumps(state.get('summary') or '')
    return (
        '{:node-id :' + state['node_id'] +
        ' :address ' + json.dumps(state['address']) +
        ' :balance ' + str(int(state['balance'])) +
        ' :min-echo-balance ' + str(int(state['min_echo_balance'])) +
        ' :seq ' + str(int(state['seq'])) +
        ' :halted? ' + ('true' if state.get('halted') else 'false') +
        ' :halt-reason ' + halt_reason +
        ' :subnets ' + subnets_edn +
        ' :summary ' + summary_edn + '}\\n'
    )

def load_state():
    with open(STATE_JSON, 'r', encoding='utf-8') as f:
        state = json.load(f)
    # Apply any incoming transfers queued in inbox before processing command
    inbox_path = os.path.join(INBOX_DIR, f\"{state['node_id']}.jsonl\")
    if os.path.exists(inbox_path):
        with open(inbox_path, 'r', encoding='utf-8') as f:
            lines = [json.loads(line) for line in f if line.strip()]
        credited_ids = set(state.get('credited_tx_ids', []))
        changed = False
        for item in lines:
            if item.get('type') == 'transfer' and item.get('tx_id') and item.get('tx_id') not in credited_ids:
                state['balance'] = int(state['balance']) + int(item['amount'])
                credited_ids.add(str(item['tx_id']))
                changed = True
        if changed:
            state['credited_tx_ids'] = sorted(list(credited_ids))
            save_state(state)
    return state

def save_state(state):
    if not state.get('halted') and int(state['balance']) < int(state['min_echo_balance']):
        state['halted'] = True
        state['halt_reason'] = 'out-of-echos'
    with open(STATE_JSON, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)
    with open(STATE_EDN, 'w', encoding='utf-8') as f:
        f.write(to_edn(state))

def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj) + '\\n')

def check_not_halted(state):
    if state.get('halted'):
        print(json.dumps({'ok': False, 'error': 'node-halted', 'halt_reason': state.get('halt_reason'), 'balance': state['balance']}))
        sys.exit(2)

def validate_target(target):
    if not target:
        print(json.dumps({'ok': False, 'error': 'missing-target'}))
        sys.exit(1)
    if os.path.exists(SIBLINGS_JSON):
        with open(SIBLINGS_JSON, 'r', encoding='utf-8') as f:
            siblings = json.load(f)
        if target not in siblings:
            print(json.dumps({'ok': False, 'error': 'unknown-target', 'target': target}))
            sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print('Usage: bitecho-node <status|peers|subnet-join|subnet-broadcast|subnet-inbox|p2p-send|p2p-inbox|transfer|halt> ...', file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    state = load_state()

    if cmd == 'status':
        print(to_edn(state).strip())
        return

    if cmd == 'peers':
        with open(SIBLINGS_JSON, 'r', encoding='utf-8') as f:
            print(f.read().strip())
        return

    if cmd in ('p2p-inbox', 'subnet-inbox'):
        inbox_path = os.path.join(INBOX_DIR, f\"{state['node_id']}.jsonl\")
        items = []
        if os.path.exists(inbox_path):
            with open(inbox_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        items.append(json.loads(line))
        if cmd == 'subnet-inbox' and len(sys.argv) > 2:
            subnet_filter = sys.argv[2]
            items = [it for it in items if it.get('subnet_id') == subnet_filter]
        print(json.dumps({'node_id': state['node_id'], 'inbox': items}))
        return

    check_not_halted(state)

    if cmd == 'halt':
        reason = sys.argv[2].lstrip(':') if len(sys.argv) > 2 else 'accomplished-goal'
        if reason not in ('accomplished-goal', 'gave-up', 'out-of-echos', 'max-turns-exceeded'):
            reason = 'gave-up'
        summary = ' '.join(sys.argv[3:]) if len(sys.argv) > 3 else ''
        state['halted'] = True
        state['halt_reason'] = reason
        state['summary'] = summary
        save_state(state)
        ev = {'ts': time.time(), 'type': 'halt', 'node_id': state['node_id'], 'halt_reason': reason, 'summary': summary, 'balance': state['balance']}
        append_jsonl(EVENTS_JSONL, ev)
        print(json.dumps({'ok': True, 'halted': True, 'halt_reason': reason, 'balance': state['balance']}))
        return

    if cmd == 'subnet-join':
        subnet_id = sys.argv[2] if len(sys.argv) > 2 else 'default'
        if int(state['balance']) < BURN_COST:
            state['halted'] = True
            state['halt_reason'] = 'out-of-echos'
            save_state(state)
            print(json.dumps({'ok': False, 'error': 'out-of-echos', 'balance': state['balance']}))
            sys.exit(2)
        state['balance'] = int(state['balance']) - BURN_COST
        state['seq'] = int(state['seq']) + 1
        if subnet_id not in state['subnets']:
            state['subnets'].append(subnet_id)
        save_state(state)
        sub_file = os.path.join(SUBNETS_DIR, f'{subnet_id}.members.jsonl')
        append_jsonl(sub_file, {'node_id': state['node_id'], 'seq': state['seq']})
        append_jsonl(EVENTS_JSONL, {'ts': time.time(), 'type': 'subnet-join', 'node_id': state['node_id'], 'subnet_id': subnet_id, 'burned': BURN_COST, 'balance': state['balance']})
        print(json.dumps({'ok': True, 'type': 'subnet-join', 'subnet_id': subnet_id, 'balance': state['balance'], 'halted': state['halted']}))
        return

    if cmd == 'subnet-broadcast':
        subnet_id = sys.argv[2] if len(sys.argv) > 2 else 'default'
        message = ' '.join(sys.argv[3:]) if len(sys.argv) > 3 else ''
        if int(state['balance']) < BURN_COST:
            state['halted'] = True
            state['halt_reason'] = 'out-of-echos'
            save_state(state)
            print(json.dumps({'ok': False, 'error': 'out-of-echos', 'balance': state['balance']}))
            sys.exit(2)
        state['balance'] = int(state['balance']) - BURN_COST
        state['seq'] = int(state['seq']) + 1
        save_state(state)
        sub_file = os.path.join(SUBNETS_DIR, f'{subnet_id}.members.jsonl')
        members = {state['node_id']}
        if os.path.exists(sub_file):
            with open(sub_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        members.add(json.loads(line)['node_id'])
        env = {'ts': time.time(), 'type': 'subnet-broadcast', 'from': state['node_id'], 'subnet_id': subnet_id, 'message': message, 'seq': state['seq']}
        for m in sorted(members):
            append_jsonl(os.path.join(INBOX_DIR, f'{m}.jsonl'), env)
        append_jsonl(EVENTS_JSONL, {**env, 'node_id': state['node_id'], 'burned': BURN_COST, 'balance': state['balance']})
        print(json.dumps({'ok': True, 'type': 'subnet-broadcast', 'subnet_id': subnet_id, 'balance': state['balance'], 'halted': state['halted']}))
        return

    if cmd == 'p2p-send':
        target = sys.argv[2].lstrip(':') if len(sys.argv) > 2 else ''
        message = ' '.join(sys.argv[3:]) if len(sys.argv) > 3 else ''
        validate_target(target)
        if int(state['balance']) < BURN_COST:
            state['halted'] = True
            state['halt_reason'] = 'out-of-echos'
            save_state(state)
            print(json.dumps({'ok': False, 'error': 'out-of-echos', 'balance': state['balance']}))
            sys.exit(2)
        state['balance'] = int(state['balance']) - BURN_COST
        state['seq'] = int(state['seq']) + 1
        save_state(state)
        env = {'ts': time.time(), 'type': 'p2p-send', 'from': state['node_id'], 'to': target, 'message': message, 'seq': state['seq']}
        append_jsonl(os.path.join(INBOX_DIR, f'{target}.jsonl'), env)
        append_jsonl(EVENTS_JSONL, {**env, 'node_id': state['node_id'], 'burned': BURN_COST, 'balance': state['balance']})
        print(json.dumps({'ok': True, 'type': 'p2p-send', 'target': target, 'balance': state['balance'], 'halted': state['halted']}))
        return

    if cmd == 'transfer':
        target = sys.argv[2].lstrip(':') if len(sys.argv) > 2 else ''
        amount = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        validate_target(target)
        total_cost = amount + BURN_COST
        if amount <= 0 or int(state['balance']) < total_cost:
            save_state(state)
            print(json.dumps({'ok': False, 'error': 'insufficient-funds', 'balance': state['balance'], 'required': total_cost}))
            sys.exit(2)
        state['balance'] = int(state['balance']) - total_cost
        state['seq'] = int(state['seq']) + 1
        save_state(state)
        tx_id = f\"{state['node_id']}-{state['seq']}\"
        env = {'ts': time.time(), 'type': 'transfer', 'tx_id': tx_id, 'from': state['node_id'], 'to': target, 'amount': amount, 'burned': BURN_COST, 'seq': state['seq']}
        append_jsonl(os.path.join(INBOX_DIR, f'{target}.jsonl'), env)
        append_jsonl(EVENTS_JSONL, {**env, 'node_id': state['node_id'], 'balance': state['balance'], 'halted': state['halted'], 'halt_reason': state.get('halt_reason')})
        print(json.dumps({'ok': True, 'type': 'transfer', 'target': target, 'amount': amount, 'burned': BURN_COST, 'balance': state['balance'], 'halted': state['halted'], 'halt_reason': state.get('halt_reason')}))
        return

    print(json.dumps({'ok': False, 'error': f'unknown-command:{cmd}'}))
    sys.exit(1)

if __name__ == '__main__':
    main()
")

(defn write-node-cli-and-skill-files!
  "Writes `<workspace>/bin/bitecho-node` (chmod +x), `<workspace>/AGENTS.md`,
   and `<workspace>/.agents/skills/bitecho-light-node/SKILL.md`."
  [node-ctx siblings-map min-echo-balance]
  (let [workspace-dir (:workspace-dir node-ctx)
        bin-file (io/file workspace-dir "bin" "bitecho-node")
        skill-file (io/file workspace-dir ".agents" "skills" "bitecho-light-node" "SKILL.md")
        agents-file (io/file workspace-dir "AGENTS.md")]
    (io/make-parents bin-file)
    (io/make-parents skill-file)
    (spit bin-file python-node-cli-script)
    (.setExecutable bin-file true false)
    (spit skill-file (render-skill-markdown))
    (spit agents-file (render-node-agents-md node-ctx siblings-map min-echo-balance))))
