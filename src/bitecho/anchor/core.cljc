(ns bitecho.anchor.core
  "Human Anchor state & command reducer for own keys, DAC management,
   service pricing, human-in-the-loop offer approval/denial, supervised agent tracking,
   emergency DAC revocation, petnames with Bech32m, and team-call subnets (Milestone 11)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.bech32m :as bech32m]
            [bitecho.fido :as fido]
            [bitecho.light-node.core :as light-core]
            [bitecho.webauthn :as webauthn]))

;;; ---------------------------------------------------------------------------
;;; Initial Anchor State
;;; ---------------------------------------------------------------------------

(defn init-anchor-state
  "Initializes Human Anchor state wrapping light-node core with human-in-the-loop policy.
   Default policy enforces autonomous? false (human approval required)."
  ([] (init-anchor-state {} {}))
  ([identity-pub-map] (init-anchor-state identity-pub-map {}))
  ([identity-pub-map opts]
   (let [base-node (light-core/init-light-state (or identity-pub-map {}) (merge {:autonomous? false} opts))
         key-mode (or (:key-mode opts) :yubikey-discoverable)
         anchor-pub (:pubkey base-node)
         anchor-addr (when anchor-pub (bech32m/pubkey->bech32m anchor-pub "ech"))]
     (assoc base-node
            :anchor/role :human-anchor
            :key-mode key-mode
            :anchor-pubkey anchor-pub
            :anchor-address anchor-addr
            :hot-pubkey (or (:hot-pubkey opts) anchor-pub)
            :active-dac (:dac base-node)
            :privkey-bytes (:privkey-bytes opts)
            :service-offers (or (:service-offers opts) {})
            :pending-offers (or (:pending-offers opts) [])
            :supervised-agents (or (:supervised-agents opts) {})
            :offers-approved 0
            :offers-denied 0
            :last-denied-reason nil
            :fido-strength (fido/evaluate-authenticator-strength
                            {:aaguid (or (:aaguid opts) "2fc0579f-8113-47ea-b116-bb5a8db9202a")
                             :up? true :uv? true :be? true :bs? false})
            :team-call-subnet nil))))

;;; ---------------------------------------------------------------------------
;;; Service Offers & Human Approval/Denial
;;; ---------------------------------------------------------------------------

(defn set-service-offer
  "Configures a service offer with price and burn floor in the anchor menu."
  [state service-id {:keys [name price burn-floor description]}]
  (assoc-in state [:service-offers (keyword service-id)]
            {:service-id (keyword service-id)
             :name (or name (clojure.core/name service-id))
             :price (or price 10)
             :burn-floor (or burn-floor 100)
             :description (or description "")}))

(defn queue-incoming-offer
  "Queues an incoming offer into pending-offers for human inspection and approval."
  [state offer]
  (let [offer-id (or (:offer-id offer) (:session-id offer) (str "offer-" (count (:pending-offers state))))
        offer-record (assoc offer :offer-id offer-id
                            :queued-at (or (:epoch state) 0))]
    (update state :pending-offers (fnil conj []) offer-record)))

(defn approve-offer
  "Human-in-the-loop action: approves a pending offer.
   Removes offer from pending-offers, increments :offers-approved,
   and returns [new-state effects]."
  [state offer-id & [accept-opts]]
  (let [pending (:pending-offers state)
        matching (first (filter #(= (:offer-id %) offer-id) pending))]
    (if-not matching
      [state [{:effect :diagnose :reason :offer-not-found :offer-id offer-id}]]
      (let [new-pending (vec (remove #(= (:offer-id %) offer-id) pending))
            new-state (-> state
                          (assoc :pending-offers new-pending)
                          (update :offers-approved (fnil inc 0)))
            effect {:effect :accept-offer
                    :offer-id offer-id
                    :peer-id (:peer-id matching)
                    :accepted-at (or (:epoch state) 0)
                    :opts accept-opts}]
        [new-state [effect]]))))

(defn deny-offer
  "Human-in-the-loop action: denies a pending offer with an explicit reason.
   Removes offer from pending-offers, increments :offers-denied,
   and returns [new-state effects]."
  [state offer-id & [reason]]
  (let [pending (:pending-offers state)
        matching (first (filter #(= (:offer-id %) offer-id) pending))
        rej-reason (or reason "denied-by-human-anchor")]
    (if-not matching
      [state [{:effect :diagnose :reason :offer-not-found :offer-id offer-id}]]
      (let [new-pending (vec (remove #(= (:offer-id %) offer-id) pending))
            new-state (-> state
                          (assoc :pending-offers new-pending)
                          (assoc :last-denied-reason rej-reason)
                          (update :offers-denied (fnil inc 0)))
            effect {:effect :diagnose
                    :reason :offer-denied-by-anchor
                    :offer-id offer-id
                    :peer-id (:peer-id matching)
                    :denial-reason rej-reason}]
        [new-state [effect]]))))

;;; ---------------------------------------------------------------------------
;;; Supervised Agent Management & DAC Revocation
;;; ---------------------------------------------------------------------------

(defn register-supervised-agent
  "Registers an autonomous or semi-autonomous agent supervised by this human anchor.
   Issues or binds a cold-certifies-hot DAC."
  [state {:keys [agent-id hot-pubkey dac permissions max-spend scopes issued-epoch expires-epoch]}]
  (let [anchor-pub (:anchor-pubkey state)
        agent-key-hex (cond
                        (string? hot-pubkey) hot-pubkey
                        (some? hot-pubkey) (basalt/bytes->hex hot-pubkey)
                        :else nil)
        effective-dac (or dac
                          (when (and (:privkey-bytes state) agent-key-hex anchor-pub)
                            (webauthn/cold-certify-hot-key
                             (:privkey-bytes state)
                             agent-key-hex
                             {:issued-epoch issued-epoch
                              :expires-epoch expires-epoch
                              :max-spend-per-epoch max-spend
                              :scopes scopes})))
        agent-record {:agent-id agent-id
                      :hot-pubkey agent-key-hex
                      :hot-address (when agent-key-hex (bech32m/pubkey->bech32m agent-key-hex "ech"))
                      :dac effective-dac
                      :status :active
                      :permissions (or permissions scopes [:offer :message :escrow])
                      :activity-log []
                      :registered-at (or (:epoch state) 0)}]
    (assoc-in state [:supervised-agents agent-id] agent-record)))

(defn log-agent-activity
  "Appends an activity event to a supervised agent's activity log."
  [state agent-id event]
  (if (get-in state [:supervised-agents agent-id])
    (update-in state [:supervised-agents agent-id :activity-log]
               (fnil conj [])
               (assoc event :logged-at (or (:epoch state) 0)))
    state))

(defn pause-agent
  "Pauses an agent's delegated authority."
  [state agent-id]
  (if (get-in state [:supervised-agents agent-id])
    (assoc-in state [:supervised-agents agent-id :status] :paused)
    state))

(defn resume-agent
  "Resumes an agent's delegated authority."
  [state agent-id]
  (if (get-in state [:supervised-agents agent-id])
    (assoc-in state [:supervised-agents agent-id :status] :active)
    state))

(defn revoke-agent-dac
  "Emergency revocation of a supervised agent's DAC.
   Immediately updates status to :revoked, constructs signed DAC revocation,
   records revocation in state, and returns [new-state effects]."
  [state agent-id & [reason]]
  (let [agent (get-in state [:supervised-agents agent-id])]
    (if-not agent
      [state [{:effect :diagnose :reason :agent-not-found :agent-id agent-id}]]
      (let [rev-reason (or reason "emergency-human-anchor-revocation")
            dac (:dac agent)
            dac-id (:dac-id dac)
            anchor-priv (:privkey-bytes state)
            anchor-pub (:anchor-pubkey state)
            agent-pub (:hot-pubkey agent)
            revocation (when (and anchor-priv anchor-pub agent-pub dac-id)
                         (light-core/create-dac-revocation
                          anchor-priv
                          {:anchor-pubkey anchor-pub
                           :agent-pubkey agent-pub
                           :dac-id dac-id
                           :revoked-epoch (or (:epoch state) 0)}))
            new-state (-> state
                          (assoc-in [:supervised-agents agent-id :status] :revoked)
                          (assoc-in [:supervised-agents agent-id :revocation] revocation)
                          (update :revoked-dacs (fnil conj []) (or revocation {:dac-id dac-id :reason rev-reason})))
            effects [{:effect :diagnose
                      :reason :supervised-agent-dac-revoked
                      :agent-id agent-id
                      :dac-id dac-id
                      :revocation-reason rev-reason}
                     {:effect :broadcast-dac-revocation
                      :agent-id agent-id
                      :dac-id dac-id
                      :revocation revocation}]]
        [new-state effects]))))

;;; ---------------------------------------------------------------------------
;;; Team-Call Subnet Management (Milestone 11A)
;;; ---------------------------------------------------------------------------

(defn create-team-call-subnet
  "Creates a team-call subnet state demonstrating how a team in a call forms a subnet.
   Supports zero or minimal burn floor for close collaboration."
  [state {:keys [topic-name peers burn-floor]}]
  (let [subnet-id (str "team-call/" (or topic-name "main-room"))
        subnet-record {:subnet-id subnet-id
                       :topic-name (or topic-name "main-room")
                       :peers (or peers [])
                       :burn-floor (or burn-floor 0)
                       :created-at (or (:epoch state) 0)
                       :status :active}]
    (assoc state :team-call-subnet subnet-record)))

;;; ---------------------------------------------------------------------------
;;; Unified Human Anchor Dashboard View
;;; ---------------------------------------------------------------------------

(defn anchor-dashboard-view
  "Computes a clean, presentation-ready view model of the Human Anchor dashboard."
  [state]
  (let [anchor-pub (:anchor-pubkey state)
        anchor-addr (or (:anchor-address state)
                        (when anchor-pub (bech32m/pubkey->bech32m anchor-pub "ech")))
        fido-hint (or (:fido-strength state)
                      (fido/evaluate-authenticator-strength (:aaguid state "2fc0579f-8113-47ea-b116-bb5a8db9202a")))
        supervised-summary (into {}
                                 (map (fn [[id a]]
                                        [id {:agent-id id
                                             :status (:status a)
                                             :address (:hot-address a)
                                             :dac-id (get-in a [:dac :dac-id])
                                             :activity-count (count (:activity-log a))}])
                                      (:supervised-agents state)))
        petnames-view (into {}
                            (map (fn [[k v]]
                                   [k {:pubkey v
                                       :address (bech32m/pubkey->bech32m v "ech")}])
                                 (or (:petnames state) {})))]
    {:identity {:anchor-pubkey anchor-pub
                :address anchor-addr
                :hot-pubkey (:hot-pubkey state)
                :key-mode (or (:key-mode state) :yubikey-discoverable)
                :active-dac-id (get-in state [:active-dac :dac-id])}
     :fido-authenticator {:strength (:strength fido-hint)
                          :score (:score fido-hint)
                          :verification-status (:verification-status fido-hint)
                          :label (:label fido-hint)
                          :warning (:warning fido-hint)
                          :yubico-enrollment (:yubico-enrollment fido-hint)}
     :accounting {:balance (get-in state [:accounts anchor-pub :balance] 0)
                  :burned-ech (or (get-in state [:local-accounting :burned-ech])
                                  (get-in state [:accounting :burned-ech])
                                  0)
                  :vouchers-count (or (some-> (get-in state [:local-accounting :vouchers]) count)
                                      (get-in state [:accounting :vouchers-count])
                                      0)
                  :offers-approved (:offers-approved state 0)
                  :offers-denied (:offers-denied state 0)}
     :pending-offers (vec (:pending-offers state []))
     :service-offers (:service-offers state {})
     :supervised-agents supervised-summary
     :petnames petnames-view
     :directory-cache (:directory-cache state {})
     :team-call-subnet (:team-call-subnet state)
     :trust-boundary webauthn/trust-boundary-disclosure
     :origin-scoping webauthn/origin-scoping-disclosure}))
