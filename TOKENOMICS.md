# **Bitecho Tokenomics & The Echo Economy**

This document defines the economic architecture, incentive structures, and mathematical parameters of the $ECHO token network. Designed specifically to facilitate high-frequency micro-transactions for autonomous AI agents without relying on global consensus bottlenecks, Bitecho's economic model executes across a distinct two-phase lifecycle:

* **Phase 1: Bootstrap (Burn-and-Mint Equilibrium):** A subsidized growth phase utilizing a probabilistic Treasury lottery and localized free-market burning to aggressively incentivize routing infrastructure and drive early adoption.  
* **Phase 2: Maturity (Asynchronous Direct Settlement):** A self-sustaining, steady-state endgame where the network sheds the BME complexity in favor of zero-latency, direct peer-to-peer payments and a simple stake-weighted tail emission.

## **1\. Macro-Economy & Genesis Allocation**

The network enforces a deterministic hard cap of **42,000,000,000 (42 Billion) $ECHO**. The system initializes from a pure genesis.edn state with the following allocations:

* **50% (21.0B): Decentralized Routing Treasury (Yield Pool).** Locked in a ![][image1]\-shared Streamlet BFT smart contract. Emitted via an Activity-Based Logarithmic Decay curve to subsidize routing infrastructure.  
* **20% (8.4B): Federated Genesis Partners.** Subsidizes the enterprise backbone of initial Full Nodes (1-year cliff, 3-year vest).  
* **15% (6.3B): Agent Ecosystem & Developer Grants.** Bootstrapping funds for developer adoption.  
* **15% (6.3B): Core Architecture & Protocol Security.** Bootstrapping funds for the core protocol (4-year vest).

## **2\. Asynchronous Settlement (Consensus Number 1\)**

To enable zero-latency streaming payments for WebRTC signaling and TURN relay, Bitecho leverages the academic principle that single-owner accounts have a Consensus Number of 1\.

* **No Global Ordering:** Micro-transfers are not sequenced in a global blockchain.  
* **Local State Execution:** AI Agents (Light Nodes) maintain a local, strictly incrementing sequence number (seq\[q\]) and cryptographic causal history.  
* **Instant Validation:** The receiving Full Node locally validates the signature, the \+1 sequence increment, and a balance \>= 0\. Services (like bandwidth relay) are provided immediately upon local validation.

## **3\. The Localized Free Market & The Burn**

The network decouples the "cost to use" from the "reward to route." Full Nodes do not collect the micro-fees paid by the agents; instead, those fees are strictly **burned** (removed from circulation).

* **Node-Advertised Pricing:** Full Nodes advertise their "Minimum Burn Requirement" via their Bloom filter routing broadcasts across the SBRB mesh.  
* **The Race to Zero:** Because Full Nodes earn their yield from the Treasury (not the user fee), they are incentivized to lower their Burn Requirement to attract maximum agent traffic. This localized free market pushes the cost of agent routing as close to zero as the spam-deterrence threshold allows.  
* **The Sybil Shield:** The burn mathematically prevents wash-routing. An attacker cannot route fake traffic through their own node to farm Treasury yield without destroying their own capital in the process.

## **4\. The Treasury Engine: Probabilistic Nanopayments**

To prevent the Streamlet BFT from being overwhelmed by millions of micro-receipts, the Treasury utilizes stake-weighted probabilistic payouts (lottery tickets).

### **A. The "Proof of Delivery" Receipt**

When a Full Node successfully relays an SDP offer to facilitate WebRTC Circuit Discovery & Client-to-Rendezvous Routing, the AI Agent signs a "Proof of Delivery" receipt.

*(Note: Continuous network services, such as TURN streaming, are settled via direct peer-to-peer micro-transfers between nodes and do not generate Treasury receipts.)*

Most receipts expire worthless. Only winning receipts are submitted to the Streamlet cluster for payout.

### **B. The Entropy Source**

The randomness required to determine if a receipt is a "winner" is derived internally from the consensus layer, requiring no external oracles.

* The entropy seed is the **Hash of the Last Finalized Streamlet Block**.  
* Because finalization requires three consecutive notarized blocks, the hash is unpredictable at the time the agent signs the receipt.

### **C. The Winning Condition**

A receipt is valid and eligible for payout if and only if it satisfies the following pure-functional cryptographic check:

;; Jules: Implement this in the pure state machine  
(\< (hash (concat receipt-signature finalized-block-hash)) current-target-difficulty)

### **D. Algorithmic Difficulty Adjustment (Emission Targeting)**

Similar to Bitcoin's hash difficulty, Bitecho adjusts the current-target-difficulty every epoch. However, Bitecho targets the Treasury's emission schedule, not a block time.

* ![][image2]: The predetermined number of $ECHO to emit this epoch (based on the logarithmic decay curve).  
* ![][image3]: The fixed $ECHO reward paid out per winning receipt.  
* ![][image4]: The target number of winning receipts (![][image5]).  
* ![][image6]: The estimated total network receipts generated, inferred from the previous epoch.

At the end of each epoch, the Streamlet BFT calculates the new difficulty target:

New Target \= Old Target \* (W\_target / Actual\_Winners\_Last\_Epoch)

*If an attacker wash-routes and spikes the network activity, the target difficulty algorithmically tightens, exponentially decaying the attacker's win probability while their burn cost remains linear.*

## **5\. Stake-Weighted Probabilities**

To further defend against Sybil attacks and align economic incentives, a Full Node's probability of winning is modified by its staked $ECHO.

* The current-target-difficulty for a specific node is positively scaled by a function of their locked stake.  
* To capture meaningful routing volume and Treasury yield, an operator must lock significant capital, directly tying the network's security to the token's market capitalization.

## **6\. Decentralizing the Streamlet Treasury**

The 21 Billion Yield Pool is a ![][image1]\-shared asset governed by the Streamlet BFT cluster.

* **Phase 1 (Permissioned):** The cluster is strictly operated by the Federated Genesis Partners to ensure high performance and stability during the bootstrap phase.  
* **Phase 2 (Dynamic Decentralization):** The protocol allows permissionless entry into the Streamlet cluster. To prevent early whales from achieving a permanent monopoly, the required stake to become a Genesis Partner is dynamically calculated as a fixed percentage of the **Circulating Supply**, rather than a static integer.

## **7\. Four-Year Vesting & Emission Modeling (Genesis to Year 4\)**

To project network economics through the end of the 4-year vesting period, we assume the following constants:

* **Treasury Target Emission:** \~17 Billion $ECHO released by Year 4 (logarithmic decay).  
* **Payout Per Winning Ticket (![][image3]):** 10,000 $ECHO.  
* **Target Winning Tickets (![][image4]):** \~1,700,000 tickets across 4 years (avg. \~1,164/day).  
* **Vesting Unlocks:** 8.4B (Partners), 6.3B (Core), 6.3B (Ecosystem) fully unlocked by Year 4\.  
* **Total Emitted & Vested by Year 4:** \~38 Billion $ECHO (Gross Supply before Burns).

We target an optimal hardware ratio of roughly **100,000 AI Agents to 1 Full Node**.

### **Scenario A: Low Adoption (The Private Swarm Baseline)**

*Network is utilized primarily by a small number of solopreneurs and enterprise orchestrators running private agent fleets.*

* **Active Agents:** 1,000,000 scaling to 5,000,000 by Year 4\.  
* **Full Nodes:** 10 scaling to 50\.  
* **Network Activity:** Agents average 10 connections/day. Total 4-year receipts generated: **\~40 Billion**.  
* **Treasury Difficulty Adjustment:** With lower volume, the algorithm expands the target hash. Winning probability settles around **1 in 23,500** per receipt.  
* **The Burn Rate:** Free-market competition is low; burn fee averages **0.01 $ECHO**.  
* **Net Tokenomics:** 40B receipts \* 0.01 \= **400 Million $ECHO burned**.  
* **Year 4 Circulating Supply:** \~37.6 Billion $ECHO. (Highly Inflationary; Nodes enjoy high probability yields).

### **Scenario B: Medium Adoption (B2B Enterprise Integration)**

*Network achieves strong product-market fit among enterprise SaaS and autonomous customer service sectors.*

* **Active Agents:** 10,000,000 scaling to 50,000,000 by Year 4\.  
* **Full Nodes:** 100 scaling to 500\.  
* **Network Activity:** Agents average 50 connections/day. Total 4-year receipts generated: **\~1.5 Trillion**.  
* **Treasury Difficulty Adjustment:** The algorithm tightens the target hash. Winning probability drops to **1 in \~880,000**.  
* **The Burn Rate:** Increased node competition drives the free-market burn fee down to **0.005 $ECHO**.  
* **Net Tokenomics:** 1.5T receipts \* 0.005 \= **7.5 Billion $ECHO burned**.  
* **Year 4 Circulating Supply:** \~30.5 Billion $ECHO. (Approaching equilibrium; deflationary pressure begins to offset emissions).

### **Scenario C: High Adoption (The Global Agent Standard)**

*Bitecho becomes the default P2P signaling layer for Web3 and mainstream AI agents globally.*

* **Active Agents:** 50,000,000 scaling to 500,000,000 by Year 4\.  
* **Full Nodes:** 500 scaling to 5,000.  
* **Network Activity:** Agents average 100 connections/day (high-frequency streams/negotiations). Total 4-year receipts generated: **\~15 Trillion**.  
* **Treasury Difficulty Adjustment:** Network volume explodes. Target hash tightens severely. Winning probability plummets to **1 in 8.8 Million**.  
* **The Burn Rate:** Hyper-competition among 5,000 nodes racing to capture volume drives the burn requirement down to **0.001 $ECHO**.  
* **Net Tokenomics:** 15T receipts \* 0.001 \= **15 Billion $ECHO burned**.  
* **Year 4 Circulating Supply:** \~23 Billion $ECHO. (Deflationary Singularity: Massive burn rates neutralize vesting schedules and Treasury emissions, driving extreme capital scarcity).

## **8\. The Steady State Transition (Phase 2: Maturity)**

The network is architected with a two-phase lifecycle. Once the primary Treasury emission schedule exhausts, the network drops the complexity of the Burn-and-Mint Equilibrium and drops into a purely asynchronous, direct-payment mesh network.

### **A. The Asynchronous Endgame (Direct Payments)**

Based on the "Consensus Number of a Cryptocurrency" model, AI agents are the sole owners and authors of their local state (their balance and strictly incrementing sequence number). Transferring that local value to a node requires a consensus number of 1\.

* **Zero Global State:** The Streamlet cluster is no longer needed to order these routing micro-transactions.  
* **Pure Local Execution:** The receiving Full Node simply evaluates a pure-functional state transition: validating the signature, ensuring seq\[q\] \== last\_seq \+ 1, and verifying sufficient balance. If successful, the WebRTC signaling is executed immediately.

### **B. Dissolution of the Sybil Threat**

The original Burn-and-Mint Equilibrium and probabilistic lottery mechanisms were specifically designed to protect the Treasury from being drained by wash-routing. Once the Treasury exhausts, there is no "free money" to farm. If a node operator spins up fake agents to route traffic through their own node, they are simply paying themselves and losing capital to standard network friction. Direct peer-to-peer payments inherently neutralize the Sybil threat.

### **C. Stake-Weighted Tail Emission**

To maintain an economic floor and offset deflationary pressure in maturity, the probabilistic receipt lottery is replaced with a simple, periodic stake-weighted tail emission.

* **Computational Simplicity:** Instead of calculating cryptographic hashes against target difficulties for every micro-transaction, the network simply snapshots the staked balances at the end of an epoch and distributes the tail emission proportionally.  
* **Economic Floor:** This acts as a baseline "Proof of Stake" yield. It incentivizes Full Nodes to lock up capital and keep their high-bandwidth routing infrastructure online, even during periods of low local network activity.

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAAAYCAYAAAAs7gcTAAAA7ElEQVR4XmNgGMJASkqKS05OzkVeXv6/goLCIXR5DABUbA1SDMTN6HIYAKioBqQYqMkGXQ4DABXuBuI3QCYzuhwKALkZqPA7EK8G8YGmlwHxBqD7NwFpQRTFQAFXqHuzVFRU2IF0CogNxD+BOBBdcRtUsREQrwGJgUwFsj/KysoqoygGCh4HKQZq2gmkNVEkkQHQhACoqUlQfgRQUzmIraysLAZ0Fh9cMVBRL0ixjIyMCpRvBcRZUI2bpKWlZeCKgQKngJJ3YXxFRUV9oMkhQKwFFF8MVwgCQIGbQNyEJvYEiPcBNYoji48C2gMAWkM4Ay7/cRIAAAAASUVORK5CYII=>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADQAAAAZCAYAAAB+Sg0DAAACuElEQVR4Xu2XS2hTQRSGb1Nf+EQ0RvO4kxfEBnGRiOBOBBdalIq7LhTtQkR8NYIvEMGdxceioKW0iBspKOJGUUEXou50reBGJFYQBIWCFKnfaWbo3CEoaAj3Qn74mXP+OTNz5s7J3BvP66CDDlqJmFLqO5z5G7PZ7BN3cGihk/5crVbni18sFhfm83kfreL7/j74Ed5yhoUXekN7bY0NVI3N6Zyhf8DuDzVIdpoTWWF8NrMS7bXVfzCXy202fqiRyWQ2kPBLS5rHiUygXbG06IDEj+iSC5BT2uXGRgIkf4cT6cOMUVa4ql82ZJdgpEDy9WQyudr4hUJhDdor43PjLVdRKT9OZKOchqMl0HYYH/sUrFn+TmO3G/I6cbUA+J0cdzdkI5FILCHmfSqVWmU0FbxA2oZ0Op2SanH1AEju3h821EXfGBy3RX5vF22/XWDdA64WQLlcXkCyk802hNZjNsu1vklre+BTOSEmH7Fie+FteJnTvED7SOtX4TNYk3j6HiPH9LAu/KMSQ3sdnrbmG8S/STskxM7rdb9IWyqVlplYM2ALnFJNruomfGuPJbH1dh3Tvw1+oyTT2h+Go2LLwtiTjDkE92N/QO6WPpI8pr8NpQrq+pYV/Qb+ebHlckJ/0Fhpdu5Pxm4ZWOCk7bPIC3nClv8c9mu7An8wZtHcCM+Lx+NL5SEofbnQzvCQ4lIJ2D+lpOFheAJmJUY+w+j7as/TEjDpfd2uo+mm/UUiu0XT1/u09KElpYywHwYm8GaT244+ZTaqdBWoxgv+TTC6AfRB4idkXrfvv8DEQ/L0eG8t1n6vnBDaWewBeBeOSQnS1mHFnUMgydE3ythryvooxq7BcThMzIgpZew+1fhN98zNEkKQ6NrIfpEI5GR5yu/YyFbxsc85IdGCflVISV2S1o/Sn8YO/hG/AWgwxI4U99x8AAAAAElFTkSuQmCC>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADkAAAAZCAYAAACLtIazAAACp0lEQVR4Xu2XW4iNURTHx8y4FEo4js5tf+eiM50H5JRSlPKglMuLSF7kUqMmilGmBsk1oRS5hkkOyqQGD8ibEi+eyBNlklJjKA+88FvzrX3adjxNydb3r9Xa+/9f+7L2Xt/3ndPSkiBBgn8ZrcaYz9iPP9hwFEVXU6nUJH9gcCCZedjrWq02znIkNwFukyb7GKrdGRIe5LawNT4vIMFXkmihUNjia0GBJN6S5EyfLxaLxpZuNpvN+XowyOVysyQJnxeQ+FFNstfXggIJbPSTLJfLM+B6sG8kut3VggTP2hVbko59wk5RrrP9+CBBMoP+Tf5X4KaqenODvhYC2PcL7CPNVl9rQj4LmuR5XwsB7L+Ld8Ytn/8FJHddk1znayGAfT8iyU6fd9FG0JAmWfRFB2PQD2APOblt+D4mjkTg81Ohfwn+ML4hn6NKpTJe4+9hyyTOnjb+JrbPTsy45friOyY8vl++x/gTsh62E/4c/q4dIzpjbsCdwb6jd1itCci5iF+N90b14yyYcAljFhNzm/ZlmVSSkzcv3HN8WuP2oC2F685kMtPx9+HWi0b7oMbskk3beeGH8vl8RmMuwp3E91Sr1cmiEbtBH6mXEqP8G1lHx7wTP2rIJvR25NYXWJ72gIlvtwu/g4VXCY+POISpcF849WnKjWyKA5lD/GYd/wQ77sz3lLVWyK8sbD794Xq9PtbqGrOfuZ45/T5XHxXY2EJZlGab5eh/YMGVTlgTevoD0pYSTqfTE6VNfGepVCrQbDdxBY2UsxyGiUtvisbtZo47zQkV8A+wI7ZPzGpbCaMGG2hgW11On8drUfzTr4FfazUpYRM/M71s5JCcOH6vuyG5NVueJv63049dEA3//nc/RFijgzFndc1u7DTzLPLjEiRIkOCv4yfTacFL7nmklAAAAABJRU5ErkJggg==>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADgAAAAZCAYAAABkdu2NAAADAklEQVR4Xu2XXYiMURjHd9ol3ynGtPP1mpllay+42IgLSmJDKLnBhbJ7QYstbL5KSok2XPlYtJH2hqwkN7SubCRtLtRya2tD2kibrMTvmfd5Z585TZmbYSbzr6dzzv95znnOf87He6ampooqqvjn8DxvCPtlTfl1Lo99nQ/En0gkMtaXTCb35Q1cTmDOm3WiL10f3HP1tRM3pYC/Kx6PL3D5soKsiq7CO8vrKn0RHyF7rE8Af8vlyhINDQ2zdJXGLI+obkRfVoFHrQ9uOdwZy5U1mPAPERKNRqdJO5VKraXdJsJUfJcJD9F+EA6HZxiuvMGEh0VIJpNJNDU1TUbYzRpfSLsK7DGxu/DvNN3LH0x6UISwcosoOymXKr9dBd6VNnyEel9+7woAk+5XIauwq4YPPhf92u7l8lky0bNCICskQrhUtmLpgJeVVIGDci7xXbH9LNi2LbK9Xb7UKCqvrJoI0bOXQzqdXqgCR7AnXEJzrT8AcUn83yORyHTXV2oUlRdhZ1XIe8vzCQkrX/BbGMDzL55HLv83UFRego6okL2OqxbuJ/aKep3jCx4Dj7GP2Gup87KZKj6280bZEXBd1E8IF4vF4rTPa58D+LspH5ohQ8R2yFGAv2jmIzd6J3ZJxzttcuflLQgSbSPoKdVa1wf/hsFWuLyBJB9hjGUBwQRWw43SLypt6te1PKYPi1GsFWvDhky/Ds8XLGN+or1G+12jfljr9d7ETR6yeUsCuVVJ+IFqKOBoD2DnTPuZlFxUnsZ/di+GxsbGmcKLKFYjRn1cHhMigPo3ypPYbvz75cxLH73Rc3lLApIfxHq1Xk9R5/nbfb1wbMs5nr/NxZc9Dth9M0QWcC3EjDU3N0+i3IENCO/5D/0XbrxAcmuZHbskYPAt2B2sNfhnwS+7iV/6Atxxz9+G93glzdP4EVZycf4oPvD16bkcwzYY/hDW4/nnUs5hVpDmzuWtGDDp8T9e/ZUEeeQj6i0ru1LarOJtN6aiIReObsFTbO0bCJztxlTxv+E3423kvzsMQn8AAAAASUVORK5CYII=>

[image5]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHYAAAAZCAYAAADkBdqeAAAFZUlEQVR4Xu2Za4ydQxjHz7Z1v1/W6t7m7IVNt0hlJUJ8IErTILQSDR+oa9a1aUtZy6pe2F5SUWWF7pZg49qG0hZLIq0mbIIP0i/tIhJFfSBEmtXI+v2dZ9oxPefQbLM5r77/5Mk8z/+ZmXee88zMO/OeTCZFihQpUqQYOTjnFsbcgYJRBP8bMvQfZHXcuNTBmK/Mw52ZJ7ZQfkDmUbUsbps4KKDa2tpvUUfLbmxsPKSurs7BtWSz2evxf4/eFTUrabS0tBzU3Nx8cMx7EFer4qZ81XPV1dXHwy20BC8P6ycSFuDlIVdTU3OW10nqQ/ivDv2lDsb7VsyFIOatlsC6kK+vrz/GeMm5oS9xIIDBpqamo7zd0NBwEsn8yNua3azgM7xd6iCesUh/zHsomZa4gdinCW6+7ZhjYn9iwPZzephEbWEEtcYl+OBBctoY/x0x74H/OiWPuJ+LfXDvWmKnxr5EgQBut0D+IQR4UVw3IShj/Fu0pcYOD/zPKEadHzzHBD8FrgfZgVwS1k8kCO4VC2QUepaEXov9R0VFxRFx3SSA8U9k/C/EfAj8A+EkNvkGmV9VVVUd108idN35KXq/1sB96G0CPYF8d3q71KGkktwLY96DQ2GDJXJH5v9wpckHZ3e6kGNLqgq3YfztJPbWwJ7s9ZEG45gUcyHsRLs1UyRh+G+wxPbGviSA32ACY/8lU+xgRwJnxIkNwX32aPzbVHoOe1NYZ6SgLZJn74r5EATdisyN+RA6MFlib4p9SUH2X65yStLrRRKrQ8iLyIqQ1J02tEcKttL6Yj4E/s36sBLzIfQhRjFT1se+pIDEzoy53dDXJZc7Ae6VWN5Dp9H4Tfmki0OfiryPbEKesqo6cM3EfhZZhizxKwZ9Mvrz/ICPoK9EX+T71zsd+3H4+cgTyNueR18uH+2eppxm70Q9V2P9stChjm34VPwfxHyIbG4bG3K5O2pB6HVk8fQhs13uFL0OVxm+RvSVjO9Rl5v44/SFi74fVh34y9QH9hUq4bqRpb5v/Jfqd4FbrEVC+Y7Vy/s8+Wy36qV+l8v9xhN8f7uB4xxkp9v7VJhPPo7ajtM919s8qANuY8b2e/QtWftChb4AGaTOeMoeylW+ncvdk9ul6x6tZ1lSN9P+fOv7POwl1kS7x3euyJcg2nVmg+tLCPq6xeKJZX1cV6CfNhvPj2qrftG3ZXKHzX7sk1UPvV2JROZUVlaeiL0W33Tz9ajEd6ezUzrlBcjP/uStyetskRR6nvFf6TnW5mbx0vcbssEWgH4sDxx0dpG3AexiK6yQbd+aN/j6Hkoc9XaqvdnTkE/h7lYwKml3F1xreXn5kaqD3eKKn2L1gw8UWs37Cv+dnD5/1c4W+uD6ND7K2dk9q7IO7jjK3/XVzrivVWonwTfDuI3ojwV9yb5KeqHn1eZW9RfeRl8W+vcL6HSNlfpkp9k35D8EaEZhf8bMPTzg5oTtBeos4Ad5L7BXaLDUfbnQoOFnuSKnWBJxMf7umB8OGON99Lk25uGmxJygleRsB7Ar498HPfqZzviaUEfD/anfyXgtjCFNBMqxRZ633u3ZuWT3q35YZ9igw6XIbWyfh5n9IAOaSzlPgVlydNgqQx+fyXMkt39QNDglc5WCE6fVid2lGS0e6aDvQ9WGOlOQ11yek6xdcT6P+eGCPrdn87zL4F+C76TsRa7xPCutHPtJ5AFkscu9hzvCw5ySqvjw3Y/ciLyBdHOOqCz0PE2K2tx5YxHlvfbbTIzrlRT0wzDIT2J+X0DAk+jnnphPMYIgCWeThAH70jUGfR0yK66XImGwd89qEtzGSt2g90rG/txPkSJFigMHfwGUeKqKOLXDaQAAAABJRU5ErkJggg==>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAAAZCAYAAAB5CNMWAAADY0lEQVR4Xu2XTUhUURTHHaXvLyOmSWecN+MMDAkVMS0KJZSIhFpEbYK+lb6kIqmQiCwjXJRWUFH0sZAsCpOgiD501YfUpoVBYES1sYhatSiwhf1O3ht3bk/Mmhb13h8O99z/Ofec9/7vvjd3cnJ8+PDh4x+G4zjvsH4X64vFYvcYV9prPA0RB2G6TS4SiYyB26OEu2TGPA0lyHIXfrqx02bbcU9C7ax8m49Go/VKqDY75knE43FHvk0mV1xcPAluCyL1Ya3hcHiKGfcs2D2rjFfth4mAxBba+Z4GwpxFlAV6nk6nR8B1wt0tLCwca+Z6HgjzyhaFXbVO7bCtJu9pFBUVJUQUm4fbKzy764wdGy44gszgGxg1OR5GOfV7cHNNPhtw6zcUuJYm7rXO5jNAUtUgYt1UYjXaseGCOs8Rp9LkmE+j9mqTyxbc+v0CAqybZ5MZIOHiIGL1KrG2yzyVSk1gXmDnDQWecpJ1n0Oh0Dg79jfwu/24zzKGPJs3kUfht4OI9Vh4OcHLXF5HbKOKnVB2jvgKvQY/BneIvP2MR6ByGXuU8B3wpclkchRpB/DvwC1W6yqZn2Zehb8Du4Ffzbg5NnB86WBca/SphTuPNUsfqSc8frvdTz1k1+slvgHuNnZYRs1ngKS08/NR4bWZwxMKy68h/DPskTSDDkhzGparOmXwzXoN/i3ObDMRZCL+e/LyGVtjSnAB/iY5sylBahTXwLpZzCtUnWXYB0f9YxDR8K8bNe7nqF2A3+0Y/13tfsy73K4XrtasA/9Gr8kaKLoT2yWvp9yEiGfE2kQkYscTicRUxX3UNy1gjey+AuwLogaFk0Mxa7YZdWS3tBhrWuCalC8P4PvfMrVrvko9lSo7OaMf/kv7etW6T7oOscmOy9v1x6DhVZsTsFsi3HSIpjXYNaxTeMZehoD8I9DHE7jdUkd2mBYb7rKuhf8wqj7+JSUlI0UA8ufKbsevkFoSI2cJ86dSVzh+2efY/cg5putqqB3Wr+tQeyncCz3PGoLB4HgaHcUu0KCeRqOFFwGY12GN+K26Mf4DuDXkLdI1ogOv9ym49TJH5JSjXgP8+fhdRm4p9gSuXcQSjnUNYnDVxK4wnoQOwMmuzegXHfgWul3vPuygrNV1pIbu68OHDx8+/nN8A1TYC24RZnySAAAAAElFTkSuQmCC>
