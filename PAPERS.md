# Papers

This document references the academic, theoretical foundation of the project.

## Basalt: A Rock-Solid Byzantine-Tolerant Peer Sampling for Very Large Decentralized Networks

**Overview:**
Basalt proposes a secure Random Peer Sampling (RPS) service designed to provide epidemic Byzantine-Fault-Tolerant (BFT) algorithms with a random stream of network nodes where malicious entities cannot become over-represented. It introduces a "stubborn chaotic search" to improve resilience against Eclipse attacks without relying on Proof-of-Stake mechanisms.
**Link:** https://inria.hal.science/hal-04394966/document

**Key Concepts and Algorithms:**
- **Random Peer Sampling (RPS):** A service that produces a random stream of node identifiers drawn uniformly from all nodes present in the network.
- **Byzantine-Fault Tolerance:** Ensures that despite the presence of malicious (Byzantine) nodes trying to manipulate the decisions of honest ones, the system maintains coordination and agreement.
- **Eclipse Attacks:** An attack where malicious nodes attempt to completely isolate an honest node by monopolizing all its incoming and outgoing connections. Basalt is specifically designed to resist these attacks.
- **Stubborn Chaotic Search:** A greedy epidemic procedure over node IDs using min-wise independent permutations. It makes it extremely hard for malicious nodes to manipulate the selection of correct nodes.
- **Elimination of Separate Views:** Unlike previous approaches like Brahms, which uses a separate dynamic view for candidates, BASALT directly uses the state of the chaotic search (nodes whose IDs best match random hash functions) to drive epidemic dissemination of IDs. This unified design provides an optimal and highly robust defense against Byzantine flooding.

## Contagion: Scalable Byzantine Reliable Broadcast

**Overview:**
Contagion proposes a scalable, probabilistic Byzantine reliable broadcast algorithm. It generalizes the traditional Byzantine reliable broadcast abstraction to allow failure with a fixed, arbitrarily small probability. By replacing heavy quorum systems with stochastic samples, the algorithm achieves logarithmic per-process communication and computation complexity rather than linear complexity.
**Link:** https://arxiv.org/abs/1908.01738

**Key Concepts and Algorithms:**
- **Byzantine Reliable Broadcast:** A primitive that ensures all correct processes agree on a message from a designated sender, even if some processes, including the sender, are Byzantine.
- **Probabilistic Byzantine Reliable Broadcast:** Relaxes standard broadcast properties by allowing them to be violated with an arbitrarily small probability, unlocking the use of stochastic methods instead of expensive quorum systems.
- **Stochastic Sampling vs. Quorums:** The algorithm replaces deterministic quorum intersections with stochastic sampling. Because samples are much smaller in size, the design scales significantly better, achieving logarithmic per-process complexity.
- **Adversary Decorators:** A novel analytical technique introduced to reason about the optimal strategy of a Byzantine adversary without making additional assumptions, allowing rigorous derivation of failure probability bounds.
- **Threshold Contagion:** A model of message propagation through a system containing Byzantine processes, analyzing how information spreads when a certain threshold of confirmation is required to forward a message.

### 1. Summary of SBRB Algorithms Detailed in the Paper
The paper *"Scalable Byzantine Reliable Broadcast"* introduces a highly scalable approach to bypass the $O(N)$ communication bottleneck of traditional quorum-based Byzantine consensus, reducing per-process communication to $O(\log N)$ by relying on probabilistic stochastic samples. It builds the broadcast stack in three distinct layers:

*   **Murmur (Probabilistic Broadcast):** A foundational epidemic gossip layer. A designated sender signs and broadcasts a message to a random sample of peers. Correct nodes verify the signature, deliver it upon first receipt, and forward it to their own random gossip sample ($G$). It guarantees *Validity* and *Totality* but **not** *Consistency* (a Byzantine sender can equivocate and cause different nodes to deliver validly signed but conflicting payloads).
*   **Sieve (Probabilistic Consistent Broadcast):** Upgrades Murmur to guarantee *Consistency* (no two correct nodes deliver different messages). Upon initialization, nodes select an **Echo Sample ($E$)** and **subscribe** to those peers. When a node receives a Murmur message, it sends an `Echo` strictly to its subscribers. A node only "Sieve-delivers" the message if it receives $\hat{E}$ matching Echoes from its chosen sample.
*   **Contagion (Probabilistic Reliable Broadcast):** Upgrades Sieve to guarantee *Totality* (preventing the network from stalling). Nodes select a **Ready Sample ($R$)** and a **Delivery Sample ($D$)** and subscribe to them. It uses a viral, epidemiological feedback loop:
    *   **Rule 1 (Infection):** If a node Sieve-delivers a message OR observes $\hat{R}$ "Ready" messages from its Ready Sample, it becomes "Ready" itself and notifies its subscribers.
    *   **Rule 2 (Delivery):** If a node observes $\hat{D}$ "Ready" messages from its Delivery Sample, it finalizes delivery to the application.
    *   Because $\hat{R}/R < \hat{D}/D$, the math guarantees that if even *one* honest node observes enough readiness to deliver, the entire honest network will eventually become infected by the "Ready" state and cascade into delivery.

## The Consensus Number of a Cryptocurrency

**Overview:**
This paper investigates the theoretical foundations of cryptocurrencies by treating the asset transfer problem as a concurrent object and analyzing its consensus number. It demonstrates that full consensus is not strictly necessary to prevent double-spending. The authors show that the consensus number of a basic single-owner asset transfer object is 1, and for a k-shared asset transfer object, the consensus number is k.
**Link:** https://arxiv.org/abs/1906.05574

**Key Concepts and Algorithms:**
- **Consensus Number:** A theoretical measure of the synchronization power of a concurrent object in distributed computing. Objects with consensus number 1 can be implemented in a purely asynchronous system without requiring a consensus mechanism.
- **Asset Transfer as a Concurrent Object:** By modeling an account from which only the owner can withdraw (as in Nakamoto's original definition) as a concurrent object, the paper establishes its consensus number is 1. This means double-spending can be prevented using asynchronous abstractions without full consensus.
- **k-shared Asset Transfer:** A generalized account where up to k processes can atomically withdraw. The paper proves that this object has a consensus number of k.
- **Asynchronous Byzantine Fault-Tolerant Implementation:** Building on these theoretical results, the paper describes a message-passing Byzantine Fault-Tolerant asset transfer algorithm that operates purely asynchronously. This implementation is simpler and more efficient than traditional consensus-based solutions (like Proof of Work or BFT consensus algorithms) for preventing double-spending.
- **Permissioned vs. Permissionless:** The results and derived algorithms are applicable to both public (permissionless) and private (permissioned) blockchain settings, as the fundamental properties depend on the abstraction of the asset transfer object rather than the underlying membership model.

## Streamlet: Textbook Streamlined Blockchains

**Overview:**
Streamlet proposes an extremely simple and natural paradigm for constructing permissioned consensus protocols. By taking the "streamlining" idea to its full potential, it unifies the classical propose-vote paradigm without the need for a complicated recovery path (like view-change in PBFT). The protocol is partially synchronous and partition tolerant, achieving consistency regardless of network delays and liveness with expected constant confirmation delay during periods of synchrony. This makes it highly suitable for pedagogy and practical implementation.
**Link:** https://eprint.iacr.org/2020/088

**Key Concepts and Algorithms:**
- **Streamlined Blockchains:** The entire protocol is streamlined into a unified path of continuous "propose-vote" actions, eliminating the distinct and complex view-change process.
- **Propose-Vote Paradigm:** In every epoch, a pseudo-randomly selected leader proposes a block extending from the longest notarized chain. Nodes vote for the first proposal they see from the leader that extends from the longest notarized chain.
- **Notarization vs. Finalization:** A block is *notarized* when it receives votes from at least 2n/3 distinct players. A block is *finalized* when there are three adjacent blocks in a notarized chain with consecutive epoch numbers; the prefix up to the second of the three blocks is then considered final.
- **Partially Synchronous and Partition Tolerant:** The protocol guarantees safety (consistency) no matter how adversarial the network delays are, ensuring it is partition-tolerant. Liveness is achieved when the network is synchronous.
- **Epoch Leader Rotation:** Leaders for each epoch are randomly chosen via a public hash function, removing the reliance on stable leader periods and increasing robustness against isolated failures.
