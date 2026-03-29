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

## Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus

**Overview:**
We propose separating the task of reliable transaction dissemination from transaction ordering, to enable high-performance Byzantine fault-tolerant quorum-based consensus. We design and evaluate a mempool protocol, Narwhal, specializing in high-throughput reliable dissemination and storage of causal histories of transactions. Narwhal tolerates an asynchronous network and maintains high performance despite failures. Narwhal is designed to easily scale-out using multiple workers at each validator, and we demonstrate that there is no foreseeable limit to the throughput we can achieve. Composing Narwhal with a partially synchronous consensus protocol (Narwhal-HotStuff) yields significantly better throughput even in the presence of faults or intermittent loss of liveness due to asynchrony. However, loss of liveness can result in higher latency. To achieve overall good performance when faults occur we design Tusk, a zero-message overhead asynchronous consensus protocol, to work with Narwhal. We demonstrate its high performance under a variety of configurations and faults. As a summary of results, on a WAN, Narwhal-Hotstuff achieves over 130,000 tx/sec at less than 2-sec latency compared with 1,800 tx/sec at 1-sec latency for Hotstuff. Additional workers increase throughput linearly to 600,000 tx/sec without any latency increase. Tusk achieves 160,000 tx/sec with about 3 seconds latency. Under faults, both protocols maintain high throughput, but Narwhal-HotStuff suffers from increased latency.
**Link:** https://arxiv.org/abs/2105.11827

**Key Concepts and Algorithms:**
- **Separation of Concerns:** Separating the task of reliable transaction dissemination (mempool) from transaction ordering (consensus) to enable high-performance Byzantine fault-tolerant quorum-based consensus.
- **Narwhal:** A DAG-based mempool protocol specializing in high-throughput reliable dissemination and storage of causal histories of transactions. It tolerates an asynchronous network and maintains high performance despite failures.
- **Scale-out Architecture:** Narwhal is designed to easily scale-out using multiple workers at each validator, allowing for massive throughput increases without corresponding latency penalties.
- **Tusk:** A zero-message overhead asynchronous consensus protocol designed to work with Narwhal, achieving high performance and maintaining overall good throughput even when faults occur.
- **Narwhal-HotStuff:** Composing Narwhal with a partially synchronous consensus protocol (like HotStuff) to yield significantly better throughput even in the presence of faults or intermittent loss of liveness due to asynchrony.
