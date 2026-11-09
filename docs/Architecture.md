# AEALSF System Architecture & Five-Layer Specification

## 1. Architectural Overview

AEALSF preserves the embedded communication module security architecture introduced by Zhang et al. in [_Constructing Next-Generation IoT Security: Embedded Smart Contracts and Multilayer Security Protection_ (IEEE IoT Journal, 2025)](https://www.researchgate.net/publication/388946680_Constructing_Next-Generation_IoT_Security_Embedded_Smart_Contracts_and_Multilayer_Security_Protection) while inserting a decoupled **Adaptive Security Layer (Layer 2)** and **Authenticated Edge Computing Layer (Layer 3)** between the resource-constrained Cat.1 IoT cellular terminal and the permissioned [FISCO BCOS](https://fisco-bcos-documentation.readthedocs.io/en/latest/) / DVRC blockchain network.

```text
+-----------------------------------------------------------------------------------+
| LAYER 1: IoT DEVICE LAYER (device/) — Fibocom L610-CN / ML307A Cat.1 Terminal      |
|  - DeviceIdentityWallet (Private keys s, d isolated in hardware/module wallet)    |
|  - DeviceResourceMonitor (OSAL/DAL telemetry: CPU%, Free RAM KB, Battery%, RTT)   |
|  - DeviceLocalSecurityEngine (Schnorr NIZK Prover, EC-ElGamal Encrypt/Decrypt)    |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 2: ADAPTIVE SECURITY LAYER (adaptive_engine/)                               |
|  - ResourceAnalyzer: Continuous non-linear pressure indices (CPU, RAM, Battery)   |
|  - CostEstimator: Multi-factor cost evaluation (C_local, C_hybrid, C_edge)        |
|  - SecurityPolicyManager: Enforces private-key locality & mandatory verification  |
|  - AdaptiveDecisionEngine: Selects Mode 1 (Local), Mode 2 (Hybrid), Mode 3 (Edge) |
+-------------------+-------------------------------------------+-------------------+
                    | (Mode 1: Local)                           | (Mode 2 & Mode 3)
                    |                                           v
                    |             +-------------------------------------------------+
                    |             | LAYER 3: EDGE COMPUTING LAYER (edge/)           |
                    |             |  - EdgeMutualAuthenticator (Challenge-Response) |
                    |             |  - EdgeExecutor (HE Sum Eq. 9, Batch NIZK, Zlib)|
                    |             |  - EdgeResultVerifier & EdgeFailoverManager     |
                    |             +-----------------------------+-------------------+
                    |                                           |
                    +---------------------+---------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 4: BLOCKCHAIN & SMART CONTRACT LAYER (blockchain/, smart_contracts/)        |
|  - DVRCConsensusEngine (5-stage reputation scoring & weighted validator quorum)   |
|  - SmartContractManager (DeviceRegistry.sol, SecurityManager.sol, TaskManagement) |
|  - BlockchainIntegrityVerifier (Merkle root, block chain, off-chain SHA-256 hash) |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 5: PRIVACY & CRYPTOGRAPHY LAYER (cryptography/)                             |
|  - NIZKAuthenticator (RFC 3526 2048-bit DLP Fiat-Shamir + Circom2 R1CS verifier)  |
|  - ECElGamalHomomorphicEngine (SECG secp256k1 Additive EC-ElGamal + BSGS DLog)    |
|  - EncryptionService (Separates EC-ElGamal HE from AES-256-GCM transport AEAD)    |
+-----------------------------------------------------------------------------------+
```

## 2. Layer Responsibilities and Interfaces

### Layer 1: IoT Device Layer (`device/`)

- **Embedded Wallet Component (`device_identity.py`)**: Implements the Wallet API from Fig. 5 of the [2025 paper](https://www.researchgate.net/publication/388946680_Constructing_Next-Generation_IoT_Security_Embedded_Smart_Contracts_and_Multilayer_Security_Protection), holding the device's NIZK secret $s$, EC-ElGamal private key $d$, signing secret, and unique blockchain account address.
- **Resource Monitor (`resource_monitor.py`)**: Abstracts OSAL/DAL telemetry on the L610-CN (2 MB RAM, 16 MB Flash) and ML307A modules.
- **Local Security (`local_security.py`)**: Generates NIZK proofs, manages precomputed EC-ElGamal blinding pools $(r_i G, r_i Q)$, and performs final decryption $m = \log_G(E_2 - dE_1)$ strictly inside the device boundary.

### Layer 2: Adaptive Security Layer (`adaptive_engine/`)

- **Resource Analyzer (`resource_analyzer.py`)**: Transforms raw telemetry into normalized pressure indices $P_{\text{cpu}}, P_{\text{mem}}, P_{\text{batt}}, P_{\text{net}} \in [0, 1]$.
- **Cost Estimator (`cost_estimator.py`)**: Evaluates:
  $$C_{\text{local}} = \alpha \cdot \text{CPU\_cost} + \beta \cdot \text{Memory\_cost} + \gamma \cdot \text{Energy\_cost} + \delta \cdot \text{Execution\_latency} + \Phi_{\text{barrier}}$$
  $$C_{\text{edge}} = \alpha \cdot \text{Comm\_cost} + \beta \cdot \text{Edge\_proc\_cost} + \gamma \cdot \text{Energy\_cost} + \delta \cdot \text{Total\_latency} + \Phi_{\text{net}}$$
- **Policy Manager (`policy_manager.py`)**: Pins any private-key operation (`PRIVATE_KEY_DECRYPTION`, `WALLET_KEY_GENERATION`) to `LOCAL_SECURITY_MODE`.

### Layer 3: Edge Computing Layer (`edge/`)

- **Edge Mutual Authenticator (`edge_authentication.py`)**: Verifies that the target edge server is authorized in `SecurityManager` on-chain and completes a bidirectional cryptographic challenge-response before accepting or sending any delegated task.
- **Edge Executor (`edge_executor.py`)**: Performs homomorphic point addition (`HOMOMORPHIC_AGGREGATION`), stream compression (`DATA_COMPRESSION`), and randomized batch NIZK verification (`BATCH_NIZK_VERIFICATION`), returning signed `EdgeExecutionReceipt` envelopes.
- **Failover Manager (`failover_manager.py`)**: Monitors edge node heartbeats and CPU load across `edge-node-0`, `edge-node-1`, and `edge-node-2`, automatically failing over to backup edge nodes or falling back to `LOCAL_SECURITY_MODE` on the IoT device if all edge nodes are unreachable or fail signature verification.

### Layer 4: Blockchain Layer (`blockchain/`, `smart_contracts/`)

- **DVRC Consensus (`dvrc_consensus.py`)**: Implements the Dynamic Vehicle/Device Reputation Consensus algorithm from [Zhang et al., _IEEE TVT_ 2024](https://ieeexplore.ieee.org/iel8/25/4356907/10752705.pdf).
- **Smart Contract Manager (`smart_contract_manager.py`)**: Executes `DeviceRegistry`, `SecurityManager`, and `TaskManagement` contracts and records off-chain result SHA-256 digests on-chain.

### Layer 5: Privacy and Cryptography Layer (`cryptography/`)

- Provides standard-compliant [RFC 3526](https://www.rfc-editor.org/info/rfc3526/) 2048-bit Schnorr NIZK proofs, [Circom 2.0](https://docs.iden3.io/circom-snarkjs/) R1CS constraint verification, and [SECG SEC 2 `secp256k1`](https://www.secg.org/sec2-v2.pdf) additive EC-ElGamal homomorphic encryption.
