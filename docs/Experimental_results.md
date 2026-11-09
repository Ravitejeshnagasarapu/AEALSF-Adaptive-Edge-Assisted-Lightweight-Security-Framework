# Experimental Evaluation & Benchmark Results Report

## 1. Experimental Methodology

To evaluate whether **AEALSF** resolves the computational and memory overhead of [_Constructing Next-Generation IoT Security: Embedded Smart Contracts and Multilayer Security Protection_ (Zhang et al., IEEE IoT Journal, 2025)](https://www.researchgate.net/publication/388946680_Constructing_Next-Generation_IoT_Security_Embedded_Smart_Contracts_and_Multilayer_Security_Protection) without weakening its security guarantees, we benchmarked two configurations under identical workloads, random seeds, network conditions, and cryptographic parameters:

1. **Baseline Configuration (`experiments/baseline.py`)**:
   - Preserves the original paper's architecture: 2048-bit [RFC 3526](https://www.rfc-editor.org/info/rfc3526/) Schnorr/DLP NIZK authentication, [SECG `secp256k1`](https://www.secg.org/sec2-v2.pdf) Additive EC-ElGamal Homomorphic Encryption, [DVRC consensus](https://ieeexplore.ieee.org/iel8/25/4356907/10752705.pdf) across 4 validator nodes (`node0..node3`), and smart contract task management, executing all device-side cryptographic proofs and encryptions without adaptive resource-aware edge scheduling.
2. **Proposed AEALSF Configuration (`experiments/proposed_framework.py`)**:
   - Integrates the **Adaptive Edge-Assisted Security Engine** (`adaptive_engine/`), dynamically selecting among **Mode 1 (`LOCAL_SECURITY_MODE`)**, **Mode 2 (`HYBRID_SECURITY_MODE`)**, and **Mode 3 (`EDGE_ASSISTED_SECURITY_MODE`)** based on real-time device CPU, free RAM (out of 2048 KB on the Fibocom L610-CN Cat.1 profile from Table II/III), battery level, network latency/bandwidth, and edge server load, combined with bounded-TTL Authenticated Session Context reuse and precomputed EC-ElGamal blinding pools.

Each device count ($N \in \{100, 500, 1000\}$) was evaluated across **3 independent trials** (`num_trials=3`), plus a scalability sweep across $N \in \{100, 300, 500, 800, 1000, 1500\}$ devices.

## 2. Comparative Experimental Results (Mean ± SD across 3 Trials)

### Table 1: Baseline vs. Proposed AEALSF Across 100, 500, and 1,000 IoT Devices

| Metric                           | 100 Devices (Baseline) |      100 Devices (AEALSF)       | 500 Devices (Baseline) |      500 Devices (AEALSF)      | 1,000 Devices (Baseline) |     1,000 Devices (AEALSF)      |
| :------------------------------- | :--------------------: | :-----------------------------: | :--------------------: | :----------------------------: | :----------------------: | :-----------------------------: |
| **Device CPU Utilization (%)**   |     71.61 ± 2.87%      |   **37.51 ± 2.33%** (-47.62%)   |     76.87 ± 2.10%      |  **36.76 ± 1.80%** (-52.18%)   |      83.35 ± 1.80%       |   **40.65 ± 2.25%** (-51.23%)   |
| **Device RAM Footprint (KB)**    |   1110.88 ± 0.00 KB    | **491.63 ± 55.92 KB** (-55.74%) |   1184.21 ± 0.00 KB    | **457.77 ± 9.88 KB** (-61.34%) |    1275.91 ± 0.00 KB     | **495.80 ± 53.28 KB** (-61.14%) |
| **Device CPU Time / Task (ms)**  |    63.63 ± 1.47 ms     |       **39.77 ± 5.06 ms**       |    66.25 ± 0.19 ms     |      **35.80 ± 0.67 ms**       |     71.16 ± 0.30 ms      |       **38.18 ± 4.67 ms**       |
| **Estimated Energy / Task (mJ)** |    35.63 ± 0.79 mJ     |  **22.95 ± 2.39 mJ** (-35.59%)  |    37.20 ± 0.11 mJ     | **21.23 ± 0.32 mJ** (-42.93%)  |     40.08 ± 0.18 mJ      |  **22.57 ± 2.23 mJ** (-43.69%)  |
| **Authentication Latency (ms)**  |    106.90 ± 0.66 ms    |  **62.11 ± 4.36 ms** (-41.90%)  |    118.53 ± 0.28 ms    | **61.09 ± 0.81 ms** (-48.46%)  |     130.94 ± 0.34 ms     |  **65.63 ± 4.17 ms** (-49.88%)  |
| **Task Execution Latency (ms)**  |    111.23 ± 1.47 ms    |  **65.19 ± 4.97 ms** (-41.39%)  |    133.85 ± 0.30 ms    | **69.70 ± 1.02 ms** (-47.93%)  |     164.01 ± 0.45 ms     |  **83.93 ± 4.78 ms** (-48.83%)  |
| **System Throughput (TPS)**      |    1678.84 ± 11.63     |  **1984.03 ± 9.69** (+18.18%)   |    1207.25 ± 13.70     | **1571.41 ± 11.41** (+30.16%)  |      605.66 ± 14.90      |  **1045.55 ± 12.42** (+72.63%)  |
| **Network Latency (ms)**         |    38.94 ± 0.65 ms     |       **33.48 ± 0.54 ms**       |    68.48 ± 0.49 ms     |      **58.87 ± 0.40 ms**       |     105.89 ± 1.93 ms     |       **91.01 ± 1.57 ms**       |
| **Bandwidth Used (kbps)**        |     131.80 ± 1.42      |        **99.33 ± 0.39**         |     146.02 ± 0.47      |       **108.72 ± 0.12**        |      163.64 ± 0.80       |        **118.56 ± 0.19**        |
| **Edge Cluster CPU Load (%)**    |         0.00%          |        **18.40 ± 0.00%**        |         0.00%          |       **24.16 ± 0.00%**        |          0.00%           |        **35.53 ± 1.47%**        |
| **Auth / Verify Failures**       |         0 / 0          |            **0 / 0**            |         0 / 0          |           **0 / 0**            |          0 / 0           |            **0 / 0**            |

### Table 2: Execution Mode Distribution in Proposed AEALSF (Across 48 Scheduled Tasks per Fleet Size)

| Fleet Size        | Mode 1: Local Security Mode | Mode 2: Hybrid Security Mode | Mode 3: Edge-Assisted Security Mode |
| :---------------- | :-------------------------: | :--------------------------: | :---------------------------------: |
| **100 Devices**   |      9 tasks (18.75%)       |      25 tasks (52.08%)       |          14 tasks (29.17%)          |
| **500 Devices**   |       3 tasks (6.25%)       |      24 tasks (50.00%)       |          21 tasks (43.75%)          |
| **1,000 Devices** |       4 tasks (8.33%)       |      21 tasks (43.75%)       |          23 tasks (47.92%)          |

## 3. Key Experimental Findings

1. **Substantial Reduction in Constrained Device CPU & RAM Pressure**: At 1,000 devices, AEALSF lowers mean IoT device CPU utilization from **83.35%** to **40.65%** (**51.23% reduction**) and lowers active RAM occupancy on the 2 MB L610-CN profile from **1275.91 KB** to **495.80 KB** (**61.14% reduction**), preventing memory exhaustion during bursty telemetry transmission.
2. **Adaptive Shift Toward Edge Assistance Under Contention**: As fleet size grows from 100 to 1,000 devices and network/resource contention intensifies, the `AdaptiveDecisionEngine` automatically shifts workload allocation from Mode 1 (18.75% at 100 devices) toward Mode 3 Edge-Assisted execution (47.92% at 1,000 devices), sustaining **1045.55 TPS** compared to **605.66 TPS** in the baseline (**+72.63% throughput gain**).
3. **Energy Estimation Transparency**: Energy figures are calculated via `monitoring/energy_estimator.py` using the documented analytical Cat.1 power-state model (420 mW active CPU, 680 mW LTE UL TX, 310 mW LTE DL RX) applied to measured runtime CPU durations and payload byte counts, yielding a **35.59% to 43.69% energy reduction per task**.
