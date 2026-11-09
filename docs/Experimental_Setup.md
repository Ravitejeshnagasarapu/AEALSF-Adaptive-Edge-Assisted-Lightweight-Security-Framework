# AEALSF Experimental Setup & Configuration

## 1. Host Execution Environment

- **Host RAM**: `15.0 GB`
- **OS / Kernel**: `Linux-6.12.105+-x86_64-with-glibc2.36 `
- **Python Runtime**: `3.11` with compiled C `secp256k1` extension (`cryptography/_secp256k1_accel.so`)

## 2. Experimental Matrix

1. **Main 540-Trial Campaign**:
   - **Device Scales ($N$)**: `100`, `500`, `1,000` virtual IoT devices.
   - **Concurrency Setting**: Uncapped full-population concurrency (`configured_concurrency_limit = N`), achieving `actual_max_inflight_clients = 100, 500, 1,000`.
   - **Six Policies Evaluated**:
     1. `ORIGINAL_BASELINE`: Original paper architecture (100% local execution, per-task NIZK authentication, local fresh sensor encryption + homomorphic aggregation + stream compression, unbatched validator verification).
     2. `ALWAYS_LOCAL`: Always executes in `LOCAL_SECURITY_MODE` with standard AEALSF wire serialization.
     3. `ALWAYS_EDGE`: Always delegates to `EDGE_ASSISTED_SECURITY_MODE` when permitted by hard security policy.
     4. `STATIC_THRESHOLD`: Fixed CPU rule (`CPU >= 75% -> EDGE_ASSISTED`, `CPU >= 48% -> HYBRID`, else `LOCAL`).
     5. `RANDOM_OFFLOADING`: Uniformly samples among policy-allowed modes using seeded RNG.
     6. `AEALSF`: Proposed 15-factor cost-minimizing adaptive controller with hysteresis and cooldown.
   - **Repetitions**: `30` reset-state repeated trials per `(N, Policy)` cell = `540` trials (`288,000` client executions).
2. **Concurrency Scaling Experiment (`AEALSF_Concurrency_Results.csv`)**:
   - Fixes `configured_clients = 1,000` and sweeps `configured_concurrency_limit in [128, 256, 512, 1000]` across all 6 policies.
3. **5-Point Sensitivity Analysis (`AEALSF_Sensitivity_Analysis.csv`)**:
   - Fixes `N = 500` and sweeps `coeff_multiplier in [0.50, 0.75, 1.00, 1.25, 1.50]` across all 6 policies.
4. **4-Way Ablation Study (`table10_ablation_study.csv`)**:
   - Separates Authentication Session Reuse (`allow_session_reuse=True/False`) from Adaptive Placement (`ORIGINAL_BASELINE/ALWAYS_LOCAL` vs. `AEALSF`) at `N = 500`.
5. **Network Degradation & Edge Failure Recovery (`table15_network_and_failure_recovery.csv`)**:
   - Tests normal conditions, `185 ms` RTT / `4 Mbps` low bandwidth, `10%` packet loss, single edge node failure, `95%` edge overload, and complete 3-node edge outage (`100%` local fallback).
