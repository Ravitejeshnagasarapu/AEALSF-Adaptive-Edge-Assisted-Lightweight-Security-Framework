# AEALSF Simulation & Experimental Methodology

## 1. Two-Layer Simulation Methodology

Because physical deployment of 1,000 cellular IoT modules and edge servers is outside the scope of this simulation-based study, AEALSF implements a strict **Two-Layer Instrumentation Architecture**:

1. **Layer 1 — Actual Host Process Instrumentation (`MEASURED_HOST_PROCESS`)**:
   - CPU time is measured via POSIX `resource.getrusage(resource.RUSAGE_SELF)` (`ru_utime + ru_stime`) and wall-clock intervals via `time.perf_counter_ns()`.
   - Process memory (`host_memory_mb`) is read from Linux kernel `/proc/self/status` (`VmRSS` and `VmHWM`) and task buffer allocations via `tracemalloc`.
   - Host throughput (`completed_tps`) is calculated strictly from actual executed transaction counts divided by measured trial wall-clock seconds:
     $$\text{completed\_tps} = \frac{\text{completed\_transactions}}{\text{trial\_wall\_sec}}$$
2. **Layer 2 — Simulated Target-Architecture Resource Model (`SIMULATED_RESOURCE_MODEL`)**:
   - Models three heterogeneous virtual IoT hardware profiles anchored to the Fibocom L610-CN (`500 MHz ARM Cortex-A5`, `2,048 KB` SRAM) from Table II of Zhang et al. (2025): `MORE_CAPABLE_IOT` (`1.35x` clock, `2,048 KB` RAM), `MODERATELY_CONSTRAINED_IOT` (`1.00x` clock, `1,536 KB` RAM), and `HIGHLY_CONSTRAINED_IOT` (`0.75x` clock, `1,024 KB` RAM).
   - Models a 3-node edge cluster (`edge-node-0..2`, `4 vCPU @ 3.0 GHz`) and a 4-node DVRC validator committee (`node0..node3`, `4 vCPU @ 2.8 GHz`).

---

## 2. Trial Initialization & Seed Policy

- **Classification**: `RESET_STATE_REPEATED_TRIAL_WITH_UNIQUE_KEYS`.
- **Provisioning**: `PreprovisionedFleetPool` (`experiments/baseline.py`) provisions `1,050` `IoTDevice` instances at startup, generating `1,050` unique EC-Schnorr, `1,050` unique EC-ElGamal, and `1,050` unique DLP keypairs via `secrets.randbelow`.
- **Per-Trial Reset Procedure**: Before each trial, `reset_for_independent_trial(num_clients, trial_seed)` clears all performance samples, security events, decision engine history/cooldown maps, NIZK pending/consumed challenge tables, edge replay registries, smart contract active sessions/nonces/tasks, and pending transaction pools.
- **Deterministic Paired Seed Formula**:
  $$\text{trial\_seed} = 100000 + N \times 100 + \text{trial\_index}$$
  - For $N = 100$, $\text{trial\_index} \in [0, 29] \implies \text{trial\_seed} \in [110000, 110029]$.
  - For $N = 500$, $\text{trial\_index} \in [0, 29] \implies \text{trial\_seed} \in [150000, 150029]$.
  - For $N = 1000$, $\text{trial\_index} \in [0, 29] \implies \text{trial\_seed} \in [200000, 200029]$.
  - Using identical `trial_seed` sequences across all 6 policies guarantees that trial $t$ exposes every policy to the exact same initial device CPU/RAM/battery state distribution and network RTT/bandwidth realizations, enabling valid paired statistical testing.

---

## 3. Statistical Analysis Methodology

All 18 scale-policy cells ($3 \times 6$) are evaluated over $n = 30$ trials (`540` total core trials). For each metric, `monitoring/metrics_collector.py` computes:

- **Parametric statistics**: Mean ($\mu$), Sample Standard Deviation ($s$), and 95% Confidence Interval ($\pm t_{0.975, 29} \cdot s / \sqrt{30}$, where $t_{0.975, 29} = 2.0452$).
- **Non-parametric & tail statistics**: Median ($P_{50}$), Interquartile Range ($\text{IQR} = P_{75} - P_{25}$), 95th Percentile ($P_{95}$), and 99th Percentile ($P_{99}$).
- **Hypothesis tests & effect sizes**: Paired Student's $t$-test (`scipy.stats.ttest_rel`) with Holm-Bonferroni correction ($m = 5$ policy comparisons), Welch's two-sample $t$-test (`ttest_ind(equal_var=False)`), Mann-Whitney $U$ test (`mannwhitneyu`), Wilcoxon signed-rank test (`wilcoxon`), paired Cohen's $d$, and pooled Cohen's $d$.
