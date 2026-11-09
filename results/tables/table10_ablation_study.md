### Table 10 — Four-Configuration Ablation Study Separating Authentication Reuse from Adaptive Placement (500 Clients, n=15 Trials)

| config_id | description | scheduling_policy | session_reuse_enabled | num_clients | num_trials | device_cpu_pct_mean | device_cpu_time_ms_mean | simulated_device_memory_kb_mean | measured_buffer_kb_mean | auth_latency_ms_mean | task_latency_ms_mean | bytes_transmitted_mean | completed_tps_mean | cpu_reduction_vs_A_pct | latency_reduction_vs_A_pct | bytes_reduction_vs_A_pct |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A_ORIG_AUTH_ORIG_EXEC | Original Auth (Per-Task NIZK) + Original Local Execution | ORIGINAL_BASELINE | False | 500 | 5 | 89.37 | 106.7722 | 703.72 | 4.23 | 0.1646 | 122.3993 | 1820.0 | 3136.61 | 0.0 | 0.0 | 0.0 |
| B_REUSE_AUTH_ORIG_EXEC | Session Reuse + Original Local Execution | ALWAYS_LOCAL | True | 500 | 5 | 89.05 | 94.8942 | 703.72 | 4.23 | 0.01 | 109.3035 | 468.0 | 5242.6 | 0.36 | 10.7 | 74.29 |
| C_ORIG_AUTH_ADAPTIVE_EXEC | Original Auth (Per-Task NIZK) + Adaptive AEALSF Placement | AEALSF | False | 500 | 5 | 70.61 | 68.1608 | 482.89 | 1.606 | 0.1631 | 112.5649 | 2639.5 | 3215.54 | 20.99 | 8.03 | -45.03 |
| D_REUSE_AUTH_ADAPTIVE_EXEC | Session Reuse + Adaptive AEALSF Placement | AEALSF | True | 500 | 5 | 69.15 | 61.77 | 482.89 | 1.606 | 0.0095 | 105.693 | 1988.2 | 4360.75 | 22.62 | 13.65 | -9.24 |
