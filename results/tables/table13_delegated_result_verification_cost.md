### Table 13 — Delegated-Result Verification Overhead (Full C1 & C2 Verification Strategies)

| strategy | local_baseline_cpu_ms | delegated_edge_exec_ms | verification_time_ms | total_device_cpu_ms | total_task_latency_ms | computation_saved_ms | net_device_cpu_benefit_ms | bytes_transmitted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ALGEBRAIC_OR_DECOMPRESS_CHECK | 217.2153 | 0.2936 | 0.2151 | 117.6129 | 152.5039 | 99.8175 | 99.6024 | 7899 |
| REDUNDANT_DUAL_EDGE | 217.2153 | 0.2715 | 0.2243 | 117.6129 | 152.6758 | 99.8267 | 99.6024 | 8362 |
| INDEPENDENT_RECOMPUTATION | 217.2153 | 0.2688 | 0.2163 | 117.6129 | 152.3562 | 99.8187 | 99.6024 | 7897 |
