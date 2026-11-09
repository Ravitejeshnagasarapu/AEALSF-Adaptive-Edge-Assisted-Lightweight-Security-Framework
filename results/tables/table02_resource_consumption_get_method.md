### Table 2 — Resource Consumption (GET Method Across All 6 Configurations, n=30 Operations/Config)

| Method | Configuration | Avg_Latency_ms | Median_Latency_ms | P95_Latency_ms | Simulated_Device_CPU_Pct | Simulated_Device_Memory_KB | Simulated_Edge_CPU_Pct | Simulated_Edge_Memory_KB | Simulated_Validator_CPU_Pct | Simulated_Validator_Memory_MB | Device_CPU_Avg_Pct | Device_Peak_Heap_KB | Validator_CPU_Avg_Pct | Validator_RSS_MB | Traffic_In_KB | Traffic_Out_KB | Successful_Ops | Failed_Ops | Simulated_Throughput_OPS | Auth_Overhead_ms | Tx_Overhead_ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GET | ORIGINAL_BASELINE | 1.0992 | 1.2377 | 1.318 | 78.47 | 645.0 | 8.0 | 32.0 | 19.59 | 211.45 | 78.47 | 91.868 | 100.0 | 401.92 | 17.943 | 48.4 | 30 | 0 | 826.38 | 0.8029 | 0.1942 |
| GET | ALWAYS_LOCAL | 1.0632 | 1.2224 | 1.3319 | 78.47 | 645.0 | 8.0 | 32.0 | 19.59 | 210.65 | 78.47 | 101.422 | 100.0 | 401.92 | 17.943 | 48.413 | 30 | 0 | 854.17 | 0.7745 | 0.1927 |
| GET | ALWAYS_EDGE | 1.0441 | 1.2014 | 1.2895 | 62.91 | 392.25 | 32.26 | 412.0 | 20.92 | 211.18 | 62.91 | 97.094 | 100.0 | 401.92 | 17.943 | 48.405 | 30 | 0 | 868.92 | 0.7608 | 0.1877 |
| GET | STATIC_THRESHOLD | 1.0538 | 1.2222 | 1.2822 | 69.8 | 527.15 | 28.51 | 124.0 | 20.25 | 210.92 | 69.8 | 106.892 | 100.0 | 401.92 | 17.943 | 48.413 | 30 | 0 | 860.91 | 0.7677 | 0.1901 |
| GET | RANDOM_OFFLOADING | 1.0857 | 1.2674 | 1.3488 | 69.8 | 527.15 | 28.51 | 124.0 | 20.25 | 210.92 | 69.8 | 97.384 | 100.0 | 401.92 | 17.943 | 48.401 | 30 | 0 | 835.72 | 0.7924 | 0.1967 |
| GET | AEALSF | 1.0723 | 1.2232 | 1.3423 | 69.8 | 527.15 | 28.51 | 124.0 | 20.25 | 210.92 | 69.8 | 97.725 | 100.0 | 401.92 | 17.943 | 48.405 | 30 | 0 | 846.54 | 0.7837 | 0.1926 |

> **Note**: Includes Mean, Median, P95 latency, Simulated Device/Edge/Validator resources, Host Heap/RSS, and Simulated Throughput.
