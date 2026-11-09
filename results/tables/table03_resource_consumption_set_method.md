### Table 3 — Resource Consumption (SET Method Across All 6 Configurations, n=30 Operations/Config)

| Method | Configuration | Avg_Latency_ms | Median_Latency_ms | P95_Latency_ms | Simulated_Device_CPU_Pct | Simulated_Device_Memory_KB | Simulated_Edge_CPU_Pct | Simulated_Edge_Memory_KB | Simulated_Validator_CPU_Pct | Simulated_Validator_Memory_MB | Device_CPU_Avg_Pct | Device_Peak_Heap_KB | Validator_CPU_Avg_Pct | Validator_RSS_MB | Traffic_In_KB | Traffic_Out_KB | Successful_Ops | Failed_Ops | Simulated_Throughput_OPS | Auth_Overhead_ms | Tx_Overhead_ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SET | ORIGINAL_BASELINE | 1.1814 | 1.2534 | 1.6879 | 85.05 | 674.0 | 8.0 | 32.0 | 19.59 | 211.45 | 85.05 | 146.044 | 100.0 | 401.92 | 10.834 | 54.229 | 30 | 0 | 768.69 | 0.7724 | 0.3135 |
| SET | ALWAYS_LOCAL | 1.1893 | 1.2852 | 1.6774 | 85.05 | 674.0 | 8.0 | 32.0 | 19.59 | 210.65 | 85.05 | 125.669 | 100.0 | 401.92 | 10.683 | 54.096 | 30 | 0 | 764.59 | 0.7803 | 0.3107 |
| SET | ALWAYS_EDGE | 1.1995 | 1.3245 | 1.6897 | 68.85 | 392.5 | 35.06 | 440.0 | 20.92 | 211.18 | 68.85 | 125.687 | 100.0 | 401.92 | 10.741 | 54.083 | 30 | 0 | 757.09 | 0.787 | 0.3149 |
| SET | STATIC_THRESHOLD | 1.1975 | 1.3343 | 1.7148 | 76.15 | 527.9 | 31.94 | 152.0 | 20.25 | 210.92 | 76.15 | 127.257 | 100.0 | 401.93 | 10.892 | 54.228 | 30 | 0 | 758.82 | 0.786 | 0.3153 |
| SET | RANDOM_OFFLOADING | 1.2314 | 1.3554 | 1.7639 | 76.15 | 527.9 | 31.94 | 152.0 | 20.25 | 210.92 | 76.15 | 125.237 | 100.0 | 401.93 | 10.918 | 54.265 | 30 | 0 | 737.74 | 0.8072 | 0.3223 |
| SET | AEALSF | 1.2262 | 1.3406 | 1.7347 | 76.15 | 527.9 | 31.94 | 152.0 | 20.25 | 210.92 | 76.15 | 127.644 | 100.0 | 401.93 | 10.602 | 53.949 | 30 | 0 | 741.02 | 0.8054 | 0.322 |

> **Note**: Includes Mean, Median, P95 latency, Simulated Device/Edge/Validator resources, Host Heap/RSS, and Simulated Throughput.
