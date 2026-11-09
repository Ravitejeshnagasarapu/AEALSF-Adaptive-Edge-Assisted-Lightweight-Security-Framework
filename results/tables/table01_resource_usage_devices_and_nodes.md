### Table 1 — Resource Usage of Devices, Edge Servers, and Validator Nodes (Two-Layer Separation, n=30 Trials)

| Configuration | Simulated_Clients | Sim_Device_CPU_Pct | Sim_Device_Mem_KB | Host_Process_CPU_Pct | Host_Process_RSS_MB | Sim_Edge_CPU_Pct | Sim_Edge_Mem_KB | Sim_Validator_CPU_Pct | Sim_Validator_Mem_MB | Net_Bytes_TX |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ORIGINAL_BASELINE | 100 | 87.63 ± 0.09% | 699.5 ± 0.0 KB | 48.30% (HOST) | 212.4 MB (HOST) | 8.0% | 32.0 KB | 24.2% | 211.4 MB | 1820.0 B |
| ALWAYS_LOCAL | 100 | 87.55 ± 0.09% | 699.5 ± 0.0 KB | 47.95% (HOST) | 214.6 MB (HOST) | 8.0% | 32.0 KB | 21.2% | 210.7 MB | 1119.3 B |
| ALWAYS_EDGE | 100 | 68.69 ± 0.11% | 393.9 ± 0.0 KB | 31.22% (HOST) | 217.0 MB (HOST) | 38.0% | 496.0 KB | 22.6% | 211.2 MB | 3465.3 B |
| STATIC_THRESHOLD | 100 | 83.00 ± 0.09% | 607.9 ± 0.0 KB | 39.84% (HOST) | 219.2 MB (HOST) | 22.4% | 169.0 KB | 21.7% | 210.8 MB | 1785.4 B |
| RANDOM_OFFLOADING | 100 | 77.42 ± 0.87% | 543.0 ± 13.2 KB | 37.32% (HOST) | 221.5 MB (HOST) | 27.2% | 242.8 KB | 21.9% | 210.9 MB | 2158.9 B |
| AEALSF | 100 | 73.07 ± 0.10% | 463.3 ± 0.0 KB | 32.12% (HOST) | 223.7 MB (HOST) | 37.1% | 349.1 KB | 22.2% | 211.0 MB | 2681.9 B |
| ORIGINAL_BASELINE | 500 | 89.37 ± 0.05% | 703.7 ± 0.0 KB | 48.30% (HOST) | 230.4 MB (HOST) | 9.8% | 32.0 KB | 30.7% | 217.9 MB | 1820.0 B |
| ALWAYS_LOCAL | 500 | 89.24 ± 0.06% | 703.7 ± 0.0 KB | 47.96% (HOST) | 236.9 MB (HOST) | 9.8% | 32.0 KB | 27.9% | 217.1 MB | 1119.3 B |
| ALWAYS_EDGE | 500 | 63.91 ± 0.07% | 401.0 ± 0.0 KB | 31.09% (HOST) | 244.6 MB (HOST) | 50.2% | 524.4 KB | 29.1% | 217.6 MB | 3465.3 B |
| STATIC_THRESHOLD | 500 | 82.59 ± 0.06% | 615.5 ± 0.0 KB | 39.79% (HOST) | 252.0 MB (HOST) | 29.5% | 182.0 KB | 28.3% | 217.3 MB | 1779.3 B |
| RANDOM_OFFLOADING | 500 | 75.18 ± 0.56% | 547.4 ± 6.2 KB | 37.12% (HOST) | 259.4 MB (HOST) | 36.3% | 263.3 KB | 28.5% | 217.4 MB | 2165.9 B |
| AEALSF | 500 | 70.53 ± 0.25% | 482.2 ± 2.1 KB | 32.94% (HOST) | 266.9 MB (HOST) | 47.0% | 366.7 KB | 28.8% | 217.5 MB | 2642.1 B |
| ORIGINAL_BASELINE | 1000 | 91.32 ± 0.04% | 710.2 ± 0.0 KB | 48.29% (HOST) | 280.0 MB (HOST) | 12.0% | 32.0 KB | 38.9% | 225.9 MB | 1820.0 B |
| ALWAYS_LOCAL | 1000 | 91.14 ± 0.04% | 710.2 ± 0.0 KB | 47.96% (HOST) | 293.2 MB (HOST) | 12.0% | 32.0 KB | 36.2% | 225.2 MB | 1119.3 B |
| ALWAYS_EDGE | 1000 | 63.59 ± 0.05% | 410.9 ± 0.0 KB | 31.09% (HOST) | 307.5 MB (HOST) | 63.9% | 560.0 KB | 37.4% | 225.7 MB | 3465.3 B |
| STATIC_THRESHOLD | 1000 | 83.98 ± 0.04% | 625.2 ± 0.0 KB | 39.82% (HOST) | 321.6 MB (HOST) | 37.6% | 200.1 KB | 36.6% | 225.3 MB | 1780.8 B |
| RANDOM_OFFLOADING | 1000 | 75.73 ± 0.34% | 555.2 ± 3.5 KB | 37.06% (HOST) | 335.1 MB (HOST) | 46.3% | 289.0 KB | 36.8% | 225.4 MB | 2175.3 B |
| AEALSF | 1000 | 79.69 ± 0.05% | 573.5 ± 0.9 KB | 37.22% (HOST) | 348.9 MB (HOST) | 46.2% | 278.2 KB | 36.8% | 225.4 MB | 2118.8 B |

> **Note**: Distinguishes Layer 2 Simulated IoT/Edge/Validator Resource Consumption (`Sim_*`) from Layer 1 Actual Host Process Measurements (`Host_*`).
