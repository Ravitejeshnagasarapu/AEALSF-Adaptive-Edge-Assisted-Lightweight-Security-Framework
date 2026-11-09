### Table 15 — Simulated Network Conditions and Edge Failure-Recovery Results

| scenario_id | description | configured_rtt_ms | configured_bw_mbps | packet_loss_rate | offline_edge_nodes | completed_tasks | failed_tasks | failed_task_pct | total_retries | probe_selected_mode | probe_used_local_fallback | failover_or_recovery_time_ms | mean_task_latency_ms | bytes_transmitted_mean | bytes_received_mean | modes_local_hybrid_edge | scenario_wall_ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SCEN_01_NORMAL | Normal Network & All 3 Edge Nodes Healthy | 28.0 | 85.0 | 0.0 | 0 | 100 | 0 | 0.0 | 0 | EDGE_ASSISTED_SECURITY_MODE | False | 2.045 | 89.5991 | 2681.9 | 620.48 | 0/51/49 | 70.51 |
| SCEN_02_HIGH_LATENCY_LOW_BW | High Latency (185 ms RTT) & Low Bandwidth (4 Mbps) | 185.0 | 4.0 | 0.0 | 0 | 100 | 0 | 0.0 | 0 | HYBRID_SECURITY_MODE | False | 1.765 | 89.523 | 2681.99 | 619.99 | 0/51/49 | 69.05 |
| SCEN_03_PACKET_LOSS_10PCT | 10% Packet Loss with Automatic Retries | 55.0 | 45.0 | 0.1 | 0 | 100 | 0 | 0.0 | 6 | EDGE_ASSISTED_SECURITY_MODE | False | 2.135 | 90.6655 | 2843.63 | 620.48 | 0/51/49 | 69.28 |
| SCEN_04_SINGLE_EDGE_FAILURE | Primary Edge Node Offline -> Failover to Secondary Edge | 35.0 | 75.0 | 0.0 | 1 | 100 | 0 | 0.0 | 0 | EDGE_ASSISTED_SECURITY_MODE | False | 1.956 | 89.6253 | 2681.83 | 620.48 | 0/51/49 | 70.47 |
| SCEN_05_EDGE_OVERLOAD | Edge Cluster Overloaded (CPU=95%) -> Adaptive Local Switch | 40.0 | 70.0 | 0.0 | 0 | 100 | 0 | 0.0 | 0 | LOCAL_SECURITY_MODE | False | 1.698 | 89.4896 | 2682.0 | 620.48 | 0/51/49 | 69.71 |
| SCEN_06_ALL_EDGES_OFFLINE | Complete Edge Cluster Outage -> 100% Local Fallback | 45.0 | 60.0 | 0.0 | 3 | 100 | 0 | 0.0 | 0 | LOCAL_SECURITY_MODE | False | 1.713 | 89.6575 | 2682.07 | 620.48 | 0/51/49 | 68.29 |
