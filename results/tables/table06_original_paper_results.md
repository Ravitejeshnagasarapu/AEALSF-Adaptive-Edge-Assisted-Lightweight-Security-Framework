### Table 6 — Original Research Paper Reported Results (Zhang et al., IEEE IoT Journal, 2025)

| Metric | Paper_Reported_Value | Paper_Reference | Experimental_Context |
| --- | --- | --- | --- |
| Peak Transaction Throughput (<100 Clients) | 1,900 TPS (1,500 TPS in Conclusion) | Section VI-A (Fig. 12) & Section VII | 4-node FISCO BCOS + DVRC |
| Throughput at 1,000 Clients (PF vs. Fusion Chain-S) | 600 TPS (PF) vs. 256 TPS (Fusion Chain-S) | Section VI-A (Fig. 12, p. 19725) | 1,000 clients, 3,000 smart contracts |
| Transaction Confirmation Time at 1,000 Clients | 0.9 s (< 1.3 s in Conclusion) | Section VI-A (Fig. 12) | Gradual rise from 0.36 s to 0.9 s |
| L610 Process CPU & Memory (GET Method) | CPU: 91.43% max, 58.78% avg; RAM: 1.4 MB max, 0.9 MB avg | Section VI-C (Table III, p. 19727) | Out of 2.0 MB total L610-CN RAM |
| L610 Process CPU & Memory (SET Method) | CPU: 81.25% max, 58.59% avg; RAM: 1.9 MB max, 1.5 MB avg | Section VI-C (Table III, p. 19727) | 95% RAM saturation on L610-CN |
| Single-Device Authentication Time (200/500/1,000 Nodes) | 34.6 ms / 48.4 ms / 61.3 ms | Section VI-C (Table IV, p. 19727) | vs. 206.8 ms (Fusion Chain-S) |
| Client-to-Node Network Latency (100/500/1,000 Clients) | 38.64±2.91 ms / 67.51±3.64 ms / 104.75±6.11 ms | Section VI-B (Fig. 14, p. 19726) | Linearly extrapolated from 5 L610 modules |
