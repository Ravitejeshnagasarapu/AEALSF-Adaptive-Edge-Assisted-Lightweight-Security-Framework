### Table 5 — Complete Simulation and Experimental Test Parameter Settings

| Parameter | Value | Layer_Classification |
| --- | --- | --- |
| Simulated Client Counts | 100, 500, 1,000 (plus 100..1,500 scalability sweep) | Concurrent Client Simulation |
| Trial Count | 30 independently initialized trials per config & scale (540 total trials) | Repeated-Measures Paired Seed Design |
| Virtual Device Profiles (3 Tiers) | HIGHLY_CONSTRAINED (200MHz, 512KB), MODERATELY_CONSTRAINED (500MHz, 2048KB), MORE_CAPABLE (800MHz, 4096KB) | Layer 2 Simulated Device Model |
| Battery Profiles | 1,800 mJ (Highly Constrained), 3,600 mJ (Moderately Constrained), 7,200 mJ (More Capable) | Layer 2 Simulated Device Model |
| Simulated Network Bandwidth & Latency | 94.12->48.77 Mbps; 38.64 ms (N=100) -> 67.51 ms (N=500) -> 104.75 ms (N=1,000), jitter=1.5..3.0ms | Layer 3 Simulated Network Model |
| Packet Loss & Failure Scenarios | 0% nominal; 10% packet loss, 185ms RTT/4Mbps, single-edge failure, 95% overload, 100% outage tested | Layer 3 Simulated Network Model |
| Simulated Edge Cluster Capacity | 3 Edge Nodes (edge-node-0..2), 4 cores @ 3.2 GHz (12,800 MHz), 8 GB RAM, max_queue=64 | Layer 2 Simulated Edge Model |
| Simulated Validator Node Count & Capacity | 4 DVRC Validators (node0..node3) in main suite; 4, 50, 200, 500, 1,000 in microbenchmarks | Layer 2 Simulated Blockchain Model |
| Task Workload Distribution | 25% FULL_HE_AND_COMPRESSION, 25% AUTH_AND_HE_AGGREGATION, 25% CONTRACT_SET_TX, 25% CONTRACT_GET_QUERY | Controlled Workload Mix |
| Cryptographic Settings | SECG secp256k1 EC-Schnorr (PK=sG, zG=R+cPK) + RFC 3526 2048-bit DLP + Additive EC-ElGamal HE | Layer 1 Actual Crypto Execution |
| Random Seeds | Base seed 202506; Trial seed = 90000 + 1000*N + trial_idx | Deterministic Reproducibility |
| Host Software Environment | Intel(R) Xeon(R) Platinum 8481C (2 vCPUs), Linux-6.12.105+-x86_64-with-glibc2.36, Python 3.11.2 | Layer 1 Host Process |
