### Table 12 — Adaptive Decision Engine Calibrated Mode Costs and Explicit Rejection Reasons

| Device_Profile | C_Local | C_Hybrid | C_Edge | Selected_Mode | Rejected_Modes_and_Reasons |
| --- | --- | --- | --- | --- | --- |
| MORE_CAPABLE_IOT (CPU=25%, FreeRAM=1600KB), RTT=38ms | 0.421 | 0.785 | 0.912 | LOCAL_SECURITY_MODE | HYBRID & EDGE: Higher calibrated cost (C > C_selected) |
| MODERATELY_CONSTRAINED_IOT (CPU=64%, FreeRAM=680KB), RTT=38ms | 0.892 | 0.641 | 0.728 | HYBRID_SECURITY_MODE | LOCAL & EDGE: Higher calibrated cost |
| HIGHLY_CONSTRAINED_IOT (CPU=89%, FreeRAM=240KB, Bat=14%), RTT=38ms | 1.984 | 0.812 | 0.594 | EDGE_ASSISTED_SECURITY_MODE | LOCAL (RAM/CPU/Battery penalty) & HYBRID (Higher cost) |
| HIGHLY_CONSTRAINED_IOT, High Congestion (RTT=105ms, N=1000) | 1.65 | 0.91 | 1.48 | HYBRID_SECURITY_MODE | EDGE: High RTT & wire-byte congestion penalty |
| Any Profile, Secret-Key Decryption (requires_private_key_access=True) | 1.54 | 999.0 | 999.0 | LOCAL_SECURITY_MODE | HYBRID & EDGE: Hard Constraint 1/3 (Mandatory Local Security Boundary) |
| Any Profile, Confidential Stream (CONFIDENTIAL_NO_EDGE_COMPRESSION) | 1.12 | 0.74 | 999.0 | HYBRID_SECURITY_MODE | EDGE: Hard Constraint 2 (Data Sensitivity forbids edge compression) |
