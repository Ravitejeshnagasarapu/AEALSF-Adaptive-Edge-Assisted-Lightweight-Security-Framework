# AEALSF Methodological & Experimental Limitations

In accordance with strict scientific integrity standards, the following limitations of the current AEALSF study are explicitly documented:

1. **Software Simulation vs. Physical Embedded Hardware**:
   - All experiments execute within a single-host Python/C simulation environment. While cryptographic primitives (`secp256k1` EC-Schnorr, EC-ElGamal, SHA-256, `zlib`) execute real mathematical operations, IoT device CPU percentage (`sim_device_cpu_pct`), device SRAM occupancy (`sim_device_memory_kb`), edge CPU load (`sim_edge_cpu_pct`), and validator CPU load (`sim_validator_cpu_pct`) are outputs of the parameterized `SimulatedResourceModel` rather than physical measurements on Fibocom L610-CN hardware.
2. **Analytical Energy Estimation Model**:
   - Device energy (`estimated_energy_mj`) is computed from an analytical LTE Cat.1 power state model ($P_{\text{cpu}} = 420\text{ mW}$, $P_{\text{tx}} = 680\text{ mW}$, $P_{\text{rx}} = 310\text{ mW}$, $P_{\text{idle}} = 45\text{ mW}$) rather than physical current-shunt or oscilloscope measurements. Although 5-point sensitivity sweeps confirm rank stability, physical RF tail states and battery chemistry non-linearities are not captured.
3. **Reset-State Repeated Trials vs. Process-Isolated Fleet Re-Keying**:
   - To complete 540 concurrent trials (`288,000` client executions) plus sensitivity and concurrency sweeps within a practical runtime (`~284s`), the benchmark pre-provisions `1,050` unique device identities at startup and executes deterministic state resets (`RESET_STATE_REPEATED_TRIAL_WITH_UNIQUE_KEYS`) between trials rather than spawning a fresh OS process per trial.
4. **Communication & Latency Trade-Offs Under High Network RTT**:
   - AEALSF does not outperform every baseline on every metric:
     - `ALWAYS_LOCAL` achieves lower network transmission bytes (`1,119.3 B` vs. `2,118.8–2,681.9 B`) and higher host-execution TPS (`3,792–3,937 TPS` vs. `3,343–3,378 TPS`) because it performs zero edge serialization or receipt verification.
     - `ALWAYS_EDGE` achieves lower simulated on-device CPU (`63.59%–68.69%`) and energy (`21.96–26.54 mJ`) when network overhead is ignored.
     - `STATIC_THRESHOLD` achieves slightly lower mean task latency at $N = 500$ (`108.42 vs. 112.71 ms`) and $N = 1,000$ (`129.03 vs. 131.21 ms`) because it leaves memory/battery-constrained devices on local execution whenever their CPU is below `48%`.
5. **Symmetric HMAC Edge Transport Signatures**:
   - Mutual edge-device session authentication and execution receipts use domain-separated HMAC-SHA256 tokens managed by `KeyManager` rather than X.509 PKI certificates.
