### Table 4 — Average Execution Time of NIZK and HE Under Different Architectures and Instantiated Simulated Node Counts

| architecture | instantiated_node_count | iterations | nizk_prove_ms | nizk_prove_p95_ms | nizk_verify_ms | nizk_verify_p95_ms | he_encrypt_ms | he_decrypt_ms | he_add_ms | he_scalar_mul_ms | execution_locus |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Local-Only Architecture (Same EC-Schnorr + Local EC-ElGamal) | 4 | 25 | 0.0481 | 0.0528 | 0.0711 | 0.0821 | 0.1041 | 0.1876 | 0.0306 | 0.0246 | All operations on Device; Committee Sync on N Simulated Nodes |
| Edge-Assisted Architecture (AEALSF EC-Schnorr + Edge EC-ElGamal) | 4 | 25 | 0.0445 | 0.0484 | 0.0685 | 0.0749 | 0.101 | 0.1877 | 0.0305 | 0.025 | Prove/Encrypt/Decrypt on Device; Verify/HE-Add/ScalarMul on Edge + N Simulated Committee Nodes |
| Distributed-Validator Architecture (Committee Consensus Verification) | 4 | 25 | 0.0447 | 0.0504 | 0.0633 | 0.07 | 0.0943 | 0.1766 | 0.0281 | 0.0227 | Full Quorum Verification Across 4 Instantiated Committee Nodes |
| Local-Only Architecture (Same EC-Schnorr + Local EC-ElGamal) | 50 | 25 | 0.0429 | 0.0495 | 0.0682 | 0.0744 | 0.0976 | 0.1818 | 0.0296 | 0.025 | All operations on Device; Committee Sync on N Simulated Nodes |
| Edge-Assisted Architecture (AEALSF EC-Schnorr + Edge EC-ElGamal) | 50 | 25 | 0.0423 | 0.0472 | 0.0692 | 0.0753 | 0.0991 | 0.1862 | 0.0294 | 0.0247 | Prove/Encrypt/Decrypt on Device; Verify/HE-Add/ScalarMul on Edge + N Simulated Committee Nodes |
| Distributed-Validator Architecture (Committee Consensus Verification) | 50 | 25 | 0.043 | 0.052 | 0.0679 | 0.073 | 0.1031 | 0.1822 | 0.0299 | 0.0244 | Full Quorum Verification Across 50 Instantiated Committee Nodes |
| Local-Only Architecture (Same EC-Schnorr + Local EC-ElGamal) | 200 | 25 | 0.0449 | 0.0517 | 0.0788 | 0.0845 | 0.1011 | 0.1865 | 0.0306 | 0.0251 | All operations on Device; Committee Sync on N Simulated Nodes |
| Edge-Assisted Architecture (AEALSF EC-Schnorr + Edge EC-ElGamal) | 200 | 25 | 0.0437 | 0.0496 | 0.0788 | 0.0849 | 0.0989 | 0.1847 | 0.0299 | 0.0244 | Prove/Encrypt/Decrypt on Device; Verify/HE-Add/ScalarMul on Edge + N Simulated Committee Nodes |
| Distributed-Validator Architecture (Committee Consensus Verification) | 200 | 25 | 0.0422 | 0.0477 | 0.076 | 0.0814 | 0.097 | 0.1818 | 0.0294 | 0.0238 | Full Quorum Verification Across 200 Instantiated Committee Nodes |
| Local-Only Architecture (Same EC-Schnorr + Local EC-ElGamal) | 500 | 25 | 0.0448 | 0.0552 | 0.097 | 0.1051 | 0.0975 | 0.1822 | 0.0293 | 0.0242 | All operations on Device; Committee Sync on N Simulated Nodes |
| Edge-Assisted Architecture (AEALSF EC-Schnorr + Edge EC-ElGamal) | 500 | 25 | 0.041 | 0.0482 | 0.0935 | 0.102 | 0.0941 | 0.1745 | 0.0275 | 0.0226 | Prove/Encrypt/Decrypt on Device; Verify/HE-Add/ScalarMul on Edge + N Simulated Committee Nodes |
| Distributed-Validator Architecture (Committee Consensus Verification) | 500 | 25 | 0.042 | 0.0475 | 0.0948 | 0.0994 | 0.0973 | 0.1841 | 0.0294 | 0.0235 | Full Quorum Verification Across 500 Instantiated Committee Nodes |
| Local-Only Architecture (Same EC-Schnorr + Local EC-ElGamal) | 1000 | 25 | 0.0433 | 0.0458 | 0.131 | 0.1403 | 0.0995 | 0.1791 | 0.0293 | 0.0238 | All operations on Device; Committee Sync on N Simulated Nodes |
| Edge-Assisted Architecture (AEALSF EC-Schnorr + Edge EC-ElGamal) | 1000 | 25 | 0.0428 | 0.0524 | 0.1223 | 0.1326 | 0.0955 | 0.1805 | 0.029 | 0.0235 | Prove/Encrypt/Decrypt on Device; Verify/HE-Add/ScalarMul on Edge + N Simulated Committee Nodes |
| Distributed-Validator Architecture (Committee Consensus Verification) | 1000 | 25 | 0.0439 | 0.0524 | 0.1303 | 0.1413 | 0.0982 | 0.1887 | 0.0294 | 0.0242 | Full Quorum Verification Across 1000 Instantiated Committee Nodes |

> **Note**: Actual software execution measurements across N=4, 50, 200, 500, and 1,000 instantiated simulated validator committee nodes.
