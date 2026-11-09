### Table 16 — Research-Gap Closure and Implementation Traceability Matrix

| Original_Paper_Mechanism | AEALSF_Implementation | Classification | Reason | Validation_Test |
| --- | --- | --- | --- | --- |
| Embedded Wallet & Key Isolation (Sec III, Fig. 5) | cryptography/key_manager.py, device/device_identity.py | Faithful | Preserves strict device wallet encapsulation of secrets s and d | tests/test_device.py |
| Solidity Smart Contracts & C SDK Generator (Sec III, Fig. 10) | smart_contracts/*.sol, blockchain/smart_contract_manager.py | Faithful + Simulated Engine | Solidity sources + deterministic Python state engine (simulated validator nodes) | tests/test_blockchain.py |
| 2048-bit Finite-Field DLP NIZK (Sec IV-A, Eq. 1-5, Alg. 1) | cryptography/nizk_authentication.py (NIZKAuthenticator) | Faithful + Hardened | Adds verifier-originated challenge registry and 6-field context binding | tests/test_nizk.py |
| 256-bit Elliptic-Curve Schnorr NIZK (PK=sG, zG=R+cPK) | cryptography/nizk_authentication.py (ECSchnorrNIZKAuthenticator) | Deviated / Enhanced | Replaces 2048-bit modular exponentiation with secp256k1 point arithmetic for lightweight auth | tests/test_nizk.py |
| Circom 2.0 / Groth16 Circuit (Sec V-B1, Fig. 11) | smart_contracts/Algorithm1.circom, CircomR1CSConstraintVerifier | Reconstructed R1CS Checker | Evaluates R1CS algebraic constraints in Python; explicitly not claimed as a Groth16 SNARK prover | tests/test_nizk.py |
| Additive EC-ElGamal Homomorphic Encryption (Sec IV-B, Eq. 6-12) | cryptography/homomorphic_encryption.py | Faithful | Implements (rG, mG+rQ), homomorphic addition, public scalar mul, rerandomization, and BSGS recovery | tests/test_homomorphic.py |
| DVRC Reputation Consensus (Sec VI-A, Ref [45]) | blockchain/dvrc_consensus.py | Reconstructed from Ref [45] | 5-metric reputation (Da,Re,Ds,Fs,Cs) with asymmetric update (phi=0.04 << delta_w=0.35) | tests/test_blockchain.py |
| Two-Layer Simulation Environment + 15-Factor Adaptive Engine + Full (C1,C2) Verifier | config/simulation_config.py, adaptive_engine/*, edge/result_verifier.py | Core AEALSF Contribution | Separates host vs simulated IoT/edge/validator resources and verifies both C1 and C2 | tests/test_instrumentation_and_corrective.py |
