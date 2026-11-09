# Implementation Details & Documented Deviations from the Original Paper

This document details the exact protocol implementations and explicitly documents every reconciliation where [_Constructing Next-Generation IoT Security: Embedded Smart Contracts and Multilayer Security Protection_ (Zhang et al., IEEE IoT Journal, 2025)](https://www.researchgate.net/publication/388946680_Constructing_Next-Generation_IoT_Security_Embedded_Smart_Contracts_and_Multilayer_Security_Protection) contains incomplete mathematical specifications or internal inconsistencies between its theoretical sections (Section IV) and implementation notes (Section V).

## 1. Reconciliation of NIZK Specification (Section IV-A vs. Section V-B1)

### Paper Specification & Internal Discrepancy

- **Section IV-A (Equations 1 to 5, Algorithm 1)**: Defines a Discrete Logarithm Problem (DLP) Schnorr-style Non-Interactive Zero-Knowledge Proof over a prime field $\mathbb{Z}_p^*$:
  $$PK = g^s \bmod p, \quad R = g^r \bmod p, \quad c = H(R, PK), \quad z = (r + c \cdot s) \bmod (p - 1)$$
  with verification:
  $$R' = g^z \times PK^{-c} \bmod p, \quad c' = H(R', PK)$$
- **Section V-B1 (Fig. 11)**: States that Algorithm 1 was compiled into [Circom 2.0](https://docs.iden3.io/circom-snarkjs/) and [SnarkJS](https://github.com/iden3/snarkjs) Groth16 (`Algorithm 1.groth16.sol`), showing 8 public inputs (`PK, R, z, c, p, g, H, R'`) and 4 public outputs with 1 non-linear constraint and 3 linear constraints, while acknowledging in the text that Circom2 does not natively support modular exponentiation over arbitrary primes $p$.
- **Security Weakness in Raw Eq. (1)**: In Equation (1), $c = H(R, PK)$ binds only $R$ and $PK$ without a fresh nonce, timestamp, or session identifier. Because $PK$ is static, any passive eavesdropper intercepting $(R, z, c, PK)$ could replay the exact tuple verbatim to impersonate the device.

### AEALSF Implementation & Documented Resolution

1. **Full 2048-Bit Safe-Prime DLP NIZK (`cryptography/nizk_authentication.py`)**: We implement Algorithm 1 over the [IETF RFC 3526 Group 14](https://www.rfc-editor.org/info/rfc3526/) 2048-bit safe prime $p = 2q + 1$ ($g = 2$), which satisfies $g^{p-1} \equiv 1 \pmod p$ required by $z = (r + c \cdot s) \bmod (p - 1)$ while preventing Pohlig-Hellman small-subgroup leakage.
2. **Replay-Hardened Challenge Binding**: By default, `NIZKAuthenticator` computes $c = \text{SHA256}(R \parallel PK \parallel \text{nonce} \parallel \text{timestamp} \parallel \text{context})$ and enforces a strict TTL window and nonce consumption registry in both `NIZKAuthenticator` and `SecurityManager.sol`. A `strict_paper_mode=True` flag is also preserved for exact unit-test verification of raw Equation (1) and the Zero-Knowledge Simulator in Equation (5).
3. **Circom 2.0 Circuit & R1CS Verifier (`smart_contracts/Algorithm1.circom`)**: We include both the exact 8-input, 4-output Circom 2.0 template matching Fig. 11 and the `CircomR1CSConstraintVerifier` in Python so both the big-integer modular exponentiation and the R1CS algebraic constraints are verified.

## 2. Reconciliation of Homomorphic Encryption (Section IV-B vs. Section V-B2)

### Paper Specification & Internal Discrepancy

- **Section IV-B (Equations 6 to 12)**: Derives **Additive Elliptic Curve ElGamal (EC-ElGamal)** over an elliptic curve $E(\mathbb{F}_p)$ with base point $G$ of order $n$:
  - Key Generation (Eq. 6): $Q = \sum_{i=0}^k d_i \cdot 2^i G = d \cdot G$.
  - Encryption (Eq. 7 & 8): $m_1 \Rightarrow (C_1, C_2) = (r_1 G, m_1 G + r_1 Q)$; $m_2 \Rightarrow (D_1, D_2) = (r_2 G, m_2 G + r_2 Q)$.
  - Homomorphic Addition (Eq. 9): $(E_1, E_2) = (C_1 + D_1, C_2 + D_2) = ((r_1 + r_2)G, (m_1 + m_2)G + (r_1 + r_2)Q)$.
  - Decryption & Extraction (Eq. 10 to 12): $E_2 - d \cdot E_1 = (m_1 + m_2)G$, followed by extracting $m_1 + m_2 = (E_2 - d \cdot E_1) \times G^{-1}$.
- **Section V-B2**: Mentions modifying [Microsoft SEAL](https://github.com/microsoft/SEAL) v3.7.2 for public-key HE. However, Microsoft SEAL implements Ring-LWE lattice schemes (BFV and CKKS), not Elliptic Curve ElGamal. Furthermore, in Equation (12), the notation $\times G^{-1}$ on an elliptic curve point $(m_1 + m_2)G$ mathematically requires solving the bounded Elliptic Curve Discrete Logarithm Problem (ECDLP) to recover the integer sum $m_1 + m_2$ from the curve point $M = (m_1 + m_2)G$.

### AEALSF Implementation & Documented Resolution

- To preserve the relevant EC-ElGamal homomorphic operations used by the original design, we implement genuine **Additive EC-ElGamal over the standard [SECG SEC 2 `secp256k1` curve](https://www.secg.org/sec2-v2.pdf)** in `cryptography/homomorphic_encryption.py` using Jacobian projective coordinates for fast scalar multiplication, and implement **Baby-Step Giant-Step (BSGS)** discrete logarithm extraction to perform the exact $(E_2 - d \cdot E_1) \times G^{-1}$ plaintext recovery in Equation (12).

## 3. Blockchain Platform & DVRC Consensus (Section VI-A & Ref [45])

### Paper Specification & Environment Constraint

- The paper evaluates a 4-node permissioned blockchain (`node0`, `node1`, `node2`, `node3` in Table III) based on [FISCO BCOS](https://fisco-bcos-documentation.readthedocs.io/en/latest/) and replaces default PBFT with the **Dynamic Vehicle Reputation Consensus (DVRC)** algorithm from [Zhang et al., _IEEE TVT_ 2024 (Ref 45)](https://ieeexplore.ieee.org/iel8/25/4356907/10752705.pdf).
- For standalone and containerized execution without requiring external dependencies or a pre-installed Java/C++ FISCO BCOS binary daemon, we provide the complete Solidity smart contracts (`DeviceRegistry.sol`, `SecurityManager.sol`, `TaskManagement.sol`), a `docker-compose.yml` topology for 4-node deployment, and a deterministic, stateful Python Blockchain & Smart Contract Execution Engine (`blockchain/`) that faithfully executes the 5-stage DVRC consensus algorithm across `node0..node3` and enforces all smart contract guards, Merkle roots, and cryptographic signatures.
