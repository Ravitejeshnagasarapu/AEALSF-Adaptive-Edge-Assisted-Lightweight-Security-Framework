### Table 11 — Security, Verifier-Challenge Freshness, and 10-Point Delegated Verification Test Results

| Test_ID | Category | Scenario | Expected | Status | Test_File |
| --- | --- | --- | --- | --- | --- |
| SEC-01 | Delegated Verification (1/10) | Invalid C1 component in aggregated ciphertext | Reject (C1 != sum k_i*C1_i) | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-02 | Delegated Verification (2/10) | Invalid C2 component ONLY (C1 valid, C2 = C2+G) | Reject (C2 != sum k_i*C2_i) | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-03 | Delegated Verification (3/10) | Modified homomorphic operation count | Reject operation_count mismatch | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-04 | Delegated Verification (4/10) | Incorrect result / checkpoint commitment hex | Reject partial_checkpoint_c1_hex mismatch | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-05 | Delegated Verification (5/10) | Forged edge HMAC-SHA256 signature | Reject invalid edge signature | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-06 | Delegated Verification (6/10) | Replayed edge execution receipt | Reject duplicate receipt_id:nonce | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-07 | Delegated Verification (7/10) | Wrong edge node identity on receipt | Reject edge_node_id mismatch | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-08 | Delegated Verification (8/10) | Wrong task identity on receipt | Reject task_id mismatch | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-09 | Delegated Verification (9/10) | Incorrect aggregation (unweighted instead of scalar-weighted) | Reject (C1, C2) algebraic mismatch | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-10 | Delegated Verification (10/10) | Malformed curve point (off-curve or infinity) | Reject off-curve point | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-11 | NIZK Challenge Freshness | Prover-fabricated nonce not issued by verifier | Reject unissued verifier_nonce | PASS | tests/test_instrumentation_and_corrective.py |
| SEC-12 | Session Revocation | Re-use of explicitly revoked session token | Reject revoked token_id | PASS | tests/test_instrumentation_and_corrective.py |
