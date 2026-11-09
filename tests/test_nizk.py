import time
import unittest
from cryptography.homomorphic_encryption import ECPoint, INFINITY_POINT
from cryptography.nizk_authentication import (
    CircomR1CSConstraintVerifier,
    ECSchnorrNIZKAuthenticator,
    ECSchnorrProof,
    NIZKAuthenticator,
    NIZKProof,
)


class TestNIZKAuthentication(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = NIZKAuthenticator()
        self.kp = self.auth.generate_keypair("dev-nizk-01")
        self.ec_auth = ECSchnorrNIZKAuthenticator()
        self.ec_kp = self.ec_auth.generate_keypair("dev-ec-01")

    def test_completeness_valid_proof_accepted(self) -> None:
        proof = self.auth.generate_proof(
            self.kp, context_bind="TEST_CTX", verifier_id="ver-01"
        )
        valid, msg = self.auth.verify_proof(
            proof,
            expected_pk=self.kp.public_key_pk,
            expected_context="TEST_CTX",
            expected_device_id="dev-nizk-01",
            expected_verifier_id="ver-01",
        )
        self.assertTrue(valid, msg)

    def test_ec_schnorr_completeness_and_verification_equation(self) -> None:
        v_nonce = self.ec_auth.issue_verifier_nonce()
        proof = self.ec_auth.generate_proof(
            self.ec_kp, verifier_id="edge-node-0", verifier_nonce=v_nonce
        )
        valid, msg = self.ec_auth.verify_proof(
            proof,
            expected_pk=self.ec_kp.public_key_pk,
            expected_device_id="dev-ec-01",
            expected_verifier_id="edge-node-0",
        )
        self.assertTrue(valid, msg)

    def test_ec_schnorr_context_and_expiry_checks(self) -> None:
        v_nonce = self.ec_auth.issue_verifier_nonce()
        proof = self.ec_auth.generate_proof(
            self.ec_kp, verifier_id="edge-node-0", verifier_nonce=v_nonce
        )
        ok_v, msg_v = self.ec_auth.verify_proof(
            proof, expected_verifier_id="edge-node-1", record_nonce=False
        )
        self.assertFalse(ok_v)
        self.assertIn("Verifier ID mismatch", msg_v)

        ok_d, msg_d = self.ec_auth.verify_proof(
            proof, expected_domain="WRONG-DOMAIN", record_nonce=False
        )
        self.assertFalse(ok_d)
        self.assertIn("Protocol domain mismatch", msg_d)

        expired_proof = self.ec_auth.generate_proof(
            self.ec_kp,
            verifier_id="edge-node-0",
            timestamp=time.time() - 3600.0,
        )
        ok_exp, msg_exp = self.ec_auth.verify_proof(expired_proof)
        self.assertFalse(ok_exp)
        self.assertIn("Expired", msg_exp)

        bad_curve_proof = ECSchnorrProof(
            device_id=proof.device_id,
            verifier_id=proof.verifier_id,
            protocol_domain=proof.protocol_domain,
            verifier_nonce=self.ec_auth.issue_verifier_nonce(),
            timestamp=time.time(),
            commitment_r=ECPoint(12345, 67890),
            challenge_c=proof.challenge_c,
            response_z=proof.response_z,
            public_key_pk=proof.public_key_pk,
        )
        ok_c, msg_c = self.ec_auth.verify_proof(bad_curve_proof)
        self.assertFalse(ok_c)
        self.assertIn("Invalid commitment R", msg_c)

        inf_pk_proof = ECSchnorrProof(
            device_id=proof.device_id,
            verifier_id=proof.verifier_id,
            protocol_domain=proof.protocol_domain,
            verifier_nonce=self.ec_auth.issue_verifier_nonce(),
            timestamp=time.time(),
            commitment_r=proof.commitment_r,
            challenge_c=proof.challenge_c,
            response_z=proof.response_z,
            public_key_pk=INFINITY_POINT,
        )
        ok_inf, _ = self.ec_auth.verify_proof(inf_pk_proof)
        self.assertFalse(ok_inf)

    def test_soundness_wrong_secret_rejected(self) -> None:
        attacker_kp = self.auth.generate_keypair("attacker")
        forged_proof = self.auth.generate_proof(attacker_kp)
        impersonation_proof = NIZKProof(
            device_id="dev-nizk-01",
            commitment_r=forged_proof.commitment_r,
            response_z=forged_proof.response_z,
            challenge_c=forged_proof.challenge_c,
            public_key_pk=self.kp.public_key_pk,
            nonce=forged_proof.nonce,
            timestamp=forged_proof.timestamp,
        )
        valid, _ = self.auth.verify_proof(
            impersonation_proof, expected_pk=self.kp.public_key_pk
        )
        self.assertFalse(valid)

    def test_zero_knowledge_simulator_transcript(self) -> None:
        sim_proof = self.auth.simulate_zero_knowledge_transcript(self.kp.public_key_pk)
        valid, msg = self.auth.verify_proof(
            sim_proof, expected_pk=self.kp.public_key_pk
        )
        self.assertTrue(valid, msg)

    def test_circom_r1cs_constraints(self) -> None:
        proof = self.auth.generate_proof(self.kp)
        res = CircomR1CSConstraintVerifier.evaluate_r1cs_witness(
            pk=proof.public_key_pk,
            r_commit=proof.commitment_r,
            z_resp=proof.response_z,
            c_chal=proof.challenge_c,
            p=self.auth.p,
            g=self.auth.g,
            h_expected=proof.challenge_c,
            r_prime=proof.commitment_r,
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["public_inputs"], 8)
        self.assertEqual(res["public_outputs"], 4)

    def test_batch_nizk_verification(self) -> None:
        kps = [self.auth.generate_keypair(f"dev-batch-{i}") for i in range(6)]
        proofs = [self.auth.generate_proof(kp) for kp in kps]
        expected_pks = {kp.device_id: kp.public_key_pk for kp in kps}
        all_ok, per_item = self.auth.batch_verify_proofs(proofs, expected_pks)
        self.assertTrue(all_ok)
        self.assertEqual(per_item, [True] * 6)


if __name__ == "__main__":
    unittest.main()
