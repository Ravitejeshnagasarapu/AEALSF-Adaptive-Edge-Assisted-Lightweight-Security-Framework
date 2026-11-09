import os
import unittest
from experiments.calibrate_weights import run_weight_calibration_experiment
from experiments.ddos_and_entropy_eval import evaluate_ddos_and_cryptographic_security
from smart_contracts.c_sdk_generator import generate_all_embedded_c_sdks


class TestCalibrationDDoSAndCSDK(unittest.TestCase):
    def test_weight_calibration_pareto_evaluation(self) -> None:
        res = run_weight_calibration_experiment(num_synthetic_tasks=40)
        self.assertEqual(len(res["profiles"]), 6)
        self.assertIn("optimal_profile", res)

    def test_ddos_50k_and_cryptographic_entropy_equations(self) -> None:
        res = evaluate_ddos_and_cryptographic_security(
            num_legitimate_clients=100, num_ddos_requests=5000
        )
        ddos = res["ddos_simulation"]
        crypto = res["cryptographic_security_metrics"]
        self.assertEqual(ddos["legitimate_success_rate_pct"], 100.0)
        self.assertEqual(ddos["malicious_filtering_rate_pct"], 100.0)
        self.assertGreater(crypto["eq15_ciphertext_shannon_entropy_bits_per_byte"], 7.8)
        self.assertEqual(crypto["eq16_homomorphic_verification_accuracy_pct"], 100.0)
        self.assertTrue(crypto["nizk_completeness_verified"])

    def test_solidity_to_c_sdk_generator(self) -> None:
        out_dir = "smart_contracts/generated_c_sdk"
        generated = generate_all_embedded_c_sdks(output_dir=out_dir)
        self.assertIn("DeviceRegistry", generated)
        self.assertIn("SecurityManager", generated)
        self.assertIn("TaskManagement", generated)
        for info in generated.values():
            self.assertTrue(os.path.exists(info["abi_json"]))
            self.assertTrue(os.path.exists(info["header"]))
            self.assertTrue(os.path.exists(info["source"]))


if __name__ == "__main__":
    unittest.main()
