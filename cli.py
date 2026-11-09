from __future__ import annotations
import argparse
import json
import sys
import unittest

from api.main import AEALSFRuntime
from experiments.calibrate_weights import run_weight_calibration_experiment
from experiments.ddos_and_entropy_eval import evaluate_ddos_and_cryptographic_security
from experiments.generate_results import generate_all_figures
from smart_contracts.c_sdk_generator import generate_all_embedded_c_sdks


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aealsf",
        description="AEALSF: Adaptive Edge-Assisted Lightweight Security Framework CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "test", help="Run the full automated unit, security, and integration test suite"
    )
    sub.add_parser(
        "benchmark", help="Run 100/500/1000-device benchmarks and generate plots"
    )
    sub.add_parser(
        "calibrate",
        help="Run experimental calibration of cost weights (alpha, beta, gamma, delta)",
    )
    sub.add_parser(
        "ddos-eval",
        help="Run the 50,000-client DDoS flood & Eq. 13-16 cryptographic evaluation",
    )
    sub.add_parser(
        "generate-c-sdk",
        help="Generate embedded C99 SDK headers/sources from Solidity ABIs",
    )

    demo_p = sub.add_parser(
        "demo-workflow",
        help="Execute a complete 7-step end-to-end IoT security workflow",
    )
    demo_p.add_argument("--device-id", default="l610-demo-01")
    demo_p.add_argument("--cpu", type=float, default=84.0)
    demo_p.add_argument("--ram-kb", type=float, default=295.0)
    demo_p.add_argument("--battery", type=float, default=19.0)

    args = parser.parse_args()

    if args.command == "test":
        suite = unittest.defaultTestLoader.discover("tests")
        runner = unittest.TextTestRunner(verbosity=2)
        res = runner.run(suite)
        return 0 if res.wasSuccessful() else 1

    if args.command == "benchmark":
        rep = generate_all_figures(results_dir="results")
        print(json.dumps(rep["comparisons_by_device_count"], indent=2))
        return 0

    if args.command == "calibrate":
        res = run_weight_calibration_experiment()
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "ddos-eval":
        res = evaluate_ddos_and_cryptographic_security()
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "generate-c-sdk":
        res = generate_all_embedded_c_sdks()
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "demo-workflow":
        rt = AEALSFRuntime()
        dev = rt.device_manager.register_new_device(
            device_id=args.device_id,
            initial_cpu_percent=args.cpu,
            initial_free_ram_kb=args.ram_kb,
            initial_battery_percent=args.battery,
        )
        dev.local_security.warm_up_precomputed_he_pool(pool_size=4)
        res = dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[240, 360, 400],
            raw_packet_bytes=b"DEMO_TELEMETRY_FRAME_" * 26,
            adaptive_enabled=True,
            priority="HIGH",
        )
        chain_ok, chain_msg = rt.blockchain_client.integrity_verifier.verify_chain(
            rt.blockchain_client.chain
        )
        print(
            json.dumps(
                {
                    "task_id": res.task_id,
                    "device_id": res.device_id,
                    "selected_mode": res.selected_mode,
                    "executed_on_node": res.executed_on_node,
                    "decrypted_homomorphic_sum": res.decrypted_aggregate_value,
                    "onchain_result_hash": res.onchain_result_hash,
                    "offchain_integrity_verified": res.offchain_integrity_verified,
                    "blockchain_verified": chain_ok,
                    "blockchain_status": chain_msg,
                    "performance": res.performance_sample.to_dict(),
                },
                indent=2,
            )
        )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
