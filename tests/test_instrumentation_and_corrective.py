from __future__ import annotations
import dataclasses
import hashlib
import time
import unittest

from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    TaskRequirementProfile,
)
from api.main import AEALSFRuntime
from config.simulation_config import (
    VIRTUAL_IOT_PROFILES,
    SimulatedNetworkChannel,
    SimulatedResourceModel,
)
from cryptography.homomorphic_encryption import (
    BASE_POINT_G,
    ECElGamalCiphertext,
    ECElGamalHomomorphicEngine,
    ECPoint,
    INFINITY_POINT,
    ec_add,
)
from cryptography.nizk_authentication import (
    ECSchnorrNIZKAuthenticator,
    NIZKAuthenticator,
)
from edge.edge_executor import EdgeDelegatedTask
from experiments.baseline import execute_policy_trial_on_fleet
from monitoring.energy_estimator import EnergyEstimator
from monitoring.performance_monitor import PerformanceMonitor


class TestCorrectiveInstrumentationAndSecurity(unittest.TestCase):

    def setUp(self) -> None:
        self.rt = AEALSFRuntime()

    def test_phase2_controlled_and_idle_cpu_measurements(self) -> None:
        c0 = PerformanceMonitor.get_process_cpu_time_ms()
        t0 = time.perf_counter_ns()
        time.sleep(0.020)
        idle_wall_ms = (time.perf_counter_ns() - t0) / 1e6
        idle_cpu_ms = max(0.0, PerformanceMonitor.get_process_cpu_time_ms() - c0)
        idle_metrics = PerformanceMonitor.compute_cpu_utilization_metrics(
            idle_cpu_ms, idle_wall_ms
        )

        c1 = PerformanceMonitor.get_process_cpu_time_ms()
        t1 = time.perf_counter_ns()
        acc = b"controlled_cpu_workload"
        for _ in range(30000):
            acc = hashlib.sha256(acc).digest()
        busy_wall_ms = (time.perf_counter_ns() - t1) / 1e6
        busy_cpu_ms = max(0.0, PerformanceMonitor.get_process_cpu_time_ms() - c1)
        busy_metrics = PerformanceMonitor.compute_cpu_utilization_metrics(
            busy_cpu_ms, busy_wall_ms
        )

        self.assertGreater(idle_metrics["measurement_interval_ms"], 15.0)
        self.assertLess(idle_metrics["single_core_cpu_pct"], 25.0)
        self.assertGreater(busy_metrics["cpu_time_ms"], idle_metrics["cpu_time_ms"])
        self.assertGreater(busy_metrics["single_core_cpu_pct"], 50.0)

    def test_phase2_and_phase3_virtual_iot_profiles_and_two_layer_model(self) -> None:
        self.assertEqual(len(VIRTUAL_IOT_PROFILES), 3)
        p_high = VIRTUAL_IOT_PROFILES["HIGHLY_CONSTRAINED_IOT"]
        p_mod = VIRTUAL_IOT_PROFILES["MODERATELY_CONSTRAINED_IOT"]
        p_cap = VIRTUAL_IOT_PROFILES["MORE_CAPABLE_IOT"]
        self.assertEqual(p_high.cpu_capacity_mhz, 200.0)
        self.assertEqual(p_high.ram_capacity_kb, 512.0)
        self.assertEqual(p_mod.cpu_capacity_mhz, 500.0)
        self.assertEqual(p_mod.ram_capacity_kb, 2048.0)
        self.assertEqual(p_cap.cpu_capacity_mhz, 800.0)
        self.assertEqual(p_cap.ram_capacity_kb, 4096.0)

        sim_local = SimulatedResourceModel.evaluate_task_resources(
            profile=p_mod,
            execution_mode="LOCAL_SECURITY_MODE",
            payload_bytes=1200,
            num_he_ops=3,
            allow_session_reuse=False,
            background_device_cpu_pct=55.0,
            Simulated_network_delay_ms=12.0,
        )
        sim_edge = SimulatedResourceModel.evaluate_task_resources(
            profile=p_mod,
            execution_mode="EDGE_ASSISTED_SECURITY_MODE",
            payload_bytes=1200,
            num_he_ops=3,
            allow_session_reuse=False,
            background_device_cpu_pct=55.0,
            Simulated_network_delay_ms=35.0,
        )
        self.assertGreater(
            sim_local["simulated_device_cpu_ms"], sim_edge["simulated_device_cpu_ms"]
        )
        self.assertGreater(
            sim_local["simulated_device_memory_kb"],
            sim_edge["simulated_device_memory_kb"],
        )

    def test_phase2_and_phase3_no_arbitrary_multipliers_in_task_manager(self) -> None:
        with open("device/task_manager.py", "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("* 95.0", src)
        self.assertNotIn("0.30 * snapshot.cpu_utilization_percent", src)
        self.assertNotIn("* 42.0", src)
        self.assertNotIn("* 0.35", src)

    def test_phase2_and_phase3_local_vs_edge_separated_cpu_and_memory(self) -> None:
        dev = self.rt.device_manager.register_new_device(
            "inst-dev-01",
            initial_cpu_percent=88.0,
            initial_free_ram_kb=260.0,
            initial_battery_percent=15.0,
        )
        payload = b"REAL_TELEMETRY_FRAME_FOR_INSTRUMENTATION_" * 100

        res_local = dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[100, 200, 300],
            raw_packet_bytes=payload,
            scheduling_policy="ALWAYS_LOCAL",
        )
        s_loc = res_local.performance_sample

        res_edge = dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[100, 200, 300],
            raw_packet_bytes=payload,
            scheduling_policy="ALWAYS_EDGE",
        )
        s_edg = res_edge.performance_sample

        self.assertGreater(s_loc.host_process_rss_kb, 1000.0)
        self.assertGreaterEqual(
            s_loc.host_process_peak_rss_kb, s_loc.host_process_rss_kb
        )
        self.assertGreater(
            s_loc.device_cpu_utilization_percent, s_edg.device_cpu_utilization_percent
        )
        self.assertGreater(s_loc.device_memory_kb, s_edg.device_memory_kb)
        self.assertEqual(s_loc.edge_cpu_load_percent, 8.0)
        self.assertGreater(s_edg.edge_cpu_load_percent, 8.0)
        self.assertGreater(s_edg.edge_execution_time_ms, 0.0)
        self.assertGreater(s_edg.edge_server_memory_kb, 32.0)
        self.assertGreater(s_loc.measured_task_buffer_kb, s_edg.measured_task_buffer_kb)

    def test_phase4_and_phase5_true_concurrent_clients_and_measured_tps(self) -> None:
        with open("experiments/baseline.py", "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("4000.0 /", src)

        summary = execute_policy_trial_on_fleet(
            None, None, scheduling_policy="AEALSF", num_devices=100, trial_index=0
        )
        self.assertEqual(summary["configured_client_count"], 100)
        self.assertEqual(summary["actual_active_client_count"], 100)
        self.assertEqual(summary["completed_tasks"], 100)
        self.assertGreater(summary["completed_tps"], 0.0)
        self.assertGreater(summary["trial_wall_time_sec"], 0.0)

    def test_phase8_calibrated_cost_rejected_reasons_and_cooldown(self) -> None:
        cal = self.rt.decision_engine.cost_estimator.calibrated
        self.assertIn("ec_scalar_mul_ms", cal)
        self.assertGreater(cal["ec_scalar_mul_ms"], 0.0)
        self.assertGreater(cal["zlib_compress_kb_ms"], cal["zlib_decompress_kb_ms"])

        snap = DeviceResourceSnapshot(
            device_id="hyst-dev",
            cpu_utilization_percent=60.0,
            available_ram_kb=700.0,
            total_ram_kb=2048.0,
            battery_percent=45.0,
            network_latency_ms=25.0,
            available_bandwidth_mbps=80.0,
        )
        task = TaskRequirementProfile(
            task_id="t-1",
            task_type="HOMOMORPHIC_AGGREGATION",
            payload_bytes=2048,
            num_homomorphic_ops=4,
            data_sensitivity="CONFIDENTIAL_NO_EDGE_COMPRESSION",
        )
        dec = self.rt.decision_engine.select_execution_mode(
            snap, task, scheduling_policy="AEALSF"
        )
        self.assertIn("EDGE_ASSISTED_SECURITY_MODE", dec.rejected_options)
        self.assertIn(
            "Data Sensitivity", dec.rejected_options["EDGE_ASSISTED_SECURITY_MODE"]
        )

    def test_phase9_1_verifier_challenge_enforcement_and_revocation(self) -> None:
        ec_auth = ECSchnorrNIZKAuthenticator()
        kp = ec_auth.generate_keypair("sec-dev-01")

        forged_nonce_proof = ec_auth.generate_proof(
            kp,
            verifier_id="blockchain-verifier",
            verifier_nonce="prover_self_generated_nonce_123456",
            register_verifier_challenge_if_none=False,
        )
        ok_unissued, msg_unissued = ec_auth.verify_proof(
            forged_nonce_proof,
            expected_pk=kp.public_key_pk,
            require_verifier_issued_nonce=True,
        )
        self.assertFalse(ok_unissued)
        self.assertIn("not issued by the verifier", msg_unissued)

        ticket = ec_auth.issue_verifier_challenge("sec-dev-01", "blockchain-verifier")
        valid_proof = ec_auth.generate_proof(
            kp, verifier_id="blockchain-verifier", verifier_nonce=ticket.nonce
        )
        ok_first, _ = ec_auth.verify_proof(
            valid_proof,
            expected_pk=kp.public_key_pk,
            require_verifier_issued_nonce=True,
        )
        self.assertTrue(ok_first)

        ok_replay, msg_replay = ec_auth.verify_proof(
            valid_proof,
            expected_pk=kp.public_key_pk,
            require_verifier_issued_nonce=True,
        )
        self.assertFalse(ok_replay)
        self.assertIn("Replay", msg_replay)

        dlp_auth = NIZKAuthenticator()
        tok = dlp_auth.issue_session_token("sec-dev-01", kp.public_key_pk)
        self.assertTrue(
            dlp_auth.verify_session_token(tok, "sec-dev-01", kp.pk_fingerprint)
        )
        dlp_auth.revoke_session_token(tok.token_id)
        self.assertFalse(
            dlp_auth.verify_session_token(tok, "sec-dev-01", kp.pk_fingerprint)
        )

    def test_phase9_3_all_10_delegated_result_verification_attacks(self) -> None:
        dev = self.rt.device_manager.register_new_device("adv-ver-dev")
        cts = dev.local_security.encrypt_telemetry_homomorphic([110, 240])
        scalars = [2, 3]
        in_hash = "0xinputhash"
        now = time.time()
        msg = f"task-adv|adv-ver-dev|HOMOMORPHIC_AGGREGATION|{in_hash}|nonce-adv|{now:.6f}".encode(
            "utf-8"
        )
        sig = dev.wallet.credentials.sign_message(msg)

        task = EdgeDelegatedTask(
            task_id="task-adv",
            device_id="adv-ver-dev",
            task_type="HOMOMORPHIC_AGGREGATION",
            execution_mode="HYBRID_SECURITY_MODE",
            input_payload_hash=in_hash,
            nonce="nonce-adv",
            timestamp=now,
            device_signature=sig,
            homomorphic_ciphertexts=cts,
            public_scalars=scalars,
        )
        edge_exec = self.rt.edge_cluster.servers["edge-node-0"].executor
        valid_rcpt = edge_exec.execute_delegated_task(task)
        verifier = self.rt.edge_cluster.result_verifier

        def _resign(rcpt_mod):
            import json
            from cryptography.verification import CryptographicVerifier

            rb = (
                json.dumps(
                    rcpt_mod.aggregated_ciphertext.to_dict(), sort_keys=True
                ).encode("utf-8")
                if rcpt_mod.aggregated_ciphertext is not None
                else rcpt_mod.result_bytes
            )
            rh = CryptographicVerifier.sha256_hex(rb)
            unsigned = dataclasses.replace(
                rcpt_mod,
                result_bytes=rb,
                result_payload_hash=rh,
                receipt_id="rcpt-"
                + hashlib.sha256(str(time.perf_counter_ns()).encode()).hexdigest()[:12],
                edge_signature="",
            )
            new_sig = self.rt.key_manager.sign_as_edge_node(
                "edge-node-0", unsigned.compute_canonical_bytes()
            )
            return dataclasses.replace(unsigned, edge_signature=new_sig)

        agg = valid_rcpt.aggregated_ciphertext
        assert agg is not None

        bad_c1_ct = dataclasses.replace(agg, c1=ec_add(agg.c1, BASE_POINT_G))
        r1 = _resign(dataclasses.replace(valid_rcpt, aggregated_ciphertext=bad_c1_ct))
        m1 = verifier.verify_receipt_with_metrics(task, r1)
        self.assertFalse(m1.verified, "Scenario 1 (Invalid C1) must be rejected")

        bad_c2_ct = dataclasses.replace(agg, c2=ec_add(agg.c2, BASE_POINT_G))
        r2 = _resign(dataclasses.replace(valid_rcpt, aggregated_ciphertext=bad_c2_ct))
        m2 = verifier.verify_receipt_with_metrics(task, r2)
        self.assertFalse(m2.verified, "Scenario 2 (Invalid C2 only) must be rejected")
        self.assertIn("C2", m2.reason)

        bad_ops_ct = dataclasses.replace(agg, operations_count=agg.operations_count + 1)
        r3 = _resign(dataclasses.replace(valid_rcpt, aggregated_ciphertext=bad_ops_ct))
        m3 = verifier.verify_receipt_with_metrics(task, r3)
        self.assertFalse(
            m3.verified, "Scenario 3 (Modified operation count) must be rejected"
        )

        r4 = _resign(
            dataclasses.replace(valid_rcpt, partial_checkpoint_c1_hex="0xdeadbeef")
        )
        m4 = verifier.verify_receipt_with_metrics(task, r4)
        self.assertFalse(
            m4.verified, "Scenario 4 (Altered commitment) must be rejected"
        )

        r5 = dataclasses.replace(
            valid_rcpt, receipt_id="rcpt-forged", edge_signature="00" * 32
        )
        m5 = verifier.verify_receipt_with_metrics(task, r5)
        self.assertFalse(
            m5.verified, "Scenario 5 (Forged edge signature) must be rejected"
        )

        ok_valid = verifier.verify_receipt_with_metrics(task, valid_rcpt)
        self.assertTrue(ok_valid.verified)
        m6 = verifier.verify_receipt_with_metrics(task, valid_rcpt)
        self.assertFalse(
            m6.verified, "Scenario 6 (Replay of old result) must be rejected"
        )

        r7 = dataclasses.replace(valid_rcpt, receipt_id="rcpt-w-edge")
        m7 = verifier.verify_receipt_with_metrics(
            task, r7, expected_edge_node_id="edge-node-2"
        )
        self.assertFalse(
            m7.verified, "Scenario 7 (Wrong edge identity) must be rejected"
        )

        r8 = dataclasses.replace(valid_rcpt, task_id="wrong-task-id-999")
        m8 = verifier.verify_receipt_with_metrics(task, r8)
        self.assertFalse(
            m8.verified, "Scenario 8 (Wrong task identity) must be rejected"
        )

        unweighted_sum = ECElGamalHomomorphicEngine.homomorphic_sum(cts)
        wrong_agg_ct = dataclasses.replace(
            unweighted_sum, operations_count=agg.operations_count
        )
        r9 = _resign(
            dataclasses.replace(valid_rcpt, aggregated_ciphertext=wrong_agg_ct)
        )
        m9 = verifier.verify_receipt_with_metrics(task, r9)
        self.assertFalse(
            m9.verified, "Scenario 9 (Incorrect aggregation) must be rejected"
        )

        off_curve_pt = ECPoint(12345, 67890)
        bad_pt_ct = dataclasses.replace(agg, c2=off_curve_pt)
        r10 = _resign(dataclasses.replace(valid_rcpt, aggregated_ciphertext=bad_pt_ct))
        m10 = verifier.verify_receipt_with_metrics(task, r10)
        self.assertFalse(
            m10.verified, "Scenario 10 (Malformed curve points) must be rejected"
        )

    def test_phase12_energy_sensitivity_analysis(self) -> None:
        est = EnergyEstimator()
        rows = est.run_sensitivity_analysis(
            local_cpu_ms=4.5,
            local_bytes_tx=680,
            edge_dev_cpu_ms=1.2,
            edge_bytes_tx=4850,
            edge_wait_ms=24.0,
        )
        self.assertEqual(len(rows), 9)
        for r in rows:
            self.assertEqual(r["classification"], "MODEL_ESTIMATED")
            self.assertGreater(float(r["estimated_local_energy_mj"]), 0.0)


if __name__ == "__main__":
    unittest.main()
