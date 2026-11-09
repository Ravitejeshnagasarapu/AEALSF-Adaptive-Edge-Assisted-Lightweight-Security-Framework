import time
import unittest
from adaptive_engine.resource_analyzer import DeviceResourceSnapshot
from api.main import AEALSFRuntime
from blockchain.smart_contract_manager import ContractExecutionError
from cryptography.nizk_authentication import NIZKProof
from edge.edge_executor import EdgeDelegatedTask


class TestSecurityAttackScenarios(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = AEALSFRuntime()
        self.legit_dev = self.rt.device_manager.register_new_device(
            device_id="legit-iot-01",
            initial_cpu_percent=85.0,
            initial_free_ram_kb=280.0,
            initial_battery_percent=19.0,
        )

    def test_01_unauthorized_duplicate_device_registration_rejected(self) -> None:
        with self.assertRaises(RuntimeError):
            self.rt.device_manager.register_new_device(device_id="legit-iot-01")

    def test_02_device_impersonation_attempt_rejected(self) -> None:
        self.rt.key_manager.provision_device_wallet("attacker-dev")
        tx = self.rt.blockchain_client.tx_manager.create_signed_transaction(
            sender_device_id="attacker-dev",
            contract_name="TaskManagement",
            method_name="createTask",
            payload={
                "taskId": "forged-task-1",
                "deviceId": "legit-iot-01",
                "assignedNodeId": "legit-iot-01",
                "mode": "LOCAL_SECURITY_MODE",
                "inputPayloadHash": "0x1234",
            },
        )
        ok, _, _, msg = self.rt.blockchain_client.submit_and_execute_transaction(tx)
        self.assertFalse(ok)
        self.assertIn("caller must match task owner", msg)

    def test_03_invalid_nizk_proof_rejected(self) -> None:
        valid_proof = self.legit_dev.local_security.generate_nizk_auth_proof()
        corrupted_proof = NIZKProof(
            device_id=valid_proof.device_id,
            commitment_r=valid_proof.commitment_r,
            response_z=(valid_proof.response_z + 17) % (self.rt.nizk_auth.p - 1),
            challenge_c=valid_proof.challenge_c,
            public_key_pk=valid_proof.public_key_pk,
            nonce=valid_proof.nonce,
            timestamp=valid_proof.timestamp,
        )
        ver_ok, _ = self.rt.nizk_auth.verify_proof(
            corrupted_proof,
            expected_pk=self.legit_dev.wallet.credentials.nizk_keypair.public_key_pk,
        )
        self.assertFalse(ver_ok)

    def test_04_replay_attack_detected_and_rejected(self) -> None:
        proof = self.legit_dev.local_security.generate_nizk_auth_proof()
        ok1, _ = self.rt.nizk_auth.verify_proof(proof)
        self.assertTrue(ok1)
        ok2, msg2 = self.rt.nizk_auth.verify_proof(proof)
        self.assertFalse(ok2)
        self.assertIn("Replay attack detected", msg2)

    def test_05_unauthorized_edge_node_access_rejected(self) -> None:
        ok, _, msg = self.rt.edge_cluster.authenticator.perform_mutual_handshake(
            device_id="legit-iot-01",
            edge_node_id="rogue-unregistered-edge-99",
        )
        self.assertFalse(ok)
        self.assertIn("not authorized", msg)

    def test_06_tampered_delegated_result_detected_and_failed_over(self) -> None:
        rep_before = self.rt.blockchain_client.dvrc.profiles[
            "edge-node-0"
        ].reputation_score
        res = self.legit_dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[300, 400],
            raw_packet_bytes=b"TAMPER_TEST_DATA_" * 32,
            adaptive_enabled=True,
            public_scalars=[1, 1],
            simulate_edge_tampering_node="edge-node-0",
        )
        rep_after = self.rt.blockchain_client.dvrc.profiles[
            "edge-node-0"
        ].reputation_score
        self.assertLess(rep_after, rep_before)
        self.assertNotEqual(res.executed_on_node, "edge-node-0")
        self.assertEqual(res.decrypted_aggregate_value, 700)
        self.assertTrue(res.offchain_integrity_verified)

    def test_07_invalid_blockchain_transaction_rejected(self) -> None:
        tx = self.rt.blockchain_client.tx_manager.create_signed_transaction(
            sender_device_id="legit-iot-01",
            contract_name="DeviceRegistry",
            method_name="getDevice",
            payload={"deviceId": "legit-iot-01"},
            tx_type="GET",
        )
        tx.payload["deviceId"] = "tampered-id"
        ok, _, _, msg = self.rt.blockchain_client.submit_and_execute_transaction(tx)
        self.assertFalse(ok)
        self.assertIn("payload hash mismatch", msg)

    def test_08_unauthorized_smart_contract_admin_operation_rejected(self) -> None:
        with self.assertRaises(ContractExecutionError):
            self.rt.blockchain_client.contracts.invoke(
                contract_name="SecurityManager",
                method_name="authorizeEdgeNode",
                caller_device_id="legit-iot-01",
                caller_address=self.legit_dev.wallet.wallet_address,
                args={"edgeNodeId": "rogue-edge", "publicTokenHash": "0x999"},
            )

    def test_09_key_handling_violation_blocked_at_edge(self) -> None:
        forbidden_task = EdgeDelegatedTask(
            task_id="bad-key-leak",
            device_id="legit-iot-01",
            task_type="DATA_COMPRESSION",
            execution_mode="EDGE_ASSISTED_SECURITY_MODE",
            input_payload_hash="0x11",
            nonce="n1",
            timestamp=time.time(),
            device_signature="sig",
            raw_data_bytes=b"abc",
            data_sensitivity="PUBLIC_COMPRESSIBLE",
            extra_metadata={"private_key_d": 12345},
        )
        with self.assertRaises(PermissionError):
            self.rt.edge_cluster.servers["edge-node-0"].executor.execute_delegated_task(
                forbidden_task
            )

    def test_10_and_11_network_interruption_all_edges_offline_triggers_local_fallback(
        self,
    ) -> None:
        for nid in self.rt.edge_config.edge_node_ids:
            self.rt.edge_cluster.monitor.set_node_availability(nid, online=False)

        res = self.legit_dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[90, 110, 200],
            raw_packet_bytes=b"OFFLINE_FALLBACK_TEST_" * 25,
            adaptive_enabled=True,
            public_scalars=[1, 1, 1],
        )
        self.assertEqual(res.selected_mode, "LOCAL_SECURITY_MODE")
        self.assertEqual(res.executed_on_node, "legit-iot-01")
        self.assertEqual(res.decrypted_aggregate_value, 400)
        self.assertTrue(res.offchain_integrity_verified)

    def test_12_byzantine_edge_computational_lie_detected_and_failed_over(self) -> None:
        res = self.legit_dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[150, 250],
            raw_packet_bytes=b"COMPUTATIONAL_LIE_TEST_" * 32,
            adaptive_enabled=True,
            public_scalars=[2, 1],
            simulate_computational_lie_node="edge-node-0",
        )
        self.assertNotEqual(res.executed_on_node, "edge-node-0")
        self.assertEqual(res.decrypted_aggregate_value, 550)
        self.assertTrue(res.offchain_integrity_verified)

    def test_13_invalid_device_telemetry_rejected(self) -> None:
        bad_snap = DeviceResourceSnapshot(
            device_id="legit-iot-01",
            cpu_utilization_percent=145.0,
            available_ram_kb=-50.0,
            total_ram_kb=2048.0,
            battery_percent=50.0,
            network_latency_ms=10.0,
            available_bandwidth_mbps=50.0,
        )
        with self.assertRaises(ValueError):
            self.rt.decision_engine.analyzer.analyze(bad_snap)

    def test_14_blockchain_validator_unavailability_resilience(self) -> None:
        self.rt.blockchain_client.dvrc.set_validator_fault_state("node3", offline=True)
        res = self.legit_dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[100, 200],
            raw_packet_bytes=b"VALIDATOR_FAULT_TEST_" * 28,
            adaptive_enabled=True,
            public_scalars=[1, 1],
        )
        self.assertEqual(res.decrypted_aggregate_value, 300)
        self.assertTrue(res.offchain_integrity_verified)


if __name__ == "__main__":
    unittest.main()
