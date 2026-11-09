import unittest
from api.main import AEALSFRuntime


class TestEdgeComputingLayer(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = AEALSFRuntime()
        self.dev = self.rt.device_manager.register_new_device(
            device_id="dev-edge-01",
            initial_cpu_percent=86.0,
            initial_free_ram_kb=290.0,
            initial_battery_percent=18.0,
        )

    def test_mutual_authentication_and_delegated_homomorphic_execution(self) -> None:
        res = self.dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[110, 240, 350],
            raw_packet_bytes=b"EDGE_TEST_STREAM_" * 32,
            adaptive_enabled=True,
        )
        self.assertEqual(res.selected_mode, "EDGE_ASSISTED_SECURITY_MODE")
        self.assertEqual(res.decrypted_aggregate_value, 700)
        self.assertTrue(res.offchain_integrity_verified)
        self.assertFalse(res.used_local_fallback)

    def test_edge_failover_to_secondary_node(self) -> None:
        self.rt.edge_cluster.monitor.set_node_availability("edge-node-0", online=False)
        res = self.dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=[50, 75],
            raw_packet_bytes=b"FAILOVER_PAYLOAD_" * 32,
            adaptive_enabled=True,
        )
        self.assertIn(res.executed_on_node, ("edge-node-1", "edge-node-2"))
        self.assertEqual(res.decrypted_aggregate_value, 125)
        self.assertTrue(res.offchain_integrity_verified)


if __name__ == "__main__":
    unittest.main()
