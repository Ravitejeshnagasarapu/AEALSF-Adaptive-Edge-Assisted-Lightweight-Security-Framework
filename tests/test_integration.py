import unittest
from fastapi.testclient import TestClient
from api.main import create_app


class TestAEALSFEndToEndIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = TestClient(self.app)

    def test_full_api_workflow_registration_auth_task_and_monitoring(self) -> None:
        r_health = self.client.get("/health")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(r_health.json()["status"], "healthy")

        r_reg = self.client.post(
            "/devices/register",
            json={
                "device_id": "l610-node-101",
                "device_name": "Fibocom L610-CN",
                "device_description": "Smart Factory Sensor",
                "hardware_model": "L610-CN",
                "initial_cpu_percent": 82.5,
                "initial_free_ram_kb": 310.0,
                "initial_battery_percent": 20.0,
                "initial_latency_ms": 24.0,
                "initial_bandwidth_mbps": 72.0,
            },
        )
        self.assertEqual(r_reg.status_code, 200)
        self.assertEqual(r_reg.json()["status"], "registered")

        r_auth = self.client.post(
            "/authentication/nizk",
            json={"device_id": "l610-node-101", "allow_session_reuse": False},
        )
        self.assertEqual(r_auth.status_code, 200)
        self.assertTrue(r_auth.json()["authenticated"])

        r_task = self.client.post(
            "/tasks/execute",
            json={
                "device_id": "l610-node-101",
                "telemetry_values": [120, 280, 600],
                "payload_text": "INDUSTRIAL_VIBRATION_TELEMETRY_FRAME",
                "adaptive_enabled": True,
                "priority": "HIGH",
            },
        )
        self.assertEqual(r_task.status_code, 200)
        data = r_task.json()
        self.assertEqual(data["decrypted_aggregate_value"], 1000)
        self.assertEqual(data["selected_mode"], "EDGE_ASSISTED_SECURITY_MODE")
        self.assertTrue(data["offchain_integrity_verified"])

        r_chain = self.client.get("/blockchain/status")
        self.assertEqual(r_chain.status_code, 200)
        self.assertTrue(r_chain.json()["chain_integrity_verified"])

        r_mon = self.client.get("/monitoring/summary")
        self.assertEqual(r_mon.status_code, 200)
        self.assertGreaterEqual(r_mon.json()["total_samples"], 1)

        r_prom = self.client.get("/monitoring/metrics")
        self.assertEqual(r_prom.status_code, 200)
        self.assertIn("aealsf_tasks_total", r_prom.text)


if __name__ == "__main__":
    unittest.main()
