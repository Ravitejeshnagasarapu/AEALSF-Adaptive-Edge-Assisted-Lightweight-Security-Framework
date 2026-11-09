import unittest
from api.main import AEALSFRuntime


class TestIoTDeviceLayer(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = AEALSFRuntime()

    def test_device_registration_and_wallet_isolation(self) -> None:
        dev = self.rt.device_manager.register_new_device(
            device_id="iot-dev-01",
            device_name="ML307A Module",
            hardware_model="ML307A",
        )
        pub = dev.wallet.get_public_identity()
        self.assertEqual(pub.device_id, "iot-dev-01")
        self.assertTrue(pub.blockchain_address.startswith("0x"))
        self.assertIsNotNone(dev.wallet.onchain_unique_id_hash)
        self.assertFalse(hasattr(pub, "private_key_s"))
        self.assertFalse(hasattr(pub, "private_key_d"))

    def test_resource_monitor_snapshot_and_deltas(self) -> None:
        dev = self.rt.device_manager.register_new_device("iot-dev-02")
        snap1 = dev.resource_monitor.capture_snapshot()
        dev.resource_monitor.apply_workload_delta(15.0, 200.0, 45.0)
        snap2 = dev.resource_monitor.capture_snapshot()
        self.assertGreater(snap2.cpu_utilization_percent, snap1.cpu_utilization_percent)
        self.assertLess(snap2.available_ram_kb, snap1.available_ram_kb)


if __name__ == "__main__":
    unittest.main()
