import unittest
from adaptive_engine.decision_engine import AdaptiveDecisionEngine, ExecutionMode
from adaptive_engine.execution_scheduler import AdaptiveExecutionScheduler
from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    TaskRequirementProfile,
)
from edge.edge_monitor import EdgeMonitor
from edge.failover_manager import EdgeFailoverManager


class TestAdaptiveDecisionEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = EdgeMonitor(["edge-node-0", "edge-node-1"])
        self.failover = EdgeFailoverManager(self.monitor)
        self.engine = AdaptiveDecisionEngine(self.failover)

    def test_selects_local_mode_when_abundant_resources_and_high_rtt(self) -> None:
        snap = DeviceResourceSnapshot(
            device_id="dev-abundant",
            cpu_utilization_percent=14.0,
            available_ram_kb=1850.0,
            total_ram_kb=2048.0,
            battery_percent=96.0,
            network_latency_ms=135.0,
            available_bandwidth_mbps=4.0,
        )
        task = TaskRequirementProfile(
            task_id="t-local",
            task_type="HOMOMORPHIC_AGGREGATION",
            payload_bytes=512,
            num_homomorphic_ops=1,
        )
        rec = self.engine.select_execution_mode(snap, task)
        self.assertEqual(rec.selected_mode, ExecutionMode.LOCAL_SECURITY_MODE)

    def test_selects_hybrid_mode_when_moderately_constrained(self) -> None:
        snap = DeviceResourceSnapshot(
            device_id="dev-moderate",
            cpu_utilization_percent=58.0,
            available_ram_kb=760.0,
            total_ram_kb=2048.0,
            battery_percent=46.0,
            network_latency_ms=22.0,
            available_bandwidth_mbps=65.0,
        )
        task = TaskRequirementProfile(
            task_id="t-hybrid",
            task_type="HOMOMORPHIC_AGGREGATION",
            payload_bytes=1024,
            num_homomorphic_ops=4,
        )
        rec = self.engine.select_execution_mode(snap, task)
        self.assertEqual(rec.selected_mode, ExecutionMode.HYBRID_SECURITY_MODE)

    def test_selects_edge_assisted_mode_when_severely_constrained(self) -> None:
        snap = DeviceResourceSnapshot(
            device_id="dev-severe",
            cpu_utilization_percent=89.0,
            available_ram_kb=260.0,
            total_ram_kb=2048.0,
            battery_percent=16.0,
            network_latency_ms=18.0,
            available_bandwidth_mbps=75.0,
        )
        task = TaskRequirementProfile(
            task_id="t-edge",
            task_type="HOMOMORPHIC_AGGREGATION",
            payload_bytes=2048,
            num_homomorphic_ops=6,
        )
        rec = self.engine.select_execution_mode(snap, task)
        self.assertEqual(rec.selected_mode, ExecutionMode.EDGE_ASSISTED_SECURITY_MODE)
        self.assertIsNotNone(rec.selected_edge_node_id)

    def test_pins_private_key_operations_strictly_to_local_mode(self) -> None:
        snap = DeviceResourceSnapshot(
            device_id="dev-severe-secret",
            cpu_utilization_percent=94.0,
            available_ram_kb=210.0,
            total_ram_kb=2048.0,
            battery_percent=12.0,
            network_latency_ms=10.0,
            available_bandwidth_mbps=90.0,
        )
        secret_task = TaskRequirementProfile(
            task_id="t-secret",
            task_type="PRIVATE_KEY_DECRYPTION",
            payload_bytes=512,
            requires_private_key_access=True,
        )
        rec = self.engine.select_execution_mode(snap, secret_task)
        self.assertEqual(rec.selected_mode, ExecutionMode.LOCAL_SECURITY_MODE)
        self.assertTrue(rec.policy_decision.mandatory_local_only)

    def test_priority_scheduler_ordering(self) -> None:
        sched = AdaptiveExecutionScheduler(self.engine)
        snap = DeviceResourceSnapshot("dev-1", 50.0, 900.0, 2048.0, 70.0, 25.0, 60.0)
        sched.enqueue_task(
            snap,
            TaskRequirementProfile("t-low", "DATA_COMPRESSION", 512, priority="LOW"),
        )
        sched.enqueue_task(
            snap,
            TaskRequirementProfile(
                "t-crit", "DATA_COMPRESSION", 512, priority="CRITICAL"
            ),
        )
        _, first_task, _ = sched.schedule_next()
        self.assertEqual(first_task.task_id, "t-crit")


if __name__ == "__main__":
    unittest.main()
