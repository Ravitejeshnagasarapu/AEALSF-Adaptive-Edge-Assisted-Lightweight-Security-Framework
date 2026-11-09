from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class EdgeNodeTelemetry:
    edge_node_id: str
    online: bool = True
    cpu_utilization_percent: float = 18.5
    memory_utilization_percent: float = 24.0
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    network_rtt_ms: float = 6.5
    available_bandwidth_mbps: float = 85.0
    last_heartbeat: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, object]:
        return {
            "edge_node_id": self.edge_node_id,
            "online": self.online,
            "cpu_utilization_percent": round(self.cpu_utilization_percent, 2),
            "memory_utilization_percent": round(self.memory_utilization_percent, 2),
            "active_tasks": self.active_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "network_rtt_ms": round(self.network_rtt_ms, 2),
            "available_bandwidth_mbps": round(self.available_bandwidth_mbps, 2),
            "last_heartbeat": self.last_heartbeat,
        }


class EdgeMonitor:

    def __init__(
        self, edge_node_ids: List[str], heartbeat_timeout_sec: float = 5.0
    ) -> None:
        self.heartbeat_timeout_sec = heartbeat_timeout_sec
        self.nodes: Dict[str, EdgeNodeTelemetry] = {
            nid: EdgeNodeTelemetry(
                edge_node_id=nid,
                cpu_utilization_percent=14.0 + idx * 3.5,
                memory_utilization_percent=22.0 + idx * 4.0,
                network_rtt_ms=5.2 + idx * 1.8,
                available_bandwidth_mbps=92.0 - idx * 4.0,
            )
            for idx, nid in enumerate(edge_node_ids)
        }

    def record_task_start(
        self, edge_node_id: str, estimated_cpu_delta: float = 1.2
    ) -> None:
        tel = self.nodes[edge_node_id]
        tel.active_tasks += 1
        tel.cpu_utilization_percent = min(
            99.0, tel.cpu_utilization_percent + estimated_cpu_delta
        )
        tel.memory_utilization_percent = min(95.0, tel.memory_utilization_percent + 0.4)
        tel.last_heartbeat = time.time()

    def record_task_completion(
        self, edge_node_id: str, success: bool = True, cpu_delta: float = 1.2
    ) -> None:
        tel = self.nodes[edge_node_id]
        tel.active_tasks = max(0, tel.active_tasks - 1)
        if success:
            tel.completed_tasks += 1
        else:
            tel.failed_tasks += 1
        tel.cpu_utilization_percent = max(
            8.0, tel.cpu_utilization_percent - cpu_delta * 0.92
        )
        tel.memory_utilization_percent = max(
            15.0, tel.memory_utilization_percent - 0.35
        )
        tel.last_heartbeat = time.time()

    def set_node_availability(self, edge_node_id: str, online: bool) -> None:
        if edge_node_id in self.nodes:
            self.nodes[edge_node_id].online = online
            if online:
                self.nodes[edge_node_id].last_heartbeat = time.time()

    def is_node_healthy(self, edge_node_id: str, max_cpu_percent: float = 88.0) -> bool:
        tel = self.nodes.get(edge_node_id)
        if tel is None or not tel.online:
            return False
        if (time.time() - tel.last_heartbeat) > self.heartbeat_timeout_sec * 60:
            return False
        return tel.cpu_utilization_percent < max_cpu_percent
