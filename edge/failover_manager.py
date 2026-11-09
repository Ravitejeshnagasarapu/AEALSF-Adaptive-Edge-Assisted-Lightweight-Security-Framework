from __future__ import annotations
from typing import List, Optional, Tuple

from config.edge_config import EdgeConfig
from edge.edge_monitor import EdgeMonitor, EdgeNodeTelemetry


class EdgeFailoverManager:

    def __init__(
        self, monitor: EdgeMonitor, config: Optional[EdgeConfig] = None
    ) -> None:
        self.monitor = monitor
        self.config = config or EdgeConfig()
        self.failover_events: List[dict] = []

    def select_best_edge_node(
        self, exclude_nodes: Optional[set[str]] = None
    ) -> Optional[EdgeNodeTelemetry]:
        excluded = exclude_nodes or set()
        candidates: List[Tuple[float, EdgeNodeTelemetry]] = []
        for nid, tel in self.monitor.nodes.items():
            if nid in excluded:
                continue
            if not self.monitor.is_node_healthy(
                nid, self.config.max_edge_cpu_load_percent
            ):
                continue
            score = (
                0.5 * tel.cpu_utilization_percent
                + 0.25 * tel.memory_utilization_percent
                + 0.25 * tel.network_rtt_ms
            )
            candidates.append((score, tel))

        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]

    def record_failover(
        self, failed_node_id: str, fallback_target: str, reason: str, task_id: str
    ) -> None:
        self.failover_events.append(
            {
                "task_id": task_id,
                "failed_node_id": failed_node_id,
                "fallback_target": fallback_target,
                "reason": reason,
            }
        )
