from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class EdgeConfig:
    edge_node_ids: List[str] = field(
        default_factory=lambda: os.getenv(
            "AEALSF_EDGE_CLUSTER_NODES", "edge-node-0,edge-node-1,edge-node-2"
        ).split(",")
    )
    heartbeat_timeout_seconds: float = field(
        default_factory=lambda: float(
            os.getenv("AEALSF_EDGE_HEARTBEAT_TIMEOUT_SEC", "5.0")
        )
    )
    max_edge_cpu_load_percent: float = 88.0
    max_edge_queue_depth: int = 500

    alpha_cpu_or_comm: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_WEIGHT_ALPHA_CPU", "0.35"))
    )
    beta_mem_or_edge_proc: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_WEIGHT_BETA_MEMORY", "0.25"))
    )
    gamma_energy: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_WEIGHT_GAMMA_ENERGY", "0.20"))
    )
    delta_latency: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_WEIGHT_DELTA_LATENCY", "0.20"))
    )

    critical_cpu_percent: float = 78.0
    moderate_cpu_percent: float = 48.0
    critical_free_ram_kb: float = 380.0
    moderate_free_ram_kb: float = 850.0
    critical_battery_percent: float = 22.0
    moderate_battery_percent: float = 50.0
    max_acceptable_latency_ms: float = 150.0

    mode_switch_hysteresis: float = 0.04
