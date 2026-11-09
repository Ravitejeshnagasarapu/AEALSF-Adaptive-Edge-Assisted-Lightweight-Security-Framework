from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Dict

from config.edge_config import EdgeConfig


@dataclass(frozen=True)
class DeviceResourceSnapshot:
    device_id: str
    cpu_utilization_percent: float
    available_ram_kb: float
    total_ram_kb: float
    battery_percent: float
    network_latency_ms: float
    available_bandwidth_mbps: float
    has_active_auth_session: bool = False

    def validate(self) -> None:
        if not self.device_id or not self.device_id.strip():
            raise ValueError("Invalid DeviceResourceSnapshot: empty device_id.")
        if not (0.0 <= self.cpu_utilization_percent <= 100.0):
            raise ValueError(
                f"Invalid cpu_utilization_percent: {self.cpu_utilization_percent}"
            )
        if self.total_ram_kb <= 0.0 or not (
            0.0 <= self.available_ram_kb <= self.total_ram_kb
        ):
            raise ValueError(
                f"Invalid RAM telemetry: {self.available_ram_kb}/{self.total_ram_kb} KB"
            )
        if not (0.0 <= self.battery_percent <= 100.0):
            raise ValueError(f"Invalid battery_percent: {self.battery_percent}")
        if self.network_latency_ms < 0.0 or self.available_bandwidth_mbps <= 0.0:
            raise ValueError("Invalid network latency or bandwidth telemetry.")

    def to_dict(self) -> Dict[str, object]:
        return {
            "device_id": self.device_id,
            "cpu_utilization_percent": round(self.cpu_utilization_percent, 2),
            "available_ram_kb": round(self.available_ram_kb, 2),
            "total_ram_kb": round(self.total_ram_kb, 2),
            "battery_percent": round(self.battery_percent, 2),
            "network_latency_ms": round(self.network_latency_ms, 2),
            "available_bandwidth_mbps": round(self.available_bandwidth_mbps, 2),
            "has_active_auth_session": self.has_active_auth_session,
        }


@dataclass(frozen=True)
class TaskRequirementProfile:
    task_id: str
    task_type: str
    payload_bytes: int
    num_homomorphic_ops: int = 4
    priority: str = "NORMAL"
    requires_private_key_access: bool = False
    latency_deadline_ms: float = 150.0
    data_sensitivity: str = "CONFIDENTIAL_HE_ONLY"
    verification_strategy: str = "ALGEBRAIC_OR_DECOMPRESS_CHECK"

    def to_dict(self) -> Dict[str, object]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_id and self.task_type,
            "payload_bytes": self.payload_bytes,
            "num_homomorphic_ops": self.num_homomorphic_ops,
            "priority": self.priority,
            "requires_private_key_access": self.requires_private_key_access,
            "latency_deadline_ms": self.latency_deadline_ms,
            "data_sensitivity": self.data_sensitivity,
            "verification_strategy": self.verification_strategy,
        }


@dataclass(frozen=True)
class ResourcePressureAnalysis:
    cpu_pressure: float
    memory_pressure: float
    battery_pressure: float
    network_congestion_index: float
    composite_device_stress: float
    is_severely_constrained: bool
    is_moderately_constrained: bool


class ResourceAnalyzer:

    def __init__(self, config: EdgeConfig | None = None) -> None:
        self.config = config or EdgeConfig()

    def analyze(self, snapshot: DeviceResourceSnapshot) -> ResourcePressureAnalysis:
        snapshot.validate()

        u_cpu = snapshot.cpu_utilization_percent / 100.0
        cpu_pressure = min(1.0, (u_cpu**1.35) * 1.15)

        used_ram_ratio = 1.0 - (snapshot.available_ram_kb / snapshot.total_ram_kb)
        if snapshot.available_ram_kb < self.config.critical_free_ram_kb:
            mem_pressure = min(
                1.0,
                0.85
                + 0.15
                * (1.0 - snapshot.available_ram_kb / self.config.critical_free_ram_kb),
            )
        else:
            mem_pressure = min(1.0, used_ram_ratio**1.25)

        batt_frac = max(0.01, snapshot.battery_percent) / 100.0
        battery_pressure = min(1.0, math.exp(-3.2 * batt_frac) / math.exp(-0.032))

        lat_norm = min(
            1.0,
            snapshot.network_latency_ms
            / max(10.0, self.config.max_acceptable_latency_ms),
        )
        bw_penalty = max(0.0, 1.0 - min(1.0, snapshot.available_bandwidth_mbps / 50.0))
        net_congestion = 0.65 * lat_norm + 0.35 * bw_penalty

        composite_stress = (
            0.38 * cpu_pressure + 0.34 * mem_pressure + 0.28 * battery_pressure
        )

        severely_constrained = (
            snapshot.cpu_utilization_percent >= self.config.critical_cpu_percent
            or snapshot.available_ram_kb <= self.config.critical_free_ram_kb
            or snapshot.battery_percent <= self.config.critical_battery_percent
            or composite_stress >= 0.72
        )
        moderately_constrained = not severely_constrained and (
            snapshot.cpu_utilization_percent >= self.config.moderate_cpu_percent
            or snapshot.available_ram_kb <= self.config.moderate_free_ram_kb
            or snapshot.battery_percent <= self.config.moderate_battery_percent
            or composite_stress >= 0.42
        )

        return ResourcePressureAnalysis(
            cpu_pressure=round(cpu_pressure, 4),
            memory_pressure=round(mem_pressure, 4),
            battery_pressure=round(battery_pressure, 4),
            network_congestion_index=round(net_congestion, 4),
            composite_device_stress=round(composite_stress, 4),
            is_severely_constrained=severely_constrained,
            is_moderately_constrained=moderately_constrained,
        )
