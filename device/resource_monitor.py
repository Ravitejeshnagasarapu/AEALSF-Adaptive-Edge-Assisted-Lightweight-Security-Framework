from __future__ import annotations
from adaptive_engine.resource_analyzer import DeviceResourceSnapshot
from config.settings import HardwareProfile, L610_CN_PROFILE


class DeviceResourceMonitor:

    def __init__(
        self,
        device_id: str,
        profile: HardwareProfile = L610_CN_PROFILE,
        initial_cpu_percent: float = 32.0,
        initial_free_ram_kb: float = 1180.0,
        initial_battery_percent: float = 82.0,
        initial_latency_ms: float = 38.64,
        initial_bandwidth_mbps: float = 94.12,
    ) -> None:
        self.device_id = device_id
        self.profile = profile
        self.cpu_utilization_percent = initial_cpu_percent
        self.available_ram_kb = min(float(profile.ram_total_kb), initial_free_ram_kb)
        self.battery_percent = initial_battery_percent
        self.network_latency_ms = initial_latency_ms
        self.available_bandwidth_mbps = initial_bandwidth_mbps
        self.has_active_auth_session = False

    def capture_snapshot(self) -> DeviceResourceSnapshot:
        return DeviceResourceSnapshot(
            device_id=self.device_id,
            cpu_utilization_percent=self.cpu_utilization_percent,
            available_ram_kb=self.available_ram_kb,
            total_ram_kb=float(self.profile.ram_total_kb),
            battery_percent=self.battery_percent,
            network_latency_ms=self.network_latency_ms,
            available_bandwidth_mbps=self.available_bandwidth_mbps,
            has_active_auth_session=self.has_active_auth_session,
        )

    def apply_workload_delta(
        self, cpu_delta_percent: float, ram_delta_kb: float, energy_used_mj: float
    ) -> None:
        self.cpu_utilization_percent = max(
            5.0, min(99.5, self.cpu_utilization_percent + cpu_delta_percent)
        )
        self.available_ram_kb = max(
            120.0,
            min(float(self.profile.ram_total_kb), self.available_ram_kb - ram_delta_kb),
        )
        self.battery_percent = max(
            1.0, self.battery_percent - (energy_used_mj / 1800.0)
        )
