from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class HardwareProfile:
    model_name: str
    ram_total_kb: int
    flash_total_mb: int
    sd_card_mb: int
    downlink_mbps: float
    uplink_mbps: float
    cpu_clock_mhz: int
    idle_power_mw: float
    active_cpu_power_mw: float
    tx_power_mw: float
    rx_power_mw: float


L610_CN_PROFILE = HardwareProfile(
    model_name="Fibocom L610-CN Cat.1",
    ram_total_kb=2048,
    flash_total_mb=16,
    sd_card_mb=2048,
    downlink_mbps=10.3,
    uplink_mbps=5.1,
    cpu_clock_mhz=500,
    idle_power_mw=18.0,
    active_cpu_power_mw=420.0,
    tx_power_mw=680.0,
    rx_power_mw=310.0,
)

ML307A_PROFILE = HardwareProfile(
    model_name="China Mobile ML307A Cat.1",
    ram_total_kb=1536,
    flash_total_mb=8,
    sd_card_mb=0,
    downlink_mbps=10.0,
    uplink_mbps=5.0,
    cpu_clock_mhz=400,
    idle_power_mw=15.0,
    active_cpu_power_mw=360.0,
    tx_power_mw=640.0,
    rx_power_mw=290.0,
)


@dataclass
class Settings:
    env: str = field(default_factory=lambda: os.getenv("AEALSF_ENV", "development"))
    log_level: str = field(
        default_factory=lambda: os.getenv("AEALSF_LOG_LEVEL", "INFO")
    )
    api_host: str = field(
        default_factory=lambda: os.getenv("AEALSF_API_HOST", "0.0.0.0")
    )
    api_port: int = field(
        default_factory=lambda: int(os.getenv("AEALSF_API_PORT", "8000"))
    )

    default_packet_size_bytes: int = 512
    data_generation_rate_kbps: float = 500.0
    backbone_bandwidth_mbps: float = 100.0
    contracts_per_client: int = 3
    num_blockchain_nodes: int = 4

    hardware_profiles: Dict[str, HardwareProfile] = field(
        default_factory=lambda: {
            "L610-CN": L610_CN_PROFILE,
            "ML307A": ML307A_PROFILE,
        }
    )


_SETTINGS_INSTANCE: Settings | None = None


def get_settings() -> Settings:
    global _SETTINGS_INSTANCE
    if _SETTINGS_INSTANCE is None:
        _SETTINGS_INSTANCE = Settings()
    return _SETTINGS_INSTANCE
