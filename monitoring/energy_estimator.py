from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

from config.settings import HardwareProfile, L610_CN_PROFILE


@dataclass(frozen=True)
class EnergyEstimateBreakdown:
    cpu_energy_mj: float
    tx_energy_mj: float
    rx_energy_mj: float
    idle_wait_energy_mj: float
    total_energy_mj: float
    e_tx_per_byte_mj: float
    e_rx_per_byte_mj: float
    measurement_classification: str = "MODEL_ESTIMATED"
    estimation_method: str = (
        "Documented Analytical Cat.1 Energy Model: E = P_cpu*t_cpu + E_tx_byte*B_tx + E_rx_byte*B_rx + P_idle*t_wait"
    )

    def to_dict(self) -> Dict[str, float | str]:
        return {
            "cpu_energy_mj": round(self.cpu_energy_mj, 4),
            "tx_energy_mj": round(self.tx_energy_mj, 4),
            "rx_energy_mj": round(self.rx_energy_mj, 4),
            "idle_wait_energy_mj": round(self.idle_wait_energy_mj, 4),
            "total_energy_mj": round(self.total_energy_mj, 4),
            "e_tx_per_byte_mj": round(self.e_tx_per_byte_mj, 6),
            "e_rx_per_byte_mj": round(self.e_rx_per_byte_mj, 6),
            "measurement_classification": self.measurement_classification,
            "estimation_method": self.estimation_method,
        }


class EnergyEstimator:

    def __init__(self, profile: HardwareProfile = L610_CN_PROFILE) -> None:
        self.profile = profile

    def estimate_task_energy(
        self,
        device_cpu_time_ms: float,
        bytes_transmitted: int,
        bytes_received: int,
        uplink_mbps: float | None = None,
        downlink_mbps: float | None = None,
        network_wait_ms: float = 0.0,
        p_cpu_mw_override: float | None = None,
        p_tx_mw_override: float | None = None,
    ) -> EnergyEstimateBreakdown:
        ul_mbps = max(0.5, uplink_mbps or self.profile.uplink_mbps)
        dl_mbps = max(0.5, downlink_mbps or self.profile.downlink_mbps)

        ul_bytes_per_sec = (ul_mbps * 1_000_000.0) / 8.0
        dl_bytes_per_sec = (dl_mbps * 1_000_000.0) / 8.0

        p_cpu = (
            p_cpu_mw_override
            if p_cpu_mw_override is not None
            else self.profile.active_cpu_power_mw
        )
        p_tx = (
            p_tx_mw_override
            if p_tx_mw_override is not None
            else self.profile.tx_power_mw
        )
        p_rx = self.profile.rx_power_mw
        p_idle = self.profile.idle_power_mw

        e_tx_per_byte_mj = p_tx / ul_bytes_per_sec
        e_rx_per_byte_mj = p_rx / dl_bytes_per_sec

        t_cpu_sec = max(0.0, device_cpu_time_ms) / 1000.0
        t_wait_sec = max(0.0, network_wait_ms) / 1000.0

        cpu_mj = p_cpu * t_cpu_sec
        tx_mj = e_tx_per_byte_mj * max(0, bytes_transmitted)
        rx_mj = e_rx_per_byte_mj * max(0, bytes_received)
        idle_mj = p_idle * t_wait_sec

        return EnergyEstimateBreakdown(
            cpu_energy_mj=cpu_mj,
            tx_energy_mj=tx_mj,
            rx_energy_mj=rx_mj,
            idle_wait_energy_mj=idle_mj,
            total_energy_mj=cpu_mj + tx_mj + rx_mj + idle_mj,
            e_tx_per_byte_mj=e_tx_per_byte_mj,
            e_rx_per_byte_mj=e_rx_per_byte_mj,
        )

    def run_sensitivity_analysis(
        self,
        local_cpu_ms: float,
        local_bytes_tx: int,
        edge_dev_cpu_ms: float,
        edge_bytes_tx: int,
        edge_wait_ms: float,
    ) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        for cpu_scale in (0.70, 1.00, 1.30):
            for tx_scale in (0.50, 1.00, 1.50):
                p_cpu = self.profile.active_cpu_power_mw * cpu_scale
                p_tx = self.profile.tx_power_mw * tx_scale
                e_loc = self.estimate_task_energy(
                    device_cpu_time_ms=local_cpu_ms,
                    bytes_transmitted=local_bytes_tx,
                    bytes_received=256,
                    network_wait_ms=2.0,
                    p_cpu_mw_override=p_cpu,
                    p_tx_mw_override=p_tx,
                )
                e_edg = self.estimate_task_energy(
                    device_cpu_time_ms=edge_dev_cpu_ms,
                    bytes_transmitted=edge_bytes_tx,
                    bytes_received=512,
                    network_wait_ms=edge_wait_ms,
                    p_cpu_mw_override=p_cpu,
                    p_tx_mw_override=p_tx,
                )
                diff_pct = (
                    (
                        (e_loc.total_energy_mj - e_edg.total_energy_mj)
                        / e_loc.total_energy_mj
                    )
                    * 100.0
                    if e_loc.total_energy_mj > 0
                    else 0.0
                )
                rows.append(
                    {
                        "cpu_power_scale": cpu_scale,
                        "tx_power_scale": tx_scale,
                        "p_cpu_mw": round(p_cpu, 1),
                        "p_tx_mw": round(p_tx, 1),
                        "estimated_local_energy_mj": round(e_loc.total_energy_mj, 4),
                        "estimated_edge_energy_mj": round(e_edg.total_energy_mj, 4),
                        "relative_reduction_pct": round(diff_pct, 2),
                        "classification": "MODEL_ESTIMATED",
                    }
                )
        return rows
