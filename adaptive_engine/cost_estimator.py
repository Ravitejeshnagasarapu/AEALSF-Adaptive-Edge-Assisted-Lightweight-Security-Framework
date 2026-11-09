from __future__ import annotations
import time
import zlib
from dataclasses import dataclass
from typing import Dict, Optional

from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    ResourcePressureAnalysis,
    TaskRequirementProfile,
)
from config.edge_config import EdgeConfig
from cryptography.homomorphic_encryption import (
    BASE_POINT_G,
    SECP256K1_N,
    ec_add,
    ec_scalar_mul,
    ec_scalar_mul_python,
)
from edge.edge_monitor import EdgeNodeTelemetry


@dataclass(frozen=True)
class ModeCostBreakdown:
    mode: str
    cpu_or_comm_term: float
    memory_or_edge_proc_term: float
    energy_term: float
    latency_term: float
    verification_overhead_term: float
    edge_queue_penalty_term: float
    constraint_penalty: float
    total_cost: float
    estimated_device_cpu_ms: float
    estimated_device_ram_kb: float
    local_execution_energy_mj: float
    communication_energy_mj: float
    estimated_device_energy_mj: float
    estimated_edge_processing_ms: float
    estimated_verification_time_ms: float
    estimated_bytes_transmitted: int
    estimated_total_latency_ms: float
    net_delegation_benefit_ms: float

    def to_dict(self) -> Dict[str, float | int | str]:
        return {
            "mode": self.mode,
            "cpu_or_comm_term": round(self.cpu_or_comm_term, 4),
            "memory_or_edge_proc_term": round(self.memory_or_edge_proc_term, 4),
            "energy_term": round(self.energy_term, 4),
            "latency_term": round(self.latency_term, 4),
            "verification_overhead_term": round(self.verification_overhead_term, 4),
            "edge_queue_penalty_term": round(self.edge_queue_penalty_term, 4),
            "constraint_penalty": round(self.constraint_penalty, 4),
            "total_cost": round(self.total_cost, 4),
            "estimated_device_cpu_ms": round(self.estimated_device_cpu_ms, 3),
            "estimated_device_ram_kb": round(self.estimated_device_ram_kb, 2),
            "local_execution_energy_mj": round(self.local_execution_energy_mj, 4),
            "communication_energy_mj": round(self.communication_energy_mj, 4),
            "estimated_device_energy_mj": round(self.estimated_device_energy_mj, 4),
            "estimated_edge_processing_ms": round(self.estimated_edge_processing_ms, 3),
            "estimated_verification_time_ms": round(
                self.estimated_verification_time_ms, 3
            ),
            "estimated_bytes_transmitted": self.estimated_bytes_transmitted,
            "estimated_total_latency_ms": round(self.estimated_total_latency_ms, 3),
            "net_delegation_benefit_ms": round(self.net_delegation_benefit_ms, 3),
        }


class CostEstimator:

    PRIORITY_LATENCY_MULTIPLIER = {
        "LOW": 0.85,
        "NORMAL": 1.0,
        "HIGH": 1.35,
        "CRITICAL": 1.75,
    }

    _CALIBRATED_TIMINGS: Optional[Dict[str, float]] = None

    def __init__(self, config: Optional[EdgeConfig] = None) -> None:
        self.config = config or EdgeConfig()
        if CostEstimator._CALIBRATED_TIMINGS is None:
            CostEstimator._CALIBRATED_TIMINGS = self.calibrate_from_microbenchmarks()
        self.calibrated = CostEstimator._CALIBRATED_TIMINGS

    @staticmethod
    def calibrate_from_microbenchmarks(iterations: int = 8) -> Dict[str, float]:
        p1 = ec_scalar_mul(1234567, BASE_POINT_G)
        p2 = ec_scalar_mul(7654321, BASE_POINT_G)

        t0 = time.perf_counter_ns()
        for i in range(iterations):
            ec_scalar_mul_python((SECP256K1_N // 3) + i, p1)
        raw_py_smul_ms = ((time.perf_counter_ns() - t0) / 1e6) / iterations
        smul_ms = max(0.50, min(0.68, raw_py_smul_ms * 0.38))

        t0 = time.perf_counter_ns()
        for _ in range(iterations * 4):
            ec_add(p1, p2)
        add_ms = max(0.005, ((time.perf_counter_ns() - t0) / 1e6) / (iterations * 4))

        sample_kb = b"IOT_SENSOR_TELEMETRY_CALIBRATION_BLOCK_" * 27
        t0 = time.perf_counter_ns()
        comp = b""
        for _ in range(iterations * 4):
            comp = zlib.compress(sample_kb, level=6)
        comp_kb_ms = max(0.01, ((time.perf_counter_ns() - t0) / 1e6) / (iterations * 4))

        t0 = time.perf_counter_ns()
        for _ in range(iterations * 4):
            zlib.decompress(comp)
        decomp_kb_ms = max(
            0.002, ((time.perf_counter_ns() - t0) / 1e6) / (iterations * 4)
        )

        return {
            "ec_scalar_mul_ms": round(smul_ms, 4),
            "ec_point_add_ms": round(add_ms, 4),
            "zlib_compress_kb_ms": round(comp_kb_ms, 4),
            "zlib_decompress_kb_ms": round(decomp_kb_ms, 4),
        }

    def estimate_all_modes(
        self,
        snapshot: DeviceResourceSnapshot,
        pressure: ResourcePressureAnalysis,
        task: TaskRequirementProfile,
        edge_telemetry: Optional[EdgeNodeTelemetry],
    ) -> Dict[str, ModeCostBreakdown]:
        alpha = self.config.alpha_cpu_or_comm
        beta = self.config.beta_mem_or_edge_proc
        gamma = self.config.gamma_energy
        delta = self.config.delta_latency
        prio_mult = self.PRIORITY_LATENCY_MULTIPLIER.get(task.priority, 1.0)

        smul_ms = self.calibrated["ec_scalar_mul_ms"]
        add_ms = self.calibrated["ec_point_add_ms"]
        comp_kb_ms = self.calibrated["zlib_compress_kb_ms"]
        decomp_kb_ms = self.calibrated["zlib_decompress_kb_ms"]

        payload_kb = max(0.5, task.payload_bytes / 1024.0)
        he_ops = max(1, task.num_homomorphic_ops)

        dev_load_slowdown = 5.4 * (1.0 + 0.85 * pressure.cpu_pressure)
        local_he_compute_ms = (
            he_ops * (2.2 * smul_ms + add_ms) + payload_kb * comp_kb_ms
        ) * dev_load_slowdown
        local_base_crypto_ms = (4.0 * smul_ms) * dev_load_slowdown
        local_cpu_ms = local_base_crypto_ms + local_he_compute_ms
        local_ram_kb = 240.0 + 42.0 * he_ops + 2.2 * payload_kb
        local_bytes_tx = 320
        local_exec_energy_mj = 0.420 * local_cpu_ms
        local_comm_energy_mj = 0.680 * (
            (local_bytes_tx * 8.0) / (snapshot.available_bandwidth_mbps * 1000.0)
        )
        local_energy_mj = local_exec_energy_mj + local_comm_energy_mj
        local_latency_ms = local_cpu_ms + 0.15 * snapshot.network_latency_ms

        cpu_cost_local = min(
            2.0, (local_cpu_ms / 40.0) * (1.0 + 1.35 * pressure.cpu_pressure)
        )
        mem_cost_local = min(
            2.0, (local_ram_kb / 850.0) * (1.0 + 1.55 * pressure.memory_pressure)
        )
        energy_cost_local = min(
            2.0, (local_energy_mj / 22.0) * (1.0 + 1.65 * pressure.battery_pressure)
        )
        lat_cost_local = min(
            2.0, (local_latency_ms / max(10.0, task.latency_deadline_ms)) * prio_mult
        )

        local_penalty = 0.0
        if snapshot.available_ram_kb < local_ram_kb * 1.25:
            local_penalty += 0.55
        if snapshot.cpu_utilization_percent >= self.config.critical_cpu_percent:
            local_penalty += 0.42
        if snapshot.battery_percent <= self.config.critical_battery_percent:
            local_penalty += 0.38
        if local_latency_ms > task.latency_deadline_ms:
            local_penalty += 0.45

        c_local = (
            alpha * cpu_cost_local
            + beta * mem_cost_local
            + gamma * energy_cost_local
            + delta * lat_cost_local
            + local_penalty
        )

        local_breakdown = ModeCostBreakdown(
            mode="LOCAL_SECURITY_MODE",
            cpu_or_comm_term=cpu_cost_local,
            memory_or_edge_proc_term=mem_cost_local,
            energy_term=energy_cost_local,
            latency_term=lat_cost_local,
            verification_overhead_term=0.0,
            edge_queue_penalty_term=0.0,
            constraint_penalty=local_penalty,
            total_cost=c_local,
            estimated_device_cpu_ms=local_cpu_ms,
            estimated_device_ram_kb=local_ram_kb,
            local_execution_energy_mj=local_exec_energy_mj,
            communication_energy_mj=local_comm_energy_mj,
            estimated_device_energy_mj=local_energy_mj,
            estimated_edge_processing_ms=0.0,
            estimated_verification_time_ms=0.0,
            estimated_bytes_transmitted=local_bytes_tx,
            estimated_total_latency_ms=local_latency_ms,
            net_delegation_benefit_ms=0.0,
        )

        if edge_telemetry is None or not edge_telemetry.online:
            unavail = ModeCostBreakdown(
                mode="HYBRID_SECURITY_MODE",
                cpu_or_comm_term=9.9,
                memory_or_edge_proc_term=9.9,
                energy_term=9.9,
                latency_term=9.9,
                verification_overhead_term=9.9,
                edge_queue_penalty_term=9.9,
                constraint_penalty=100.0,
                total_cost=999.0,
                estimated_device_cpu_ms=local_cpu_ms,
                estimated_device_ram_kb=local_ram_kb,
                local_execution_energy_mj=local_exec_energy_mj,
                communication_energy_mj=0.0,
                estimated_device_energy_mj=local_energy_mj,
                estimated_edge_processing_ms=999.0,
                estimated_verification_time_ms=0.0,
                estimated_bytes_transmitted=0,
                estimated_total_latency_ms=999.0,
                net_delegation_benefit_ms=-999.0,
            )
            return {
                "LOCAL_SECURITY_MODE": local_breakdown,
                "HYBRID_SECURITY_MODE": unavail,
                "EDGE_ASSISTED_SECURITY_MODE": ModeCostBreakdown(
                    **{**unavail.__dict__, "mode": "EDGE_ASSISTED_SECURITY_MODE"}
                ),
            }

        effective_bw_mbps = max(
            0.5,
            min(
                snapshot.available_bandwidth_mbps,
                edge_telemetry.available_bandwidth_mbps,
            ),
        )
        edge_cpu_factor = 1.0 + (edge_telemetry.cpu_utilization_percent / 100.0)
        edge_mem_factor = 1.0 + (edge_telemetry.memory_utilization_percent / 100.0)
        edge_queue_penalty = min(0.5, edge_telemetry.active_tasks * 0.03)
        rtt_ms = snapshot.network_latency_ms + edge_telemetry.network_rtt_ms

        if task.verification_strategy == "INDEPENDENT_RECOMPUTATION":
            ver_time_ms = local_he_compute_ms * 0.90
            ver_comm_bytes = 256
        elif task.verification_strategy == "REDUNDANT_DUAL_EDGE":
            ver_time_ms = 0.65 + 2.0 * he_ops * add_ms
            ver_comm_bytes = 640 + 256 * he_ops
        else:
            ver_time_ms = 0.35 + 2.0 * he_ops * add_ms + payload_kb * decomp_kb_ms
            ver_comm_bytes = 256

        ver_overhead_term = (ver_time_ms / 25.0) + (ver_comm_bytes / 8192.0)

        hybrid_bytes_tx = 384 + 260 * he_ops + ver_comm_bytes
        hybrid_tx_ms = (
            (hybrid_bytes_tx * 8.0) / (effective_bw_mbps * 1000.0)
        ) + 0.45 * rtt_ms
        hybrid_dev_cpu_ms = (
            3.2 * smul_ms + payload_kb * comp_kb_ms
        ) * dev_load_slowdown + ver_time_ms
        hybrid_dev_ram_kb = 135.0 + 16.0 * he_ops + 1.1 * payload_kb
        edge_proc_hybrid_ms = (
            (1.4 + 0.55 * he_ops)
            * edge_cpu_factor
            * (1.0 + 0.08 * edge_telemetry.active_tasks)
        )
        hybrid_local_energy_mj = 0.420 * hybrid_dev_cpu_ms
        hybrid_comm_energy_mj = 0.680 * (hybrid_tx_ms * 0.6) + 0.310 * (
            hybrid_tx_ms * 0.4
        )
        hybrid_energy_mj = hybrid_local_energy_mj + hybrid_comm_energy_mj
        hybrid_latency_ms = hybrid_dev_cpu_ms + edge_proc_hybrid_ms + hybrid_tx_ms
        hybrid_net_benefit_ms = (local_cpu_ms - hybrid_dev_cpu_ms) - (
            hybrid_tx_ms * 0.35 + ver_time_ms
        )

        comm_cost_hybrid = min(
            2.0,
            0.45 * (hybrid_dev_cpu_ms / 40.0) * (1.0 + 0.75 * pressure.cpu_pressure)
            + 0.55 * (hybrid_tx_ms / 65.0) * (1.0 + pressure.network_congestion_index),
        )
        proc_cost_hybrid = min(
            2.0,
            0.45 * (hybrid_dev_ram_kb / 850.0) * (1.0 + 0.75 * pressure.memory_pressure)
            + 0.55
            * (
                (
                    edge_telemetry.cpu_utilization_percent
                    + edge_telemetry.memory_utilization_percent
                )
                / 200.0
            ),
        )
        energy_cost_hybrid = min(
            2.0, (hybrid_energy_mj / 22.0) * (1.0 + 1.05 * pressure.battery_pressure)
        )
        lat_cost_hybrid = min(
            2.0, (hybrid_latency_ms / max(10.0, task.latency_deadline_ms)) * prio_mult
        )

        hybrid_penalty = 0.0
        if pressure.is_severely_constrained:
            hybrid_penalty += 0.22
        if (
            not pressure.is_moderately_constrained
            and not pressure.is_severely_constrained
        ):
            hybrid_penalty += 0.32
        if hybrid_latency_ms > task.latency_deadline_ms:
            hybrid_penalty += 0.45
        if hybrid_net_benefit_ms < -5.0:
            hybrid_penalty += 0.35

        c_hybrid = (
            alpha * comm_cost_hybrid
            + beta * proc_cost_hybrid
            + gamma * energy_cost_hybrid
            + delta * lat_cost_hybrid
            + 0.15 * ver_overhead_term
            + edge_queue_penalty
            + hybrid_penalty
        )

        hybrid_breakdown = ModeCostBreakdown(
            mode="HYBRID_SECURITY_MODE",
            cpu_or_comm_term=comm_cost_hybrid,
            memory_or_edge_proc_term=proc_cost_hybrid,
            energy_term=energy_cost_hybrid,
            latency_term=lat_cost_hybrid,
            verification_overhead_term=ver_overhead_term,
            edge_queue_penalty_term=edge_queue_penalty,
            constraint_penalty=hybrid_penalty,
            total_cost=c_hybrid,
            estimated_device_cpu_ms=hybrid_dev_cpu_ms,
            estimated_device_ram_kb=hybrid_dev_ram_kb,
            local_execution_energy_mj=hybrid_local_energy_mj,
            communication_energy_mj=hybrid_comm_energy_mj,
            estimated_device_energy_mj=hybrid_energy_mj,
            estimated_edge_processing_ms=edge_proc_hybrid_ms,
            estimated_verification_time_ms=ver_time_ms,
            estimated_bytes_transmitted=hybrid_bytes_tx,
            estimated_total_latency_ms=hybrid_latency_ms,
            net_delegation_benefit_ms=hybrid_net_benefit_ms,
        )

        edge_bytes_tx = task.payload_bytes + 260 * he_ops + ver_comm_bytes
        edge_tx_ms = (
            (edge_bytes_tx * 8.0) / (effective_bw_mbps * 1000.0)
        ) + 0.62 * rtt_ms
        edge_dev_cpu_ms = (1.8 * smul_ms) * dev_load_slowdown + ver_time_ms
        edge_dev_ram_kb = 76.0 + 7.5 * he_ops + 0.35 * payload_kb
        edge_proc_full_ms = (
            (2.1 + 0.72 * he_ops + 0.09 * payload_kb)
            * edge_cpu_factor
            * (0.8 + 0.2 * edge_mem_factor)
            * (1.0 + 0.10 * edge_telemetry.active_tasks)
        )
        edge_local_energy_mj = 0.420 * edge_dev_cpu_ms
        edge_comm_energy_mj = 0.680 * (edge_tx_ms * 0.65) + 0.310 * (edge_tx_ms * 0.35)
        edge_energy_mj = edge_local_energy_mj + edge_comm_energy_mj
        edge_latency_ms = edge_dev_cpu_ms + edge_proc_full_ms + edge_tx_ms
        edge_net_benefit_ms = (local_cpu_ms - edge_dev_cpu_ms) - (
            edge_tx_ms * 0.45 + ver_time_ms
        )

        comm_cost_edge = min(
            2.0, (edge_tx_ms / 70.0) * (1.0 + 1.25 * pressure.network_congestion_index)
        )
        edge_proc_cost = min(
            2.0,
            0.25 * (edge_dev_ram_kb / 850.0)
            + 0.75
            * (
                (
                    edge_telemetry.cpu_utilization_percent * 0.65
                    + edge_telemetry.memory_utilization_percent * 0.35
                )
                / 100.0
            ),
        )
        energy_cost_edge = min(
            2.0, (edge_energy_mj / 22.0) * (1.0 + 0.65 * pressure.battery_pressure)
        )
        lat_cost_edge = min(
            2.0, (edge_latency_ms / max(10.0, task.latency_deadline_ms)) * prio_mult
        )

        edge_penalty = 0.0
        if not pressure.is_severely_constrained:
            edge_penalty += 0.44 if not pressure.is_moderately_constrained else 0.14
        if snapshot.network_latency_ms > self.config.max_acceptable_latency_ms:
            edge_penalty += 0.65
        if edge_latency_ms > task.latency_deadline_ms:
            edge_penalty += 0.48
        if edge_net_benefit_ms < -6.0:
            edge_penalty += 0.42

        c_edge = (
            alpha * comm_cost_edge
            + beta * edge_proc_cost
            + gamma * energy_cost_edge
            + delta * lat_cost_edge
            + 0.18 * ver_overhead_term
            + edge_queue_penalty
            + edge_penalty
        )

        edge_breakdown = ModeCostBreakdown(
            mode="EDGE_ASSISTED_SECURITY_MODE",
            cpu_or_comm_term=comm_cost_edge,
            memory_or_edge_proc_term=edge_proc_cost,
            energy_term=energy_cost_edge,
            latency_term=lat_cost_edge,
            verification_overhead_term=ver_overhead_term,
            edge_queue_penalty_term=edge_queue_penalty,
            constraint_penalty=edge_penalty,
            total_cost=c_edge,
            estimated_device_cpu_ms=edge_dev_cpu_ms,
            estimated_device_ram_kb=edge_dev_ram_kb,
            local_execution_energy_mj=edge_local_energy_mj,
            communication_energy_mj=edge_comm_energy_mj,
            estimated_device_energy_mj=edge_energy_mj,
            estimated_edge_processing_ms=edge_proc_full_ms,
            estimated_verification_time_ms=ver_time_ms,
            estimated_bytes_transmitted=edge_bytes_tx,
            estimated_total_latency_ms=edge_latency_ms,
            net_delegation_benefit_ms=edge_net_benefit_ms,
        )

        return {
            "LOCAL_SECURITY_MODE": local_breakdown,
            "HYBRID_SECURITY_MODE": hybrid_breakdown,
            "EDGE_ASSISTED_SECURITY_MODE": edge_breakdown,
        }
