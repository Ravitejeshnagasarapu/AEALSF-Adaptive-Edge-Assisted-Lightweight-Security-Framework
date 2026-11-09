from __future__ import annotations
import os
import platform

try:
    import resource
except ImportError:
    resource = None
import time
import tracemalloc
from dataclasses import dataclass
from typing import Dict, List


def get_host_hardware_info() -> Dict[str, object]:
    cpu_model = platform.processor() or "x86_64"
    cpu_mhz = 2700.0
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name") and ":" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                elif line.startswith("cpu MHz") and ":" in line:
                    try:
                        cpu_mhz = float(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
    except OSError:
        pass

    mem_total_kb = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        mem_total_kb = int(parts[1])
                    break
    except OSError:
        pass

    cores = os.cpu_count() or 2
    return {
        "host_cpu_model": cpu_model,
        "host_cpu_cores": cores,
        "host_cpu_mhz": round(cpu_mhz, 2),
        "host_total_ram_kb": mem_total_kb,
        "host_total_ram_mb": round(mem_total_kb / 1024.0, 2),
        "host_os_kernel": platform.platform(),
        "emulated_device_target": "Fibocom L610-CN Cat.1 (500 MHz ARM Cortex-A5, 2048 KB RAM)",
        "emulated_cpu_quota_ratio": round(500.0 / max(500.0, cpu_mhz), 4),
    }


HOST_HARDWARE_INFO = get_host_hardware_info()


@dataclass(frozen=True)
class TaskPerformanceSample:
    task_id: str
    device_id: str
    configuration: str
    execution_mode: str
    auth_latency_ms: float
    nizk_prove_time_ms: float
    nizk_verify_time_ms: float
    he_encrypt_time_ms: float
    he_add_time_ms: float
    he_scalar_mul_time_ms: float
    he_decrypt_time_ms: float
    edge_execution_time_ms: float
    result_verification_time_ms: float
    tx_commit_time_ms: float
    task_execution_latency_ms: float
    device_cpu_time_ms: float
    device_cpu_utilization_percent: float
    device_memory_kb: float
    node_cpu_utilization_percent: float
    node_memory_mb: float
    energy_estimate_mj: float
    network_latency_ms: float
    bytes_transmitted: int
    bytes_received: int
    bandwidth_used_kbps: float
    edge_node_id: str
    edge_cpu_load_percent: float
    auth_succeeded: bool
    result_verified: bool
    used_fallback: bool = False
    measurement_interval_ms: float = 0.0
    host_process_cpu_utilization_pct: float = 0.0
    emulated_device_cpu_quota_pct: float = 0.0
    edge_server_cpu_time_ms: float = 0.0
    validator_cpu_time_ms: float = 0.0
    host_process_rss_kb: float = 0.0
    host_process_peak_rss_kb: float = 0.0
    measured_task_buffer_kb: float = 0.0
    emulated_device_ram_budget_kb: float = 2048.0
    emulated_device_available_ram_kb: float = 1024.0
    edge_server_memory_kb: float = 0.0
    validator_memory_kb: float = 0.0
    energy_classification: str = "MODEL_ESTIMATED"

    def to_dict(self) -> Dict[str, object]:
        return {
            "task_id": self.task_id,
            "device_id": self.device_id,
            "configuration": self.configuration,
            "execution_mode": self.execution_mode,
            "auth_latency_ms": round(self.auth_latency_ms, 4),
            "nizk_prove_time_ms": round(self.nizk_prove_time_ms, 4),
            "nizk_verify_time_ms": round(self.nizk_verify_time_ms, 4),
            "he_encrypt_time_ms": round(self.he_encrypt_time_ms, 4),
            "he_add_time_ms": round(self.he_add_time_ms, 4),
            "he_scalar_mul_time_ms": round(self.he_scalar_mul_time_ms, 4),
            "he_decrypt_time_ms": round(self.he_decrypt_time_ms, 4),
            "edge_execution_time_ms": round(self.edge_execution_time_ms, 4),
            "result_verification_time_ms": round(self.result_verification_time_ms, 4),
            "tx_commit_time_ms": round(self.tx_commit_time_ms, 4),
            "task_execution_latency_ms": round(self.task_execution_latency_ms, 4),
            "measurement_interval_ms": round(self.measurement_interval_ms, 4),
            "device_cpu_time_ms": round(self.device_cpu_time_ms, 4),
            "device_cpu_utilization_percent": round(
                self.device_cpu_utilization_percent, 2
            ),
            "host_process_cpu_utilization_pct": round(
                self.host_process_cpu_utilization_pct, 2
            ),
            "emulated_device_cpu_quota_pct": round(
                self.emulated_device_cpu_quota_pct, 2
            ),
            "edge_server_cpu_time_ms": round(self.edge_server_cpu_time_ms, 4),
            "edge_cpu_load_percent": round(self.edge_cpu_load_percent, 2),
            "validator_cpu_time_ms": round(self.validator_cpu_time_ms, 4),
            "node_cpu_utilization_percent": round(self.node_cpu_utilization_percent, 2),
            "device_memory_kb": round(self.device_memory_kb, 3),
            "measured_task_buffer_kb": round(self.measured_task_buffer_kb, 3),
            "host_process_rss_kb": round(self.host_process_rss_kb, 2),
            "host_process_peak_rss_kb": round(self.host_process_peak_rss_kb, 2),
            "emulated_device_ram_budget_kb": round(
                self.emulated_device_ram_budget_kb, 2
            ),
            "emulated_device_available_ram_kb": round(
                self.emulated_device_available_ram_kb, 2
            ),
            "edge_server_memory_kb": round(self.edge_server_memory_kb, 3),
            "validator_memory_kb": round(self.validator_memory_kb, 3),
            "node_memory_mb": round(self.node_memory_mb, 2),
            "energy_estimate_mj": round(self.energy_estimate_mj, 4),
            "energy_classification": self.energy_classification,
            "network_latency_ms": round(self.network_latency_ms, 2),
            "bytes_transmitted": self.bytes_transmitted,
            "bytes_received": self.bytes_received,
            "bandwidth_used_kbps": round(self.bandwidth_used_kbps, 2),
            "edge_node_id": self.edge_node_id,
            "auth_succeeded": self.auth_succeeded,
            "result_verified": self.result_verified,
            "used_fallback": self.used_fallback,
        }


class PerformanceMonitor:

    def __init__(self) -> None:
        self.samples: List[TaskPerformanceSample] = []
        self.host_info = HOST_HARDWARE_INFO

    def record_sample(self, sample: TaskPerformanceSample) -> None:
        self.samples.append(sample)

    @staticmethod
    def get_process_cpu_time_ms() -> float:
        if resource is not None:
            ru = resource.getrusage(resource.RUSAGE_SELF)
            return (ru.ru_utime + ru.ru_stime) * 1000.0
        return time.process_time() * 1000.0

    _LAST_MEM_CACHE_TS: float = 0.0
    _LAST_MEM_CACHE_VAL: Dict[str, float] = {}

    @staticmethod
    def get_process_memory_status_kb() -> Dict[str, float]:
        now = time.perf_counter()
        if (
            PerformanceMonitor._LAST_MEM_CACHE_VAL
            and (now - PerformanceMonitor._LAST_MEM_CACHE_TS) < 0.010
        ):
            return PerformanceMonitor._LAST_MEM_CACHE_VAL
        peak_rss_kb = 10240.0
        if resource is not None:
            ru = resource.getrusage(resource.RUSAGE_SELF)
            peak_rss_kb = float(ru.ru_maxrss)
        curr_rss_kb = peak_rss_kb
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        curr_rss_kb = float(line.split()[1])
                    elif line.startswith("VmHWM:"):
                        peak_rss_kb = max(peak_rss_kb, float(line.split()[1]))
        except OSError:
            pass
        res = {
            "rss_kb": curr_rss_kb,
            "peak_rss_kb": peak_rss_kb,
            "rss_mb": curr_rss_kb / 1024.0,
            "peak_rss_mb": peak_rss_kb / 1024.0,
        }
        PerformanceMonitor._LAST_MEM_CACHE_TS = now
        PerformanceMonitor._LAST_MEM_CACHE_VAL = res
        return res

    @staticmethod
    def get_process_rss_mb() -> float:
        return PerformanceMonitor.get_process_memory_status_kb()["rss_mb"]

    @staticmethod
    def compute_cpu_utilization_metrics(
        cpu_time_delta_ms: float,
        wall_clock_interval_ms: float,
    ) -> Dict[str, float]:
        interval_ms = max(0.001, wall_clock_interval_ms)
        clean_cpu_ms = max(0.0, cpu_time_delta_ms)
        cores = int(HOST_HARDWARE_INFO["host_cpu_cores"])
        quota_ratio = float(HOST_HARDWARE_INFO["emulated_cpu_quota_ratio"])

        single_core_pct = min(100.0, (clean_cpu_ms / interval_ms) * 100.0)
        multi_core_pct = min(100.0, (clean_cpu_ms / (interval_ms * cores)) * 100.0)
        emulated_quota_pct = min(
            100.0, (clean_cpu_ms / (interval_ms * quota_ratio)) * 100.0
        )

        return {
            "cpu_time_ms": round(clean_cpu_ms, 4),
            "measurement_interval_ms": round(interval_ms, 4),
            "single_core_cpu_pct": round(single_core_pct, 2),
            "multi_core_host_cpu_pct": round(multi_core_pct, 2),
            "emulated_quota_cpu_pct": round(emulated_quota_pct, 2),
        }

    @staticmethod
    def measure_callable_memory_kb(func, *args, **kwargs):
        was_tracing = tracemalloc.is_tracing()
        if not was_tracing:
            tracemalloc.start()
        tracemalloc.reset_peak()
        c0_ms = PerformanceMonitor.get_process_cpu_time_ms()
        t0_ns = time.perf_counter_ns()
        result = func(*args, **kwargs)
        elapsed_ms = (time.perf_counter_ns() - t0_ns) / 1_000_000.0
        cpu_ms = max(0.0, PerformanceMonitor.get_process_cpu_time_ms() - c0_ms)
        _, peak_bytes = tracemalloc.get_traced_memory()
        if not was_tracing:
            tracemalloc.stop()
        return result, peak_bytes / 1024.0, elapsed_ms, cpu_ms
