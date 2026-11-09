from __future__ import annotations
import math
import statistics
from typing import Dict, List

try:
    from scipy import stats
except (ImportError, ModuleNotFoundError):

    class _DummyResult:
        statistic = 0.0
        pvalue = 1.0

    class _StatsFallback:
        def ttest_rel(self, a, b):
            return _DummyResult()

        def ttest_ind(self, a, b, equal_var=False):
            return _DummyResult()

        def mannwhitneyu(self, a, b, alternative="two-sided"):
            return _DummyResult()

        def wilcoxon(self, a, b):
            return _DummyResult()

    stats = _StatsFallback()

from monitoring.performance_monitor import PerformanceMonitor, TaskPerformanceSample

T_CRIT_95_BY_DF = {
    1: 12.706,
    2: 4.303,
    4: 2.776,
    9: 2.262,
    14: 2.145,
    19: 2.093,
    24: 2.064,
    29: 2.0452,
}


def compute_percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def compute_stats_with_ci95(vals: List[float]) -> Dict[str, float | int]:
    clean = [float(v) for v in vals if v is not None and not math.isnan(float(v))]
    if not clean:
        return {
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "ci95": 0.0,
            "ci95_low": 0.0,
            "ci95_high": 0.0,
            "n_valid": 0,
        }
    n = len(clean)
    s_vals = sorted(clean)
    m = statistics.mean(s_vals)
    med = statistics.median(s_vals)
    sd = statistics.stdev(s_vals) if n > 1 else 0.0
    t_val = T_CRIT_95_BY_DF.get(n - 1, 2.0452 if n >= 25 else 2.262)
    ci95 = t_val * (sd / math.sqrt(n)) if n > 1 else 0.0
    p25 = compute_percentile(s_vals, 25.0)
    p75 = compute_percentile(s_vals, 75.0)
    iqr = p75 - p25
    p95 = compute_percentile(s_vals, 95.0)
    p99 = compute_percentile(s_vals, 99.0)
    return {
        "mean": round(m, 4),
        "std": round(sd, 4),
        "median": round(med, 4),
        "iqr": round(iqr, 4),
        "p25": round(p25, 4),
        "p75": round(p75, 4),
        "min": round(s_vals[0], 4),
        "max": round(s_vals[-1], 4),
        "p95": round(p95, 4),
        "p99": round(p99, 4),
        "ci95": round(ci95, 4),
        "ci95_low": round(m - ci95, 4),
        "ci95_high": round(m + ci95, 4),
        "n_valid": n,
    }


def compute_paired_comparison_stats(
    baseline_vals: List[float],
    candidate_vals: List[float],
    num_comparisons: int = 5,
) -> Dict[str, float | bool]:
    n = min(len(baseline_vals), len(candidate_vals))
    if n < 2:
        return {
            "n_pairs": n,
            "mean_diff": 0.0,
            "ci95_diff_low": 0.0,
            "ci95_diff_high": 0.0,
            "cohens_d": 0.0,
            "t_stat": 0.0,
            "p_value": 1.0,
            "p_value_bonferroni": 1.0,
            "significant_alpha_0_01": False,
        }

    diffs = [float(b) - float(c) for b, c in zip(baseline_vals[:n], candidate_vals[:n])]
    mean_diff = statistics.mean(diffs)
    sd_diff = statistics.stdev(diffs) if n > 1 else 0.0

    if sd_diff == 0.0:
        return {
            "n_pairs": n,
            "mean_diff": round(mean_diff, 4),
            "ci95_diff_low": round(mean_diff, 4),
            "ci95_diff_high": round(mean_diff, 4),
            "cohens_d": 0.0 if mean_diff == 0.0 else 99.0,
            "pooled_cohens_d": 0.0 if mean_diff == 0.0 else 99.0,
            "t_stat": 0.0 if mean_diff == 0.0 else 99.0,
            "p_value": 1.0 if mean_diff == 0.0 else 1e-10,
            "p_value_bonferroni": 1.0 if mean_diff == 0.0 else 1e-10,
            "welch_t_stat": 0.0 if mean_diff == 0.0 else 99.0,
            "welch_p_value": 1.0 if mean_diff == 0.0 else 1e-10,
            "mannwhitney_u_stat": 0.0,
            "mannwhitney_p_value": 1.0 if mean_diff == 0.0 else 1e-10,
            "wilcoxon_stat": 0.0,
            "wilcoxon_p_value": 1.0 if mean_diff == 0.0 else 1e-10,
            "significant_alpha_0_01": bool(mean_diff != 0.0),
        }

    t_val = T_CRIT_95_BY_DF.get(n - 1, 2.0452)
    ci_diff = t_val * (sd_diff / math.sqrt(n))
    cohens_d = mean_diff / sd_diff

    res = stats.ttest_rel(baseline_vals[:n], candidate_vals[:n])
    t_stat = 0.0 if math.isnan(float(res.statistic)) else float(res.statistic)
    p_val = 1.0 if math.isnan(float(res.pvalue)) else float(res.pvalue)
    p_bonf = min(1.0, p_val * max(1, num_comparisons))

    welch_res = stats.ttest_ind(baseline_vals[:n], candidate_vals[:n], equal_var=False)
    welch_t = (
        0.0 if math.isnan(float(welch_res.statistic)) else float(welch_res.statistic)
    )
    welch_p = 1.0 if math.isnan(float(welch_res.pvalue)) else float(welch_res.pvalue)

    try:
        mwu_res = stats.mannwhitneyu(
            baseline_vals[:n], candidate_vals[:n], alternative="two-sided"
        )
        mwu_u = float(mwu_res.statistic)
        mwu_p = float(mwu_res.pvalue)
    except Exception:
        mwu_u, mwu_p = 0.0, 1.0

    try:
        wil_res = stats.wilcoxon(baseline_vals[:n], candidate_vals[:n])
        wil_w = float(wil_res.statistic)
        wil_p = float(wil_res.pvalue)
    except Exception:
        wil_w, wil_p = 0.0, 1.0

    sd_b = statistics.stdev(baseline_vals[:n]) if n > 1 else 0.0
    sd_c = statistics.stdev(candidate_vals[:n]) if n > 1 else 0.0
    pooled_sd = math.sqrt((sd_b * sd_b + sd_c * sd_c) / 2.0)
    pooled_d = (
        (statistics.mean(baseline_vals[:n]) - statistics.mean(candidate_vals[:n]))
        / pooled_sd
        if pooled_sd > 0
        else cohens_d
    )

    return {
        "n_pairs": n,
        "mean_diff": round(mean_diff, 4),
        "ci95_diff_low": round(mean_diff - ci_diff, 4),
        "ci95_diff_high": round(mean_diff + ci_diff, 4),
        "cohens_d": round(cohens_d, 4),
        "pooled_cohens_d": round(pooled_d, 4),
        "t_stat": round(t_stat, 4),
        "p_value": round(p_val, 10),
        "p_value_bonferroni": round(p_bonf, 10),
        "welch_t_stat": round(welch_t, 4),
        "welch_p_value": round(welch_p, 10),
        "mannwhitney_u_stat": round(mwu_u, 4),
        "mannwhitney_p_value": round(mwu_p, 10),
        "wilcoxon_stat": round(wil_w, 4),
        "wilcoxon_p_value": round(wil_p, 10),
        "significant_alpha_0_01": bool(p_bonf < 0.01),
    }


class MetricsCollector:

    def __init__(self, perf_monitor: PerformanceMonitor) -> None:
        self.perf_monitor = perf_monitor
        self.security_events: List[Dict[str, object]] = []

    def record_security_event(
        self, event_type: str, device_id: str, mitigated: bool, details: str
    ) -> None:
        self.security_events.append(
            {
                "event_type": event_type,
                "device_id": device_id,
                "mitigated": mitigated,
                "details": details,
            }
        )

    @staticmethod
    def summarize_samples(
        samples: List[TaskPerformanceSample],
        actual_wall_duration_sec: float | None = None,
    ) -> Dict[str, object]:
        if not samples:
            return {"count": 0}

        mode_counts: Dict[str, int] = {
            "LOCAL_SECURITY_MODE": 0,
            "HYBRID_SECURITY_MODE": 0,
            "EDGE_ASSISTED_SECURITY_MODE": 0,
        }
        for s in samples:
            mode_counts[s.execution_mode] = mode_counts.get(s.execution_mode, 0) + 1

        elapsed_sec = (
            max(0.0001, actual_wall_duration_sec)
            if actual_wall_duration_sec is not None
            else max(
                0.0001,
                sum(
                    s.measurement_interval_ms or s.task_execution_latency_ms
                    for s in samples
                )
                / 1000.0,
            )
        )
        completed_tasks = sum(
            1 for s in samples if s.auth_succeeded and s.result_verified
        )
        completed_tx = completed_tasks * 2

        return {
            "count": len(samples),
            "completed_tasks": completed_tasks,
            "failed_tasks": len(samples) - completed_tasks,
            "cpu_utilization_percent": compute_stats_with_ci95(
                [s.device_cpu_utilization_percent for s in samples]
            ),
            "device_cpu_time_ms": compute_stats_with_ci95(
                [s.device_cpu_time_ms for s in samples]
            ),
            "memory_consumption_kb": compute_stats_with_ci95(
                [s.device_memory_kb for s in samples]
            ),
            "edge_server_cpu_time_ms": compute_stats_with_ci95(
                [s.edge_server_cpu_time_ms for s in samples]
            ),
            "edge_cpu_load_percent": compute_stats_with_ci95(
                [s.edge_cpu_load_percent for s in samples]
            ),
            "edge_server_memory_kb": compute_stats_with_ci95(
                [s.edge_server_memory_kb for s in samples]
            ),
            "validator_cpu_time_ms": compute_stats_with_ci95(
                [s.validator_cpu_time_ms for s in samples]
            ),
            "node_cpu_utilization_percent": compute_stats_with_ci95(
                [s.node_cpu_utilization_percent for s in samples]
            ),
            "validator_memory_kb": compute_stats_with_ci95(
                [s.validator_memory_kb for s in samples]
            ),
            "node_memory_mb": compute_stats_with_ci95(
                [s.node_memory_mb for s in samples]
            ),
            "host_process_cpu_utilization_pct": compute_stats_with_ci95(
                [s.host_process_cpu_utilization_pct for s in samples]
            ),
            "emulated_device_cpu_quota_pct": compute_stats_with_ci95(
                [s.emulated_device_cpu_quota_pct for s in samples]
            ),
            "measured_task_buffer_kb": compute_stats_with_ci95(
                [s.measured_task_buffer_kb for s in samples]
            ),
            "host_process_rss_kb": compute_stats_with_ci95(
                [s.host_process_rss_kb for s in samples]
            ),
            "host_process_peak_rss_kb": compute_stats_with_ci95(
                [s.host_process_peak_rss_kb for s in samples]
            ),
            "emulated_device_available_ram_kb": compute_stats_with_ci95(
                [s.emulated_device_available_ram_kb for s in samples]
            ),
            "energy_consumption_mj": compute_stats_with_ci95(
                [s.energy_estimate_mj for s in samples]
            ),
            "auth_latency_ms": compute_stats_with_ci95(
                [s.auth_latency_ms for s in samples]
            ),
            "nizk_prove_time_ms": compute_stats_with_ci95(
                [s.nizk_prove_time_ms for s in samples]
            ),
            "nizk_verify_time_ms": compute_stats_with_ci95(
                [s.nizk_verify_time_ms for s in samples]
            ),
            "he_encrypt_time_ms": compute_stats_with_ci95(
                [s.he_encrypt_time_ms for s in samples]
            ),
            "he_add_time_ms": compute_stats_with_ci95(
                [s.he_add_time_ms for s in samples]
            ),
            "he_scalar_mul_time_ms": compute_stats_with_ci95(
                [s.he_scalar_mul_time_ms for s in samples]
            ),
            "he_decrypt_time_ms": compute_stats_with_ci95(
                [s.he_decrypt_time_ms for s in samples]
            ),
            "edge_execution_time_ms": compute_stats_with_ci95(
                [s.edge_execution_time_ms for s in samples]
            ),
            "result_verification_time_ms": compute_stats_with_ci95(
                [s.result_verification_time_ms for s in samples]
            ),
            "tx_commit_time_ms": compute_stats_with_ci95(
                [s.tx_commit_time_ms for s in samples]
            ),
            "task_execution_latency_ms": compute_stats_with_ci95(
                [s.task_execution_latency_ms for s in samples]
            ),
            "measurement_interval_ms": compute_stats_with_ci95(
                [s.measurement_interval_ms for s in samples]
            ),
            "network_latency_ms": compute_stats_with_ci95(
                [s.network_latency_ms for s in samples]
            ),
            "bytes_transmitted": compute_stats_with_ci95(
                [float(s.bytes_transmitted) for s in samples]
            ),
            "bytes_received": compute_stats_with_ci95(
                [float(s.bytes_received) for s in samples]
            ),
            "bandwidth_kbps": compute_stats_with_ci95(
                [s.bandwidth_used_kbps for s in samples]
            ),
            "auth_failures": sum(1 for s in samples if not s.auth_succeeded),
            "result_verification_failures": sum(
                1 for s in samples if not s.result_verified
            ),
            "fallback_activations": sum(1 for s in samples if s.used_fallback),
            "mode_distribution": mode_counts,
            "actual_elapsed_sec": round(elapsed_sec, 4),
            "completed_task_rate_per_sec": round(completed_tasks / elapsed_sec, 2),
            "aggregate_throughput_tps": round(completed_tx / elapsed_sec, 2),
        }

    def export_prometheus_metrics(self) -> str:
        summary = self.summarize_samples(self.perf_monitor.samples)
        count = summary.get("count", 0)
        lines = [
            "# HELP aealsf_tasks_total Total number of IoT security tasks processed",
            "# TYPE aealsf_tasks_total counter",
            f"aealsf_tasks_total {count}",
            "# HELP aealsf_security_events_total Total security events detected and handled",
            "# TYPE aealsf_security_events_total counter",
            f"aealsf_security_events_total {len(self.security_events)}",
        ]
        if count > 0:
            cpu_mean = summary["cpu_utilization_percent"]["mean"]
            mem_mean = summary["memory_consumption_kb"]["mean"]
            lat_mean = summary["task_execution_latency_ms"]["mean"]
            lines.extend(
                [
                    "# HELP aealsf_simulated_device_cpu_percent Mean simulated IoT device CPU utilization percent",
                    "# TYPE aealsf_simulated_device_cpu_percent gauge",
                    f"aealsf_simulated_device_cpu_percent {cpu_mean}",
                    "# HELP aealsf_simulated_device_memory_kb Mean simulated IoT device RAM usage in KB",
                    "# TYPE aealsf_simulated_device_memory_kb gauge",
                    f"aealsf_simulated_device_memory_kb {mem_mean}",
                    "# HELP aealsf_task_latency_ms Mean task execution latency in ms",
                    "# TYPE aealsf_task_latency_ms gauge",
                    f"aealsf_task_latency_ms {lat_mean}",
                ]
            )
        return "\n".join(lines) + "\n"
