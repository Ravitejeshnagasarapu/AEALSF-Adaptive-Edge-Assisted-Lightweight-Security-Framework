from __future__ import annotations
from typing import Dict, List

from experiments.baseline import execute_policy_trial_on_fleet


def run_scalability_sweep(
    device_counts: List[int] | None = None,
) -> List[Dict[str, object]]:
    counts = device_counts or [100, 250, 500, 750, 1000, 1250, 1500]
    rows: List[Dict[str, object]] = []
    for n in counts:
        b_res = execute_policy_trial_on_fleet(
            None, None, "ORIGINAL_BASELINE", n, 0, allow_session_reuse=False
        )
        p_res = execute_policy_trial_on_fleet(
            None, None, "AEALSF", n, 0, allow_session_reuse=False
        )

        rows.append(
            {
                "device_count": n,
                "active_clients": b_res["actual_active_client_count"],
                "baseline_tps": b_res["completed_tps"],
                "proposed_tps": p_res["completed_tps"],
                "baseline_cpu_pct": b_res["cpu_utilization_percent"]["mean"],
                "proposed_cpu_pct": p_res["cpu_utilization_percent"]["mean"],
                "baseline_mem_kb": b_res["memory_consumption_kb"]["mean"],
                "proposed_mem_kb": p_res["memory_consumption_kb"]["mean"],
                "baseline_task_lat_ms": b_res["task_execution_latency_ms"]["mean"],
                "proposed_task_lat_ms": p_res["task_execution_latency_ms"]["mean"],
                "baseline_net_lat_ms": b_res["network_latency_ms"]["mean"],
                "proposed_net_lat_ms": p_res["network_latency_ms"]["mean"],
                "baseline_bytes_tx": b_res["bytes_transmitted"]["mean"],
                "proposed_bytes_tx": p_res["bytes_transmitted"]["mean"],
            }
        )
    return rows
