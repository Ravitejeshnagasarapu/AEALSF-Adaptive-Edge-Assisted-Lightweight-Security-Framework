from __future__ import annotations
import json
import os
import random
from typing import Dict, List

from adaptive_engine.decision_engine import AdaptiveDecisionEngine
from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    TaskRequirementProfile,
)
from config.edge_config import EdgeConfig
from edge.edge_monitor import EdgeMonitor
from edge.failover_manager import EdgeFailoverManager


CANDIDATE_WEIGHT_PROFILES = [
    {
        "name": "AEALSF-Calibrated (0.35, 0.25, 0.20, 0.20)",
        "alpha": 0.35,
        "beta": 0.25,
        "gamma": 0.20,
        "delta": 0.20,
    },
    {
        "name": "Equal-Weights (0.25, 0.25, 0.25, 0.25)",
        "alpha": 0.25,
        "beta": 0.25,
        "gamma": 0.25,
        "delta": 0.25,
    },
    {
        "name": "CPU-Greedy (0.70, 0.10, 0.10, 0.10)",
        "alpha": 0.70,
        "beta": 0.10,
        "gamma": 0.10,
        "delta": 0.10,
    },
    {
        "name": "Memory-Greedy (0.10, 0.70, 0.10, 0.10)",
        "alpha": 0.10,
        "beta": 0.70,
        "gamma": 0.10,
        "delta": 0.10,
    },
    {
        "name": "Energy-Greedy (0.10, 0.10, 0.70, 0.10)",
        "alpha": 0.10,
        "beta": 0.10,
        "gamma": 0.70,
        "delta": 0.10,
    },
    {
        "name": "Latency-Greedy (0.10, 0.10, 0.10, 0.70)",
        "alpha": 0.10,
        "beta": 0.10,
        "gamma": 0.10,
        "delta": 0.70,
    },
]


def run_weight_calibration_experiment(
    num_synthetic_tasks: int = 120,
) -> Dict[str, object]:
    rng = random.Random(20250615)
    snapshots: List[DeviceResourceSnapshot] = []
    tasks: List[TaskRequirementProfile] = []

    for i in range(num_synthetic_tasks):
        snapshots.append(
            DeviceResourceSnapshot(
                device_id=f"cal-dev-{i:03d}",
                cpu_utilization_percent=rng.uniform(15.0, 94.0),
                available_ram_kb=rng.uniform(210.0, 1820.0),
                total_ram_kb=2048.0,
                battery_percent=rng.uniform(12.0, 98.0),
                network_latency_ms=rng.uniform(12.0, 140.0),
                available_bandwidth_mbps=rng.uniform(8.0, 95.0),
            )
        )
        tasks.append(
            TaskRequirementProfile(
                task_id=f"cal-task-{i:03d}",
                task_type=(
                    "PRIVATE_KEY_DECRYPTION"
                    if i % 15 == 0
                    else "HOMOMORPHIC_AGGREGATION"
                ),
                payload_bytes=512 * (1 + (i % 4)),
                num_homomorphic_ops=2 + (i % 4),
                priority=["LOW", "NORMAL", "HIGH", "CRITICAL"][i % 4],
                requires_private_key_access=(i % 15 == 0),
            )
        )

    profile_results: List[Dict[str, object]] = []
    for prof in CANDIDATE_WEIGHT_PROFILES:
        cfg = EdgeConfig(
            alpha_cpu_or_comm=float(prof["alpha"]),
            beta_mem_or_edge_proc=float(prof["beta"]),
            gamma_energy=float(prof["gamma"]),
            delta_latency=float(prof["delta"]),
        )
        monitor = EdgeMonitor(["edge-node-0", "edge-node-1", "edge-node-2"])
        failover = EdgeFailoverManager(monitor, cfg)
        engine = AdaptiveDecisionEngine(failover, cfg)

        cpu_ms_list: List[float] = []
        ram_kb_list: List[float] = []
        energy_mj_list: List[float] = []
        latency_ms_list: List[float] = []
        unnecessary_offloads_on_congested_net = 0

        for snap, task in zip(snapshots, tasks):
            rec = engine.select_execution_mode(snap, task)
            chosen_cost = rec.costs_by_mode[rec.selected_mode.value]
            cpu_ms_list.append(chosen_cost.estimated_device_cpu_ms)
            ram_kb_list.append(chosen_cost.estimated_device_ram_kb)
            energy_mj_list.append(chosen_cost.estimated_device_energy_mj)
            latency_ms_list.append(chosen_cost.estimated_total_latency_ms)
            if (
                rec.selected_mode.value != "LOCAL_SECURITY_MODE"
                and snap.network_latency_ms > 95.0
                and snap.cpu_utilization_percent < 65.0
            ):
                unnecessary_offloads_on_congested_net += 1

        mean_cpu = sum(cpu_ms_list) / len(cpu_ms_list)
        mean_ram = sum(ram_kb_list) / len(ram_kb_list)
        mean_eng = sum(energy_mj_list) / len(energy_mj_list)
        mean_lat = sum(latency_ms_list) / len(latency_ms_list)

        weight_variance_penalty = (
            sum(
                (float(prof[k]) - 0.25) ** 2
                for k in ("alpha", "beta", "gamma", "delta")
            )
            * 0.45
        )

        pareto_loss = (
            (mean_cpu / 25.0) * 0.30
            + (mean_ram / 250.0) * 0.25
            + (mean_eng / 12.0) * 0.25
            + (mean_lat / 70.0) * 0.20
            + unnecessary_offloads_on_congested_net * 0.012
            + weight_variance_penalty
        )

        profile_results.append(
            {
                "profile_name": prof["name"],
                "weights": {
                    "alpha": prof["alpha"],
                    "beta": prof["beta"],
                    "gamma": prof["gamma"],
                    "delta": prof["delta"],
                },
                "mean_device_cpu_ms": round(mean_cpu, 2),
                "mean_device_ram_kb": round(mean_ram, 2),
                "mean_device_energy_mj": round(mean_eng, 2),
                "mean_total_latency_ms": round(mean_lat, 2),
                "congested_link_over_offloads": unnecessary_offloads_on_congested_net,
                "composite_pareto_loss": round(pareto_loss, 4),
                "mode_distribution": engine.get_mode_distribution_summary(),
            }
        )

    profile_results.sort(key=lambda r: float(r["composite_pareto_loss"]))
    output = {
        "num_tasks_evaluated": num_synthetic_tasks,
        "optimal_profile": profile_results[0]["profile_name"],
        "profiles": profile_results,
    }
    os.makedirs("results", exist_ok=True)
    with open("results/weight_calibration.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    return output


if __name__ == "__main__":
    res = run_weight_calibration_experiment()
    print(json.dumps(res, indent=2))
