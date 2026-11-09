
from __future__ import annotations
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from adaptive_engine.cost_estimator import CostEstimator, ModeCostBreakdown
from adaptive_engine.policy_manager import SecurityPolicyDecision, SecurityPolicyManager
from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    ResourceAnalyzer,
    ResourcePressureAnalysis,
    TaskRequirementProfile,
)
from config.edge_config import EdgeConfig
from edge.failover_manager import EdgeFailoverManager


class ExecutionMode(str, Enum):
    LOCAL_SECURITY_MODE = "LOCAL_SECURITY_MODE"
    HYBRID_SECURITY_MODE = "HYBRID_SECURITY_MODE"
    EDGE_ASSISTED_SECURITY_MODE = "EDGE_ASSISTED_SECURITY_MODE"


@dataclass
class DecisionRecord:
    task_id: str
    device_id: str
    scheduling_policy: str
    selected_mode: ExecutionMode
    selected_edge_node_id: Optional[str]
    device_state: Dict[str, object]
    network_state: Dict[str, float]
    edge_node_state: Optional[Dict[str, object]]
    task_properties: Dict[str, object]
    security_constraints: Dict[str, object]
    estimated_local_cost: float
    estimated_hybrid_cost: float
    estimated_edge_cost: float
    verification_cost_term: float
    costs_by_mode: Dict[str, ModeCostBreakdown]
    rejected_options: Dict[str, str]
    pressure_analysis: ResourcePressureAnalysis
    policy_decision: SecurityPolicyDecision
    decision_latency_us: float
    rationale: str
    timestamp: float
    hysteresis_or_cooldown_applied: bool = False
    actual_execution_outcome: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "task_id": self.task_id,
            "device_id": self.device_id,
            "scheduling_policy": self.scheduling_policy,
            "selected_mode": self.selected_mode.value,
            "selected_edge_node_id": self.selected_edge_node_id,
            "device_state": self.device_state,
            "network_state": self.network_state,
            "edge_node_state": self.edge_node_state,
            "task_properties": self.task_properties,
            "security_constraints": self.security_constraints,
            "estimated_local_cost": round(self.estimated_local_cost, 4),
            "estimated_hybrid_cost": round(self.estimated_hybrid_cost, 4),
            "estimated_edge_cost": round(self.estimated_edge_cost, 4),
            "verification_cost_term": round(self.verification_cost_term, 4),
            "costs_by_mode": {k: v.to_dict() for k, v in self.costs_by_mode.items()},
            "rejected_options": self.rejected_options,
            "hysteresis_or_cooldown_applied": self.hysteresis_or_cooldown_applied,
            "pressure": {
                "cpu_pressure": self.pressure_analysis.cpu_pressure,
                "memory_pressure": self.pressure_analysis.memory_pressure,
                "battery_pressure": self.pressure_analysis.battery_pressure,
                "network_congestion": self.pressure_analysis.network_congestion_index,
                "composite_stress": self.pressure_analysis.composite_device_stress,
            },
            "decision_latency_us": round(self.decision_latency_us, 2),
            "rationale": self.rationale,
            "timestamp": self.timestamp,
            "actual_execution_outcome": self.actual_execution_outcome,
        }


class AdaptiveDecisionEngine:

    DEFAULT_COOLDOWN_SEC = 0.05

    def __init__(
        self,
        failover_manager: EdgeFailoverManager,
        config: Optional[EdgeConfig] = None,
        rng_seed: int = 42,
        cooldown_sec: float = DEFAULT_COOLDOWN_SEC,
    ) -> None:
        self.config = config or EdgeConfig()
        self.failover_manager = failover_manager
        self.analyzer = ResourceAnalyzer(self.config)
        self.cost_estimator = CostEstimator(self.config)
        self.policy_manager = SecurityPolicyManager()
        self.cooldown_sec = cooldown_sec
        self._last_mode_by_device: Dict[str, ExecutionMode] = {}
        self._last_switch_ts_by_device: Dict[str, float] = {}
        self._rng = random.Random(rng_seed)
        self.decision_history: List[DecisionRecord] = []

    def reset_state(self, rng_seed: Optional[int] = None) -> None:
        self._last_mode_by_device.clear()
        self._last_switch_ts_by_device.clear()
        self.decision_history.clear()
        if rng_seed is not None:
            self._rng.seed(rng_seed)

    def select_execution_mode(
        self,
        snapshot: DeviceResourceSnapshot,
        task: TaskRequirementProfile,
        scheduling_policy: str = "AEALSF",
    ) -> DecisionRecord:
        t0 = time.perf_counter_ns()
        now = time.time()

        pressure = self.analyzer.analyze(snapshot)
        best_edge = self.failover_manager.select_best_edge_node()
        policy = self.policy_manager.evaluate_policy(task, best_edge, snapshot)
        costs = self.cost_estimator.estimate_all_modes(snapshot, pressure, task, best_edge)
        rejected_options: Dict[str, str] = dict(policy.rejected_modes_with_reasons)
        hysteresis_applied = False

        norm_policy = (
            "RANDOM_OFFLOADING"
            if scheduling_policy == "RANDOM_SCHEDULING"
            else ("AEALSF" if scheduling_policy == "PROPOSED_AEALSF" else scheduling_policy)
        )

        if policy.mandatory_local_only or norm_policy in ("ORIGINAL_BASELINE", "ALWAYS_LOCAL"):
            chosen_mode = ExecutionMode.LOCAL_SECURITY_MODE
            chosen_edge_id = None
            for m in ("HYBRID_SECURITY_MODE", "EDGE_ASSISTED_SECURITY_MODE"):
                if m not in rejected_options:
                    rejected_options[m] = f"Excluded by fixed policy '{scheduling_policy}'."
            rationale = (
                policy.policy_rationale
                if policy.mandatory_local_only
                else f"Policy '{scheduling_policy}' executes strictly in LOCAL_SECURITY_MODE."
            )

        elif norm_policy == "ALWAYS_EDGE":
            if ExecutionMode.EDGE_ASSISTED_SECURITY_MODE.value in policy.allowed_modes:
                chosen_mode = ExecutionMode.EDGE_ASSISTED_SECURITY_MODE
                chosen_edge_id = best_edge.edge_node_id if best_edge else None
                for m in ("LOCAL_SECURITY_MODE", "HYBRID_SECURITY_MODE"):
                    rejected_options[m] = "Excluded by ALWAYS_EDGE policy."
                rationale = "ALWAYS_EDGE policy selected EDGE_ASSISTED_SECURITY_MODE (permitted by security policy)."
            else:
                chosen_mode = ExecutionMode.LOCAL_SECURITY_MODE
                chosen_edge_id = None
                rationale = "ALWAYS_EDGE policy restricted to LOCAL_SECURITY_MODE by hard constraint."

        elif norm_policy == "STATIC_THRESHOLD":
            if (
                snapshot.cpu_utilization_percent >= 75.0
                and ExecutionMode.EDGE_ASSISTED_SECURITY_MODE.value in policy.allowed_modes
            ):
                chosen_mode = ExecutionMode.EDGE_ASSISTED_SECURITY_MODE
            elif (
                snapshot.cpu_utilization_percent >= 48.0
                and ExecutionMode.HYBRID_SECURITY_MODE.value in policy.allowed_modes
            ):
                chosen_mode = ExecutionMode.HYBRID_SECURITY_MODE
            else:
                chosen_mode = ExecutionMode.LOCAL_SECURITY_MODE
            chosen_edge_id = (
                best_edge.edge_node_id
                if (chosen_mode != ExecutionMode.LOCAL_SECURITY_MODE and best_edge is not None)
                else None
            )
            for m in ("LOCAL_SECURITY_MODE", "HYBRID_SECURITY_MODE", "EDGE_ASSISTED_SECURITY_MODE"):
                if m != chosen_mode.value and m not in rejected_options:
                    rejected_options[m] = f"Not selected by fixed CPU threshold (CPU={snapshot.cpu_utilization_percent:.1f}%)."
            rationale = f"STATIC_THRESHOLD selected {chosen_mode.value} based solely on CPU={snapshot.cpu_utilization_percent:.1f}%."

        elif norm_policy == "RANDOM_OFFLOADING":
            picked_str = self._rng.choice(policy.allowed_modes)
            chosen_mode = ExecutionMode(picked_str)
            chosen_edge_id = (
                best_edge.edge_node_id
                if (chosen_mode != ExecutionMode.LOCAL_SECURITY_MODE and best_edge is not None)
                else None
            )
            for m in policy.allowed_modes:
                if m != chosen_mode.value:
                    rejected_options[m] = "Not drawn in uniform random sampling."
            rationale = f"RANDOM_OFFLOADING uniformly sampled {chosen_mode.value} from allowed modes."

        else:
            allowed_candidates = [
                (ExecutionMode(m), costs[m].total_cost)
                for m in policy.allowed_modes
                if m in costs
            ]
            allowed_candidates.sort(key=lambda item: item[1])
            best_mode, best_cost = allowed_candidates[0]

            if (
                best_mode != ExecutionMode.LOCAL_SECURITY_MODE
                and snapshot.available_ram_kb > self.config.critical_free_ram_kb
                and costs[best_mode.value].net_delegation_benefit_ms < -8.0
                and costs["LOCAL_SECURITY_MODE"].total_cost <= best_cost + 0.12
            ):
                rejected_options[best_mode.value] = (
                    f"Negative net delegation benefit ({costs[best_mode.value].net_delegation_benefit_ms:.2f} ms) under high RTT."
                )
                best_mode = ExecutionMode.LOCAL_SECURITY_MODE
                best_cost = costs["LOCAL_SECURITY_MODE"].total_cost

            prev_mode = self._last_mode_by_device.get(snapshot.device_id)
            last_switch_ts = self._last_switch_ts_by_device.get(snapshot.device_id, 0.0)
            if (
                prev_mode is not None
                and prev_mode.value in policy.allowed_modes
                and prev_mode != best_mode
                and not pressure.is_severely_constrained
            ):
                prev_cost = costs[prev_mode.value].total_cost
                within_cooldown = (now - last_switch_ts) < self.cooldown_sec
                within_hysteresis = (prev_cost - best_cost) < self.config.mode_switch_hysteresis
                if within_hysteresis or (within_cooldown and (prev_cost - best_cost) < self.config.mode_switch_hysteresis * 2.5):
                    rejected_options[best_mode.value] = (
                        f"Suppressed by hysteresis/cooldown (cost delta {prev_cost - best_cost:.4f} < threshold)."
                    )
                    best_mode = prev_mode
                    best_cost = prev_cost
                    hysteresis_applied = True

            chosen_mode = best_mode
            for m_enum, m_cost in allowed_candidates:
                if m_enum != chosen_mode and m_enum.value not in rejected_options:
                    rejected_options[m_enum.value] = (
                        f"Higher calibrated cost (C={m_cost:.4f} > C_selected={best_cost:.4f})."
                    )

            chosen_edge_id = (
                best_edge.edge_node_id
                if (chosen_mode != ExecutionMode.LOCAL_SECURITY_MODE and best_edge is not None)
                else None
            )
            rationale = (
                f"Selected {chosen_mode.value} (C={best_cost:.3f} vs "
                f"C_local={costs['LOCAL_SECURITY_MODE'].total_cost:.3f}, "
                f"C_hybrid={costs['HYBRID_SECURITY_MODE'].total_cost:.3f}, "
                f"C_edge={costs['EDGE_ASSISTED_SECURITY_MODE'].total_cost:.3f}, "
                f"V_cost={costs[chosen_mode.value].verification_overhead_term:.3f}, "
                f"stress={pressure.composite_device_stress:.2f})."
            )

        if self._last_mode_by_device.get(snapshot.device_id) != chosen_mode:
            self._last_switch_ts_by_device[snapshot.device_id] = now
        self._last_mode_by_device[snapshot.device_id] = chosen_mode
        decision_us = (time.perf_counter_ns() - t0) / 1000.0

        record = DecisionRecord(
            task_id=task.task_id,
            device_id=snapshot.device_id,
            scheduling_policy=scheduling_policy,
            selected_mode=chosen_mode,
            selected_edge_node_id=chosen_edge_id,
            device_state=snapshot.to_dict(),
            network_state={
                "network_latency_ms": round(snapshot.network_latency_ms, 2),
                "available_bandwidth_mbps": round(snapshot.available_bandwidth_mbps, 2),
                "network_congestion_index": pressure.network_congestion_index,
            },
            edge_node_state=best_edge.to_dict() if best_edge is not None else None,
            task_properties=task.to_dict(),
            security_constraints={
                "mandatory_local_only": policy.mandatory_local_only,
                "allowed_modes": policy.allowed_modes,
                "verification_strategy": policy.verification_strategy,
                "policy_rationale": policy.policy_rationale,
            },
            estimated_local_cost=costs["LOCAL_SECURITY_MODE"].total_cost,
            estimated_hybrid_cost=costs["HYBRID_SECURITY_MODE"].total_cost,
            estimated_edge_cost=costs["EDGE_ASSISTED_SECURITY_MODE"].total_cost,
            verification_cost_term=costs[chosen_mode.value].verification_overhead_term,
            costs_by_mode=costs,
            rejected_options=rejected_options,
            pressure_analysis=pressure,
            policy_decision=policy,
            decision_latency_us=decision_us,
            rationale=rationale,
            timestamp=now,
            hysteresis_or_cooldown_applied=hysteresis_applied,
        )
        self.decision_history.append(record)
        return record

    def get_mode_distribution_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {
            ExecutionMode.LOCAL_SECURITY_MODE.value: 0,
            ExecutionMode.HYBRID_SECURITY_MODE.value: 0,
            ExecutionMode.EDGE_ASSISTED_SECURITY_MODE.value: 0,
        }
        for rec in self.decision_history:
            counts[rec.selected_mode.value] = counts.get(rec.selected_mode.value, 0) + 1
        return counts
