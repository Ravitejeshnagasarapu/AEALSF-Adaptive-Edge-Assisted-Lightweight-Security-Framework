from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    TaskRequirementProfile,
)
from edge.edge_monitor import EdgeNodeTelemetry


@dataclass(frozen=True)
class SecurityPolicyDecision:
    allowed_modes: List[str]
    mandatory_local_only: bool
    requires_edge_mutual_auth: bool
    requires_result_signature_verification: bool
    requires_computational_verification: bool
    requires_onchain_hash_commit: bool
    verification_strategy: str
    policy_rationale: str
    rejected_modes_with_reasons: Dict[str, str] = field(default_factory=dict)


class SecurityPolicyManager:

    SECRET_DEPENDENT_TASKS = {
        "PRIVATE_KEY_DECRYPTION",
        "WALLET_KEY_GENERATION",
        "NIZK_WITNESS_SIGNING",
        "EC_ELGAMAL_RANDOMNESS_GEN",
    }

    MAX_EDGE_CPU_PERCENT = 92.0
    MAX_EDGE_MEMORY_PERCENT = 92.0
    MAX_EDGE_QUEUE_DEPTH = 32

    def evaluate_policy(
        self,
        task: TaskRequirementProfile,
        best_edge_node: Optional[EdgeNodeTelemetry],
        snapshot: Optional[DeviceResourceSnapshot] = None,
    ) -> SecurityPolicyDecision:
        rejected: Dict[str, str] = {}

        if (
            task.requires_private_key_access
            or task.task_type in self.SECRET_DEPENDENT_TASKS
            or task.data_sensitivity == "SECRET_LOCAL_ONLY"
        ):
            reason = (
                "Hard Constraint 1/3 (Mandatory Local Security Boundary): Task accesses private key "
                "material (s or d) or SECRET_LOCAL_ONLY data."
            )
            rejected["HYBRID_SECURITY_MODE"] = reason
            rejected["EDGE_ASSISTED_SECURITY_MODE"] = reason
            return SecurityPolicyDecision(
                allowed_modes=["LOCAL_SECURITY_MODE"],
                mandatory_local_only=True,
                requires_edge_mutual_auth=False,
                requires_result_signature_verification=False,
                requires_computational_verification=False,
                requires_onchain_hash_commit=True,
                verification_strategy="NONE_LOCAL",
                policy_rationale=reason,
                rejected_modes_with_reasons=rejected,
            )

        if task.data_sensitivity in (
            "CONFIDENTIAL_NO_EDGE_COMPRESSION",
            "CONFIDENTIAL_RAW_PLAINTEXT",
        ):
            if task.task_type == "DATA_COMPRESSION":
                reason = (
                    f"Hard Constraint 2 (Data Sensitivity): Plaintext task '{task.task_type}' with "
                    f"sensitivity '{task.data_sensitivity}' cannot be offloaded unencrypted."
                )
                rejected["HYBRID_SECURITY_MODE"] = reason
                rejected["EDGE_ASSISTED_SECURITY_MODE"] = reason
                return SecurityPolicyDecision(
                    allowed_modes=["LOCAL_SECURITY_MODE"],
                    mandatory_local_only=True,
                    requires_edge_mutual_auth=False,
                    requires_result_signature_verification=False,
                    requires_computational_verification=False,
                    requires_onchain_hash_commit=True,
                    verification_strategy="NONE_LOCAL",
                    policy_rationale=reason,
                    rejected_modes_with_reasons=rejected,
                )
            else:
                rejected["EDGE_ASSISTED_SECURITY_MODE"] = (
                    f"Hard Constraint 2 (Data Sensitivity): '{task.data_sensitivity}' forbids offloading "
                    "unencrypted stream compression in EDGE_ASSISTED_SECURITY_MODE."
                )

        if best_edge_node is None or not best_edge_node.online:
            reason = "Hard Constraint 6 (Edge Capacity): No online authenticated edge node available."
            rejected["HYBRID_SECURITY_MODE"] = reason
            rejected["EDGE_ASSISTED_SECURITY_MODE"] = reason
            return SecurityPolicyDecision(
                allowed_modes=["LOCAL_SECURITY_MODE"],
                mandatory_local_only=True,
                requires_edge_mutual_auth=False,
                requires_result_signature_verification=False,
                requires_computational_verification=False,
                requires_onchain_hash_commit=True,
                verification_strategy="NONE_LOCAL",
                policy_rationale=reason,
                rejected_modes_with_reasons=rejected,
            )

        if (
            best_edge_node.cpu_utilization_percent >= self.MAX_EDGE_CPU_PERCENT
            or best_edge_node.memory_utilization_percent >= self.MAX_EDGE_MEMORY_PERCENT
            or best_edge_node.active_tasks >= self.MAX_EDGE_QUEUE_DEPTH
        ):
            reason = (
                f"Hard Constraint 6 (Edge Overload): Edge node {best_edge_node.edge_node_id} exceeded capacity "
                f"(CPU={best_edge_node.cpu_utilization_percent:.1f}%, RAM={best_edge_node.memory_utilization_percent:.1f}%, "
                f"queue={best_edge_node.active_tasks})."
            )
            rejected["HYBRID_SECURITY_MODE"] = reason
            rejected["EDGE_ASSISTED_SECURITY_MODE"] = reason
            return SecurityPolicyDecision(
                allowed_modes=["LOCAL_SECURITY_MODE"],
                mandatory_local_only=True,
                requires_edge_mutual_auth=False,
                requires_result_signature_verification=False,
                requires_computational_verification=False,
                requires_onchain_hash_commit=True,
                verification_strategy="NONE_LOCAL",
                policy_rationale=reason,
                rejected_modes_with_reasons=rejected,
            )

        if (
            snapshot is not None
            and snapshot.network_latency_ms > task.latency_deadline_ms * 1.65
        ):
            if snapshot.available_ram_kb > 220.0 and snapshot.battery_percent > 8.0:
                reason = (
                    f"Hard Constraint 4 (Task Deadline): Network RTT ({snapshot.network_latency_ms:.1f} ms) "
                    f"exceeds 1.65x task deadline ({task.latency_deadline_ms:.1f} ms)."
                )
                rejected["HYBRID_SECURITY_MODE"] = reason
                rejected["EDGE_ASSISTED_SECURITY_MODE"] = reason
                return SecurityPolicyDecision(
                    allowed_modes=["LOCAL_SECURITY_MODE"],
                    mandatory_local_only=True,
                    requires_edge_mutual_auth=False,
                    requires_result_signature_verification=False,
                    requires_computational_verification=False,
                    requires_onchain_hash_commit=True,
                    verification_strategy="NONE_LOCAL",
                    policy_rationale=reason,
                    rejected_modes_with_reasons=rejected,
                )

        allowed = [
            m
            for m in (
                "LOCAL_SECURITY_MODE",
                "HYBRID_SECURITY_MODE",
                "EDGE_ASSISTED_SECURITY_MODE",
            )
            if m not in rejected
        ]

        return SecurityPolicyDecision(
            allowed_modes=allowed,
            mandatory_local_only=(allowed == ["LOCAL_SECURITY_MODE"]),
            requires_edge_mutual_auth=True,
            requires_result_signature_verification=True,
            requires_computational_verification=True,
            requires_onchain_hash_commit=True,
            verification_strategy=task.verification_strategy,
            policy_rationale=(
                "Task passed hard security, sensitivity, deadline, battery, and edge-capacity checks."
            ),
            rejected_modes_with_reasons=rejected,
        )
