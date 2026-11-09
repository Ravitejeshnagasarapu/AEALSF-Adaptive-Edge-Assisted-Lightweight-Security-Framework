from __future__ import annotations
import time
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.homomorphic_encryption import (
    INFINITY_POINT,
    ec_add,
    ec_scalar_mul,
    is_on_curve,
)
from cryptography.key_manager import KeyManager
from cryptography.verification import CryptographicVerifier, ReplayProtectionRegistry
from edge.edge_executor import EdgeDelegatedTask, EdgeExecutionReceipt


@dataclass(frozen=True)
class VerificationMetrics:
    verified: bool
    strategy_used: str
    verification_time_ms: float
    verification_bytes_overhead: int
    reason: str


class EdgeResultVerifier:

    GLOBAL_VERIFIER_INVOCATIONS: int = 0
    GLOBAL_VERIFIER_ACCEPTS: int = 0
    GLOBAL_VERIFIER_REJECTS: int = 0

    @classmethod
    def get_audit_counters(cls) -> dict:
        return {
            "verifier_invocation_count": cls.GLOBAL_VERIFIER_INVOCATIONS,
            "verifier_accept_count": cls.GLOBAL_VERIFIER_ACCEPTS,
            "verifier_reject_count": cls.GLOBAL_VERIFIER_REJECTS,
        }

    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager
        self.replay_registry = ReplayProtectionRegistry(ttl_seconds=120.0)
        self.verifier_invocation_count: int = 0
        self.verifier_accept_count: int = 0
        self.verifier_reject_count: int = 0

    def verify_receipt_with_metrics(
        self,
        task: EdgeDelegatedTask,
        receipt: EdgeExecutionReceipt,
        strategy: str = "ALGEBRAIC_OR_DECOMPRESS_CHECK",
        secondary_receipt: Optional[EdgeExecutionReceipt] = None,
        expected_edge_node_id: Optional[str] = None,
    ) -> VerificationMetrics:
        self.verifier_invocation_count += 1
        EdgeResultVerifier.GLOBAL_VERIFIER_INVOCATIONS += 1
        t0 = time.perf_counter_ns()
        extra_bytes = len(receipt.edge_signature) + 128

        def _reject(msg: str) -> VerificationMetrics:
            self.verifier_reject_count += 1
            EdgeResultVerifier.GLOBAL_VERIFIER_REJECTS += 1
            return VerificationMetrics(
                False, strategy, (time.perf_counter_ns() - t0) / 1e6, extra_bytes, msg
            )

        if receipt.task_id != task.task_id:
            return _reject(
                f"Wrong task identity: expected {task.task_id}, got {receipt.task_id}."
            )
        if receipt.device_id != task.device_id:
            return _reject(
                f"Wrong device identity: expected {task.device_id}, got {receipt.device_id}."
            )
        if (
            expected_edge_node_id is not None
            and receipt.edge_node_id != expected_edge_node_id
        ):
            return _reject(
                f"Wrong edge identity: expected {expected_edge_node_id}, got {receipt.edge_node_id}."
            )
        if receipt.nonce != task.nonce:
            return _reject("Receipt nonce does not match delegated task nonce.")
        if receipt.input_payload_hash != task.input_payload_hash:
            return _reject(
                "Receipt input_payload_hash does not match original task input."
            )

        computed_result_hash = CryptographicVerifier.sha256_hex(receipt.result_bytes)
        if computed_result_hash != receipt.result_payload_hash:
            return _reject(
                "Tampered edge result detected: result_bytes SHA-256 mismatch!"
            )

        if not self.key_manager.verify_edge_node_signature(
            receipt.edge_node_id,
            receipt.compute_canonical_bytes(),
            receipt.edge_signature,
        ):
            return _reject(
                "Invalid or forged edge node cryptographic signature on receipt!"
            )

        fresh, msg = self.replay_registry.validate_and_record(
            receipt.edge_node_id,
            f"{receipt.receipt_id}:{receipt.nonce}",
            receipt.timestamp,
        )
        if not fresh:
            return _reject(f"Replay detected on edge receipt: {msg}")

        if task.task_type == "HOMOMORPHIC_AGGREGATION":
            agg = receipt.aggregated_ciphertext
            if agg is None:
                return _reject(
                    "Missing aggregated ciphertext in HOMOMORPHIC_AGGREGATION receipt."
                )

            if (
                agg.c1.is_infinity
                or agg.c2.is_infinity
                or not is_on_curve(agg.c1)
                or not is_on_curve(agg.c2)
            ):
                return _reject(
                    "Malformed curve points: aggregated C1 or C2 is infinity or not on secp256k1."
                )

            expected_ops = (
                sum(
                    k * c.operations_count
                    for k, c in zip(task.public_scalars, task.homomorphic_ciphertexts)
                )
                if (
                    task.public_scalars
                    and len(task.public_scalars) == len(task.homomorphic_ciphertexts)
                )
                else sum(c.operations_count for c in task.homomorphic_ciphertexts)
            )
            if agg.operations_count != expected_ops:
                return _reject(
                    f"Modified operation count: expected {expected_ops}, got {agg.operations_count}."
                )

            if strategy == "REDUNDANT_DUAL_EDGE" and secondary_receipt is not None:
                extra_bytes += len(secondary_receipt.result_bytes) + 128
                if secondary_receipt.edge_node_id == receipt.edge_node_id:
                    return _reject(
                        "Redundant verification requires two distinct edge nodes."
                    )
                if not self.key_manager.verify_edge_node_signature(
                    secondary_receipt.edge_node_id,
                    secondary_receipt.compute_canonical_bytes(),
                    secondary_receipt.edge_signature,
                ):
                    return _reject(
                        "Secondary edge node signature invalid during redundant verification."
                    )
                if (
                    secondary_receipt.result_payload_hash != receipt.result_payload_hash
                    or secondary_receipt.aggregated_ciphertext
                    != receipt.aggregated_ciphertext
                ):
                    return _reject(
                        "Byzantine computational discrepancy detected between primary and secondary edge nodes!"
                    )

            expected_c1 = INFINITY_POINT
            expected_c2 = INFINITY_POINT
            if task.public_scalars and len(task.public_scalars) == len(
                task.homomorphic_ciphertexts
            ):
                for k, ct in zip(task.public_scalars, task.homomorphic_ciphertexts):
                    expected_c1 = ec_add(expected_c1, ec_scalar_mul(k, ct.c1))
                    expected_c2 = ec_add(expected_c2, ec_scalar_mul(k, ct.c2))
            else:
                for ct in task.homomorphic_ciphertexts:
                    expected_c1 = ec_add(expected_c1, ct.c1)
                    expected_c2 = ec_add(expected_c2, ct.c2)

            if agg.c1 != expected_c1:
                return _reject(
                    "Algebraic C1 verification failed: edge returned invalid or forged C1 component!"
                )
            if agg.c2 != expected_c2:
                return _reject(
                    "Algebraic C2 verification failed: edge returned invalid or forged C2 component!"
                )

            expected_checkpoint_hex = (
                hex(expected_c1.x) if not expected_c1.is_infinity else "0x0"
            )
            if (
                receipt.partial_checkpoint_c1_hex is not None
                and receipt.partial_checkpoint_c1_hex != expected_checkpoint_hex
            ):
                return _reject(
                    "Altered commitment checkpoint: partial_checkpoint_c1_hex mismatch!"
                )

            if receipt.compressed_stream_bytes and task.raw_data_bytes:
                try:
                    decomp = zlib.decompress(receipt.compressed_stream_bytes)
                except Exception as exc:
                    return _reject(f"Edge returned corrupted compressed stream: {exc}")
                if decomp != task.raw_data_bytes:
                    return _reject(
                        "Decompressed stream from edge does not match original telemetry payload!"
                    )

        elif task.task_type == "DATA_COMPRESSION":
            try:
                decompressed = zlib.decompress(receipt.result_bytes)
            except Exception as exc:
                return _reject(f"Edge returned corrupted compressed stream: {exc}")
            if (
                CryptographicVerifier.sha256_hex(decompressed)
                != task.input_payload_hash
            ):
                return _reject(
                    "Computational correctness failure: decompressed stream does not match original input!"
                )

        ver_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        self.verifier_accept_count += 1
        EdgeResultVerifier.GLOBAL_VERIFIER_ACCEPTS += 1
        return VerificationMetrics(
            True,
            strategy,
            ver_ms,
            extra_bytes,
            "Edge computation result cryptographically and computationally verified (full C1 & C2).",
        )

    def verify_receipt(
        self,
        task: EdgeDelegatedTask,
        receipt: EdgeExecutionReceipt,
        expected_edge_node_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        m = self.verify_receipt_with_metrics(
            task=task, receipt=receipt, expected_edge_node_id=expected_edge_node_id
        )
        return m.verified, m.reason
