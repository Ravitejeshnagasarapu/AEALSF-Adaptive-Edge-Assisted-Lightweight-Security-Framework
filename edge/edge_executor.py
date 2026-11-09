from __future__ import annotations
import json
import secrets
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cryptography.homomorphic_encryption import (
    ECElGamalCiphertext,
    ECElGamalHomomorphicEngine,
    is_on_curve,
)
from cryptography.key_manager import KeyManager
from cryptography.nizk_authentication import NIZKAuthenticator, NIZKProof
from cryptography.verification import CryptographicVerifier


@dataclass(frozen=True)
class EdgeDelegatedTask:
    task_id: str
    device_id: str
    task_type: str
    execution_mode: str
    input_payload_hash: str
    nonce: str
    timestamp: float
    device_signature: str
    homomorphic_ciphertexts: List[ECElGamalCiphertext] = field(default_factory=list)
    public_scalars: List[int] = field(default_factory=list)
    raw_data_bytes: bytes = b""
    nizk_proofs_batch: List[NIZKProof] = field(default_factory=list)
    data_sensitivity: str = "CONFIDENTIAL_HE_ONLY"
    extra_metadata: Dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class EdgeExecutionReceipt:
    receipt_id: str
    task_id: str
    device_id: str
    edge_node_id: str
    task_type: str
    input_payload_hash: str
    result_payload_hash: str
    result_bytes: bytes
    aggregated_ciphertext: Optional[ECElGamalCiphertext]
    partial_checkpoint_c1_hex: Optional[str]
    processing_time_ms: float
    nonce: str
    timestamp: float
    edge_signature: str
    compressed_stream_bytes: bytes = b""

    def compute_canonical_bytes(self) -> bytes:
        meta = {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "device_id": self.device_id,
            "edge_node_id": self.edge_node_id,
            "task_type": self.task_type,
            "input_payload_hash": self.input_payload_hash,
            "result_payload_hash": self.result_payload_hash,
            "partial_checkpoint_c1_hex": self.partial_checkpoint_c1_hex,
            "nonce": self.nonce,
            "timestamp": round(self.timestamp, 6),
        }
        return json.dumps(meta, sort_keys=True).encode("utf-8")


class EdgeExecutor:

    GLOBAL_EXECUTOR_INVOCATIONS: int = 0

    @classmethod
    def get_audit_counters(cls) -> dict:
        return {"executor_invocation_count": cls.GLOBAL_EXECUTOR_INVOCATIONS}

    FORBIDDEN_SECRET_KEYS = {
        "private_key_s",
        "private_key_d",
        "_signing_secret",
        "secret_key",
        "encryption_random_r",
    }

    def __init__(
        self,
        edge_node_id: str,
        key_manager: KeyManager,
        he_engine: ECElGamalHomomorphicEngine,
        nizk_auth: NIZKAuthenticator,
    ) -> None:
        self.edge_node_id = edge_node_id
        self.key_manager = key_manager
        self.he_engine = he_engine
        self.nizk_auth = nizk_auth
        self.executor_invocation_count: int = 0

    def execute_delegated_task(self, task: EdgeDelegatedTask) -> EdgeExecutionReceipt:
        self.executor_invocation_count += 1
        EdgeExecutor.GLOBAL_EXECUTOR_INVOCATIONS += 1
        t0 = time.perf_counter_ns()

        if any(k in self.FORBIDDEN_SECRET_KEYS for k in task.extra_metadata.keys()):
            raise PermissionError(
                "CRITICAL SECURITY VIOLATION: Secret key or randomness material detected in edge payload!"
            )

        req_msg = (
            f"{task.task_id}|{task.device_id}|{task.task_type}|"
            f"{task.input_payload_hash}|{task.nonce}|{task.timestamp:.6f}"
        ).encode("utf-8")
        if not self.key_manager.verify_device_signature(
            task.device_id, req_msg, task.device_signature
        ):
            raise PermissionError(
                f"EdgeExecutor: Invalid device signature on delegated task {task.task_id}."
            )

        aggregated_ct: Optional[ECElGamalCiphertext] = None
        partial_c1_hex: Optional[str] = None
        compressed_stream: bytes = b""

        if task.task_type == "HOMOMORPHIC_AGGREGATION":
            if not task.homomorphic_ciphertexts:
                raise ValueError(
                    "HOMOMORPHIC_AGGREGATION requires non-empty ciphertexts."
                )
            for ct in task.homomorphic_ciphertexts:
                if (
                    ct.c1.is_infinity
                    or ct.c2.is_infinity
                    or not (is_on_curve(ct.c1) and is_on_curve(ct.c2))
                ):
                    raise ValueError(
                        "Invalid or off-curve EC-ElGamal ciphertext point in input."
                    )

            if task.public_scalars and len(task.public_scalars) == len(
                task.homomorphic_ciphertexts
            ):
                weighted = [
                    self.he_engine.homomorphic_scalar_mul(k, ct)
                    for k, ct in zip(task.public_scalars, task.homomorphic_ciphertexts)
                ]
                aggregated_ct = self.he_engine.homomorphic_sum(weighted)
            else:
                aggregated_ct = self.he_engine.homomorphic_sum(
                    task.homomorphic_ciphertexts
                )

            partial_c1_hex = (
                hex(aggregated_ct.c1.x) if not aggregated_ct.c1.is_infinity else "0x0"
            )
            result_bytes = json.dumps(aggregated_ct.to_dict(), sort_keys=True).encode(
                "utf-8"
            )

            if task.raw_data_bytes and task.data_sensitivity in (
                "PUBLIC_COMPRESSIBLE",
                "NON_SENSITIVE_TELEMETRY",
            ):
                compressed_stream = zlib.compress(task.raw_data_bytes, level=6)

        elif task.task_type == "DATA_COMPRESSION":
            if task.data_sensitivity not in (
                "PUBLIC_COMPRESSIBLE",
                "NON_SENSITIVE_TELEMETRY",
            ):
                raise PermissionError(
                    f"Data sensitivity policy '{task.data_sensitivity}' forbids plaintext edge compression."
                )
            if not task.raw_data_bytes:
                raise ValueError("DATA_COMPRESSION requires non-empty raw_data_bytes.")
            actual_in_hash = CryptographicVerifier.sha256_hex(task.raw_data_bytes)
            if actual_in_hash != task.input_payload_hash:
                raise ValueError(
                    "Input payload hash mismatch prior to edge compression."
                )
            result_bytes = zlib.compress(task.raw_data_bytes, level=6)
            compressed_stream = result_bytes

        elif task.task_type == "BATCH_NIZK_VERIFICATION":
            all_ok, per_proof = self.nizk_auth.batch_verify_proofs(
                task.nizk_proofs_batch
            )
            result_bytes = json.dumps(
                {"all_verified": all_ok, "results": per_proof}, sort_keys=True
            ).encode("utf-8")

        else:
            raise ValueError(
                f"Unsupported or non-delegable task type: {task.task_type}"
            )

        result_hash = CryptographicVerifier.sha256_hex(result_bytes)
        proc_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        now = time.time()
        receipt_id = "rcpt-" + secrets.token_hex(8)

        unsigned_receipt = EdgeExecutionReceipt(
            receipt_id=receipt_id,
            task_id=task.task_id,
            device_id=task.device_id,
            edge_node_id=self.edge_node_id,
            task_type=task.task_type,
            input_payload_hash=task.input_payload_hash,
            result_payload_hash=result_hash,
            result_bytes=result_bytes,
            aggregated_ciphertext=aggregated_ct,
            partial_checkpoint_c1_hex=partial_c1_hex,
            processing_time_ms=proc_ms,
            nonce=task.nonce,
            timestamp=now,
            edge_signature="",
            compressed_stream_bytes=compressed_stream,
        )
        sig = self.key_manager.sign_as_edge_node(
            self.edge_node_id, unsigned_receipt.compute_canonical_bytes()
        )
        return EdgeExecutionReceipt(
            receipt_id=receipt_id,
            task_id=task.task_id,
            device_id=task.device_id,
            edge_node_id=self.edge_node_id,
            task_type=task.task_type,
            input_payload_hash=task.input_payload_hash,
            result_payload_hash=result_hash,
            result_bytes=result_bytes,
            aggregated_ciphertext=aggregated_ct,
            partial_checkpoint_c1_hex=partial_c1_hex,
            processing_time_ms=proc_ms,
            nonce=task.nonce,
            timestamp=now,
            edge_signature=sig,
            compressed_stream_bytes=compressed_stream,
        )
