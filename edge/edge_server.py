from __future__ import annotations
from typing import Dict, Optional, Tuple

from blockchain.blockchain_client import BlockchainClient
from config.edge_config import EdgeConfig
from cryptography.homomorphic_encryption import (
    BASE_POINT_G,
    ECElGamalCiphertext,
    ECElGamalHomomorphicEngine,
    ec_add,
)
from cryptography.key_manager import KeyManager
from cryptography.nizk_authentication import NIZKAuthenticator
from edge.edge_authentication import EdgeMutualAuthenticator
from edge.edge_executor import EdgeDelegatedTask, EdgeExecutionReceipt, EdgeExecutor
from edge.edge_monitor import EdgeMonitor
from edge.failover_manager import EdgeFailoverManager
from edge.result_verifier import EdgeResultVerifier, VerificationMetrics


class EdgeServer:

    def __init__(
        self,
        edge_node_id: str,
        key_manager: KeyManager,
        he_engine: ECElGamalHomomorphicEngine,
        nizk_auth: NIZKAuthenticator,
    ) -> None:
        self.edge_node_id = edge_node_id
        self.public_token = key_manager.register_edge_node(edge_node_id)
        self.executor = EdgeExecutor(edge_node_id, key_manager, he_engine, nizk_auth)


class EdgeClusterManager:

    def __init__(
        self,
        key_manager: KeyManager,
        blockchain_client: BlockchainClient,
        he_engine: ECElGamalHomomorphicEngine,
        nizk_auth: NIZKAuthenticator,
        config: Optional[EdgeConfig] = None,
    ) -> None:
        self.config = config or EdgeConfig()
        self.key_manager = key_manager
        self.blockchain_client = blockchain_client
        self.monitor = EdgeMonitor(
            self.config.edge_node_ids, self.config.heartbeat_timeout_seconds
        )
        self.failover_manager = EdgeFailoverManager(self.monitor, self.config)
        self.authenticator = EdgeMutualAuthenticator(key_manager, blockchain_client)
        self.result_verifier = EdgeResultVerifier(key_manager)
        self.servers: Dict[str, EdgeServer] = {}

        admin_wallet = self.key_manager.get_device_wallet("system-governance-admin")
        for nid in self.config.edge_node_ids:
            srv = EdgeServer(nid, key_manager, he_engine, nizk_auth)
            self.servers[nid] = srv
            self.blockchain_client.contracts.invoke(
                contract_name="SecurityManager",
                method_name="authorizeEdgeNode",
                caller_device_id="system-governance-admin",
                caller_address=admin_wallet.blockchain_address,
                args={"edgeNodeId": nid, "publicTokenHash": srv.public_token},
            )
            self.blockchain_client.dvrc.register_participant(
                nid, role="EDGE_NODE", initial_score=85.0
            )

    def dispatch_with_failover(
        self,
        task: EdgeDelegatedTask,
        preferred_edge_id: Optional[str] = None,
        simulate_tampering_on_node: Optional[str] = None,
        simulate_computational_lie_on_node: Optional[str] = None,
        verification_strategy: str = "ALGEBRAIC_OR_DECOMPRESS_CHECK",
    ) -> Tuple[bool, Optional[EdgeExecutionReceipt], str]:
        ok, receipt, _, msg = self.dispatch_with_verification_metrics(
            task=task,
            preferred_edge_id=preferred_edge_id,
            simulate_tampering_on_node=simulate_tampering_on_node,
            simulate_computational_lie_on_node=simulate_computational_lie_on_node,
            verification_strategy=verification_strategy,
        )
        return ok, receipt, msg

    def dispatch_with_verification_metrics(
        self,
        task: EdgeDelegatedTask,
        preferred_edge_id: Optional[str] = None,
        simulate_tampering_on_node: Optional[str] = None,
        simulate_computational_lie_on_node: Optional[str] = None,
        verification_strategy: str = "ALGEBRAIC_OR_DECOMPRESS_CHECK",
    ) -> Tuple[
        bool, Optional[EdgeExecutionReceipt], Optional[VerificationMetrics], str
    ]:
        tried_nodes: set[str] = set()
        cumulative_ver_ms = 0.0
        cumulative_ver_bytes = 0

        while True:
            if preferred_edge_id and preferred_edge_id not in tried_nodes:
                if self.monitor.is_node_healthy(
                    preferred_edge_id, self.config.max_edge_cpu_load_percent
                ):
                    candidate_tel = self.monitor.nodes[preferred_edge_id]
                else:
                    tried_nodes.add(preferred_edge_id)
                    next_tel = self.failover_manager.select_best_edge_node(tried_nodes)
                    if next_tel is None:
                        self.failover_manager.record_failover(
                            preferred_edge_id,
                            "LOCAL_FALLBACK",
                            "Preferred edge node unhealthy and no backup edge available",
                            task.task_id,
                        )
                        return (
                            False,
                            None,
                            None,
                            "All edge nodes unavailable; trigger local fallback.",
                        )
                    self.failover_manager.record_failover(
                        preferred_edge_id,
                        next_tel.edge_node_id,
                        "Preferred edge node unhealthy or offline",
                        task.task_id,
                    )
                    candidate_tel = next_tel
            else:
                candidate_tel = self.failover_manager.select_best_edge_node(tried_nodes)
                if candidate_tel is None:
                    return (
                        False,
                        None,
                        None,
                        "No healthy edge node available; trigger local fallback.",
                    )

            edge_id = candidate_tel.edge_node_id
            tried_nodes.add(edge_id)

            if not self.authenticator.has_valid_session(task.device_id, edge_id):
                ok_hs, _, hs_msg = self.authenticator.perform_mutual_handshake(
                    task.device_id, edge_id
                )
                if not ok_hs:
                    self.failover_manager.record_failover(
                        edge_id,
                        "NEXT_EDGE",
                        f"Handshake failed: {hs_msg}",
                        task.task_id,
                    )
                    continue

            self.monitor.record_task_start(edge_id)
            try:
                receipt = self.servers[edge_id].executor.execute_delegated_task(task)
                if simulate_tampering_on_node == edge_id:
                    receipt = EdgeExecutionReceipt(
                        receipt_id=receipt.receipt_id,
                        task_id=receipt.task_id,
                        device_id=receipt.device_id,
                        edge_node_id=receipt.edge_node_id,
                        task_type=receipt.task_type,
                        input_payload_hash=receipt.input_payload_hash,
                        result_payload_hash=receipt.result_payload_hash,
                        result_bytes=receipt.result_bytes + b"_TAMPERED",
                        aggregated_ciphertext=receipt.aggregated_ciphertext,
                        partial_checkpoint_c1_hex=receipt.partial_checkpoint_c1_hex,
                        processing_time_ms=receipt.processing_time_ms,
                        nonce=receipt.nonce,
                        timestamp=receipt.timestamp,
                        edge_signature=receipt.edge_signature,
                    )
                elif (
                    simulate_computational_lie_on_node == edge_id
                    and receipt.aggregated_ciphertext is not None
                ):
                    import json
                    from cryptography.verification import CryptographicVerifier

                    bad_ct = ECElGamalCiphertext(
                        c1=ec_add(receipt.aggregated_ciphertext.c1, BASE_POINT_G),
                        c2=ec_add(receipt.aggregated_ciphertext.c2, BASE_POINT_G),
                        operations_count=receipt.aggregated_ciphertext.operations_count,
                    )
                    bad_bytes = json.dumps(bad_ct.to_dict(), sort_keys=True).encode(
                        "utf-8"
                    )
                    bad_hash = CryptographicVerifier.sha256_hex(bad_bytes)
                    unsigned_bad = EdgeExecutionReceipt(
                        receipt_id=receipt.receipt_id,
                        task_id=receipt.task_id,
                        device_id=receipt.device_id,
                        edge_node_id=edge_id,
                        task_type=receipt.task_type,
                        input_payload_hash=receipt.input_payload_hash,
                        result_payload_hash=bad_hash,
                        result_bytes=bad_bytes,
                        aggregated_ciphertext=bad_ct,
                        partial_checkpoint_c1_hex=hex(bad_ct.c1.x),
                        processing_time_ms=receipt.processing_time_ms,
                        nonce=receipt.nonce,
                        timestamp=receipt.timestamp,
                        edge_signature="",
                    )
                    bad_sig = self.key_manager.sign_as_edge_node(
                        edge_id, unsigned_bad.compute_canonical_bytes()
                    )
                    receipt = EdgeExecutionReceipt(
                        **{**unsigned_bad.__dict__, "edge_signature": bad_sig}
                    )
            except Exception as exc:
                self.monitor.record_task_completion(edge_id, success=False)
                self.blockchain_client.dvrc.update_reputation(
                    edge_id, success=False, severity_multiplier=1.2
                )
                self.failover_manager.record_failover(
                    edge_id, "NEXT_EDGE", f"Execution error: {exc}", task.task_id
                )
                continue

            secondary_receipt: Optional[EdgeExecutionReceipt] = None
            if verification_strategy == "REDUNDANT_DUAL_EDGE":
                sec_tel = self.failover_manager.select_best_edge_node(tried_nodes)
                if sec_tel is not None:
                    sec_id = sec_tel.edge_node_id
                    if not self.authenticator.has_valid_session(task.device_id, sec_id):
                        self.authenticator.perform_mutual_handshake(
                            task.device_id, sec_id
                        )
                    secondary_receipt = self.servers[
                        sec_id
                    ].executor.execute_delegated_task(task)

            ver_metrics = self.result_verifier.verify_receipt_with_metrics(
                task=task,
                receipt=receipt,
                strategy=verification_strategy,
                secondary_receipt=secondary_receipt,
            )
            cumulative_ver_ms += ver_metrics.verification_time_ms
            cumulative_ver_bytes += ver_metrics.verification_bytes_overhead

            if not ver_metrics.verified:
                self.monitor.record_task_completion(edge_id, success=False)
                self.blockchain_client.dvrc.update_reputation(
                    edge_id, success=False, severity_multiplier=2.0
                )
                self.failover_manager.record_failover(
                    edge_id,
                    "NEXT_EDGE",
                    f"Result verification failed: {ver_metrics.reason}",
                    task.task_id,
                )
                continue

            self.monitor.record_task_completion(edge_id, success=True)
            self.blockchain_client.dvrc.update_reputation(
                edge_id, success=True, response_time_ms=receipt.processing_time_ms
            )
            final_ver_metrics = VerificationMetrics(
                verified=True,
                strategy_used=ver_metrics.strategy_used,
                verification_time_ms=cumulative_ver_ms,
                verification_bytes_overhead=cumulative_ver_bytes,
                reason=ver_metrics.reason,
            )
            return True, receipt, final_ver_metrics, f"Verified execution on {edge_id}"
