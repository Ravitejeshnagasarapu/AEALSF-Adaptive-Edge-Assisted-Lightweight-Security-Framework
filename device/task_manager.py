from __future__ import annotations
import json
import secrets
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from adaptive_engine.decision_engine import (
    AdaptiveDecisionEngine,
    DecisionRecord,
    ExecutionMode,
)
from adaptive_engine.resource_analyzer import TaskRequirementProfile
from blockchain.blockchain_client import BlockchainClient
from config.simulation_config import SimulatedResourceModel, VIRTUAL_IOT_PROFILES
from cryptography.nizk_authentication import CircomR1CSConstraintVerifier
from cryptography.verification import CryptographicVerifier
from device.device_identity import DeviceIdentityWallet
from device.local_security import DeviceLocalSecurityEngine
from device.resource_monitor import DeviceResourceMonitor
from edge.edge_executor import EdgeDelegatedTask
from edge.edge_server import EdgeClusterManager
from monitoring.energy_estimator import EnergyEstimator
from monitoring.performance_monitor import PerformanceMonitor, TaskPerformanceSample


@dataclass(frozen=True)
class TaskExecutionResult:
    task_id: str
    device_id: str
    selected_mode: str
    executed_on_node: str
    decrypted_aggregate_value: Optional[int]
    compressed_size_bytes: Optional[int]
    onchain_result_hash: str
    offchain_integrity_verified: bool
    used_local_fallback: bool
    performance_sample: TaskPerformanceSample
    decision_record: Optional[DecisionRecord]


class DeviceTaskManager:

    def __init__(
        self,
        wallet: DeviceIdentityWallet,
        resource_monitor: DeviceResourceMonitor,
        local_security: DeviceLocalSecurityEngine,
        blockchain_client: BlockchainClient,
        edge_cluster: EdgeClusterManager,
        decision_engine: AdaptiveDecisionEngine,
        perf_monitor: PerformanceMonitor,
        energy_estimator: EnergyEstimator,
    ) -> None:
        self.wallet = wallet
        self.resource_monitor = resource_monitor
        self.local_security = local_security
        self.blockchain_client = blockchain_client
        self.edge_cluster = edge_cluster
        self.decision_engine = decision_engine
        self.perf_monitor = perf_monitor
        self.energy_estimator = energy_estimator

    def authenticate_device_on_chain(
        self,
        allow_session_reuse: bool = False,
        nizk_scheme: str = "EC_SCHNORR",
    ) -> Tuple[bool, float, float, float, int, str]:
        t0_ns = time.perf_counter_ns()

        if allow_session_reuse:
            t_p0 = time.perf_counter_ns()
            reusable, tok = self.local_security.can_reuse_authenticated_session()
            prove_ms = (time.perf_counter_ns() - t_p0) / 1e6
            if reusable and tok is not None:
                t_v0 = time.perf_counter_ns()
                check = self.blockchain_client.contracts.invoke(
                    contract_name="SecurityManager",
                    method_name="isDeviceAuthenticated",
                    caller_device_id=self.wallet.device_id,
                    caller_address=self.wallet.wallet_address,
                    args={"deviceId": self.wallet.device_id},
                )
                verify_ms = (time.perf_counter_ns() - t_v0) / 1e6
                if check.return_data.get("authenticated", False):
                    self.resource_monitor.has_active_auth_session = True
                    total_ms = (time.perf_counter_ns() - t0_ns) / 1e6
                    return (
                        True,
                        total_ms,
                        prove_ms,
                        verify_ms,
                        128,
                        "Reused verified NIZK session context.",
                    )

        if nizk_scheme == "EC_SCHNORR":
            ticket = self.local_security.nizk_auth.ec_schnorr.issue_verifier_challenge(
                device_id=self.wallet.device_id,
                verifier_id="blockchain-verifier",
            )
            t_prove_start = time.perf_counter_ns()
            proof = self.local_security.generate_ec_schnorr_auth_proof(
                verifier_id="blockchain-verifier",
                verifier_nonce=ticket.nonce,
                context_bind="BLOCKCHAIN_AUTH",
            )
            prove_ms = (time.perf_counter_ns() - t_prove_start) / 1e6

            t_ver_start = time.perf_counter_ns()
            ver_ok, ver_msg = self.local_security.nizk_auth.ec_schnorr.verify_proof(
                proof,
                expected_pk=(
                    self.wallet.credentials.ec_schnorr_keypair.public_key_pk
                    if self.wallet.credentials.ec_schnorr_keypair
                    else None
                ),
                expected_device_id=self.wallet.device_id,
                expected_verifier_id="blockchain-verifier",
                require_verifier_issued_nonce=True,
            )
            verify_ms = (time.perf_counter_ns() - t_ver_start) / 1e6
            if not ver_ok:
                total_ms = (time.perf_counter_ns() - t0_ns) / 1e6
                return False, total_ms, prove_ms, verify_ms, 0, ver_msg

            proof_bytes = json.dumps(proof.to_dict(), sort_keys=True).encode("utf-8")
            proof_hash = CryptographicVerifier.sha256_hex(proof_bytes)
            nonce_hash = CryptographicVerifier.sha256_hex(
                f"{self.wallet.device_id}:{proof.verifier_nonce}"
            )
            r1cs_ok = True
        else:
            ticket = self.local_security.nizk_auth.issue_verifier_challenge(
                device_id=self.wallet.device_id,
                verifier_id="blockchain-verifier",
            )
            t_prove_start = time.perf_counter_ns()
            dlp_proof = self.local_security.generate_nizk_auth_proof(
                context_bind="BLOCKCHAIN_AUTH",
                verifier_id="blockchain-verifier",
                verifier_nonce=ticket.nonce,
            )
            prove_ms = (time.perf_counter_ns() - t_prove_start) / 1e6

            t_ver_start = time.perf_counter_ns()
            ver_ok, ver_msg = self.local_security.nizk_auth.verify_proof(
                dlp_proof,
                expected_pk=self.wallet.credentials.nizk_keypair.public_key_pk,
                expected_device_id=self.wallet.device_id,
                expected_verifier_id="blockchain-verifier",
                require_verifier_issued_nonce=True,
            )
            if not ver_ok:
                verify_ms = (time.perf_counter_ns() - t_ver_start) / 1e6
                total_ms = (time.perf_counter_ns() - t0_ns) / 1e6
                return False, total_ms, prove_ms, verify_ms, 0, ver_msg

            r1cs = CircomR1CSConstraintVerifier.evaluate_r1cs_witness(
                pk=dlp_proof.public_key_pk,
                r_commit=dlp_proof.commitment_r,
                z_resp=dlp_proof.response_z,
                c_chal=dlp_proof.challenge_c,
                p=self.local_security.nizk_auth.p,
                g=self.local_security.nizk_auth.g,
                h_expected=dlp_proof.challenge_c,
                r_prime=dlp_proof.commitment_r,
            )
            verify_ms = (time.perf_counter_ns() - t_ver_start) / 1e6
            proof_bytes = json.dumps(dlp_proof.to_dict(), sort_keys=True).encode(
                "utf-8"
            )
            proof_hash = CryptographicVerifier.sha256_hex(proof_bytes)
            nonce_hash = CryptographicVerifier.sha256_hex(
                f"{self.wallet.device_id}:{dlp_proof.nonce}"
            )
            r1cs_ok = bool(r1cs["verified"])

        tx = self.blockchain_client.tx_manager.create_signed_transaction(
            sender_device_id=self.wallet.device_id,
            contract_name="SecurityManager",
            method_name="recordNIZKAuthentication",
            payload={
                "deviceId": self.wallet.device_id,
                "proofHash": proof_hash,
                "nonceHash": nonce_hash,
                "ttlSeconds": 300.0,
                "r1csVerified": r1cs_ok,
            },
            tx_type="SET",
        )
        ok, _, _, msg = self.blockchain_client.submit_and_execute_transaction(
            tx, auto_commit_block=True
        )
        if ok:
            self.wallet.active_session_token = (
                self.local_security.nizk_auth.issue_session_token(
                    self.wallet.device_id,
                    self.wallet.credentials.nizk_keypair.public_key_pk,
                )
            )
            self.resource_monitor.has_active_auth_session = True
        total_ms = (time.perf_counter_ns() - t0_ns) / 1e6
        return (
            ok,
            total_ms,
            prove_ms,
            verify_ms,
            len(proof_bytes) + len(tx.compute_canonical_bytes()),
            msg,
        )

    def execute_telemetry_and_compression_task(
        self,
        telemetry_values: List[int],
        raw_packet_bytes: bytes,
        adaptive_enabled: bool = True,
        scheduling_policy: Optional[str] = None,
        priority: str = "NORMAL",
        public_scalars: Optional[List[int]] = None,
        data_sensitivity: str = "PUBLIC_COMPRESSIBLE",
        verification_strategy: str = "ALGEBRAIC_OR_DECOMPRESS_CHECK",
        simulate_edge_tampering_node: Optional[str] = None,
        simulate_computational_lie_node: Optional[str] = None,
        allow_session_reuse: Optional[bool] = None,
        nizk_scheme: str = "EC_SCHNORR",
    ) -> TaskExecutionResult:
        t_total_start_ns = time.perf_counter_ns()
        cpu_start_ms = PerformanceMonitor.get_process_cpu_time_ms()
        task_id = "task-" + secrets.token_hex(8)

        if scheduling_policy is None:
            policy_label = "AEALSF" if adaptive_enabled else "ORIGINAL_BASELINE"
        else:
            policy_label = scheduling_policy

        use_reuse = False if allow_session_reuse is None else allow_session_reuse
        auth_ok, auth_ms, nizk_prove_ms, nizk_verify_ms, auth_bytes, auth_msg = (
            self.authenticate_device_on_chain(
                allow_session_reuse=use_reuse,
                nizk_scheme=nizk_scheme,
            )
        )
        if not auth_ok:
            raise PermissionError(f"Device authentication failed: {auth_msg}")

        snapshot = self.resource_monitor.capture_snapshot()
        scalars = public_scalars or [1] * len(telemetry_values)
        task_profile = TaskRequirementProfile(
            task_id=task_id,
            task_type="HOMOMORPHIC_AGGREGATION",
            payload_bytes=len(raw_packet_bytes),
            num_homomorphic_ops=len(telemetry_values),
            priority=priority,
            requires_private_key_access=False,
            data_sensitivity=data_sensitivity,
            verification_strategy=verification_strategy,
        )

        decision = self.decision_engine.select_execution_mode(
            snapshot=snapshot,
            task=task_profile,
            scheduling_policy=policy_label,
        )
        selected_mode = decision.selected_mode
        target_edge_id = decision.selected_edge_node_id

        t_enc_start_ns = time.perf_counter_ns()
        ciphertexts = self.local_security.encrypt_telemetry_homomorphic(
            telemetry_values, use_precomputed_pool=False
        )
        he_encrypt_ms = (time.perf_counter_ns() - t_enc_start_ns) / 1e6

        serialized_cts = json.dumps(
            [c.to_dict() for c in ciphertexts], sort_keys=True
        ).encode("utf-8")
        input_hash = CryptographicVerifier.sha256_hex(serialized_cts + raw_packet_bytes)

        used_fallback = False
        executed_node = self.wallet.device_id
        edge_cpu_time_ms = 0.0
        he_add_ms = 0.0
        he_scalar_mul_ms = 0.0
        edge_exec_ms = 0.0
        result_ver_ms = 0.0
        ver_extra_bytes = 0
        local_working_buffers_bytes = len(serialized_cts) + sum(
            sys.getsizeof(c) for c in ciphertexts
        )

        if selected_mode in (
            ExecutionMode.HYBRID_SECURITY_MODE,
            ExecutionMode.EDGE_ASSISTED_SECURITY_MODE,
        ):
            dev_cpu_before_edge_ms = max(
                0.0, PerformanceMonitor.get_process_cpu_time_ms() - cpu_start_ms
            )
            edge_cpu_start_ms = PerformanceMonitor.get_process_cpu_time_ms()
            nonce = secrets.token_hex(12)
            now_ts = time.time()
            req_msg = (
                f"{task_id}|{self.wallet.device_id}|HOMOMORPHIC_AGGREGATION|"
                f"{input_hash}|{nonce}|{now_ts:.6f}"
            ).encode("utf-8")
            dev_sig = self.wallet.credentials.sign_message(req_msg)

            delegated_task = EdgeDelegatedTask(
                task_id=task_id,
                device_id=self.wallet.device_id,
                task_type="HOMOMORPHIC_AGGREGATION",
                execution_mode=selected_mode.value,
                input_payload_hash=input_hash,
                nonce=nonce,
                timestamp=now_ts,
                device_signature=dev_sig,
                homomorphic_ciphertexts=ciphertexts,
                public_scalars=scalars,
                raw_data_bytes=(
                    raw_packet_bytes
                    if selected_mode == ExecutionMode.EDGE_ASSISTED_SECURITY_MODE
                    else b""
                ),
                data_sensitivity=data_sensitivity,
            )

            edge_ok, edge_receipt, ver_metrics, _ = (
                self.edge_cluster.dispatch_with_verification_metrics(
                    delegated_task,
                    preferred_edge_id=target_edge_id,
                    simulate_tampering_on_node=simulate_edge_tampering_node,
                    simulate_computational_lie_on_node=simulate_computational_lie_node,
                    verification_strategy=verification_strategy,
                )
            )
            if (
                edge_ok
                and edge_receipt is not None
                and edge_receipt.aggregated_ciphertext is not None
            ):
                executed_node = edge_receipt.edge_node_id
                edge_exec_ms = edge_receipt.processing_time_ms
                result_ver_ms = ver_metrics.verification_time_ms if ver_metrics else 0.0
                ver_extra_bytes = (
                    ver_metrics.verification_bytes_overhead if ver_metrics else 0
                )
                aggregated_ct = edge_receipt.aggregated_ciphertext

                cpu_resume_ms = PerformanceMonitor.get_process_cpu_time_ms()
                edge_cpu_time_ms = max(
                    0.0, cpu_resume_ms - edge_cpu_start_ms - result_ver_ms
                )

                if selected_mode == ExecutionMode.HYBRID_SECURITY_MODE:
                    compressed_bytes = self.local_security.execute_local_compression(
                        raw_packet_bytes
                    )
                    local_working_buffers_bytes += len(raw_packet_bytes) + len(
                        compressed_bytes
                    )
                else:
                    comp_c0 = PerformanceMonitor.get_process_cpu_time_ms()
                    comp_nonce = secrets.token_hex(12)
                    comp_ts = time.time()
                    raw_hash = CryptographicVerifier.sha256_hex(raw_packet_bytes)
                    comp_msg = (
                        f"{task_id}-c|{self.wallet.device_id}|DATA_COMPRESSION|"
                        f"{raw_hash}|{comp_nonce}|{comp_ts:.6f}"
                    ).encode("utf-8")
                    comp_task = EdgeDelegatedTask(
                        task_id=f"{task_id}-c",
                        device_id=self.wallet.device_id,
                        task_type="DATA_COMPRESSION",
                        execution_mode=selected_mode.value,
                        input_payload_hash=raw_hash,
                        nonce=comp_nonce,
                        timestamp=comp_ts,
                        device_signature=self.wallet.credentials.sign_message(comp_msg),
                        raw_data_bytes=raw_packet_bytes,
                        data_sensitivity=data_sensitivity,
                    )
                    c_ok, c_rcpt, c_ver, _ = (
                        self.edge_cluster.dispatch_with_verification_metrics(
                            comp_task, preferred_edge_id=executed_node
                        )
                    )
                    comp_c1 = PerformanceMonitor.get_process_cpu_time_ms()
                    if c_ok and c_rcpt is not None:
                        compressed_bytes = c_rcpt.result_bytes
                        edge_exec_ms += c_rcpt.processing_time_ms
                        c_ver_ms = c_ver.verification_time_ms if c_ver else 0.0
                        result_ver_ms += c_ver_ms
                        ver_extra_bytes += (
                            c_ver.verification_bytes_overhead if c_ver else 0
                        )
                        edge_cpu_time_ms += max(0.0, (comp_c1 - comp_c0) - c_ver_ms)
                        cpu_resume_ms = comp_c1 - c_ver_ms
                    else:
                        compressed_bytes = (
                            self.local_security.execute_local_compression(
                                raw_packet_bytes
                            )
                        )
                        local_working_buffers_bytes += len(raw_packet_bytes) + len(
                            compressed_bytes
                        )

                t_dec_ns = time.perf_counter_ns()
                decrypted_sum = self.local_security.decrypt_homomorphic_aggregate(
                    aggregated_ct
                )
                he_decrypt_ms = (time.perf_counter_ns() - t_dec_ns) / 1e6
                host_device_cpu_ms = (
                    dev_cpu_before_edge_ms
                    + result_ver_ms
                    + max(
                        0.0,
                        PerformanceMonitor.get_process_cpu_time_ms() - cpu_resume_ms,
                    )
                )
                result_bytes = edge_receipt.result_bytes + compressed_bytes
                sig_hash = CryptographicVerifier.sha256_hex(edge_receipt.edge_signature)
            else:
                used_fallback = True
                selected_mode = ExecutionMode.LOCAL_SECURITY_MODE
                executed_node = self.wallet.device_id
                cpu_fb_start = PerformanceMonitor.get_process_cpu_time_ms()
                t_sm_ns = time.perf_counter_ns()
                weighted_cts = [
                    self.local_security.he_engine.homomorphic_scalar_mul(k, c)
                    for k, c in zip(scalars, ciphertexts)
                ]
                he_scalar_mul_ms = (time.perf_counter_ns() - t_sm_ns) / 1e6

                t_add_ns = time.perf_counter_ns()
                aggregated_ct = self.local_security.he_engine.homomorphic_sum(
                    weighted_cts
                )
                he_add_ms = (time.perf_counter_ns() - t_add_ns) / 1e6

                compressed_bytes = self.local_security.execute_local_compression(
                    raw_packet_bytes
                )
                weighted_bytes = json.dumps(
                    [w.to_dict() for w in weighted_cts], sort_keys=True
                ).encode("utf-8")
                local_working_buffers_bytes += (
                    len(raw_packet_bytes) + len(compressed_bytes) + len(weighted_bytes)
                )
                t_dec_ns = time.perf_counter_ns()
                decrypted_sum = self.local_security.decrypt_homomorphic_aggregate(
                    aggregated_ct
                )
                he_decrypt_ms = (time.perf_counter_ns() - t_dec_ns) / 1e6
                host_device_cpu_ms = dev_cpu_before_edge_ms + max(
                    0.0, PerformanceMonitor.get_process_cpu_time_ms() - cpu_fb_start
                )
                result_bytes = (
                    json.dumps(aggregated_ct.to_dict(), sort_keys=True).encode("utf-8")
                    + compressed_bytes
                )
                sig_hash = CryptographicVerifier.sha256_hex(
                    self.wallet.credentials.sign_message(result_bytes)
                )
        else:
            t_sm_ns = time.perf_counter_ns()
            weighted_cts = [
                self.local_security.he_engine.homomorphic_scalar_mul(k, c)
                for k, c in zip(scalars, ciphertexts)
            ]
            he_scalar_mul_ms = (time.perf_counter_ns() - t_sm_ns) / 1e6

            t_add_ns = time.perf_counter_ns()
            aggregated_ct = self.local_security.he_engine.homomorphic_sum(weighted_cts)
            he_add_ms = (time.perf_counter_ns() - t_add_ns) / 1e6

            compressed_bytes = self.local_security.execute_local_compression(
                raw_packet_bytes
            )
            weighted_bytes = json.dumps(
                [w.to_dict() for w in weighted_cts], sort_keys=True
            ).encode("utf-8")
            local_working_buffers_bytes += (
                len(raw_packet_bytes) + len(compressed_bytes) + len(weighted_bytes)
            )
            t_dec_ns = time.perf_counter_ns()
            decrypted_sum = self.local_security.decrypt_homomorphic_aggregate(
                aggregated_ct
            )
            he_decrypt_ms = (time.perf_counter_ns() - t_dec_ns) / 1e6
            host_device_cpu_ms = max(
                0.0, PerformanceMonitor.get_process_cpu_time_ms() - cpu_start_ms
            )
            result_bytes = (
                json.dumps(aggregated_ct.to_dict(), sort_keys=True).encode("utf-8")
                + compressed_bytes
            )
            sig_hash = CryptographicVerifier.sha256_hex(
                self.wallet.credentials.sign_message(result_bytes)
            )

        val_cpu_start_ms = PerformanceMonitor.get_process_cpu_time_ms()
        t_tx_ns = time.perf_counter_ns()
        create_tx = self.blockchain_client.tx_manager.create_signed_transaction(
            sender_device_id=self.wallet.device_id,
            contract_name="TaskManagement",
            method_name="createTask",
            payload={
                "taskId": task_id,
                "deviceId": self.wallet.device_id,
                "assignedNodeId": executed_node,
                "mode": selected_mode.value,
                "inputPayloadHash": input_hash,
            },
            tx_type="SET",
        )
        self.blockchain_client.submit_and_execute_transaction(
            create_tx, auto_commit_block=False
        )

        onchain_result_hash = self.blockchain_client.store_offchain_result(
            task_id, result_bytes
        )
        submit_tx = self.blockchain_client.tx_manager.create_signed_transaction(
            sender_device_id=self.wallet.device_id,
            contract_name="TaskManagement",
            method_name="submitTaskResult",
            payload={
                "taskId": task_id,
                "executorNodeId": executed_node,
                "resultPayloadHash": onchain_result_hash,
                "edgeReceiptSignatureHash": sig_hash,
            },
            tx_type="SET",
        )
        self.blockchain_client.submit_and_execute_transaction(
            submit_tx, auto_commit_block=True
        )
        retrieved_bytes = self.blockchain_client.retrieve_and_verify_offchain_result(
            task_id, self.wallet.device_id
        )
        integrity_ok = retrieved_bytes == result_bytes
        tx_commit_ms = (time.perf_counter_ns() - t_tx_ns) / 1e6
        validator_cpu_ms = max(
            0.0, PerformanceMonitor.get_process_cpu_time_ms() - val_cpu_start_ms
        )

        if selected_mode == ExecutionMode.LOCAL_SECURITY_MODE:
            bytes_tx = (
                auth_bytes
                + len(create_tx.compute_canonical_bytes())
                + len(submit_tx.compute_canonical_bytes())
            )
            bytes_rx = 256
            wire_delay_ms = 0.20 * snapshot.network_latency_ms + (
                (bytes_tx + bytes_rx) * 8.0
            ) / (snapshot.available_bandwidth_mbps * 1000.0)
        elif selected_mode == ExecutionMode.HYBRID_SECURITY_MODE:
            bytes_tx = (
                auth_bytes
                + len(serialized_cts)
                + len(create_tx.compute_canonical_bytes())
                + ver_extra_bytes
            )
            bytes_rx = len(result_bytes) + 256
            wire_delay_ms = 0.45 * snapshot.network_latency_ms + (
                (bytes_tx + bytes_rx) * 8.0
            ) / (snapshot.available_bandwidth_mbps * 1000.0)
        else:
            bytes_tx = (
                auth_bytes
                + len(serialized_cts)
                + len(raw_packet_bytes)
                + len(create_tx.compute_canonical_bytes())
                + ver_extra_bytes
            )
            bytes_rx = len(result_bytes) + 256
            wire_delay_ms = 0.60 * snapshot.network_latency_ms + (
                (bytes_tx + bytes_rx) * 8.0
            ) / (snapshot.available_bandwidth_mbps * 1000.0)

        measured_wall_ms = (time.perf_counter_ns() - t_total_start_ns) / 1e6

        cpu_metrics = PerformanceMonitor.compute_cpu_utilization_metrics(
            cpu_time_delta_ms=host_device_cpu_ms,
            wall_clock_interval_ms=measured_wall_ms,
        )
        mem_status = PerformanceMonitor.get_process_memory_status_kb()
        measured_buffer_kb = round(local_working_buffers_bytes / 1024.0, 3)

        if (
            snapshot.available_ram_kb <= 400.0
            or snapshot.cpu_utilization_percent >= 78.0
        ):
            v_prof = VIRTUAL_IOT_PROFILES["HIGHLY_CONSTRAINED_IOT"]
        elif (
            snapshot.available_ram_kb <= 950.0
            or snapshot.cpu_utilization_percent >= 48.0
        ):
            v_prof = VIRTUAL_IOT_PROFILES["MODERATELY_CONSTRAINED_IOT"]
        else:
            v_prof = VIRTUAL_IOT_PROFILES["MORE_CAPABLE_IOT"]

        sim_res = SimulatedResourceModel.evaluate_task_resources(
            profile=v_prof,
            execution_mode=selected_mode.value,
            payload_bytes=len(raw_packet_bytes),
            num_he_ops=len(telemetry_values),
            allow_session_reuse=use_reuse,
            background_device_cpu_pct=snapshot.cpu_utilization_percent,
            Simulated_network_delay_ms=wire_delay_ms,
        )

        total_latency_ms = measured_wall_ms + sim_res["simulated_total_latency_ms"]

        energy_est = self.energy_estimator.estimate_task_energy(
            device_cpu_time_ms=sim_res["simulated_device_cpu_ms"],
            bytes_transmitted=bytes_tx,
            bytes_received=bytes_rx,
            uplink_mbps=snapshot.available_bandwidth_mbps,
            downlink_mbps=snapshot.available_bandwidth_mbps,
            network_wait_ms=wire_delay_ms,
        )

        bw_kbps = ((bytes_tx + bytes_rx) * 8.0) / max(0.001, total_latency_ms)

        sample = TaskPerformanceSample(
            task_id=task_id,
            device_id=self.wallet.device_id,
            configuration=policy_label,
            execution_mode=selected_mode.value,
            auth_latency_ms=auth_ms,
            nizk_prove_time_ms=nizk_prove_ms,
            nizk_verify_time_ms=nizk_verify_ms,
            he_encrypt_time_ms=he_encrypt_ms,
            he_add_time_ms=he_add_ms,
            he_scalar_mul_time_ms=he_scalar_mul_ms,
            he_decrypt_time_ms=he_decrypt_ms,
            edge_execution_time_ms=(
                edge_exec_ms if edge_exec_ms > 0 else sim_res["simulated_edge_exec_ms"]
            ),
            result_verification_time_ms=result_ver_ms,
            tx_commit_time_ms=tx_commit_ms,
            task_execution_latency_ms=total_latency_ms,
            device_cpu_time_ms=sim_res["simulated_device_cpu_ms"],
            device_cpu_utilization_percent=sim_res["simulated_device_cpu_pct"],
            device_memory_kb=sim_res["simulated_device_memory_kb"],
            node_cpu_utilization_percent=sim_res["simulated_validator_cpu_pct"],
            node_memory_mb=sim_res["simulated_validator_memory_mb"],
            edge_cpu_load_percent=sim_res["simulated_edge_cpu_pct"],
            edge_server_memory_kb=sim_res["simulated_edge_memory_kb"],
            energy_estimate_mj=energy_est.total_energy_mj,
            network_latency_ms=snapshot.network_latency_ms,
            bytes_transmitted=bytes_tx,
            bytes_received=bytes_rx,
            bandwidth_used_kbps=bw_kbps,
            edge_node_id=executed_node,
            auth_succeeded=auth_ok,
            result_verified=integrity_ok,
            used_fallback=used_fallback,
            measurement_interval_ms=measured_wall_ms,
            host_process_cpu_utilization_pct=cpu_metrics["multi_core_host_cpu_pct"],
            emulated_device_cpu_quota_pct=sim_res["simulated_device_cpu_pct"],
            edge_server_cpu_time_ms=edge_cpu_time_ms,
            validator_cpu_time_ms=validator_cpu_ms,
            host_process_rss_kb=mem_status["rss_kb"],
            host_process_peak_rss_kb=mem_status["peak_rss_kb"],
            measured_task_buffer_kb=measured_buffer_kb,
            emulated_device_ram_budget_kb=v_prof.ram_capacity_kb,
            emulated_device_available_ram_kb=snapshot.available_ram_kb,
            validator_memory_kb=sim_res["simulated_validator_memory_mb"] * 1024.0,
            energy_classification="MODEL_ESTIMATED",
        )
        self.perf_monitor.record_sample(sample)

        if decision is not None:
            decision.actual_execution_outcome = {
                "executed_mode": selected_mode.value,
                "executed_on_node": executed_node,
                "used_local_fallback": used_fallback,
                "simulated_device_cpu_ms": sim_res["simulated_device_cpu_ms"],
                "simulated_device_cpu_pct": sim_res["simulated_device_cpu_pct"],
                "simulated_device_memory_kb": sim_res["simulated_device_memory_kb"],
                "host_measured_buffer_kb": measured_buffer_kb,
                "total_latency_ms": round(total_latency_ms, 3),
                "result_verification_time_ms": round(result_ver_ms, 3),
                "bytes_transmitted": bytes_tx,
                "verified": integrity_ok,
            }

        return TaskExecutionResult(
            task_id=task_id,
            device_id=self.wallet.device_id,
            selected_mode=selected_mode.value,
            executed_on_node=executed_node,
            decrypted_aggregate_value=decrypted_sum,
            compressed_size_bytes=len(compressed_bytes),
            onchain_result_hash=onchain_result_hash,
            offchain_integrity_verified=integrity_ok,
            used_local_fallback=used_fallback,
            performance_sample=sample,
            decision_record=decision,
        )
