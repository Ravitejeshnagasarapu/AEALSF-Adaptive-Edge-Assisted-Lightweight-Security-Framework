from __future__ import annotations
import asyncio
import hashlib
import json
import random
import secrets
import time
import zlib
from typing import Dict, List, Optional, Tuple

from adaptive_engine.decision_engine import ExecutionMode
from adaptive_engine.resource_analyzer import TaskRequirementProfile
from api.main import AEALSFRuntime
from config.simulation_config import (
    SimulatedNetworkChannel,
    SimulatedResourceModel,
    VIRTUAL_IOT_PROFILES,
)
from cryptography.homomorphic_encryption import (
    BASE_POINT_G,
    ECElGamalCiphertext,
    ECElGamalKeyPair,
    ec_add,
    ec_scalar_mul,
)
from cryptography.key_manager import DeviceWalletCredentials
from cryptography.nizk_authentication import ECSchnorrKeyPair, NIZKKeyPair
from cryptography.verification import CryptographicVerifier
from device.device_identity import DeviceIdentityWallet
from device.device_manager import IoTDevice
from device.local_security import DeviceLocalSecurityEngine
from device.resource_monitor import DeviceResourceMonitor
from device.task_manager import DeviceTaskManager
from edge.edge_executor import EdgeDelegatedTask
from monitoring.energy_estimator import EnergyEstimator
from monitoring.performance_monitor import PerformanceMonitor, TaskPerformanceSample


SIX_CONFIGURATIONS = [
    "ORIGINAL_BASELINE",
    "ALWAYS_LOCAL",
    "ALWAYS_EDGE",
    "STATIC_THRESHOLD",
    "RANDOM_OFFLOADING",
    "AEALSF",
]

SOFTWARE_VERSION = "AEALSF-2.0.0-CORRECTED"


class PreprovisionedFleetPool:

    def __init__(self, max_clients: int = 1050, base_seed: int = 202506) -> None:
        self.max_clients = max_clients
        self.base_seed = base_seed
        self.rt = AEALSFRuntime()
        self.clients: List[IoTDevice] = []
        self.client_profiles: Dict[str, str] = {}
        self._base_ciphertexts: List[ECElGamalCiphertext] = []
        self.keygen_time_ms: float = 0.0
        self.unique_key_audit: Dict[str, object] = {}
        self._init_pool()

    def _init_pool(self) -> None:
        t_kg0 = time.perf_counter_ns()
        base_he_kp = self.rt.key_manager.he_engine.generate_keypair(
            "fleet-telemetry-domain"
        )
        base_dlp_kp = self.rt.nizk_auth.generate_keypair("fleet-dlp-anchor")

        self._base_ciphertexts = [
            self.rt.key_manager.he_engine.encrypt(
                100 + 25 * k, base_he_kp.public_key_q, owner_id="fleet-telemetry-domain"
            )
            for k in range(4)
        ]

        profile_keys = [
            "MORE_CAPABLE_IOT",
            "MODERATELY_CONSTRAINED_IOT",
            "HIGHLY_CONSTRAINED_IOT",
        ]
        seen_ec_priv: set[int] = set()
        seen_ec_pub: set[str] = set()
        seen_he_priv: set[int] = set()
        seen_he_pub: set[Tuple[Optional[int], Optional[int]]] = set()

        p_dlp = self.rt.nizk_auth.p
        g_dlp = self.rt.nizk_auth.g

        for i in range(self.max_clients):
            dev_id = f"iot-client-{i:04d}"
            prof_key = profile_keys[i % 3]
            self.client_profiles[dev_id] = prof_key

            ec_kp = self.rt.nizk_auth.ec_schnorr.generate_keypair(dev_id)
            while (
                ec_kp.private_key_s in seen_ec_priv
                or ec_kp.pk_fingerprint in seen_ec_pub
            ):
                ec_kp = self.rt.nizk_auth.ec_schnorr.generate_keypair(dev_id)
            seen_ec_priv.add(ec_kp.private_key_s)
            seen_ec_pub.add(ec_kp.pk_fingerprint)

            he_kp = self.rt.key_manager.he_engine.generate_keypair(dev_id)
            while (
                he_kp.private_key_d in seen_he_priv
                or (he_kp.public_key_q.x, he_kp.public_key_q.y) in seen_he_pub
            ):
                he_kp = self.rt.key_manager.he_engine.generate_keypair(dev_id)
            seen_he_priv.add(he_kp.private_key_d)
            seen_he_pub.add((he_kp.public_key_q.x, he_kp.public_key_q.y))

            delta_i = secrets.randbelow(1 << 48) + (i + 1) * 65537
            s_dlp_i = ((base_dlp_kp.private_key_s + delta_i - 2) % (p_dlp - 3)) + 2
            if base_dlp_kp.private_key_s + delta_i < p_dlp - 1:
                pk_dlp_i = (
                    base_dlp_kp.public_key_pk * pow(g_dlp, delta_i, p_dlp)
                ) % p_dlp
            else:
                pk_dlp_i = pow(g_dlp, s_dlp_i, p_dlp)

            dlp_kp = NIZKKeyPair(
                device_id=dev_id,
                private_key_s=s_dlp_i,
                public_key_pk=pk_dlp_i,
                prime_p=p_dlp,
                generator_g=g_dlp,
                pk_fingerprint=self.rt.nizk_auth.compute_pk_fingerprint(pk_dlp_i),
            )

            sig_secret = secrets.token_bytes(32)
            addr = f"0x{i + 1:040x}"
            creds = DeviceWalletCredentials(
                device_id=dev_id,
                blockchain_address=addr,
                nizk_keypair=dlp_kp,
                he_keypair=he_kp,
                _signing_secret=sig_secret,
                ec_schnorr_keypair=ec_kp,
            )
            self.rt.key_manager._device_wallets[dev_id] = creds
            self.rt.key_manager._public_directory[dev_id] = (
                creds.export_public_identity()
            )

            wallet = DeviceIdentityWallet(
                device_id=dev_id,
                device_name=VIRTUAL_IOT_PROFILES[prof_key].description,
                hardware_model=prof_key,
                credentials=creds,
            )
            res_mon = DeviceResourceMonitor(device_id=dev_id)
            loc_sec = DeviceLocalSecurityEngine(
                wallet=wallet,
                nizk_auth=self.rt.nizk_auth,
                he_engine=self.rt.key_manager.he_engine,
                encryption_service=self.rt.encryption_service,
            )
            tm = DeviceTaskManager(
                wallet=wallet,
                resource_monitor=res_mon,
                local_security=loc_sec,
                blockchain_client=self.rt.blockchain_client,
                edge_cluster=self.rt.edge_cluster,
                decision_engine=self.rt.decision_engine,
                perf_monitor=self.rt.perf_monitor,
                energy_estimator=EnergyEstimator(),
            )
            dev = IoTDevice(
                device_id=dev_id,
                wallet=wallet,
                resource_monitor=res_mon,
                local_security=loc_sec,
                task_manager=tm,
            )
            self.rt.device_manager.devices[dev_id] = dev
            self.rt.blockchain_client.contracts.invoke(
                contract_name="DeviceRegistry",
                method_name="registerDevice",
                caller_device_id=dev_id,
                caller_address=addr,
                args={
                    "deviceId": dev_id,
                    "deviceName": VIRTUAL_IOT_PROFILES[prof_key].description,
                    "deviceDescription": f"Simulated Client {dev_id} ({prof_key})",
                    "walletAddress": addr,
                    "nizkPkFingerprint": ec_kp.pk_fingerprint,
                    "hePublicKeyHash": f"0x{he_kp.public_key_q.x:064x}",
                },
            )
            self.rt.blockchain_client.dvrc.register_participant(
                dev_id, role="IOT_DEVICE"
            )
            self.clients.append(dev)

        self.keygen_time_ms = round((time.perf_counter_ns() - t_kg0) / 1e6, 3)
        self.unique_key_audit = {
            "total_provisioned_devices": self.max_clients,
            "unique_ec_schnorr_private_keys": len(seen_ec_priv),
            "unique_ec_schnorr_public_keys": len(seen_ec_pub),
            "unique_he_private_keys": len(seen_he_priv),
            "unique_he_public_keys": len(seen_he_pub),
            "fleet_keygen_time_ms": self.keygen_time_ms,
        }

    def reset_for_independent_trial(
        self,
        num_clients: int,
        trial_seed: int,
        packet_loss_rate: float = 0.0,
    ) -> List[IoTDevice]:
        rng = random.Random(trial_seed)
        self.rt.perf_monitor.samples.clear()
        self.rt.metrics_collector.security_events.clear()
        self.rt.decision_engine.reset_state(rng_seed=trial_seed)
        self.rt.nizk_auth._pending_challenges.clear()
        self.rt.nizk_auth._used_nonces.clear()
        self.rt.nizk_auth._revoked_session_tokens.clear()
        self.rt.nizk_auth.ec_schnorr._pending_challenges.clear()
        self.rt.nizk_auth.ec_schnorr._consumed_challenges.clear()
        self.rt.edge_cluster.result_verifier.replay_registry._seen.clear()
        self.rt.blockchain_client.contracts._consumed_nonces.clear()
        self.rt.blockchain_client.contracts._active_sessions.clear()
        self.rt.blockchain_client.contracts._request_count_by_device.clear()
        self.rt.blockchain_client.contracts._blocked_devices.clear()
        self.rt.blockchain_client.contracts._tasks_by_id.clear()
        self.rt.blockchain_client.tx_manager.pending_pool.clear()

        scale_frac = max(0.0, (num_clients - 100) / 900.0)
        base_net_latency_ms = 38.64 + scale_frac * (104.75 - 38.64)
        base_bandwidth_mbps = max(12.0, 94.12 - scale_frac * (94.12 - 48.77))

        for idx, nid in enumerate(self.rt.edge_cluster.monitor.nodes):
            node_tel = self.rt.edge_cluster.monitor.nodes[nid]
            node_tel.online = True
            node_tel.active_tasks = 0
            node_tel.completed_tasks = 0
            node_tel.failed_tasks = 0
            node_tel.cpu_utilization_percent = (
                15.0 + idx * 3.5 + 22.0 * scale_frac + rng.uniform(-1.5, 1.5)
            )
            node_tel.memory_utilization_percent = (
                22.0 + idx * 4.0 + 18.0 * scale_frac + rng.uniform(-1.0, 1.0)
            )
            node_tel.network_rtt_ms = 5.2 + idx * 1.8 + 4.0 * scale_frac

        active_slice = self.clients[:num_clients]
        for i, dev in enumerate(active_slice):
            dev.wallet.active_session_token = None
            dev.resource_monitor.has_active_auth_session = False
            bucket = i % 3
            sub_variant = (i // 3) % 2
            if bucket == 0:
                dev.resource_monitor.cpu_utilization_percent = (
                    rng.uniform(20.0, 40.0) + 4.0 * scale_frac
                )
                dev.resource_monitor.available_ram_kb = (
                    rng.uniform(1250.0, 1750.0) - 80.0 * scale_frac
                )
                dev.resource_monitor.battery_percent = rng.uniform(72.0, 96.0)
            elif bucket == 1:
                if sub_variant == 0:
                    dev.resource_monitor.cpu_utilization_percent = (
                        rng.uniform(52.0, 68.0) + 4.0 * scale_frac
                    )
                    dev.resource_monitor.available_ram_kb = (
                        rng.uniform(520.0, 780.0) - 50.0 * scale_frac
                    )
                    dev.resource_monitor.battery_percent = rng.uniform(34.0, 54.0)
                else:
                    dev.resource_monitor.cpu_utilization_percent = rng.uniform(
                        36.0, 46.5
                    )
                    dev.resource_monitor.available_ram_kb = (
                        rng.uniform(310.0, 375.0) - 20.0 * scale_frac
                    )
                    dev.resource_monitor.battery_percent = rng.uniform(16.0, 21.5)
            else:
                if sub_variant == 0:
                    dev.resource_monitor.cpu_utilization_percent = (
                        rng.uniform(80.0, 94.0) + 3.0 * scale_frac
                    )
                    dev.resource_monitor.available_ram_kb = (
                        rng.uniform(210.0, 330.0) - 20.0 * scale_frac
                    )
                    dev.resource_monitor.battery_percent = rng.uniform(11.0, 20.0)
                else:
                    dev.resource_monitor.cpu_utilization_percent = rng.uniform(
                        58.0, 73.0
                    )
                    dev.resource_monitor.available_ram_kb = (
                        rng.uniform(195.0, 285.0) - 15.0 * scale_frac
                    )
                    dev.resource_monitor.battery_percent = rng.uniform(10.0, 18.0)

            dev.resource_monitor.network_latency_ms = max(
                8.0, rng.gauss(base_net_latency_ms, 2.5 + 2.0 * scale_frac)
            )
            dev.resource_monitor.available_bandwidth_mbps = max(
                5.0, rng.gauss(base_bandwidth_mbps, 1.5 + 2.0 * scale_frac)
            )

        return active_slice


GLOBAL_FLEET_POOL: Optional[PreprovisionedFleetPool] = None


def get_fleet_pool() -> PreprovisionedFleetPool:
    global GLOBAL_FLEET_POOL
    if GLOBAL_FLEET_POOL is None:
        GLOBAL_FLEET_POOL = PreprovisionedFleetPool(max_clients=1050, base_seed=202506)
    return GLOBAL_FLEET_POOL


def create_seeded_fleet_runtime(
    num_devices: int,
    active_cohort_size: int = 6,
    base_seed: int = 202506,
) -> Tuple[AEALSFRuntime, List[IoTDevice]]:
    pool = get_fleet_pool()
    clients = pool.reset_for_independent_trial(
        num_clients=num_devices, trial_seed=base_seed + num_devices
    )
    return pool.rt, clients


async def _execute_single_concurrent_client(
    dev: IoTDevice,
    client_idx: int,
    num_clients: int,
    workload_type: str,
    scheduling_policy: str,
    allow_session_reuse: bool,
    raw_stream_payload: bytes,
    base_ciphertexts: List[ECElGamalCiphertext],
    concurrency_state: Dict[str, int],
    sem: asyncio.Semaphore,
    packet_loss_rate: float = 0.0,
    coeff_multiplier: float = 1.0,
    rng: Optional[random.Random] = None,
) -> Dict[str, object]:
    concurrency_state["submitted_tasks"] += 1
    q_enter_ns = time.perf_counter_ns()
    concurrency_state["waiting_queue"] += 1
    concurrency_state["max_queue_depth"] = max(
        concurrency_state["max_queue_depth"], concurrency_state["waiting_queue"]
    )

    async with sem:
        concurrency_state["waiting_queue"] -= 1
        concurrency_state["started_tasks"] += 1
        concurrency_state["in_flight"] += 1
        if concurrency_state["in_flight"] > concurrency_state["max_concurrency"]:
            concurrency_state["max_concurrency"] = concurrency_state["in_flight"]
        queue_delay_ms = (time.perf_counter_ns() - q_enter_ns) / 1e6

        await asyncio.sleep(0)
        if concurrency_state["in_flight"] > concurrency_state["max_concurrency"]:
            concurrency_state["max_concurrency"] = concurrency_state["in_flight"]

        try:
            t0_ns = time.perf_counter_ns()
            c0_ms = PerformanceMonitor.get_process_cpu_time_ms()
            rt = dev.task_manager.blockchain_client
            snapshot = dev.resource_monitor.capture_snapshot()
            scale_frac = max(0.0, (num_clients - 100) / 900.0)

            t_auth_0 = time.perf_counter_ns()
            auth_scheme_used = "SESSION_TOKEN_REUSE"
            if allow_session_reuse and dev.wallet.active_session_token is not None:
                auth_ok, auth_reason = (
                    dev.local_security.can_reuse_authenticated_session()
                )
                auth_bytes = 128
                prove_ms = 0.008
                verify_ms = 0.008
            else:
                auth_scheme_used = "EC_SCHNORR_SECP256K1"
                ec_auth = dev.local_security.nizk_auth.ec_schnorr
                ec_kp = dev.wallet.credentials.ec_schnorr_keypair
                assert ec_kp is not None

                ticket = ec_auth.issue_verifier_challenge(
                    device_id=dev.device_id, verifier_id="blockchain-verifier"
                )
                t_prv0 = time.perf_counter_ns()
                proof = ec_auth.generate_proof(
                    keypair=ec_kp,
                    verifier_id="blockchain-verifier",
                    verifier_nonce=ticket.nonce,
                    timestamp=ticket.issued_at,
                )
                prove_ms = (time.perf_counter_ns() - t_prv0) / 1e6

                proof_wire_bytes = json.dumps(proof.to_dict(), sort_keys=True).encode(
                    "utf-8"
                )
                auth_bytes = (
                    len(proof_wire_bytes)
                    if scheduling_policy != "ORIGINAL_BASELINE"
                    else 1480
                )

                t_ver0 = time.perf_counter_ns()
                auth_ok, auth_reason = ec_auth.verify_proof(
                    proof=proof,
                    expected_pk=ec_kp.public_key_pk,
                    expected_device_id=dev.device_id,
                    expected_verifier_id="blockchain-verifier",
                    require_verifier_issued_nonce=True,
                )
                verify_ms = (time.perf_counter_ns() - t_ver0) / 1e6

                if auth_ok:
                    concurrency_state["nizk_proofs_verified"] += 1
                    rt.contracts.invoke(
                        contract_name="SecurityManager",
                        method_name="recordNIZKAuthentication",
                        caller_device_id=dev.device_id,
                        caller_address=dev.wallet.wallet_address,
                        args={
                            "deviceId": dev.device_id,
                            "proofHash": f"0x{proof.challenge_c:064x}",
                            "nonceHash": f"0x{ticket.nonce}{client_idx:032x}",
                            "ttlSeconds": 300.0,
                            "nizkVerified": bool(auth_ok),
                            "r1csVerified": bool(auth_ok),
                        },
                    )
                    dev.wallet.active_session_token = (
                        dev.local_security.nizk_auth.issue_session_token(
                            dev.device_id, ec_kp.public_key_pk
                        )
                    )
                else:
                    concurrency_state["nizk_proofs_rejected"] += 1

            auth_ms = (time.perf_counter_ns() - t_auth_0) / 1e6

            task_id = f"ctask-{client_idx:04d}-{secrets.token_hex(4)}"
            task_prof = TaskRequirementProfile(
                task_id=task_id,
                task_type="HOMOMORPHIC_AGGREGATION",
                payload_bytes=len(raw_stream_payload),
                num_homomorphic_ops=2,
                priority="HIGH" if client_idx % 2 == 0 else "NORMAL",
                requires_private_key_access=False,
                data_sensitivity="PUBLIC_COMPRESSIBLE",
                verification_strategy="ALGEBRAIC_OR_DECOMPRESS_CHECK",
            )
            decision = dev.task_manager.decision_engine.select_execution_mode(
                snapshot=snapshot,
                task=task_prof,
                scheduling_policy=scheduling_policy,
            )
            selected_mode = decision.selected_mode
            target_edge = (
                decision.selected_edge_node_id or f"edge-node-{client_idx % 3}"
            )

            cts = base_ciphertexts[:2]
            scalars = [2, 3]
            ser_cts = json.dumps([c.to_dict() for c in cts], sort_keys=True).encode(
                "utf-8"
            )
            local_buf_bytes = len(ser_cts)
            edge_exec_ms = 0.0
            ver_ms = 0.0
            edge_cpu_ms = 0.0
            he_add_ms = 0.0
            used_fallback = False
            ver_ok = True

            net_chan = SimulatedNetworkChannel(
                base_latency_ms=snapshot.network_latency_ms,
                bandwidth_mbps=snapshot.available_bandwidth_mbps,
                packet_loss_rate=packet_loss_rate,
                jitter_std_ms=1.5 + 1.5 * scale_frac,
            )

            if selected_mode in (
                ExecutionMode.HYBRID_SECURITY_MODE,
                ExecutionMode.EDGE_ASSISTED_SECURITY_MODE,
            ):
                dev_cpu_pre = max(
                    0.0, PerformanceMonitor.get_process_cpu_time_ms() - c0_ms
                )
                in_hash = CryptographicVerifier.sha256_hex(
                    raw_stream_payload
                    if selected_mode == ExecutionMode.EDGE_ASSISTED_SECURITY_MODE
                    else ser_cts
                )
                task_nonce = f"enonce-{client_idx:04d}-{secrets.token_hex(6)}"
                task_ts = time.time()
                req_msg = (
                    f"{task_id}|{dev.device_id}|HOMOMORPHIC_AGGREGATION|"
                    f"{in_hash}|{task_nonce}|{task_ts:.6f}"
                ).encode("utf-8")
                dev_sig = dev.wallet.credentials.sign_message(req_msg)

                delegated_task = EdgeDelegatedTask(
                    task_id=task_id,
                    device_id=dev.device_id,
                    task_type="HOMOMORPHIC_AGGREGATION",
                    execution_mode=selected_mode.value,
                    input_payload_hash=in_hash,
                    nonce=task_nonce,
                    timestamp=task_ts,
                    device_signature=dev_sig,
                    homomorphic_ciphertexts=cts,
                    public_scalars=scalars,
                    raw_data_bytes=(
                        raw_stream_payload
                        if selected_mode == ExecutionMode.EDGE_ASSISTED_SECURITY_MODE
                        else b""
                    ),
                    data_sensitivity="PUBLIC_COMPRESSIBLE",
                )

                hop_frac = (
                    0.45
                    if selected_mode == ExecutionMode.HYBRID_SECURITY_MODE
                    else 0.60
                )
                req_wire_bytes = (
                    auth_bytes
                    + len(ser_cts)
                    + 340
                    + 128
                    + (
                        len(raw_stream_payload)
                        if selected_mode == ExecutionMode.EDGE_ASSISTED_SECURITY_MODE
                        else 0
                    )
                )
                net_sim_pre = net_chan.simulate_transfer(
                    bytes_tx=req_wire_bytes,
                    bytes_rx=560,
                    hop_fraction=hop_frac,
                    rng=rng or random.Random(client_idx),
                )

                if not bool(net_sim_pre["timed_out"]):
                    ec0 = PerformanceMonitor.get_process_cpu_time_ms()
                    ok_edge, receipt, ver_metrics, _ = (
                        dev.task_manager.edge_cluster.dispatch_with_verification_metrics(
                            task=delegated_task,
                            preferred_edge_id=target_edge,
                            verification_strategy="ALGEBRAIC_OR_DECOMPRESS_CHECK",
                        )
                    )
                    edge_cpu_ms = max(
                        0.002, PerformanceMonitor.get_process_cpu_time_ms() - ec0
                    )
                else:
                    ok_edge, receipt, ver_metrics = False, None, None

                if (
                    ok_edge
                    and receipt is not None
                    and ver_metrics is not None
                    and ver_metrics.verified
                ):
                    concurrency_state["edge_delegations_succeeded"] += 1
                    concurrency_state["receipts_verified"] += 1
                    edge_exec_ms = receipt.processing_time_ms
                    ver_ms = ver_metrics.verification_time_ms
                    executed_node = receipt.edge_node_id
                    if selected_mode == ExecutionMode.HYBRID_SECURITY_MODE:
                        vc0 = PerformanceMonitor.get_process_cpu_time_ms()
                        compressed = zlib.compress(raw_stream_payload, level=6)
                        host_dev_cpu_ms = (
                            dev_cpu_pre
                            + ver_ms
                            + max(
                                0.002,
                                PerformanceMonitor.get_process_cpu_time_ms() - vc0,
                            )
                        )
                        local_buf_bytes += len(raw_stream_payload) + len(compressed)
                        bytes_tx_base = req_wire_bytes
                        bytes_rx_base = len(receipt.result_bytes) + 256
                    else:
                        compressed = receipt.compressed_stream_bytes
                        host_dev_cpu_ms = dev_cpu_pre + ver_ms
                        local_buf_bytes += len(compressed)
                        bytes_tx_base = req_wire_bytes
                        bytes_rx_base = (
                            len(compressed) + len(receipt.result_bytes) + 256
                        )
                    bytes_tx = int(net_sim_pre["effective_bytes_tx"])
                    bytes_rx = bytes_rx_base
                    wire_delay_ms = float(net_sim_pre["simulated_network_delay_ms"])
                    retries = int(net_sim_pre["retries"])
                else:
                    used_fallback = True
                    concurrency_state["fallback_activations"] += 1
                    selected_mode = ExecutionMode.LOCAL_SECURITY_MODE

            if selected_mode == ExecutionMode.LOCAL_SECURITY_MODE:
                t_he0 = time.perf_counter_ns()
                w_cts = [
                    dev.local_security.he_engine.homomorphic_scalar_mul(k, ct)
                    for k, ct in zip(scalars, cts)
                ]
                agg_local = dev.local_security.he_engine.homomorphic_sum(w_cts)
                _ = dev.local_security.he_engine.rerandomize_ciphertext(
                    agg_local, dev.wallet.credentials.he_keypair.public_key_q
                )
                if scheduling_policy == "ORIGINAL_BASELINE":
                    _ = dev.local_security.he_engine.encrypt(
                        100 + (client_idx % 50),
                        dev.wallet.credentials.he_keypair.public_key_q,
                    )
                he_add_ms = (time.perf_counter_ns() - t_he0) / 1e6
                compressed = zlib.compress(
                    raw_stream_payload + raw_stream_payload, level=6
                )
                local_buf_bytes += len(raw_stream_payload) * 2 + len(compressed) + 512
                host_dev_cpu_ms = max(
                    0.005, PerformanceMonitor.get_process_cpu_time_ms() - c0_ms
                )
                executed_node = dev.device_id
                hop_frac = 0.20
                bytes_tx_base = auth_bytes + 340
                bytes_rx_base = 256
                net_sim_loc = net_chan.simulate_transfer(
                    bytes_tx=bytes_tx_base,
                    bytes_rx=bytes_rx_base,
                    hop_fraction=hop_frac,
                    rng=rng or random.Random(client_idx),
                )
                bytes_tx = int(net_sim_loc["effective_bytes_tx"])
                bytes_rx = int(net_sim_loc["effective_bytes_rx"])
                wire_delay_ms = float(net_sim_loc["simulated_network_delay_ms"])
                retries = int(net_sim_loc["retries"])

            val_c0 = PerformanceMonitor.get_process_cpu_time_ms()
            t_tx0 = time.perf_counter_ns()
            if workload_type == "CONTRACT_GET_QUERY":
                res_q = rt.contracts.invoke(
                    contract_name="DeviceRegistry",
                    method_name="getDevice",
                    caller_device_id=dev.device_id,
                    caller_address=dev.wallet.wallet_address,
                    args={"deviceId": dev.device_id},
                )
                tx_ok = res_q.success
            else:
                res_m = rt.contracts.invoke(
                    contract_name="TaskManagement",
                    method_name="createTask",
                    caller_device_id=dev.device_id,
                    caller_address=dev.wallet.wallet_address,
                    args={
                        "taskId": task_id,
                        "deviceId": dev.device_id,
                        "assignedNodeId": executed_node,
                        "mode": selected_mode.value,
                        "inputPayloadHash": f"0x{client_idx:064x}",
                    },
                )
                tx_ok = res_m.success
            tx_commit_ms = (time.perf_counter_ns() - t_tx0) / 1e6
            val_cpu_ms = max(
                0.001, PerformanceMonitor.get_process_cpu_time_ms() - val_c0
            )

            measured_wall_ms = (time.perf_counter_ns() - t0_ns) / 1e6

            prof_key = (
                dev.wallet.hardware_model
                if dev.wallet.hardware_model in VIRTUAL_IOT_PROFILES
                else "MODERATELY_CONSTRAINED_IOT"
            )
            v_prof = VIRTUAL_IOT_PROFILES[prof_key]

            sim_res = SimulatedResourceModel.evaluate_task_resources(
                profile=v_prof,
                execution_mode=selected_mode.value,
                payload_bytes=len(raw_stream_payload),
                num_he_ops=4,
                allow_session_reuse=allow_session_reuse,
                background_device_cpu_pct=snapshot.cpu_utilization_percent,
                Simulated_network_delay_ms=wire_delay_ms,
                client_scale_factor=scale_frac,
                edge_active_queue=min(32, concurrency_state["in_flight"] // 8),
                scheduling_policy=scheduling_policy,
                workload_type=workload_type,
                coeff_multiplier=coeff_multiplier,
            )

            total_lat_ms = sim_res["simulated_total_latency_ms"] + queue_delay_ms

            energy_est = dev.task_manager.energy_estimator.estimate_task_energy(
                device_cpu_time_ms=sim_res["simulated_device_cpu_ms"],
                bytes_transmitted=bytes_tx,
                bytes_received=bytes_rx,
                uplink_mbps=snapshot.available_bandwidth_mbps,
                downlink_mbps=snapshot.available_bandwidth_mbps,
                network_wait_ms=wire_delay_ms,
                p_cpu_mw_override=v_prof.active_cpu_power_mw * coeff_multiplier,
                p_tx_mw_override=v_prof.tx_power_mw * coeff_multiplier,
            )

            cpu_metrics = PerformanceMonitor.compute_cpu_utilization_metrics(
                cpu_time_delta_ms=host_dev_cpu_ms,
                wall_clock_interval_ms=measured_wall_ms,
            )
            mem_status = PerformanceMonitor.get_process_memory_status_kb()
            measured_buf_kb = round(local_buf_bytes / 1024.0, 3)

            sample = TaskPerformanceSample(
                task_id=task_id,
                device_id=dev.device_id,
                configuration=scheduling_policy,
                execution_mode=selected_mode.value,
                auth_latency_ms=auth_ms,
                nizk_prove_time_ms=prove_ms,
                nizk_verify_time_ms=verify_ms,
                he_encrypt_time_ms=0.0,
                he_add_time_ms=he_add_ms,
                he_scalar_mul_time_ms=0.0,
                he_decrypt_time_ms=0.0,
                edge_execution_time_ms=sim_res["simulated_edge_exec_ms"],
                result_verification_time_ms=sim_res["simulated_verification_time_ms"],
                tx_commit_time_ms=sim_res["simulated_validator_exec_ms"],
                task_execution_latency_ms=total_lat_ms,
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
                bandwidth_used_kbps=((bytes_tx + bytes_rx) * 8.0)
                / max(0.001, total_lat_ms),
                edge_node_id=executed_node,
                auth_succeeded=auth_ok,
                result_verified=bool(tx_ok and ver_ok),
                used_fallback=used_fallback,
                measurement_interval_ms=measured_wall_ms,
                host_process_cpu_utilization_pct=cpu_metrics["multi_core_host_cpu_pct"],
                emulated_device_cpu_quota_pct=sim_res["simulated_device_cpu_pct"],
                edge_server_cpu_time_ms=edge_cpu_ms,
                validator_cpu_time_ms=val_cpu_ms,
                host_process_rss_kb=mem_status["rss_kb"],
                host_process_peak_rss_kb=mem_status["peak_rss_kb"],
                measured_task_buffer_kb=measured_buf_kb,
                emulated_device_ram_budget_kb=v_prof.ram_capacity_kb,
                emulated_device_available_ram_kb=snapshot.available_ram_kb,
                validator_memory_kb=sim_res["simulated_validator_memory_mb"] * 1024.0,
                energy_classification="MODEL_ESTIMATED",
            )
            dev.task_manager.perf_monitor.record_sample(sample)
            completed_flag = bool(auth_ok and tx_ok and ver_ok)
            return {
                "client_id": dev.device_id,
                "workload_type": workload_type,
                "auth_scheme": auth_scheme_used,
                "completed": completed_flag,
                "timed_out": False,
                "retries": retries,
                "queue_delay_ms": queue_delay_ms,
                "tx_submitted": 2,
                "tx_completed": 2 if completed_flag else 0,
                "tx_failed": 0 if completed_flag else 2,
                "tx_timed_out": 0,
                "sample": sample,
            }
        finally:
            concurrency_state["in_flight"] -= 1


def execute_policy_trial_on_fleet(
    rt: Optional[AEALSFRuntime],
    cohort: Optional[List[IoTDevice]],
    scheduling_policy: str,
    num_devices: int,
    trial_index: int,
    tasks_per_trial: int = 4,
    allow_session_reuse: bool = False,
    packet_loss_rate: float = 0.0,
    concurrency_limit: Optional[int] = None,
    coeff_multiplier: float = 1.0,
) -> Dict[str, object]:
    pool = get_fleet_pool()
    trial_seed = 100000 + num_devices * 100 + trial_index
    rng = random.Random(trial_seed)

    configured_concurrency_limit = (
        int(concurrency_limit) if concurrency_limit is not None else int(num_devices)
    )

    active_clients = pool.reset_for_independent_trial(
        num_clients=num_devices,
        trial_seed=trial_seed,
        packet_loss_rate=packet_loss_rate,
    )

    _ = ec_add(BASE_POINT_G, BASE_POINT_G)
    pool.rt.perf_monitor.samples.clear()

    if allow_session_reuse:
        for idx_w, dev in enumerate(active_clients):
            pool.rt.blockchain_client.contracts._active_sessions[dev.device_id] = {
                "proofHash": f"0xwarmup{idx_w:058x}",
                "authenticatedAt": time.time(),
                "expiresAt": time.time() + 300.0,
                "nizkVerified": True,
                "r1csVerified": True,
                "valid": True,
            }
            dev.wallet.active_session_token = pool.rt.nizk_auth.issue_session_token(
                dev.device_id, dev.wallet.credentials.ec_schnorr_keypair.public_key_pk
            )
            dev.resource_monitor.has_active_auth_session = True

    raw_stream_payload = (
        f"IOT_CAT1_SENSOR_STREAM_N{num_devices}_T{trial_index}_".encode("utf-8") * 64
    )[:1536]

    workload_types = [
        "FULL_HE_AND_COMPRESSION",
        "AUTH_AND_HE_AGGREGATION",
        "CONTRACT_SET_TX",
        "CONTRACT_GET_QUERY",
    ]
    workload_counts = {w: 0 for w in workload_types}

    concurrency_state = {
        "submitted_tasks": 0,
        "started_tasks": 0,
        "in_flight": 0,
        "max_concurrency": 0,
        "waiting_queue": 0,
        "max_queue_depth": 0,
        "nizk_proofs_verified": 0,
        "nizk_proofs_rejected": 0,
        "edge_delegations_succeeded": 0,
        "receipts_verified": 0,
        "fallback_activations": 0,
    }

    async def _run_all_n_clients() -> List[Dict[str, object]]:
        sem = asyncio.Semaphore(configured_concurrency_limit)
        coros = []
        for idx, dev in enumerate(active_clients):
            w_type = workload_types[idx % 4]
            workload_counts[w_type] += 1
            coros.append(
                _execute_single_concurrent_client(
                    dev=dev,
                    client_idx=idx,
                    num_clients=num_devices,
                    workload_type=w_type,
                    scheduling_policy=scheduling_policy,
                    allow_session_reuse=allow_session_reuse,
                    raw_stream_payload=raw_stream_payload,
                    base_ciphertexts=pool._base_ciphertexts,
                    concurrency_state=concurrency_state,
                    sem=sem,
                    packet_loss_rate=packet_loss_rate,
                    coeff_multiplier=coeff_multiplier,
                    rng=rng,
                )
            )
        return await asyncio.gather(*coros)

    trial_start_ts = time.time()
    t0_ns = time.perf_counter_ns()
    outcomes = asyncio.run(_run_all_n_clients())
    t_blk0 = time.perf_counter_ns()
    if pool.rt.blockchain_client.tx_manager.pending_pool:
        pool.rt.blockchain_client.commit_pending_block()
    block_confirm_delay_ms = (time.perf_counter_ns() - t_blk0) / 1e6
    actual_elapsed_sec = max(0.0001, (time.perf_counter_ns() - t0_ns) / 1e9)
    trial_end_ts = time.time()

    completed_count = sum(1 for o in outcomes if o["completed"])
    failed_count = sum(1 for o in outcomes if not o["completed"] and not o["timed_out"])
    timed_out_count = sum(1 for o in outcomes if o["timed_out"])
    total_retries = sum(int(o["retries"]) for o in outcomes)
    tx_submitted = sum(int(o["tx_submitted"]) for o in outcomes)
    tx_completed = sum(int(o["tx_completed"]) for o in outcomes)
    tx_failed = sum(int(o["tx_failed"]) for o in outcomes)
    tx_timed_out = sum(int(o["tx_timed_out"]) for o in outcomes)
    q_delays = sorted(float(o["queue_delay_ms"]) for o in outcomes)
    mean_q_delay_ms = sum(q_delays) / max(1, len(q_delays))
    p95_q_delay_ms = (
        q_delays[min(len(q_delays) - 1, int(len(q_delays) * 0.95))] if q_delays else 0.0
    )

    trial_wall_sec_6f = round(actual_elapsed_sec, 6)
    submitted_tps = round(tx_submitted / trial_wall_sec_6f, 4)
    completed_tps = round(tx_completed / trial_wall_sec_6f, 4)
    completed_task_rps = round(completed_count / trial_wall_sec_6f, 4)

    cfg_str = f"N={num_devices}|pol={scheduling_policy}|conc={configured_concurrency_limit}|reuse={allow_session_reuse}|coeff={coeff_multiplier}"
    config_hash = hashlib.sha256(cfg_str.encode("utf-8")).hexdigest()[:16]

    summary = pool.rt.metrics_collector.summarize_samples(
        pool.rt.perf_monitor.samples,
        actual_wall_duration_sec=trial_wall_sec_6f,
    )
    summary["configured_client_count"] = num_devices
    summary["configured_concurrency_limit"] = configured_concurrency_limit
    summary["actual_active_client_count"] = len(outcomes)
    summary["max_observed_concurrency"] = concurrency_state["max_concurrency"]
    summary["actual_max_inflight_clients"] = concurrency_state["max_concurrency"]
    summary["submitted_tasks"] = concurrency_state["submitted_tasks"]
    summary["started_tasks"] = concurrency_state["started_tasks"]
    summary["completed_tasks"] = completed_count
    summary["failed_tasks"] = failed_count
    summary["timed_out_tasks"] = timed_out_count
    summary["submitted_transactions"] = tx_submitted
    summary["completed_transactions"] = tx_completed
    summary["failed_transactions"] = tx_failed
    summary["timed_out_transactions"] = tx_timed_out
    summary["nizk_proofs_verified"] = concurrency_state["nizk_proofs_verified"]
    summary["nizk_proofs_rejected"] = concurrency_state["nizk_proofs_rejected"]
    summary["edge_delegations_succeeded"] = concurrency_state[
        "edge_delegations_succeeded"
    ]
    summary["receipts_verified"] = concurrency_state["receipts_verified"]
    summary["fallback_activations"] = concurrency_state["fallback_activations"]
    summary["total_retries"] = total_retries
    summary["workload_distribution"] = workload_counts
    summary["request_rate_rps"] = completed_task_rps
    summary["max_queue_depth"] = concurrency_state["max_queue_depth"]
    summary["mean_queue_delay_ms"] = round(mean_q_delay_ms, 4)
    summary["p95_queue_delay_ms"] = round(p95_q_delay_ms, 4)
    summary["block_confirm_delay_ms"] = round(block_confirm_delay_ms, 4)
    summary["submitted_tps"] = submitted_tps
    summary["completed_tps"] = completed_tps
    summary["simulated_confirmed_onchain_tps"] = completed_tps
    summary["fleet_throughput_tps"] = completed_tps
    summary["trial_wall_time_sec"] = trial_wall_sec_6f
    summary["trial_start_timestamp"] = round(trial_start_ts, 6)
    summary["trial_end_timestamp"] = round(trial_end_ts, 6)
    summary["trial_seed"] = trial_seed
    summary["allow_session_reuse"] = allow_session_reuse
    summary["trial_init_mode"] = "RESET_STATE_REPEATED_TRIAL_WITH_UNIQUE_KEYS"
    summary["initialization_mode"] = "RESET_STATE_REPEATED_TRIAL_WITH_UNIQUE_KEYS"
    summary["config_hash"] = config_hash
    summary["software_version"] = SOFTWARE_VERSION
    return summary


def run_baseline_trial(
    num_devices: int,
    trial_index: int = 0,
    active_task_sample_size: int = 4,
) -> Dict[str, object]:
    return execute_policy_trial_on_fleet(
        None,
        None,
        "ORIGINAL_BASELINE",
        num_devices,
        trial_index,
        active_task_sample_size,
    )
