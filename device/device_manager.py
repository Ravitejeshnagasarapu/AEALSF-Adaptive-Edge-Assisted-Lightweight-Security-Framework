from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

from adaptive_engine.decision_engine import AdaptiveDecisionEngine
from blockchain.blockchain_client import BlockchainClient
from config.settings import HardwareProfile, L610_CN_PROFILE, ML307A_PROFILE
from cryptography.encryption_service import EncryptionService
from cryptography.homomorphic_encryption import ECElGamalHomomorphicEngine
from cryptography.key_manager import KeyManager
from cryptography.nizk_authentication import NIZKAuthenticator
from device.device_identity import DeviceIdentityWallet
from device.local_security import DeviceLocalSecurityEngine
from device.resource_monitor import DeviceResourceMonitor
from device.task_manager import DeviceTaskManager
from edge.edge_server import EdgeClusterManager
from monitoring.energy_estimator import EnergyEstimator
from monitoring.performance_monitor import PerformanceMonitor


@dataclass
class IoTDevice:
    device_id: str
    wallet: DeviceIdentityWallet
    resource_monitor: DeviceResourceMonitor
    local_security: DeviceLocalSecurityEngine
    task_manager: DeviceTaskManager


class DeviceManager:

    def __init__(
        self,
        key_manager: KeyManager,
        nizk_auth: NIZKAuthenticator,
        he_engine: ECElGamalHomomorphicEngine,
        encryption_service: EncryptionService,
        blockchain_client: BlockchainClient,
        edge_cluster: EdgeClusterManager,
        decision_engine: AdaptiveDecisionEngine,
        perf_monitor: PerformanceMonitor,
    ) -> None:
        self.key_manager = key_manager
        self.nizk_auth = nizk_auth
        self.he_engine = he_engine
        self.encryption_service = encryption_service
        self.blockchain_client = blockchain_client
        self.edge_cluster = edge_cluster
        self.decision_engine = decision_engine
        self.perf_monitor = perf_monitor
        self.devices: Dict[str, IoTDevice] = {}

    def register_new_device(
        self,
        device_id: str,
        device_name: str = "ML307A Module",
        device_description: str = "IoT framework",
        hardware_model: str = "L610-CN",
        initial_cpu_percent: float = 32.0,
        initial_free_ram_kb: float = 1180.0,
        initial_battery_percent: float = 82.0,
        initial_latency_ms: float = 38.64,
        initial_bandwidth_mbps: float = 94.12,
    ) -> IoTDevice:
        profile: HardwareProfile = (
            ML307A_PROFILE if hardware_model == "ML307A" else L610_CN_PROFILE
        )
        wallet = DeviceIdentityWallet.create(
            key_manager=self.key_manager,
            device_id=device_id,
            device_name=device_name,
            hardware_model=hardware_model,
        )
        he_pk = wallet.credentials.he_keypair.public_key_q
        he_pk_hash = hashlib.sha256(f"{he_pk.x}|{he_pk.y}".encode("utf-8")).hexdigest()

        tx = self.blockchain_client.tx_manager.create_signed_transaction(
            sender_device_id=device_id,
            contract_name="DeviceRegistry",
            method_name="registerDevice",
            payload={
                "deviceId": device_id,
                "deviceName": device_name,
                "deviceDescription": device_description,
                "walletAddress": wallet.wallet_address,
                "nizkPkFingerprint": wallet.credentials.nizk_keypair.pk_fingerprint,
                "hePublicKeyHash": he_pk_hash,
            },
            tx_type="SET",
        )
        ok, receipt, _, msg = self.blockchain_client.submit_and_execute_transaction(
            tx, auto_commit_block=True
        )
        if not ok or receipt is None:
            raise RuntimeError(f"Smart contract device registration failed: {msg}")

        wallet.onchain_unique_id_hash = str(receipt.return_data["uniqueIdHash"])
        self.blockchain_client.dvrc.register_participant(device_id, role="IOT_DEVICE")

        res_mon = DeviceResourceMonitor(
            device_id=device_id,
            profile=profile,
            initial_cpu_percent=initial_cpu_percent,
            initial_free_ram_kb=initial_free_ram_kb,
            initial_battery_percent=initial_battery_percent,
            initial_latency_ms=initial_latency_ms,
            initial_bandwidth_mbps=initial_bandwidth_mbps,
        )
        loc_sec = DeviceLocalSecurityEngine(
            wallet=wallet,
            nizk_auth=self.nizk_auth,
            he_engine=self.he_engine,
            encryption_service=self.encryption_service,
        )
        energy_est = EnergyEstimator(profile=profile)
        task_mgr = DeviceTaskManager(
            wallet=wallet,
            resource_monitor=res_mon,
            local_security=loc_sec,
            blockchain_client=self.blockchain_client,
            edge_cluster=self.edge_cluster,
            decision_engine=self.decision_engine,
            perf_monitor=self.perf_monitor,
            energy_estimator=energy_est,
        )

        device = IoTDevice(
            device_id=device_id,
            wallet=wallet,
            resource_monitor=res_mon,
            local_security=loc_sec,
            task_manager=task_mgr,
        )
        self.devices[device_id] = device
        return device

    def get_device(self, device_id: str) -> Optional[IoTDevice]:
        return self.devices.get(device_id)
