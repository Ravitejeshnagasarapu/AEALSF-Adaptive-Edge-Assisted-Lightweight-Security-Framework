from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional

from cryptography.key_manager import (
    DeviceWalletCredentials,
    KeyManager,
    PublicDeviceIdentity,
)
from cryptography.nizk_authentication import AuthenticatedSessionToken


@dataclass
class DeviceIdentityWallet:
    device_id: str
    device_name: str
    hardware_model: str
    credentials: DeviceWalletCredentials
    onchain_unique_id_hash: Optional[str] = None
    active_session_token: Optional[AuthenticatedSessionToken] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def wallet_address(self) -> str:
        return self.credentials.blockchain_address

    def get_public_identity(self) -> PublicDeviceIdentity:
        return self.credentials.export_public_identity()

    @classmethod
    def create(
        cls,
        key_manager: KeyManager,
        device_id: str,
        device_name: str = "ML307A Module",
        hardware_model: str = "L610-CN",
    ) -> DeviceIdentityWallet:
        creds = key_manager.provision_device_wallet(device_id)
        return cls(
            device_id=device_id,
            device_name=device_name,
            hardware_model=hardware_model,
            credentials=creds,
        )
