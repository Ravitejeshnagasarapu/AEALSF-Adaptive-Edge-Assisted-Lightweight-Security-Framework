from __future__ import annotations
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional

from cryptography.nizk_authentication import (
    ECSchnorrKeyPair,
    NIZKAuthenticator,
    NIZKKeyPair,
)
from cryptography.homomorphic_encryption import (
    ECElGamalHomomorphicEngine,
    ECElGamalKeyPair,
    ECPoint,
)


@dataclass(frozen=True)
class PublicDeviceIdentity:
    device_id: str
    blockchain_address: str
    nizk_public_key: int
    nizk_pk_fingerprint: str
    he_public_key: ECPoint
    public_signing_token: str
    ec_schnorr_public_key: Optional[ECPoint] = None
    ec_schnorr_pk_fingerprint: str = ""


@dataclass
class DeviceWalletCredentials:
    device_id: str
    blockchain_address: str
    nizk_keypair: NIZKKeyPair
    he_keypair: ECElGamalKeyPair
    _signing_secret: bytes = field(repr=False)
    ec_schnorr_keypair: Optional[ECSchnorrKeyPair] = None
    registered_contracts: Dict[str, str] = field(default_factory=dict)

    @property
    def public_signing_token(self) -> str:
        return hashlib.sha256(self._signing_secret).hexdigest()

    def sign_message(self, message: bytes) -> str:
        return hmac.new(self._signing_secret, message, hashlib.sha256).hexdigest()

    def export_public_identity(self) -> PublicDeviceIdentity:
        return PublicDeviceIdentity(
            device_id=self.device_id,
            blockchain_address=self.blockchain_address,
            nizk_public_key=self.nizk_keypair.public_key_pk,
            nizk_pk_fingerprint=self.nizk_keypair.pk_fingerprint,
            he_public_key=self.he_keypair.public_key_q,
            public_signing_token=self.public_signing_token,
            ec_schnorr_public_key=(
                self.ec_schnorr_keypair.public_key_pk
                if self.ec_schnorr_keypair
                else None
            ),
            ec_schnorr_pk_fingerprint=(
                self.ec_schnorr_keypair.pk_fingerprint
                if self.ec_schnorr_keypair
                else ""
            ),
        )


class KeyManager:

    def __init__(
        self,
        nizk_auth: Optional[NIZKAuthenticator] = None,
        he_engine: Optional[ECElGamalHomomorphicEngine] = None,
    ) -> None:
        self.nizk_auth = nizk_auth or NIZKAuthenticator()
        self.he_engine = he_engine or ECElGamalHomomorphicEngine()
        self._device_wallets: Dict[str, DeviceWalletCredentials] = {}
        self._public_directory: Dict[str, PublicDeviceIdentity] = {}
        self._edge_secrets: Dict[str, bytes] = {}
        self._edge_public_tokens: Dict[str, str] = {}

    def provision_device_wallet(self, device_id: str) -> DeviceWalletCredentials:
        if not device_id or not device_id.strip():
            raise ValueError("device_id must be a non-empty string.")
        nizk_kp = self.nizk_auth.generate_keypair(device_id)
        ec_schnorr_kp = self.nizk_auth.ec_schnorr.generate_keypair(device_id)
        he_kp = self.he_engine.generate_keypair(device_id)
        signing_secret = secrets.token_bytes(32)

        addr_hash = hashlib.sha256(
            f"{device_id}|{nizk_kp.pk_fingerprint}|{he_kp.public_key_q.x}".encode(
                "utf-8"
            )
        ).hexdigest()
        blockchain_address = "0x" + addr_hash[:40]

        wallet = DeviceWalletCredentials(
            device_id=device_id,
            blockchain_address=blockchain_address,
            nizk_keypair=nizk_kp,
            he_keypair=he_kp,
            _signing_secret=signing_secret,
            ec_schnorr_keypair=ec_schnorr_kp,
        )
        self._device_wallets[device_id] = wallet
        self._public_directory[device_id] = wallet.export_public_identity()
        return wallet

    def get_device_wallet(self, device_id: str) -> DeviceWalletCredentials:
        if device_id not in self._device_wallets:
            raise KeyError(f"Unknown or unprovisioned device wallet: {device_id}")
        return self._device_wallets[device_id]

    def get_public_identity(self, device_id: str) -> Optional[PublicDeviceIdentity]:
        return self._public_directory.get(device_id)

    def verify_device_signature(
        self, device_id: str, message: bytes, signature: str
    ) -> bool:
        wallet = self._device_wallets.get(device_id)
        if wallet is None:
            return False
        expected = wallet.sign_message(message)
        return hmac.compare_digest(expected, signature)

    def register_edge_node(self, edge_node_id: str) -> str:
        secret = secrets.token_bytes(32)
        pub_token = hashlib.sha256(secret).hexdigest()
        self._edge_secrets[edge_node_id] = secret
        self._edge_public_tokens[edge_node_id] = pub_token
        return pub_token

    def sign_as_edge_node(self, edge_node_id: str, message: bytes) -> str:
        if edge_node_id not in self._edge_secrets:
            raise KeyError(f"Edge node {edge_node_id} is not registered in KeyManager.")
        return hmac.new(
            self._edge_secrets[edge_node_id], message, hashlib.sha256
        ).hexdigest()

    def verify_edge_node_signature(
        self, edge_node_id: str, message: bytes, signature: str
    ) -> bool:
        secret = self._edge_secrets.get(edge_node_id)
        if secret is None:
            return False
        expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
