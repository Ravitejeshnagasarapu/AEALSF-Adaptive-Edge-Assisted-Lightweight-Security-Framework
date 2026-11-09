from __future__ import annotations
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from blockchain.blockchain_client import BlockchainClient
from cryptography.key_manager import KeyManager
from cryptography.verification import ReplayProtectionRegistry


@dataclass(frozen=True)
class EdgeAuthHandshake:
    handshake_id: str
    device_id: str
    edge_node_id: str
    device_challenge_nonce: str
    edge_challenge_nonce: str
    edge_signature: str
    device_signature: str
    established_at: float
    expires_at: float
    verified: bool


class EdgeMutualAuthenticator:

    def __init__(
        self,
        key_manager: KeyManager,
        blockchain_client: BlockchainClient,
        session_ttl_seconds: float = 300.0,
    ) -> None:
        self.key_manager = key_manager
        self.blockchain_client = blockchain_client
        self.session_ttl_seconds = session_ttl_seconds
        self.replay_registry = ReplayProtectionRegistry(ttl_seconds=120.0)
        self._active_handshakes: dict[Tuple[str, str], EdgeAuthHandshake] = {}

    def perform_mutual_handshake(
        self,
        device_id: str,
        edge_node_id: str,
        forged_edge_signature: Optional[str] = None,
        forged_device_signature: Optional[str] = None,
    ) -> Tuple[bool, Optional[EdgeAuthHandshake], str]:
        now = time.time()

        edge_auth_check = self.blockchain_client.contracts.invoke(
            contract_name="SecurityManager",
            method_name="isEdgeNodeAuthorized",
            caller_device_id=device_id,
            caller_address="0x0",
            args={"edgeNodeId": edge_node_id},
        )
        if not edge_auth_check.return_data.get("authorized", False):
            return (
                False,
                None,
                f"Edge node {edge_node_id} is not authorized in SecurityManager.",
            )

        dev_auth_check = self.blockchain_client.contracts.invoke(
            contract_name="SecurityManager",
            method_name="isDeviceAuthenticated",
            caller_device_id=device_id,
            caller_address="0x0",
            args={"deviceId": device_id},
        )
        if not dev_auth_check.return_data.get("authenticated", False):
            return (
                False,
                None,
                f"IoT device {device_id} lacks active NIZK authentication.",
            )

        dev_nonce = secrets.token_hex(12)
        edge_nonce = secrets.token_hex(12)

        edge_Transcript = f"EDGE_AUTH|{edge_node_id}|{device_id}|{dev_nonce}|{edge_nonce}|{now:.3f}".encode(
            "utf-8"
        )
        dev_Transcript = f"DEV_AUTH|{device_id}|{edge_node_id}|{edge_nonce}|{dev_nonce}|{now:.3f}".encode(
            "utf-8"
        )

        try:
            edge_sig = (
                forged_edge_signature
                if forged_edge_signature is not None
                else self.key_manager.sign_as_edge_node(edge_node_id, edge_Transcript)
            )
            wallet = self.key_manager.get_device_wallet(device_id)
            dev_sig = (
                forged_device_signature
                if forged_device_signature is not None
                else wallet.sign_message(dev_Transcript)
            )
        except KeyError as exc:
            return False, None, f"Credential lookup error during handshake: {exc}"

        if not self.key_manager.verify_edge_node_signature(
            edge_node_id, edge_Transcript, edge_sig
        ):
            return (
                False,
                None,
                f"Edge node {edge_node_id} failed signature verification.",
            )

        if not self.key_manager.verify_device_signature(
            device_id, dev_Transcript, dev_sig
        ):
            return (
                False,
                None,
                f"Device {device_id} failed signature verification at edge.",
            )

        handshake = EdgeAuthHandshake(
            handshake_id=secrets.token_hex(10),
            device_id=device_id,
            edge_node_id=edge_node_id,
            device_challenge_nonce=dev_nonce,
            edge_challenge_nonce=edge_nonce,
            edge_signature=edge_sig,
            device_signature=dev_sig,
            established_at=now,
            expires_at=now + self.session_ttl_seconds,
            verified=True,
        )
        self._active_handshakes[(device_id, edge_node_id)] = handshake
        return True, handshake, "Mutual device-edge authentication succeeded."

    def has_valid_session(self, device_id: str, edge_node_id: str) -> bool:
        hs = self._active_handshakes.get((device_id, edge_node_id))
        if hs is None:
            return False
        return hs.verified and (time.time() <= hs.expires_at)
