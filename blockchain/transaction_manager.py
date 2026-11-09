from __future__ import annotations
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.key_manager import KeyManager
from cryptography.verification import CryptographicVerifier, ReplayProtectionRegistry


@dataclass(frozen=True)
class BlockchainTransaction:
    tx_id: str
    sender_device_id: str
    sender_wallet_address: str
    contract_name: str
    method_name: str
    tx_type: str
    payload: Dict[str, object]
    nonce: str
    timestamp: float
    signature: str
    payload_hash: str

    def compute_canonical_bytes(self) -> bytes:
        body = {
            "tx_id": self.tx_id,
            "sender_device_id": self.sender_device_id,
            "sender_wallet_address": self.sender_wallet_address,
            "contract_name": self.contract_name,
            "method_name": self.method_name,
            "tx_type": self.tx_type,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": round(self.timestamp, 6),
            "payload_hash": self.payload_hash,
        }
        return json.dumps(body, sort_keys=True).encode("utf-8")

    def to_dict(self) -> Dict[str, object]:
        return {
            "tx_id": self.tx_id,
            "sender_device_id": self.sender_device_id,
            "sender_wallet_address": self.sender_wallet_address,
            "contract_name": self.contract_name,
            "method_name": self.method_name,
            "tx_type": self.tx_type,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "payload_hash": self.payload_hash,
        }


@dataclass(frozen=True)
class Block:
    block_height: int
    block_hash: str
    previous_hash: str
    merkle_root: str
    proposer_node_id: str
    timestamp: float
    transactions: List[BlockchainTransaction]
    dvrc_round_id: str
    dvrc_approval_ratio: float
    validator_signatures: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def compute_block_hash(
        block_height: int,
        previous_hash: str,
        merkle_root: str,
        proposer_node_id: str,
        timestamp: float,
        dvrc_round_id: str,
    ) -> str:
        header = (
            f"{block_height}|{previous_hash}|{merkle_root}|"
            f"{proposer_node_id}|{timestamp:.6f}|{dvrc_round_id}"
        )
        return hashlib.sha256(header.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, object]:
        return {
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "proposer_node_id": self.proposer_node_id,
            "timestamp": self.timestamp,
            "tx_count": len(self.transactions),
            "dvrc_round_id": self.dvrc_round_id,
            "dvrc_approval_ratio": round(self.dvrc_approval_ratio, 4),
            "validator_signatures": self.validator_signatures,
        }


class TransactionManager:

    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager
        self.replay_registry = ReplayProtectionRegistry(ttl_seconds=120.0)
        self.pending_pool: List[BlockchainTransaction] = []
        self.committed_tx_index: Dict[str, Tuple[int, BlockchainTransaction]] = {}

    def create_signed_transaction(
        self,
        sender_device_id: str,
        contract_name: str,
        method_name: str,
        payload: Dict[str, object],
        tx_type: str = "SET",
        custom_nonce: Optional[str] = None,
        custom_timestamp: Optional[float] = None,
    ) -> BlockchainTransaction:
        wallet = self.key_manager.get_device_wallet(sender_device_id)
        tx_id = "0x" + secrets.token_hex(16)
        nonce = custom_nonce if custom_nonce is not None else secrets.token_hex(12)
        ts = custom_timestamp if custom_timestamp is not None else time.time()
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_hash = CryptographicVerifier.sha256_hex(payload_bytes)

        unsigned_tx = BlockchainTransaction(
            tx_id=tx_id,
            sender_device_id=sender_device_id,
            sender_wallet_address=wallet.blockchain_address,
            contract_name=contract_name,
            method_name=method_name,
            tx_type=tx_type,
            payload=payload,
            nonce=nonce,
            timestamp=ts,
            signature="",
            payload_hash=payload_hash,
        )
        sig = wallet.sign_message(unsigned_tx.compute_canonical_bytes())
        return BlockchainTransaction(
            tx_id=tx_id,
            sender_device_id=sender_device_id,
            sender_wallet_address=wallet.blockchain_address,
            contract_name=contract_name,
            method_name=method_name,
            tx_type=tx_type,
            payload=payload,
            nonce=nonce,
            timestamp=ts,
            signature=sig,
            payload_hash=payload_hash,
        )

    def validate_transaction(
        self, tx: BlockchainTransaction, record_nonce: bool = True
    ) -> Tuple[bool, str]:
        pub_id = self.key_manager.get_public_identity(tx.sender_device_id)
        if pub_id is None:
            return (
                False,
                f"Sender device {tx.sender_device_id} has no provisioned wallet.",
            )
        if pub_id.blockchain_address != tx.sender_wallet_address:
            return (
                False,
                "Transaction wallet address does not match sender device wallet.",
            )

        expected_payload_hash = CryptographicVerifier.sha256_hex(
            json.dumps(tx.payload, sort_keys=True).encode("utf-8")
        )
        if expected_payload_hash != tx.payload_hash:
            return False, "Transaction payload hash mismatch (tampered payload)."

        if not self.key_manager.verify_device_signature(
            tx.sender_device_id, tx.compute_canonical_bytes(), tx.signature
        ):
            return False, "Invalid transaction cryptographic signature."

        if record_nonce:
            fresh, msg = self.replay_registry.validate_and_record(
                tx.sender_device_id, tx.nonce, tx.timestamp
            )
            if not fresh:
                return False, msg

        return True, "Transaction valid."
