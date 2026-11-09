from __future__ import annotations
from typing import Dict, List, Tuple

from blockchain.transaction_manager import Block, TransactionManager
from cryptography.verification import CryptographicVerifier


class BlockchainIntegrityVerifier:

    def __init__(self, tx_manager: TransactionManager) -> None:
        self.tx_manager = tx_manager

    def verify_chain(self, chain: List[Block]) -> Tuple[bool, str]:
        if not chain:
            return False, "Blockchain is empty (missing genesis block)."

        for idx, blk in enumerate(chain):
            if blk.block_height != idx:
                return False, f"Block height mismatch at index {idx}."

            if idx == 0:
                if blk.previous_hash != "0" * 64:
                    return False, "Genesis block previous_hash is invalid."
            else:
                if blk.previous_hash != chain[idx - 1].block_hash:
                    return False, f"Broken hash chain linkage at block {idx}."

            tx_hashes = [
                CryptographicVerifier.sha256_hex(tx.compute_canonical_bytes())
                for tx in blk.transactions
            ]
            expected_merkle = CryptographicVerifier.compute_merkle_root(tx_hashes)
            if blk.merkle_root != expected_merkle:
                return False, f"Merkle root mismatch at block {idx}."

            expected_block_hash = Block.compute_block_hash(
                block_height=blk.block_height,
                previous_hash=blk.previous_hash,
                merkle_root=blk.merkle_root,
                proposer_node_id=blk.proposer_node_id,
                timestamp=blk.timestamp,
                dvrc_round_id=blk.dvrc_round_id,
            )
            if blk.block_hash != expected_block_hash:
                return False, f"Tampered block header hash at block {idx}."

            for tx in blk.transactions:
                valid, msg = self.tx_manager.validate_transaction(
                    tx, record_nonce=False
                )
                if not valid:
                    return (
                        False,
                        f"Invalid transaction {tx.tx_id} in block {idx}: {msg}",
                    )

        return (
            True,
            f"Verified {len(chain)} blocks with {sum(len(b.transactions) for b in chain)} transactions.",
        )

    @staticmethod
    def verify_offchain_result_integrity(
        raw_result_bytes: bytes, onchain_result_hash: str
    ) -> bool:
        computed = CryptographicVerifier.sha256_hex(raw_result_bytes)
        return computed == onchain_result_hash
