from __future__ import annotations
import time
from typing import Dict, List, Optional, Tuple

from config.blockchain_config import BlockchainConfig
from cryptography.key_manager import KeyManager
from cryptography.verification import CryptographicVerifier
from blockchain.dvrc_consensus import DVRCConsensusEngine, ConsensusRoundResult
from blockchain.transaction_manager import (
    Block,
    BlockchainTransaction,
    TransactionManager,
)
from blockchain.smart_contract_manager import (
    ContractExecutionError,
    ContractReceipt,
    SmartContractManager,
)
from blockchain.integrity_verifier import BlockchainIntegrityVerifier


class BlockchainClient:

    def __init__(
        self,
        key_manager: KeyManager,
        config: Optional[BlockchainConfig] = None,
    ) -> None:
        self.config = config or BlockchainConfig()
        self.key_manager = key_manager
        self.dvrc = DVRCConsensusEngine(self.config)
        self.tx_manager = TransactionManager(key_manager)
        self.contracts = SmartContractManager(admin_device_id="system-governance-admin")
        self.integrity_verifier = BlockchainIntegrityVerifier(self.tx_manager)
        self.chain: List[Block] = []
        self.offchain_storage: Dict[str, bytes] = {}

        self.key_manager.provision_device_wallet("system-governance-admin")
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        ts = time.time()
        merkle = CryptographicVerifier.compute_merkle_root([])
        b_hash = Block.compute_block_hash(
            block_height=0,
            previous_hash="0" * 64,
            merkle_root=merkle,
            proposer_node_id=self.config.validator_node_ids[0],
            timestamp=ts,
            dvrc_round_id="genesis-round",
        )
        genesis = Block(
            block_height=0,
            block_hash=b_hash,
            previous_hash="0" * 64,
            merkle_root=merkle,
            proposer_node_id=self.config.validator_node_ids[0],
            timestamp=ts,
            transactions=[],
            dvrc_round_id="genesis-round",
            dvrc_approval_ratio=1.0,
        )
        self.chain.append(genesis)

    def submit_and_execute_transaction(
        self,
        tx: BlockchainTransaction,
        auto_commit_block: bool = True,
    ) -> Tuple[bool, Optional[ContractReceipt], Optional[ConsensusRoundResult], str]:
        t0 = time.perf_counter()

        tx_valid, tx_msg = self.tx_manager.validate_transaction(tx, record_nonce=True)
        if not tx_valid:
            round_res = self.dvrc.execute_consensus_round(
                block_candidate_hash=tx.payload_hash,
                transactions_valid=False,
                invalid_sender_ids=[tx.sender_device_id],
            )
            return False, None, round_res, f"Transaction validation failed: {tx_msg}"

        try:
            receipt = self.contracts.invoke(
                contract_name=tx.contract_name,
                method_name=tx.method_name,
                caller_device_id=tx.sender_device_id,
                caller_address=tx.sender_wallet_address,
                args=tx.payload,
            )
        except ContractExecutionError as exc:
            self.dvrc.update_reputation(
                tx.sender_device_id, success=False, severity_multiplier=1.0
            )
            return False, None, None, str(exc)

        if tx.tx_type == "GET" or not auto_commit_block:
            self.dvrc.update_reputation(
                tx.sender_device_id,
                success=True,
                response_time_ms=(time.perf_counter() - t0) * 1000.0,
            )
            return True, receipt, None, "Query executed."

        self.tx_manager.pending_pool.append(tx)
        block_ok, round_res, blk_msg = self.commit_pending_block()
        if not block_ok:
            return False, receipt, round_res, blk_msg

        self.dvrc.update_reputation(
            tx.sender_device_id,
            success=True,
            response_time_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return True, receipt, round_res, "Transaction committed via DVRC consensus."

    def commit_pending_block(self) -> Tuple[bool, ConsensusRoundResult, str]:
        batch = list(
            self.tx_manager.pending_pool[: self.config.max_transactions_per_block]
        )
        if not batch:
            raise RuntimeError("No pending transactions to commit.")

        tx_hashes = [
            CryptographicVerifier.sha256_hex(t.compute_canonical_bytes()) for t in batch
        ]
        merkle_root = CryptographicVerifier.compute_merkle_root(tx_hashes)
        prev_hash = self.chain[-1].block_hash
        candidate_hash = CryptographicVerifier.sha256_hex(f"{prev_hash}|{merkle_root}")

        round_res = self.dvrc.execute_consensus_round(
            block_candidate_hash=candidate_hash,
            transactions_valid=True,
        )
        if not round_res.reached_consensus:
            return False, round_res, round_res.reason

        ts = time.time()
        height = len(self.chain)
        final_hash = Block.compute_block_hash(
            block_height=height,
            previous_hash=prev_hash,
            merkle_root=merkle_root,
            proposer_node_id=round_res.proposer_node_id,
            timestamp=ts,
            dvrc_round_id=round_res.round_id,
        )
        val_sigs = {v.validator_id: v.signature for v in round_res.votes if v.approved}
        new_block = Block(
            block_height=height,
            block_hash=final_hash,
            previous_hash=prev_hash,
            merkle_root=merkle_root,
            proposer_node_id=round_res.proposer_node_id,
            timestamp=ts,
            transactions=batch,
            dvrc_round_id=round_res.round_id,
            dvrc_approval_ratio=round_res.weighted_approval_ratio,
            validator_signatures=val_sigs,
        )
        self.chain.append(new_block)
        for t in batch:
            self.tx_manager.committed_tx_index[t.tx_id] = (height, t)
        del self.tx_manager.pending_pool[: len(batch)]
        return True, round_res, f"Committed block #{height} ({final_hash[:12]}...)"

    def store_offchain_result(self, task_id: str, result_bytes: bytes) -> str:
        result_hash = CryptographicVerifier.sha256_hex(result_bytes)
        self.offchain_storage[task_id] = result_bytes
        return result_hash

    def retrieve_and_verify_offchain_result(
        self, task_id: str, caller_device_id: str
    ) -> bytes:
        if task_id not in self.offchain_storage:
            raise KeyError(f"Off-chain result for task {task_id} not found.")
        raw_bytes = self.offchain_storage[task_id]
        candidate_hash = CryptographicVerifier.sha256_hex(raw_bytes)

        wallet = self.key_manager.get_device_wallet(caller_device_id)
        receipt = self.contracts.invoke(
            contract_name="TaskManagement",
            method_name="verifyRetrievedResult",
            caller_device_id=caller_device_id,
            caller_address=wallet.blockchain_address,
            args={"taskId": task_id, "candidateResultHash": candidate_hash},
        )
        if not receipt.return_data.get("verified", False):
            raise ValueError(
                f"Off-chain result integrity verification failed for task {task_id}!"
            )
        return raw_bytes
