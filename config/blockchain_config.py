from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class BlockchainConfig:
    validator_node_ids: List[str] = field(
        default_factory=lambda: os.getenv(
            "AEALSF_BLOCKCHAIN_NODES", "node0,node1,node2,node3"
        ).split(",")
    )
    initial_reputation_score: float = field(
        default_factory=lambda: float(
            os.getenv("AEALSF_DVRC_INITIAL_REPUTATION", "75.0")
        )
    )
    consensus_reputation_threshold: float = field(
        default_factory=lambda: float(
            os.getenv("AEALSF_DVRC_REPUTATION_THRESHOLD", "60.0")
        )
    )
    suspicious_reputation_threshold: float = 40.0
    isolation_reputation_threshold: float = 25.0

    reward_phi: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_DVRC_REWARD_PHI", "0.8"))
    )
    penalty_delta_w: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_DVRC_PENALTY_DELTA_W", "8.5"))
    )
    inactivity_decay_rate: float = 0.01

    weight_da: float = 0.25
    weight_re: float = 0.25
    weight_ds: float = 0.15
    weight_fs: float = 0.15
    weight_cs: float = 0.20

    max_transactions_per_block: int = 250
    block_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("AEALSF_BLOCK_INTERVAL_SEC", "0.4"))
    )
    quorum_ratio: float = 0.67
