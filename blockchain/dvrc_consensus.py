from __future__ import annotations
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from config.blockchain_config import BlockchainConfig


@dataclass
class ReputationProfile:
    participant_id: str
    role: str
    data_accuracy_da: float = 80.0
    reliability_re: float = 80.0
    behavior_conduct_ds: float = 80.0
    feedback_rating_fs: float = 80.0
    consensus_request_count_crc: int = 0
    successful_consensus_count_scc: int = 0
    avg_response_time_ms_crt: float = 15.0
    correct_feedback_num: int = 0
    error_count_mis: int = 0
    reputation_score: float = 75.0
    trust_state: str = "ACTIVE"
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, object]:
        return {
            "participant_id": self.participant_id,
            "role": self.role,
            "data_accuracy_da": round(self.data_accuracy_da, 2),
            "reliability_re": round(self.reliability_re, 2),
            "behavior_conduct_ds": round(self.behavior_conduct_ds, 2),
            "feedback_rating_fs": round(self.feedback_rating_fs, 2),
            "consensus_request_count_crc": self.consensus_request_count_crc,
            "successful_consensus_count_scc": self.successful_consensus_count_scc,
            "avg_response_time_ms_crt": round(self.avg_response_time_ms_crt, 2),
            "correct_feedback_num": self.correct_feedback_num,
            "error_count_mis": self.error_count_mis,
            "reputation_score": round(self.reputation_score, 2),
            "trust_state": self.trust_state,
        }


@dataclass(frozen=True)
class ValidatorVote:
    validator_id: str
    block_candidate_hash: str
    approved: bool
    reputation_weight: float
    signature: str
    timestamp: float
    reason: str = "VALID"


@dataclass(frozen=True)
class ConsensusRoundResult:
    round_id: str
    block_candidate_hash: str
    reached_consensus: bool
    proposer_node_id: str
    participating_validators: List[str]
    weighted_approval_ratio: float
    dynamic_threshold_used: float
    votes: List[ValidatorVote]
    consensus_latency_ms: float
    reason: str


class DVRCConsensusEngine:

    def __init__(self, config: Optional[BlockchainConfig] = None) -> None:
        self.config = config or BlockchainConfig()
        self.profiles: Dict[str, ReputationProfile] = {}
        self._validator_secrets: Dict[str, bytes] = {}
        self._offline_validators: set[str] = set()
        self._byzantine_validators: set[str] = set()

        for idx, node_id in enumerate(self.config.validator_node_ids):
            self._validator_secrets[node_id] = secrets.token_bytes(32)
            base_rep = 88.0 - (idx * 2.5)
            self.profiles[node_id] = ReputationProfile(
                participant_id=node_id,
                role="VALIDATOR",
                data_accuracy_da=92.0,
                reliability_re=90.0,
                behavior_conduct_ds=90.0,
                feedback_rating_fs=88.0,
                reputation_score=base_rep,
                trust_state="ACTIVE",
            )

    def register_participant(
        self,
        participant_id: str,
        role: str = "IOT_DEVICE",
        initial_score: Optional[float] = None,
    ) -> ReputationProfile:
        score = (
            initial_score
            if initial_score is not None
            else self.config.initial_reputation_score
        )
        profile = ReputationProfile(
            participant_id=participant_id,
            role=role,
            reputation_score=score,
            trust_state=self._classify_state(score),
        )
        self.profiles[participant_id] = profile
        if role == "VALIDATOR" and participant_id not in self._validator_secrets:
            self._validator_secrets[participant_id] = secrets.token_bytes(32)
        return profile

    def _classify_state(self, score: float) -> str:
        if score < self.config.isolation_reputation_threshold:
            return "ISOLATED"
        if score < self.config.suspicious_reputation_threshold:
            return "MONITOR"
        return "ACTIVE"

    def compute_consensus_contribution_cs(self, profile: ReputationProfile) -> float:
        if profile.consensus_request_count_crc <= 0:
            return 75.0
        success_ratio = min(
            1.0,
            profile.successful_consensus_count_scc
            / max(1, profile.consensus_request_count_crc),
        )
        crt_factor = max(0.0, 1.0 - (profile.avg_response_time_ms_crt / 200.0))
        return 100.0 * (0.7 * success_ratio + 0.3 * crt_factor)

    def update_reputation(
        self,
        participant_id: str,
        success: bool,
        response_time_ms: float = 12.0,
        severity_multiplier: float = 1.0,
    ) -> ReputationProfile:
        if participant_id not in self.profiles:
            self.register_participant(participant_id)
        prof = self.profiles[participant_id]
        now = time.time()
        elapsed_idle = max(0.0, now - prof.last_updated)

        prof.consensus_request_count_crc += 1
        prof.avg_response_time_ms_crt = (
            0.8 * prof.avg_response_time_ms_crt + 0.2 * response_time_ms
        )

        if success:
            prof.successful_consensus_count_scc += 1
            prof.correct_feedback_num += 1
            prof.data_accuracy_da = min(100.0, prof.data_accuracy_da + 0.4)
            prof.reliability_re = min(100.0, prof.reliability_re + 0.3)
        else:
            prof.error_count_mis += 1
            prof.data_accuracy_da = max(
                0.0, prof.data_accuracy_da - 4.0 * severity_multiplier
            )
            prof.reliability_re = max(
                0.0, prof.reliability_re - 5.0 * severity_multiplier
            )
            prof.behavior_conduct_ds = max(
                0.0, prof.behavior_conduct_ds - 4.5 * severity_multiplier
            )

        cs_val = self.compute_consensus_contribution_cs(prof)
        base_weighted = (
            self.config.weight_da * prof.data_accuracy_da
            + self.config.weight_re * prof.reliability_re
            + self.config.weight_ds * prof.behavior_conduct_ds
            + self.config.weight_fs * prof.feedback_rating_fs
            + self.config.weight_cs * cs_val
        )

        net_adjustment = (
            self.config.reward_phi * prof.correct_feedback_num
            - self.config.penalty_delta_w * prof.error_count_mis * severity_multiplier
            - self.config.inactivity_decay_rate * min(elapsed_idle, 60.0)
        )

        new_score = max(0.0, min(100.0, base_weighted + net_adjustment))
        prof.reputation_score = new_score
        prof.trust_state = self._classify_state(new_score)
        prof.last_updated = now
        return prof

    def get_allowed_request_quota(
        self, participant_id: str, base_quota: int = 25
    ) -> int:
        prof = self.profiles.get(participant_id)
        if prof is None:
            return base_quota
        if prof.trust_state in ("ISOLATED", "REVOKED"):
            return 0
        if prof.trust_state == "MONITOR":
            return max(2, base_quota // 4)
        return int(base_quota * (prof.reputation_score / 75.0))

    def compute_dynamic_consensus_threshold(self) -> float:
        active_scores = [
            p.reputation_score
            for nid, p in self.profiles.items()
            if p.role == "VALIDATOR" and nid not in self._offline_validators
        ]
        if not active_scores:
            return self.config.consensus_reputation_threshold
        mean_rep = sum(active_scores) / len(active_scores)
        return max(
            self.config.suspicious_reputation_threshold,
            min(self.config.consensus_reputation_threshold, 0.75 * mean_rep),
        )

    def select_high_reputation_committee(self) -> Tuple[str, List[str], float]:
        dyn_threshold = self.compute_dynamic_consensus_threshold()
        eligible = [
            p
            for nid, p in self.profiles.items()
            if p.role == "VALIDATOR"
            and nid not in self._offline_validators
            and p.reputation_score >= dyn_threshold
            and p.trust_state == "ACTIVE"
        ]
        eligible.sort(key=lambda x: x.reputation_score, reverse=True)
        if not eligible:
            raise RuntimeError(
                "DVRC Consensus Failure: No eligible high-reputation validators online."
            )
        proposer = eligible[0].participant_id
        committee = [p.participant_id for p in eligible]
        return proposer, committee, dyn_threshold

    def set_validator_fault_state(
        self, validator_id: str, offline: bool = False, byzantine: bool = False
    ) -> None:
        if offline:
            self._offline_validators.add(validator_id)
        else:
            self._offline_validators.discard(validator_id)
        if byzantine:
            self._byzantine_validators.add(validator_id)
        else:
            self._byzantine_validators.discard(validator_id)

    def execute_consensus_round(
        self,
        block_candidate_hash: str,
        transactions_valid: bool,
        invalid_sender_ids: Optional[List[str]] = None,
    ) -> ConsensusRoundResult:
        t0 = time.perf_counter()
        round_id = secrets.token_hex(8)
        try:
            proposer, committee, dyn_threshold = self.select_high_reputation_committee()
        except RuntimeError as exc:
            return ConsensusRoundResult(
                round_id=round_id,
                block_candidate_hash=block_candidate_hash,
                reached_consensus=False,
                proposer_node_id="none",
                participating_validators=[],
                weighted_approval_ratio=0.0,
                dynamic_threshold_used=self.config.consensus_reputation_threshold,
                votes=[],
                consensus_latency_ms=(time.perf_counter() - t0) * 1000.0,
                reason=str(exc),
            )

        votes: List[ValidatorVote] = []
        total_weight = 0.0
        approved_weight = 0.0

        for val_id in committee:
            prof = self.profiles[val_id]
            weight = prof.reputation_score
            is_byzantine = val_id in self._byzantine_validators

            if is_byzantine:
                vote_approve = not transactions_valid
                vote_reason = "BYZANTINE_CONFLICTING_VOTE"
            else:
                vote_approve = transactions_valid
                vote_reason = (
                    "VALID_BLOCK" if transactions_valid else "INVALID_TX_DETECTED"
                )

            msg = f"{val_id}|{block_candidate_hash}|{vote_approve}|{weight:.2f}".encode(
                "utf-8"
            )
            sig = hmac.new(
                self._validator_secrets[val_id], msg, hashlib.sha256
            ).hexdigest()

            votes.append(
                ValidatorVote(
                    validator_id=val_id,
                    block_candidate_hash=block_candidate_hash,
                    approved=vote_approve,
                    reputation_weight=weight,
                    signature=sig,
                    timestamp=time.time(),
                    reason=vote_reason,
                )
            )
            total_weight += weight
            if vote_approve:
                approved_weight += weight

            if is_byzantine:
                self.update_reputation(val_id, success=False, severity_multiplier=1.5)
            else:
                self.update_reputation(val_id, success=True, response_time_ms=8.0)

        for bad_sender in invalid_sender_ids or []:
            self.update_reputation(bad_sender, success=False, severity_multiplier=1.2)

        approval_ratio = (approved_weight / total_weight) if total_weight > 0 else 0.0
        reached = transactions_valid and (approval_ratio >= self.config.quorum_ratio)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        return ConsensusRoundResult(
            round_id=round_id,
            block_candidate_hash=block_candidate_hash,
            reached_consensus=reached,
            proposer_node_id=proposer,
            participating_validators=committee,
            weighted_approval_ratio=approval_ratio,
            dynamic_threshold_used=dyn_threshold,
            votes=votes,
            consensus_latency_ms=latency_ms,
            reason=(
                "DVRC quorum reached" if reached else "DVRC validation or quorum failed"
            ),
        )
