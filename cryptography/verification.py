
from __future__ import annotations
import hashlib
import time
from typing import Dict, List, Tuple


class ReplayProtectionRegistry:

    def __init__(self, ttl_seconds: float = 60.0, max_entries: int = 50000) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._seen: Dict[str, float] = {}

    def validate_and_record(
        self, sender_id: str, nonce: str, timestamp: float
    ) -> Tuple[bool, str]:
        now = time.time()
        if abs(now - timestamp) > self.ttl_seconds:
            return False, f"Timestamp outside allowed window ({self.ttl_seconds}s)."
        composite = f"{sender_id}:{nonce}"
        if composite in self._seen:
            return False, f"Replay detected for sender={sender_id}, nonce={nonce}."
        if len(self._seen) >= self.max_entries:
            cutoff = now - self.ttl_seconds
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
        self._seen[composite] = now
        return True, "Fresh request verified."


class CryptographicVerifier:

    @staticmethod
    def sha256_hex(data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def compute_merkle_root(cls, leaf_hashes: List[str]) -> str:
        if not leaf_hashes:
            return cls.sha256_hex(b"EMPTY_MERKLE_TREE")
        current_level = list(leaf_hashes)
        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                combined = f"{current_level[i]}|{current_level[i + 1]}"
                next_level.append(cls.sha256_hex(combined))
            current_level = next_level
        return current_level[0]

    @staticmethod
    def shannon_entropy_bits_per_byte(data: bytes) -> float:
        if not data:
            return 0.0
        import math
        counts: Dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        n = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy
