from __future__ import annotations
import os
from dataclasses import dataclass, field


RFC3526_2048_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)


@dataclass
class SecurityConfig:
    nizk_prime_hex: str = RFC3526_2048_PRIME_HEX
    nizk_generator: int = 2
    nizk_proof_ttl_seconds: float = field(
        default_factory=lambda: float(
            os.getenv("AEALSF_NIZK_PROOF_TTL_SECONDS", "60.0")
        )
    )
    session_token_ttl_seconds: float = field(
        default_factory=lambda: float(
            os.getenv("AEALSF_SESSION_TOKEN_TTL_SECONDS", "300.0")
        )
    )
    max_nonce_cache_size: int = 50000
    he_bsgs_max_bound: int = field(
        default_factory=lambda: int(os.getenv("AEALSF_HE_BSGS_MAX_BOUND", "262144"))
    )
    he_precompute_pool_size: int = 16
    enforce_replay_protection: bool = True
    enforce_strict_edge_mutual_auth: bool = True
    enforce_result_signature_verification: bool = True
    ddos_rate_limit_per_window: int = 25
    ddos_window_seconds: float = 10.0
