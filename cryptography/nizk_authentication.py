from __future__ import annotations
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from config.security_config import SecurityConfig
from cryptography.homomorphic_encryption import (
    BASE_POINT_G,
    ECPoint,
    SECP256K1_N,
    ec_add,
    ec_scalar_mul,
    ec_schnorr_verify_equation,
    is_on_curve,
)


@dataclass(frozen=True)
class VerifierChallengeTicket:
    nonce: str
    device_id: str
    verifier_id: str
    protocol_domain: str
    context_bind: str
    issued_at: float
    expires_at: float


@dataclass(frozen=True)
class ECSchnorrKeyPair:
    device_id: str
    private_key_s: int
    public_key_pk: ECPoint
    pk_fingerprint: str


@dataclass(frozen=True)
class ECSchnorrProof:
    device_id: str
    verifier_id: str
    protocol_domain: str
    verifier_nonce: str
    timestamp: float
    commitment_r: ECPoint
    challenge_c: int
    response_z: int
    public_key_pk: ECPoint
    context_bind: str = "BLOCKCHAIN_AUTH"

    @property
    def nonce(self) -> str:
        return self.verifier_nonce

    def to_dict(self) -> Dict[str, object]:
        return {
            "scheme": "EC_SCHNORR_SECP256K1",
            "device_id": self.device_id,
            "verifier_id": self.verifier_id,
            "protocol_domain": self.protocol_domain,
            "verifier_nonce": self.verifier_nonce,
            "timestamp": self.timestamp,
            "context_bind": self.context_bind,
            "commitment_r": self.commitment_r.to_dict(),
            "challenge_c": hex(self.challenge_c),
            "response_z": hex(self.response_z),
            "public_key_pk": self.public_key_pk.to_dict(),
        }


class ECSchnorrNIZKAuthenticator:

    DEFAULT_DOMAIN = "AEALSF-EC-SCHNORR-NIZK-v1"
    GLOBAL_PROVER_INVOCATIONS: int = 0
    GLOBAL_VERIFIER_INVOCATIONS: int = 0
    GLOBAL_VERIFIER_ACCEPTS: int = 0
    GLOBAL_VERIFIER_REJECTS: int = 0

    @classmethod
    def get_audit_counters(cls) -> Dict[str, int]:
        return {
            "prover_invocation_count": cls.GLOBAL_PROVER_INVOCATIONS,
            "verifier_invocation_count": cls.GLOBAL_VERIFIER_INVOCATIONS,
            "verifier_accept_count": cls.GLOBAL_VERIFIER_ACCEPTS,
            "verifier_reject_count": cls.GLOBAL_VERIFIER_REJECTS,
        }

    def __init__(self, config: Optional[SecurityConfig] = None) -> None:
        self.config = config or SecurityConfig()
        self.q = SECP256K1_N
        self._pending_challenges: Dict[str, VerifierChallengeTicket] = {}
        self._consumed_challenges: Dict[str, float] = {}
        self.prover_invocation_count: int = 0
        self.verifier_invocation_count: int = 0
        self.verifier_accept_count: int = 0
        self.verifier_reject_count: int = 0

    @staticmethod
    def compute_pk_fingerprint(pk: ECPoint) -> str:
        if pk.is_infinity:
            raise ValueError("Cannot compute fingerprint of point at infinity.")
        return hashlib.sha256(
            f"EC_SCHNORR|{hex(pk.x)}|{hex(pk.y)}".encode("utf-8")
        ).hexdigest()

    def generate_keypair(
        self, device_id: str, secret_s: Optional[int] = None
    ) -> ECSchnorrKeyPair:
        if not device_id or not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string.")
        if secret_s is None:
            secret_s = secrets.randbelow(self.q - 2) + 1
        if not (1 <= secret_s < self.q):
            raise ValueError("Private key s must lie in [1, q - 1].")
        pk = ec_scalar_mul(secret_s, BASE_POINT_G)
        return ECSchnorrKeyPair(
            device_id=device_id,
            private_key_s=secret_s,
            public_key_pk=pk,
            pk_fingerprint=self.compute_pk_fingerprint(pk),
        )

    def issue_verifier_challenge(
        self,
        device_id: str,
        verifier_id: str = "blockchain-verifier",
        protocol_domain: str = DEFAULT_DOMAIN,
        context_bind: str = "BLOCKCHAIN_AUTH",
        ttl_seconds: Optional[float] = None,
    ) -> VerifierChallengeTicket:
        now = time.time()
        ttl = (
            ttl_seconds
            if ttl_seconds is not None
            else self.config.nizk_proof_ttl_seconds
        )
        nonce = secrets.token_hex(16)
        ticket = VerifierChallengeTicket(
            nonce=nonce,
            device_id=device_id,
            verifier_id=verifier_id,
            protocol_domain=protocol_domain,
            context_bind=context_bind,
            issued_at=now,
            expires_at=now + ttl,
        )
        challenge_key = f"{protocol_domain}:{device_id}:{verifier_id}:{nonce}"
        self._pending_challenges[challenge_key] = ticket
        return ticket

    def issue_verifier_nonce(
        self,
        device_id: str = "default-device",
        verifier_id: str = "blockchain-verifier",
        protocol_domain: str = DEFAULT_DOMAIN,
    ) -> str:
        return self.issue_verifier_challenge(
            device_id=device_id,
            verifier_id=verifier_id,
            protocol_domain=protocol_domain,
        ).nonce

    def compute_challenge(
        self,
        protocol_domain: str,
        device_id: str,
        verifier_id: str,
        verifier_nonce: str,
        timestamp: float,
        commitment_r: ECPoint,
        public_key_pk: ECPoint,
        context_bind: str = "BLOCKCHAIN_AUTH",
    ) -> int:
        if commitment_r.is_infinity or public_key_pk.is_infinity:
            raise ValueError(
                "Commitment R and public key PK must not be the point at infinity."
            )
        transcript = (
            f"{protocol_domain}|{device_id}|{verifier_id}|{verifier_nonce}|"
            f"{timestamp:.6f}|{context_bind}|{hex(commitment_r.x)}|{hex(commitment_r.y)}|"
            f"{hex(public_key_pk.x)}|{hex(public_key_pk.y)}"
        ).encode("utf-8")
        digest_int = int.from_bytes(
            hashlib.sha256(transcript).digest(), byteorder="big"
        )
        c = digest_int % self.q
        return c if c != 0 else 1

    def generate_proof(
        self,
        keypair: ECSchnorrKeyPair,
        verifier_id: str = "blockchain-verifier",
        verifier_nonce: Optional[str] = None,
        protocol_domain: str = DEFAULT_DOMAIN,
        timestamp: Optional[float] = None,
        context_bind: str = "BLOCKCHAIN_AUTH",
        register_verifier_challenge_if_none: bool = True,
    ) -> ECSchnorrProof:
        self.prover_invocation_count += 1
        ECSchnorrNIZKAuthenticator.GLOBAL_PROVER_INVOCATIONS += 1
        if not verifier_id or not verifier_id.strip():
            raise ValueError("verifier_id must be non-empty.")
        if not protocol_domain or not protocol_domain.strip():
            raise ValueError("protocol_domain must be non-empty.")
        if verifier_nonce is None:
            if register_verifier_challenge_if_none:
                ticket = self.issue_verifier_challenge(
                    device_id=keypair.device_id,
                    verifier_id=verifier_id,
                    protocol_domain=protocol_domain,
                    context_bind=context_bind,
                )
                v_nonce = ticket.nonce
            else:
                v_nonce = secrets.token_hex(16)
        else:
            v_nonce = verifier_nonce

        if not v_nonce or len(v_nonce) < 8:
            raise ValueError("verifier_nonce must be at least 8 characters.")
        ts = timestamp if timestamp is not None else time.time()

        r = secrets.randbelow(self.q - 2) + 1
        commitment_r = ec_scalar_mul(r, BASE_POINT_G)
        challenge_c = self.compute_challenge(
            protocol_domain=protocol_domain,
            device_id=keypair.device_id,
            verifier_id=verifier_id,
            verifier_nonce=v_nonce,
            timestamp=ts,
            commitment_r=commitment_r,
            public_key_pk=keypair.public_key_pk,
            context_bind=context_bind,
        )
        response_z = (r + challenge_c * keypair.private_key_s) % self.q
        return ECSchnorrProof(
            device_id=keypair.device_id,
            verifier_id=verifier_id,
            protocol_domain=protocol_domain,
            verifier_nonce=v_nonce,
            timestamp=ts,
            commitment_r=commitment_r,
            challenge_c=challenge_c,
            response_z=response_z,
            public_key_pk=keypair.public_key_pk,
            context_bind=context_bind,
        )

    def verify_proof(
        self,
        proof: ECSchnorrProof,
        expected_pk: Optional[ECPoint] = None,
        expected_device_id: Optional[str] = None,
        expected_verifier_id: Optional[str] = None,
        expected_domain: str = DEFAULT_DOMAIN,
        expected_context: Optional[str] = None,
        require_verifier_issued_nonce: bool = False,
        record_nonce: bool = True,
    ) -> Tuple[bool, str]:
        self.verifier_invocation_count += 1
        ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_INVOCATIONS += 1
        if not isinstance(proof, ECSchnorrProof):
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return False, "Malformed proof object."
        if not proof.device_id or not proof.verifier_id or not proof.verifier_nonce:
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                "Malformed proof fields (empty device_id, verifier_id, or nonce).",
            )
        if expected_device_id is not None and proof.device_id != expected_device_id:
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                f"Device ID mismatch: expected {expected_device_id}, got {proof.device_id}.",
            )
        if (
            expected_verifier_id is not None
            and proof.verifier_id != expected_verifier_id
        ):
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                f"Verifier ID mismatch: expected {expected_verifier_id}, got {proof.verifier_id}.",
            )
        if proof.protocol_domain != expected_domain:
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                f"Protocol domain mismatch: expected {expected_domain}, got {proof.protocol_domain}.",
            )
        if expected_context is not None and proof.context_bind != expected_context:
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                f"Context binding mismatch: expected {expected_context}, got {proof.context_bind}.",
            )

        if proof.public_key_pk.is_infinity or not is_on_curve(proof.public_key_pk):
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                "Invalid public key PK (point at infinity or not on secp256k1).",
            )
        if proof.commitment_r.is_infinity or not is_on_curve(proof.commitment_r):
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                "Invalid commitment R (point at infinity or not on secp256k1).",
            )
        if not (1 <= proof.response_z < self.q and 1 <= proof.challenge_c < self.q):
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return (
                False,
                "Response z or challenge c out of scalar field bounds [1, q-1].",
            )

        if expected_pk is not None and proof.public_key_pk != expected_pk:
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return False, "Public key PK does not match registered device public key."

        if self.config.enforce_replay_protection:
            now = time.time()
            if abs(now - proof.timestamp) > self.config.nizk_proof_ttl_seconds:
                self.verifier_reject_count += 1
                ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
                return (
                    False,
                    "Expired or future NIZK proof timestamp outside freshness window.",
                )
            replay_key = f"{proof.protocol_domain}:{proof.device_id}:{proof.verifier_id}:{proof.verifier_nonce}"
            if replay_key in self._consumed_challenges:
                self.verifier_reject_count += 1
                ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
                return False, "Replay attack detected: verifier nonce already consumed."
            if require_verifier_issued_nonce:
                ticket = self._pending_challenges.get(replay_key)
                if ticket is None:
                    self.verifier_reject_count += 1
                    ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
                    return (
                        False,
                        "Untrusted challenge: verifier_nonce was not issued by the verifier.",
                    )
                if now > ticket.expires_at:
                    self._pending_challenges.pop(replay_key, None)
                    self.verifier_reject_count += 1
                    ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
                    return (
                        False,
                        "Verifier challenge ticket expired before proof submission.",
                    )
            if record_nonce:
                self._pending_challenges.pop(replay_key, None)
                self._consumed_challenges[replay_key] = now

        expected_c = self.compute_challenge(
            protocol_domain=proof.protocol_domain,
            device_id=proof.device_id,
            verifier_id=proof.verifier_id,
            verifier_nonce=proof.verifier_nonce,
            timestamp=proof.timestamp,
            commitment_r=proof.commitment_r,
            public_key_pk=proof.public_key_pk,
            context_bind=proof.context_bind,
        )
        if expected_c != proof.challenge_c:
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return False, "Challenge hash mismatch: c != H(context || R || PK)."

        if not ec_schnorr_verify_equation(
            proof.response_z, proof.challenge_c, proof.commitment_r, proof.public_key_pk
        ):
            self.verifier_reject_count += 1
            ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_REJECTS += 1
            return False, "Schnorr verification equation failed: z*G != R + c*PK."

        self.verifier_accept_count += 1
        ECSchnorrNIZKAuthenticator.GLOBAL_VERIFIER_ACCEPTS += 1
        return True, "EC-Schnorr NIZK proof verified."


@dataclass(frozen=True)
class NIZKKeyPair:
    device_id: str
    private_key_s: int
    public_key_pk: int
    prime_p: int
    generator_g: int
    pk_fingerprint: str


@dataclass(frozen=True)
class NIZKProof:
    device_id: str
    commitment_r: int
    response_z: int
    challenge_c: int
    public_key_pk: int
    nonce: str
    timestamp: float
    context_bind: str = "BLOCKCHAIN_AUTH"
    verifier_id: str = "blockchain-verifier"
    protocol_domain: str = "AEALSF-DLP-NIZK-v1"
    strict_paper_mode: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "scheme": "DLP_RFC3526_2048",
            "device_id": self.device_id,
            "verifier_id": self.verifier_id,
            "protocol_domain": self.protocol_domain,
            "commitment_r": hex(self.commitment_r),
            "response_z": hex(self.response_z),
            "challenge_c": hex(self.challenge_c),
            "public_key_pk": hex(self.public_key_pk),
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "context_bind": self.context_bind,
            "strict_paper_mode": self.strict_paper_mode,
        }


@dataclass(frozen=True)
class AuthenticatedSessionToken:
    token_id: str
    device_id: str
    pk_fingerprint: str
    issued_at: float
    expires_at: float
    session_hmac_signature: str


class CircomR1CSConstraintVerifier:

    @staticmethod
    def evaluate_r1cs_witness(
        pk: int,
        r_commit: int,
        z_resp: int,
        c_chal: int,
        p: int,
        g: int,
        h_expected: int,
        r_prime: int,
    ) -> Dict[str, object]:
        c1_residual = (r_commit - r_prime) % p
        c2_residual = c_chal - h_expected
        c3_valid = int(1 < pk < p and 1 < r_commit < p and 0 < z_resp < (p - 1))
        pk_inv_c = pow(pk, p - 1 - (c_chal % (p - 1)), p)
        lhs = (pow(g, z_resp, p) * pk_inv_c) % p
        nonlinear_residual = (lhs - r_prime) % p

        valid = (
            c1_residual == 0
            and c2_residual == 0
            and c3_valid == 1
            and nonlinear_residual == 0
        )
        return {
            "public_inputs": 8,
            "public_outputs": 4,
            "nonlinear_constraints": 1,
            "linear_constraints": 3,
            "c1_residual": c1_residual,
            "c2_residual": c2_residual,
            "c3_valid": c3_valid,
            "nonlinear_residual": nonlinear_residual,
            "finalR": r_prime,
            "finalZ": z_resp,
            "finalC": c_chal,
            "finalValid": int(valid),
            "verified": valid,
        }


class NIZKAuthenticator:

    def __init__(self, config: Optional[SecurityConfig] = None) -> None:
        self.config = config or SecurityConfig()
        self.p: int = int(self.config.nizk_prime_hex, 16)
        self.g: int = self.config.nizk_generator
        self._pending_challenges: Dict[str, VerifierChallengeTicket] = {}
        self._used_nonces: Dict[str, float] = {}
        self._revoked_session_tokens: set[str] = set()
        self._verifier_master_secret: bytes = secrets.token_bytes(32)
        self._random_oracle_sim_table: Dict[Tuple[int, int], int] = {}
        self.ec_schnorr = ECSchnorrNIZKAuthenticator(self.config)
        self.dlp_prover_invocation_count: int = 0
        self.dlp_verifier_invocation_count: int = 0

    @staticmethod
    def compute_pk_fingerprint(public_key_pk: int) -> str:
        pk_bytes = hex(public_key_pk).encode("utf-8")
        return hashlib.sha256(pk_bytes).hexdigest()

    def issue_verifier_challenge(
        self,
        device_id: str,
        verifier_id: str = "blockchain-verifier",
        protocol_domain: str = "AEALSF-DLP-NIZK-v1",
        context_bind: str = "BLOCKCHAIN_AUTH",
        ttl_seconds: Optional[float] = None,
    ) -> VerifierChallengeTicket:
        now = time.time()
        ttl = (
            ttl_seconds
            if ttl_seconds is not None
            else self.config.nizk_proof_ttl_seconds
        )
        nonce = secrets.token_hex(16)
        ticket = VerifierChallengeTicket(
            nonce=nonce,
            device_id=device_id,
            verifier_id=verifier_id,
            protocol_domain=protocol_domain,
            context_bind=context_bind,
            issued_at=now,
            expires_at=now + ttl,
        )
        key = f"{protocol_domain}:{device_id}:{verifier_id}:{nonce}"
        self._pending_challenges[key] = ticket
        return ticket

    def generate_keypair(
        self, device_id: str, secret_s: Optional[int] = None
    ) -> NIZKKeyPair:
        if not device_id or not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string.")
        if secret_s is None:
            secret_s = secrets.randbelow(self.p - 3) + 2
        if not (1 <= secret_s < self.p - 1):
            raise ValueError("Private key s must lie in {1, ..., p - 2}.")
        pk = pow(self.g, secret_s, self.p)
        fingerprint = self.compute_pk_fingerprint(pk)
        return NIZKKeyPair(
            device_id=device_id,
            private_key_s=secret_s,
            public_key_pk=pk,
            prime_p=self.p,
            generator_g=self.g,
            pk_fingerprint=fingerprint,
        )

    @staticmethod
    def hash_challenge(
        commitment_r: int,
        public_key_pk: int,
        nonce: str = "",
        timestamp: float = 0.0,
        context_bind: str = "BLOCKCHAIN_AUTH",
        device_id: str = "",
        verifier_id: str = "blockchain-verifier",
        protocol_domain: str = "AEALSF-DLP-NIZK-v1",
        strict_paper_mode: bool = False,
    ) -> int:
        hasher = hashlib.sha256()
        if not strict_paper_mode:
            hasher.update(protocol_domain.encode("utf-8"))
            hasher.update(b"|")
            hasher.update(device_id.encode("utf-8"))
            hasher.update(b"|")
            hasher.update(verifier_id.encode("utf-8"))
            hasher.update(b"|")
            hasher.update(nonce.encode("utf-8"))
            hasher.update(b"|")
            hasher.update(f"{timestamp:.6f}".encode("utf-8"))
            hasher.update(b"|")
            hasher.update(context_bind.encode("utf-8"))
            hasher.update(b"|")
        hasher.update(hex(commitment_r).encode("utf-8"))
        hasher.update(b"|")
        hasher.update(hex(public_key_pk).encode("utf-8"))
        return int.from_bytes(hasher.digest(), byteorder="big")

    def generate_proof(
        self,
        keypair: NIZKKeyPair,
        context_bind: str = "BLOCKCHAIN_AUTH",
        verifier_id: str = "blockchain-verifier",
        protocol_domain: str = "AEALSF-DLP-NIZK-v1",
        strict_paper_mode: bool = False,
        custom_nonce: Optional[str] = None,
        custom_timestamp: Optional[float] = None,
        register_verifier_challenge_if_none: bool = True,
    ) -> NIZKProof:
        self.dlp_prover_invocation_count += 1
        r = secrets.randbelow(self.p - 3) + 2
        commitment_r = pow(self.g, r, self.p)

        if custom_nonce is not None:
            nonce = custom_nonce
        elif register_verifier_challenge_if_none and not strict_paper_mode:
            nonce = self.issue_verifier_challenge(
                device_id=keypair.device_id,
                verifier_id=verifier_id,
                protocol_domain=protocol_domain,
                context_bind=context_bind,
            ).nonce
        else:
            nonce = secrets.token_hex(16)

        ts = custom_timestamp if custom_timestamp is not None else time.time()

        challenge_c = self.hash_challenge(
            commitment_r=commitment_r,
            public_key_pk=keypair.public_key_pk,
            nonce=nonce,
            timestamp=ts,
            context_bind=context_bind,
            device_id=keypair.device_id,
            verifier_id=verifier_id,
            protocol_domain=protocol_domain,
            strict_paper_mode=strict_paper_mode,
        )
        response_z = (r + challenge_c * keypair.private_key_s) % (self.p - 1)

        return NIZKProof(
            device_id=keypair.device_id,
            commitment_r=commitment_r,
            response_z=response_z,
            challenge_c=challenge_c,
            public_key_pk=keypair.public_key_pk,
            nonce=nonce,
            timestamp=ts,
            context_bind=context_bind,
            verifier_id=verifier_id,
            protocol_domain=protocol_domain,
            strict_paper_mode=strict_paper_mode,
        )

    def verify_proof(
        self,
        proof: NIZKProof,
        expected_pk: Optional[int] = None,
        expected_context: Optional[str] = None,
        expected_device_id: Optional[str] = None,
        expected_verifier_id: Optional[str] = None,
        expected_domain: Optional[str] = None,
        require_verifier_issued_nonce: bool = False,
        record_nonce: bool = True,
    ) -> Tuple[bool, str]:
        self.dlp_verifier_invocation_count += 1
        if not isinstance(proof, NIZKProof) or not proof.device_id:
            return False, "Malformed NIZKProof input."
        if not (1 < proof.public_key_pk < self.p and 1 < proof.commitment_r < self.p):
            return (
                False,
                "Public key PK or commitment R out of valid group bounds (1, p-1).",
            )
        if not (0 <= proof.response_z < self.p - 1):
            return False, "Response z out of valid modulo (p - 1) range."

        if expected_pk is not None and proof.public_key_pk != expected_pk:
            return (
                False,
                "Public key PK does not match registered blockchain device identity.",
            )
        if expected_device_id is not None and proof.device_id != expected_device_id:
            return False, "Proof device_id does not match expected device_id."
        if (
            expected_verifier_id is not None
            and proof.verifier_id != expected_verifier_id
        ):
            return False, "Proof verifier_id does not match expected verifier_id."
        if expected_domain is not None and proof.protocol_domain != expected_domain:
            return False, "Proof protocol_domain does not match expected domain."
        if expected_context is not None and proof.context_bind != expected_context:
            return False, "Proof context binding mismatch."

        if self.config.enforce_replay_protection and not proof.strict_paper_mode:
            if not proof.nonce or len(proof.nonce) < 4:
                return False, "Missing or malformed verifier nonce."
            now = time.time()
            if abs(now - proof.timestamp) > self.config.nizk_proof_ttl_seconds:
                return (
                    False,
                    "NIZK proof timestamp expired or outside freshness window.",
                )
            nonce_key = f"{proof.protocol_domain}:{proof.device_id}:{proof.verifier_id}:{proof.nonce}"
            if nonce_key in self._used_nonces:
                return (
                    False,
                    "Replay attack detected: NIZK proof nonce already consumed.",
                )
            if require_verifier_issued_nonce:
                ticket = self._pending_challenges.get(nonce_key)
                if ticket is None:
                    return (
                        False,
                        "Untrusted challenge: nonce was not issued by verifier.",
                    )
                if now > ticket.expires_at:
                    self._pending_challenges.pop(nonce_key, None)
                    return False, "Verifier challenge ticket expired."
            if record_nonce:
                self._pending_challenges.pop(nonce_key, None)
                if len(self._used_nonces) >= self.config.max_nonce_cache_size:
                    cutoff = sorted(self._used_nonces.values())[
                        len(self._used_nonces) // 4
                    ]
                    self._used_nonces = {
                        k: v for k, v in self._used_nonces.items() if v > cutoff
                    }
                self._used_nonces[nonce_key] = now

        c_mod = proof.challenge_c % (self.p - 1)
        pk_inv_c = pow(proof.public_key_pk, (self.p - 1 - c_mod) % (self.p - 1), self.p)
        r_prime = (pow(self.g, proof.response_z, self.p) * pk_inv_c) % self.p

        if (
            proof.strict_paper_mode
            and (r_prime, proof.public_key_pk) in self._random_oracle_sim_table
        ):
            c_prime = self._random_oracle_sim_table[(r_prime, proof.public_key_pk)]
        else:
            c_prime = self.hash_challenge(
                commitment_r=r_prime,
                public_key_pk=proof.public_key_pk,
                nonce=proof.nonce,
                timestamp=proof.timestamp,
                context_bind=proof.context_bind,
                device_id=proof.device_id,
                verifier_id=proof.verifier_id,
                protocol_domain=proof.protocol_domain,
                strict_paper_mode=proof.strict_paper_mode,
            )

        if c_prime != proof.challenge_c or r_prime != proof.commitment_r:
            return False, "Cryptographic NIZK challenge verification failed (c' != c)."

        return True, "NIZK proof verified."

    def batch_verify_proofs(
        self,
        proofs: List[NIZKProof],
        expected_pks: Optional[Dict[str, int]] = None,
    ) -> Tuple[bool, List[bool]]:
        if not proofs:
            return True, []

        metadata_valid: List[bool] = []
        for prf in proofs:
            exp_pk = expected_pks.get(prf.device_id) if expected_pks else None
            if exp_pk is not None and prf.public_key_pk != exp_pk:
                metadata_valid.append(False)
                continue
            c_expected = self.hash_challenge(
                commitment_r=prf.commitment_r,
                public_key_pk=prf.public_key_pk,
                nonce=prf.nonce,
                timestamp=prf.timestamp,
                context_bind=prf.context_bind,
                device_id=prf.device_id,
                verifier_id=prf.verifier_id,
                protocol_domain=prf.protocol_domain,
                strict_paper_mode=prf.strict_paper_mode,
            )
            if c_expected != prf.challenge_c:
                metadata_valid.append(False)
                continue
            if self.config.enforce_replay_protection and not prf.strict_paper_mode:
                now = time.time()
                if abs(now - prf.timestamp) > self.config.nizk_proof_ttl_seconds:
                    metadata_valid.append(False)
                    continue
                nonce_key = f"{prf.protocol_domain}:{prf.device_id}:{prf.verifier_id}:{prf.nonce}"
                if nonce_key in self._used_nonces:
                    metadata_valid.append(False)
                    continue
            metadata_valid.append(True)

        if not all(metadata_valid):
            individual_results = [
                self.verify_proof(
                    prf,
                    expected_pk=(
                        expected_pks.get(prf.device_id) if expected_pks else None
                    ),
                )[0]
                for prf in proofs
            ]
            return all(individual_results), individual_results

        lhs_r = 1
        sum_alpha_z = 0
        rhs_pk_term = 1
        order = self.p - 1

        for prf in proofs:
            alpha = secrets.randbits(64) + 1
            lhs_r = (lhs_r * pow(prf.commitment_r, alpha, self.p)) % self.p
            sum_alpha_z = (sum_alpha_z + alpha * prf.response_z) % order
            neg_alpha_c = (order - ((alpha * prf.challenge_c) % order)) % order
            rhs_pk_term = (
                rhs_pk_term * pow(prf.public_key_pk, neg_alpha_c, self.p)
            ) % self.p

        rhs = (pow(self.g, sum_alpha_z, self.p) * rhs_pk_term) % self.p
        if lhs_r == rhs:
            now = time.time()
            for prf in proofs:
                if self.config.enforce_replay_protection and not prf.strict_paper_mode:
                    self._used_nonces[
                        f"{prf.protocol_domain}:{prf.device_id}:{prf.verifier_id}:{prf.nonce}"
                    ] = now
            return True, [True] * len(proofs)

        individual_results = [
            self.verify_proof(
                prf,
                expected_pk=(expected_pks.get(prf.device_id) if expected_pks else None),
            )[0]
            for prf in proofs
        ]
        return all(individual_results), individual_results

    def simulate_zero_knowledge_transcript(self, public_key_pk: int) -> NIZKProof:
        r_sim = secrets.randbelow(self.p - 3) + 2
        r_initial = pow(self.g, r_sim, self.p)
        c_sim = self.hash_challenge(r_initial, public_key_pk, strict_paper_mode=True)
        z_prime = secrets.randbelow(self.p - 3) + 2
        c_mod = c_sim % (self.p - 1)
        pk_inv_c = pow(public_key_pk, (self.p - 1 - c_mod) % (self.p - 1), self.p)
        r_prime = (pow(self.g, z_prime, self.p) * pk_inv_c) % self.p
        self._random_oracle_sim_table[(r_prime, public_key_pk)] = c_sim
        return NIZKProof(
            device_id="simulator",
            commitment_r=r_prime,
            response_z=z_prime,
            challenge_c=c_sim,
            public_key_pk=public_key_pk,
            nonce="sim",
            timestamp=time.time(),
            strict_paper_mode=True,
        )

    def issue_session_token(
        self,
        device_id: str,
        public_key_pk: int | ECPoint,
        ttl_override: Optional[float] = None,
    ) -> AuthenticatedSessionToken:
        now = time.time()
        ttl = (
            ttl_override
            if ttl_override is not None
            else self.config.session_token_ttl_seconds
        )
        expires = now + ttl
        token_id = secrets.token_hex(12)
        if isinstance(public_key_pk, ECPoint):
            pk_fp = ECSchnorrNIZKAuthenticator.compute_pk_fingerprint(public_key_pk)
        else:
            pk_fp = self.compute_pk_fingerprint(public_key_pk)
        msg = f"{token_id}|{device_id}|{pk_fp}|{now:.3f}|{expires:.3f}".encode("utf-8")
        sig = hmac.new(self._verifier_master_secret, msg, hashlib.sha256).hexdigest()
        return AuthenticatedSessionToken(
            token_id=token_id,
            device_id=device_id,
            pk_fingerprint=pk_fp,
            issued_at=now,
            expires_at=expires,
            session_hmac_signature=sig,
        )

    def revoke_session_token(self, token_id: str) -> None:
        self._revoked_session_tokens.add(token_id)

    def verify_session_token(
        self,
        token: AuthenticatedSessionToken,
        expected_device_id: str,
        expected_pk_fp: str,
    ) -> bool:
        if token.token_id in self._revoked_session_tokens:
            return False
        now = time.time()
        if now > token.expires_at or token.device_id != expected_device_id:
            return False
        if token.pk_fingerprint != expected_pk_fp:
            return False
        msg = (
            f"{token.token_id}|{token.device_id}|{token.pk_fingerprint}|"
            f"{token.issued_at:.3f}|{token.expires_at:.3f}"
        ).encode("utf-8")
        expected_sig = hmac.new(
            self._verifier_master_secret, msg, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_sig, token.session_hmac_signature)
