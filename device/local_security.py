from __future__ import annotations
import zlib
from typing import List, Optional, Tuple, Union

from cryptography.encryption_service import EncryptionService
from cryptography.homomorphic_encryption import (
    ECElGamalCiphertext,
    ECElGamalHomomorphicEngine,
)
from cryptography.nizk_authentication import (
    AuthenticatedSessionToken,
    ECSchnorrProof,
    NIZKAuthenticator,
    NIZKProof,
)
from device.device_identity import DeviceIdentityWallet


class DeviceLocalSecurityEngine:

    def __init__(
        self,
        wallet: DeviceIdentityWallet,
        nizk_auth: NIZKAuthenticator,
        he_engine: ECElGamalHomomorphicEngine,
        encryption_service: EncryptionService,
    ) -> None:
        self.wallet = wallet
        self.nizk_auth = nizk_auth
        self.he_engine = he_engine
        self.encryption_service = encryption_service

    def warm_up_precomputed_he_pool(self, pool_size: int = 8) -> int:
        return self.he_engine.precompute_blinding_pool(
            owner_id=self.wallet.device_id,
            public_key_q=self.wallet.credentials.he_keypair.public_key_q,
            pool_size=pool_size,
        )

    def generate_ec_schnorr_auth_proof(
        self,
        verifier_id: str = "blockchain-verifier",
        verifier_nonce: Optional[str] = None,
        context_bind: str = "BLOCKCHAIN_AUTH",
    ) -> ECSchnorrProof:
        ec_kp = self.wallet.credentials.ec_schnorr_keypair
        if ec_kp is None:
            ec_kp = self.nizk_auth.ec_schnorr.generate_keypair(self.wallet.device_id)
            self.wallet.credentials.ec_schnorr_keypair = ec_kp
        return self.nizk_auth.ec_schnorr.generate_proof(
            keypair=ec_kp,
            verifier_id=verifier_id,
            verifier_nonce=verifier_nonce,
            context_bind=context_bind,
        )

    def generate_nizk_auth_proof(
        self,
        context_bind: str = "BLOCKCHAIN_AUTH",
        verifier_id: str = "blockchain-verifier",
        verifier_nonce: Optional[str] = None,
    ) -> NIZKProof:
        return self.nizk_auth.generate_proof(
            keypair=self.wallet.credentials.nizk_keypair,
            context_bind=context_bind,
            verifier_id=verifier_id,
            custom_nonce=verifier_nonce,
        )

    def can_reuse_authenticated_session(
        self,
    ) -> Tuple[bool, Optional[AuthenticatedSessionToken]]:
        tok = self.wallet.active_session_token
        if tok is None:
            return False, None
        ec_fp = (
            self.wallet.credentials.ec_schnorr_keypair.pk_fingerprint
            if self.wallet.credentials.ec_schnorr_keypair
            else ""
        )
        dlp_fp = self.wallet.credentials.nizk_keypair.pk_fingerprint
        valid = self.nizk_auth.verify_session_token(
            tok,
            expected_device_id=self.wallet.device_id,
            expected_pk_fp=(
                tok.pk_fingerprint if tok.pk_fingerprint in (ec_fp, dlp_fp) else dlp_fp
            ),
        )
        return valid, tok if valid else None

    def encrypt_telemetry_homomorphic(
        self, values: List[int], use_precomputed_pool: bool = False
    ) -> List[ECElGamalCiphertext]:
        return self.encryption_service.encrypt_homomorphic_metrics(
            values=values,
            public_key_q=self.wallet.credentials.he_keypair.public_key_q,
            owner_id=self.wallet.device_id,
            use_precomputed_pool=use_precomputed_pool,
        )

    def decrypt_homomorphic_aggregate(self, ciphertext: ECElGamalCiphertext) -> int:
        return self.encryption_service.decrypt_homomorphic_result(
            aggregated_ciphertext=ciphertext,
            private_key_d=self.wallet.credentials.he_keypair.private_key_d,
        )

    @staticmethod
    def execute_local_compression(raw_bytes: bytes) -> bytes:
        return zlib.compress(raw_bytes, level=6)
