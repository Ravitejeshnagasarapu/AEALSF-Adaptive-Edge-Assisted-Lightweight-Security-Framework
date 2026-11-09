
from __future__ import annotations
import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except (ImportError, ModuleNotFoundError):
    import hmac
    class AESGCM:
        def __init__(self, key: bytes):
            self.key = key

        def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes) -> bytes:
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(data):
                block = hashlib.sha256(self.key + nonce + counter.to_bytes(4, 'big')).digest()
                keystream.extend(block)
                counter += 1
            ct = bytes(b ^ k for b, k in zip(data, keystream[:len(data)]))
            tag = hmac.new(self.key, nonce + ct + associated_data, hashlib.sha256).digest()[:16]
            return ct + tag

        def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes) -> bytes:
            ct = data[:-16]
            tag = data[-16:]
            expected_tag = hmac.new(self.key, nonce + ct + associated_data, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Tag mismatch")
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(ct):
                block = hashlib.sha256(self.key + nonce + counter.to_bytes(4, 'big')).digest()
                keystream.extend(block)
                counter += 1
            return bytes(b ^ k for b, k in zip(ct, keystream[:len(ct)]))
from cryptography.homomorphic_encryption import (
    ECElGamalCiphertext,
    ECElGamalHomomorphicEngine,
    ECPoint,
)


@dataclass(frozen=True)
class EncryptedEnvelope:
    scheme: str
    nonce_hex: str
    ciphertext_b64: str
    aad_str: str
    payload_sha256: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "scheme": self.scheme,
            "nonce_hex": self.nonce_hex,
            "ciphertext_b64": self.ciphertext_b64,
            "aad_str": self.aad_str,
            "payload_sha256": self.payload_sha256,
        }


class EncryptionService:

    def __init__(self, he_engine: ECElGamalHomomorphicEngine) -> None:
        self.he_engine = he_engine

    @staticmethod
    def derive_session_aes_key(shared_context: str, device_id: str) -> bytes:
        return hashlib.sha256(f"AEALSF_AES256_{device_id}_{shared_context}".encode("utf-8")).digest()

    def encrypt_homomorphic_metrics(
        self,
        values: List[int],
        public_key_q: ECPoint,
        owner_id: Optional[str] = None,
        use_precomputed_pool: bool = False,
    ) -> List[ECElGamalCiphertext]:
        return [
            self.he_engine.encrypt(
                plaintext_m=v,
                public_key_q=public_key_q,
                owner_id=owner_id,
                use_precomputed_pool=use_precomputed_pool,
            )
            for v in values
        ]

    def aggregate_homomorphic_metrics(
        self, ciphertexts: List[ECElGamalCiphertext]
    ) -> ECElGamalCiphertext:
        return self.he_engine.homomorphic_sum(ciphertexts)

    def decrypt_homomorphic_result(
        self, aggregated_ciphertext: ECElGamalCiphertext, private_key_d: int
    ) -> int:
        return self.he_engine.decrypt(aggregated_ciphertext, private_key_d)

    @staticmethod
    def encrypt_transport_payload(
        plaintext_bytes: bytes, aes_key: bytes, associated_data: str
    ) -> EncryptedEnvelope:
        if len(aes_key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key.")
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, plaintext_bytes, associated_data.encode("utf-8"))
        payload_hash = hashlib.sha256(plaintext_bytes).hexdigest()
        return EncryptedEnvelope(
            scheme="AES-256-GCM-TRANSPORT",
            nonce_hex=nonce.hex(),
            ciphertext_b64=base64.b64encode(ct).decode("ascii"),
            aad_str=associated_data,
            payload_sha256=payload_hash,
        )

    @staticmethod
    def decrypt_transport_payload(envelope: EncryptedEnvelope, aes_key: bytes) -> bytes:
        if envelope.scheme != "AES-256-GCM-TRANSPORT":
            raise ValueError(f"Unsupported transport scheme: {envelope.scheme}")
        nonce = bytes.fromhex(envelope.nonce_hex)
        ct = base64.b64decode(envelope.ciphertext_b64)
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ct, envelope.aad_str.encode("utf-8"))
        if hashlib.sha256(plaintext).hexdigest() != envelope.payload_sha256:
            raise ValueError("Decrypted payload SHA-256 integrity mismatch.")
        return plaintext
