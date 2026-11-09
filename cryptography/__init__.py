
from __future__ import annotations
import os
import site

__version__ = "38.0.4"

_dist_candidates = [
    "/usr/lib/python3/dist-packages/cryptography",
    "/usr/local/lib/python3.11/dist-packages/cryptography",
] + [
    os.path.join(sp, "cryptography")
    for sp in site.getsitepackages() + [site.getusersitepackages()]
]

for _cand in _dist_candidates:
    if os.path.isdir(_cand) and _cand not in __path__:
        __path__.append(_cand)

from cryptography.nizk_authentication import (
    ECSchnorrKeyPair,
    ECSchnorrProof,
    ECSchnorrNIZKAuthenticator,
    NIZKKeyPair,
    NIZKProof,
    NIZKAuthenticator,
    CircomR1CSConstraintVerifier,
    AuthenticatedSessionToken,
)
from cryptography.homomorphic_encryption import (
    ECPoint,
    ECElGamalKeyPair,
    ECElGamalCiphertext,
    ECElGamalHomomorphicEngine,
)
from cryptography.key_manager import KeyManager, DeviceWalletCredentials, PublicDeviceIdentity
from cryptography.encryption_service import EncryptionService, EncryptedEnvelope
from cryptography.verification import CryptographicVerifier, ReplayProtectionRegistry

__all__ = [
    "__version__",
    "ECSchnorrKeyPair",
    "ECSchnorrProof",
    "ECSchnorrNIZKAuthenticator",
    "NIZKKeyPair",
    "NIZKProof",
    "NIZKAuthenticator",
    "CircomR1CSConstraintVerifier",
    "AuthenticatedSessionToken",
    "ECPoint",
    "ECElGamalKeyPair",
    "ECElGamalCiphertext",
    "ECElGamalHomomorphicEngine",
    "KeyManager",
    "DeviceWalletCredentials",
    "PublicDeviceIdentity",
    "EncryptionService",
    "EncryptedEnvelope",
    "CryptographicVerifier",
    "ReplayProtectionRegistry",
]
