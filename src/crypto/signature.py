"""Signing and verification for all three profiles.

The signed message is the raw canonical manifest bytes; hashing is done by
each profile's primitive (Ed25519 uses no external pre-hash).
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from src.crypto.keys import PrivateKey, PublicKey, detect_profile, require_profile
from src.crypto.profiles import (
    ECDSA_P256_SHA256,
    P256_ORDER,
    P256_SCALAR_BYTES,
    RSA_PSS_SALT_BYTES,
    RSA_PSS_SHA256,
    SIGNATURE_BYTES,
    require_supported,
)

def _pss_padding() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=RSA_PSS_SALT_BYTES)

def sign(private_key: PrivateKey, message: bytes) -> bytes:
    """Sign ``message`` with a private key using its profile.

    * ``rsa-pss-sha256``: RSASSA-PSS, MGF1-SHA256, 32-byte salt → 384 bytes.
    * ``ecdsa-p256-sha256``: ECDSA-SHA256, DER output converted to raw
      ``r || s`` → 64 bytes.
    * ``ed25519``: pure Ed25519 → 64 bytes.

    Args:
        private_key (PrivateKey): Private key with a supported profile.
        message (bytes): Message to sign (canonical manifest).

    Returns:
        bytes: Fixed-length signature per :data:`SIGNATURE_BYTES`.

    Raises:
        InvalidKeyError: Key matches no supported profile.

    Example:
        >>> key = generate_private_key("ecdsa-p256-sha256")
        >>> sig = sign(key, b"hello")
        >>> len(sig)
        64
    """
    profile = detect_profile(private_key)

    if profile == RSA_PSS_SHA256:
        return private_key.sign(message, _pss_padding(), hashes.SHA256())
    if profile == ECDSA_P256_SHA256:
        der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return ecdsa_der_to_raw(der)
    return private_key.sign(message)

def verify(public_key: PublicKey, profile: str, message: bytes, signature: bytes) -> bool:
    """Verify a signature against a message and public key.

    Signature length is checked first; for ECDSA, ``r`` and ``s`` must also
    lie in ``[1, n-1]`` before DER conversion.

    Args:
        public_key (PublicKey): Signer's public key.
        profile (str): Algorithm profile claimed by the manifest.
        message (bytes): Original message (canonical manifest).
        signature (bytes): Signature to check.

    Returns:
        bool: ``True`` if valid, otherwise ``False`` (including wrong length
        or ``r``/``s`` out of range).

    Raises:
        UnsupportedAlgorithmError: Unknown ``profile``.
        InvalidKeyError: Public key does not match ``profile``.

    Example:
        >>> key = generate_private_key("ed25519")
        >>> sig = sign(key, b"hello")
        >>> verify(key.public_key(), "ed25519", b"hello", sig)
        True
        >>> verify(key.public_key(), "ed25519", b"hellO", sig)
        False
    """
    require_supported(profile)
    require_profile(public_key, profile)

    if len(signature) != SIGNATURE_BYTES[profile]:
        return False

    try:
        if profile == RSA_PSS_SHA256:
            public_key.verify(signature, message, _pss_padding(), hashes.SHA256())
        elif profile == ECDSA_P256_SHA256:
            der = ecdsa_raw_to_der(signature)
            if der is None:
                return False
            public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True

def ecdsa_der_to_raw(der: bytes) -> bytes:
    """Convert a DER ECDSA signature (``SEQUENCE{r, s}``) to raw ``r || s``.

    Args:
        der (bytes): DER-encoded ECDSA signature.

    Returns:
        bytes: 64 bytes; ``r`` and ``s`` as 32-byte big-endian each.
    """
    r, s = decode_dss_signature(der)
    return r.to_bytes(P256_SCALAR_BYTES, "big") + s.to_bytes(P256_SCALAR_BYTES, "big")

def ecdsa_raw_to_der(raw: bytes) -> bytes | None:
    """Convert a raw ``r || s`` ECDSA signature to DER.

    Args:
        raw (bytes): 64-byte raw signature.

    Returns:
        bytes | None: DER signature, or ``None`` if the length is not 64 bytes
        or ``r``/``s`` is outside ``[1, n-1]`` (n = P-256 curve order).
    """
    if len(raw) != 2 * P256_SCALAR_BYTES:
        return None
    r = int.from_bytes(raw[:P256_SCALAR_BYTES], "big")
    s = int.from_bytes(raw[P256_SCALAR_BYTES:], "big")
    if not (1 <= r < P256_ORDER and 1 <= s < P256_ORDER):
        return None
    return encode_dss_signature(r, s)
