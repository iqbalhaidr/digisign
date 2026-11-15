"""Supported algorithm profiles and their parameters.

* ``rsa-pss-sha256`` — RSA 3072-bit, e = 65537, RSASSA-PSS + MGF1-SHA256,
  32-byte salt; 384-byte signature.
* ``ecdsa-p256-sha256`` — ECDSA P-256 + SHA-256; 64-byte raw ``r || s``
  signature.
* ``ed25519`` — Ed25519 (PureEdDSA, no pre-hash); 64-byte signature.
"""

from src.errors import UnsupportedAlgorithmError

#: RSASSA-PSS 3072-bit with SHA-256.
RSA_PSS_SHA256 = "rsa-pss-sha256"
#: ECDSA P-256 with SHA-256 (raw ``r || s`` signature).
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
#: Ed25519.
ED25519 = "ed25519"

#: All supported profile names, in documentation order.
SUPPORTED_PROFILES: tuple[str, ...] = (RSA_PSS_SHA256, ECDSA_P256_SHA256, ED25519)

#: RSA modulus size (bits).
RSA_KEY_BITS = 3072
#: Required RSA public exponent.
RSA_PUBLIC_EXPONENT = 65537
#: RSASSA-PSS salt length (bytes).
RSA_PSS_SALT_BYTES = 32

#: P-256 ``r`` / ``s`` scalar length (bytes).
P256_SCALAR_BYTES = 32
#: P-256 curve group order ``n``.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#: Signature length (bytes) per profile: RSA 384, ECDSA 64, Ed25519 64.
SIGNATURE_BYTES: dict[str, int] = {
    RSA_PSS_SHA256: RSA_KEY_BITS // 8,
    ECDSA_P256_SHA256: 2 * P256_SCALAR_BYTES,
    ED25519: 64,
}

def is_supported(profile: object) -> bool:
    """Check whether ``profile`` is a supported profile name.

    Args:
        profile (object): Any value (safe for unvalidated input).

    Returns:
        bool: ``True`` if ``profile`` is a ``str`` in :data:`SUPPORTED_PROFILES`.

    Example:
        >>> is_supported("ed25519")
        True
        >>> is_supported("rsa-pkcs1-sha256")
        False
    """
    return isinstance(profile, str) and profile in SUPPORTED_PROFILES

def require_supported(profile: object) -> str:
    """Validate a profile name and return it.

    Args:
        profile (object): Profile name to check.

    Returns:
        str: ``profile`` itself, if supported.

    Raises:
        UnsupportedAlgorithmError: Unknown profile.
    """
    if not is_supported(profile):
        raise UnsupportedAlgorithmError(f"unsupported algorithm profile: {profile!r}")
    return profile
