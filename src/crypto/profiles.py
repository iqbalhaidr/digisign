"""Definisi profil algoritma yang didukung beserta parameternya.

* ``rsa-pss-sha256`` — RSA 3072-bit, e = 65537, RSASSA-PSS + MGF1-SHA256,
  salt 32 byte; signature 384 byte.
* ``ecdsa-p256-sha256`` — ECDSA kurva P-256 + SHA-256; signature raw
  ``r || s`` 64 byte.
* ``ed25519`` — Ed25519 (PureEdDSA, tanpa pre-hash); signature 64 byte.
"""

from src.errors import UnsupportedAlgorithmError

#: Profil RSASSA-PSS 3072-bit dengan SHA-256.
RSA_PSS_SHA256 = "rsa-pss-sha256"
#: Profil ECDSA kurva P-256 dengan SHA-256 (signature raw ``r || s``).
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
#: Profil Ed25519.
ED25519 = "ed25519"

#: Seluruh nama profil yang didukung, sesuai urutan dokumentasi.
SUPPORTED_PROFILES: tuple[str, ...] = (RSA_PSS_SHA256, ECDSA_P256_SHA256, ED25519)

#: Ukuran modulus RSA (bit).
RSA_KEY_BITS = 3072
#: Eksponen publik RSA yang diwajibkan.
RSA_PUBLIC_EXPONENT = 65537
#: Panjang salt RSASSA-PSS (byte).
RSA_PSS_SALT_BYTES = 32

#: Panjang skalar ``r`` / ``s`` P-256 (byte).
P256_SCALAR_BYTES = 32
#: Orde ``n`` grup kurva P-256.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#: Panjang signature (byte) per profil: RSA 384, ECDSA 64, Ed25519 64.
SIGNATURE_BYTES: dict[str, int] = {
    RSA_PSS_SHA256: RSA_KEY_BITS // 8,
    ECDSA_P256_SHA256: 2 * P256_SCALAR_BYTES,
    ED25519: 64,
}

def is_supported(profile: object) -> bool:
    """Periksa apakah ``profile`` adalah nama profil yang didukung.

    Args:
        profile (object): Nilai apa pun (aman untuk input yang belum divalidasi).

    Returns:
        bool: ``True`` bila ``profile`` berupa ``str`` dan ada di :data:`SUPPORTED_PROFILES`.

    Example:
        >>> is_supported("ed25519")
        True
        >>> is_supported("rsa-pkcs1-sha256")
        False
    """
    return isinstance(profile, str) and profile in SUPPORTED_PROFILES

def require_supported(profile: object) -> str:
    """Validasi nama profil dan kembalikan nilainya.

    Args:
        profile (object): Nama profil yang akan diperiksa.

    Returns:
        str: ``profile`` itu sendiri bila didukung.

    Raises:
        UnsupportedAlgorithmError: Profil tidak dikenal.
    """
    if not is_supported(profile):
        raise UnsupportedAlgorithmError(f"unsupported algorithm profile: {profile!r}")
    return profile
