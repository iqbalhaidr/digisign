"""Operasi tanda tangan dan verifikasi untuk ketiga profil.

Pesan yang ditandatangani adalah byte manifest canonical apa adanya; hashing
dilakukan oleh primitif masing-masing profil (Ed25519 tanpa pre-hash eksternal).
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
    """Tandatangani ``message`` dengan kunci privat sesuai profilnya.

    * ``rsa-pss-sha256``: RSASSA-PSS, MGF1-SHA256, salt 32 byte → 384 byte.
    * ``ecdsa-p256-sha256``: ECDSA-SHA256, output DER dikonversi ke raw
      ``r || s`` → 64 byte.
    * ``ed25519``: Ed25519 murni → 64 byte.

    Args:
        private_key (PrivateKey): Kunci privat dengan profil yang didukung.
        message (bytes): Pesan yang ditandatangani (manifest canonical).

    Returns:
        bytes: Signature dengan panjang tetap sesuai :data:`SIGNATURE_BYTES`.

    Raises:
        InvalidKeyError: Kunci tidak sesuai profil mana pun.

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
    """Verifikasi signature terhadap pesan dan kunci publik.

    Panjang signature diperiksa lebih dulu; untuk ECDSA, nilai ``r`` dan ``s``
    juga wajib berada pada rentang ``[1, n-1]`` sebelum dikonversi ke DER.

    Args:
        public_key (PublicKey): Kunci publik penanda tangan.
        profile (str): Profil algoritma yang diklaim manifest.
        message (bytes): Pesan asli (manifest canonical).
        signature (bytes): Signature yang akan diperiksa.

    Returns:
        bool: ``True`` bila signature valid, ``False`` bila tidak (termasuk
        panjang salah atau ``r``/``s`` di luar rentang).

    Raises:
        UnsupportedAlgorithmError: ``profile`` tidak dikenal.
        InvalidKeyError: Kunci publik tidak sesuai ``profile``.

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
    """Konversi signature ECDSA DER (``SEQUENCE{r, s}``) ke raw ``r || s``.

    Args:
        der (bytes): Signature ECDSA dalam encoding DER.

    Returns:
        bytes: 64 byte; ``r`` dan ``s`` masing-masing 32 byte big-endian.
    """
    r, s = decode_dss_signature(der)
    return r.to_bytes(P256_SCALAR_BYTES, "big") + s.to_bytes(P256_SCALAR_BYTES, "big")

def ecdsa_raw_to_der(raw: bytes) -> bytes | None:
    """Konversi signature ECDSA raw ``r || s`` ke DER.

    Args:
        raw (bytes): Signature raw 64 byte.

    Returns:
        bytes | None: Signature DER, atau ``None`` bila panjang bukan 64 byte
        atau ``r``/``s`` di luar rentang ``[1, n-1]`` (n = orde kurva P-256).
    """
    if len(raw) != 2 * P256_SCALAR_BYTES:
        return None
    r = int.from_bytes(raw[:P256_SCALAR_BYTES], "big")
    s = int.from_bytes(raw[P256_SCALAR_BYTES:], "big")
    if not (1 <= r < P256_ORDER and 1 <= s < P256_ORDER):
        return None
    return encode_dss_signature(r, s)
