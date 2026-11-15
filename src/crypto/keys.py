"""Manajemen kunci: pembangkitan, encoding PEM, parsing ketat, dan keyid.

Kunci privat disimpan sebagai **PKCS#8 PEM tanpa enkripsi**, kunci publik
sebagai **SubjectPublicKeyInfo (SPKI) PEM**. ``keyid`` adalah SHA-256 atas DER
SPKI kunci publik.
"""

import hashlib
from typing import Union

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from src.crypto.pem import decode_pem
from src.crypto.profiles import (
    ECDSA_P256_SHA256,
    ED25519,
    RSA_KEY_BITS,
    RSA_PSS_SHA256,
    RSA_PUBLIC_EXPONENT,
    require_supported,
)
from src.errors import InvalidKeyError

#: Tipe kunci privat yang didukung: ``RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey``.
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]
#: Tipe kunci publik yang didukung: ``RSAPublicKey | EllipticCurvePublicKey | Ed25519PublicKey``.
PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]

PRIVATE_KEY_LABEL = "PRIVATE KEY"
PUBLIC_KEY_LABEL = "PUBLIC KEY"

_DER_SEQUENCE = 0x30
_DER_INTEGER = 0x02

def detect_profile(key: PrivateKey | PublicKey) -> str:
    """Tentukan profil algoritma dari objek kunci dan validasi parameternya.

    Args:
        key (PrivateKey | PublicKey): Kunci privat atau publik dari pustaka ``cryptography``.

    Returns:
        str: Salah satu dari ``"rsa-pss-sha256"``, ``"ecdsa-p256-sha256"``, ``"ed25519"``.

    Raises:
        InvalidKeyError: RSA bukan 3072-bit atau eksponen bukan 65537, kurva EC
            bukan P-256, atau tipe kunci tidak didukung.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
        if public.key_size != RSA_KEY_BITS:
            raise InvalidKeyError(f"RSA key: modulus must be {RSA_KEY_BITS} bits, got {public.key_size}")
        if public.public_numbers().e != RSA_PUBLIC_EXPONENT:
            raise InvalidKeyError(f"RSA key: public exponent must be {RSA_PUBLIC_EXPONENT}")
        return RSA_PSS_SHA256

    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if not isinstance(key.curve, ec.SECP256R1):
            raise InvalidKeyError(f"EC key: curve must be P-256, got {key.curve.name}")
        return ECDSA_P256_SHA256

    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return ED25519

    raise InvalidKeyError(f"unsupported key type: {type(key).__name__}")


def require_profile(key: PrivateKey | PublicKey, expected: str) -> None:
    """Pastikan kunci sesuai dengan profil yang diharapkan.

    Args:
        key (PrivateKey | PublicKey): Kunci yang diperiksa.
        expected (str): Nama profil yang diharapkan.

    Returns:
        None

    Raises:
        UnsupportedAlgorithmError: ``expected`` bukan profil yang didukung.
        InvalidKeyError: Profil kunci berbeda dengan ``expected`` atau parameternya tidak valid.
    """
    require_supported(expected)
    actual = detect_profile(key)
    if actual != expected:
        raise InvalidKeyError(f"key profile is {actual}, expected {expected}")

def generate_private_key(profile: str) -> PrivateKey:
    """Bangkitkan kunci privat baru untuk profil tertentu.

    Args:
        profile (str): Nama profil algoritma.

    Returns:
        PrivateKey: ``RSAPrivateKey`` (3072-bit, e=65537), ``EllipticCurvePrivateKey``
        (P-256), atau ``Ed25519PrivateKey``.

    Raises:
        UnsupportedAlgorithmError: Profil tidak dikenal.

    Example:
        >>> key = generate_private_key("ed25519")
        >>> detect_profile(key)
        'ed25519'
    """
    require_supported(profile)
    if profile == RSA_PSS_SHA256:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_BITS)
    if profile == ECDSA_P256_SHA256:
        return ec.generate_private_key(ec.SECP256R1())
    return ed25519.Ed25519PrivateKey.generate()

def private_key_to_pem(key: PrivateKey) -> bytes:
    """Serialisasi kunci privat ke PKCS#8 PEM tanpa enkripsi.

    Args:
        key (PrivateKey): Kunci privat dengan profil yang didukung.

    Returns:
        bytes: PEM berlabel ``PRIVATE KEY``.

    Raises:
        InvalidKeyError: Kunci tidak sesuai profil mana pun.
    """
    detect_profile(key)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def public_key_to_der(key: PublicKey) -> bytes:
    """Serialisasi kunci publik ke DER SubjectPublicKeyInfo.

    Args:
        key (PublicKey): Kunci publik.

    Returns:
        bytes: Byte DER SPKI (input untuk perhitungan keyid).
    """
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def public_key_to_pem(key: PublicKey) -> bytes:
    """Serialisasi kunci publik ke SPKI PEM.

    Args:
        key (PublicKey): Kunci publik dengan profil yang didukung.

    Returns:
        bytes: PEM berlabel ``PUBLIC KEY``.

    Raises:
        InvalidKeyError: Kunci tidak sesuai profil mana pun.
    """
    detect_profile(key)
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def compute_keyid(public_key: PublicKey) -> str:
    """Hitung fingerprint ``keyid`` sebuah kunci publik.

    ``keyid = lowercase_hex(SHA-256(DER(SubjectPublicKeyInfo)))``

    Args:
        public_key (PublicKey): Kunci publik dengan profil yang didukung.

    Returns:
        str: 64 karakter heksadesimal huruf kecil.

    Raises:
        InvalidKeyError: Kunci tidak sesuai profil mana pun.

    Example:
        >>> keyid = compute_keyid(generate_private_key("ed25519").public_key())
        >>> len(keyid)
        64
    """
    detect_profile(public_key)
    return hashlib.sha256(public_key_to_der(public_key)).hexdigest()

def load_private_key_pem(data: bytes) -> PrivateKey:
    """Muat kunci privat dari PKCS#8 PEM tanpa enkripsi secara ketat.

    Selain parsing oleh pustaka, struktur DER diperiksa harus berupa
    ``PrivateKeyInfo`` PKCS#8 (SEQUENCE berisi INTEGER versi lalu SEQUENCE
    AlgorithmIdentifier) tanpa byte sisa, sehingga format tradisional
    (``RSA PRIVATE KEY``, ``EC PRIVATE KEY``) ditolak.

    Args:
        data (bytes): Isi berkas ``*.key.pem``.

    Returns:
        PrivateKey: Kunci privat yang sudah tervalidasi profilnya.

    Raises:
        InvalidKeyError: PEM/DER tidak valid, terenkripsi, bukan PKCS#8, atau
            parameter kunci tidak sesuai profil.

    Example:
        >>> with open("release.key.pem", "rb") as f:
        ...     private_key = load_private_key_pem(f.read())
    """
    der = decode_pem(data, PRIVATE_KEY_LABEL)
    _require_pkcs8_structure(der)
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise InvalidKeyError("private key: not a valid unencrypted PKCS#8 key") from e
    detect_profile(key)
    return key

def load_public_key_pem(data: bytes) -> PublicKey:
    """Muat kunci publik dari SPKI PEM secara ketat.

    DER hasil decode harus identik dengan re-encode standar oleh pustaka;
    encoding DER non-kanonik ditolak agar ``keyid`` selalu unik per kunci.

    Args:
        data (bytes): Isi berkas ``*.pub.pem``.

    Returns:
        PublicKey: Kunci publik yang sudah tervalidasi profilnya.

    Raises:
        InvalidKeyError: PEM tidak valid, bukan SPKI, DER tidak standar, atau
            parameter kunci tidak sesuai profil.
    """
    der = decode_pem(data, PUBLIC_KEY_LABEL)
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm) as e:
        raise InvalidKeyError("public key: not a valid SubjectPublicKeyInfo") from e
    detect_profile(key)

    if public_key_to_der(key) != der:
        raise InvalidKeyError("public key: SPKI is not in the required standard DER encoding")
    return key

def _read_tlv(der: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(der):
        raise InvalidKeyError("private key: truncated DER")
    tag, first = der[offset], der[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(der):
            raise InvalidKeyError("private key: invalid DER length")
        length = int.from_bytes(der[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(der):
        raise InvalidKeyError("private key: truncated DER")
    return tag, pos, end

def _require_pkcs8_structure(der: bytes) -> None:
    tag, start, end = _read_tlv(der, 0)
    if tag != _DER_SEQUENCE or end != len(der):
        raise InvalidKeyError("private key: not a PKCS#8 PrivateKeyInfo")
    tag, _, after_version = _read_tlv(der, start)
    if tag != _DER_INTEGER:
        raise InvalidKeyError("private key: not a PKCS#8 PrivateKeyInfo")
    tag, _, _ = _read_tlv(der, after_version)
    if tag != _DER_SEQUENCE:
        raise InvalidKeyError("private key: not a PKCS#8 PrivateKeyInfo")
