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

PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]
PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]

PRIVATE_KEY_LABEL = "PRIVATE KEY"
PUBLIC_KEY_LABEL = "PUBLIC KEY"

_DER_SEQUENCE = 0x30
_DER_INTEGER = 0x02

def detect_profile(key: PrivateKey | PublicKey) -> str:
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
    require_supported(expected)
    actual = detect_profile(key)
    if actual != expected:
        raise InvalidKeyError(f"key profile is {actual}, expected {expected}")

def generate_private_key(profile: str) -> PrivateKey:
    require_supported(profile)
    if profile == RSA_PSS_SHA256:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_BITS)
    if profile == ECDSA_P256_SHA256:
        return ec.generate_private_key(ec.SECP256R1())
    return ed25519.Ed25519PrivateKey.generate()

def private_key_to_pem(key: PrivateKey) -> bytes:
    detect_profile(key)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def public_key_to_der(key: PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def public_key_to_pem(key: PublicKey) -> bytes:
    detect_profile(key)
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def compute_keyid(public_key: PublicKey) -> str:
    detect_profile(public_key)
    return hashlib.sha256(public_key_to_der(public_key)).hexdigest()

def load_private_key_pem(data: bytes) -> PrivateKey:
    der = decode_pem(data, PRIVATE_KEY_LABEL)
    _require_pkcs8_structure(der)
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise InvalidKeyError("private key: not a valid unencrypted PKCS#8 key") from e
    detect_profile(key)
    return key

def load_public_key_pem(data: bytes) -> PublicKey:
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
