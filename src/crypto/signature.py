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
    profile = detect_profile(private_key)

    if profile == RSA_PSS_SHA256:
        return private_key.sign(message, _pss_padding(), hashes.SHA256())
    if profile == ECDSA_P256_SHA256:
        der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return ecdsa_der_to_raw(der)
    return private_key.sign(message)

def verify(public_key: PublicKey, profile: str, message: bytes, signature: bytes) -> bool:
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
    r, s = decode_dss_signature(der)
    return r.to_bytes(P256_SCALAR_BYTES, "big") + s.to_bytes(P256_SCALAR_BYTES, "big")

def ecdsa_raw_to_der(raw: bytes) -> bytes | None:
    if len(raw) != 2 * P256_SCALAR_BYTES:
        return None
    r = int.from_bytes(raw[:P256_SCALAR_BYTES], "big")
    s = int.from_bytes(raw[P256_SCALAR_BYTES:], "big")
    if not (1 <= r < P256_ORDER and 1 <= s < P256_ORDER):
        return None
    return encode_dss_signature(r, s)
