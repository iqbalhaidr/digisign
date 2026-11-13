from src.errors import UnsupportedAlgorithmError

RSA_PSS_SHA256 = "rsa-pss-sha256"
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
ED25519 = "ed25519"

SUPPORTED_PROFILES: tuple[str, ...] = (RSA_PSS_SHA256, ECDSA_P256_SHA256, ED25519)

RSA_KEY_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537
RSA_PSS_SALT_BYTES = 32

P256_SCALAR_BYTES = 32
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

SIGNATURE_BYTES: dict[str, int] = {
    RSA_PSS_SHA256: RSA_KEY_BITS // 8,
    ECDSA_P256_SHA256: 2 * P256_SCALAR_BYTES,
    ED25519: 64,
}

def is_supported(profile: object) -> bool:
    return isinstance(profile, str) and profile in SUPPORTED_PROFILES

def require_supported(profile: object) -> str:
    if not is_supported(profile):
        raise UnsupportedAlgorithmError(f"unsupported algorithm profile: {profile!r}")
    return profile
