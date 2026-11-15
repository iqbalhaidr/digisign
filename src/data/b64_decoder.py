"""Canonical Base64 decoder for bundle ``*_b64`` fields.
"""

import base64
import binascii

from src.errors import FormatError

def decode_b64_strict(value: object, where: str) -> bytes:
    """Canonically decode a standard Base64 string (RFC 4648, padded).

    The string must also equal the re-encoding of its bytes, so variants such
    as whitespace, extra padding, or non-zero trailing bits are rejected. Each
    byte value thus has exactly one representation.

    Args:
        value (object): Field value from JSON.
        where (str): Location for error messages, e.g. ``"bundle.signature_b64"``.

    Returns:
        bytes: Decoded bytes.

    Raises:
        FormatError: Not a string, contains non-ASCII, invalid Base64, or not
            canonical.
    """
    if type(value) is not str:
        raise FormatError(f"{where}: must be a string")

    if not value.isascii():
        raise FormatError(f"{where}: contains non-ASCII characters")

    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as e:
        raise FormatError(f"{where}: invalid Base64 ({e})") from e

    if base64.b64encode(raw).decode("ascii") != value:
        raise FormatError(f"{where}: Base64 is not in canonical form")

    return raw
