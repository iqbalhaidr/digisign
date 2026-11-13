import base64
import binascii

from src.errors import FormatError

def decode_b64_strict(value: object, where: str) -> bytes:
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
