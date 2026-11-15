"""Strict PEM decoder for a single key block.
"""

import base64
import binascii

from src.errors import InvalidKeyError

def decode_pem(data: bytes, label: str) -> bytes:
    """Decode a single PEM block with the given label into DER.

    Enforced rules:

    * Content must be ASCII only.
    * Exactly one ``-----BEGIN <label>-----`` … ``-----END <label>-----`` block
      with no text outside it (blank lines ignored, CRLF accepted).
    * The Base64 body must be valid and non-empty.

    Args:
        data (bytes): PEM file contents.
        label (str): Expected label, e.g. ``"PRIVATE KEY"`` or ``"PUBLIC KEY"``.

    Returns:
        bytes: DER bytes decoded from the Base64 body.

    Raises:
        InvalidKeyError: Any rule above is violated.
    """
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as e:
        raise InvalidKeyError("PEM: contains non-ASCII bytes") from e

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.strip() for line in lines if line.strip()]

    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    if len(lines) < 3 or lines[0] != begin or lines[-1] != end:
        raise InvalidKeyError(f"PEM: expected exactly one '{label}' block")

    body = "".join(lines[1:-1])
    if "-----" in body:
        raise InvalidKeyError(f"PEM: expected exactly one '{label}' block")

    try:
        der = base64.b64decode(body, validate=True)
    except binascii.Error as e:
        raise InvalidKeyError(f"PEM: invalid Base64 body ({e})") from e

    if not der:
        raise InvalidKeyError("PEM: empty body")
    return der
