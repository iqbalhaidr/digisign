"""Decoder PEM ketat untuk satu blok kunci.
"""

import base64
import binascii

from src.errors import InvalidKeyError

def decode_pem(data: bytes, label: str) -> bytes:
    """Decode satu blok PEM berlabel tertentu menjadi DER.

    Aturan yang ditegakkan:

    * Seluruh isi harus ASCII.
    * Tepat satu blok ``-----BEGIN <label>-----`` … ``-----END <label>-----``
      tanpa teks lain di luar blok (baris kosong diabaikan, CRLF diterima).
    * Body Base64 harus valid dan tidak kosong.

    Args:
        data (bytes): Isi berkas PEM.
        label (str): Label yang diharapkan, mis. ``"PRIVATE KEY"`` atau ``"PUBLIC KEY"``.

    Returns:
        bytes: Byte DER hasil decode body Base64.

    Raises:
        InvalidKeyError: Bila salah satu aturan di atas dilanggar.
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
