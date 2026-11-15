"""Decoder Base64 kanonik untuk field ``*_b64`` pada bundle.
"""

import base64
import binascii

from src.errors import FormatError

def decode_b64_strict(value: object, where: str) -> bytes:
    """Decode string Base64 standar (RFC 4648, dengan padding) secara kanonik.

    Selain harus valid, string wajib identik dengan hasil re-encode byte-nya,
    sehingga variasi seperti whitespace, padding berlebih, atau bit sisa
    non-nol ditolak. Dengan begitu satu nilai byte hanya punya satu representasi.

    Args:
        value (object): Nilai field dari JSON.
        where (str): Lokasi untuk pesan error, mis. ``"bundle.signature_b64"``.

    Returns:
        bytes: Byte hasil decode.

    Raises:
        FormatError: Bukan string, mengandung non-ASCII, Base64 tidak valid,
            atau bukan bentuk kanonik.
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
