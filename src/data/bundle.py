"""Format bundle: wadah manifest canonical dan signature-nya.

Contoh isi berkas bundle::

    {
      "schema": "minisign-bundle/v1",
      "manifest_b64": "<Base64 manifest canonical>",
      "signature_b64": "<Base64 signature>"
    }
"""

import base64
import json
from dataclasses import dataclass

from src.constants import BUNDLE_SCHEMA, MAX_BUNDLE_BYTES
from src.data.b64_decoder import decode_b64_strict
from src.data.strict_json import expect_object, expect_str, parse_strict
from src.errors import FormatError

_BUNDLE_KEYS = ["schema", "manifest_b64", "signature_b64"]

@dataclass(frozen=True)
class Bundle:
    """Isi bundle yang sudah di-decode.

    Attributes:
        manifest_bytes (bytes): Byte manifest canonical persis seperti yang ditandatangani.
        signature (bytes): Byte signature mentah.
    """
    manifest_bytes: bytes
    signature: bytes


def parse_bundle(data: bytes) -> Bundle:
    """Parse dan validasi berkas bundle.

    Args:
        data (bytes): Isi berkas bundle (maks. :data:`~src.constants.MAX_BUNDLE_BYTES`).

    Returns:
        Bundle: Manifest bytes dan signature hasil decode Base64 kanonik.
        Manifest **belum** di-parse; gunakan :func:`~src.data.manifest.parse_manifest`.

    Raises:
        FormatError: JSON tidak ketat, field tidak tepat, ``schema`` salah, atau
            Base64 tidak kanonik.
    """
    b = parse_strict(data, max_bytes=MAX_BUNDLE_BYTES)
    expect_object(b, _BUNDLE_KEYS, "bundle")

    schema = expect_str(b["schema"], "bundle.schema")
    if schema != BUNDLE_SCHEMA:
        raise FormatError(f"bundle.schema: must be {BUNDLE_SCHEMA}")

    return Bundle(
        manifest_bytes=decode_b64_strict(b["manifest_b64"], "bundle.manifest_b64"),
        signature=decode_b64_strict(b["signature_b64"], "bundle.signature_b64"),
    )


def serialize_bundle(manifest_bytes: bytes, signature: bytes) -> bytes:
    """Bentuk berkas bundle dari manifest canonical dan signature.

    Args:
        manifest_bytes (bytes): Hasil :func:`~src.data.manifest.serialize_manifest`.
        signature (bytes): Signature atas ``manifest_bytes``.

    Returns:
        bytes: JSON ASCII ber-indentasi 2 spasi diakhiri newline.

    Raises:
        FormatError: Hasil melebihi :data:`~src.constants.MAX_BUNDLE_BYTES`.
    """
    document = {
        "schema": BUNDLE_SCHEMA,
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    data = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    if len(data) > MAX_BUNDLE_BYTES:
        raise FormatError(f"bundle: exceeds {MAX_BUNDLE_BYTES} bytes")
    return data
