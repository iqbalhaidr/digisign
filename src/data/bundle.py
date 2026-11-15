"""Bundle format: a container for the canonical manifest and its signature.

Example bundle file::

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
    """Decoded bundle contents.

    Attributes:
        manifest_bytes (bytes): Canonical manifest bytes exactly as signed.
        signature (bytes): Raw signature bytes.
    """
    manifest_bytes: bytes
    signature: bytes


def parse_bundle(data: bytes) -> Bundle:
    """Parse and validate a bundle file.

    Args:
        data (bytes): Bundle file contents (max :data:`~src.constants.MAX_BUNDLE_BYTES`).

    Returns:
        Bundle: Manifest bytes and signature from canonical Base64.
        The manifest is **not** parsed; use :func:`~src.data.manifest.parse_manifest`.

    Raises:
        FormatError: Non-strict JSON, wrong fields, wrong ``schema``, or
            non-canonical Base64.
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
    """Build a bundle file from a canonical manifest and its signature.

    Args:
        manifest_bytes (bytes): Output of :func:`~src.data.manifest.serialize_manifest`.
        signature (bytes): Signature over ``manifest_bytes``.

    Returns:
        bytes: ASCII JSON, 2-space indented, ending with a newline.

    Raises:
        FormatError: Output exceeds :data:`~src.constants.MAX_BUNDLE_BYTES`.
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
