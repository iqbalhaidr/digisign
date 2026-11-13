from dataclasses import dataclass

from src.constants import BUNDLE_SCHEMA, MAX_BUNDLE_BYTES
from src.data.b64_decoder import decode_b64_strict
from src.data.strict_json import expect_object, expect_str, parse_strict
from src.errors import FormatError

_BUNDLE_KEYS = ["schema", "manifest_b64", "signature_b64"]

@dataclass(frozen=True)
class Bundle:
    manifest_bytes: bytes
    signature: bytes


def parse_bundle(data: bytes) -> Bundle:
    b = parse_strict(data, max_bytes=MAX_BUNDLE_BYTES)
    expect_object(b, _BUNDLE_KEYS, "bundle")

    schema = expect_str(b["schema"], "bundle.schema")
    if schema != BUNDLE_SCHEMA:
        raise FormatError(f"bundle.schema: must be {BUNDLE_SCHEMA}")

    return Bundle(
        manifest_bytes=decode_b64_strict(b["manifest_b64"], "bundle.manifest_b64"),
        signature=decode_b64_strict(b["signature_b64"], "bundle.signature_b64"),
    )
