"""Data layer: strict JSON parser, Base64 validation, canonical manifest, and bundle."""

from src.data.b64_decoder import decode_b64_strict
from src.data.bundle import parse_bundle
from src.data.manifest import parse_manifest, serialize_manifest, validate_manifest
from src.data.strict_json import expect_int, expect_object, expect_str, parse_strict

__all__ = [
    "decode_b64_strict",
    "parse_bundle",
    "parse_manifest",
    "serialize_manifest",
    "validate_manifest",
    "expect_int",
    "expect_object",
    "expect_str",
    "parse_strict",
]
