"""Release manifest model, validation, and canonical serialization.

The canonical manifest is ASCII-only JSON with no whitespace and a fixed
field order ``schema, package, version, algorithm, keyid, artifact{name, size, sha256}``.
These are the bytes that get signed::

    {"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0","algorithm":"ed25519","keyid":"<64 hex>","artifact":{"name":"contoh-app.zip","size":1234,"sha256":"<64 hex>"}}
"""

from dataclasses import dataclass

import json
import re
from typing import Any

from src.constants import (
    ARTIFACT_NAME_RE,
    HEX64_RE,
    MANIFEST_SCHEMA,
    MAX_MANIFEST_BYTES,
    MAX_SAFE_INT,
    PACKAGE_RE,
    VERSION_RE,
)
from src.data.strict_json import expect_int, expect_object, expect_str, parse_strict
from src.errors import FormatError

_MANIFEST_KEYS = ["schema", "package", "version", "algorithm", "keyid", "artifact"]
_ARTIFACT_KEYS = ["name", "size", "sha256"]

@dataclass(frozen=True)
class Artifact:
    """Release artifact metadata referenced by the manifest.

    Attributes:
        name (str): File basename, matching :data:`~src.constants.ARTIFACT_NAME_RE`.
        size (int): File size in bytes, ``0..2**53-1``.
        sha256 (str): File SHA-256 digest, 64 lowercase hex characters.
    """
    name: str
    size: int
    sha256: str

@dataclass(frozen=True)
class Manifest:
    """Signed release manifest.

    Attributes:
        package (str): Package name, matching :data:`~src.constants.PACKAGE_RE`.
        version (str): Release version, matching :data:`~src.constants.VERSION_RE`.
        algorithm (str): Signer's algorithm profile name.
        keyid (str): Signer's public key fingerprint.
        artifact (Artifact): Artifact metadata.
        schema (str): Always ``"minisign-manifest/v1"``.
    """
    package: str
    version: str
    algorithm: str
    keyid: str
    artifact: Artifact
    schema: str = MANIFEST_SCHEMA


def _expect_match(value: str, pattern: re.Pattern[str], where: str) -> str:
    if pattern.fullmatch(value) is None:
        raise FormatError(f"{where}: does not match {pattern.pattern}")
    return value


def validate_manifest(raw: object) -> Manifest:
    """Validate a parsed JSON object into a :class:`Manifest`.

    Checks the exact field set (no extras), types, ``schema``, and each field's
    pattern. ``algorithm`` is only checked to be a string; profile support is
    checked separately during verification.

    Args:
        raw (object): Output of :func:`~src.data.strict_json.parse_strict`.

    Returns:
        Manifest: Validated manifest.

    Raises:
        FormatError: Invalid structure, type, or field pattern.
    """
    obj = expect_object(raw, _MANIFEST_KEYS, "manifest")

    schema = expect_str(obj["schema"], "manifest.schema")
    if schema != MANIFEST_SCHEMA:
        raise FormatError(f"manifest.schema: must be {MANIFEST_SCHEMA}")

    package = _expect_match(expect_str(obj["package"], "manifest.package"), PACKAGE_RE, "manifest.package")
    version = _expect_match(expect_str(obj["version"], "manifest.version"), VERSION_RE, "manifest.version")
    algorithm = expect_str(obj["algorithm"], "manifest.algorithm")
    keyid = _expect_match(expect_str(obj["keyid"], "manifest.keyid"), HEX64_RE, "manifest.keyid")

    art = expect_object(obj["artifact"], _ARTIFACT_KEYS, "manifest.artifact")
    artifact = Artifact(
        name=_expect_match(
            expect_str(art["name"], "manifest.artifact.name"),
            ARTIFACT_NAME_RE,
            "manifest.artifact.name"
        ),
        size=expect_int(art["size"], "manifest.artifact.size", 0, MAX_SAFE_INT),
        sha256=_expect_match(
            expect_str(art["sha256"], "manifest.artifact.sha256"),
            HEX64_RE,
            "manifest.artifact.sha256"
        ),
    )
    return Manifest(package, version, algorithm, keyid, artifact, schema)


def _to_ordered_dict(m: Manifest) -> dict[str, Any]:
    return {
        "schema": m.schema,
        "package": m.package,
        "version": m.version,
        "algorithm": m.algorithm,
        "keyid": m.keyid,
        "artifact": {
            "name": m.artifact.name,
            "size": m.artifact.size,
            "sha256": m.artifact.sha256
        }
    }


def serialize_manifest(m: Manifest) -> bytes:
    """Serialize a :class:`Manifest` to canonical form.

    Args:
        m (Manifest): Manifest to serialize (re-validated first).

    Returns:
        bytes: ASCII JSON with no whitespace and a fixed field order.

    Raises:
        FormatError: Invalid field or output exceeds 16 KiB.

    Example:
        >>> m = Manifest("contoh-app", "1.0.0", "ed25519", "0" * 64,
        ...              Artifact("contoh-app.zip", 3, "0" * 64))
        >>> serialize_manifest(m)[:40]
        b'{"schema":"minisign-manifest/v1","packag'
    """
    ordered = _to_ordered_dict(m)
    validate_manifest(ordered)

    text = json.dumps(ordered, separators=(",", ":"), ensure_ascii=True)
    data = text.encode("ascii")
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError(f"manifest: exceeds {MAX_MANIFEST_BYTES} bytes")

    return data


def parse_manifest(data: bytes) -> Manifest:
    """Parse manifest bytes and ensure they are canonical.

    After validation, the manifest is re-serialized and compared byte for byte
    with the input; any difference (whitespace, field order, Unicode escapes)
    is rejected.

    Args:
        data (bytes): Manifest bytes from the bundle.

    Returns:
        Manifest: Validated manifest.

    Raises:
        FormatError: Non-strict JSON, invalid field, or not canonical.
    """
    m = validate_manifest(parse_strict(data, max_bytes=MAX_MANIFEST_BYTES))

    if serialize_manifest(m) != data:
        raise FormatError("manifest: not in canonical serialization")
    return m
