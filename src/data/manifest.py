import json

from constants import (
    ARTIFACT_NAME_RE,
    HEX64_RE,
    MANIFEST_SCHEMA,
    MAX_MANIFEST_BYTES,
    MAX_SAFE_INT,
    PACKAGE_RE,
    VERSION_RE,
)

from errors import FormatError
from strict_json import expect_int, expect_object, expect_str, parse_strict

_MANIFEST_KEYS = ["schema", "package", "version", "algorithm", "keyid", "artifact"]
_ARTIFACT_KEYS = ["name", "size", "sha256"]

def _expect_match(value, pattern, where):
    if pattern.fullmatch(value) is None:
        raise FormatError(f"{where}: does not match {pattern.pattern}")
    return value

def validate_manifest(m):
    expect_object(m, _MANIFEST_KEYS, "manifest")

    schema = expect_str(m["schema"], "manifest.schema")
    if schema != MANIFEST_SCHEMA:
        raise FormatError(f"manifest.schema: must be {MANIFEST_SCHEMA}")

    _expect_match(expect_str(m["package"], "manifest.package"), PACKAGE_RE, "manifest.package")
    _expect_match(expect_str(m["version"], "manifest.version"), VERSION_RE, "manifest.version")
    expect_str(m["algorithm"],"manifest.algorithm")
    _expect_match(expect_str(m["keyid"], "manifest.keyid"), HEX64_RE, "manifest.keyid")

    # validate artifact
    artifact = expect_object(m["artifact"], _ARTIFACT_KEYS, "manifest.artifact")
    _expect_match(
        expect_str(artifact["name"], "manifest.artifact.name"),
        ARTIFACT_NAME_RE,
        "manifest.artifact.name"
    )
    expect_int(artifact["size"], "manifest.artifact.size", 0, MAX_SAFE_INT)
    _expect_match(
        expect_str(artifact["sha256"], "manifest.artifact.sha256"),
        HEX64_RE,
        "manifest.artifact.sha256"
    )

    return m

def serialize_manifest(m):
    validate_manifest(m)

    ordered = {
        "schema": m["schema"],
        "package": m["package"],
        "version": m["version"],
        "algorithm": m["algorithm"],
        "keyid": m["keyid"],
        "artifact": {
            "name": m["artifact"]["name"],
            "size": m["artifact"]["size"],
            "sha256": m["artifact"]["sha256"]
        }
    }

    text = json.dumps(ordered, separators=(",", ":"), ensure_ascii=True)
    data = text.encode("ascii")
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError(f"manifest: exceeds {MAX_MANIFEST_BYTES} bytes")

    return data

def parse_manifest(data):
    m = parse_strict(data, max_bytes=MAX_MANIFEST_BYTES)
    validate_manifest(m)

    if serialize_manifest(m) != data:
        raise FormatError("manifest: not in canonical serialization")
    return m