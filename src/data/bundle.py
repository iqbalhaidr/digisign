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
    name: str
    size: int
    sha256: str

@dataclass(frozen=True)
class Manifest:
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
    ordered = _to_ordered_dict(m)
    validate_manifest(ordered)

    text = json.dumps(ordered, separators=(",", ":"), ensure_ascii=True)
    data = text.encode("ascii")
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError(f"manifest: exceeds {MAX_MANIFEST_BYTES} bytes")

    return data


def parse_manifest(data: bytes) -> Manifest:
    m = validate_manifest(parse_strict(data, max_bytes=MAX_MANIFEST_BYTES))

    if serialize_manifest(m) != data:
        raise FormatError("manifest: not in canonical serialization")
    return m
