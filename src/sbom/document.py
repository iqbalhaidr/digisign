"""SBOM document (CycloneDX JSON): generation, validation, and binding check.

The release artifact is ``metadata.component``; its SHA-256 in
``metadata.component.hashes`` binds the SBOM to the artifact. For a ZIP
artifact, each entry is listed as a ``file`` component with its SHA-256.

.. code-block:: json

    {
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "serialNumber": "urn:uuid:...",
      "version": 1,
      "metadata": {
        "timestamp": "2026-11-15T10:00:00Z",
        "tools": {"components": [{"type": "application", "name": "digisign", "version": "1.0.0"}]},
        "component": {
          "type": "application",
          "bom-ref": "pkg:generic/contoh-app@1.0.0",
          "name": "contoh-app",
          "version": "1.0.0",
          "purl": "pkg:generic/contoh-app@1.0.0",
          "hashes": [{"alg": "SHA-256", "content": "<64 hex>"}],
          "properties": [
            {"name": "digisign:artifact:name", "value": "contoh-app.zip"},
            {"name": "digisign:artifact:size", "value": "1234"}
          ]
        }
      },
      "components": [
        {"type": "file", "name": "contoh-app.txt",
         "hashes": [{"alg": "SHA-256", "content": "<64 hex>"}],
         "properties": [{"name": "digisign:file:size", "value": "42"}]}
      ]
    }
"""

import datetime
import hashlib
import json
import os
import uuid
import zipfile
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from src.constants import ARTIFACT_NAME_RE, HEX64_RE, PACKAGE_RE, PROGRAM_VERSION, VERSION_RE
from src.data.strict_json import parse_strict
from src.errors import FormatError
from src.fileio import hash_file

#: Required value of the ``bomFormat`` field.
BOM_FORMAT = "CycloneDX"
#: CycloneDX version produced by :func:`build_sbom`.
SPEC_VERSION = "1.6"
#: CycloneDX versions accepted by :func:`parse_sbom`.
SUPPORTED_SPEC_VERSIONS: tuple[str, ...] = ("1.4", "1.5", "1.6")
#: CycloneDX name of the SHA-256 hash algorithm.
SHA256_ALG = "SHA-256"
#: Maximum SBOM size in bytes (8 MiB).
MAX_SBOM_BYTES = 8 * 1024 * 1024
#: ``metadata.component`` property holding the artifact file name.
ARTIFACT_NAME_PROPERTY = "digisign:artifact:name"
#: ``metadata.component`` property holding the artifact size.
ARTIFACT_SIZE_PROPERTY = "digisign:artifact:size"
#: ``file`` component property holding the entry size.
FILE_SIZE_PROPERTY = "digisign:file:size"

_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class SbomDocument:
    """Validated SBOM summary used for the binding check (immutable).

    Attributes:
        spec_version (str): ``specVersion``.
        name (str): ``metadata.component.name`` (release package).
        version (str): ``metadata.component.version`` (release version).
        sha256 (str): Release artifact SHA-256 from ``metadata.component.hashes``.
        artifact_name (str | None): ``digisign:artifact:name`` property, if present.
        component_count (int): Number of ``components`` entries.
    """
    spec_version: str
    name: str
    version: str
    sha256: str
    artifact_name: str | None
    component_count: int


def _field(obj: dict[str, Any], key: str, where: str) -> Any:
    if key not in obj:
        raise FormatError(f"{where}: missing field {key!r}")
    return obj[key]

def _object(value: object, where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise FormatError(f"{where}: must be an object")
    return value

def _array(value: object, where: str) -> list[Any]:
    if type(value) is not list:
        raise FormatError(f"{where}: must be an array")
    return value

def _string(value: object, where: str) -> str:
    if type(value) is not str:
        raise FormatError(f"{where}: must be a string")
    return value

def _parse_sha256(hashes: object, where: str) -> str:
    found: list[str] = []
    for i, raw in enumerate(_array(hashes, where)):
        item = _object(raw, f"{where}[{i}]")
        alg = _string(_field(item, "alg", f"{where}[{i}]"), f"{where}[{i}].alg")
        content = _string(_field(item, "content", f"{where}[{i}]"), f"{where}[{i}].content")
        if alg == SHA256_ALG:
            if HEX64_RE.fullmatch(content) is None:
                raise FormatError(f"{where}[{i}].content: must be 64 lowercase hex characters")
            found.append(content)
    if len(found) != 1:
        raise FormatError(f"{where}: must contain exactly one {SHA256_ALG} entry, found {len(found)}")
    return found[0]

def _parse_artifact_name(properties: object, where: str) -> str | None:
    value: str | None = None
    for i, raw in enumerate(_array(properties, where)):
        item = _object(raw, f"{where}[{i}]")
        name = _string(_field(item, "name", f"{where}[{i}]"), f"{where}[{i}].name")
        if name != ARTIFACT_NAME_PROPERTY:
            continue
        if value is not None:
            raise FormatError(f"{where}: duplicate property {ARTIFACT_NAME_PROPERTY!r}")
        value = _string(_field(item, "value", f"{where}[{i}]"), f"{where}[{i}].value")
    return value


def parse_sbom(data: bytes) -> SbomDocument:
    """Parse and validate a CycloneDX JSON SBOM.

    Uses :func:`~src.data.strict_json.parse_strict` (no duplicate keys,
    ``null``, floats, or BOM). Required: ``bomFormat`` = ``CycloneDX``,
    ``specVersion`` in :data:`SUPPORTED_SPEC_VERSIONS`,
    ``metadata.component.name``/``version``, and exactly one ``SHA-256``
    entry in ``metadata.component.hashes``. Other CycloneDX fields are ignored.

    Args:
        data (bytes): SBOM file contents (at most :data:`MAX_SBOM_BYTES`).

    Returns:
        SbomDocument: Validated SBOM summary.

    Raises:
        FormatError: Invalid JSON or SBOM structure.

    Example:
        >>> with open("contoh-app.cdx.json", "rb") as f:
        ...     doc = parse_sbom(f.read())
        >>> doc.name, doc.version
        ('contoh-app', '1.0.0')
    """
    root = _object(parse_strict(data, max_bytes=MAX_SBOM_BYTES), "sbom")

    if _string(_field(root, "bomFormat", "sbom"), "sbom.bomFormat") != BOM_FORMAT:
        raise FormatError(f"sbom.bomFormat: must be {BOM_FORMAT}")
    spec_version = _string(_field(root, "specVersion", "sbom"), "sbom.specVersion")
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise FormatError(f"sbom.specVersion: must be one of {', '.join(SUPPORTED_SPEC_VERSIONS)}")

    metadata = _object(_field(root, "metadata", "sbom"), "sbom.metadata")
    where = "sbom.metadata.component"
    component = _object(_field(metadata, "component", "sbom.metadata"), where)
    name = _string(_field(component, "name", where), f"{where}.name")
    version = _string(_field(component, "version", where), f"{where}.version")
    sha256 = _parse_sha256(_field(component, "hashes", where), f"{where}.hashes")
    artifact_name = None
    if "properties" in component:
        artifact_name = _parse_artifact_name(component["properties"], f"{where}.properties")

    count = 0
    if "components" in root:
        components = _array(root["components"], "sbom.components")
        for i, item in enumerate(components):
            _object(item, f"sbom.components[{i}]")
        count = len(components)

    return SbomDocument(spec_version, name, version, sha256, artifact_name, count)


def binding_error(
    doc: SbomDocument,
    package: str,
    version: str,
    artifact_name: str,
    artifact_sha256: str,
) -> str | None:
    """Check that an SBOM is bound to a release artifact.

    Checks stop at the first mismatch, in this order: SHA-256, package name,
    version, and artifact name (only if ``digisign:artifact:name`` is present).

    Args:
        doc (SbomDocument): Validated SBOM.
        package (str): Release package name.
        version (str): Release version.
        artifact_name (str): Artifact file name (basename).
        artifact_sha256 (str): Artifact SHA-256.

    Returns:
        str | None: First mismatch message, or ``None`` if bound.
    """
    if doc.sha256 != artifact_sha256:
        return "SBOM does not reference the SHA-256 of the release artifact"
    if doc.name != package:
        return f"SBOM component name {doc.name!r} differs from package {package!r}"
    if doc.version != version:
        return f"SBOM component version {doc.version!r} differs from version {version!r}"
    if doc.artifact_name is not None and doc.artifact_name != artifact_name:
        return f"SBOM artifact name {doc.artifact_name!r} differs from {artifact_name!r}"
    return None


def _zip_components(path: str) -> list[dict[str, Any]]:
    if not zipfile.is_zipfile(path):
        return []
    components = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                digest = hashlib.sha256()
                with archive.open(info) as f:
                    while chunk := f.read(_CHUNK_SIZE):
                        digest.update(chunk)
                components.append({
                    "type": "file",
                    "name": info.filename,
                    "hashes": [{"alg": SHA256_ALG, "content": digest.hexdigest()}],
                    "properties": [{"name": FILE_SIZE_PROPERTY, "value": str(info.file_size)}],
                })
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as e:
        raise FormatError(f"--file: cannot read ZIP entries ({e})") from e
    return components


def build_sbom(
    file_path: str,
    package: str,
    version: str,
    timestamp: datetime.datetime | None = None,
    serial_number: str | None = None,
) -> bytes:
    """Generate a CycloneDX 1.6 SBOM for a release artifact.

    The artifact is hashed in streaming mode. ZIP entries are hashed in memory
    and listed as ``file`` components; other artifacts yield empty ``components``.

    Args:
        file_path (str): Release artifact path.
        package (str): Package name, matches :data:`~src.constants.PACKAGE_RE`.
        version (str): Release version, matches :data:`~src.constants.VERSION_RE`.
        timestamp (datetime.datetime | None): Creation time. Default current UTC time.
        serial_number (str | None): ``serialNumber`` URN. Default ``urn:uuid:<uuid4>``.

    Returns:
        bytes: ASCII JSON, 2-space indented, ending with a newline.

    Raises:
        FormatError: Invalid package, version, or file name; corrupt ZIP; or
            output larger than :data:`MAX_SBOM_BYTES`.
        OSError: Artifact cannot be read.

    Example:
        >>> data = build_sbom("contoh-app.zip", "contoh-app", "1.0.0")
        >>> parse_sbom(data).sha256 == hash_file("contoh-app.zip")[1]
        True
    """
    if PACKAGE_RE.fullmatch(package) is None:
        raise FormatError(f"--package: {package!r} does not match {PACKAGE_RE.pattern}")
    if VERSION_RE.fullmatch(version) is None:
        raise FormatError(f"--version: {version!r} does not match {VERSION_RE.pattern}")
    artifact_name = os.path.basename(file_path)
    if ARTIFACT_NAME_RE.fullmatch(artifact_name) is None:
        raise FormatError(f"--file: name {artifact_name!r} does not match {ARTIFACT_NAME_RE.pattern}")

    size, sha256 = hash_file(file_path)
    components = _zip_components(file_path)

    when = timestamp or datetime.datetime.now(datetime.timezone.utc)
    purl = f"pkg:generic/{package}@{quote(version, safe='')}"
    document = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {"type": "application", "name": "digisign", "version": PROGRAM_VERSION},
                ],
            },
            "component": {
                "type": "application",
                "bom-ref": purl,
                "name": package,
                "version": version,
                "purl": purl,
                "hashes": [{"alg": SHA256_ALG, "content": sha256}],
                "properties": [
                    {"name": ARTIFACT_NAME_PROPERTY, "value": artifact_name},
                    {"name": ARTIFACT_SIZE_PROPERTY, "value": str(size)},
                ],
            },
        },
        "components": components,
    }
    data = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    if len(data) > MAX_SBOM_BYTES:
        raise FormatError(f"sbom: exceeds {MAX_SBOM_BYTES} bytes")
    return data
