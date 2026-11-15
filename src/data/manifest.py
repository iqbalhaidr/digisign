"""Model, validasi, dan serialisasi canonical manifest rilis.

Manifest canonical adalah JSON tanpa whitespace dengan urutan field tetap
``schema, package, version, algorithm, keyid, artifact{name, size, sha256}``
dan hanya karakter ASCII. Byte inilah yang ditandatangani::

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
    """Metadata artefak rilis yang dirujuk manifest.

    Attributes:
        name (str): Nama berkas (basename), cocok :data:`~src.constants.ARTIFACT_NAME_RE`.
        size (int): Ukuran berkas dalam byte, ``0..2**53-1``.
        sha256 (str): Digest SHA-256 berkas, 64 heksadesimal huruf kecil.
    """
    name: str
    size: int
    sha256: str

@dataclass(frozen=True)
class Manifest:
    """Manifest rilis yang ditandatangani.

    Attributes:
        package (str): Nama paket, cocok :data:`~src.constants.PACKAGE_RE`.
        version (str): Versi rilis, cocok :data:`~src.constants.VERSION_RE`.
        algorithm (str): Nama profil algoritma penanda tangan.
        keyid (str): Fingerprint kunci publik penanda tangan.
        artifact (Artifact): Metadata artefak.
        schema (str): Selalu ``"minisign-manifest/v1"``.
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
    """Validasi objek JSON hasil parsing menjadi :class:`Manifest`.

    Memeriksa kelengkapan field (tanpa field tambahan), tipe, ``schema``, dan
    pola setiap field. Nilai ``algorithm`` hanya dipastikan string; dukungan
    profil diperiksa terpisah pada tahap verifikasi.

    Args:
        raw (object): Hasil :func:`~src.data.strict_json.parse_strict`.

    Returns:
        Manifest: Objek manifest tervalidasi.

    Raises:
        FormatError: Struktur, tipe, atau pola field tidak sesuai.
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
    """Serialisasi :class:`Manifest` ke bentuk canonical.

    Args:
        m (Manifest): Manifest yang akan diserialisasi (divalidasi ulang dulu).

    Returns:
        bytes: JSON ASCII tanpa whitespace dengan urutan field tetap.

    Raises:
        FormatError: Field tidak valid atau hasil melebihi 16 KiB.

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
    """Parse byte manifest dan pastikan sudah dalam bentuk canonical.

    Setelah divalidasi, manifest diserialisasi ulang dan dibandingkan byte per
    byte dengan input; perbedaan sekecil apa pun (spasi, urutan field, escape
    Unicode) ditolak.

    Args:
        data (bytes): Byte manifest dari bundle.

    Returns:
        Manifest: Objek manifest tervalidasi.

    Raises:
        FormatError: JSON tidak ketat, field tidak valid, atau bukan canonical.
    """
    m = validate_manifest(parse_strict(data, max_bytes=MAX_MANIFEST_BYTES))

    if serialize_manifest(m) != data:
        raise FormatError("manifest: not in canonical serialization")
    return m
