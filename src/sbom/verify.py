"""Verifikasi bundle SBOM dan pemeriksaan keterikatan SBOM dengan artefak rilis."""

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from src.data.manifest import Manifest
from src.errors import FormatError
from src.sbom.document import MAX_SBOM_BYTES, SbomDocument, binding_error, parse_sbom
from src.verify.result import (
    ARTIFACT_MISMATCH,
    EXIT_CODES,
    EXIT_REJECTED,
    FORMAT_ERROR,
    INPUT_ERROR,
    OK,
    VerifyResult,
)
from src.verify.verify import verify_release_detailed

#: Status tambahan khusus ``sbom check``: SBOM sah tetapi tidak terikat dengan artefak rilis.
SBOM_MISMATCH = "SBOM_MISMATCH"

#: Tahap ``sbom check`` tempat kegagalan terjadi.
STAGE_RELEASE = "release"
#: Tahap verifikasi bundle SBOM.
STAGE_SBOM = "sbom"
#: Tahap pencocokan SHA-256 dan metadata SBOM dengan artefak rilis.
STAGE_BINDING = "binding"

#: Pemetaan status ``sbom check`` ke exit code (status wajib + ``SBOM_MISMATCH``).
CHECK_EXIT_CODES: dict[str, int] = {**EXIT_CODES, SBOM_MISMATCH: EXIT_REJECTED}


def _with_manifest(status: str, message: str, manifest: Manifest) -> VerifyResult:
    return VerifyResult(
        status, message, manifest.algorithm, manifest.keyid, manifest.package, manifest.version
    )

def verify_sbom(
    sbom_path: str,
    bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
) -> tuple[VerifyResult, SbomDocument | None]:
    """Verifikasi signature SBOM lalu validasi isinya.

    Tahap 1–8 identik dengan :func:`~src.verify.verify.verify_release`, dengan
    berkas SBOM sebagai artefak. Isi SBOM baru di-parse **setelah** signature
    dan SHA-256-nya terbukti sah, kemudian:

    * Byte SBOM dibaca sekali dan dicocokkan lagi dengan ukuran serta SHA-256
      manifest, sehingga yang di-parse tepat byte yang ditandatangani
      (``ARTIFACT_MISMATCH`` bila berkas berubah di tengah proses).
    * Struktur CycloneDX divalidasi dengan :func:`~src.sbom.document.parse_sbom`
      (``FORMAT_ERROR`` bila tidak valid).

    Args:
        sbom_path (str): Path dokumen SBOM.
        bundle_path (str): Path bundle SBOM.
        trust_store_path (str): Path trust store.
        package (str): Nama paket yang diharapkan.
        version (str): Versi yang diharapkan.

    Returns:
        tuple[VerifyResult, SbomDocument | None]: Hasil verifikasi (format
        Tabel 2.9) dan ringkasan SBOM, yang hanya ada bila status ``OK``.

    Example:
        >>> result, doc = verify_sbom("contoh-app.cdx.json", "contoh-app.cdx.bundle.json",
        ...                           "trust.json", "contoh-app", "1.0.0")
        >>> result.status, doc.sha256[:8]
        ('OK', '1ebe02c5')
    """
    result, manifest = verify_release_detailed(sbom_path, bundle_path, trust_store_path, package, version)
    if manifest is None:
        return result, None

    if manifest.artifact.size > MAX_SBOM_BYTES:
        return _with_manifest(FORMAT_ERROR, f"sbom: exceeds {MAX_SBOM_BYTES} bytes", manifest), None
    try:
        with open(sbom_path, "rb") as f:
            data = f.read(MAX_SBOM_BYTES + 1)
    except OSError as e:
        return _with_manifest(INPUT_ERROR, f"cannot read SBOM: {e}", manifest), None
    if len(data) != manifest.artifact.size or hashlib.sha256(data).hexdigest() != manifest.artifact.sha256:
        return _with_manifest(ARTIFACT_MISMATCH, "SBOM changed during verification", manifest), None

    try:
        doc = parse_sbom(data)
    except FormatError as e:
        return _with_manifest(FORMAT_ERROR, str(e), manifest), None
    return _with_manifest(OK, "SBOM signature and content are valid.", manifest), doc


def _result_dict(result: VerifyResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "valid": result.valid,
        "status": result.status,
        "message": result.message,
        "algorithm": result.algorithm,
        "keyid": result.keyid,
        "package": result.package,
        "version": result.version,
    }


@dataclass(frozen=True)
class SbomCheckResult:
    """Hasil ``sbom check`` (immutable).

    Attributes:
        status (str): Status akhir: status wajib Tabel 2.8 atau ``SBOM_MISMATCH``.
        message (str): Penjelasan singkat.
        stage (str | None): Tahap kegagalan (``release``, ``sbom``, ``binding``),
            ``None`` bila ``OK`` atau kesalahan argumen CLI.
        artifact_sha256 (str | None): SHA-256 artefak dari manifest rilis terverifikasi.
        release (VerifyResult | None): Hasil verifikasi bundle rilis.
        sbom (VerifyResult | None): Hasil verifikasi bundle SBOM.

    Raises:
        ValueError: ``status`` tidak dikenal.
    """
    status: str
    message: str
    stage: str | None = None
    artifact_sha256: str | None = None
    release: VerifyResult | None = None
    sbom: VerifyResult | None = None

    def __post_init__(self) -> None:
        if self.status not in CHECK_EXIT_CODES:
            raise ValueError(f"unknown sbom check status: {self.status!r}")

    @property
    def valid(self) -> bool:
        """bool: ``True`` hanya bila :attr:`status` adalah ``OK``."""
        return self.status == OK

    @property
    def exit_code(self) -> int:
        """int: Exit code CLI untuk :attr:`status` (lihat :data:`CHECK_EXIT_CODES`)."""
        return CHECK_EXIT_CODES[self.status]

    def to_json(self) -> str:
        """Serialisasi hasil ke satu baris JSON (keluaran ``sbom check --json``).

        Returns:
            str: JSON ASCII dengan field ``valid``, ``status``, ``stage``,
            ``message``, ``artifact_sha256``, ``release``, ``sbom`` diakhiri newline.
            ``release`` dan ``sbom`` berformat Tabel 2.9 atau ``null``.
        """
        document = {
            "valid": self.valid,
            "status": self.status,
            "stage": self.stage,
            "message": self.message,
            "artifact_sha256": self.artifact_sha256,
            "release": _result_dict(self.release),
            "sbom": _result_dict(self.sbom),
        }
        return json.dumps(document, ensure_ascii=True) + "\n"


def check_sbom(
    file_path: str,
    bundle_path: str,
    sbom_path: str,
    sbom_bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
) -> SbomCheckResult:
    """Verifikasi bundle rilis dan bundle SBOM, lalu cocokkan keterikatannya.

    Urutan pemeriksaan (berhenti pada kegagalan pertama):

    1. ``release`` — :func:`~src.verify.verify.verify_release_detailed` atas artefak rilis.
    2. ``sbom`` — :func:`verify_sbom` atas dokumen SBOM.
    3. ``binding`` — :func:`~src.sbom.document.binding_error`: SHA-256 di SBOM
       harus sama dengan ``artifact.sha256`` manifest rilis terverifikasi, serta
       nama paket, versi, dan nama berkas artefak harus sama. Gagal → ``SBOM_MISMATCH``.

    Kedua bundle boleh ditandatangani kunci berbeda, asalkan keduanya
    tepercaya untuk ``package`` di trust store.

    Args:
        file_path (str): Path artefak rilis.
        bundle_path (str): Path bundle rilis.
        sbom_path (str): Path dokumen SBOM.
        sbom_bundle_path (str): Path bundle SBOM.
        trust_store_path (str): Path trust store.
        package (str): Nama paket yang diharapkan.
        version (str): Versi yang diharapkan.

    Returns:
        SbomCheckResult: Hasil gabungan. Tidak melempar exception untuk input buruk.

    Example:
        >>> r = check_sbom("contoh-app.zip", "contoh-app.bundle.json",
        ...                "contoh-app.cdx.json", "contoh-app.cdx.bundle.json",
        ...                "trust.json", "contoh-app", "1.0.0")
        >>> r.status, r.exit_code
        ('OK', 0)
    """
    release, release_manifest = verify_release_detailed(
        file_path, bundle_path, trust_store_path, package, version
    )
    if release_manifest is None:
        return SbomCheckResult(release.status, f"release: {release.message}", STAGE_RELEASE, release=release)
    artifact = release_manifest.artifact

    sbom, doc = verify_sbom(sbom_path, sbom_bundle_path, trust_store_path, package, version)
    if doc is None:
        return SbomCheckResult(
            sbom.status, f"sbom: {sbom.message}", STAGE_SBOM, artifact.sha256, release, sbom
        )

    error = binding_error(doc, package, version, artifact.name, artifact.sha256)
    if error is not None:
        return SbomCheckResult(SBOM_MISMATCH, error, STAGE_BINDING, artifact.sha256, release, sbom)
    return SbomCheckResult(
        OK, "Release and SBOM are valid and bound to the same artifact.", None, artifact.sha256, release, sbom
    )
