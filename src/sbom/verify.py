"""SBOM bundle verification and the SBOM-to-release binding check."""

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

#: Extra ``sbom check`` status: SBOM is valid but not bound to the release artifact.
SBOM_MISMATCH = "SBOM_MISMATCH"

#: ``sbom check`` stage: release bundle verification.
STAGE_RELEASE = "release"
#: ``sbom check`` stage: SBOM bundle verification.
STAGE_SBOM = "sbom"
#: ``sbom check`` stage: SBOM SHA-256 and metadata matched against the release.
STAGE_BINDING = "binding"

#: Maps each ``sbom check`` status to its exit code (:data:`~src.verify.result.EXIT_CODES` + ``SBOM_MISMATCH``).
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
    """Verify an SBOM bundle, then validate the SBOM contents.

    Runs the 8-step :func:`~src.verify.verify.verify_release` check with the
    SBOM as the artifact. Only after it passes, the SBOM is read once, matched
    again against the manifest size and SHA-256 (``ARTIFACT_MISMATCH`` if it
    changed meanwhile), and parsed with :func:`~src.sbom.document.parse_sbom`
    (``FORMAT_ERROR`` if invalid).

    Args:
        sbom_path (str): SBOM path.
        bundle_path (str): SBOM bundle path.
        trust_store_path (str): Trust store path.
        package (str): Expected package name.
        version (str): Expected version.

    Returns:
        tuple[VerifyResult, SbomDocument | None]: Verification result and the
        SBOM summary (``None`` unless the status is ``OK``).

    Example:
        >>> result, doc = verify_sbom("contoh-app.cdx.json", "contoh-app.cdx.bundle.json",
        ...                           "trust.json", "contoh-app", "1.0.0")
        >>> result.status, doc.name
        ('OK', 'contoh-app')
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
    """Final ``sbom check`` result (immutable).

    Attributes:
        status (str): A verification status or ``SBOM_MISMATCH``.
        message (str): Short human-readable explanation.
        stage (str | None): Failed stage (``release``, ``sbom``, ``binding``);
            ``None`` on ``OK`` or invalid CLI arguments.
        artifact_sha256 (str | None): Artifact SHA-256 from the verified release manifest.
        release (VerifyResult | None): Release bundle verification result.
        sbom (VerifyResult | None): SBOM bundle verification result.

    Raises:
        ValueError: Unknown ``status``.
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
        """bool: ``True`` only if :attr:`status` is ``OK``."""
        return self.status == OK

    @property
    def exit_code(self) -> int:
        """int: CLI exit code for :attr:`status` (see :data:`CHECK_EXIT_CODES`)."""
        return CHECK_EXIT_CODES[self.status]

    def to_json(self) -> str:
        """Serialize the result to a single JSON line (``sbom check --json`` output).

        Returns:
            str: ASCII JSON with ``valid``, ``status``, ``stage``, ``message``,
            ``artifact_sha256``, ``release``, ``sbom``, ending with a newline.
            ``release`` and ``sbom`` use the ``verify --json`` format or ``null``.
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
    """Verify the release and SBOM bundles, then check that they are bound.

    Checks stop at the first failure, in this order:

    1. ``release`` — :func:`~src.verify.verify.verify_release_detailed` on the artifact.
    2. ``sbom`` — :func:`verify_sbom` on the SBOM.
    3. ``binding`` — :func:`~src.sbom.document.binding_error` against the verified
       release manifest (``artifact.sha256``, package, version, artifact name).
       Failure gives ``SBOM_MISMATCH``.

    Both bundles may use different keys if each is trusted for ``package``.

    Args:
        file_path (str): Release artifact path.
        bundle_path (str): Release bundle path.
        sbom_path (str): SBOM path.
        sbom_bundle_path (str): SBOM bundle path.
        trust_store_path (str): Trust store path.
        package (str): Expected package name.
        version (str): Expected version.

    Returns:
        SbomCheckResult: Combined result. Never raises on bad input.

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
