import os
import sys
from typing import TextIO

from src.constants import MAX_BUNDLE_BYTES
from src.crypto import is_supported
from src.crypto import verify as verify_signature
from src.data.bundle import parse_bundle
from src.data.manifest import Manifest, parse_manifest
from src.errors import FormatError
from src.fileio import hash_file
from src.trust import parse_trust_store
from src.verify.result import (
    ARTIFACT_MISMATCH,
    FORMAT_ERROR,
    INPUT_ERROR,
    INVALID_SIGNATURE,
    KEY_NOT_TRUSTED,
    METADATA_MISMATCH,
    OK,
    UNSUPPORTED_ALGORITHM,
    VerifyResult,
)

def _result(status: str, message: str, manifest: Manifest | None = None) -> VerifyResult:
    if manifest is None:
        return VerifyResult(status, message)
    return VerifyResult(
        status, message, manifest.algorithm, manifest.keyid, manifest.package, manifest.version
    )

def _read_file(path: str, limit: int | None = None) -> bytes:
    with open(path, "rb") as f:
        return f.read() if limit is None else f.read(limit)

def verify_release(
    file_path: str,
    bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
) -> VerifyResult:

    # 1. INPUT_ERROR
    try:
        bundle_bytes = _read_file(bundle_path, MAX_BUNDLE_BYTES + 1)
        trust_bytes = _read_file(trust_store_path)
        with open(file_path, "rb"):
            pass
    except OSError as e:
        return _result(INPUT_ERROR, f"cannot read input: {e}")

    # 2. FORMAT_ERROR
    try:
        bundle = parse_bundle(bundle_bytes)
        manifest = parse_manifest(bundle.manifest_bytes)
    except FormatError as e:
        return _result(FORMAT_ERROR, str(e))
    try:
        store = parse_trust_store(trust_bytes)
    except FormatError as e:
        return _result(FORMAT_ERROR, f"trust store: {e}", manifest)

    # 3. UNSUPPORTED_ALGORITHM
    if not is_supported(manifest.algorithm):
        return _result(UNSUPPORTED_ALGORITHM, f"unsupported algorithm: {manifest.algorithm!r}", manifest)

    # 4. KEY_NOT_TRUSTED
    entry = store.find(manifest.keyid)
    if entry is None:
        return _result(KEY_NOT_TRUSTED, "keyid is not in the trust store", manifest)
    if entry.algorithm != manifest.algorithm:
        return _result(KEY_NOT_TRUSTED, "trusted key profile differs from the manifest algorithm", manifest)
    if not entry.allows(package):
        return _result(KEY_NOT_TRUSTED, f"key is not allowed for package {package!r}", manifest)
    
    # 5. INVALID_SIGNATURE
    if not verify_signature(entry.public_key, manifest.algorithm, bundle.manifest_bytes, bundle.signature):
        return _result(INVALID_SIGNATURE, "signature does not match the manifest", manifest)

    # 6. METADATA_MISMATCH
    if manifest.package != package:
        return _result(METADATA_MISMATCH, f"package mismatch: manifest has {manifest.package!r}", manifest)
    if manifest.version != version:
        return _result(METADATA_MISMATCH, f"version mismatch: manifest has {manifest.version!r}", manifest)
    if manifest.artifact.name != os.path.basename(file_path):
        return _result(METADATA_MISMATCH, f"artifact name mismatch: manifest has {manifest.artifact.name!r}", manifest)

    # 7. ARTIFACT_MISMATCH
    try:
        size, sha256 = hash_file(file_path)
    except OSError as e:
        return _result(INPUT_ERROR, f"cannot read artifact: {e}", manifest)
    if size != manifest.artifact.size:
        return _result(ARTIFACT_MISMATCH, "artifact size differs from the manifest", manifest)
    if sha256 != manifest.artifact.sha256:
        return _result(ARTIFACT_MISMATCH, "artifact SHA-256 differs from the manifest", manifest)

    # 8. OK
    return _result(OK, "Signature and artifact are valid.", manifest)

def verify_command(
    file_path: str,
    bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
    as_json: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    result = verify_release(file_path, bundle_path, trust_store_path, package, version)

    if as_json:
        out.write(result.to_json())
        if not result.valid:
            err.write(f"{result.status}: {result.message}\n")
    else:
        out.write(f"{result.status}: {result.message}\n")
    return result.exit_code