"""Implementasi subcommand ``verify``: delapan tahap pemeriksaan rilis berurutan.
"""

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
    """Verifikasi artefak rilis terhadap bundle dan trust store.

    Pemeriksaan berhenti pada kegagalan pertama dengan urutan:

    1. ``INPUT_ERROR`` — bundle, trust store, atau artefak tidak dapat dibaca.
    2. ``FORMAT_ERROR`` — bundle, manifest (termasuk canonical), atau trust store tidak valid.
    3. ``UNSUPPORTED_ALGORITHM`` — profil pada manifest tidak dikenal.
    4. ``KEY_NOT_TRUSTED`` — ``keyid`` tidak ada, profil berbeda, atau paket tidak diizinkan.
    5. ``INVALID_SIGNATURE`` — signature tidak cocok dengan manifest.
    6. ``METADATA_MISMATCH`` — paket, versi, atau nama berkas berbeda dari yang diharapkan.
    7. ``ARTIFACT_MISMATCH`` — ukuran atau SHA-256 artefak berbeda.
    8. ``OK`` — semua pemeriksaan lolos.

    Isi manifest baru dipercaya setelah tahap 5 lolos; tahap 6–7 membandingkan
    manifest terverifikasi dengan input pemanggil.

    Args:
        file_path (str): Path artefak rilis.
        bundle_path (str): Path bundle.
        trust_store_path (str): Path trust store.
        package (str): Nama paket yang diharapkan.
        version (str): Versi yang diharapkan.

    Returns:
        VerifyResult: Hasil verifikasi. Fungsi ini tidak melempar exception
        untuk input buruk; semua kegagalan dikembalikan sebagai status.

    Example:
        >>> r = verify_release("contoh-app.zip", "contoh-app.bundle.json",
        ...                    "trust.json", "contoh-app", "1.0.0")
        >>> r.status, r.exit_code
        ('OK', 0)
    """
    return verify_release_detailed(file_path, bundle_path, trust_store_path, package, version)[0]

def verify_release_detailed(
    file_path: str,
    bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
) -> tuple[VerifyResult, Manifest | None]:
    """Sama dengan :func:`verify_release`, ditambah manifest yang terverifikasi.

    Dipakai modul lain (mis. :mod:`src.sbom`) yang perlu membaca isi manifest
    setelah verifikasi berhasil, tanpa mem-parse ulang bundle.

    Args:
        file_path (str): Path artefak rilis.
        bundle_path (str): Path bundle.
        trust_store_path (str): Path trust store.
        package (str): Nama paket yang diharapkan.
        version (str): Versi yang diharapkan.

    Returns:
        tuple[VerifyResult, Manifest | None]: Hasil verifikasi dan manifest-nya.
        Manifest hanya dikembalikan bila status ``OK``; selain itu ``None``.
    """

    # 1. INPUT_ERROR
    try:
        bundle_bytes = _read_file(bundle_path, MAX_BUNDLE_BYTES + 1)
        trust_bytes = _read_file(trust_store_path)
        with open(file_path, "rb"):
            pass
    except OSError as e:
        return _result(INPUT_ERROR, f"cannot read input: {e}"), None

    # 2. FORMAT_ERROR
    try:
        bundle = parse_bundle(bundle_bytes)
        manifest = parse_manifest(bundle.manifest_bytes)
    except FormatError as e:
        return _result(FORMAT_ERROR, str(e)), None
    try:
        store = parse_trust_store(trust_bytes)
    except FormatError as e:
        return _result(FORMAT_ERROR, f"trust store: {e}", manifest), None

    # 3. UNSUPPORTED_ALGORITHM
    if not is_supported(manifest.algorithm):
        return _result(UNSUPPORTED_ALGORITHM, f"unsupported algorithm: {manifest.algorithm!r}", manifest), None

    # 4. KEY_NOT_TRUSTED
    entry = store.find(manifest.keyid)
    if entry is None:
        return _result(KEY_NOT_TRUSTED, "keyid is not in the trust store", manifest), None
    if entry.algorithm != manifest.algorithm:
        return _result(KEY_NOT_TRUSTED, "trusted key profile differs from the manifest algorithm", manifest), None
    if not entry.allows(package):
        return _result(KEY_NOT_TRUSTED, f"key is not allowed for package {package!r}", manifest), None
    
    # 5. INVALID_SIGNATURE
    if not verify_signature(entry.public_key, manifest.algorithm, bundle.manifest_bytes, bundle.signature):
        return _result(INVALID_SIGNATURE, "signature does not match the manifest", manifest), None

    # 6. METADATA_MISMATCH
    if manifest.package != package:
        return _result(METADATA_MISMATCH, f"package mismatch: manifest has {manifest.package!r}", manifest), None
    if manifest.version != version:
        return _result(METADATA_MISMATCH, f"version mismatch: manifest has {manifest.version!r}", manifest), None
    if manifest.artifact.name != os.path.basename(file_path):
        return _result(METADATA_MISMATCH, f"artifact name mismatch: manifest has {manifest.artifact.name!r}", manifest), None

    # 7. ARTIFACT_MISMATCH
    try:
        size, sha256 = hash_file(file_path)
    except OSError as e:
        return _result(INPUT_ERROR, f"cannot read artifact: {e}", manifest), None
    if size != manifest.artifact.size:
        return _result(ARTIFACT_MISMATCH, "artifact size differs from the manifest", manifest), None
    if sha256 != manifest.artifact.sha256:
        return _result(ARTIFACT_MISMATCH, "artifact SHA-256 differs from the manifest", manifest), None

    # 8. OK
    return _result(OK, "Signature and artifact are valid.", manifest), manifest

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
    """Jalankan verifikasi dan cetak hasilnya (subcommand ``verify``).

    Mode teks mencetak ``<STATUS>: <message>`` ke ``out``. Mode JSON mencetak
    :meth:`VerifyResult.to_json` ke ``out`` dan, bila gagal, ringkasan ke ``err``.

    Args:
        file_path (str): Path artefak rilis.
        bundle_path (str): Path bundle.
        trust_store_path (str): Path trust store.
        package (str): Nama paket yang diharapkan.
        version (str): Versi yang diharapkan.
        as_json (bool): Keluarkan hasil dalam format JSON.
        out (TextIO | None): Stream keluaran normal. Default ``sys.stdout``.
        err (TextIO | None): Stream pesan error. Default ``sys.stderr``.

    Returns:
        int: ``0`` (valid), ``1`` (ditolak), atau ``2`` (input error).
    """
    out, err = out or sys.stdout, err or sys.stderr
    result = verify_release(file_path, bundle_path, trust_store_path, package, version)

    if as_json:
        out.write(result.to_json())
        if not result.valid:
            err.write(f"{result.status}: {result.message}\n")
    else:
        out.write(f"{result.status}: {result.message}\n")
    return result.exit_code