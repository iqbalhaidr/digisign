"""Implementasi subcommand ``sbom generate``, ``sbom sign``, ``sbom verify``, dan ``sbom check``."""

import os
import sys
from typing import TextIO

from src.errors import FormatError, SignerError
from src.fileio import hash_file, write_new
from src.sbom.document import MAX_SBOM_BYTES, binding_error, build_sbom, parse_sbom
from src.sbom.verify import check_sbom, verify_sbom
from src.sign.sign import sign_command

EXIT_OK = 0
EXIT_FAILURE = 2


def sbom_generate_command(
    file_path: str,
    package: str,
    version: str,
    out_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Bangkitkan SBOM CycloneDX untuk artefak rilis (subcommand ``sbom generate``).

    Args:
        file_path (str): Path artefak rilis.
        package (str): Nama paket.
        version (str): Versi rilis.
        out_path (str): Path SBOM keluaran; tidak boleh sudah ada dan tidak
            boleh sama dengan ``file_path``.
        out (TextIO | None): Stream keluaran normal. Default ``sys.stdout``.
        err (TextIO | None): Stream pesan error. Default ``sys.stderr``.

    Returns:
        int: ``0`` bila berhasil, ``2`` bila input tidak valid atau gagal I/O.

    Example:
        >>> sbom_generate_command("contoh-app.zip", "contoh-app", "1.0.0", "contoh-app.cdx.json")
        sbom:       contoh-app.cdx.json
        component:  contoh-app 1.0.0
        sha256:     1ebe02c5...
        components: 1
        0
    """
    out, err = out or sys.stdout, err or sys.stderr
    try:
        _validate_output(out_path, [file_path])
        data = build_sbom(file_path, package, version)
        doc = parse_sbom(data)
        write_new(out_path, data)
    except (SignerError, OSError) as e:
        err.write(f"error: {e}\n")
        return EXIT_FAILURE

    out.write(f"sbom:       {out_path}\n")
    out.write(f"component:  {doc.name} {doc.version}\n")
    out.write(f"sha256:     {doc.sha256}\n")
    out.write(f"components: {doc.component_count}\n")
    return EXIT_OK


def sbom_sign_command(
    sbom_path: str,
    file_path: str,
    package: str,
    version: str,
    key_path: str,
    out_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Tandatangani SBOM sebagai artefak terpisah (subcommand ``sbom sign``).

    Sebelum ditandatangani, SBOM divalidasi dengan
    :func:`~src.sbom.document.parse_sbom` dan wajib terikat dengan artefak
    rilis (:func:`~src.sbom.document.binding_error`), sehingga SBOM yang tidak
    memuat SHA-256 artefak rilis tidak akan pernah ditandatangani. Penandatanganan
    memakai :func:`~src.sign.sign.sign_command` dengan berkas SBOM sebagai
    artefak, sehingga bundle berformat ``minisign-bundle/v1`` yang sama.

    Args:
        sbom_path (str): Path dokumen SBOM.
        file_path (str): Path artefak rilis yang dirujuk SBOM.
        package (str): Nama paket.
        version (str): Versi rilis.
        key_path (str): Path kunci privat PKCS#8 PEM.
        out_path (str): Path bundle SBOM keluaran.
        out (TextIO | None): Stream keluaran normal. Default ``sys.stdout``.
        err (TextIO | None): Stream pesan error. Default ``sys.stderr``.

    Returns:
        int: ``0`` bila bundle berhasil ditulis, ``2`` bila SBOM tidak valid,
        tidak terikat dengan artefak, atau terjadi kegagalan lain.
    """
    out, err = out or sys.stdout, err or sys.stderr
    try:
        _validate_output(out_path, [file_path])
        with open(sbom_path, "rb") as f:
            doc = parse_sbom(f.read(MAX_SBOM_BYTES + 1))
        _, artifact_sha256 = hash_file(file_path)
        error = binding_error(doc, package, version, os.path.basename(file_path), artifact_sha256)
        if error is not None:
            raise FormatError(error)
    except (SignerError, OSError) as e:
        err.write(f"error: {e}\n")
        return EXIT_FAILURE
    return sign_command(sbom_path, package, version, key_path, out_path, out, err)


def sbom_verify_command(
    sbom_path: str,
    bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
    as_json: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Verifikasi signature dan isi SBOM (subcommand ``sbom verify``).

    Keluaran mengikuti ``verify``: mode teks ``<STATUS>: <message>``, mode
    JSON berformat Tabel 2.9.

    Args:
        sbom_path (str): Path dokumen SBOM.
        bundle_path (str): Path bundle SBOM.
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
    result, _ = verify_sbom(sbom_path, bundle_path, trust_store_path, package, version)
    if as_json:
        out.write(result.to_json())
        if not result.valid:
            err.write(f"{result.status}: {result.message}\n")
    else:
        out.write(f"{result.status}: {result.message}\n")
    return result.exit_code


def sbom_check_command(
    file_path: str,
    bundle_path: str,
    sbom_path: str,
    sbom_bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
    as_json: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Verifikasi kedua bundle dan cocokkan SHA-256 artefak (subcommand ``sbom check``).

    Mode teks mencetak ``<STATUS>: <message>`` (diawali tahap kegagalan);
    mode JSON mencetak :meth:`~src.sbom.verify.SbomCheckResult.to_json`.

    Args:
        file_path (str): Path artefak rilis.
        bundle_path (str): Path bundle rilis.
        sbom_path (str): Path dokumen SBOM.
        sbom_bundle_path (str): Path bundle SBOM.
        trust_store_path (str): Path trust store.
        package (str): Nama paket yang diharapkan.
        version (str): Versi yang diharapkan.
        as_json (bool): Keluarkan hasil dalam format JSON.
        out (TextIO | None): Stream keluaran normal. Default ``sys.stdout``.
        err (TextIO | None): Stream pesan error. Default ``sys.stderr``.

    Returns:
        int: ``0`` (valid dan terikat), ``1`` (ditolak, termasuk ``SBOM_MISMATCH``),
        atau ``2`` (input error).
    """
    out, err = out or sys.stdout, err or sys.stderr
    result = check_sbom(
        file_path, bundle_path, sbom_path, sbom_bundle_path, trust_store_path, package, version
    )
    if as_json:
        out.write(result.to_json())
        if not result.valid:
            err.write(f"{result.status}: {result.message}\n")
    else:
        out.write(f"{result.status}: {result.message}\n")
    return result.exit_code


def _validate_output(out_path: str, inputs: list[str]) -> None:
    for path in inputs:
        if os.path.abspath(out_path) == os.path.abspath(path):
            raise SignerError("--out must not be an input file")
    if os.path.lexists(out_path):
        raise SignerError(f"output file already exists: {out_path}")
