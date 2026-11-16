"""Implementation of the ``sbom generate``, ``sbom sign``, ``sbom verify``, and ``sbom check`` subcommands.
"""

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
    """Generate a CycloneDX SBOM for a release artifact (``sbom generate`` subcommand).

    Args:
        file_path (str): Release artifact path.
        package (str): Package name.
        version (str): Release version.
        out_path (str): Output SBOM path. Must not exist or equal ``file_path``.
        out (TextIO | None): Output stream. Default ``sys.stdout``.
        err (TextIO | None): Error stream. Default ``sys.stderr``.

    Returns:
        int: ``0`` on success; ``2`` on invalid input or I/O failure.

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
    """Sign an SBOM as a separate artifact (``sbom sign`` subcommand).

    The SBOM must be valid and bound to ``file_path``
    (:func:`~src.sbom.document.binding_error`) before signing. Signing uses
    :func:`~src.sign.sign.sign_command` with the SBOM as the artifact, so the
    output is a regular ``minisign-bundle/v1`` bundle.

    Args:
        sbom_path (str): SBOM path.
        file_path (str): Release artifact path referenced by the SBOM.
        package (str): Package name.
        version (str): Release version.
        key_path (str): PKCS#8 PEM private key path.
        out_path (str): Output SBOM bundle path.
        out (TextIO | None): Output stream. Default ``sys.stdout``.
        err (TextIO | None): Error stream. Default ``sys.stderr``.

    Returns:
        int: ``0`` on success; ``2`` if the SBOM is invalid or unbound, or on failure.

    Example:
        >>> sbom_sign_command("contoh-app.cdx.json", "contoh-app.zip", "contoh-app", "1.0.0",
        ...                   "keys/release.key.pem", "contoh-app.cdx.bundle.json")
        bundle:    contoh-app.cdx.bundle.json
        keyid:     3f1c...
        algorithm: ed25519
        artifact:  contoh-app.cdx.json (1024 bytes)
        0
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
    """Verify an SBOM signature and contents (``sbom verify`` subcommand).

    Output matches ``verify``: text ``<STATUS>: <message>`` or the
    ``verify --json`` format.

    Args:
        sbom_path (str): SBOM path.
        bundle_path (str): SBOM bundle path.
        trust_store_path (str): Trust store path.
        package (str): Expected package name.
        version (str): Expected version.
        as_json (bool): Output the result as JSON.
        out (TextIO | None): Output stream. Default ``sys.stdout``.
        err (TextIO | None): Error stream. Default ``sys.stderr``.

    Returns:
        int: ``0`` (valid), ``1`` (rejected), or ``2`` (input error).
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
    """Verify both bundles and match the artifact SHA-256 (``sbom check`` subcommand).

    Text mode prints ``<STATUS>: <message>`` (message prefixed by the failed
    stage). JSON mode prints :meth:`~src.sbom.verify.SbomCheckResult.to_json`.

    Args:
        file_path (str): Release artifact path.
        bundle_path (str): Release bundle path.
        sbom_path (str): SBOM path.
        sbom_bundle_path (str): SBOM bundle path.
        trust_store_path (str): Trust store path.
        package (str): Expected package name.
        version (str): Expected version.
        as_json (bool): Output the result as JSON.
        out (TextIO | None): Output stream. Default ``sys.stdout``.
        err (TextIO | None): Error stream. Default ``sys.stderr``.

    Returns:
        int: ``0`` (valid and bound), ``1`` (rejected, including ``SBOM_MISMATCH``),
        or ``2`` (input error).
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
