"""Implementation of the ``sign`` subcommand: builds a manifest and bundle for an artifact.
"""

import os
import sys
from typing import TextIO

from src.constants import PACKAGE_RE, VERSION_RE
from src.crypto import PrivateKey, compute_keyid, detect_profile, load_private_key_pem, sign
from src.data.bundle import serialize_bundle
from src.data.manifest import Artifact, Manifest, serialize_manifest
from src.errors import FormatError, SignerError
from src.fileio import hash_file, write_new

EXIT_OK = 0
EXIT_FAILURE = 2

def sign_command(
    file_path: str,
    package: str,
    version: str,
    key_path: str,
    out_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Sign a release artifact and write its bundle (``sign`` subcommand).

    Args:
        file_path (str): Release artifact path.
        package (str): Package name, matching :data:`~src.constants.PACKAGE_RE`.
        version (str): Release version, matching :data:`~src.constants.VERSION_RE`.
        key_path (str): PKCS#8 PEM private key path.
        out_path (str): Output bundle path; must not exist and must differ
            from ``file_path``.
        out (TextIO | None): Output stream. Default ``sys.stdout``.
        err (TextIO | None): Error stream. Default ``sys.stderr``.

    Returns:
        int: ``0`` if the bundle was written; ``2`` on invalid input/format/key
        or I/O failure.

    Example:
        >>> sign_command("contoh-app.zip", "contoh-app", "1.0.0",
        ...              "keys/release.key.pem", "contoh-app.bundle.json")
        bundle:    contoh-app.bundle.json
        keyid:     3f1c...
        algorithm: ed25519
        artifact:  contoh-app.zip (1234 bytes)
        0
    """
    out, err = out or sys.stdout, err or sys.stderr
    try:
        _validate_metadata(package, version)
        _validate_output(file_path, out_path)
        with open(key_path, "rb") as f:
            private_key = load_private_key_pem(f.read())
        manifest, bundle = create_bundle(file_path, package, version, private_key)
        write_new(out_path, bundle)
    except (SignerError, OSError) as e:
        err.write(f"error: {e}\n")
        return EXIT_FAILURE

    out.write(f"bundle:    {out_path}\n")
    out.write(f"keyid:     {manifest.keyid}\n")
    out.write(f"algorithm: {manifest.algorithm}\n")
    out.write(f"artifact:  {manifest.artifact.name} ({manifest.artifact.size} bytes)\n")
    return EXIT_OK

def create_bundle(file_path: str, package: str, version: str, private_key: PrivateKey) -> tuple[Manifest, bytes]:
    """Build the manifest, sign it, and serialize the bundle (no disk write).

    The algorithm profile and ``keyid`` come from ``private_key``; the
    artifact name is the basename of ``file_path``.

    Args:
        file_path (str): Path of the artifact to hash.
        package (str): Package name.
        version (str): Release version.
        private_key (PrivateKey): Signer's private key.

    Returns:
        tuple[Manifest, bytes]: Manifest object and bundle file contents.

    Raises:
        FormatError: Invalid manifest field (e.g. file name does not match the pattern).
        InvalidKeyError: Key matches no supported profile.
        OSError: Artifact cannot be read.

    Example:
        >>> key = generate_private_key("ed25519")
        >>> manifest, bundle = create_bundle("contoh-app.zip", "contoh-app", "1.0.0", key)
        >>> manifest.artifact.name
        'contoh-app.zip'
    """
    size, sha256 = hash_file(file_path)
    manifest = Manifest(
        package=package,
        version=version,
        algorithm=detect_profile(private_key),
        keyid=compute_keyid(private_key.public_key()),
        artifact=Artifact(name=os.path.basename(file_path), size=size, sha256=sha256),
    )
    manifest_bytes = serialize_manifest(manifest)
    signature = sign(private_key, manifest_bytes)
    return manifest, serialize_bundle(manifest_bytes, signature)

def _validate_metadata(package: str, version: str) -> None:
    if PACKAGE_RE.fullmatch(package) is None:
        raise FormatError(f"--package: {package!r} does not match {PACKAGE_RE.pattern}")
    if VERSION_RE.fullmatch(version) is None:
        raise FormatError(f"--version: {version!r} does not match {VERSION_RE.pattern}")


def _validate_output(file_path: str, out_path: str) -> None:
    if os.path.abspath(out_path) == os.path.abspath(file_path):
        raise SignerError("--out must not be the artifact file")
    if os.path.lexists(out_path):
        raise SignerError(f"output file already exists: {out_path}")
