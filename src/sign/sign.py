import base64
import hashlib
import json
import os
import sys
from typing import TextIO

from src.constants import BUNDLE_SCHEMA, MAX_BUNDLE_BYTES, PACKAGE_RE, VERSION_RE
from src.crypto import PrivateKey, compute_keyid, detect_profile, load_private_key_pem, sign
from src.data.manifest import Artifact, Manifest, serialize_manifest
from src.errors import FormatError, SignerError
from src.fileio import write_new

EXIT_OK = 0
EXIT_FAILURE = 2

_CHUNK_SIZE = 1024 * 1024

def sign_command(
    file_path: str,
    package: str,
    version: str,
    key_path: str,
    out_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
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
    size, sha256 = hash_artifact(file_path)
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

def hash_artifact(path: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()

def serialize_bundle(manifest_bytes: bytes, signature: bytes) -> bytes:
    document = {
        "schema": BUNDLE_SCHEMA,
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    data = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    if len(data) > MAX_BUNDLE_BYTES:
        raise FormatError(f"bundle: exceeds {MAX_BUNDLE_BYTES} bytes")
    return data

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
