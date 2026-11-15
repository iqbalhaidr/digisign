"""Implementasi subcommand ``keygen``.

Menghasilkan dua berkas dari satu prefix ``--out``:
``<prefix>.key.pem`` (PKCS#8, mode ``0600``) dan ``<prefix>.pub.pem`` (SPKI, mode ``0644``).
"""

import contextlib
import os
import sys
from typing import TextIO

from src.crypto import (
    compute_keyid,
    generate_private_key,
    private_key_to_pem,
    public_key_to_pem,
    require_supported,
)
from src.errors import SignerError
from src.fileio import PRIVATE_FILE_MODE, PUBLIC_FILE_MODE, write_atomic, write_new

EXIT_OK = 0
EXIT_FAILURE = 2

#: Akhiran nama berkas kunci privat.
PRIVATE_KEY_SUFFIX = ".key.pem"
#: Akhiran nama berkas kunci publik.
PUBLIC_KEY_SUFFIX = ".pub.pem"


def keygen_command(
    algorithm: str,
    out_prefix: str,
    force: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Bangkitkan pasangan kunci dan tulis ke disk (subcommand ``keygen``).

    Tanpa ``force``, berkas yang sudah ada tidak akan ditimpa dan bila kunci
    publik gagal ditulis, kunci privat yang baru dibuat dihapus kembali.
    Dengan ``force``, kedua berkas ditimpa secara atomik.

    Args:
        algorithm (str): Profil algoritma (``rsa-pss-sha256``, ``ecdsa-p256-sha256``, ``ed25519``).
        out_prefix (str): Prefix path keluaran, mis. ``keys/release``.
        force (bool): Timpa berkas yang sudah ada.
        out (TextIO | None): Stream keluaran normal. Default ``sys.stdout``.
        err (TextIO | None): Stream pesan error. Default ``sys.stderr``.

    Returns:
        int: ``0`` bila berhasil, ``2`` bila algoritma tidak dikenal, berkas sudah
        ada, atau terjadi kegagalan I/O.

    Example:
        >>> keygen_command("ed25519", "keys/release")
        keyid:       3f1c...
        algorithm:   ed25519
        private key: keys/release.key.pem
        public key:  keys/release.pub.pem
        0
    """
    out, err = out or sys.stdout, err or sys.stderr
    try:
        require_supported(algorithm)
        private_path, public_path = key_paths(out_prefix)
        if not force:
            _refuse_existing([private_path, public_path])

        private_key = generate_private_key(algorithm)
        public_key = private_key.public_key()
        _write_pair(
            private_path, private_key_to_pem(private_key),
            public_path, public_key_to_pem(public_key),
            force,
        )
        keyid = compute_keyid(public_key)
    except (SignerError, OSError) as e:
        err.write(f"error: {e}\n")
        return EXIT_FAILURE

    out.write(f"keyid:       {keyid}\n")
    out.write(f"algorithm:   {algorithm}\n")
    out.write(f"private key: {private_path}\n")
    out.write(f"public key:  {public_path}\n")
    return EXIT_OK

def key_paths(out_prefix: str) -> tuple[str, str]:
    """Turunkan path kunci privat dan publik dari sebuah prefix.

    Args:
        out_prefix (str): Prefix keluaran; bagian basename tidak boleh kosong.

    Returns:
        tuple[str, str]: ``(prefix + ".key.pem", prefix + ".pub.pem")``.

    Raises:
        SignerError: Prefix kosong atau diakhiri pemisah direktori.

    Example:
        >>> key_paths("keys/release")
        ('keys/release.key.pem', 'keys/release.pub.pem')
    """
    if not out_prefix or not os.path.basename(out_prefix):
        raise SignerError(f"--out: invalid prefix {out_prefix!r}")
    return out_prefix + PRIVATE_KEY_SUFFIX, out_prefix + PUBLIC_KEY_SUFFIX

def _refuse_existing(paths: list[str]) -> None:
    for path in paths:
        if os.path.lexists(path):
            raise SignerError(f"output file already exists: {path} (use --force to overwrite)")

def _write_pair(private_path: str, private_pem: bytes, public_path: str, public_pem: bytes, force: bool) -> None:
    if force:
        write_atomic(private_path, private_pem, PRIVATE_FILE_MODE)
        write_atomic(public_path, public_pem, PUBLIC_FILE_MODE)
        return

    write_new(private_path, private_pem, PRIVATE_FILE_MODE)
    try:
        write_new(public_path, public_pem, PUBLIC_FILE_MODE)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(private_path)
        raise
