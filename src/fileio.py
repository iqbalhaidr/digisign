"""File I/O utilities: streaming hashing and safe file writes.

Writes are *crash-safe*: data is ``fsync``-ed before the file is considered
complete, and partial files are removed on failure.
"""

import contextlib
import hashlib
import os
import tempfile

#: Default mode for public files (bundle, public key, trust store).
PUBLIC_FILE_MODE = 0o644
#: Mode for private key files (owner only).
PRIVATE_FILE_MODE = 0o600

_CHUNK_SIZE = 1024 * 1024

def hash_file(path: str) -> tuple[int, str]:
    """Compute a file's size and SHA-256 digest by streaming.

    The file is read in 1 MiB chunks, so memory use is constant regardless of
    artifact size.

    Args:
        path (str): Path of the file to hash.

    Returns:
        tuple[int, str]: ``(size, sha256)`` — size in bytes and SHA-256 digest
        as 64 lowercase hex characters.

    Raises:
        OSError: File does not exist or cannot be read.

    Example:
        >>> size, digest = hash_file("contoh-app.zip")
        >>> len(digest)
        64
    """
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()

def write_new(path: str, data: bytes, mode: int = PUBLIC_FILE_MODE) -> None:
    """Write a **new** file; fail if the path already exists.

    Uses ``O_CREAT | O_EXCL`` so it never overwrites another file (including
    symlinks). If the write fails midway, the partial file is removed.

    Args:
        path (str): Destination path. Must not exist.
        data (bytes): File contents.
        mode (int): New file mode. Default :data:`PUBLIC_FILE_MODE`
            (``0o644``); use :data:`PRIVATE_FILE_MODE` (``0o600``) for private keys.

    Returns:
        None

    Raises:
        FileExistsError: Path already exists.
        OSError: Other I/O failure.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise

def write_atomic(path: str, data: bytes, mode: int = PUBLIC_FILE_MODE) -> None:
    """Atomically write or overwrite a file.

    Data is written to a temporary file in the same directory, ``fsync``-ed,
    given ``mode``, then moved into place with :func:`os.replace`. Readers see
    either the complete old or the complete new contents, never a partial file.
    Used for the trust store and ``keygen --force``.

    Args:
        path (str): Destination path (may already exist).
        data (bytes): File contents.
        mode (int): Final file mode. Default ``0o644``.

    Returns:
        None

    Raises:
        OSError: I/O failure; the temporary file is removed and the old file is left intact.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    _fsync_directory(directory)

def _fsync_directory(directory: str) -> None:
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
