"""Utilitas I/O berkas: hashing streaming dan penulisan berkas yang aman.

Penulisan dibuat *crash-safe*: data di-``fsync`` sebelum berkas dianggap jadi,
dan berkas parsial dihapus bila terjadi kegagalan.
"""

import contextlib
import hashlib
import os
import tempfile

#: Permission default berkas publik (bundle, kunci publik, trust store).
PUBLIC_FILE_MODE = 0o644
#: Permission berkas kunci privat (hanya pemilik).
PRIVATE_FILE_MODE = 0o600

_CHUNK_SIZE = 1024 * 1024

def hash_file(path: str) -> tuple[int, str]:
    """Hitung ukuran dan digest SHA-256 sebuah berkas secara streaming.

    Berkas dibaca per blok 1 MiB sehingga penggunaan memori konstan
    berapapun ukuran artefaknya.

    Args:
        path (str): Path berkas yang akan di-hash.

    Returns:
        tuple[int, str]: Pasangan ``(size, sha256)`` — ukuran dalam byte dan
        digest SHA-256 dalam 64 karakter heksadesimal huruf kecil.

    Raises:
        OSError: Berkas tidak ada atau tidak dapat dibaca.

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
    """Tulis berkas **baru**; gagal bila path sudah ada.

    Memakai ``O_CREAT | O_EXCL`` sehingga tidak pernah menimpa berkas lain
    (termasuk symlink). Jika penulisan gagal di tengah jalan, berkas parsial
    dihapus.

    Args:
        path (str): Path tujuan. Tidak boleh sudah ada.
        data (bytes): Isi berkas.
        mode (int): Permission berkas baru. Default :data:`PUBLIC_FILE_MODE`
            (``0o644``); gunakan :data:`PRIVATE_FILE_MODE` (``0o600``) untuk kunci privat.

    Returns:
        None

    Raises:
        FileExistsError: Path sudah ada.
        OSError: Kegagalan I/O lainnya.
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
    """Tulis atau timpa berkas secara atomik.

    Data ditulis ke berkas sementara pada direktori yang sama, di-``fsync``,
    diberi permission ``mode``, lalu dipindahkan dengan :func:`os.replace`.
    Pembaca lain hanya akan melihat isi lama atau isi baru secara utuh, tidak
    pernah setengah jadi. Dipakai untuk trust store dan ``keygen --force``.

    Args:
        path (str): Path tujuan (boleh sudah ada).
        data (bytes): Isi berkas.
        mode (int): Permission akhir berkas. Default ``0o644``.

    Returns:
        None

    Raises:
        OSError: Kegagalan I/O; berkas sementara dibersihkan dan berkas lama tetap utuh.
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
