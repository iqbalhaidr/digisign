"""Parser JSON ketat dan helper validasi tipe.

Dibangun di atas :mod:`json` standar dengan hook tambahan untuk menolak
konstruksi yang ambigu atau berbahaya bagi kontrak format.
"""

import json
from typing import Any, NoReturn

from src.errors import FormatError

_BOM = b"\xef\xbb\xbf"

def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"duplicate key: {key!r}")
        obj[key] = value
    return obj

def _reject_constant(name: str) -> NoReturn:
    raise FormatError(f"JSON constant not allowed: {name}")

def _reject_float(name: str) -> NoReturn:
    raise FormatError(f"Non-integer number not allowed: {name}")

def _reject_null(value: object, where: str = "root") -> None:
    if value is None:
        raise FormatError(f"null value not allowed on {where}")

    if isinstance(value, dict):
        for key, item in value.items():
            _reject_null(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_null(item, f"{where}[{index}]")

def parse_strict(data: bytes, max_bytes: int | None = None) -> Any:
    """Parse JSON dengan aturan ketat.

    Yang ditolak:

    * Ukuran melebihi ``max_bytes`` (diperiksa sebelum parsing).
    * UTF-8 BOM dan byte non-UTF-8.
    * Nama field duplikat pada objek mana pun.
    * Konstanta ``NaN``, ``Infinity``, ``-Infinity``.
    * Bilangan non-integer (pecahan/eksponen).
    * Nilai ``null`` di posisi mana pun.

    Args:
        data (bytes): Dokumen JSON mentah.
        max_bytes (int | None): Batas ukuran opsional dalam byte.

    Returns:
        Any: Nilai Python hasil parsing (``dict``, ``list``, ``str``, ``int``, ``bool``).

    Raises:
        FormatError: Bila salah satu aturan dilanggar atau JSON tidak valid.

    Example:
        >>> parse_strict(b'{"a": 1}')
        {'a': 1}
        >>> parse_strict(b'{"a": 1, "a": 2}')
        Traceback (most recent call last):
        ...
        src.errors.FormatError: duplicate key: 'a'
    """
    if max_bytes is not None and len(data) > max_bytes:
        raise FormatError(f"{len(data)} bytes exceed the max {max_bytes} bytes")

    if data.startswith(_BOM):
        raise FormatError("BOM is not allowed")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise FormatError("invalid UTF-8") from e

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float
        )
    except (ValueError, RecursionError) as e:
        raise FormatError(f"Invalid JSON: {e}") from e

    _reject_null(value)

    return value

def expect_object(value: object, keys: list[str], where: str) -> dict[str, Any]:
    """Pastikan ``value`` adalah objek dengan himpunan field tepat ``keys``.

    Field yang kurang maupun berlebih sama-sama ditolak.

    Args:
        value (object): Nilai hasil :func:`parse_strict`.
        keys (list[str]): Daftar nama field yang wajib ada (dan satu-satunya yang boleh ada).
        where (str): Lokasi untuk pesan error, mis. ``"manifest.artifact"``.

    Returns:
        dict[str, Any]: ``value`` itu sendiri.

    Raises:
        FormatError: Bukan ``dict`` atau himpunan field berbeda.
    """
    if type(value) is not dict:
        raise FormatError(f"{where}: must be an object")

    expected = set(keys)
    actual = set(value)

    if actual != expected:
        raise FormatError(
            f"{where}: field is incompatible "
            f"(less={sorted(expected - actual)}, more={sorted(actual - expected)})"
        )
    return value

def expect_str(value: object, where: str) -> str:
    """Pastikan ``value`` bertipe ``str``.

    Args:
        value (object): Nilai yang diperiksa.
        where (str): Lokasi untuk pesan error.

    Returns:
        str: ``value`` itu sendiri.

    Raises:
        FormatError: Bukan string.
    """
    if type(value) is not str:
        raise FormatError(f"{where}: must be a string")
    return value

def expect_int(value: object, where: str, minimum: int, maximum: int) -> int:
    """Pastikan ``value`` integer (bukan ``bool``) dalam rentang inklusif.

    Args:
        value (object): Nilai yang diperiksa.
        where (str): Lokasi untuk pesan error.
        minimum (int): Batas bawah inklusif.
        maximum (int): Batas atas inklusif.

    Returns:
        int: ``value`` itu sendiri.

    Raises:
        FormatError: Bukan ``int`` atau di luar ``minimum..maximum``.
    """
    if type(value) is not int:
        raise FormatError(f"{where}: must be an integer")
    if not minimum <= value <= maximum:
        raise FormatError(f"{where}: is outside range of {minimum}..{maximum}")
    return value
