import json

from errors import FormatError

_BOM = b"\xef\xbb\xbf"

def _reject_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"duplicate key: {key!r}")
        obj[key] = value
    return obj

def _reject_constant(name):
    raise FormatError(f"JSON constant not allowed: {name}")

def _reject_float(name):
    raise FormatError(f"Non-integer number not allowed: {name}")

def _reject_null(value, where="root"):
    if value is None:
        raise FormatError(f"null value not allowed on {where}")

    if isinstance(value, dict):
        for key, item in value.items():
            _reject_null(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_null(item, f"{where}[{index}]")

def parse_strict(data, max_bytes=None):
    if max_bytes is not None and len(data) > max_bytes:
        raise FormatError(f"{len(data)} sizes exceed the max {max_bytes} byte")

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

def expect_object(value, keys, where):
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

def expect_str(value, where):
    if type(value) is not str:
        raise FormatError(f"{where}: must be a string")
    return value

def expect_int(value, where, minimum, maximum):
    if type(value) is not int:
        raise FormatError(f"{where}: must be an integer")
    if not minimum <= value <= maximum:
        raise FormatError(f"{where}: is outside range of {minimum}..{maximum}")
    return value
