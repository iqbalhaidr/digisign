import sys
from typing import TextIO

from src.crypto import load_public_key_pem
from src.errors import SignerError
from src.trust.store import (
    TrustEntry,
    TrustStore,
    load_trust_store,
    save_trust_store,
    validate_package_name,
)

EXIT_OK = 0
EXIT_FAILURE = 2

def trust_add(
    key_path: str,
    package: str,
    store_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    try:
        validate_package_name(package, "--package")
        with open(key_path, "rb") as f:
            public_key = load_public_key_pem(f.read())
        store = _load_or_create(store_path)
        entry, changed = store.add(public_key, package)
        if changed:
            save_trust_store(store, store_path)
    except (SignerError, OSError) as e:
        return _fail(err, e)

    out.write(f"keyid:     {entry.keyid}\n")
    out.write(f"algorithm: {entry.algorithm}\n")
    out.write(f"packages:  {', '.join(entry.packages)}\n")
    err.write("trust store updated\n" if changed else "already trusted, no changes\n")
    return EXIT_OK

def trust_list(store_path: str, out: TextIO | None = None, err: TextIO | None = None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    try:
        store = load_trust_store(store_path)
    except (SignerError, OSError) as e:
        return _fail(err, e)

    if not store.entries:
        err.write("trust store is empty\n")
    for entry in store.entries:
        out.write(_format_line(entry))
    return EXIT_OK

def trust_remove(
    keyid: str,
    store_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    try:
        store = load_trust_store(store_path)
        if not store.remove(keyid):
            err.write(f"error: keyid not found in trust store: {keyid}\n")
            return EXIT_FAILURE
        save_trust_store(store, store_path)
    except (SignerError, OSError) as e:
        return _fail(err, e)

    out.write(f"removed: {keyid}\n")
    return EXIT_OK


def _load_or_create(store_path: str) -> TrustStore:
    try:
        return load_trust_store(store_path)
    except FileNotFoundError:
        return TrustStore()


def _format_line(entry: TrustEntry) -> str:
    return f"{entry.keyid}  {entry.algorithm}  {','.join(entry.packages)}\n"


def _fail(err: TextIO, error: Exception) -> int:
    err.write(f"error: {error}\n")
    return EXIT_FAILURE
