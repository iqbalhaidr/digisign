r"""Model, parsing ketat, dan penyimpanan atomik trust store.

Contoh berkas trust store::

    {
      "schema": "minisign-trust/v1",
      "keys": [
        {
          "keyid": "<64 hex>",
          "algorithm": "ed25519",
          "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
          "packages": ["contoh-app"]
        }
      ]
    }
"""

import json
from dataclasses import dataclass, field

from src.constants import HEX64_RE, PACKAGE_RE
from src.crypto import (
    PublicKey,
    compute_keyid,
    detect_profile,
    is_supported,
    load_public_key_pem,
    public_key_to_pem,
    require_profile,
)
from src.data.strict_json import expect_object, expect_str, parse_strict
from src.errors import FormatError, InvalidKeyError
from src.fileio import write_atomic

#: Nilai wajib field ``schema`` pada trust store.
TRUST_SCHEMA = "minisign-trust/v1"

_STORE_KEYS = ["schema", "keys"]
_ENTRY_KEYS = ["keyid", "algorithm", "public_key_pem", "packages"]
_WILDCARD_CHARS = "*?[]"

def validate_package_name(name: object, where: str = "package") -> str:
    """Validasi nama paket untuk trust store.

    Wildcard (``*``, ``?``, ``[``, ``]``) ditolak secara eksplisit agar izin
    paket selalu berupa pencocokan persis.

    Args:
        name (object): Nilai yang divalidasi.
        where (str): Lokasi untuk pesan error.

    Returns:
        str: Nama paket yang valid.

    Raises:
        FormatError: Bukan string, mengandung wildcard, atau tidak cocok
            :data:`~src.constants.PACKAGE_RE`.
    """
    name = expect_str(name, where)
    if any(char in name for char in _WILDCARD_CHARS):
        raise FormatError(f"{where}: wildcard is not allowed ({name!r})")
    if PACKAGE_RE.fullmatch(name) is None:
        raise FormatError(f"{where}: {name!r} does not match {PACKAGE_RE.pattern}")
    return name

@dataclass
class TrustEntry:
    """Satu kunci publik tepercaya beserta daftar paket yang diizinkan.

    Attributes:
        keyid (str): Fingerprint kunci publik.
        algorithm (str): Profil algoritma kunci.
        public_key (PublicKey): Objek kunci publik.
        packages (list[str]): Nama paket yang boleh ditandatangani kunci ini.
    """
    keyid: str
    algorithm: str
    public_key: PublicKey
    packages: list[str]

    def allows(self, package: str) -> bool:
        """Periksa apakah kunci ini diizinkan untuk ``package``.

        Args:
            package (str): Nama paket (pencocokan persis).

        Returns:
            bool: ``True`` bila ``package`` ada di :attr:`packages`.
        """
        return package in self.packages

@dataclass
class TrustStore:
    """Kumpulan :class:`TrustEntry` dengan ``keyid`` unik.

    Attributes:
        entries (list[TrustEntry]): Entri sesuai urutan di berkas.
    """
    entries: list[TrustEntry] = field(default_factory=list)

    def find(self, keyid: str) -> TrustEntry | None:
        """Cari entri berdasarkan ``keyid``.

        Args:
            keyid (str): Fingerprint kunci.

        Returns:
            TrustEntry | None: Entri yang cocok, atau ``None``.
        """
        for entry in self.entries:
            if entry.keyid == keyid:
                return entry
        return None

    def add(self, public_key: PublicKey, package: str) -> tuple[TrustEntry, bool]:
        """Tambahkan izin ``package`` untuk ``public_key``.

        Bila kunci belum ada, entri baru dibuat. Bila sudah ada, ``package``
        ditambahkan ke daftar paketnya (idempoten).

        Args:
            public_key (PublicKey): Kunci publik yang dipercaya.
            package (str): Nama paket yang diizinkan.

        Returns:
            tuple[TrustEntry, bool]: Entri terkait dan flag apakah store berubah.

        Raises:
            FormatError: Nama paket tidak valid.
            InvalidKeyError: Kunci tidak sesuai profil mana pun.

        Example:
            >>> store = TrustStore()
            >>> entry, changed = store.add(public_key, "contoh-app")
            >>> changed
            True
            >>> store.add(public_key, "contoh-app")[1]
            False
        """
        validate_package_name(package)
        keyid = compute_keyid(public_key)

        entry = self.find(keyid)
        if entry is None:
            entry = TrustEntry(keyid, detect_profile(public_key), public_key, [package])
            self.entries.append(entry)
            return entry, True
        if entry.allows(package):
            return entry, False
        entry.packages.append(package)
        return entry, True

    def remove(self, keyid: str) -> bool:
        """Hapus entri berdasarkan ``keyid``.

        Args:
            keyid (str): Fingerprint kunci.

        Returns:
            bool: ``True`` bila entri ditemukan dan dihapus.
        """
        entry = self.find(keyid)
        if entry is None:
            return False
        self.entries.remove(entry)
        return True

def parse_trust_store(data: bytes) -> TrustStore:
    """Parse dan validasi isi berkas trust store.

    Setiap entri divalidasi: format ``keyid``, profil didukung, PEM ASCII dan
    sesuai profil, ``keyid`` cocok dengan fingerprint PEM, ``packages`` tidak
    kosong, tanpa duplikat, dan tanpa wildcard. ``keyid`` duplikat antar-entri ditolak.

    Args:
        data (bytes): Isi berkas trust store.

    Returns:
        TrustStore: Trust store tervalidasi.

    Raises:
        FormatError: Salah satu aturan di atas dilanggar.
    """
    root = parse_strict(data)
    expect_object(root, _STORE_KEYS, "trust")

    if expect_str(root["schema"], "trust.schema") != TRUST_SCHEMA:
        raise FormatError(f"trust.schema: must be {TRUST_SCHEMA}")

    keys = root["keys"]
    if type(keys) is not list:
        raise FormatError("trust.keys: must be an array")

    store = TrustStore()
    for index, raw in enumerate(keys):
        where = f"trust.keys[{index}]"
        entry = _parse_entry(raw, where)
        if store.find(entry.keyid) is not None:
            raise FormatError(f"{where}.keyid: duplicate keyid {entry.keyid}")
        store.entries.append(entry)
    return store

def _parse_entry(raw: object, where: str) -> TrustEntry:
    expect_object(raw, _ENTRY_KEYS, where)

    keyid = expect_str(raw["keyid"], f"{where}.keyid")
    if HEX64_RE.fullmatch(keyid) is None:
        raise FormatError(f"{where}.keyid: must be 64 lowercase hex characters")

    algorithm = expect_str(raw["algorithm"], f"{where}.algorithm")
    if not is_supported(algorithm):
        raise FormatError(f"{where}.algorithm: unsupported profile {algorithm!r}")

    pem = expect_str(raw["public_key_pem"], f"{where}.public_key_pem")
    if not pem.isascii():
        raise FormatError(f"{where}.public_key_pem: contains non-ASCII characters")
    try:
        public_key = load_public_key_pem(pem.encode("ascii"))
        require_profile(public_key, algorithm)
    except InvalidKeyError as e:
        raise FormatError(f"{where}.public_key_pem: {e}") from e

    if compute_keyid(public_key) != keyid:
        raise FormatError(f"{where}.keyid: does not match the fingerprint of public_key_pem")

    packages = _parse_packages(raw["packages"], f"{where}.packages")
    return TrustEntry(keyid, algorithm, public_key, packages)

def _parse_packages(value: object, where: str) -> list[str]:
    if type(value) is not list:
        raise FormatError(f"{where}: must be an array")
    if not value:
        raise FormatError(f"{where}: must not be empty")
    packages = [validate_package_name(item, f"{where}[{i}]") for i, item in enumerate(value)]
    if len(set(packages)) != len(packages):
        raise FormatError(f"{where}: contains duplicate package names")
    return packages

def serialize_trust_store(store: TrustStore) -> bytes:
    """Serialisasi trust store ke JSON.

    Args:
        store (TrustStore): Trust store yang akan disimpan.

    Returns:
        bytes: JSON ASCII ber-indentasi 2 spasi diakhiri newline.
    """
    document = {
        "schema": TRUST_SCHEMA,
        "keys": [
            {
                "keyid": entry.keyid,
                "algorithm": entry.algorithm,
                "public_key_pem": public_key_to_pem(entry.public_key).decode("ascii"),
                "packages": list(entry.packages),
            }
            for entry in store.entries
        ],
    }
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")

def load_trust_store(path: str) -> TrustStore:
    """Baca dan parse trust store dari berkas.

    Args:
        path (str): Path berkas trust store.

    Returns:
        TrustStore: Trust store tervalidasi.

    Raises:
        OSError: Berkas tidak dapat dibaca (``FileNotFoundError`` bila tidak ada).
        FormatError: Isi berkas tidak valid.
    """
    with open(path, "rb") as f:
        return parse_trust_store(f.read())

def save_trust_store(store: TrustStore, path: str) -> None:
    """Simpan trust store ke berkas secara atomik.

    Args:
        store (TrustStore): Trust store yang akan disimpan.
        path (str): Path tujuan.

    Returns:
        None

    Raises:
        OSError: Kegagalan I/O (berkas lama tetap utuh).
    """
    write_atomic(path, serialize_trust_store(store))
