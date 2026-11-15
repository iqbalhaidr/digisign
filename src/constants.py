"""Konstanta global: identitas skema, batas ukuran, dan pola validasi field.

Seluruh pola ``*_RE`` dipakai dengan :meth:`re.Pattern.fullmatch`, sehingga
string harus cocok secara utuh (tanpa anchor ``^``/``$``).
"""

import re

#: Nilai wajib field ``schema`` pada manifest.
MANIFEST_SCHEMA = "minisign-manifest/v1"
#: Nilai wajib field ``schema`` pada bundle.
BUNDLE_SCHEMA = "minisign-bundle/v1"

#: Ukuran maksimum manifest canonical dalam byte (16 KiB).
MAX_MANIFEST_BYTES = 16 * 1024
#: Ukuran maksimum berkas bundle dalam byte (64 KiB).
MAX_BUNDLE_BYTES = 64 * 1024
#: Bilangan bulat terbesar yang aman di JSON (``2**53 - 1``); batas atas ``artifact.size``.
MAX_SAFE_INT = 2**53 - 1

#: Pola nama paket: diawali huruf kecil/angka, lalu ``[a-z0-9._-]``, panjang total 1–64.
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
#: Pola versi rilis: diawali alfanumerik, lalu ``[A-Za-z0-9._+-]``, panjang total 1–64.
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
#: Pola nama berkas artefak: diawali alfanumerik, lalu ``[A-Za-z0-9._-]``, panjang total 1–128.
ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
#: Pola 64 karakter heksadesimal huruf kecil (digest SHA-256 dan keyid).
HEX64_RE = re.compile(r"[0-9a-f]{64}")
