"""Status hasil verifikasi dan pemetaannya ke exit code.

========================= ========= ==================================================
Status                    Exit code Arti
========================= ========= ==================================================
``OK``                    0         Signature dan artefak valid
``FORMAT_ERROR``          1         Bundle/manifest/trust store tidak sesuai format
``UNSUPPORTED_ALGORITHM`` 1         Profil algoritma manifest tidak dikenal
``KEY_NOT_TRUSTED``       1         Kunci tidak tepercaya untuk paket tersebut
``INVALID_SIGNATURE``     1         Signature tidak cocok dengan manifest
``METADATA_MISMATCH``     1         Paket, versi, atau nama artefak berbeda
``ARTIFACT_MISMATCH``     1         Ukuran atau SHA-256 artefak berbeda
``INPUT_ERROR``           2         Berkas tidak dapat dibaca / argumen CLI salah
========================= ========= ==================================================
"""

import json
from dataclasses import dataclass

OK = "OK"
INPUT_ERROR = "INPUT_ERROR"
FORMAT_ERROR = "FORMAT_ERROR"
UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
METADATA_MISMATCH = "METADATA_MISMATCH"
ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"

EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_INPUT_ERROR = 2

#: Pemetaan status verifikasi ke exit code CLI.
EXIT_CODES: dict[str, int] = {
    OK: EXIT_OK,
    FORMAT_ERROR: EXIT_REJECTED,
    UNSUPPORTED_ALGORITHM: EXIT_REJECTED,
    KEY_NOT_TRUSTED: EXIT_REJECTED,
    INVALID_SIGNATURE: EXIT_REJECTED,
    METADATA_MISMATCH: EXIT_REJECTED,
    ARTIFACT_MISMATCH: EXIT_REJECTED,
    INPUT_ERROR: EXIT_INPUT_ERROR,
}

@dataclass(frozen=True)
class VerifyResult:
    """Hasil akhir verifikasi rilis (immutable).

    Attributes:
        status (str): Salah satu konstanta status di modul ini.
        message (str): Penjelasan singkat yang dapat dibaca manusia.
        algorithm (str | None): Profil algoritma dari manifest, bila sudah ter-parse.
        keyid (str | None): ``keyid`` dari manifest, bila sudah ter-parse.
        package (str | None): Nama paket dari manifest, bila sudah ter-parse.
        version (str | None): Versi dari manifest, bila sudah ter-parse.

    Raises:
        ValueError: ``status`` tidak dikenal.
    """
    status: str
    message: str
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        if self.status not in EXIT_CODES:
            raise ValueError(f"unknown verification status: {self.status!r}")

    @property
    def valid(self) -> bool:
        """bool: ``True`` hanya bila :attr:`status` adalah ``OK``."""
        return self.status == OK

    @property
    def exit_code(self) -> int:
        """int: Exit code CLI untuk :attr:`status` (lihat :data:`EXIT_CODES`)."""
        return EXIT_CODES[self.status]

    def to_json(self) -> str:
        r"""Serialisasi hasil ke satu baris JSON (keluaran ``verify --json``).

        Returns:
            str: JSON ASCII dengan field ``valid``, ``status``, ``message``,
            ``algorithm``, ``keyid``, ``package``, ``version`` diakhiri newline.

        Example:
            >>> VerifyResult("KEY_NOT_TRUSTED", "keyid is not in the trust store").to_json()
            '{"valid": false, "status": "KEY_NOT_TRUSTED", "message": "keyid is not in the trust store", "algorithm": null, "keyid": null, "package": null, "version": null}\n'
        """
        document = {
            "valid": self.valid,
            "status": self.status,
            "message": self.message,
            "algorithm": self.algorithm,
            "keyid": self.keyid,
            "package": self.package,
            "version": self.version,
        }
        return json.dumps(document, ensure_ascii=True) + "\n"