"""Verification statuses and their exit codes.

All possible verification statuses can be seen on :ref:`verification-status`.
and exit codes on :ref:`exit-code`.
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

#: Maps each verification status to its CLI exit code.
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
    """Final release verification result (immutable).

    Attributes:
        status (str): One of this module's status constants.
        message (str): Short human-readable explanation.
        algorithm (str | None): Manifest algorithm profile, if parsed.
        keyid (str | None): Manifest ``keyid``, if parsed.
        package (str | None): Manifest package name, if parsed.
        version (str | None): Manifest version, if parsed.

    Raises:
        ValueError: Unknown ``status``.
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
        """bool: ``True`` only if :attr:`status` is ``OK``."""
        return self.status == OK

    @property
    def exit_code(self) -> int:
        """int: CLI exit code for :attr:`status` (see :data:`EXIT_CODES`)."""
        return EXIT_CODES[self.status]

    def to_json(self) -> str:
        r"""Serialize the result to a single JSON line (``verify --json`` output).

        Returns:
            str: ASCII JSON with ``valid``, ``status``, ``message``,
            ``algorithm``, ``keyid``, ``package``, ``version``, ending with a newline.

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