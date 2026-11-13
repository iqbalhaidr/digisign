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
        return self.status == OK

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.status]

    def to_json(self) -> str:
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