"""Verify: verification results (status, exit code) and the 8-step release check."""

from src.verify.result import (
    ARTIFACT_MISMATCH,
    EXIT_CODES,
    FORMAT_ERROR,
    INPUT_ERROR,
    INVALID_SIGNATURE,
    KEY_NOT_TRUSTED,
    METADATA_MISMATCH,
    OK,
    UNSUPPORTED_ALGORITHM,
    VerifyResult,
)
from src.verify.verify import verify_command, verify_release

__all__ = [
    "ARTIFACT_MISMATCH",
    "EXIT_CODES",
    "FORMAT_ERROR",
    "INPUT_ERROR",
    "INVALID_SIGNATURE",
    "KEY_NOT_TRUSTED",
    "METADATA_MISMATCH",
    "OK",
    "UNSUPPORTED_ALGORITHM",
    "VerifyResult",
    "verify_command",
    "verify_release",
]
