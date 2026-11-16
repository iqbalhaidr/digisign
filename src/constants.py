"""Global constants: schema identifiers, size limits, and field validation patterns.

All ``*_RE`` patterns are used with :meth:`re.Pattern.fullmatch`, so the whole
string must match (no ``^``/``$`` anchors needed).
"""

import re

#: Program version (shown by ``--version`` and recorded as the SBOM tool).
PROGRAM_VERSION = "1.1.0"

#: Required value of the manifest ``schema`` field.
MANIFEST_SCHEMA = "minisign-manifest/v1"
#: Required value of the bundle ``schema`` field.
BUNDLE_SCHEMA = "minisign-bundle/v1"

#: Maximum canonical manifest size in bytes (16 KiB).
MAX_MANIFEST_BYTES = 16 * 1024
#: Maximum bundle file size in bytes (64 KiB).
MAX_BUNDLE_BYTES = 64 * 1024
#: Largest JSON-safe integer (``2**53 - 1``); upper bound of ``artifact.size``.
MAX_SAFE_INT = 2**53 - 1

#: Package name: starts with a lowercase letter/digit, then ``[a-z0-9._-]``; 1–64 chars.
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
#: Release version: starts with an alphanumeric, then ``[A-Za-z0-9._+-]``; 1–64 chars.
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
#: Artifact file name: starts with an alphanumeric, then ``[A-Za-z0-9._-]``; 1–128 chars.
ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
#: 64 lowercase hex characters (SHA-256 digest and keyid).
HEX64_RE = re.compile(r"[0-9a-f]{64}")
