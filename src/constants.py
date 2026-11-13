import re

MANIFEST_SCHEMA = "minisign-manifest/v1"
BUNDLE_SCHEMA = "minisign-bundle/v1"

MAX_MANIFEST_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = 64 * 1024
MAX_SAFE_INT = 2**53 - 1

PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
