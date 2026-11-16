# Others

## Algorithm
| Profiles | Information | Signature |
| ------ | ------------------ | --------- |
| `rsa-pss-sha256` | **Key:** RSA 3072 bit, public exponent 65537; **Scheme:** RSASSA-PSS (SHA-256, MGF1-SHA-256); **Salt:** 32 byte | 384 byte |
| `ecdsa-p256-sha256` | **Curve:** NIST P-256 / secp256r1; **Hash:** SHA-256; **Nonce:** CSPRNG/RFC 6979 | 64 byte |
| `ed25519` | **Variant:** Ed25519 (PureEdDSA) RFC 8032 | 64 byte |

## Key

| File | Format |
| ------ | ------ |
| `<prefix>.key.pem` | `PKCS#8` |
| `<prefix>.pub.pem` | `SubjectPublicKeyInfo (SPKI)` |

## Manifest

| Field | Type | Value |
| ----- | ---- | ------ |
| `schema` | string | `minisign-manifest/v1` |
| `package` | string | `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519` |
| `keyid` | string | 64 hex |
| `artifact` | object | `name`, `size`, `sha256` |
| `artifact.name` | string | `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` |
| `artifact.size` | integer | `0–9007199254740991` |
| `artifact.sha256` | string | 64 hex |

{class}`~src.data.manifest.Manifest`, {class}`~src.data.manifest.Artifact`.

## Bundle

| Field | Type | Value |
| ----- | ---- | ------ |
| `schema` | string | `minisign-bundle/v1` |
| `manifest_b64` | string | Base64 RFC 4648 |
| `signature_b64` | string | Base64 RFC 4648 |

{class}`~src.data.bundle.Bundle`

## Trust entry

| Field | Type | Value |
| ----- | ---- | ------ |
| `schema` | string | `minisign-trust/v1` |
| `keys` | array of object | Can be empty, `keyid` must be unique |
| `keys[].keyid` | string | 64 hex, `public_key_pem` fingerprint |
| `keys[].algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519` |
| `keys[].public_key_pem` | string | `.pub.pem` |
| `keys[].packages` | array of string | Can't empty, no duplicate, no wildcard (`* ? [ ]`) |

{class}`~src.trust.store.TrustEntry`

## SBOM
| Field | Type | Value |
| ----- | ---- | ------ |
| `bomFormat` | string | `CycloneDX` |
| `specVersion` | string | `1.4`, `1.5`, `1.6` (`sbom generate` writes `1.6`) |
| `metadata.component` | object | The release artifact |
| `metadata.component.name` | string | Must equal `--package` |
| `metadata.component.version` | string | Must equal `--version` |
| `metadata.component.hashes[]` | array of object | Exactly one `{"alg": "SHA-256", "content": <64 hex>}`, the release artifact SHA-256 |
| `metadata.component.properties[]` | array of object | Optional; `digisign:artifact:name` must equal the artifact file name |
| `components[]` | array of object | Optional; ZIP entries as `file` components with SHA-256 |

{class}`~src.sbom.document.SbomDocument`

## Output `verify --json` 
| Field | Type | Infomation |
| ----- | ---- | ---------- |
| `valid` | boolean | `true` iff `status == "OK"` |
| `status` | string | One of the `Verification status` |
| `message` | string | Short explanation |
| `algorithm` | string \| null | One of the `Algorithm` profile |
| `keyid` | string \| null | Read from manifest |
| `package` | string \| null | Read from manifest |
| `version` | string \| null | Read from manifest |

## Output `sbom check --json`
| Field | Type | Infomation |
| ----- | ---- | ---------- |
| `valid` | boolean | `true` iff `status == "OK"` |
| `status` | string | One of the `Verification status` |
| `stage` | string \| null | Failed stage: `release`, `sbom`, `binding`; `null` on `OK` |
| `message` | string | Short explanation |
| `artifact_sha256` | string \| null | From the verified release manifest |
| `release` | object \| null | Release bundle result, `verify --json` format |
| `sbom` | object \| null | SBOM bundle result, `verify --json` format |

{class}`~src.sbom.verify.SbomCheckResult`

(verification-status)=
## Verification status
| Status | Exit code | Causes |
| ------ | --------- | -------- |
| `INPUT_ERROR` | 2 | Can't read bundle, trust store, artifacts; wrong CLI args |
| `FORMAT_ERROR` | 1 | Invalid bundle, manifest, trust store format or encoding |
| `UNSUPPORTED_ALGORITHM` | 1 | `manifest.algorithm` isn't one of the Algorithms |
| `KEY_NOT_TRUSTED` | 1 | `keyid` not in trust store, profile missmatch, key not authorized for the package |
| `INVALID_SIGNATURE` | 1 | Wrong signature |
| `METADATA_MISMATCH` | 1 | `--package`, `--version`, file name missmatch with manifest |
| `ARTIFACT_MISMATCH` | 1 | size, sha256 missmatch with manifest |
| `SBOM_MISMATCH` | 1 | `sbom check` only: SBOM SHA-256, package, version, or artifact name differs from the release |
| `OK` | 0 | Pass all checks |

(exit-code)=
## Exit code
| Exit code | Causes |
| --------- | ---- |
| `0` | Success |
| `1` | `verify`, `sbom verify`, `sbom check` denied |
| `2` | Invalid args, I/O error, other non-`verify` commands error |

## ``sbom`` subcommand parameter

| Subcommand | Parameter | Output |
|---|---|---|
| `sbom generate` | `--file` | SBOM file |
| | `--package` / `--version` |  | |
| | `--out` |  | |
| `sbom sign` | `--sbom` | SBOM bundle |
| | `--file` |  | |
| | `--package` / `--version` |  | |
| | `--key` |  | |
| | `--out` |  | |
| `sbom verify` | `--sbom`, `--bundle`, `--trust-store` | Verification result status and exit code |
| | `--package` / `--version` |  | |
| | `--json` |  | |
| `sbom check` | `--file`, `--bundle` | `sbom check` json verification result and exit code |
| | `--sbom`, `--sbom-bundle` |  | |
| | `--trust-store` |  | |
| | `--package` / `--version` |  | |
| | `--json` |  | |