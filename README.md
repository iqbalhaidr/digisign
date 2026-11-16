# digisign
digisign adalah kakas penandatanganan dan verifikasi rilis perangkat lunak yang ditujukan untuk pipeline CI/CD. Algoritma tanda tangan yang didukung adalah RSA, ECDSA, dan EdDSA. Program melakukan tanda tangan pada release manifest (metadata) kemudian hasil tanda tangan dan release manifest disimpan dalam sebuah bundle. Proses verifikasi dilakukan menggunakan kunci yang terdaftar pada trust store.

| Links | |
|---|---|
| Image registry | [https://github.com/iqbalhaidr/digisign/pkgs/container/digisign](https://github.com/iqbalhaidr/digisign/pkgs/container/digisign) |
| API Documentation | [https://iqbalhaidr.github.io/digisign/](https://iqbalhaidr.github.io/digisign/) |


## Tech Stack
| Category | Tech |
|---|---|
| Language | Python |
| Registry | GitHub Container Registry |
| CI/CD | GitHub Actions |
| Container | Docker |

## Dependency
| Library | Version |
|---|---|
| `cryptography` | 50.0.2 |
| `sphinx` | 9.1.1 |
| `furo` | 2025.12.19 |
| `myst-parser` | 5.2.0 |
| stdlib | Python 3.12 |

## Run (Runner CI/CD)

### Release Image
| Version | Tag | Digest |
| ----- | --- | ------ |
| `v1.1.0` | ``1.1.0`` | ``sha256:`` |
| ``v1.0.0`` | ``1.0.0`` | ``sha256:046d973f54c64d776252465c3a4c0da0c75bd2d32f1e20965a2c3fb4c8a0077a`` |

### Runner CI/CD

```bash
# Sign
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
  "$IMAGE" sign --file /input/contoh-app.zip \
  --package contoh-app --version 1.0.0 \
  --key /run/signing.key.pem --out /output/rilis.json

# Verify
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/contoh-app.zip \
  --bundle /output/rilis.json --trust-store /trust.json \
  --package contoh-app --version 1.0.0 --json > out/verification.json
```

### Workflow Configuration (`.github/workflows/test.yml`)

| Component | Value |
| -------- | ----- |
| Image | ``1.1.0`` |
| Pre-build | test/ci/contoh-app.txt |
| --file | contoh-app.zip |
| --package | contoh-app |
| --version | 1.0.0 |
| --key | CI_SIGNING_KEY_RSA, CI_SIGNING_KEY_ECDSA, CI_SIGNING_KEY_ED25519 |
| --trust-store | test/ci/trust.json |

Last Workflow Run: [https://github.com/iqbalhaidr/digisign/actions/runs/](https://github.com/iqbalhaidr/digisign/actions/runs/)

## Run (Manual)
```bash
git clone https://github.com/iqbalhaidr/digisign.git && cd digisign
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
python -m src.main --help
alias digisign='python -m src.main'  # optional
```

## Subcommands

```bash
# 1. Keygen
digisign keygen --algorithm ed25519 --out keys/publisher 
# --force untuk menimpa kunci

# 2. Trust store
digisign trust add    --key keys/publisher.pub.pem --package contoh-app --store trust.json
digisign trust list   --store trust.json
digisign trust remove --keyid <64-hex-keyid> --store trust.json

# 3. Sign
digisign sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json

# 4. Verify
digisign verify --file contoh-app.zip --bundle release.json --trust-store trust.json \
  --package contoh-app --version 1.0.0 --json

# 5. Signed SBOM
digisign sbom generate --file contoh-app.zip --package contoh-app --version 1.0.0 --out contoh-app.cdx.json
digisign sbom sign  --sbom contoh-app.cdx.json --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out contoh-app.cdx.bundle.json
digisign sbom verify --sbom contoh-app.cdx.json --bundle contoh-app.cdx.bundle.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
digisign sbom check --file contoh-app.zip --bundle release.json \
  --sbom contoh-app.cdx.json --sbom-bundle contoh-app.cdx.bundle.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
```

## Format 

### Algorithm
| Profile | Information | Signature |
| ------ | ------------------ | --------- |
| `rsa-pss-sha256` | **Key:** RSA 3072 bit, public exponent 65537; **Scheme:** RSASSA-PSS (SHA-256, MGF1-SHA-256); **Salt:** 32 byte | 384 byte |
| `ecdsa-p256-sha256` | **Curve:** NIST P-256 / secp256r1; **Hash:** SHA-256; **Nonce:** CSPRNG/RFC 6979 | 64 byte |
| `ed25519` | **Variant:** Ed25519 (PureEdDSA) RFC 8032 | 64 byte |

### Key

| File | Format |
| ------ | ------ |
| `<prefix>.key.pem` | `PKCS#8` |
| `<prefix>.pub.pem` | `SubjectPublicKeyInfo (SPKI)` |

### Manifest

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

### Bundle

| Field | Type | Value |
| ----- | ---- | ------ |
| `schema` | string | `minisign-bundle/v1` |
| `manifest_b64` | string | Base64 RFC 4648 |
| `signature_b64` | string | Base64 RFC 4648 |

### Trust entry

| Field | Type | Value |
| ----- | ---- | ------ |
| `schema` | string | `minisign-trust/v1` |
| `keys` | array of object | Can be empty, `keyid` must be unique |
| `keys[].keyid` | string | 64 hex, `public_key_pem` fingerprint |
| `keys[].algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519` |
| `keys[].public_key_pem` | string | `.pub.pem` |
| `keys[].packages` | array of string | Can't empty, no duplicate, no wildcard (`* ? [ ]`) |

### SBOM
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

### Output `verify --json` 
| Field | Type | Infomation |
| ----- | ---- | ---------- |
| `valid` | boolean | `true` iff `status == "OK"` |
| `status` | string | One of the `Verification status` |
| `message` | string | Short explanation |
| `algorithm` | string \| null | One of the `Algorithm` profile |
| `keyid` | string \| null | Read from manifest |
| `package` | string \| null | Read from manifest |
| `version` | string \| null | Read from manifest |

### Output `sbom check --json`
| Field | Type | Infomation |
| ----- | ---- | ---------- |
| `valid` | boolean | `true` iff `status == "OK"` |
| `status` | string | One of the `Verification status` |
| `stage` | string \| null | Failed stage: `release`, `sbom`, `binding`; `null` on `OK` |
| `message` | string | Short explanation |
| `artifact_sha256` | string \| null | From the verified release manifest |
| `release` | object \| null | Release bundle result, `verify --json` format |
| `sbom` | object \| null | SBOM bundle result, `verify --json` format |


## Testing
| Test | Script |
|---|---|
| U01–U14 | `python test/scenarios/run_scenarios.py` |
| Interoperability | `python test/interop/run_interop.py` |
| Performance | `python test/performance/benchmark.py` |
| C01–C05 | GitHub Actions **test** -> *Run workflow* |
| Signed SBOM | `python test/sbom/run_sbom.py` |

- `test/scenarios/keys/` berisi pasangan kunci **khusus pengujian**. 
- `test/ci/keys/` berisi kunci publik demo pipeline. kunci privat disimpan sebagai GitHub Secrets.

## Contributor
| NIM | Name | 
|-----|------|
| 13523023 | Muhammad Aufa Farabi |
| 13523025 | Joel Hotlan Haris Siahaan |
| 13523111 | Muhammad Iqbal Haidar |