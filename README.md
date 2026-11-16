# digisign
digisign adalah kakas penandatanganan dan verifikasi rilis perangkat lunak yang ditujukan untuk pipeline CI/CD. Algoritma tanda tangan yang didukung adalah RSA, ECDSA, dan EdDSA. Program melakukan tanda tangan pada release manifest (metadata) kemudian hasil tanda tangan dan release manifest disimpan dalam sebuah bundle. Proses verifikasi dilakukan menggunakan kunci yang terdaftar pada trust store.

| Links | |
|---|---|
| Image registry | [https://github.com/iqbalhaidr/digisign/pkgs/container/digisign](https://github.com/iqbalhaidr/digisign/pkgs/container/digisign) |
| API Documentation | [https://iqbalhaidr.github.io/digisign/](https://iqbalhaidr.github.io/digisign/) |

<table>
<tr>
<td valign="top">

## Tech Stack

| Category | Tech |
| :--- | :--- |
| Language | Python |
| Registry | GitHub Container Registry |
| CI/CD | GitHub Actions |
| Container | Docker |

</td>
<td valign="top">

## Dependency

| Library | Version |
| :--- | :--- |
| `cryptography` | 50.0.2 |
| `sphinx` | 9.1.1 |
| `furo` | 2025.12.19 |
| `myst-parser` | 5.2.0 |
| stdlib | Python 3.12 |

</td>
</tr>
</table>

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
See all format used in this program: [API Documentation (https://iqbalhaidr.github.io/digisign/others.html#)](https://iqbalhaidr.github.io/digisign/others.html#)

## Testing
| Test | Script |
|---|---|
| U01–U14 | `python test/scenarios/run_scenarios.py` |
| Interoperability | `python test/interop/run_interop.py` |
| Performance | `python test/performance/benchmark.py` |
| C01–C05 | GitHub Actions **test** -> *Run workflow* |
| Signed SBOM | `python test/sbom/run_sbom.py` |

- `test/scenarios/keys/` contains keypairs **only for testing**. 
- `test/ci/keys/` contains public keys for pipeline demo. Private keys stored in GitHub Secrets.

## Contributor
| NIM | Name | 
|-----|------|
| 13523023 | Muhammad Aufa Farabi |
| 13523025 | Joel Hotlan Haris Siahaan |
| 13523111 | Muhammad Iqbal Haidar |