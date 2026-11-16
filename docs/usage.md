# Examples

## Generate key pair

```python
from src.keygen import keygen_command

exit_code = keygen_command("ed25519", "keys/release")
# keyid:       xxxxx...
# algorithm:   ed25519
# private key: keys/release.key.pem
# public key:  keys/release.pub.pem
assert exit_code == 0
```
{func}`~src.keygen.keygen.keygen_command`

`cli`:
```bash
digisign keygen --algorithm ed25519 --out keys/release
```

## Sign

```python
from src.sign import sign_command

exit_code = sign_command(
    file_path="contoh-app.zip", 
    package="contoh-app", 
    version="1.0.0",
    key_path="keys/release.key.pem"
    out_path="contoh-app.bundle.json"
)
# bundle:    contoh-app.bundle.json
# keyid:     xxxxx...
# algorithm: ed25519
# artifact:  contoh-app.zip
```
{func}`~src.sign.sign.sign_command`

`cli`:
```bash
digisign sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
              --key keys/release.key.pem --out contoh-app.bundle.json
```

## Trust store

```python
from src.crypto import load_public_key_pem
from src.trust import TrustStore, load_trust_store, save_trust_store

with open("keys/release.pub.pem", "rb") as f:
    public_key = load_public_key_pem(f.read())

store = TrustStore()
entry, changed = store.add(public_key, "contoh-app")
save_trust_store(store, "trust.json")

store = load_trust_store("trust.json")

```

`cli`:
```bash
digisign trust add --key keys/release.pub.pem --package contoh-app --store trust.json
digisign trust list --store trust.json
digisign trust remove --keyid <keyid> --store trust.json
```

## Verify

```python
from src.verify import verify_release, OK

result = verify_release(
    file_path="contoh-app.zip",
    bundle_path="contoh-app.bundle.json",
    trust_store_path="trust.json",
    package="contoh-app",
    version="1.0.0",
)

print(result.status, result.message, result.exit_code)
```
{func}`~src.verify.verify.verify_release` 

`cli`:
```bash
digisign verify --file contoh-app.zip --bundle contoh-app.bundle.json \
                --trust-store trust.json --package contoh-app --version 1.0.0 --json
```

## Signed SBOM

```python
from src.sbom import check_sbom, sbom_generate_command, sbom_sign_command

sbom_generate_command("contoh-app.zip", "contoh-app", "1.0.0", "contoh-app.cdx.json")
# sbom:       contoh-app.cdx.json
# component:  contoh-app 1.0.0
# sha256:     xxxxx...
# components: 1

sbom_sign_command(
    sbom_path="contoh-app.cdx.json",
    file_path="contoh-app.zip",
    package="contoh-app",
    version="1.0.0",
    key_path="keys/release.key.pem",
    out_path="contoh-app.cdx.bundle.json",
)

result = check_sbom(
    file_path="contoh-app.zip",
    bundle_path="contoh-app.bundle.json",
    sbom_path="contoh-app.cdx.json",
    sbom_bundle_path="contoh-app.cdx.bundle.json",
    trust_store_path="trust.json",
    package="contoh-app",
    version="1.0.0",
)

print(result.status, result.stage, result.message, result.exit_code)
```
{func}`~src.sbom.commands.sbom_generate_command`, {func}`~src.sbom.commands.sbom_sign_command`, {func}`~src.sbom.verify.check_sbom`

`cli`:
```bash
digisign sbom generate --file contoh-app.zip --package contoh-app --version 1.0.0 --out contoh-app.cdx.json
digisign sbom sign --sbom contoh-app.cdx.json --file contoh-app.zip --package contoh-app --version 1.0.0 \
                   --key keys/release.key.pem --out contoh-app.cdx.bundle.json
digisign sbom verify --sbom contoh-app.cdx.json --bundle contoh-app.cdx.bundle.json \
                     --trust-store trust.json --package contoh-app --version 1.0.0 --json
digisign sbom check --file contoh-app.zip --bundle contoh-app.bundle.json \
                    --sbom contoh-app.cdx.json --sbom-bundle contoh-app.cdx.bundle.json \
                    --trust-store trust.json --package contoh-app --version 1.0.0 --json
```
