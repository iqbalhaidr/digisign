# Contoh Penggunaan

Semua contoh dijalankan dari root repositori agar paket `src` dapat di-import:

```bash
pip install -r requirements.txt
python3            # atau: PYTHONPATH=. python3 skrip.py
```

## 1. Membangkitkan pasangan kunci

```python
from src.crypto import (
    generate_private_key, private_key_to_pem, public_key_to_pem, compute_keyid,
)

private_key = generate_private_key("ed25519")   # atau "rsa-pss-sha256", "ecdsa-p256-sha256"
public_key = private_key.public_key()

private_pem = private_key_to_pem(private_key)   # bytes, PKCS#8 "PRIVATE KEY"
public_pem = public_key_to_pem(public_key)      # bytes, SPKI  "PUBLIC KEY"
keyid = compute_keyid(public_key)               # str, 64 hex huruf kecil

print(keyid)
# 9b7c0e...  (SHA-256 atas DER SubjectPublicKeyInfo)
```

Untuk sekaligus menulis berkas dengan permission yang benar (`0600` untuk
kunci privat), gunakan {func}`~src.keygen.keygen.keygen_command`:

```python
from src.keygen import keygen_command

exit_code = keygen_command("ed25519", "keys/release")
# keyid:       9b7c0e...
# algorithm:   ed25519
# private key: keys/release.key.pem
# public key:  keys/release.pub.pem
assert exit_code == 0
```

Padanan CLI:

```bash
digisign keygen --algorithm ed25519 --out keys/release
```

## 2. Menandatangani artefak

```python
from src.crypto import load_private_key_pem
from src.sign import create_bundle

with open("keys/release.key.pem", "rb") as f:
    private_key = load_private_key_pem(f.read())

manifest, bundle_bytes = create_bundle(
    "contoh-app.zip", package="contoh-app", version="1.0.0", private_key=private_key,
)

print(manifest.algorithm, manifest.keyid)
print(manifest.artifact)
# Artifact(name='contoh-app.zip', size=1234, sha256='e3b0c4...')

with open("contoh-app.bundle.json", "wb") as f:
    f.write(bundle_bytes)
```

{func}`~src.sign.sign.create_bundle` tidak menulis ke disk. Versi yang
memvalidasi argumen dan menolak menimpa bundle yang ada adalah
{func}`~src.sign.sign.sign_command`.

Padanan CLI:

```bash
digisign sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
              --key keys/release.key.pem --out contoh-app.bundle.json
```

## 3. Mengelola trust store

```python
from src.crypto import load_public_key_pem
from src.trust import TrustStore, load_trust_store, save_trust_store

with open("keys/release.pub.pem", "rb") as f:
    public_key = load_public_key_pem(f.read())

store = TrustStore()
entry, changed = store.add(public_key, "contoh-app")
print(entry.keyid, entry.algorithm, entry.packages, changed)
# 9b7c0e... ed25519 ['contoh-app'] True

save_trust_store(store, "trust.json")           # penulisan atomik

store = load_trust_store("trust.json")          # parsing + validasi ketat
assert store.find(entry.keyid).allows("contoh-app")
assert not store.find(entry.keyid).allows("aplikasi-lain")
```

Padanan CLI:

```bash
digisign trust add --key keys/release.pub.pem --package contoh-app --store trust.json
digisign trust list --store trust.json
digisign trust remove --keyid <keyid> --store trust.json
```

## 4. Memverifikasi rilis

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
# OK Signature and artifact are valid. 0

if result.status != OK:
    raise SystemExit(result.exit_code)

print(result.to_json(), end="")
# {"valid": true, "status": "OK", "message": "Signature and artifact are valid.",
#  "algorithm": "ed25519", "keyid": "9b7c0e...", "package": "contoh-app", "version": "1.0.0"}
```

{func}`~src.verify.verify.verify_release` **tidak pernah melempar exception**
untuk input buruk; seluruh kegagalan dikembalikan sebagai
{class}`~src.verify.result.VerifyResult` dengan status yang sesuai.

Padanan CLI:

```bash
digisign verify --file contoh-app.zip --bundle contoh-app.bundle.json \
                --trust-store trust.json --package contoh-app --version 1.0.0 --json
```

## 5. Menangani kegagalan

```python
from src.errors import SignerError, FormatError, InvalidKeyError
from src.crypto import load_private_key_pem

try:
    load_private_key_pem(b"-----BEGIN RSA PRIVATE KEY-----\n...")
except InvalidKeyError as e:
    print("kunci ditolak:", e)
    # kunci ditolak: PEM: expected exactly one 'PRIVATE KEY' block
```

Contoh hasil verifikasi yang ditolak ketika artefak diganti:

```python
result = verify_release("contoh-app.zip", "contoh-app.bundle.json",
                        "trust.json", "contoh-app", "1.0.0")
print(result.status, result.exit_code)
# ARTIFACT_MISMATCH 1
```

## 6. Primitif tingkat rendah

```python
from src.crypto import generate_private_key, sign, verify, SIGNATURE_BYTES
from src.crypto.signature import ecdsa_der_to_raw, ecdsa_raw_to_der

key = generate_private_key("ecdsa-p256-sha256")
sig = sign(key, b"pesan")
assert len(sig) == SIGNATURE_BYTES["ecdsa-p256-sha256"] == 64   # raw r || s
assert verify(key.public_key(), "ecdsa-p256-sha256", b"pesan", sig)
assert not verify(key.public_key(), "ecdsa-p256-sha256", b"pesan!", sig)
```

```python
from src.data import parse_strict
from src.errors import FormatError

parse_strict(b'{"a": 1}')          # {'a': 1}
for bad in (b'{"a": 1, "a": 2}', b'{"a": null}', b'{"a": 1.5}', b'\xef\xbb\xbf{}'):
    try:
        parse_strict(bad)
    except FormatError as e:
        print(e)
# duplicate key: 'a'
# null value not allowed on root.a
# Non-integer number not allowed: 1.5
# BOM is not allowed
```
