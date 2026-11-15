# Format Berkas & Profil Algoritma

Semua berkas JSON di-parse oleh {func}`~src.data.strict_json.parse_strict`:
UTF-8 tanpa BOM, tanpa field duplikat, tanpa `null`, tanpa bilangan pecahan,
dan **tidak boleh ada field tambahan** maupun field yang hilang.

## Kunci

| Berkas | Format | Label PEM | Permission | API |
| ------ | ------ | --------- | ---------- | --- |
| `<prefix>.key.pem` | PKCS#8 `PrivateKeyInfo`, tanpa enkripsi | `PRIVATE KEY` | `0600` | {func}`~src.crypto.keys.load_private_key_pem`, {func}`~src.crypto.keys.private_key_to_pem` |
| `<prefix>.pub.pem` | X.509 `SubjectPublicKeyInfo` | `PUBLIC KEY` | `0644` | {func}`~src.crypto.keys.load_public_key_pem`, {func}`~src.crypto.keys.public_key_to_pem` |

**keyid** — `lowercase_hex(SHA-256(DER(SubjectPublicKeyInfo)))`, 64 karakter,
dihitung oleh {func}`~src.crypto.keys.compute_keyid`.

## Manifest

Manifest adalah byte yang ditandatangani. Bentuknya **canonical**: JSON ASCII
tanpa spasi/baris baru, urutan field tetap. Manifest dengan isi sama tetapi
serialisasi berbeda ditolak sebagai `FORMAT_ERROR`.

```json
{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0","algorithm":"ed25519","keyid":"9b7c...","artifact":{"name":"contoh-app.zip","size":1234,"sha256":"e3b0..."}}
```

| Field | Tipe | Aturan |
| ----- | ---- | ------ |
| `schema` | string | Tepat `minisign-manifest/v1` |
| `package` | string | `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `algorithm` | string | Salah satu profil di bawah (diperiksa pada tahap `UNSUPPORTED_ALGORITHM`) |
| `keyid` | string | 64 hex huruf kecil |
| `artifact.name` | string | Basename artefak, `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` |
| `artifact.size` | integer | `0 … 2^53 − 1` |
| `artifact.sha256` | string | 64 hex huruf kecil |

Ukuran maksimum: 16 KiB. Model Python: {class}`~src.data.manifest.Manifest`
dan {class}`~src.data.manifest.Artifact`.

## Bundle

```json
{
  "schema": "minisign-bundle/v1",
  "manifest_b64": "eyJzY2hlbWEiOiJtaW5pc2lnbi1tYW5pZmVzdC92MSIs...",
  "signature_b64": "q1mX...=="
}
```

| Field | Tipe | Aturan |
| ----- | ---- | ------ |
| `schema` | string | Tepat `minisign-bundle/v1` |
| `manifest_b64` | string | Base64 standar kanonik dari byte manifest canonical |
| `signature_b64` | string | Base64 standar kanonik dari signature |

Ukuran maksimum: 64 KiB. API: {func}`~src.data.bundle.parse_bundle`,
{func}`~src.data.bundle.serialize_bundle`, {func}`~src.data.b64_decoder.decode_b64_strict`.

## Trust store

```json
{
  "schema": "minisign-trust/v1",
  "keys": [
    {
      "keyid": "9b7c...",
      "algorithm": "ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
      "packages": ["contoh-app"]
    }
  ]
}
```

| Field | Tipe | Aturan |
| ----- | ---- | ------ |
| `schema` | string | Tepat `minisign-trust/v1` |
| `keys` | array of object | Boleh kosong; `keyid` unik antar-entri |
| `keys[].keyid` | string | 64 hex, wajib sama dengan fingerprint `public_key_pem` |
| `keys[].algorithm` | string | Profil yang didukung dan sesuai jenis kunci |
| `keys[].public_key_pem` | string | SPKI PEM ASCII |
| `keys[].packages` | array of string | Tidak kosong, tanpa duplikat, tanpa wildcard (`* ? [ ]`) |

Trust store selalu ditulis secara atomik ({func}`~src.fileio.write_atomic`).
API: {class}`~src.trust.store.TrustStore`, {func}`~src.trust.store.parse_trust_store`,
{func}`~src.trust.store.load_trust_store`, {func}`~src.trust.store.save_trust_store`.

## Pemetaan profil algoritma ke API pustaka

Implementasi memakai pustaka [`cryptography`](https://cryptography.io/) 50.0.2
(`cryptography.hazmat.primitives`).

| Profil | Pembangkitan kunci | Penandatanganan | Verifikasi | Signature |
| ------ | ------------------ | --------------- | ---------- | --------- |
| `rsa-pss-sha256` | `rsa.generate_private_key(public_exponent=65537, key_size=3072)` | `key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())` | `pub.verify(sig, msg, <PSS sama>, hashes.SHA256())` | 384 byte |
| `ecdsa-p256-sha256` | `ec.generate_private_key(ec.SECP256R1())` | `key.sign(msg, ec.ECDSA(hashes.SHA256()))` → `decode_dss_signature` → `r ‖ s` | `encode_dss_signature(r, s)` → `pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))` | 64 byte |
| `ed25519` | `ed25519.Ed25519PrivateKey.generate()` | `key.sign(msg)` | `pub.verify(sig, msg)` | 64 byte |

Serialisasi kunci memakai `serialization.Encoding.PEM` / `DER` dengan
`PrivateFormat.PKCS8` + `NoEncryption()` dan `PublicFormat.SubjectPublicKeyInfo`.
Lihat {mod}`src.crypto.signature` dan {mod}`src.crypto.keys`.
