# Hasil Uji Interoperabilitas dengan OpenSSL

**Ringkasan: 12/12 kasus lulus.**

## Cara menjalankan

```
python test/interop/run_interop.py
```

## Lingkungan

- Waktu (UTC): 2026-11-15 11:34:10
- OS: Windows-11-10.0.26200-SP0
- Python: 3.12.10
- cryptography: 50.0.1
- OpenSSL CLI: OpenSSL 3.2.2 4 Jun 2024 (Library: OpenSSL 3.2.2 4 Jun 2024)

## Hasil

| ID | Profil | Skenario | Diharapkan | Hasil | Status | Bukti |
|---|---|---|---|---|---|---|
| I1 | rsa-pss-sha256 | Kunci buatan OpenSSL (`genpkey`) dibaca program; keyid sama | keyid 59dab9d5951ce379... | exit 0, keyid 59dab9d5951ce379... | LULUS | `test/interop/results/rsa-pss-sha256` |
| I2 | rsa-pss-sha256 | Kunci buatan program (`keygen`) dibaca OpenSSL (`pkey`); keyid sama | keyid b784f299f706549c... | pkey exit 0/0, keyid b784f299f706549c... | LULUS | `test/interop/results/rsa-pss-sha256` |
| I3 | rsa-pss-sha256 | Tanda tangan program diverifikasi OpenSSL | OpenSSL exit 0 | OpenSSL exit 0: Verified OK | LULUS | `test/interop/results/rsa-pss-sha256` |
| I4 | rsa-pss-sha256 | Tanda tangan OpenSSL diverifikasi program (`verify`) | OK (exit 0) | OK (exit 0) | LULUS | `test/interop/results/rsa-pss-sha256` |
| I1 | ecdsa-p256-sha256 | Kunci buatan OpenSSL (`genpkey`) dibaca program; keyid sama | keyid e1c8ba79514d360c... | exit 0, keyid e1c8ba79514d360c... | LULUS | `test/interop/results/ecdsa-p256-sha256` |
| I2 | ecdsa-p256-sha256 | Kunci buatan program (`keygen`) dibaca OpenSSL (`pkey`); keyid sama | keyid 58e85df3926f9160... | pkey exit 0/0, keyid 58e85df3926f9160... | LULUS | `test/interop/results/ecdsa-p256-sha256` |
| I3 | ecdsa-p256-sha256 | Tanda tangan program diverifikasi OpenSSL | OpenSSL exit 0 | OpenSSL exit 0: Verified OK | LULUS | `test/interop/results/ecdsa-p256-sha256` |
| I4 | ecdsa-p256-sha256 | Tanda tangan OpenSSL diverifikasi program (`verify`) | OK (exit 0) | OK (exit 0) | LULUS | `test/interop/results/ecdsa-p256-sha256` |
| I1 | ed25519 | Kunci buatan OpenSSL (`genpkey`) dibaca program; keyid sama | keyid 3c2f05a7a6e2597a... | exit 0, keyid 3c2f05a7a6e2597a... | LULUS | `test/interop/results/ed25519` |
| I2 | ed25519 | Kunci buatan program (`keygen`) dibaca OpenSSL (`pkey`); keyid sama | keyid 748a42fe6fdcd27e... | pkey exit 0/0, keyid 748a42fe6fdcd27e... | LULUS | `test/interop/results/ed25519` |
| I3 | ed25519 | Tanda tangan program diverifikasi OpenSSL | OpenSSL exit 0 | OpenSSL exit 0: Signature Verified Successfully | LULUS | `test/interop/results/ed25519` |
| I4 | ed25519 | Tanda tangan OpenSSL diverifikasi program (`verify`) | OK (exit 0) | OK (exit 0) | LULUS | `test/interop/results/ed25519` |

## Keterangan

- **I1**: kunci dibangkitkan `openssl genpkey` (PKCS#8 PEM), dibaca program melalui `trust add`.
  keyid pembanding dihitung OpenSSL: `openssl pkey -pubout -outform DER | openssl dgst -sha256`.
- **I2**: kunci dari `keygen` dibaca `openssl pkey`; keyid dihitung OpenSSL dari DER SPKI hasil ekspornya.
- **I3**: manifest M dan tanda tangan diambil dari bundle hasil `sign`, lalu diverifikasi:
  - RSA-PSS: `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -verify`
  - ECDSA: tanda tangan r||s (64 byte) diubah ke ASN.1 DER, lalu `openssl dgst -sha256 -verify`
  - Ed25519: `openssl pkeyutl -verify -rawin` (pesan mentah, tanpa pre-hash)
- **I4**: OpenSSL menandatangani M yang sama dengan perintah setara; untuk ECDSA keluaran DER diubah ke r||s.
  Bundle dirakit skrip ini, lalu diverifikasi dengan `verify --json`.
- Konversi DER <-> r||s dan pembentukan bundle ditulis ulang di skrip ini, tidak memakai kode program.
