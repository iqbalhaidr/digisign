# Hasil Skenario Uji U01, U05, U06, U07, U11, U12, U14

**Ringkasan: 33/33 kasus lulus.**

## Cara menjalankan

```
python test/scenarios/run_scenarios.py
```

## Lingkungan

- Waktu (UTC): 2026-11-15 11:34:06
- OS: Windows-11-10.0.26200-SP0
- Python: 3.12.10
- cryptography: 50.0.1
- OpenSSL CLI: OpenSSL 3.2.2 4 Jun 2024

## Hasil

| ID | Profil | Skenario | Diharapkan | Hasil | Status | Bukti |
|---|---|---|---|---|---|---|
| U01 | rsa-pss-sha256 | Berkas teks `contoh-app.txt` (40 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | rsa-pss-sha256 | Berkas biner `contoh-app.bin` (4096 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | rsa-pss-sha256 | Berkas kosong `contoh-app-empty.txt` (0 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | ecdsa-p256-sha256 | Berkas teks `contoh-app.txt` (40 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | ecdsa-p256-sha256 | Berkas biner `contoh-app.bin` (4096 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | ecdsa-p256-sha256 | Berkas kosong `contoh-app-empty.txt` (0 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | ed25519 | Berkas teks `contoh-app.txt` (40 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | ed25519 | Berkas biner `contoh-app.bin` (4096 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U01 | ed25519 | Berkas kosong `contoh-app-empty.txt` (0 byte), kunci dan metadata sesuai | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U01` |
| U05 | rsa-pss-sha256 | Kontrol: bundle asli | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U05` |
| U05 | rsa-pss-sha256 | Bit 0 byte ke-192 tanda tangan dibalik (panjang dan Base64 tetap valid) | INVALID_SIGNATURE (exit 1) | INVALID_SIGNATURE (exit 1) | LULUS | `test/scenarios/results/U05` |
| U05 | ecdsa-p256-sha256 | Kontrol: bundle asli | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U05` |
| U05 | ecdsa-p256-sha256 | Bit 0 byte ke-32 tanda tangan dibalik (panjang dan Base64 tetap valid) | INVALID_SIGNATURE (exit 1) | INVALID_SIGNATURE (exit 1) | LULUS | `test/scenarios/results/U05` |
| U05 | ed25519 | Kontrol: bundle asli | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U05` |
| U05 | ed25519 | Bit 0 byte ke-32 tanda tangan dibalik (panjang dan Base64 tetap valid) | INVALID_SIGNATURE (exit 1) | INVALID_SIGNATURE (exit 1) | LULUS | `test/scenarios/results/U05` |
| U06 | ed25519 | Trust store kosong | KEY_NOT_TRUSTED (exit 1) | KEY_NOT_TRUSTED (exit 1) | LULUS | `test/scenarios/results/U06` |
| U06 | ed25519 | Kontrol: kunci penerbit ada di trust store | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U06` |
| U06 | ed25519 | Kunci penerbit dihapus dengan `trust remove` | KEY_NOT_TRUSTED (exit 1) | KEY_NOT_TRUSTED (exit 1) | LULUS | `test/scenarios/results/U06` |
| U07 | ed25519 | Kunci hanya diizinkan untuk paket `other-app` | KEY_NOT_TRUSTED (exit 1) | KEY_NOT_TRUSTED (exit 1) | LULUS | `test/scenarios/results/U07` |
| U07 | ed25519 | Kontrol: izin `contoh-app` ditambahkan ke kunci yang sama | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U07` |
| U11 | ed25519 | Nilai `algorithm` = `ed448` pada manifest | UNSUPPORTED_ALGORITHM (exit 1) | UNSUPPORTED_ALGORITHM (exit 1) | LULUS | `test/scenarios/results/U11` |
| U11 | ed25519 | Nilai `algorithm` = `rsa-pkcs1-sha256` pada manifest | UNSUPPORTED_ALGORITHM (exit 1) | UNSUPPORTED_ALGORITHM (exit 1) | LULUS | `test/scenarios/results/U11` |
| U11 | ed25519 | Nilai `algorithm` = `ED25519` pada manifest | UNSUPPORTED_ALGORITHM (exit 1) | UNSUPPORTED_ALGORITHM (exit 1) | LULUS | `test/scenarios/results/U11` |
| U12 | ed25519 | Ditandatangani kunci lain berprofil sama (keyid 3e954e3af345...) yang tidak ada di trust store | KEY_NOT_TRUSTED (exit 1) | KEY_NOT_TRUSTED (exit 1) | LULUS | `test/scenarios/results/U12` |
| U14 | rsa-pss-sha256 | Manifest identik ditandatangani dua kali dengan kunci yang sama | manifest identik, signature berbeda | manifest identik, signature berbeda | LULUS | `test/scenarios/results/U14` |
| U14 | rsa-pss-sha256 | Bundle pertama tetap valid | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U14` |
| U14 | rsa-pss-sha256 | Bundle kedua tetap valid | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U14` |
| U14 | ecdsa-p256-sha256 | Manifest identik ditandatangani dua kali dengan kunci yang sama | manifest identik, signature berbeda | manifest identik, signature berbeda | LULUS | `test/scenarios/results/U14` |
| U14 | ecdsa-p256-sha256 | Bundle pertama tetap valid | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U14` |
| U14 | ecdsa-p256-sha256 | Bundle kedua tetap valid | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U14` |
| U14 | ed25519 | Manifest identik ditandatangani dua kali dengan kunci yang sama | manifest identik, signature identik | manifest identik, signature identik | LULUS | `test/scenarios/results/U14` |
| U14 | ed25519 | Bundle pertama tetap valid | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U14` |
| U14 | ed25519 | Bundle kedua tetap valid | OK (exit 0) | OK (exit 0) | LULUS | `test/scenarios/results/U14` |

## Berkas masukan

- `test/scenarios/inputs/contoh-app.txt`: berkas teks, 40 byte
- `test/scenarios/inputs/contoh-app.bin`: berkas biner, 4096 byte
- `test/scenarios/inputs/contoh-app-empty.txt`: berkas kosong, 0 byte
- `test/scenarios/keys/`: pasangan kunci khusus pengujian untuk ketiga profil, ditambah `other-ed25519` (kunci lain untuk U12)


## Analisis U14

- **Ed25519** menghasilkan tanda tangan identik. Nonce diturunkan secara deterministik dari
  `SHA-512(prefix_kunci || M)` (RFC 8032), sehingga M dan kunci yang sama selalu menghasilkan nonce
  dan tanda tangan yang sama.
- **RSA-PSS** menghasilkan tanda tangan berbeda karena setiap penandatanganan memakai salt acak
  32 byte dari CSPRNG. Verifier membuka salt dari tanda tangan, sehingga keduanya tetap valid.
- **ECDSA P-256** menghasilkan tanda tangan berbeda karena nonce `k` diambil acak dari CSPRNG OpenSSL
  (bukan mode deterministik RFC 6979). Nilai `r = (k·G).x` dan `s` berubah, tetapi keduanya valid.
  Nonce tidak boleh dipakai ulang, karena dua tanda tangan dengan `k` yang sama membocorkan kunci privat.
