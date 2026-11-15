# Kunci Khusus Pengujian

Pasangan kunci di folder ini **khusus dibuat untuk pengujian** (Bagian 3.1 poin g) dan tidak dipakai
pada real service. Kunci dibangkitkan dengan `keygen` milik program saat
`python test/scenarios/run_scenarios.py` pertama kali dijalankan, lalu dipakai ulang agar
pengujian dapat diulang dengan kunci yang sama.

| Berkas | Profil | Dipakai pada |
|---|---|---|
| `rsa-pss-sha256.key.pem` / `.pub.pem` | rsa-pss-sha256 | U01, U05, U14 |
| `ecdsa-p256-sha256.key.pem` / `.pub.pem` | ecdsa-p256-sha256 | U01, U05, U14 |
| `ed25519.key.pem` / `.pub.pem` | ed25519 | U01, U05, U06, U07, U11, U12, U14 |
| `other-ed25519.key.pem` / `.pub.pem` | ed25519 | U12 (kunci lain yang tidak ada di trust store) |

Hapus folder ini lalu jalankan ulang skrip untuk membangkitkan kunci baru.
