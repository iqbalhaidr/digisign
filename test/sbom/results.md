# Hasil Pengujian Signed SBOM

Dihasilkan oleh `python3 test/sbom/run_tests.py`. Kolom *Diharapkan* dan *Aktual* berformat `exit / status / stage`.

| ID | Skenario | Perintah | Diharapkan | Aktual | Hasil |
| -- | -------- | -------- | ---------- | ------ | ----- |
| S01-rsa-pss-sha256 | Rilis + SBOM sah (rsa-pss-sha256): sbom verify dan sbom check berhasil | sbom verify | `0` / `OK` / – | `0` / `OK` / – | PASS |
|  |  | sbom check | `0` / `OK` / – | `0` / `OK` / – | PASS |
| S01-ecdsa-p256-sha256 | Rilis + SBOM sah (ecdsa-p256-sha256): sbom verify dan sbom check berhasil | sbom verify | `0` / `OK` / – | `0` / `OK` / – | PASS |
|  |  | sbom check | `0` / `OK` / – | `0` / `OK` / – | PASS |
| S01-ed25519 | Rilis + SBOM sah (ed25519): sbom verify dan sbom check berhasil | sbom verify | `0` / `OK` / – | `0` / `OK` / – | PASS |
|  |  | sbom check | `0` / `OK` / – | `0` / `OK` / – | PASS |
| S02 | Isi SBOM diubah setelah ditandatangani: satu karakter hash komponen diganti (ukuran tetap) | sbom verify | `1` / `ARTIFACT_MISMATCH` / – | `1` / `ARTIFACT_MISMATCH` / – | PASS |
|  |  | sbom check | `1` / `ARTIFACT_MISMATCH` / `sbom` | `1` / `ARTIFACT_MISMATCH` / `sbom` | PASS |
| S03 | Isi SBOM diubah: hash metadata.component diganti ke SHA-256 artefak pengganti | sbom verify | `1` / `ARTIFACT_MISMATCH` / – | `1` / `ARTIFACT_MISMATCH` / – | PASS |
|  |  | sbom check | `1` / `ARTIFACT_MISMATCH` / `sbom` | `1` / `ARTIFACT_MISMATCH` / `sbom` | PASS |
| S04 | Isi SBOM diubah: komponen baru ditambahkan (ukuran berubah) | sbom verify | `1` / `ARTIFACT_MISMATCH` / – | `1` / `ARTIFACT_MISMATCH` / – | PASS |
|  |  | sbom check | `1` / `ARTIFACT_MISMATCH` / `sbom` | `1` / `ARTIFACT_MISMATCH` / `sbom` | PASS |
| S05 | Artefak rilis diganti, bundle rilis lama dipakai | sbom verify | `0` / `OK` / – | `0` / `OK` / – | PASS |
|  |  | sbom check | `1` / `ARTIFACT_MISMATCH` / `release` | `1` / `ARTIFACT_MISMATCH` / `release` | PASS |
| S06 | Artefak rilis diganti dan rilis ditandatangani ulang dengan kunci sah, SBOM lama tetap dipakai | sbom verify | `0` / `OK` / – | `0` / `OK` / – | PASS |
|  |  | sbom check | `1` / `SBOM_MISMATCH` / `binding` | `1` / `SBOM_MISMATCH` / `binding` | PASS |
| S07 | Artefak rilis diganti, SBOM baru dibuat dan ditandatangani kunci yang tidak tepercaya | sbom verify | `1` / `KEY_NOT_TRUSTED` / – | `1` / `KEY_NOT_TRUSTED` / – | PASS |
|  |  | sbom check | `1` / `KEY_NOT_TRUSTED` / `sbom` | `1` / `KEY_NOT_TRUSTED` / `sbom` | PASS |
| S08 | sbom sign menolak SBOM yang tidak memuat SHA-256 artefak (artefak diganti setelah SBOM dibuat) | sbom sign | `2` / – / – | `2` / – / – | PASS |
| S09 | sbom sign menolak --version yang berbeda dari versi pada SBOM | sbom sign | `2` / – / – | `2` / – / – | PASS |
| S10 | Berkas JSON non-SBOM ditandatangani dengan sign biasa lalu diverifikasi sebagai SBOM | sbom verify | `1` / `FORMAT_ERROR` / – | `1` / `FORMAT_ERROR` / – | PASS |
|  |  | sbom check | `1` / `FORMAT_ERROR` / `sbom` | `1` / `FORMAT_ERROR` / `sbom` | PASS |
| S11 | SBOM dengan field duplikat ditandatangani dengan sign biasa (strict JSON) | sbom verify | `1` / `FORMAT_ERROR` / – | `1` / `FORMAT_ERROR` / – | PASS |
| S12 | Bundle rilis tertukar dipakai sebagai --sbom-bundle | sbom check | `1` / `METADATA_MISMATCH` / `sbom` | `1` / `METADATA_MISMATCH` / `sbom` | PASS |
| S13 | Kunci SBOM hanya diizinkan untuk paket lain | sbom verify | `1` / `KEY_NOT_TRUSTED` / – | `1` / `KEY_NOT_TRUSTED` / – | PASS |
| S14 | Berkas SBOM tidak ada | sbom verify | `2` / `INPUT_ERROR` / – | `2` / `INPUT_ERROR` / – | PASS |
|  |  | sbom check | `2` / `INPUT_ERROR` / `sbom` | `2` / `INPUT_ERROR` / `sbom` | PASS |
| S15 | Kompatibilitas format: SBOM + bundle SBOM diverifikasi dengan verify biasa | verify | `0` / `OK` / – | `0` / `OK` / – | PASS |

**Total: 17/17 skenario lulus.**
