# Error & Exit Code

## Hierarki exception

Fungsi tingkat rendah melempar exception turunan {class}`~src.errors.SignerError`.
Fungsi subcommand (`*_command`, `trust_*`) menangkapnya bersama `OSError`,
mencetak `error: <pesan>` ke stderr, dan mengembalikan exit code `2`.

| Exception | Dilempar ketika | Contoh sumber |
| --------- | --------------- | ------------- |
| {class}`~src.errors.SignerError` | Kesalahan umum (berkas keluaran sudah ada, prefix tidak valid) | {func}`~src.keygen.keygen.key_paths` |
| {class}`~src.errors.FormatError` | JSON/Base64/manifest/bundle/trust store melanggar kontrak | {func}`~src.data.strict_json.parse_strict`, {func}`~src.data.manifest.parse_manifest` |
| {class}`~src.errors.UnsupportedAlgorithmError` | Nama profil tidak dikenal | {func}`~src.crypto.profiles.require_supported` |
| {class}`~src.errors.InvalidKeyError` | PEM/DER rusak, bukan PKCS#8/SPKI, atau parameter kunci salah | {func}`~src.crypto.keys.load_private_key_pem`, {func}`~src.crypto.keys.detect_profile` |

## Status verifikasi

{func}`~src.verify.verify.verify_release` mengembalikan
{class}`~src.verify.result.VerifyResult`; tahapan diperiksa berurutan dan
berhenti pada kegagalan pertama.

| Urutan | Status | Exit code | Penyebab |
| ------ | ------ | --------- | -------- |
| 1 | `INPUT_ERROR` | 2 | Bundle, trust store, atau artefak tidak dapat dibaca; argumen CLI salah |
| 2 | `FORMAT_ERROR` | 1 | Bundle/manifest/trust store tidak valid atau manifest tidak canonical |
| 3 | `UNSUPPORTED_ALGORITHM` | 1 | `manifest.algorithm` bukan profil yang didukung |
| 4 | `KEY_NOT_TRUSTED` | 1 | `keyid` tidak ada di trust store, profil berbeda, atau paket tidak diizinkan |
| 5 | `INVALID_SIGNATURE` | 1 | Signature tidak valid untuk manifest |
| 6 | `METADATA_MISMATCH` | 1 | `--package`, `--version`, atau nama berkas berbeda dari manifest |
| 7 | `ARTIFACT_MISMATCH` | 1 | Ukuran atau SHA-256 artefak berbeda dari manifest |
| 8 | `OK` | 0 | Semua pemeriksaan lolos |

## Exit code CLI

| Exit code | Arti |
| --------- | ---- |
| `0` | Berhasil / rilis valid |
| `1` | Verifikasi ditolak (hanya `verify`) |
| `2` | Argumen tidak valid, input/I/O error, atau kegagalan subcommand non-verify |

## Keluaran `verify --json`

Satu baris JSON di stdout, untuk keberhasilan maupun kegagalan (termasuk
argumen CLI yang salah):

| Field | Tipe | Keterangan |
| ----- | ---- | ---------- |
| `valid` | boolean | `true` hanya bila `status == "OK"` |
| `status` | string | Salah satu status di atas |
| `message` | string | Penjelasan singkat |
| `algorithm` | string \| null | Dari manifest, `null` bila manifest belum ter-parse |
| `keyid` | string \| null | Dari manifest |
| `package` | string \| null | Dari manifest |
| `version` | string \| null | Dari manifest |
