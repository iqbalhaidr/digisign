# digisign — Dokumentasi API

**digisign** adalah kakas CLI terkontainerisasi untuk menandatangani dan
memverifikasi rilis perangkat lunak (mirip *Sigstore Cosign* mode kunci).
Dokumentasi ini menjelaskan **API modul internal Python** yang dipakai oleh CLI:
setiap fungsi publik, parameter masukan, keluaran, tipe datanya, exception yang
mungkin dilempar, beserta contoh penggunaannya.

## Deskripsi API

API dibagi menjadi beberapa lapisan. Lapisan atas (subcommand) hanya merangkai
lapisan di bawahnya, sehingga setiap modul dapat dipakai langsung dari kode Python.

| Lapisan | Paket | Tanggung jawab |
| ------- | ----- | -------------- |
| CLI | {mod}`src.main` | Parsing argumen, pemetaan subcommand → fungsi, exit code |
| Subcommand | {mod}`src.keygen`, {mod}`src.sign`, {mod}`src.verify`, {mod}`src.trust` | Logika tiap perintah: `keygen`, `sign`, `verify`, `trust add/list/remove` |
| Kriptografi | {mod}`src.crypto` | Profil algoritma, kunci PKCS#8/SPKI, `keyid`, sign/verify |
| Data | {mod}`src.data` | Parser JSON ketat, Base64 kanonik, manifest canonical, bundle |
| Utilitas | {mod}`src.fileio`, {mod}`src.errors`, {mod}`src.constants` | I/O aman, hierarki exception, konstanta dan pola validasi |

### Alur penandatanganan

```text
artefak ──hash_file──▶ (size, sha256)
                           │
private key ──detect_profile / compute_keyid──▶ Manifest
                           │
                   serialize_manifest  ──▶ manifest canonical (bytes)
                           │
                         sign          ──▶ signature (bytes)
                           │
                   serialize_bundle    ──▶ bundle.json
```

### Alur verifikasi

{func}`~src.verify.verify.verify_release` menjalankan 8 tahap berurutan dan
berhenti pada kegagalan pertama:
`INPUT_ERROR → FORMAT_ERROR → UNSUPPORTED_ALGORITHM → KEY_NOT_TRUSTED →
INVALID_SIGNATURE → METADATA_MISMATCH → ARTIFACT_MISMATCH → OK`.

## Cara membaca dokumentasi

- **[Contoh Penggunaan](usage.md)** — skenario lengkap memakai API dari Python dan padanannya di CLI.
- **[Format Berkas & Profil](formats.md)** — format manifest, bundle, trust store, dan pemetaan profil algoritma ke API pustaka `cryptography`.
- **[Error & Exit Code](errors.md)** — hierarki exception, status verifikasi, dan exit code.
- **[Referensi API](api/index.md)** — dokumentasi tiap modul, dihasilkan otomatis dari docstring.
- **[Tentang Dokumentasi](tooling.md)** — kakas yang dipakai dan cara membangun dokumentasi ini.

Konvensi penulisan tipe mengikuti anotasi Python (`str`, `bytes`, `int | None`,
`tuple[int, str]`, dll.). Tipe `PrivateKey` dan `PublicKey` adalah alias union
kunci RSA/EC/Ed25519 dari pustaka
[`cryptography`](https://cryptography.io/en/latest/), lihat {mod}`src.crypto.keys`.

```{toctree}
:hidden:
:maxdepth: 2

usage
formats
errors
api/index
tooling
```
