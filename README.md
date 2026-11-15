# [Nama Program]

## Deskripsi
Lorem ipsum dolor sit amet

## Tech Stack
Lorem ipsum dolor sit amet

## Dependensi
Lorem ipsum dolor sit amet

## Run (Runner CI/CD)
Lorem ipsum dolor sit amet. [Tata cara mengambil image dari registry dan menjalankan program pada runner CI/CD.]

## Subcommands
Lorem ipsum dolor sit amet. [Contoh seluruh subcommand wajib dan cara mengulang pengujian.]

## Format 
Lorem ipsum dolor sit amet. [Format berkas serta pemetaan profil algoritma ke API pustaka.]

## Run (Manual)
Lorem ipsum dolor sit amet. [Tata cara menjalankan program di luar runner CI/CD.]

## Dokumentasi API
**Tautan**: [https://iqbalhaidr.github.io/digisign/](https://iqbalhaidr.github.io/digisign/)

Dokumentasi API modul internal Python (`src/`) yang dipakai CLI: deskripsi API, parameter masukan dan keluaran beserta tipe datanya, contoh penggunaan, format berkas, serta status dan exit code.

| Kakas | Kegunaan |
| ----- | -------- |
| Sphinx 9.1.1 | Generator dokumentasi |
| `sphinx.ext.autodoc` + `sphinx.ext.napoleon` | Membangkitkan referensi API dari docstring gaya Google (`Args`, `Returns`, `Raises`, `Example`) di `src/` |
| `sphinx.ext.viewcode`, `sphinx.ext.intersphinx` | Tautan ke kode sumber dan ke dokumentasi Python / `cryptography` |
| MyST-Parser 5.2.0 | Halaman naratif dalam Markdown (`docs/*.md`) |
| Furo 2025.12.19 | Tema HTML |
| GitHub Pages + GitHub Actions | Hosting; `.github/workflows/docs.yml` membangun dan men-deploy otomatis setiap push ke `main` yang mengubah `src/` atau `docs/` |

Build lokal:
```bash
pip install -r docs/requirements.txt
sphinx-build -W --keep-going -b html docs docs/_build/html   # buka docs/_build/html/index.html
```

## Lainnya
**Tautan image public**: [digisgn](https://github.com/iqbalhaidr/digisign/pkgs/container/digisign)

### Pemetaan
| Versi | Tag | Digest |
| ----- | --- | ------ |
| **v1.0.0** | **1.0.0** | **sha256:046d973f54c64d776252465c3a4c0da0c75bd2d32f1e20965a2c3fb4c8a0077a** |

### Konfigurasi Workflow
| Komponen | Nilai |
| -------- | ----- |
| Pre-build | test/ci/contoh-app.txt |
| --file | contoh-app.zip |
| --package | contoh-app |
| --version | 1.0.0 |
| --key | CI_SIGNING_KEY_RSA, CI_SIGNING_KEY_ECDSA, CI_SIGNING_KEY_ED25519 |
| --trust-store | test/ci/trust.json |

**Catatan**: Gunakan **.github/workflows/test.yml job c01** sebagai contoh penggunaan program untuk CI/CD pipeline


## Kontributor
| NIM | Nama | 
|-----|------|
| 13523023 | Muhammad Aufa Farabi |
| 13523025 | Joel Hotlan Haris Siahaan |
| 13523111 | Muhammad Iqbal Haidar |