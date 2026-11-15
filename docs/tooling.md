# Tentang Dokumentasi

## Kakas yang digunakan

| Kakas | Versi | Kegunaan |
| ----- | ----- | -------- |
| [Sphinx](https://www.sphinx-doc.org/) | 9.1.1 | Generator dokumentasi |
| `sphinx.ext.autodoc` | bawaan Sphinx | Mengambil signature dan docstring langsung dari kode `src/`, sehingga dokumentasi selalu sinkron dengan implementasi |
| `sphinx.ext.napoleon` | bawaan Sphinx | Membaca docstring gaya Google (`Args:`, `Returns:`, `Raises:`, `Example:`) |
| `sphinx.ext.viewcode` | bawaan Sphinx | Tautan `[source]` ke kode sumber tiap fungsi |
| `sphinx.ext.intersphinx` | bawaan Sphinx | Tautan silang ke dokumentasi Python dan `cryptography` |
| [MyST-Parser](https://myst-parser.readthedocs.io/) | 5.2.0 | Halaman naratif ditulis dalam Markdown |
| [Furo](https://pradyunsg.me/furo/) | 2025.12.19 | Tema HTML (mendukung mode gelap dan tampilan ponsel) |
| [GitHub Pages](https://pages.github.com/) + GitHub Actions | — | Hosting publik; workflow `.github/workflows/docs.yml` membangun dan men-deploy otomatis setiap ada perubahan pada `src/` atau `docs/` di branch `main` |

## Struktur

```text
docs/
├── conf.py            # konfigurasi Sphinx
├── requirements.txt   # dependensi build dokumentasi
├── index.md           # deskripsi API
├── usage.md           # contoh penggunaan
├── formats.md         # format berkas & pemetaan profil
├── errors.md          # exception, status, exit code
├── tooling.md         # halaman ini
└── api/               # referensi API per modul (autodoc)
```

Referensi API di `docs/api/` hanya berisi direktif `automodule`; isinya
dihasilkan dari docstring di `src/`. Untuk mengubah dokumentasi sebuah fungsi,
ubah docstring-nya.

## Membangun secara lokal

```bash
python3 -m venv .venv-docs
. .venv-docs/bin/activate
pip install -r docs/requirements.txt
sphinx-build -W --keep-going -b html docs docs/_build/html
# buka docs/_build/html/index.html
```

Opsi `-W` membuat build gagal bila ada peringatan (mis. referensi silang yang
rusak), sehingga kesalahan dokumentasi tertangkap di CI.
