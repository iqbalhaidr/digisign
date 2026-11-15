# Referensi API

Referensi berikut dihasilkan otomatis dari docstring kode sumber. Setiap entri
memuat signature dengan anotasi tipe, penjelasan parameter (`Args`), nilai
kembalian (`Returns`), exception (`Raises`), dan contoh (`Example`) bila ada.
Tautan **[source]** menuju implementasinya.

| Halaman | Modul |
| ------- | ----- |
| [CLI](cli.md) | `src.main` |
| [Keygen](keygen.md) | `src.keygen.keygen` |
| [Sign](sign.md) | `src.sign.sign` |
| [Verify](verify.md) | `src.verify.verify`, `src.verify.result` |
| [Trust store](trust.md) | `src.trust.store`, `src.trust.commands` |
| [Kriptografi](crypto.md) | `src.crypto.profiles`, `src.crypto.keys`, `src.crypto.signature`, `src.crypto.pem` |
| [Data](data.md) | `src.data.strict_json`, `src.data.b64_decoder`, `src.data.manifest`, `src.data.bundle` |
| [Utilitas](utils.md) | `src.fileio`, `src.errors`, `src.constants` |

```{toctree}
:hidden:

cli
keygen
sign
verify
trust
crypto
data
utils
```
