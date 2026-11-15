# Signed SBOM

Fitur bonus **Signed SBOM** menandatangani *Software Bill of Materials* (SBOM)
sebagai **artefak terpisah** dari artefak rilis, memakai format manifest,
bundle (`minisign-bundle/v1`), dan trust store yang sama dengan fitur wajib.
SBOM memuat SHA-256 artefak rilis yang dirujuk, sehingga keduanya dapat
diverifikasi dan dicocokkan satu sama lain.

```text
contoh-app.zip ──sign──────────▶ contoh-app.bundle.json        (bundle rilis)
      │
      └─sbom generate─▶ contoh-app.cdx.json ──sbom sign──▶ contoh-app.cdx.bundle.json (bundle SBOM)
                         (memuat SHA-256 contoh-app.zip)

sbom check = verify(rilis) + verify(SBOM) + cocokkan SHA-256 SBOM ↔ artifact.sha256 manifest rilis
```

## Format data SBOM

SBOM menggunakan **CycloneDX 1.6 JSON**. SBOM yang dihasilkan `sbom generate`
lolos validasi skema resmi CycloneDX 1.6 (strict), dan SBOM dari kakas
eksternal diterima selama memenuhi tabel berikut.

| Field | Tipe | Wajib | Ketentuan |
| ----- | ---- | ----- | --------- |
| `bomFormat` | string | ya | Tepat `CycloneDX` |
| `specVersion` | string | ya | `1.4`, `1.5`, atau `1.6` (`generate` menghasilkan `1.6`) |
| `serialNumber` | string | tidak | `urn:uuid:<uuid4>` (diisi `generate`) |
| `version` | integer | tidak | `1` (diisi `generate`) |
| `metadata.timestamp` | string | tidak | Waktu UTC ISO-8601, mis. `2026-11-15T10:00:00Z` |
| `metadata.tools.components[]` | array of object | tidak | Kakas pembuat: `digisign` beserta versinya |
| `metadata.component` | object | ya | Merepresentasikan **artefak rilis** |
| `metadata.component.type` | string | tidak | `application` |
| `metadata.component.name` | string | ya | Harus sama dengan `--package` |
| `metadata.component.version` | string | ya | Harus sama dengan `--version` |
| `metadata.component.purl` / `bom-ref` | string | tidak | `pkg:generic/<package>@<version>` |
| `metadata.component.hashes[]` | array of `{alg, content}` | ya | **Tepat satu** entri `alg` = `SHA-256`; `content` = SHA-256 artefak rilis, 64 hex huruf kecil |
| `metadata.component.properties[]` | array of `{name, value}` | tidak | `digisign:artifact:name` (nama berkas artefak; maksimal satu, bila ada harus sama dengan basename artefak) dan `digisign:artifact:size` (ukuran byte, informatif) |
| `components[]` | array of object | tidak | Isi artefak. Bila artefak berupa ZIP, setiap berkas dicatat sebagai `{type: "file", name, hashes: [SHA-256], properties: [digisign:file:size]}` |

Aturan tambahan:

- Dokumen di-parse dengan parser JSON ketat yang sama dengan fitur wajib: field
  duplikat, `null`, bilangan pecahan, dan BOM ditolak. Field CycloneDX lain
  di luar tabel boleh ada dan diabaikan.
- Ukuran maksimum SBOM 8 MiB.
- SBOM ditandatangani apa adanya (byte berkas), sehingga perubahan satu byte pun
  terdeteksi sebagai `ARTIFACT_MISMATCH` pada bundle SBOM.

Contoh lengkap dapat dilihat pada {mod}`src.sbom.document`.

## Manifest dan bundle SBOM

Bundle SBOM adalah bundle `minisign-bundle/v1` biasa dengan manifest
`minisign-manifest/v1` yang `artifact`-nya adalah berkas SBOM:

| Field manifest | Nilai pada bundle SBOM |
| -------------- | ---------------------- |
| `package`, `version` | Sama dengan rilis yang dirujuk |
| `algorithm`, `keyid` | Dari kunci privat penanda tangan SBOM |
| `artifact.name` | Nama berkas SBOM, mis. `contoh-app.cdx.json` |
| `artifact.size`, `artifact.sha256` | Ukuran dan SHA-256 berkas SBOM |

Karena formatnya identik, SBOM beserta bundle-nya juga dapat diverifikasi dengan
`digisign verify` biasa. Izin kunci di trust store berlaku per paket, sehingga
kunci yang diizinkan untuk `contoh-app` dapat menandatangani rilis maupun SBOM
`contoh-app`. Rilis dan SBOM boleh ditandatangani kunci berbeda selama keduanya
tepercaya untuk paket tersebut.

## Subcommand

### `sbom generate`

Membuat SBOM CycloneDX untuk artefak rilis.

| Parameter | Tipe | Wajib | Keterangan |
| --------- | ---- | ----- | ---------- |
| `--file <path>` | path | ya | Artefak rilis |
| `--package <nama>` | string | ya | Nama paket, pola `[a-z0-9][a-z0-9._-]{0,63}` |
| `--version <versi>` | string | ya | Versi, pola `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `--out <sbom.json>` | path | ya | SBOM keluaran; tidak boleh sudah ada |

| Keluaran | Keterangan |
| -------- | ---------- |
| Berkas `--out` | Dokumen SBOM CycloneDX 1.6 |
| stdout | `sbom`, `component` (nama dan versi), `sha256` artefak, jumlah `components` |
| Exit code | `0` berhasil; `2` input tidak valid, ZIP rusak, berkas sudah ada, atau I/O error |

### `sbom sign`

Menandatangani SBOM sebagai artefak terpisah. SBOM divalidasi lebih dulu dan
**wajib terikat** dengan `--file` (lihat [aturan keterikatan](#aturan-keterikatan));
SBOM yang tidak memuat SHA-256 artefak rilis ditolak dan tidak ditandatangani.

| Parameter | Tipe | Wajib | Keterangan |
| --------- | ---- | ----- | ---------- |
| `--sbom <sbom.json>` | path | ya | Dokumen SBOM |
| `--file <path>` | path | ya | Artefak rilis yang dirujuk SBOM |
| `--package <nama>` | string | ya | Nama paket |
| `--version <versi>` | string | ya | Versi rilis |
| `--key <private.pem>` | path | ya | Kunci privat PKCS#8 PEM; profil ditentukan dari kunci |
| `--out <bundle.json>` | path | ya | Bundle SBOM keluaran; tidak boleh sudah ada |

| Keluaran | Keterangan |
| -------- | ---------- |
| Berkas `--out` | Bundle `minisign-bundle/v1` atas berkas SBOM |
| stdout | `bundle`, `keyid`, `algorithm`, `artifact` (sama dengan `sign`) |
| Exit code | `0` berhasil; `2` SBOM tidak valid/tidak terikat, kunci tidak valid, berkas sudah ada, atau I/O error |

### `sbom verify`

Memverifikasi signature SBOM lalu memvalidasi isinya.

| Parameter | Tipe | Wajib | Keterangan |
| --------- | ---- | ----- | ---------- |
| `--sbom <sbom.json>` | path | ya | Dokumen SBOM |
| `--bundle <bundle.json>` | path | ya | Bundle SBOM |
| `--trust-store <trust.json>` | path | ya | Trust store |
| `--package <nama>` | string | ya | Nama paket yang diharapkan |
| `--version <versi>` | string | ya | Versi yang diharapkan |
| `--json` | flag | tidak | Keluaran JSON |

Urutan pemeriksaan:

| No | Status jika gagal | Pemeriksaan |
| -- | ----------------- | ----------- |
| 1–7 | `INPUT_ERROR` … `ARTIFACT_MISMATCH` | Identik dengan `verify` (Tabel 2.8) dengan berkas SBOM sebagai artefak |
| 8 | `ARTIFACT_MISMATCH` | Byte SBOM yang akan di-parse masih sama dengan yang terverifikasi (berkas tidak berubah di tengah proses) |
| 9 | `FORMAT_ERROR` | Isi SBOM sesuai [format data SBOM](#format-data-sbom) |
| 10 | `OK` | Seluruh pemeriksaan berhasil |

Isi SBOM sengaja baru di-parse **setelah** signature terbukti sah, sehingga data
dari pihak yang tidak tepercaya tidak pernah diproses.

| Keluaran | Keterangan |
| -------- | ---------- |
| stdout (teks) | `<STATUS>: <message>` |
| stdout (`--json`) | Satu objek JSON berformat sama dengan `verify --json` (Tabel 2.9): `valid`, `status`, `message`, `algorithm`, `keyid`, `package`, `version` |
| Exit code | `0` OK; `1` ditolak; `2` `INPUT_ERROR` |

### `sbom check`

Memverifikasi **kedua bundle** (rilis dan SBOM) lalu mencocokkan nilai SHA-256.

| Parameter | Tipe | Wajib | Keterangan |
| --------- | ---- | ----- | ---------- |
| `--file <path>` | path | ya | Artefak rilis |
| `--bundle <bundle.json>` | path | ya | Bundle rilis |
| `--sbom <sbom.json>` | path | ya | Dokumen SBOM |
| `--sbom-bundle <bundle.json>` | path | ya | Bundle SBOM |
| `--trust-store <trust.json>` | path | ya | Trust store |
| `--package <nama>` | string | ya | Nama paket yang diharapkan |
| `--version <versi>` | string | ya | Versi yang diharapkan |
| `--json` | flag | tidak | Keluaran JSON |

Urutan pemeriksaan (berhenti pada kegagalan pertama):

| Tahap (`stage`) | Status jika gagal | Pemeriksaan |
| --------------- | ----------------- | ----------- |
| `release` | Status Tabel 2.8 | `verify` atas artefak rilis dan bundle rilis |
| `sbom` | Status `sbom verify` | `sbom verify` atas SBOM dan bundle SBOM |
| `binding` | `SBOM_MISMATCH` | [Aturan keterikatan](#aturan-keterikatan) antara SBOM dan manifest rilis terverifikasi |
| – | `OK` | Rilis dan SBOM sah serta terikat pada artefak yang sama |

Keluaran `--json` (satu objek JSON diakhiri newline):

| Field | Tipe | Keterangan |
| ----- | ---- | ---------- |
| `valid` | boolean | `true` hanya bila `status == "OK"` |
| `status` | string | Status Tabel 2.8 atau `SBOM_MISMATCH` |
| `stage` | string \| null | `release`, `sbom`, `binding`; `null` bila `OK` atau argumen CLI salah |
| `message` | string | Penjelasan singkat, diawali tahap kegagalan |
| `artifact_sha256` | string \| null | SHA-256 artefak dari manifest rilis terverifikasi |
| `release` | object \| null | Hasil verifikasi rilis (format Tabel 2.9) |
| `sbom` | object \| null | Hasil verifikasi SBOM (format Tabel 2.9) |

Contoh keluaran skenario S06 (artefak diganti dan rilis ditandatangani ulang,
SBOM lama dipakai). Keluaran asli berupa satu baris; di sini diberi indentasi
agar mudah dibaca:

```json
{
  "valid": false,
  "status": "SBOM_MISMATCH",
  "stage": "binding",
  "message": "SBOM does not reference the SHA-256 of the release artifact",
  "artifact_sha256": "880762b061f6ca0001612c90bde944e1131afc125a701a9577b6c409ed163fe2",
  "release": {
    "valid": true,
    "status": "OK",
    "message": "Signature and artifact are valid.",
    "algorithm": "rsa-pss-sha256",
    "keyid": "a0d0ff5d67b01029880f33ada6b0464e5bfa782233a2784a916f300b45a4ff00",
    "package": "contoh-app",
    "version": "1.0.0"
  },
  "sbom": {
    "valid": true,
    "status": "OK",
    "message": "SBOM signature and content are valid.",
    "algorithm": "rsa-pss-sha256",
    "keyid": "a0d0ff5d67b01029880f33ada6b0464e5bfa782233a2784a916f300b45a4ff00",
    "package": "contoh-app",
    "version": "1.0.0"
  }
}
```

| Exit code | Keterangan |
| --------- | ---------- |
| `0` | `OK` |
| `1` | Ditolak: status Tabel 2.8 selain `OK`/`INPUT_ERROR`, atau `SBOM_MISMATCH` |
| `2` | `INPUT_ERROR` (berkas tidak terbaca atau argumen CLI salah) |

## Aturan keterikatan

SBOM terikat dengan artefak rilis apabila seluruh kondisi berikut terpenuhi
({func}`~src.sbom.document.binding_error`):

| No | Kondisi | Pesan bila gagal |
| -- | ------- | ---------------- |
| 1 | SHA-256 pada `metadata.component.hashes` = `artifact.sha256` manifest rilis | `SBOM does not reference the SHA-256 of the release artifact` |
| 2 | `metadata.component.name` = `--package` | `SBOM component name ... differs from package ...` |
| 3 | `metadata.component.version` = `--version` | `SBOM component version ... differs from version ...` |
| 4 | Property `digisign:artifact:name` (bila ada) = nama berkas artefak rilis | `SBOM artifact name ... differs from ...` |

Aturan ini dipakai di dua tempat: `sbom sign` (menolak menandatangani SBOM yang
tidak terikat, exit code `2`) dan tahap `binding` pada `sbom check`
(`SBOM_MISMATCH`, exit code `1`).

## Contoh penggunaan

```bash
digisign keygen --algorithm ed25519 --out keys/publisher
digisign trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json

# rilis
digisign sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out contoh-app.bundle.json

# SBOM
digisign sbom generate --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --out contoh-app.cdx.json
digisign sbom sign --sbom contoh-app.cdx.json --file contoh-app.zip \
  --package contoh-app --version 1.0.0 --key keys/publisher.key.pem \
  --out contoh-app.cdx.bundle.json

# verifikasi
digisign sbom verify --sbom contoh-app.cdx.json --bundle contoh-app.cdx.bundle.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
digisign sbom check --file contoh-app.zip --bundle contoh-app.bundle.json \
  --sbom contoh-app.cdx.json --sbom-bundle contoh-app.cdx.bundle.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
```

Dari Python:

```python
from src.sbom import build_sbom, parse_sbom, check_sbom

data = build_sbom("contoh-app.zip", "contoh-app", "1.0.0")   # bytes CycloneDX JSON
doc = parse_sbom(data)                                         # SbomDocument
print(doc.name, doc.version, doc.sha256, doc.component_count)

result = check_sbom("contoh-app.zip", "contoh-app.bundle.json",
                    "contoh-app.cdx.json", "contoh-app.cdx.bundle.json",
                    "trust.json", "contoh-app", "1.0.0")
print(result.status, result.stage, result.exit_code)          # OK None 0
```

## Pengujian

Skrip `test/sbom/run_tests.py` menjalankan CLI asli untuk setiap skenario dan
menulis hasilnya ke `test/sbom/results.md` dan `test/sbom/results.json`. Berkas
masukan ada di `test/sbom/input/`; kunci uji dibangkitkan ulang tiap run.

```bash
python3 test/sbom/run_tests.py
```

| ID | Skenario | Hasil yang diharapkan |
| -- | -------- | --------------------- |
| S01 | Rilis + SBOM sah, untuk ketiga algoritma | `sbom verify` dan `sbom check`: `OK`, exit `0` |
| S02 | **Isi SBOM diubah**: satu karakter hash komponen diganti (ukuran tetap) | `ARTIFACT_MISMATCH` (stage `sbom`) |
| S03 | **Isi SBOM diubah**: hash `metadata.component` diganti ke SHA-256 artefak pengganti | `ARTIFACT_MISMATCH` (stage `sbom`) |
| S04 | **Isi SBOM diubah**: komponen ditambahkan (ukuran berubah) | `ARTIFACT_MISMATCH` (stage `sbom`) |
| S05 | **Artefak rilis diganti**, bundle rilis lama dipakai | `sbom check`: `ARTIFACT_MISMATCH` (stage `release`) |
| S06 | **Artefak rilis diganti** dan rilis ditandatangani ulang dengan kunci sah, SBOM lama tetap dipakai | `sbom check`: `SBOM_MISMATCH` (stage `binding`) |
| S07 | **Artefak rilis diganti**, SBOM baru ditandatangani kunci tidak tepercaya | `KEY_NOT_TRUSTED` (stage `sbom`) |
| S08 | `sbom sign` atas SBOM yang tidak memuat SHA-256 artefak | exit `2`, bundle tidak dibuat |
| S09 | `sbom sign` dengan `--version` berbeda dari SBOM | exit `2` |
| S10 | JSON non-SBOM ditandatangani dengan `sign` biasa | `FORMAT_ERROR` |
| S11 | SBOM dengan field duplikat ditandatangani dengan `sign` biasa | `FORMAT_ERROR` |
| S12 | Bundle rilis dipakai sebagai `--sbom-bundle` | `METADATA_MISMATCH` (stage `sbom`) |
| S13 | Kunci SBOM hanya diizinkan untuk paket lain | `KEY_NOT_TRUSTED` |
| S14 | Berkas SBOM tidak ada | `INPUT_ERROR`, exit `2` |
| S15 | SBOM + bundle SBOM diverifikasi dengan `verify` biasa | `OK` (format bundle identik) |
