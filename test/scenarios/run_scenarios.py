# Skenario uji melalui CLI.
#
# Skenario:
#   U01  Sign dan verify berkas teks, biner, dan kosong untuk ketiga profil
#   U02  Satu byte artefak diubah tanpa mengubah ukuran atau nama berkas
#   U03  Byte ditambahkan atau dihapus pada artefak
#   U04  Versi pada manifest diubah, tanda tangan dari manifest sebelumnya
#   U05  Satu bit tanda tangan dibalik
#   U06  Trust store kosong atau kunci penerbit dihapus
#   U07  Kunci hanya diizinkan untuk paket lain
#   U08  Bundle sah diverifikasi dengan versi yang berbeda dari manifest
#   U09  Nama berkas artefak diubah tanpa mengubah isinya
#   U10  Field duplikat, tipe data salah, Base64 tidak valid, manifest melebihi batas
#   U11  Nilai algorithm yang tidak didukung pada manifest
#   U12  Ditandatangani kunci lain berprofil sama yang tidak ada di trust store
#   U13  White space dan urutan field bundle diubah, Base64 tetap
#   U14  Manifest identik ditandatangani dua kali dengan kunci yang sama

import base64
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(os.path.dirname(HERE)), os.path.dirname(HERE)]

from harness import (  # noqa: E402
    PACKAGE, PROFILES, REPO_ROOT, VERSION, Recorder, Report, SetupError, rel, require,
)

KEYS_DIR = os.path.join(HERE, "keys")
INPUTS_DIR = os.path.join(HERE, "inputs")
RESULTS_DIR = os.path.join(HERE, "results")

OTHER_KEY = "other-ed25519"
ARTIFACTS = {
    "teks": ("contoh-app.txt", b"Contoh artefak rilis berupa berkas teks."),
    "biner": ("contoh-app.bin", bytes(range(256)) * 16),
    "kosong": ("contoh-app-empty.txt", b""),
}
MAIN_ARTIFACT = os.path.join(INPUTS_DIR, ARTIFACTS["biner"][0])
TRUST_SCHEMA = "minisign-trust/v1"


def key(name: str, kind: str) -> str:
    return rel(os.path.join(KEYS_DIR, f"{name}.{kind}.pem"))


def ensure_inputs() -> None:
    os.makedirs(INPUTS_DIR, exist_ok=True)
    for name, data in ARTIFACTS.values():
        path = os.path.join(INPUTS_DIR, name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)


def ensure_keys() -> None:
    missing = [
        (name, profile)
        for name, profile in [*((p, p) for p in PROFILES), (OTHER_KEY, "ed25519")]
        if not os.path.exists(os.path.join(KEYS_DIR, f"{name}.key.pem"))
    ]
    if not missing:
        return
    os.makedirs(KEYS_DIR, exist_ok=True)
    rec = Recorder()
    for name, profile in missing:
        require(rec.cli("keygen", "--algorithm", profile, "--out", rel(os.path.join(KEYS_DIR, name))), f"keygen {name}")


class Scenario:
    def __init__(self, sid: str, report: Report):
        self.sid = sid
        self.report = report
        self.dir = os.path.join(RESULTS_DIR, sid)
        os.makedirs(self.dir, exist_ok=True)
        self.rec = Recorder()

    def path(self, name: str) -> str:
        return rel(os.path.join(self.dir, name))

    def trust_add(self, store: str, key_name: str, package: str = PACKAGE):
        return require(
            self.rec.cli("trust", "add", "--key", key(key_name, "pub"), "--package", package, "--store", store),
            "trust add",
        )

    def sign(self, artifact: str, key_name: str, bundle: str):
        return require(
            self.rec.cli(
                "sign", "--file", rel(artifact), "--package", PACKAGE, "--version", VERSION,
                "--key", key(key_name, "key"), "--out", bundle,
            ),
            "sign",
        )

    def verify(self, artifact: str, bundle: str, store: str, package: str = PACKAGE, version: str = VERSION):
        return self.rec.cli(
            "verify", "--file", rel(artifact), "--bundle", bundle, "--trust-store", store,
            "--package", package, "--version", version, "--json",
        )

    def check(self, profile: str, description: str, run, expected_status: str) -> None:
        self.report.add_verify(self.sid, profile, description, run, expected_status, rel(self.dir))

    def signed(self, profile: str = "ed25519") -> tuple[str, str]:
        store = self.path("trust.json")
        self.trust_add(store, profile)
        bundle = self.path("bundle.json")
        self.sign(MAIN_ARTIFACT, profile, bundle)
        return store, bundle

    def artifact(self, subdir: str, name: str, data: bytes) -> str:
        folder = os.path.join(self.dir, subdir)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name)
        with open(path, "wb") as f:
            f.write(data)
        return path


def read_json(path: str) -> dict:
    with open(os.path.join(REPO_ROOT, path), "rb") as f:
        return json.loads(f.read())


def write_json(path: str, document: dict) -> None:
    with open(os.path.join(REPO_ROOT, path), "w", encoding="utf-8", newline="\n") as f:
        json.dump(document, f, indent=2)
        f.write("\n")


def write_text(path: str, text: str) -> None:
    with open(os.path.join(REPO_ROOT, path), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def u01(report: Report) -> None:
    s = Scenario("U01", report)
    store = s.path("trust.json")
    for profile in PROFILES:
        s.trust_add(store, profile)
    for profile in PROFILES:
        for kind, (name, data) in ARTIFACTS.items():
            artifact = os.path.join(INPUTS_DIR, name)
            bundle = s.path(f"{profile}-{kind}.json")
            s.sign(artifact, profile, bundle)
            s.check(profile, f"Berkas {kind} `{name}` ({len(data)} byte), kunci dan metadata sesuai",
                    s.verify(artifact, bundle, store), "OK")


def u02(report: Report) -> None:
    s = Scenario("U02", report)
    store, bundle = s.signed()
    data = read_bytes(MAIN_ARTIFACT)
    s.check("ed25519", "Kontrol: artefak asli", s.verify(MAIN_ARTIFACT, bundle, store), "OK")

    index = len(data) // 2
    changed = bytearray(data)
    changed[index] ^= 0x01
    artifact = s.artifact("ubah-byte", os.path.basename(MAIN_ARTIFACT), bytes(changed))
    s.check("ed25519", f"Satu byte artefak (ke-{index}) diubah, ukuran dan nama berkas tetap",
            s.verify(artifact, bundle, store), "ARTIFACT_MISMATCH")


def u03(report: Report) -> None:
    s = Scenario("U03", report)
    store, bundle = s.signed()
    data = read_bytes(MAIN_ARTIFACT)
    name = os.path.basename(MAIN_ARTIFACT)

    longer = s.artifact("tambah-byte", name, data + b"\x00")
    s.check("ed25519", "Satu byte ditambahkan di akhir artefak", s.verify(longer, bundle, store), "ARTIFACT_MISMATCH")

    shorter = s.artifact("hapus-byte", name, data[:-1])
    s.check("ed25519", "Satu byte dihapus dari akhir artefak", s.verify(shorter, bundle, store), "ARTIFACT_MISMATCH")


def u04(report: Report) -> None:
    s = Scenario("U04", report)
    store, bundle = s.signed()
    document = read_json(bundle)
    manifest = base64.b64decode(document["manifest_b64"])
    edited = manifest.replace(b'"version":"1.0.0"', b'"version":"1.0.1"')
    assert edited != manifest and len(edited) == len(manifest)
    document["manifest_b64"] = base64.b64encode(edited).decode("ascii")
    tampered = s.path("bundle-versi-diubah.json")
    write_json(tampered, document)
    s.check("ed25519", "Versi manifest diubah menjadi 1.0.1, tanda tangan lama",
            s.verify(MAIN_ARTIFACT, tampered, store, version="1.0.1"), "INVALID_SIGNATURE")


def u05(report: Report) -> None:
    s = Scenario("U05", report)
    store = s.path("trust.json")
    for profile in PROFILES:
        s.trust_add(store, profile)
        bundle = s.path(f"{profile}.json")
        s.sign(MAIN_ARTIFACT, profile, bundle)
        s.check(profile, "Kontrol: bundle asli", s.verify(MAIN_ARTIFACT, bundle, store), "OK")

        document = read_json(bundle)
        signature = bytearray(base64.b64decode(document["signature_b64"]))
        index = len(signature) // 2
        signature[index] ^= 0x01
        document["signature_b64"] = base64.b64encode(bytes(signature)).decode("ascii")
        tampered = s.path(f"{profile}-bitflip.json")
        write_json(tampered, document)

        s.check(profile, f"Bit 0 byte ke-{index} tanda tangan dibalik (panjang dan Base64 tetap valid)",
                s.verify(MAIN_ARTIFACT, tampered, store), "INVALID_SIGNATURE")


def u06(report: Report) -> None:
    s = Scenario("U06", report)
    profile = "ed25519"
    bundle = s.path("bundle.json")
    s.sign(MAIN_ARTIFACT, profile, bundle)

    empty_store = s.path("trust-empty.json")
    write_json(empty_store, {"schema": TRUST_SCHEMA, "keys": []})
    s.check(profile, "Trust store kosong", s.verify(MAIN_ARTIFACT, bundle, empty_store), "KEY_NOT_TRUSTED")

    store = s.path("trust.json")
    keyid = s.trust_add(store, profile).keyid
    s.check(profile, "Kontrol: kunci penerbit ada di trust store", s.verify(MAIN_ARTIFACT, bundle, store), "OK")
    require(s.rec.cli("trust", "remove", "--keyid", keyid, "--store", store), "trust remove")
    s.check(profile, "Kunci penerbit dihapus dengan `trust remove`", s.verify(MAIN_ARTIFACT, bundle, store),
            "KEY_NOT_TRUSTED")


def u07(report: Report) -> None:
    s = Scenario("U07", report)
    profile = "ed25519"
    store = s.path("trust.json")
    s.trust_add(store, profile, package="other-app")
    bundle = s.path("bundle.json")
    s.sign(MAIN_ARTIFACT, profile, bundle)
    s.check(profile, "Kunci hanya diizinkan untuk paket `other-app`", s.verify(MAIN_ARTIFACT, bundle, store),
            "KEY_NOT_TRUSTED")

    s.trust_add(store, profile, package=PACKAGE)
    s.check(profile, "Kontrol: izin `contoh-app` ditambahkan ke kunci yang sama",
            s.verify(MAIN_ARTIFACT, bundle, store), "OK")


def u08(report: Report) -> None:
    s = Scenario("U08", report)
    store, bundle = s.signed()
    s.check("ed25519", "Kontrol: versi sama dengan manifest (1.0.0)", s.verify(MAIN_ARTIFACT, bundle, store), "OK")
    s.check("ed25519", "Bundle sah, paket sesuai, versi pengguna 2.0.0 berbeda dari manifest (1.0.0)",
            s.verify(MAIN_ARTIFACT, bundle, store, version="2.0.0"), "METADATA_MISMATCH")


def u09(report: Report) -> None:
    s = Scenario("U09", report)
    store, bundle = s.signed()
    data = read_bytes(MAIN_ARTIFACT)
    s.check("ed25519", "Kontrol: nama berkas sama dengan manifest", s.verify(MAIN_ARTIFACT, bundle, store), "OK")

    renamed = s.artifact("nama-lain", "contoh-app-renamed.bin", data)
    s.check("ed25519", "Nama berkas diubah menjadi `contoh-app-renamed.bin`, isi tidak berubah",
            s.verify(renamed, bundle, store), "METADATA_MISMATCH")


def u10(report: Report) -> None:
    from src.constants import MAX_MANIFEST_BYTES

    s = Scenario("U10", report)
    store, bundle = s.signed()
    document = read_json(bundle)
    with open(os.path.join(REPO_ROOT, bundle), encoding="utf-8") as f:
        raw = f.read()

    cases = [
        ("bundle-duplikat.json", "Field `schema` muncul dua kali di bundle",
         raw.rstrip()[:-1].rstrip() + ',\n  "schema": "minisign-bundle/v1"\n}\n'),
        ("bundle-tipe-salah.json", "`manifest_b64` bertipe angka, bukan string",
         json.dumps({**document, "manifest_b64": 123}, indent=2) + "\n"),
        ("bundle-base64-salah.json", "`signature_b64` = `QQ-_` (karakter di luar alfabet Base64)",
         json.dumps({**document, "signature_b64": "QQ-_"}, indent=2) + "\n"),
        ("bundle-manifest-besar.json", f"Manifest {MAX_MANIFEST_BYTES + 1} byte, melebihi batas {MAX_MANIFEST_BYTES} byte",
         json.dumps({**document, "manifest_b64": base64.b64encode(b" " * (MAX_MANIFEST_BYTES + 1)).decode("ascii")},
                    indent=2) + "\n"),
    ]
    for name, description, text in cases:
        path = s.path(name)
        write_text(path, text)
        s.check("ed25519", description, s.verify(MAIN_ARTIFACT, path, store), "FORMAT_ERROR")


def u11(report: Report) -> None:
    from src.crypto import compute_keyid, load_private_key_pem, sign
    from src.data.bundle import serialize_bundle
    from src.data.manifest import Artifact, Manifest, serialize_manifest
    from src.fileio import hash_file

    s = Scenario("U11", report)
    store = s.path("trust.json")
    s.trust_add(store, "ed25519")

    with open(os.path.join(KEYS_DIR, "ed25519.key.pem"), "rb") as f:
        private_key = load_private_key_pem(f.read())
    size, sha256 = hash_file(MAIN_ARTIFACT)

    for algorithm in ["ed448", "rsa-pkcs1-sha256", "ED25519"]:
        manifest = Manifest(
            package=PACKAGE, version=VERSION, algorithm=algorithm,
            keyid=compute_keyid(private_key.public_key()),
            artifact=Artifact(os.path.basename(MAIN_ARTIFACT), size, sha256),
        )
        manifest_bytes = serialize_manifest(manifest)
        bundle = s.path(f"bundle-{algorithm}.json")
        with open(os.path.join(s.dir, f"bundle-{algorithm}.json"), "wb") as f:
            f.write(serialize_bundle(manifest_bytes, sign(private_key, manifest_bytes)))
        s.check("ed25519", f"Nilai `algorithm` = `{algorithm}` pada manifest",
                s.verify(MAIN_ARTIFACT, bundle, store), "UNSUPPORTED_ALGORITHM")


def u12(report: Report) -> None:
    s = Scenario("U12", report)
    store = s.path("trust.json")
    s.trust_add(store, "ed25519")
    bundle = s.path("bundle-other-key.json")
    other = s.sign(MAIN_ARTIFACT, OTHER_KEY, bundle).keyid
    s.check("ed25519", f"Ditandatangani kunci lain berprofil sama (keyid {other[:12]}...) yang tidak ada di trust store",
            s.verify(MAIN_ARTIFACT, bundle, store), "KEY_NOT_TRUSTED")


def u13(report: Report) -> None:
    s = Scenario("U13", report)
    store, bundle = s.signed()
    document = read_json(bundle)
    reordered = s.path("bundle-urutan-whitespace.json")
    write_text(
        reordered,
        '{ "signature_b64" :\n\t"%s" ,\n   "schema":"%s",\n\n  "manifest_b64"  :   "%s"   }\n'
        % (document["signature_b64"], document["schema"], document["manifest_b64"]),
    )
    s.check("ed25519", "Urutan field dan white space bundle diubah, Base64 tetap",
            s.verify(MAIN_ARTIFACT, reordered, store), "OK")


def u14(report: Report) -> None:
    s = Scenario("U14", report)
    store = s.path("trust.json")
    for profile in PROFILES:
        s.trust_add(store, profile)
        first, second = s.path(f"{profile}-1.json"), s.path(f"{profile}-2.json")
        s.sign(MAIN_ARTIFACT, profile, first)
        s.sign(MAIN_ARTIFACT, profile, second)
        a, b = read_json(first), read_json(second)

        same_manifest = a["manifest_b64"] == b["manifest_b64"]
        same_signature = a["signature_b64"] == b["signature_b64"]
        expect_same = profile == "ed25519"
        expected = f"manifest identik, signature {'identik' if expect_same else 'berbeda'}"
        actual = (f"manifest {'identik' if same_manifest else 'berbeda'}, "
                  f"signature {'identik' if same_signature else 'berbeda'}")
        report.add("U14", profile, "Manifest identik ditandatangani dua kali dengan kunci yang sama",
                   expected, actual, same_manifest and same_signature == expect_same, rel(s.dir))

        s.check(profile, "Bundle pertama tetap valid", s.verify(MAIN_ARTIFACT, first, store), "OK")
        s.check(profile, "Bundle kedua tetap valid", s.verify(MAIN_ARTIFACT, second, store), "OK")


# Analisis U14:
# - Ed25519 menghasilkan tanda tangan identik. Nonce diturunkan secara deterministik dari
#   SHA-512(prefix_kunci || M) (RFC 8032), sehingga M dan kunci yang sama selalu menghasilkan nonce
#   dan tanda tangan yang sama.
# - RSA-PSS menghasilkan tanda tangan berbeda karena setiap penandatanganan memakai salt acak
#   32 byte dari CSPRNG. Verifier membuka salt dari tanda tangan, sehingga keduanya tetap valid.
# - ECDSA P-256 menghasilkan tanda tangan berbeda karena nonce k diambil acak dari CSPRNG OpenSSL
#   (bukan mode deterministik RFC 6979). Nilai r = (k*G).x dan s berubah, tetapi keduanya valid.
#   Nonce tidak boleh dipakai ulang, karena dua tanda tangan dengan k yang sama membocorkan kunci privat.


def main() -> int:
    if os.path.exists(RESULTS_DIR):
        shutil.rmtree(RESULTS_DIR, ignore_errors=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ensure_inputs()
    ensure_keys()

    report = Report("Hasil Skenario Uji U01-U14")
    for scenario in (u01, u02, u03, u04, u05, u06, u07, u08, u09, u10, u11, u12, u13, u14):
        sid = scenario.__name__.upper()
        try:
            scenario(report)
        except SetupError as e:
            report.add(sid, "-", "Persiapan skenario", "persiapan berhasil", str(e), False, rel(RESULTS_DIR))
            continue

    report.write(RESULTS_DIR)

    for case in report.cases:
        if not case.passed:
            print(f"[GAGAL] {case.id} {case.profile}: {case.description} -> {case.actual}")
    print(f"{sum(c.passed for c in report.cases)}/{len(report.cases)} kasus lulus. Hasil: {rel(RESULTS_DIR)}/results.json")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
