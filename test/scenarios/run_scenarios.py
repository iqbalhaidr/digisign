# Skenario uji melalui CLI.
#
# Skenario:
#   U01  Sign dan verify berkas teks, biner, dan kosong untuk ketiga profil
#   U05  Satu bit tanda tangan dibalik
#   U06  Trust store kosong atau kunci penerbit dihapus
#   U07  Kunci hanya diizinkan untuk paket lain
#   U11  Nilai algorithm yang tidak didukung pada manifest
#   U12  Ditandatangani kunci lain berprofil sama yang tidak ada di trust store
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
DISCARD_FILES = {"trust.json"}


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
    rec = Recorder(os.path.join(RESULTS_DIR, "setup", "commands.log"))
    for name, profile in missing:
        require(rec.cli("keygen", "--algorithm", profile, "--out", rel(os.path.join(KEYS_DIR, name))), f"keygen {name}")


class Scenario:
    def __init__(self, sid: str, report: Report):
        self.sid = sid
        self.report = report
        self.dir = os.path.join(RESULTS_DIR, sid)
        os.makedirs(self.dir, exist_ok=True)
        self.rec = Recorder(os.path.join(self.dir, "commands.log"))

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


def read_json(path: str) -> dict:
    with open(os.path.join(REPO_ROOT, path), "rb") as f:
        return json.loads(f.read())


def write_json(path: str, document: dict) -> None:
    with open(os.path.join(REPO_ROOT, path), "w", encoding="utf-8", newline="\n") as f:
        json.dump(document, f, indent=2)
        f.write("\n")


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
        s.rec.note(f"{tampered}: bit 0 pada byte ke-{index} tanda tangan dibalik; panjang tetap {len(signature)} byte")

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
        s.rec.note(f"{bundle}: dirakit skrip, manifest = {manifest_bytes.decode('ascii')}")
        s.check("ed25519", f"Nilai `algorithm` = `{algorithm}` pada manifest",
                s.verify(MAIN_ARTIFACT, bundle, store), "UNSUPPORTED_ALGORITHM")


def u12(report: Report) -> None:
    s = Scenario("U12", report)
    store = s.path("trust.json")
    trusted = s.trust_add(store, "ed25519").keyid
    bundle = s.path("bundle-other-key.json")
    other = s.sign(MAIN_ARTIFACT, OTHER_KEY, bundle).keyid
    s.rec.note(f"keyid tepercaya {trusted}; keyid penanda tangan {other}")
    s.check("ed25519", f"Ditandatangani kunci lain berprofil sama (keyid {other[:12]}...) yang tidak ada di trust store",
            s.verify(MAIN_ARTIFACT, bundle, store), "KEY_NOT_TRUSTED")


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
        s.rec.note(f"{profile}: signature_b64 #1 = {a['signature_b64']}")
        s.rec.note(f"{profile}: signature_b64 #2 = {b['signature_b64']}")
        report.add("U14", profile, "Manifest identik ditandatangani dua kali dengan kunci yang sama",
                   expected, actual, same_manifest and same_signature == expect_same, rel(s.dir))

        s.check(profile, "Bundle pertama tetap valid", s.verify(MAIN_ARTIFACT, first, store), "OK")
        s.check(profile, "Bundle kedua tetap valid", s.verify(MAIN_ARTIFACT, second, store), "OK")


U14_ANALYSIS = """
## Analisis U14

- **Ed25519** menghasilkan tanda tangan identik. Nonce diturunkan secara deterministik dari
  `SHA-512(prefix_kunci || M)` (RFC 8032), sehingga M dan kunci yang sama selalu menghasilkan nonce
  dan tanda tangan yang sama.
- **RSA-PSS** menghasilkan tanda tangan berbeda karena setiap penandatanganan memakai salt acak
  32 byte dari CSPRNG. Verifier membuka salt dari tanda tangan, sehingga keduanya tetap valid.
- **ECDSA P-256** menghasilkan tanda tangan berbeda karena nonce `k` diambil acak dari CSPRNG OpenSSL
  (bukan mode deterministik RFC 6979). Nilai `r = (k·G).x` dan `s` berubah, tetapi keduanya valid.
  Nonce tidak boleh dipakai ulang, karena dua tanda tangan dengan `k` yang sama membocorkan kunci privat.
"""


def main() -> int:
    if os.path.exists(RESULTS_DIR):
        shutil.rmtree(RESULTS_DIR)
    os.makedirs(RESULTS_DIR)
    ensure_inputs()
    ensure_keys()

    report = Report("Hasil Skenario Uji U01, U05, U06, U07, U11, U12, U14")
    for scenario in (u01, u05, u06, u07, u11, u12, u14):
        sid = scenario.__name__.upper()
        try:
            scenario(report)
        except SetupError as e:
            report.add(sid, "-", "Persiapan skenario", "persiapan berhasil", str(e), False, rel(RESULTS_DIR))
            continue
        for name in DISCARD_FILES:
            path = os.path.join(RESULTS_DIR, sid, name)
            if os.path.exists(path):
                os.remove(path)

    inputs = "\n".join(
        f"- `{rel(os.path.join(INPUTS_DIR, name))}`: berkas {kind}, {len(data)} byte"
        for kind, (name, data) in ARTIFACTS.items()
    )
    keys = (f"- `{rel(KEYS_DIR)}/`: pasangan kunci khusus pengujian untuk ketiga profil, "
            f"ditambah `{OTHER_KEY}` (kunci lain untuk U12)")
    report.write(
        RESULTS_DIR,
        "python test/scenarios/run_scenarios.py",
        f"## Berkas masukan\n\n{inputs}\n{keys}\n\n{U14_ANALYSIS}",
    )

    for case in report.cases:
        print(f"[{'LULUS' if case.passed else 'GAGAL'}] {case.id} {case.profile}: {case.description}"
              f" -> {case.actual}")
    print(f"\nHasil lengkap: {rel(RESULTS_DIR)}/README.md")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
