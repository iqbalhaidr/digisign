# Uji interoperabilitas dengan OpenSSL CLI sebagai implementasi independen.
#
# Untuk setiap profil:
#   I1  Kunci buatan OpenSSL dibaca program; keyid program = SHA-256(DER SPKI) hitungan OpenSSL
#   I2  Kunci buatan program (keygen) dibaca OpenSSL; keyid sama
#   I3  Tanda tangan program diverifikasi OpenSSL
#   I4  Tanda tangan OpenSSL diverifikasi program

import base64
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.dirname(HERE)
sys.path[:0] = [TEST_DIR]

from harness import PACKAGE, PROFILES, VERSION, Recorder, Report, SetupError, rel, require  # noqa: E402

RESULTS_DIR = os.path.join(HERE, "results")
ARTIFACT = os.path.join(TEST_DIR, "scenarios", "inputs", "contoh-app.bin")
KEEP_FILES = {"commands.log", "bundle-program.json", "bundle-openssl.json", "openssl.pub.pem"}

OPENSSL_GENPKEY = {
    "rsa-pss-sha256": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
    "ecdsa-p256-sha256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "ed25519": ["-algorithm", "ed25519"],
}
RSA_PSS_OPTS = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"]


def _der_int(value: bytes) -> bytes:
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + bytes([len(value)]) + value


def raw_to_der(raw: bytes) -> bytes:
    body = _der_int(raw[:32]) + _der_int(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def der_to_raw(der: bytes) -> bytes:
    if der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("bukan SEQUENCE DER ECDSA yang valid")
    pos, values = 2, []
    for _ in range(2):
        if der[pos] != 0x02:
            raise ValueError("elemen bukan INTEGER")
        length = der[pos + 1]
        values.append(int.from_bytes(der[pos + 2:pos + 2 + length], "big"))
        pos += 2 + length
    return b"".join(v.to_bytes(32, "big") for v in values)


class Profile:
    def __init__(self, profile: str, openssl: str, report: Report):
        self.profile = profile
        self.openssl = openssl
        self.report = report
        self.dir = os.path.join(RESULTS_DIR, profile)
        os.makedirs(self.dir)
        self.rec = Recorder(os.path.join(self.dir, "commands.log"))

    def path(self, name: str) -> str:
        return rel(os.path.join(self.dir, name))

    def ssl(self, *args: str):
        return self.rec.tool(self.openssl, *args)

    def openssl_keyid(self, der_name: str) -> str:
        run = require(self.ssl("dgst", "-sha256", "-r", self.path(der_name)), "openssl dgst")
        return run.stdout.split()[0].lower()

    def add(self, cid: str, description: str, expected: str, actual: str, passed: bool) -> None:
        self.report.add(cid, self.profile, description, expected, actual, passed, rel(self.dir))

    def read(self, name: str) -> bytes:
        with open(os.path.join(self.dir, name), "rb") as f:
            return f.read()

    def write(self, name: str, data: bytes) -> None:
        with open(os.path.join(self.dir, name), "wb") as f:
            f.write(data)

    def cleanup(self) -> None:
        for name in os.listdir(self.dir):
            if name not in KEEP_FILES:
                os.remove(os.path.join(self.dir, name))

    def run(self) -> None:
        artifact = rel(ARTIFACT)
        store = self.path("trust.json")

        # I1
        require(self.ssl("genpkey", *OPENSSL_GENPKEY[self.profile], "-out", self.path("openssl.key.pem")), "genpkey")
        require(self.ssl("pkey", "-in", self.path("openssl.key.pem"), "-pubout", "-out", self.path("openssl.pub.pem")),
                "pkey -pubout")
        require(self.ssl("pkey", "-in", self.path("openssl.key.pem"), "-pubout", "-outform", "DER",
                         "-out", self.path("openssl.pub.der")), "pkey -outform DER")
        expected_keyid = self.openssl_keyid("openssl.pub.der")
        trust = self.rec.cli("trust", "add", "--key", self.path("openssl.pub.pem"), "--package", PACKAGE,
                             "--store", store)
        self.add("I1", "Kunci buatan OpenSSL (`genpkey`) dibaca program; keyid sama",
                 f"keyid {expected_keyid[:16]}...", f"exit {trust.code}, keyid {(trust.keyid or '-')[:16]}...",
                 trust.code == 0 and trust.keyid == expected_keyid)

        # I2
        keygen = self.rec.cli("keygen", "--algorithm", self.profile, "--out", self.path("program"))
        read_private = self.ssl("pkey", "-in", self.path("program.key.pem"), "-noout")
        read_public = self.ssl("pkey", "-pubin", "-in", self.path("program.pub.pem"), "-outform", "DER",
                               "-out", self.path("program.pub.der"))
        program_keyid = self.openssl_keyid("program.pub.der") if read_public.code == 0 else None
        self.add("I2", "Kunci buatan program (`keygen`) dibaca OpenSSL (`pkey`); keyid sama",
                 f"keyid {(keygen.keyid or '-')[:16]}...",
                 f"pkey exit {read_private.code}/{read_public.code}, keyid {(program_keyid or '-')[:16]}...",
                 keygen.code == 0 and read_private.code == 0 and program_keyid == keygen.keyid)

        # I3
        bundle = self.path("bundle-program.json")
        require(self.rec.cli("sign", "--file", artifact, "--package", PACKAGE, "--version", VERSION,
                             "--key", self.path("openssl.key.pem"), "--out", bundle), "sign")
        document = json.loads(self.read("bundle-program.json"))
        manifest = base64.b64decode(document["manifest_b64"])
        signature = base64.b64decode(document["signature_b64"])
        self.write("manifest.bin", manifest)

        if self.profile == "ecdsa-p256-sha256":
            self.write("sig-program.der", raw_to_der(signature))
            check = self.ssl("dgst", "-sha256", "-verify", self.path("openssl.pub.pem"),
                             "-signature", self.path("sig-program.der"), self.path("manifest.bin"))
        elif self.profile == "rsa-pss-sha256":
            self.write("sig-program.bin", signature)
            check = self.ssl("dgst", "-sha256", *RSA_PSS_OPTS, "-verify", self.path("openssl.pub.pem"),
                             "-signature", self.path("sig-program.bin"), self.path("manifest.bin"))
        else:
            self.write("sig-program.bin", signature)
            check = self.ssl("pkeyutl", "-verify", "-pubin", "-inkey", self.path("openssl.pub.pem"), "-rawin",
                             "-in", self.path("manifest.bin"), "-sigfile", self.path("sig-program.bin"))
        self.add("I3", "Tanda tangan program diverifikasi OpenSSL", "OpenSSL exit 0",
                 f"OpenSSL exit {check.code}: {check.stdout.strip() or check.stderr.strip()}", check.code == 0)

        # I4
        if self.profile == "ecdsa-p256-sha256":
            require(self.ssl("dgst", "-sha256", "-sign", self.path("openssl.key.pem"),
                             "-out", self.path("sig-openssl.der"), self.path("manifest.bin")), "openssl sign")
            openssl_signature = der_to_raw(self.read("sig-openssl.der"))
        elif self.profile == "rsa-pss-sha256":
            require(self.ssl("dgst", "-sha256", *RSA_PSS_OPTS, "-sign", self.path("openssl.key.pem"),
                             "-out", self.path("sig-openssl.bin"), self.path("manifest.bin")), "openssl sign")
            openssl_signature = self.read("sig-openssl.bin")
        else:
            require(self.ssl("pkeyutl", "-sign", "-inkey", self.path("openssl.key.pem"), "-rawin",
                             "-in", self.path("manifest.bin"), "-out", self.path("sig-openssl.bin")), "openssl sign")
            openssl_signature = self.read("sig-openssl.bin")

        openssl_bundle = {
            "schema": "minisign-bundle/v1",
            "manifest_b64": base64.b64encode(manifest).decode("ascii"),
            "signature_b64": base64.b64encode(openssl_signature).decode("ascii"),
        }
        self.write("bundle-openssl.json", (json.dumps(openssl_bundle, indent=2) + "\n").encode("ascii"))
        self.rec.note(f"{self.path('bundle-openssl.json')}: manifest yang sama, tanda tangan dari OpenSSL")
        verify = self.rec.cli("verify", "--file", artifact, "--bundle", self.path("bundle-openssl.json"),
                              "--trust-store", store, "--package", PACKAGE, "--version", VERSION, "--json")
        self.add("I4", "Tanda tangan OpenSSL diverifikasi program (`verify`)", "OK (exit 0)",
                 f"{verify.status} (exit {verify.code})", verify.status == "OK" and verify.code == 0)

        self.cleanup()


def main() -> int:
    openssl = shutil.which("openssl")
    if openssl is None:
        print("error: openssl tidak ditemukan di PATH", file=sys.stderr)
        return 2
    if not os.path.exists(ARTIFACT):
        print(f"error: artefak uji tidak ditemukan: {rel(ARTIFACT)}", file=sys.stderr)
        return 2

    if os.path.exists(RESULTS_DIR):
        shutil.rmtree(RESULTS_DIR)
    os.makedirs(RESULTS_DIR)

    report = Report("Hasil Uji Interoperabilitas dengan OpenSSL")
    for profile in PROFILES:
        try:
            Profile(profile, openssl, report).run()
        except SetupError as e:
            report.add("-", profile, "Persiapan", "persiapan berhasil", str(e), False, rel(RESULTS_DIR))

    notes = """
## Keterangan

- **I1**: kunci dibangkitkan `openssl genpkey` (PKCS#8 PEM), dibaca program melalui `trust add`.
  keyid pembanding dihitung OpenSSL: `openssl pkey -pubout -outform DER | openssl dgst -sha256`.
- **I2**: kunci dari `keygen` dibaca `openssl pkey`; keyid dihitung OpenSSL dari DER SPKI hasil ekspornya.
- **I3**: manifest M dan tanda tangan diambil dari bundle hasil `sign`, lalu diverifikasi:
  - RSA-PSS: `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -verify`
  - ECDSA: tanda tangan r||s (64 byte) diubah ke ASN.1 DER, lalu `openssl dgst -sha256 -verify`
  - Ed25519: `openssl pkeyutl -verify -rawin` (pesan mentah, tanpa pre-hash)
- **I4**: OpenSSL menandatangani M yang sama dengan perintah setara; untuk ECDSA keluaran DER diubah ke r||s.
  Bundle dirakit skrip ini, lalu diverifikasi dengan `verify --json`.
- Konversi DER <-> r||s dan pembentukan bundle ditulis ulang di skrip ini, tidak memakai kode program.
"""
    report.write(RESULTS_DIR, "python test/interop/run_interop.py", notes)

    for case in report.cases:
        print(f"[{'LULUS' if case.passed else 'GAGAL'}] {case.id} {case.profile}: {case.description}"
              f" -> {case.actual}")
    print(f"\nHasil lengkap: {rel(RESULTS_DIR)}/README.md")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
