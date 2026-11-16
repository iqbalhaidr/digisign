# Skenario uji Signed SBOM melalui CLI (`sbom check --json`).
#
# Skenario:
#   S01  Kontrol: artefak rilis, bundle rilis, SBOM, dan bundle SBOM sah
#   S02  Isi SBOM diubah setelah ditandatangani
#   S03  Artefak rilis diganti dan ditandatangani ulang, SBOM lama tetap dipakai

import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(os.path.dirname(HERE)), os.path.dirname(HERE)]

from harness import PACKAGE, REPO_ROOT, VERSION, Recorder, Report, SetupError, rel, require  # noqa: E402

KEYS_DIR = os.path.join(os.path.dirname(HERE), "scenarios", "keys")
INPUTS_DIR = os.path.join(HERE, "inputs")
RESULTS_DIR = os.path.join(HERE, "results")

PROFILE = "ed25519"
ZIP_TIME = (2026, 11, 1, 0, 0, 0)


def key(kind: str) -> str:
    return rel(os.path.join(KEYS_DIR, f"{PROFILE}.{kind}.pem"))


def make_zip(path: str, source: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    info = zipfile.ZipInfo("contoh-app.txt", ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    with open(source, "rb") as f, zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, f.read())
    return rel(path)


class Release:
    """Satu rilis sah: trust store, artefak ZIP, bundle rilis, SBOM, dan bundle SBOM."""

    def __init__(self, sid: str, report: Report):
        self.sid = sid
        self.report = report
        self.dir = os.path.join(RESULTS_DIR, sid)
        self.rec = Recorder()
        self.store = self.path("trust.json")
        self.artifact = make_zip(os.path.join(self.dir, "contoh-app.zip"), os.path.join(INPUTS_DIR, "contoh-app.txt"))
        self.bundle = self.path("contoh-app.bundle.json")
        self.sbom = self.path("contoh-app.cdx.json")
        self.sbom_bundle = self.path("contoh-app.cdx.bundle.json")

        require(self.rec.cli("trust", "add", "--key", key("pub"), "--package", PACKAGE, "--store", self.store),
                "trust add")
        self.sign(self.artifact, self.bundle)
        require(self.rec.cli("sbom", "generate", "--file", self.artifact, "--package", PACKAGE,
                             "--version", VERSION, "--out", self.sbom), "sbom generate")
        require(self.rec.cli("sbom", "sign", "--sbom", self.sbom, "--file", self.artifact, "--package", PACKAGE,
                             "--version", VERSION, "--key", key("key"), "--out", self.sbom_bundle), "sbom sign")

    def path(self, name: str) -> str:
        return rel(os.path.join(self.dir, name))

    def sign(self, artifact: str, bundle: str) -> None:
        require(self.rec.cli("sign", "--file", artifact, "--package", PACKAGE, "--version", VERSION,
                             "--key", key("key"), "--out", bundle), "sign")

    def check(self, description: str, expected_status: str, expected_stage: str | None,
              artifact: str | None = None, bundle: str | None = None, sbom: str | None = None) -> None:
        run = self.rec.cli(
            "sbom", "check", "--file", artifact or self.artifact, "--bundle", bundle or self.bundle,
            "--sbom", sbom or self.sbom, "--sbom-bundle", self.sbom_bundle, "--trust-store", self.store,
            "--package", PACKAGE, "--version", VERSION, "--json",
        )
        stage = run.json.get("stage") if run.json else None
        expected_exit = 0 if expected_status == "OK" else 1
        self.report.add(
            self.sid, PROFILE, description,
            f"{expected_status}, stage {expected_stage or '-'} (exit {expected_exit})",
            f"{run.status}, stage {stage or '-'} (exit {run.code})",
            run.status == expected_status and stage == expected_stage and run.code == expected_exit,
            rel(self.dir), run.command,
        )


def s01(report: Report) -> None:
    r = Release("S01", report)
    r.check("Kontrol: rilis dan SBOM sah, SHA-256 pada SBOM sama dengan artefak rilis", "OK", None)


def s02(report: Report) -> None:
    r = Release("S02", report)
    with open(os.path.join(REPO_ROOT, r.sbom), encoding="ascii") as f:
        text = f.read()
    old = text.split('"content": "', 2)[2][:64]  # SHA-256 entri pertama `components`
    new = ("0" if old[0] != "0" else "1") + old[1:]
    tampered = os.path.join(r.dir, "diubah", "contoh-app.cdx.json")
    os.makedirs(os.path.dirname(tampered), exist_ok=True)
    with open(tampered, "w", encoding="ascii", newline="\n") as f:
        f.write(text.replace(old, new, 1))
    r.check("Isi SBOM diubah setelah ditandatangani: satu karakter SHA-256 komponen diganti, ukuran tetap",
            "ARTIFACT_MISMATCH", "sbom", sbom=rel(tampered))


def s03(report: Report) -> None:
    r = Release("S03", report)
    replaced = make_zip(os.path.join(r.dir, "diganti", "contoh-app.zip"),
                        os.path.join(INPUTS_DIR, "contoh-app-replaced.txt"))
    bundle = r.path("contoh-app-diganti.bundle.json")
    r.sign(replaced, bundle)
    r.check("Artefak rilis diganti dan ditandatangani ulang dengan kunci sah, SBOM lama tetap dipakai",
            "SBOM_MISMATCH", "binding", artifact=replaced, bundle=bundle)


def main() -> int:
    if os.path.exists(RESULTS_DIR):
        shutil.rmtree(RESULTS_DIR, ignore_errors=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    report = Report("Hasil Skenario Uji Signed SBOM S01-S03")
    for scenario in (s01, s02, s03):
        sid = scenario.__name__.upper()
        try:
            scenario(report)
        except SetupError as e:
            report.add(sid, "-", "Persiapan skenario", "persiapan berhasil", str(e), False, rel(RESULTS_DIR))

    report.write(RESULTS_DIR)

    for case in report.cases:
        if not case.passed:
            print(f"[GAGAL] {case.id} {case.profile}: {case.description} -> {case.actual}")
    print(f"{sum(c.passed for c in report.cases)}/{len(report.cases)} kasus lulus. Hasil: {rel(RESULTS_DIR)}/results.json")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
