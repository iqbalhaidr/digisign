#!/usr/bin/env python3
"""Pengujian end-to-end bonus Signed SBOM.

Seluruh skenario menjalankan CLI asli (``python -m src.main``) sebagai
subprocess dan memeriksa exit code, status, dan (untuk ``sbom check``) tahap
kegagalan dari keluaran ``--json``.

Pemakaian (dari root repositori):

    python3 test/sbom/run_tests.py

Keluaran:
    test/sbom/out/<ID>/   berkas kerja tiap skenario (kunci privat tidak di-commit)
    test/sbom/results.json  hasil mentah
    test/sbom/results.md    tabel hasil
"""

import json
import os
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SBOM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SBOM_DIR.parent.parent
INPUT_DIR = SBOM_DIR / "input"
OUT_DIR = SBOM_DIR / "out"

PACKAGE = "contoh-app"
VERSION = "1.0.0"
ALGORITHMS = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
FIXED_ZIP_TIME = (2026, 11, 1, 0, 0, 0)


# ---------------------------------------------------------------------------

def cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "src.main", *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )

def must(*args: str) -> subprocess.CompletedProcess:
    proc = cli(*args)
    if proc.returncode != 0:
        raise RuntimeError(f"setup failed: {' '.join(args)}\n{proc.stdout}{proc.stderr}")
    return proc

def make_zip(path: Path, source: Path) -> Path:
    info = zipfile.ZipInfo(source.name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, source.read_bytes())
    return path


@dataclass
class Release:
    """Satu rilis sah: kunci, trust store, artefak, bundle rilis, SBOM, bundle SBOM."""
    dir: Path
    algorithm: str
    key: Path = field(init=False)
    pub: Path = field(init=False)
    trust: Path = field(init=False)
    artifact: Path = field(init=False)
    bundle: Path = field(init=False)
    sbom: Path = field(init=False)
    sbom_bundle: Path = field(init=False)

    def __post_init__(self) -> None:
        self.dir.mkdir(parents=True)
        prefix = self.dir / f"publisher-{self.algorithm}"
        self.key, self.pub = Path(f"{prefix}.key.pem"), Path(f"{prefix}.pub.pem")
        self.trust = self.dir / "trust.json"
        self.artifact = make_zip(self.dir / "contoh-app.zip", INPUT_DIR / "contoh-app.txt")
        self.bundle = self.dir / "contoh-app.bundle.json"
        self.sbom = self.dir / "contoh-app.cdx.json"
        self.sbom_bundle = self.dir / "contoh-app.cdx.bundle.json"

        must("keygen", "--algorithm", self.algorithm, "--out", str(prefix))
        must("trust", "add", "--key", str(self.pub), "--package", PACKAGE, "--store", str(self.trust))
        must("sign", "--file", str(self.artifact), "--package", PACKAGE, "--version", VERSION,
             "--key", str(self.key), "--out", str(self.bundle))
        must("sbom", "generate", "--file", str(self.artifact), "--package", PACKAGE,
             "--version", VERSION, "--out", str(self.sbom))
        must("sbom", "sign", "--sbom", str(self.sbom), "--file", str(self.artifact),
             "--package", PACKAGE, "--version", VERSION, "--key", str(self.key),
             "--out", str(self.sbom_bundle))

    def replace_artifact(self) -> None:
        self.artifact.unlink()
        make_zip(self.artifact, INPUT_DIR / "contoh-app-replaced.txt")

    def resign_release(self, key: Path | None = None) -> None:
        self.bundle.unlink()
        must("sign", "--file", str(self.artifact), "--package", PACKAGE, "--version", VERSION,
             "--key", str(key or self.key), "--out", str(self.bundle))


def sbom_verify(r: Release, sbom: Path | None = None, bundle: Path | None = None,
                trust: Path | None = None, package: str = PACKAGE) -> dict:
    proc = cli("sbom", "verify", "--sbom", str(sbom or r.sbom), "--bundle", str(bundle or r.sbom_bundle),
               "--trust-store", str(trust or r.trust), "--package", package, "--version", VERSION, "--json")
    out = json.loads(proc.stdout)
    return {"command": "sbom verify", "exit": proc.returncode, "status": out["status"],
            "stage": None, "valid": out["valid"], "message": out["message"]}

def sbom_check(r: Release, sbom_bundle: Path | None = None, sbom: Path | None = None) -> dict:
    proc = cli("sbom", "check", "--file", str(r.artifact), "--bundle", str(r.bundle),
               "--sbom", str(sbom or r.sbom), "--sbom-bundle", str(sbom_bundle or r.sbom_bundle),
               "--trust-store", str(r.trust), "--package", PACKAGE, "--version", VERSION, "--json")
    out = json.loads(proc.stdout)
    return {"command": "sbom check", "exit": proc.returncode, "status": out["status"],
            "stage": out["stage"], "valid": out["valid"], "message": out["message"]}

def plain(proc: subprocess.CompletedProcess, command: str, status: str | None = None) -> dict:
    return {"command": command, "exit": proc.returncode, "status": status, "stage": None,
            "valid": None, "message": (proc.stderr or proc.stdout).strip()}


# ---------------------------------------------------------------------------
# Skenario: (id, deskripsi, ekspektasi, fungsi)  — ekspektasi = list (exit, status, stage)

SCENARIOS = []

def scenario(sid: str, title: str, expected: list[tuple[int, str | None, str | None]]):
    def wrap(fn):
        SCENARIOS.append((sid, title, expected, fn))
        return fn
    return wrap


for _algo in ALGORITHMS:
    def _happy(d: Path, algo=_algo) -> list[dict]:
        r = Release(d, algo)
        return [sbom_verify(r), sbom_check(r)]
    scenario(f"S01-{_algo}",
             f"Rilis + SBOM sah ({_algo}): sbom verify dan sbom check berhasil",
             [(0, "OK", None), (0, "OK", None)])(_happy)


@scenario("S02", "Isi SBOM diubah setelah ditandatangani: satu karakter hash komponen diganti (ukuran tetap)",
          [(1, "ARTIFACT_MISMATCH", None), (1, "ARTIFACT_MISMATCH", "sbom")])
def s02(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    doc = json.loads(r.sbom.read_text())
    h = doc["components"][0]["hashes"][0]["content"]
    doc["components"][0]["hashes"][0]["content"] = ("0" if h[0] != "0" else "1") + h[1:]
    r.sbom.write_text(json.dumps(doc, indent=2) + "\n")
    return [sbom_verify(r), sbom_check(r)]

@scenario("S03", "Isi SBOM diubah: hash metadata.component diganti ke SHA-256 artefak pengganti",
          [(1, "ARTIFACT_MISMATCH", None), (1, "ARTIFACT_MISMATCH", "sbom")])
def s03(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    r.replace_artifact()
    r.resign_release()
    import hashlib
    doc = json.loads(r.sbom.read_text())
    doc["metadata"]["component"]["hashes"][0]["content"] = hashlib.sha256(r.artifact.read_bytes()).hexdigest()
    r.sbom.write_text(json.dumps(doc, indent=2) + "\n")
    return [sbom_verify(r), sbom_check(r)]

@scenario("S04", "Isi SBOM diubah: komponen baru ditambahkan (ukuran berubah)",
          [(1, "ARTIFACT_MISMATCH", None), (1, "ARTIFACT_MISMATCH", "sbom")])
def s04(d: Path) -> list[dict]:
    r = Release(d, "ecdsa-p256-sha256")
    doc = json.loads(r.sbom.read_text())
    doc["components"].append({"type": "library", "name": "backdoor", "version": "6.6.6"})
    r.sbom.write_text(json.dumps(doc, indent=2) + "\n")
    return [sbom_verify(r), sbom_check(r)]

@scenario("S05", "Artefak rilis diganti, bundle rilis lama dipakai",
          [(0, "OK", None), (1, "ARTIFACT_MISMATCH", "release")])
def s05(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    r.replace_artifact()
    return [sbom_verify(r), sbom_check(r)]

@scenario("S06", "Artefak rilis diganti dan rilis ditandatangani ulang dengan kunci sah, SBOM lama tetap dipakai",
          [(0, "OK", None), (1, "SBOM_MISMATCH", "binding")])
def s06(d: Path) -> list[dict]:
    r = Release(d, "rsa-pss-sha256")
    r.replace_artifact()
    r.resign_release()
    return [sbom_verify(r), sbom_check(r)]

@scenario("S07", "Artefak rilis diganti, SBOM baru dibuat dan ditandatangani kunci yang tidak tepercaya",
          [(1, "KEY_NOT_TRUSTED", None), (1, "KEY_NOT_TRUSTED", "sbom")])
def s07(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    r.replace_artifact()
    r.resign_release()
    must("keygen", "--algorithm", "ed25519", "--out", str(d / "attacker"))
    r.sbom.unlink(); r.sbom_bundle.unlink()
    must("sbom", "generate", "--file", str(r.artifact), "--package", PACKAGE, "--version", VERSION,
         "--out", str(r.sbom))
    must("sbom", "sign", "--sbom", str(r.sbom), "--file", str(r.artifact), "--package", PACKAGE,
         "--version", VERSION, "--key", str(d / "attacker.key.pem"), "--out", str(r.sbom_bundle))
    return [sbom_verify(r), sbom_check(r)]

@scenario("S08", "sbom sign menolak SBOM yang tidak memuat SHA-256 artefak (artefak diganti setelah SBOM dibuat)",
          [(2, None, None)])
def s08(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    r.replace_artifact()
    out = d / "rejected.cdx.bundle.json"
    proc = cli("sbom", "sign", "--sbom", str(r.sbom), "--file", str(r.artifact), "--package", PACKAGE,
               "--version", VERSION, "--key", str(r.key), "--out", str(out))
    res = plain(proc, "sbom sign")
    res["message"] += f" | bundle written: {out.exists()}"
    return [res]

@scenario("S09", "sbom sign menolak --version yang berbeda dari versi pada SBOM",
          [(2, None, None)])
def s09(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    proc = cli("sbom", "sign", "--sbom", str(r.sbom), "--file", str(r.artifact), "--package", PACKAGE,
               "--version", "1.0.1", "--key", str(r.key), "--out", str(d / "v101.bundle.json"))
    return [plain(proc, "sbom sign")]

@scenario("S10", "Berkas JSON non-SBOM ditandatangani dengan sign biasa lalu diverifikasi sebagai SBOM",
          [(1, "FORMAT_ERROR", None), (1, "FORMAT_ERROR", "sbom")])
def s10(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    fake = d / "fake.cdx.json"
    fake.write_text('{"bomFormat": "SPDX", "specVersion": "2.3"}\n')
    fake_bundle = d / "fake.cdx.bundle.json"
    must("sign", "--file", str(fake), "--package", PACKAGE, "--version", VERSION,
         "--key", str(r.key), "--out", str(fake_bundle))
    return [sbom_verify(r, sbom=fake, bundle=fake_bundle), sbom_check(r, sbom=fake, sbom_bundle=fake_bundle)]

@scenario("S11", "SBOM dengan field duplikat ditandatangani dengan sign biasa (strict JSON)",
          [(1, "FORMAT_ERROR", None)])
def s11(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    dup = d / "dup.cdx.json"
    text = r.sbom.read_text().replace('"bomFormat": "CycloneDX",', '"bomFormat": "CycloneDX", "bomFormat": "CycloneDX",', 1)
    dup.write_text(text)
    dup_bundle = d / "dup.cdx.bundle.json"
    must("sign", "--file", str(dup), "--package", PACKAGE, "--version", VERSION,
         "--key", str(r.key), "--out", str(dup_bundle))
    return [sbom_verify(r, sbom=dup, bundle=dup_bundle)]

@scenario("S12", "Bundle rilis tertukar dipakai sebagai --sbom-bundle",
          [(1, "METADATA_MISMATCH", "sbom")])
def s12(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    return [sbom_check(r, sbom_bundle=r.bundle)]

@scenario("S13", "Kunci SBOM hanya diizinkan untuk paket lain",
          [(1, "KEY_NOT_TRUSTED", None)])
def s13(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    other = d / "trust-other.json"
    must("trust", "add", "--key", str(r.pub), "--package", "aplikasi-lain", "--store", str(other))
    return [sbom_verify(r, trust=other)]

@scenario("S14", "Berkas SBOM tidak ada",
          [(2, "INPUT_ERROR", None), (2, "INPUT_ERROR", "sbom")])
def s14(d: Path) -> list[dict]:
    r = Release(d, "ed25519")
    missing = d / "missing.cdx.json"
    return [sbom_verify(r, sbom=missing), sbom_check(r, sbom=missing)]

@scenario("S15", "Kompatibilitas format: SBOM + bundle SBOM diverifikasi dengan verify biasa",
          [(0, "OK", None)])
def s15(d: Path) -> list[dict]:
    r = Release(d, "ecdsa-p256-sha256")
    proc = cli("verify", "--file", str(r.sbom), "--bundle", str(r.sbom_bundle), "--trust-store", str(r.trust),
               "--package", PACKAGE, "--version", VERSION, "--json")
    out = json.loads(proc.stdout)
    return [{"command": "verify", "exit": proc.returncode, "status": out["status"], "stage": None,
             "valid": out["valid"], "message": out["message"]}]


# ---------------------------------------------------------------------------

def main() -> int:
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir()

    results, failed = [], 0
    for sid, title, expected, fn in SCENARIOS:
        try:
            actual = fn(OUT_DIR / sid)
        except Exception as e:  # kegagalan setup dihitung sebagai FAIL
            actual = [{"command": "setup", "exit": None, "status": None, "stage": None,
                       "valid": None, "message": str(e)}]
        checks = []
        for i, exp in enumerate(expected):
            act = actual[i] if i < len(actual) else None
            ok = act is not None and (act["exit"], act["status"], act["stage"]) == exp
            checks.append({"expected": {"exit": exp[0], "status": exp[1], "stage": exp[2]},
                           "actual": act, "pass": ok})
        passed = len(actual) == len(expected) and all(c["pass"] for c in checks)
        failed += not passed
        for c in checks:  # jangan simpan path absolut mesin lokal pada hasil
            if c["actual"]:
                c["actual"]["message"] = c["actual"]["message"].replace(str(REPO_ROOT) + os.sep, "")
        results.append({"id": sid, "scenario": title, "pass": passed, "checks": checks})
        print(f"[{'PASS' if passed else 'FAIL'}] {sid}: {title}")
        for c in checks:
            a = c["actual"] or {}
            print(f"        {a.get('command')}: exit={a.get('exit')} status={a.get('status')} "
                  f"stage={a.get('stage')}  (expected {c['expected']})")

    (SBOM_DIR / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    write_markdown(results)
    print(f"\n{len(results) - failed}/{len(results)} scenarios passed")
    return 1 if failed else 0

def fmt(value) -> str:
    return "–" if value is None else f"`{value}`"

def write_markdown(results: list[dict]) -> None:
    lines = [
        "# Hasil Pengujian Signed SBOM", "",
        "Dihasilkan oleh `python3 test/sbom/run_tests.py`. Kolom *Diharapkan* dan *Aktual* berformat "
        "`exit / status / stage`.", "",
        "| ID | Skenario | Perintah | Diharapkan | Aktual | Hasil |",
        "| -- | -------- | -------- | ---------- | ------ | ----- |",
    ]
    for r in results:
        for i, c in enumerate(r["checks"]):
            e, a = c["expected"], c["actual"] or {}
            lines.append(
                f"| {r['id'] if i == 0 else ''} | {r['scenario'] if i == 0 else ''} | {a.get('command', '–')} "
                f"| {fmt(e['exit'])} / {fmt(e['status'])} / {fmt(e['stage'])} "
                f"| {fmt(a.get('exit'))} / {fmt(a.get('status'))} / {fmt(a.get('stage'))} "
                f"| {'PASS' if c['pass'] else 'FAIL'} |"
            )
    passed = sum(r["pass"] for r in results)
    lines += ["", f"**Total: {passed}/{len(results)} skenario lulus.**", ""]
    (SBOM_DIR / "results.md").write_text("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
