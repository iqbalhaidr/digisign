# Utilitas untuk skrip skenario uji dan uji interoperabilitas.

import datetime
import json
import os
import platform
import re
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROFILES = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
PACKAGE = "contoh-app"
VERSION = "1.0.0"

_KEYID_RE = re.compile(r"keyid:\s+([0-9a-f]{64})")


class SetupError(Exception):
    "Langkah persiapan gagal, sehingga skenario tidak dapat dinilai"


def rel(path: str) -> str:
    return os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")


@dataclass
class Run:
    command: str
    code: int
    stdout: str
    stderr: str

    @property
    def json(self) -> dict | None:
        try:
            value = json.loads(self.stdout)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    @property
    def status(self) -> str | None:
        document = self.json
        return document.get("status") if document else None

    @property
    def keyid(self) -> str | None:
        match = _KEYID_RE.search(self.stdout)
        return match.group(1) if match else None


class Recorder:
    def __init__(self, log_path: str | None = None):
        self.log_path = log_path
        if log_path:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"# Log perintah ({rel(log_path)})\n\n")

    def cli(self, *args: str) -> Run:
        return self._run(["digisign", *args], [sys.executable, "-m", "src.main", *args])

    def tool(self, *argv: str) -> Run:
        return self._run(list(argv), list(argv))

    def note(self, text: str) -> None:
        with open(self.log_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"# {text}\n\n")

    def _run(self, shown: list[str], argv: list[str]) -> Run:
        proc = subprocess.run(
            argv, cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        shown[0] = os.path.basename(shown[0])
        run = Run(" ".join(shlex.quote(a) for a in shown), proc.returncode, proc.stdout, proc.stderr)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8", newline="\n") as f:
                f.write(f"$ {run.command}\nexit: {run.code}\n")
                if run.stdout:
                    f.write(f"[stdout]\n{run.stdout.rstrip()}\n")
                if run.stderr:
                    f.write(f"[stderr]\n{run.stderr.rstrip()}\n")
                f.write("\n")
        return run


def require(run: Run, what: str) -> Run:
    if run.code != 0:
        raise SetupError(f"{what} gagal (exit {run.code}): {run.stderr.strip()}")
    return run


@dataclass
class Case:
    id: str
    profile: str
    description: str
    expected: str
    actual: str
    passed: bool
    evidence: str
    command: str = "-"


@dataclass
class Report:
    title: str
    cases: list[Case] = field(default_factory=list)

    def add(self, sid, profile, description, expected, actual, passed, evidence, command="-") -> None:
        self.cases.append(Case(sid, profile, description, expected, actual, passed, evidence, command))

    def add_verify(self, sid, profile, description, run: Run, expected_status: str, evidence: str) -> None:
        expected_exit = 0 if expected_status == "OK" else 1
        self.add(
            sid, profile, description,
            f"{expected_status} (exit {expected_exit})",
            f"{run.status} (exit {run.code})",
            run.status == expected_status and run.code == expected_exit,
            evidence,
            run.command,
        )

    @property
    def passed(self) -> bool:
        return all(case.passed for case in self.cases)

    def write(self, results_dir: str) -> None:
        document = {"title": self.title, "environment": environment(), "cases": [asdict(c) for c in self.cases]}
        with open(os.path.join(results_dir, "results.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(document, f, indent=2)
            f.write("\n")


def environment() -> dict[str, str]:
    import cryptography

    env = {
        "Waktu (UTC)": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "OS": platform.platform(),
        "Python": platform.python_version(),
        "cryptography": cryptography.__version__,
    }
    try:
        out = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
        if out:
            env["OpenSSL CLI"] = out
    except OSError:
        pass
    return env
