#!/usr/bin/env python3
import io
import json
import math
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any
import shutil

PERF_DIR = Path(__file__).resolve().parent
REPO_ROOT = PERF_DIR.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cryptography
from cryptography.hazmat.primitives import serialization

from src.crypto.keys import (
    compute_keyid,
    public_key_to_der,
    load_private_key_pem,
)
from src.crypto.profiles import SUPPORTED_PROFILES
from src.crypto.signature import sign
from src.crypto.signature import verify
from src.data.bundle import parse_bundle
from src.data.manifest import Artifact, Manifest, serialize_manifest
from src.fileio import hash_file
from src.keygen.keygen import keygen_command
from src.sign.sign import sign_command
from src.trust.commands import trust_add
from src.verify.verify import verify_command

WARMUP_RUNS = 5
MEASURE_RUNS = 30
KEYGEN_RUNS = 5


def nearest_rank_p95(data: list[float]) -> float:
    sorted_data = sorted(data)
    n = len(sorted_data)
    pos = math.ceil(0.95 * n)
    return sorted_data[pos - 1]


def compute_stats(samples_ns: list[int]) -> dict[str, float]:
    samples_ms = [ns / 1_000_000.0 for ns in samples_ns]
    return {
        "median_ms": round(statistics.median(samples_ms), 4),
        "p95_ms": round(nearest_rank_p95(samples_ms), 4),
        "min_ms": round(min(samples_ms), 4),
        "max_ms": round(max(samples_ms), 4),
        "mean_ms": round(statistics.mean(samples_ms), 4),
    }


def spec() -> dict[str, str]:
    cpu = platform.processor() or "Unknown"
    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text(errors="ignore").splitlines():
            if "model name" in line:
                cpu = line.split(":", 1)[1].strip()
                break

    ram = "Unknown"
    if Path("/proc/meminfo").exists():
        for line in Path("/proc/meminfo").read_text(errors="ignore").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                ram = f"{kb / (1024 * 1024):.2f} GiB"
                break

    return {
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "arch": platform.machine(),
        "cpu": cpu,
        "cpu_cores": str(os.cpu_count() or "Unknown"),
        "ram": ram,
        "python_version": platform.python_version(),
        "cryptography_version": cryptography.__version__,
    }


def private_key_to_der(private_key: Any) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def main() -> int:
    files_dir = PERF_DIR / "files"
    results_dir = PERF_DIR / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    artifacts = sorted([p for p in files_dir.iterdir() if p.is_file()], key=lambda p: (p.stat().st_size, p.name))

    print("=" * 70)

    specs = spec()

    # =========================================================================
    print("=" * 70)
    print("[TEST] Pembangkitan kunci")
    keygen_summary: dict[str, dict[str, Any]] = {}

    for algo in SUPPORTED_PROFILES:
        for _ in range(WARMUP_RUNS):
            keygen_command(
                algorithm=algo,
                out_prefix=f'{results_dir}/{algo}',
                force=True,
            )

        samples_ns: list[int] = []
        for i in range(KEYGEN_RUNS):
            t0 = time.perf_counter_ns()
            keygen_command(
                algorithm=algo,
                out_prefix=f'{results_dir}/{algo}',
                force=True,
            )
            t1 = time.perf_counter_ns()
            samples_ns.append(t1 - t0)

        stats = compute_stats(samples_ns)
        keygen_summary[algo] = {
            **stats
        }

    # =========================================================================
    print("=" * 70)
    print("[TEST] Hash artefak")
    hash_summary: dict[str, dict[str, Any]] = {}

    for art_path in artifacts:
        for _ in range(WARMUP_RUNS):
            hash_file(str(art_path))

        samples_ns = []
        size = 0
        sha256 = ""
        for i in range(MEASURE_RUNS):
            t0 = time.perf_counter_ns()
            size, sha256 = hash_file(str(art_path))
            t1 = time.perf_counter_ns()
            samples_ns.append(t1 - t0)

        stats = compute_stats(samples_ns)
        hash_summary[art_path.name] = {
            "size": size,
            "sha256": sha256,
            **stats,
        }

    # =========================================================================
    print("=" * 70)
    print("[TEST] Sign/Verify")
    crypto_summary: list[dict[str, Any]] = []

    keypairs: dict[str, tuple[Any, Any, str]] = {}
    for algo in SUPPORTED_PROFILES:
        priv_path = results_dir / f"{algo}.key.pem"
        priv_key = load_private_key_pem(priv_path.read_bytes())
        pub_key = priv_key.public_key()
        keyid = compute_keyid(pub_key)
        keypairs[algo] = (priv_key, pub_key, keyid)

    for art_path in artifacts:
        art_info = hash_summary[art_path.name]
        for algo in SUPPORTED_PROFILES:
            priv_key, pub_key, keyid = keypairs[algo]
            manifest = Manifest(
                package="bench-app",
                version="1.0.0",
                algorithm=algo,
                keyid=keyid,
                artifact=Artifact(
                    name=art_path.name,
                    size=art_info["size"],
                    sha256=art_info["sha256"],
                ),
            )
            manifest_bytes = serialize_manifest(manifest)

            sig = b""
            for _ in range(WARMUP_RUNS):
                sig = sign(priv_key, manifest_bytes)
                verify(pub_key, algo, manifest_bytes, sig)

            # Sign
            sign_samples_ns: list[int] = []
            for i in range(MEASURE_RUNS):
                t0 = time.perf_counter_ns()
                sig = sign(priv_key, manifest_bytes)
                t1 = time.perf_counter_ns()
                sign_samples_ns.append(t1 - t0)

            # Verify
            verify_samples_ns: list[int] = []
            for i in range(MEASURE_RUNS):
                t0 = time.perf_counter_ns()
                ok = verify(pub_key, algo, manifest_bytes, sig)
                t1 = time.perf_counter_ns()
                assert ok is True
                verify_samples_ns.append(t1 - t0)

            sign_stats = compute_stats(sign_samples_ns)
            verify_stats = compute_stats(verify_samples_ns)
            crypto_summary.append({
                "artifact": art_path.name,
                "algorithm": algo,
                "manifest_bytes": len(manifest_bytes),
                "signature_raw_bytes": len(sig),
                "sign_median_ms": sign_stats["median_ms"],
                "sign_p95_ms": sign_stats["p95_ms"],
                "verify_median_ms": verify_stats["median_ms"],
                "verify_p95_ms": verify_stats["p95_ms"],
            })

    # =========================================================================
    print("=" * 70)
    print("[TEST] End-to-End")
    e2e_summary: list[dict[str, Any]] = []

    (results_dir / "trust.json").unlink(missing_ok=True)
    for algo in SUPPORTED_PROFILES:
        trust_add(
            key_path=f'{results_dir}/{algo}.pub.pem',
            package="bench-app",
            store_path=f'{results_dir}/trust.json',
        )

    for art_path in artifacts:
        art_size = hash_summary[art_path.name]["size"]
        for algo in SUPPORTED_PROFILES:
            sink_out = io.StringIO()
            sink_err = io.StringIO()
            bundle_file = results_dir / f"bundle_{algo}_{art_path.name}.json"

            for _ in range(WARMUP_RUNS):
                bundle_file.unlink(missing_ok=True)

                rc_s = sign_command(
                    file_path=str(art_path),
                    package="bench-app",
                    version="1.0.0",
                    key_path=f'{results_dir}/{algo}.key.pem',
                    out_path=f'{results_dir}/bundle_{algo}_{art_path.name}.json',
                    out=sink_out,
                    err=sink_err,
                )
                assert rc_s == 0

                rc_v = verify_command(
                    file_path=str(art_path),
                    bundle_path=f'{results_dir}/bundle_{algo}_{art_path.name}.json',
                    trust_store_path=f'{results_dir}/trust.json',
                    package="bench-app",
                    version="1.0.0",
                    as_json=True,
                    out=sink_out,
                    err=sink_err,
                )
                assert rc_v == 0

            e2e_ns: list[int] = []
            for i in range(MEASURE_RUNS):
                bundle_file.unlink(missing_ok=True)
                t0 = time.perf_counter_ns()
                rc_s = sign_command(
                    file_path=str(art_path),
                    package="bench-app",
                    version="1.0.0",
                    key_path=f'{results_dir}/{algo}.key.pem',
                    out_path=f'{results_dir}/bundle_{algo}_{art_path.name}.json',
                    out=sink_out,
                    err=sink_err,
                )
                assert rc_s == 0

                rc_v = verify_command(
                    file_path=str(art_path),
                    bundle_path=f'{results_dir}/bundle_{algo}_{art_path.name}.json',
                    trust_store_path=f'{results_dir}/trust.json',
                    package="bench-app",
                    version="1.0.0",
                    as_json=True,
                    out=sink_out,
                    err=sink_err,
                )
                assert rc_v == 0
                t1 = time.perf_counter_ns()
                e2e_ns.append(t1 - t0)

            e2e_stats = compute_stats(e2e_ns)
            e2e_summary.append({
                "artifact": art_path.name,
                "artifact_size_bytes": art_size,
                "algorithm": algo,
                "e2e_median_ms": e2e_stats["median_ms"],
                "e2e_p95_ms": e2e_stats["p95_ms"],
            })

    # =========================================================================
    print("=" * 70)
    print("[TEST] Ukuran")
    size_summary: dict[str, dict[str, Any]] = {}

    for algo in SUPPORTED_PROFILES:
        priv_key, pub_key, _ = keypairs[algo]
        priv_der_bytes = len(private_key_to_der(priv_key))
        pub_der_bytes = len(public_key_to_der(pub_key))

        sample_bundle_path = results_dir / f"bundle_{algo}_{artifacts[0].name}.json"
        parsed_bundle = parse_bundle(sample_bundle_path.read_bytes())
        sig_raw_bytes = len(parsed_bundle.signature)

        bundle_sizes_by_artifact: dict[str, int] = {}
        for art_path in artifacts:
            b_path = results_dir / f"bundle_{algo}_{art_path.name}.json"
            bundle_sizes_by_artifact[art_path.name] = b_path.stat().st_size

        size_summary[algo] = {
            "private_key_der_bytes": priv_der_bytes,
            "public_key_der_bytes": pub_der_bytes,
            "signature_raw_bytes": sig_raw_bytes,
            "bundle_bytes_per_artifact": bundle_sizes_by_artifact,
        }

    # =========================================================================
    full_output = {
        "environment": specs,
        "keygen_summary": keygen_summary,
        "hash_summary": hash_summary,
        "crypto_summary": crypto_summary,
        "e2e_summary": e2e_summary,
        "size_summary": size_summary
    }

    json_path = PERF_DIR / "summary.json"
    json_path.write_text(json.dumps(full_output, indent=2) + "\n", encoding="utf-8")

    if results_dir.exists():
        shutil.rmtree(results_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())