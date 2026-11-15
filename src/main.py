"""Entry point CLI ``digisign`` (``python -m src.main``).

Mendefinisikan parser argumen dan meneruskan setiap subcommand ke fungsi
``*_command`` yang sesuai. Kesalahan argumen selalu menghasilkan exit code ``2``.
"""

import argparse
import sys
from typing import List, NoReturn

from src.keygen.keygen import keygen_command
from src.sign.sign import sign_command
from src.trust.commands import trust_add, trust_list, trust_remove
from src.verify.result import INPUT_ERROR, VerifyResult
from src.verify.verify import verify_command

VERSION = "1.0.0"

EXIT_OK = 0
EXIT_VERIFY_REJECTED = 1
EXIT_USAGE_OR_IO_ERROR = 2

# =====================================================================

def handle_keygen(args: argparse.Namespace) -> int:
    return keygen_command(
        algorithm=args.algorithm,
        out_prefix=args.out,
        force=args.force,
    )

def handle_sign(args: argparse.Namespace) -> int:
    return sign_command(
        file_path=args.file,
        package=args.package,
        version=args.version,
        key_path=args.key,
        out_path=args.out,
    )

def handle_verify(args: argparse.Namespace) -> int:
    return verify_command(
        file_path=args.file,
        bundle_path=args.bundle,
        trust_store_path=args.trust_store,
        package=args.package,
        version=args.version,
        as_json=args.json,
    )

def handle_trust_add(args: argparse.Namespace) -> int:
    return trust_add(
        key_path=args.key,
        package=args.package,
        store_path=args.store,
    )

def handle_trust_list(args: argparse.Namespace) -> int:
    return trust_list(
        store_path=args.store,
    )

def handle_trust_remove(args: argparse.Namespace) -> int:
    return trust_remove(
        keyid=args.keyid,
        store_path=args.store,
    )

# =====================================================================

class StrictArgumentParser(argparse.ArgumentParser):
    """``ArgumentParser`` yang keluar dengan exit code ``2`` saat argumen tidak valid."""
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(EXIT_USAGE_OR_IO_ERROR)

def build_parser() -> argparse.ArgumentParser:
    """Bangun parser argumen untuk seluruh subcommand.

    Returns:
        argparse.ArgumentParser: Parser dengan subcommand ``keygen``, ``sign``,
        ``verify``, dan ``trust {add,list,remove}``.
    """
    parser = StrictArgumentParser(
        prog="digisign",
        description="Software Release Sign & Verify",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"digisign {VERSION}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate cryptographic key pair")
    p_keygen.add_argument("--algorithm", required=True, help="Algorithm profile (rsa-pss-sha256, ecdsa-p256-sha256, ed25519)")
    p_keygen.add_argument("--out", required=True, help="Output key path prefix")
    p_keygen.add_argument("--force", action="store_true", help="Overwrite existing key files")
    p_keygen.set_defaults(func=handle_keygen)

    # 2. sign
    p_sign = subparsers.add_parser("sign", help="Sign release artifact and create bundle")
    p_sign.add_argument("--file", required=True, help="Path to artifact file")
    p_sign.add_argument("--package", required=True, help="Release package name")
    p_sign.add_argument("--version", required=True, help="Release version")
    p_sign.add_argument("--key", required=True, help="Path to private key")
    p_sign.add_argument("--out", required=True, help="Output bundle path")
    p_sign.set_defaults(func=handle_sign)

    # 3. verify
    p_verify = subparsers.add_parser("verify", help="Verify release artifact against bundle and trust store")
    p_verify.add_argument("--file", required=True, help="Path to artifact file")
    p_verify.add_argument("--bundle", required=True, help="Path to bundle")
    p_verify.add_argument("--trust-store", required=True, dest="trust_store", help="Path to trust store")
    p_verify.add_argument("--package", required=True, help="Expected package name")
    p_verify.add_argument("--version", required=True, help="Expected release version")
    p_verify.add_argument("--json", action="store_true", help="Output verification resul")
    p_verify.set_defaults(func=handle_verify)

    # 4. trust
    p_trust = subparsers.add_parser("trust", help="Manage trust store")
    trust_sub = p_trust.add_subparsers(dest="trust_command", required=True)

    p_add = trust_sub.add_parser("add", help="Add package permission for a public key")
    p_add.add_argument("--key", required=True, help="Path to public key")
    p_add.add_argument("--package", required=True, help="Allowed package name")
    p_add.add_argument("--store", required=True, help="Path to trust store")
    p_add.set_defaults(func=handle_trust_add)

    p_list = trust_sub.add_parser("list", help="List entries in trust store")
    p_list.add_argument("--store", required=True, help="Path to trust store")
    p_list.set_defaults(func=handle_trust_list)

    p_remove = trust_sub.add_parser("remove", help="Remove key entry")
    p_remove.add_argument("--keyid", required=True, help="Public key keyid")
    p_remove.add_argument("--store", required=True, help="Path to trust store")
    p_remove.set_defaults(func=handle_trust_remove)

    return parser

# =====================================================================

def main(argv: List[str] | None = None) -> int:
    """Jalankan CLI.

    Untuk ``verify --json``, kesalahan argumen atau exception tak terduga
    tetap menghasilkan satu baris JSON berstatus ``INPUT_ERROR`` di stdout.

    Args:
        argv (list[str] | None): Argumen tanpa nama program. Default ``sys.argv[1:]``.

    Returns:
        int: Exit code proses (``0``, ``1``, atau ``2``).

    Example:
        >>> main(["trust", "list", "--store", "trust.json"])
        0
    """
    if argv is None:
        argv = sys.argv[1:]

    is_verify_json = ("verify" in argv) and ("--json" in argv)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return args.func(args)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else EXIT_USAGE_OR_IO_ERROR
        if code != EXIT_OK and is_verify_json:
            res = VerifyResult(status=INPUT_ERROR, message="invalid or missing CLI arguments")
            sys.stdout.write(res.to_json())
        return code
    except Exception as exc:
        if is_verify_json:
            res = VerifyResult(status=INPUT_ERROR, message=str(exc))
            sys.stdout.write(res.to_json())
        sys.stderr.write(f"Unexpected error: {exc}\n")
        return EXIT_USAGE_OR_IO_ERROR
    

if __name__ == "__main__":
    sys.exit(main())