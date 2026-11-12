import argparse
import sys
from typing import List, NoReturn

VERSION = "0.0.0"

EXIT_OK = 0
EXIT_VERIFY_REJECTED = 1
EXIT_USAGE_OR_IO_ERROR = 2

# =====================================================================

def handle_keygen(args: argparse.Namespace) -> int:
    # TODO
    return EXIT_OK

def handle_sign(args: argparse.Namespace) -> int:
    # TODO
    return EXIT_OK

def handle_verify(args: argparse.Namespace) -> int:
    # TODO
    return EXIT_OK

def handle_trust_add(args: argparse.Namespace) -> int:
    # TODO
    return EXIT_OK

def handle_trust_list(args: argparse.Namespace) -> int:
    # TODO
    return EXIT_OK

def handle_trust_remove(args: argparse.Namespace) -> int:
    # TODO
    return EXIT_OK

# =====================================================================

class StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(EXIT_USAGE_OR_IO_ERROR)

def build_parser() -> argparse.ArgumentParser:
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
    p_keygen = subparsers.add_parser("keygen", help="TODO")
    p_keygen.add_argument("--algorithm", required=True, help="TODO")
    p_keygen.add_argument("--out", required=True, help="TODO")
    p_keygen.set_defaults(func=handle_keygen)

    # 2. sign
    p_sign = subparsers.add_parser("sign", help="TODO")
    p_sign.add_argument("--file", required=True, help="TODO")
    p_sign.add_argument("--package", required=True, help="TODO")
    p_sign.add_argument("--version", required=True, help="TODO")
    p_sign.add_argument("--key", required=True, help="TODO")
    p_sign.add_argument("--out", required=True, help="TODO")
    p_sign.set_defaults(func=handle_sign)

    # 3. verify
    p_verify = subparsers.add_parser("verify", help="TODO")
    p_verify.add_argument("--file", required=True, help="TODO")
    p_verify.add_argument("--bundle", required=True, help="TODO")
    p_verify.add_argument("--trust-store", required=True, dest="trust_store", help="TODO")
    p_verify.add_argument("--package", required=True, help="TODO")
    p_verify.add_argument("--version", required=True, help="TODO")
    p_verify.add_argument("--json", action="store_true", help="TODO")
    p_verify.set_defaults(func=handle_verify)

    # 4. trust
    p_trust = subparsers.add_parser("trust", help="TODO")
    trust_sub = p_trust.add_subparsers(dest="trust_command", required=True)

    p_add = trust_sub.add_parser("add", help="TODO")
    p_add.add_argument("--key", required=True, help="TODO")
    p_add.add_argument("--package", required=True, help="TODO")
    p_add.add_argument("--store", required=True, help="TODO")
    p_add.set_defaults(func=handle_trust_add)

    p_list = trust_sub.add_parser("list", help="TODO")
    p_list.add_argument("--store", required=True, help="TODO")
    p_list.set_defaults(func=handle_trust_list)

    p_remove = trust_sub.add_parser("remove", help="TODO")
    p_remove.add_argument("--keyid", required=True, help="TODO")
    p_remove.add_argument("--store", required=True, help="TODO")
    p_remove.set_defaults(func=handle_trust_remove)

    return parser

# =====================================================================

def main(argv: List[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return args.func(args)
    except Exception as exc:
        sys.stderr.write(f"Unexpected error: {exc}\n")
        return EXIT_USAGE_OR_IO_ERROR
    

if __name__ == "__main__":
    sys.exit(main())