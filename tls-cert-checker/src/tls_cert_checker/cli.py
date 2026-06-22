"""Command-line interface for tls-cert-checker."""

from __future__ import annotations

import argparse
from pathlib import Path
from collections.abc import Sequence

from .checker import check_certificate
from .output import format_json, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-cert-checker",
        description="Check TLS certificate expiration, issuer, and validity.",
    )
    parser.add_argument("domains", nargs="*", help="one or more domains to check")
    parser.add_argument("--file", type=Path, help="text file containing one domain per line")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default: 443)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="output JSON")
    return parser


def _domains_from_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        try:
            domains.extend(_domains_from_file(args.file))
        except OSError as exc:
            parser.error(f"could not read {args.file}: {exc}")

    if not domains:
        parser.error("provide at least one domain or use --file")
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535")

    results = [check_certificate(domain, args.port) for domain in domains]
    print(format_json(results) if args.as_json else format_text(results))
    return 1 if any(result.status == "ERROR" for result in results) else 0
