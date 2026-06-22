"""Command-line interface for tls-cert-checker."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from . import __version__
from .checker import check_certificate
from .output import format_csv, format_json, format_markdown, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-cert-checker",
        description=(
            "Inspect TLS certificates and report their issuer, validity period, "
            "expiration status, and days remaining."
        ),
        epilog=dedent(
            """\
            examples:
              tls-cert-checker example.com
              tls-cert-checker example.com --json
              tls-cert-checker example.com --warning-days 14
              tls-cert-checker --file domains.txt --format markdown --output report.md
              tls-cert-checker --file domains.txt --format csv --output report.csv
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN", help="one or more domains to check")
    parser.add_argument("--file", type=Path, metavar="PATH", help="read domains from a text file")
    parser.add_argument("--port", type=int, default=443, metavar="PORT", help="TLS port (default: 443)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--warning-days",
        type=int,
        default=30,
        help="days remaining before a certificate receives WARNING (default: 30)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "csv"),
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    parser.add_argument("--json", action="store_true", dest="as_json", help="alias for --format json")
    parser.add_argument("--output", type=Path, metavar="PATH", help="write output to a file instead of stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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
    if args.warning_days < 0:
        parser.error("--warning-days must be zero or greater")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    results = [
        check_certificate(
            domain,
            args.port,
            timeout=args.timeout,
            warning_days=args.warning_days,
        )
        for domain in domains
    ]
    output_format = "json" if args.as_json else args.output_format
    formatters = {
        "text": format_text,
        "json": format_json,
        "markdown": format_markdown,
        "csv": format_csv,
    }
    formatted_output = formatters[output_format](results)

    if args.output:
        try:
            args.output.write_text(formatted_output + "\n", encoding="utf-8")
        except OSError as exc:
            parser.error(f"could not write {args.output}: {exc}")
    else:
        print(formatted_output)
    return 1 if any(result.status == "ERROR" for result in results) else 0
