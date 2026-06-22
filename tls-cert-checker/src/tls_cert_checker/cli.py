"""Command-line interface for tls-cert-checker."""

from __future__ import annotations

import argparse
import math
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from . import __version__
from .checker import check_certificate
from .output import format_csv, format_json, format_markdown, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-cert-checker",
        usage="%(prog)s [DOMAIN ...] [options]",
        description=dedent(
            """\
            Lightweight TLS certificate inspection CLI.

            Checks certificate expiration, issuer, SANs, fingerprint, public key info,
            hostname match, TLS version and selected cipher.
            """
        ),
        epilog=dedent(
            """\
            Examples:
              tls-cert-checker example.com
              tls-cert-checker example.com --show-san
              tls-cert-checker example.com --format json
              tls-cert-checker example.com --timeout 3
              tls-cert-checker --file domains.txt
              tls-cert-checker --file domains.txt --format markdown --output report.md
              tls-cert-checker --file domains.txt --format csv --output report.csv
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    input_group = parser.add_argument_group("Input")
    input_group.add_argument("domains", nargs="*", metavar="DOMAIN", help="one or more domains to check")
    input_group.add_argument("--file", type=Path, metavar="PATH", help="read domains from a text file")
    input_group.add_argument("--port", type=int, default=443, metavar="PORT", help="TLS port (default: 443)")
    input_group.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="connection timeout in seconds (default: 5)",
    )
    status_group = parser.add_argument_group("Status")
    status_group.add_argument(
        "--warning-days",
        type=int,
        default=30,
        help="mark certificates as WARNING when they expire within this many days (default: 30)",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--format",
        choices=("text", "json", "markdown", "csv"),
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    output_group.add_argument("--json", action="store_true", dest="as_json", help="alias for --format json")
    output_group.add_argument("--show-san", action="store_true", help="include the full SAN list in text output")
    output_group.add_argument("--output", type=Path, metavar="PATH", help="write output to a file instead of stdout")

    other_group = parser.add_argument_group("Other")
    other_group.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    other_group.add_argument("-h", "--help", action="help", help="show this help message and exit")
    return parser


def _domains_from_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        try:
            domains.extend(_domains_from_file(args.file))
        except (OSError, UnicodeError) as exc:
            parser.error(f"could not read {args.file}: {exc}")

    if not domains:
        parser.error("provide at least one domain or use --file")
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535")
    if args.warning_days < 0:
        parser.error("--warning-days must be zero or greater")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite number greater than zero")

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
    if output_format == "text":
        formatted_output = format_text(results, show_san=args.show_san)
    else:
        formatted_output = formatters[output_format](results)

    if args.output:
        try:
            args.output.write_text(formatted_output + "\n", encoding="utf-8")
        except OSError as exc:
            parser.error(f"could not write {args.output}: {exc}")
    else:
        print(formatted_output)
    return 1 if any(result.status == "ERROR" for result in results) else 0
