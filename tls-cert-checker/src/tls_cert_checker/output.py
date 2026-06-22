"""Format certificate check results for terminal output."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence

from .checker import CertificateResult


def format_json(results: Sequence[CertificateResult]) -> str:
    """Format one result as an object and multiple results as an array."""
    payload = [result.to_dict() for result in results]
    return json.dumps(payload[0] if len(payload) == 1 else payload, indent=2)


def format_text(results: Sequence[CertificateResult]) -> str:
    """Format one result as a detail block and multiple results as a table."""
    if len(results) == 1:
        result = results[0]
        fields = [
            ("Domain", result.domain),
            ("Port", str(result.port)),
            ("Issuer", result.issuer or "-"),
            ("Subject", result.subject or "-"),
            ("Valid from", result.valid_from or "-"),
            ("Valid to", result.valid_to or "-"),
            ("Days remaining", str(result.days_remaining) if result.days_remaining is not None else "-"),
            ("Status", result.status),
        ]
        if result.error:
            fields.append(("Error", result.error))
        label_width = max(len(label) for label, _ in fields)
        title = "TLS Certificate Check"
        details = "\n".join(f"{label:<{label_width}} : {value}" for label, value in fields)
        return f"{title}\n{'=' * len(title)}\n{details}"

    headers = ["Domain", "Port", "Issuer", "Subject", "Valid From", "Valid To", "Days", "Status", "Error"]
    rows = [
        [
            result.domain,
            str(result.port),
            result.issuer or "-",
            result.subject or "-",
            result.valid_from or "-",
            result.valid_to or "-",
            str(result.days_remaining) if result.days_remaining is not None else "-",
            result.status,
            result.error or "-",
        ]
        for result in results
    ]
    widths = [max(len(header), *(len(row[index]) for row in rows)) for index, header in enumerate(headers)]

    def table_row(values: Sequence[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip()

    separator = "  ".join("-" * width for width in widths)
    return "\n".join([table_row(headers), separator, *(table_row(row) for row in rows)])


def _markdown_cell(value: str | int | None) -> str:
    text = "-" if value is None or value == "" else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def format_markdown(results: Sequence[CertificateResult]) -> str:
    """Format certificate results as a Markdown table."""
    headers = ["Domain", "Port", "Issuer", "Valid To", "Days Remaining", "Status"]
    rows = [
        [
            result.domain,
            result.port,
            result.issuer,
            result.valid_to,
            result.days_remaining,
            result.status,
        ]
        for result in results
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_markdown_cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def format_csv(results: Sequence[CertificateResult]) -> str:
    """Format certificate results as CSV with a stable column order."""
    fields = [
        "domain",
        "port",
        "issuer",
        "subject",
        "valid_from",
        "valid_to",
        "days_remaining",
        "status",
        "error",
    ]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for result in results:
        writer.writerow({field: getattr(result, field) for field in fields})
    return stream.getvalue().rstrip("\n")
