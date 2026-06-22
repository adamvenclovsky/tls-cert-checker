"""Format certificate check results for terminal output."""

from __future__ import annotations

import json
from collections.abc import Sequence

from .checker import CertificateResult


def format_json(results: Sequence[CertificateResult]) -> str:
    """Format one result as an object and multiple results as an array."""
    payload = [result.to_dict() for result in results]
    return json.dumps(payload[0] if len(payload) == 1 else payload, indent=2)


def format_text(results: Sequence[CertificateResult]) -> str:
    blocks: list[str] = []
    for result in results:
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
        width = max(len(label) for label, _ in fields)
        blocks.append("\n".join(f"{label:<{width}} : {value}" for label, value in fields))
    return "\n\n".join(blocks)
