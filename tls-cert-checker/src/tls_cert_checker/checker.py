"""Retrieve and describe TLS certificates."""

from __future__ import annotations

import math
import socket
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from cryptography import x509


@dataclass(frozen=True)
class CertificateResult:
    domain: str
    port: int
    issuer: str | None = None
    subject: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    days_remaining: int | None = None
    status: str = "ERROR"
    error: str | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        """Return a JSON-serializable representation without empty error fields."""
        data = asdict(self)
        if self.error is None:
            data.pop("error")
        return data


def calculate_status(days_remaining: int) -> str:
    """Map a whole number of remaining days to a certificate status."""
    if days_remaining > 30:
        return "OK"
    if days_remaining >= 1:
        return "WARNING"
    return "EXPIRED"


def _remaining_days(expires_at: datetime, now: datetime) -> int:
    seconds = (expires_at - now).total_seconds()
    return math.ceil(seconds / 86_400) if seconds > 0 else math.floor(seconds / 86_400)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def check_certificate(
    domain: str,
    port: int = 443,
    *,
    timeout: float = 10.0,
    now: datetime | None = None,
) -> CertificateResult:
    """Connect to a host and return information from its leaf certificate."""
    domain = domain.strip()
    try:
        if not domain:
            raise ValueError("domain is empty")
        if not 1 <= port <= 65_535:
            raise ValueError("port must be between 1 and 65535")

        hostname = domain.encode("idna").decode("ascii")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                der_certificate = tls_socket.getpeercert(binary_form=True)

        if not der_certificate:
            raise ssl.SSLError("server did not provide a certificate")

        certificate = x509.load_der_x509_certificate(der_certificate)
        valid_from = _utc(certificate.not_valid_before_utc)
        valid_to = _utc(certificate.not_valid_after_utc)
        current_time = _utc(now or datetime.now(timezone.utc))
        days_remaining = _remaining_days(valid_to, current_time)

        return CertificateResult(
            domain=domain,
            port=port,
            issuer=certificate.issuer.rfc4514_string(),
            subject=certificate.subject.rfc4514_string(),
            valid_from=_format_datetime(valid_from),
            valid_to=_format_datetime(valid_to),
            days_remaining=days_remaining,
            status=calculate_status(days_remaining),
        )
    except (OSError, ValueError, ssl.SSLError, x509.InvalidVersion) as exc:
        return CertificateResult(
            domain=domain,
            port=port,
            status="ERROR",
            error=str(exc) or exc.__class__.__name__,
        )
