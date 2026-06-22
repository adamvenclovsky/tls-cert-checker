"""Retrieve and describe TLS certificates."""

from __future__ import annotations

import ipaddress
import math
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


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
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str = "UNKNOWN"
    public_key_size: int | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    san_count: int = 0
    is_wildcard: bool = False
    hostname_match: bool | None = None
    tls_version: str | None = None
    cipher: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation without empty error fields."""
        data = asdict(self)
        if self.error is None:
            data.pop("error")
        return data


def calculate_status(days_remaining: int, warning_days: int = 30) -> str:
    """Map a whole number of remaining days to a certificate status."""
    if days_remaining > warning_days:
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


def _escape_nonprintable(value: str) -> str:
    """Render control characters safely instead of sending them to a terminal."""
    escaped: list[str] = []
    for character in value:
        if character.isprintable():
            escaped.append(character)
        elif ord(character) <= 0xFF:
            escaped.append(f"\\x{ord(character):02X}")
        else:
            escaped.append(f"\\u{ord(character):04X}")
    return "".join(escaped)


def _public_key_details(public_key: Any) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        algorithm = "EC"
    elif isinstance(public_key, dsa.DSAPublicKey):
        algorithm = "DSA"
    else:
        algorithm = "UNKNOWN"
    return algorithm, getattr(public_key, "key_size", None)


def _hostname_matches(domain: str, subject_alt_names: list[str]) -> bool:
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    hostname = domain.rstrip(".").lower()
    for certificate_name in subject_alt_names:
        pattern = certificate_name.rstrip(".").lower()
        if "*" not in pattern and hostname == pattern:
            return True
        if pattern.startswith("*.") and pattern.count("*") == 1:
            if hostname.endswith(pattern[1:]) and hostname.count(".") == pattern.count("."):
                return True
    return False


def parse_certificate_details(certificate: x509.Certificate, domain: str) -> dict[str, Any]:
    """Extract focused certificate metadata used by the CLI outputs."""
    try:
        raw_subject_alt_names = list(
            certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            .value.get_values_for_type(x509.DNSName)
        )
    except x509.ExtensionNotFound:
        raw_subject_alt_names = []

    public_key_algorithm, public_key_size = _public_key_details(certificate.public_key())
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
    signature_oid = certificate.signature_algorithm_oid
    subject_alt_names = [_escape_nonprintable(name) for name in raw_subject_alt_names]

    return {
        "serial_number": format(certificate.serial_number, "X"),
        "sha256_fingerprint": ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2)),
        "signature_algorithm": getattr(signature_oid, "_name", None) or signature_oid.dotted_string,
        "public_key_algorithm": public_key_algorithm,
        "public_key_size": public_key_size,
        "subject_alt_names": subject_alt_names,
        "san_count": len(subject_alt_names),
        "is_wildcard": any(name.startswith("*.") for name in raw_subject_alt_names),
        "hostname_match": _hostname_matches(domain, raw_subject_alt_names),
    }


def check_certificate(
    domain: str,
    port: int = 443,
    *,
    timeout: float = 5.0,
    now: datetime | None = None,
    warning_days: int = 30,
) -> CertificateResult:
    """Connect to a host and return information from its leaf certificate."""
    domain = domain.strip()
    display_domain = _escape_nonprintable(domain)
    try:
        if not domain:
            raise ValueError("domain is empty")
        if display_domain != domain:
            raise ValueError("domain contains non-printable characters")
        if not 1 <= port <= 65_535:
            raise ValueError("port must be between 1 and 65535")

        hostname = domain.encode("idna").decode("ascii")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                der_certificate = tls_socket.getpeercert(binary_form=True)
                tls_version = tls_socket.version()
                cipher_info = tls_socket.cipher()
                cipher = cipher_info[0] if cipher_info else None

        if not der_certificate:
            raise ssl.SSLError("server did not provide a certificate")

        certificate = x509.load_der_x509_certificate(der_certificate)
        valid_from = _utc(certificate.not_valid_before_utc)
        valid_to = _utc(certificate.not_valid_after_utc)
        current_time = _utc(now or datetime.now(timezone.utc))
        days_remaining = _remaining_days(valid_to, current_time)
        details = parse_certificate_details(certificate, hostname)

        return CertificateResult(
            domain=display_domain,
            port=port,
            issuer=_escape_nonprintable(certificate.issuer.rfc4514_string()),
            subject=_escape_nonprintable(certificate.subject.rfc4514_string()),
            valid_from=_format_datetime(valid_from),
            valid_to=_format_datetime(valid_to),
            days_remaining=days_remaining,
            status=calculate_status(days_remaining, warning_days),
            tls_version=tls_version,
            cipher=cipher,
            **details,
        )
    except (OSError, ValueError, ssl.SSLError, x509.InvalidVersion, UnsupportedAlgorithm) as exc:
        return CertificateResult(
            domain=display_domain,
            port=port,
            status="ERROR",
            error=str(exc) or exc.__class__.__name__,
        )
