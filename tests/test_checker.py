import re
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from tls_cert_checker.checker import calculate_status, check_certificate, parse_certificate_details


def _certificate(key, subject_alt_names=None, common_name="example.com"):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
    )
    if subject_alt_names is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in subject_alt_names]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def _check_with_certificate(certificate, domain="example.com"):
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate.public_bytes(serialization.Encoding.DER)
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    context = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value = tls_socket

    with (
        patch("tls_cert_checker.checker.ssl.create_default_context", return_value=context),
        patch("tls_cert_checker.checker.socket.create_connection") as create_connection,
    ):
        result = check_certificate(domain)
    return result, create_connection


def test_calculate_status_boundaries():
    assert calculate_status(31) == "OK"
    assert calculate_status(30) == "WARNING"
    assert calculate_status(1) == "WARNING"
    assert calculate_status(0) == "EXPIRED"
    assert calculate_status(-10) == "EXPIRED"


def test_calculate_status_uses_custom_warning_days():
    assert calculate_status(15, warning_days=14) == "OK"
    assert calculate_status(14, warning_days=14) == "WARNING"


def test_connection_timeout_returns_error():
    with patch("tls_cert_checker.checker.socket.create_connection", side_effect=TimeoutError("timed out")):
        result = check_certificate("example.com", timeout=1.5)

    assert result.status == "ERROR"
    assert result.error == "timed out"


def test_nonprintable_domain_is_rejected_and_escaped():
    with patch("tls_cert_checker.checker.socket.create_connection") as create_connection:
        result = check_certificate("unsafe\x1b[31m.example")

    assert result.status == "ERROR"
    assert result.domain == r"unsafe\x1B[31m.example"
    assert result.error == "domain contains non-printable characters"
    create_connection.assert_not_called()


def test_certificate_details_include_fingerprint_key_and_sans():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = _certificate(key, ["example.com", "*.example.org"])

    details = parse_certificate_details(certificate, "api.example.org")

    assert re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", details["sha256_fingerprint"])
    assert details["public_key_algorithm"] == "RSA"
    assert details["public_key_size"] == 2048
    assert details["subject_alt_names"] == ["example.com", "*.example.org"]
    assert details["san_count"] == 2
    assert details["is_wildcard"] is True
    assert details["hostname_match"] is True


def test_hostname_mismatch_and_ec_public_key():
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate(key, ["example.com"])

    details = parse_certificate_details(certificate, "other.test")

    assert details["public_key_algorithm"] == "EC"
    assert details["public_key_size"] == 256
    assert details["hostname_match"] is False
    assert details["is_wildcard"] is False


def test_hostname_matching_handles_case_trailing_dot_and_wildcard_depth():
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate(key, ["EXAMPLE.COM", "*.example.org"])

    assert parse_certificate_details(certificate, "example.com.")["hostname_match"] is True
    assert parse_certificate_details(certificate, "api.example.org")["hostname_match"] is True
    assert parse_certificate_details(certificate, "deep.api.example.org")["hostname_match"] is False


def test_missing_san_does_not_match_hostname():
    key = ec.generate_private_key(ec.SECP256R1())
    details = parse_certificate_details(_certificate(key), "example.com")

    assert details["subject_alt_names"] == []
    assert details["san_count"] == 0
    assert details["hostname_match"] is False


def test_tls_version_and_cipher_are_included_in_result():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = _certificate(key, ["example.com"])
    result, create_connection = _check_with_certificate(certificate)

    assert create_connection.call_args.kwargs["timeout"] == 5.0
    assert result.tls_version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.hostname_match is True


def test_malformed_certificate_returns_error():
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = b"not a DER certificate"
    tls_socket.version.return_value = None
    tls_socket.cipher.return_value = None
    context = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value = tls_socket

    with (
        patch("tls_cert_checker.checker.ssl.create_default_context", return_value=context),
        patch("tls_cert_checker.checker.socket.create_connection"),
    ):
        result = check_certificate("example.com")

    assert result.status == "ERROR"
    assert result.error


def test_certificate_control_characters_are_escaped():
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate(key, ["example.com"], common_name="unsafe\x1b[31m")

    result, _ = _check_with_certificate(certificate)

    assert "\x1b" not in result.subject
    assert r"\x1B" in result.subject
