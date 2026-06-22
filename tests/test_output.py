import csv
import io
import json

from tls_cert_checker.checker import CertificateResult
from tls_cert_checker.output import format_csv, format_json, format_markdown, format_text


def test_single_result_json_format():
    result = CertificateResult(
        domain="example.com",
        port=443,
        issuer="CN=Example CA",
        subject="CN=example.com",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2026-12-31T00:00:00Z",
        days_remaining=192,
        status="OK",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        public_key_algorithm="RSA",
        public_key_size=2048,
        subject_alt_names=["example.com", "www.example.com"],
        san_count=2,
        hostname_match=True,
    )

    payload = json.loads(format_json([result]))

    assert payload["domain"] == "example.com"
    assert payload["days_remaining"] == 192
    assert payload["status"] == "OK"
    assert payload["tls_version"] == "TLSv1.3"
    assert payload["subject_alt_names"] == ["example.com", "www.example.com"]
    assert {
        "serial_number",
        "sha256_fingerprint",
        "signature_algorithm",
        "public_key_algorithm",
        "public_key_size",
        "san_count",
        "is_wildcard",
        "hostname_match",
        "cipher",
    } <= payload.keys()
    assert "error" not in payload


def test_multiple_results_are_a_json_array():
    results = [
        CertificateResult(domain="one.test", port=443, status="ERROR", error="not found"),
        CertificateResult(domain="two.test", port=443, status="OK"),
    ]

    assert len(json.loads(format_json(results))) == 2


def test_markdown_format():
    results = [
        CertificateResult(
            domain="one.test",
            port=443,
            issuer="Example | CA",
            valid_to="2026-12-31T00:00:00Z",
            days_remaining=50,
            status="OK",
            tls_version="TLSv1.3",
            public_key_algorithm="RSA",
            public_key_size=2048,
            san_count=2,
            hostname_match=True,
            subject_alt_names=["one.test", "*.one.test"],
        ),
        CertificateResult(domain="two.test", port=8443, status="ERROR", error="not found"),
    ]

    output = format_markdown(results)

    assert "| Domain | Port | Valid To | Days Remaining | Status | TLS Version | Public Key | SAN Count | Hostname Match |" in output
    assert "| one.test | 443 | 2026-12-31T00:00:00Z | 50 | OK | TLSv1.3 | RSA 2048-bit | 2 | Yes |" in output
    assert "Issuer" not in output
    assert "Example | CA" not in output
    assert "*.one.test" not in output


def test_csv_format():
    result = CertificateResult(
        domain="example.com",
        port=443,
        issuer="Example, Inc.",
        subject="CN=example.com",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2026-12-31T00:00:00Z",
        days_remaining=192,
        status="OK",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        public_key_algorithm="RSA",
        public_key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        sha256_fingerprint="AA:BB",
        serial_number="1234",
        subject_alt_names=["example.com", "www.example.com"],
        san_count=2,
        hostname_match=True,
    )

    reader = csv.DictReader(format_csv([result]).splitlines())
    rows = list(reader)

    assert rows[0]["domain"] == "example.com"
    assert rows[0]["issuer"] == "Example, Inc."
    assert rows[0]["tls_version"] == "TLSv1.3"
    assert rows[0]["subject_alt_names"] == "example.com,www.example.com"
    assert rows[0]["error"] == ""
    assert reader.fieldnames == [
        "domain", "port", "issuer", "subject", "valid_from", "valid_to", "days_remaining", "status",
        "tls_version", "cipher", "public_key_algorithm", "public_key_size", "signature_algorithm",
        "sha256_fingerprint", "serial_number", "san_count", "is_wildcard", "hostname_match",
        "subject_alt_names", "error",
    ]


def test_csv_round_trips_quotes_commas_and_newlines():
    issuer = 'Example "CA", Inc.\nSecond line'
    output = format_csv([CertificateResult(domain="example.com", port=443, issuer=issuer)])

    row = next(csv.DictReader(io.StringIO(output)))

    assert row["issuer"] == issuer


def test_markdown_escapes_backslashes_pipes_and_line_breaks():
    result = CertificateResult(
        domain="example.com",
        port=443,
        valid_to="line one\r\nline two",
        status="OK",
        tls_version=r"TLS\|test",
    )

    output = format_markdown([result])

    assert "line one  line two" in output
    assert r"TLS\\\|test" in output


def test_single_text_result_is_a_labeled_block():
    result = CertificateResult(domain="example.com", port=443, status="OK")

    output = format_text([result])

    assert output.startswith("TLS Certificate Check\n=====================")
    assert "Domain" in output
    assert ": example.com" in output


def test_multiple_text_results_are_an_aligned_table():
    results = [
        CertificateResult(domain="one.test", port=443, days_remaining=50, status="OK"),
        CertificateResult(domain="longer-domain.test", port=8443, status="ERROR", error="timed out"),
    ]

    output = format_text(results)

    assert output.splitlines()[0].startswith("Domain")
    assert "longer-domain.test" in output
    assert "TLS Version" in output
    assert "Issuer" not in output
    assert "timed out" not in output


def test_show_san_controls_single_text_output():
    result = CertificateResult(
        domain="example.com",
        port=443,
        status="OK",
        subject_alt_names=["example.com", "www.example.com"],
        san_count=2,
    )

    assert "Subject Alternative Names" not in format_text([result])
    assert "Subject Alternative Names" in format_text([result], show_san=True)
    assert "example.com, www.example.com" in format_text([result], show_san=True)
