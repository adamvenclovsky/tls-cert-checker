import csv
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
    )

    payload = json.loads(format_json([result]))

    assert payload["domain"] == "example.com"
    assert payload["days_remaining"] == 192
    assert payload["status"] == "OK"
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
        ),
        CertificateResult(domain="two.test", port=8443, status="ERROR", error="not found"),
    ]

    output = format_markdown(results)

    assert "| Domain | Port | Issuer | Valid To | Days Remaining | Status |" in output
    assert "| one.test | 443 | Example \\| CA | 2026-12-31T00:00:00Z | 50 | OK |" in output
    assert "| two.test | 8443 | - | - | - | ERROR |" in output


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
    )

    rows = list(csv.DictReader(format_csv([result]).splitlines()))

    assert rows[0]["domain"] == "example.com"
    assert rows[0]["issuer"] == "Example, Inc."
    assert rows[0]["error"] == ""


def test_single_text_result_is_a_labeled_block():
    result = CertificateResult(domain="example.com", port=443, status="OK")

    output = format_text([result])

    assert output.startswith("TLS Certificate Check\n=====================")
    assert "Domain         : example.com" in output


def test_multiple_text_results_are_an_aligned_table():
    results = [
        CertificateResult(domain="one.test", port=443, days_remaining=50, status="OK"),
        CertificateResult(domain="longer-domain.test", port=8443, status="ERROR", error="timed out"),
    ]

    output = format_text(results)

    assert output.splitlines()[0].startswith("Domain")
    assert "longer-domain.test" in output
    assert "timed out" in output
