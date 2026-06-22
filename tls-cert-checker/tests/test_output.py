import json

from tls_cert_checker.checker import CertificateResult
from tls_cert_checker.output import format_json


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
