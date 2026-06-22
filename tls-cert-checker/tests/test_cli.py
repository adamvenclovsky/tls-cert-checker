import json
from unittest.mock import patch

import pytest

from tls_cert_checker.checker import CertificateResult
from tls_cert_checker.cli import main


def test_cli_json_output(capsys):
    result = CertificateResult(domain="example.com", port=443, days_remaining=50, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result) as check:
        exit_code = main(["example.com", "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "OK"
    check.assert_called_once_with("example.com", 443, timeout=5.0, warning_days=30)


def test_cli_reads_domains_file(tmp_path, capsys):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("one.test\n# comment\n\ntwo.test\n", encoding="utf-8")

    def fake_check(domain, port, *, timeout, warning_days):
        return CertificateResult(domain=domain, port=port, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", side_effect=fake_check) as check:
        exit_code = main(["--file", str(domains_file), "--port", "8443"])

    assert exit_code == 0
    assert check.call_count == 2
    assert "one.test" in capsys.readouterr().out


def test_cli_returns_error_exit_code(capsys):
    result = CertificateResult(domain="bad.invalid", port=443, status="ERROR", error="not found")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result):
        exit_code = main(["bad.invalid"])

    assert exit_code == 1
    assert "ERROR" in capsys.readouterr().out


def test_cli_passes_custom_warning_days(capsys):
    result = CertificateResult(domain="example.com", port=443, days_remaining=10, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result) as check:
        exit_code = main(["example.com", "--warning-days", "7"])

    assert exit_code == 0
    check.assert_called_once_with("example.com", 443, timeout=5.0, warning_days=7)
    capsys.readouterr()


def test_json_flag_remains_an_alias(capsys):
    result = CertificateResult(domain="example.com", port=443, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result):
        exit_code = main(["example.com", "--format", "text", "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["domain"] == "example.com"


def test_cli_writes_output_file(tmp_path, capsys):
    output_file = tmp_path / "report.md"
    result = CertificateResult(domain="example.com", port=443, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result):
        exit_code = main(["example.com", "--format", "markdown", "--output", str(output_file)])

    assert exit_code == 0
    assert "| example.com | 443 |" in output_file.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""


def test_help_includes_examples(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "Inspect TLS certificates" in output
    assert "tls-cert-checker example.com --warning-days 14" in output


def test_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "tls-cert-checker 0.2.0"


def test_cli_passes_timeout(capsys):
    result = CertificateResult(domain="example.com", port=443, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result) as check:
        exit_code = main(["example.com", "--timeout", "2.5"])

    assert exit_code == 0
    check.assert_called_once_with("example.com", 443, timeout=2.5, warning_days=30)
    capsys.readouterr()
