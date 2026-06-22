import json
from unittest.mock import patch

from tls_cert_checker.checker import CertificateResult
from tls_cert_checker.cli import main


def test_cli_json_output(capsys):
    result = CertificateResult(domain="example.com", port=443, days_remaining=50, status="OK")

    with patch("tls_cert_checker.cli.check_certificate", return_value=result) as check:
        exit_code = main(["example.com", "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "OK"
    check.assert_called_once_with("example.com", 443)


def test_cli_reads_domains_file(tmp_path, capsys):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("one.test\n# comment\n\ntwo.test\n", encoding="utf-8")

    def fake_check(domain, port):
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
