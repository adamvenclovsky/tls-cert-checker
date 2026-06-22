from unittest.mock import patch

from tls_cert_checker.checker import calculate_status, check_certificate


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
