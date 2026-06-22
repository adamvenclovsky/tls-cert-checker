from tls_cert_checker.checker import calculate_status


def test_calculate_status_boundaries():
    assert calculate_status(31) == "OK"
    assert calculate_status(30) == "WARNING"
    assert calculate_status(1) == "WARNING"
    assert calculate_status(0) == "EXPIRED"
    assert calculate_status(-10) == "EXPIRED"
