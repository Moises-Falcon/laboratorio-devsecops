from src.telemetry import get_telemetry, is_operation_allowed


def test_read_is_allowed():
    assert is_operation_allowed("read") is True


def test_write_is_denied():
    assert is_operation_allowed("write") is False


def test_delete_is_denied():
    assert is_operation_allowed("delete") is False


def test_empty_operation_is_denied():
    assert is_operation_allowed("") is False


def test_read_temperature():
    assert get_telemetry("read", "temperature") == {
        "status": "ok", "measurement": "temperature", "value": 24.5
    }


def test_unknown_measurement():
    assert get_telemetry("read", "humidity") == {
        "status": "not_found", "measurement": "humidity"
    }


def test_write_cannot_read_or_modify_telemetry():
    assert get_telemetry("write", "temperature") == {
        "status": "denied", "operation": "write"
    }
