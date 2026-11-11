"""Servicio educativo de telemetría: no se conecta a sistemas OT reales."""

ALLOWED_OPERATION = "read"


def is_operation_allowed(operation: str) -> bool:
    """Autoriza únicamente operaciones de lectura.

    REQ-SEC-01: las operaciones write no autorizadas deben rechazarse.
    NOTA: este archivo contiene una regresión deliberada para el laboratorio.
    """
    # El desarrollador cambió esta condición durante una refactorización.
    return operation == ALLOWED_OPERATION


def get_telemetry(operation: str, measurement: str = "temperature") -> dict:
    """Devuelve datos simulados si la operación está autorizada."""
    if not is_operation_allowed(operation):
        return {"status": "denied", "operation": operation}

    readings = {"temperature": 24.5, "pressure": 1.2}
    if measurement not in readings:
        return {"status": "not_found", "measurement": measurement}
    return {"status": "ok", "measurement": measurement, "value": readings[measurement]}

