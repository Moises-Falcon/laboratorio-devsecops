"""Collector OPC UA v2 de MaquetaOT.

Servidor OPC UA que recibe las mediciones de la estacion de bombeo y dosificacion,
valida cada muestra y la guarda en PostgreSQL con la hora de origen y la de recepcion.

Seguridad:
- Solo la politica Basic256Sha256 con firma y cifrado (sin endpoint sin seguridad).
- El certificado del cliente debe estar en el directorio de confianza.
- El usuario "scada" se autentica con contrasena (hash PBKDF2 tomado del entorno).
- Rol de usuario: puede leer y escribir valores, pero no crear ni borrar nodos.
- Ningun secreto vive en el codigo: todo se lee de variables de entorno.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import hmac
import logging
import math
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

NAMESPACE_URI = "urn:ciber-lab:planta"
EXPECTED_TAG_COUNT = 15
VALID_DATATYPES = ("Double", "Boolean")
SCADA_USER = "scada"
PBKDF2_ITERATIONS = 600_000

log = logging.getLogger("collector")


# ---------------------------------------------------------------- tags ----
@dataclass(frozen=True)
class Tag:
    name: str
    datatype: str
    unit: str = ""
    description: str = ""
    minimum: float | None = None
    maximum: float | None = None


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str = ""


def _opt_float(text: str | None) -> float | None:
    text = (text or "").strip()
    return float(text) if text else None


def load_tags(path: str | Path) -> dict[str, Tag]:
    """Carga tags.csv. Falla si hay duplicados, tipos no soportados o rangos invertidos."""
    tags: dict[str, Tag] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("name") or "").strip()
            datatype = (row.get("datatype") or "").strip()
            if not name:
                raise ValueError("tag sin nombre")
            if name in tags:
                raise ValueError(f"tag duplicado: {name}")
            if datatype not in VALID_DATATYPES:
                raise ValueError(f"tipo no soportado para {name}: {datatype!r}")
            tag = Tag(
                name=name,
                datatype=datatype,
                unit=(row.get("unit") or "").strip(),
                description=(row.get("description") or "").strip(),
                minimum=_opt_float(row.get("min")),
                maximum=_opt_float(row.get("max")),
            )
            if tag.minimum is not None and tag.maximum is not None and tag.minimum > tag.maximum:
                raise ValueError(f"rango invertido en {name}")
            tags[name] = tag
    return tags


def validate_sample(tags: dict[str, Tag], name: str, value: object) -> Verdict:
    """Decide si una muestra se acepta. Todo lo que no este permitido se rechaza."""
    tag = tags.get(name)
    if tag is None:
        return Verdict(False, "tag no autorizado")
    if tag.datatype == "Boolean":
        if not isinstance(value, bool):
            return Verdict(False, "tipo incorrecto: se esperaba Boolean")
        return Verdict(True)
    # Double: un bool no cuenta como numero
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return Verdict(False, "tipo incorrecto: se esperaba Double")
    number = float(value)
    if math.isnan(number) or math.isinf(number):
        return Verdict(False, "valor no finito")
    if tag.minimum is not None and number < tag.minimum:
        return Verdict(False, "valor por debajo del minimo")
    if tag.maximum is not None and number > tag.maximum:
        return Verdict(False, "valor por encima del maximo")
    return Verdict(True)


# ------------------------------------------------------------- usuario ----
def make_password_hash(password: str, salt: bytes | None = None) -> str:
    """Devuelve 'pbkdf2_sha256$iteraciones$sal$hash' (hex)."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


# ------------------------------------------------------- base de datos ----
INSERT_SQL = (
    "INSERT INTO mediciones (tag, valor_num, valor_bool, source_timestamp, received_timestamp) "
    "VALUES (%s, %s, %s, %s, %s)"
)

CREATE_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS mediciones ("
    "id BIGSERIAL PRIMARY KEY, tag TEXT NOT NULL, valor_num DOUBLE PRECISION, valor_bool BOOLEAN, "
    "source_timestamp TIMESTAMPTZ, received_timestamp TIMESTAMPTZ NOT NULL)"
)


def build_row(tag: Tag, value: object, source_ts: datetime | None, received_ts: datetime) -> tuple:
    """Fila lista para INSERT_SQL (consulta parametrizada, sin concatenar texto)."""
    if tag.datatype == "Boolean":
        return (tag.name, None, bool(value), source_ts, received_ts)
    return (tag.name, float(value), None, source_ts, received_ts)


def store_sample(connection, row: tuple) -> None:
    """Guarda una fila. 'connection' es una conexion psycopg."""
    with connection.cursor() as cur:
        cur.execute(INSERT_SQL, row)
    connection.commit()


# ------------------------------------------------------------ servidor ----
class ScadaUserManager:
    """Autentica al usuario 'scada' por contrasena y le da rol User (leer/escribir, sin crear nodos)."""

    def __init__(self, password_hash: str):
        self._password_hash = password_hash

    def get_user(self, iserver, username=None, password=None, certificate=None):
        from asyncua.crypto.permission_rules import User, UserRole

        if username == SCADA_USER and password and verify_password(password, self._password_hash):
            return User(role=UserRole.User, name=SCADA_USER)
        return None


class SampleHandler:
    """Recibe cada cambio de valor, lo valida y lo guarda (o lo rechaza y lo registra)."""

    def __init__(self, tags: dict[str, Tag], sink):
        self._tags = tags
        self._sink = sink  # funcion(row) o None
        self._names: dict = {}  # NodeId -> nombre del tag
        self.accepted = 0
        self.rejected = 0

    def register(self, nodeid, name: str) -> None:
        self._names[nodeid] = name

    def datachange_notification(self, node, val, data):
        name = self._names.get(node.nodeid, str(node.nodeid))
        verdict = validate_sample(self._tags, name, val)
        if not verdict.ok:
            self.rejected += 1
            log.warning("muestra rechazada tag=%s motivo=%s", name, verdict.reason)
            return
        self.accepted += 1
        if self._sink is not None:
            source_ts = None
            try:
                source_ts = data.monitored_item.Value.SourceTimestamp
            except AttributeError:
                pass
            self._sink(build_row(self._tags[name], val, source_ts, datetime.now(timezone.utc)))


async def build_server(
    tags: dict[str, Tag],
    endpoint: str,
    cert_path: Path,
    key_path: Path,
    trust_dir: Path,
    password_hash: str,
    sink=None,
):
    """Crea y arranca el servidor. Devuelve (server, handler)."""
    from asyncua import Server, ua
    from asyncua.crypto.truststore import TrustStore
    from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions

    server = Server(user_manager=ScadaUserManager(password_hash))
    await server.init()
    server.set_endpoint(endpoint)
    server.set_server_name("Collector MaquetaOT v2")
    await server.load_certificate(cert_path)
    await server.load_private_key(key_path)
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    server.set_security_IDs(["Username"])

    store = TrustStore([trust_dir], [])
    await store.load()
    validator = CertificateValidator(
        CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_CLIENT, store
    )
    server.set_certificate_validator(validator)

    idx = await server.register_namespace(NAMESPACE_URI)
    objects = server.get_objects_node()
    plant = await objects.add_object(idx, "Planta")
    handler = SampleHandler(tags, sink)
    subscription = await server.create_subscription(100, handler)
    for tag in tags.values():
        initial = False if tag.datatype == "Boolean" else 0.0
        variant = ua.VariantType.Boolean if tag.datatype == "Boolean" else ua.VariantType.Double
        node = await plant.add_variable(idx, tag.name, initial, varianttype=variant)
        await node.set_writable()
        handler.register(node.nodeid, tag.name)
        await subscription.subscribe_data_change(node)
    await server.start()
    return server, handler


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Falta la variable de entorno {name}")
    return value


async def main() -> None:
    import psycopg

    here = Path(__file__).parent
    tags = load_tags(os.environ.get("COLLECTOR_TAGS", here / "tags.csv"))
    if len(tags) != EXPECTED_TAG_COUNT:
        raise SystemExit(f"Se esperaban {EXPECTED_TAG_COUNT} tags y hay {len(tags)}")
    connection = psycopg.connect(_require_env("COLLECTOR_DB_DSN"))
    with connection.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)
    connection.commit()
    server, _ = await build_server(
        tags,
        endpoint=os.environ.get("COLLECTOR_ENDPOINT", "opc.tcp://0.0.0.0:4840/historian/"),
        cert_path=Path(_require_env("COLLECTOR_CERT")),
        key_path=Path(_require_env("COLLECTOR_KEY")),
        trust_dir=Path(_require_env("COLLECTOR_TRUST_DIR")),
        password_hash=_require_env("COLLECTOR_SCADA_PASSWORD_HASH"),
        sink=lambda row: store_sample(connection, row),
    )
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()
        connection.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
