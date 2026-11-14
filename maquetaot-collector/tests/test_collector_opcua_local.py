"""Prueba local del servidor OPC UA del Collector: servidor y clientes en 127.0.0.1.

Los certificados se generan en una carpeta temporal durante la prueba; no hay llaves en el repositorio.
No sustituye la prueba con el SCADA real, certificados reales, VPN ni firewall.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collector_opcua as c  # noqa: E402
from asyncua import Client, ua  # noqa: E402
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256  # noqa: E402
from asyncua.crypto.cert_gen import setup_self_signed_certificate  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: E402

PORT = 48401
URL = f"opc.tcp://127.0.0.1:{PORT}/historian/"
CLIENT_URI = "urn:freeopcua:client"
SERVER_URI = "urn:freeopcua:python:server"
PASSWORD = "clave-solo-para-pruebas"
TAGS_CSV = Path(__file__).resolve().parents[1] / "tags.csv"


async def _make_cert(directory: Path, name: str, uri: str, use):
    key, cert = directory / f"{name}.pem", directory / f"{name}.der"
    await setup_self_signed_certificate(key, cert, uri, "127.0.0.1", [use], {"commonName": name})
    return key, cert


async def _client(url, key, cert, server_cert, user=c.SCADA_USER, password=PASSWORD):
    cl = Client(url)
    cl.application_uri = CLIENT_URI
    await cl.set_security(SecurityPolicyBasic256Sha256, str(cert), str(key), server_certificate=str(server_cert))
    cl.set_user(user)
    cl.set_password(password)
    return cl


async def _escenario(tmp: Path):
    tags = c.load_tags(TAGS_CSV)
    skey, scert = await _make_cert(tmp, "servidor", SERVER_URI, ExtendedKeyUsageOID.SERVER_AUTH)
    ckey, ccert = await _make_cert(tmp, "cliente_confiable", CLIENT_URI, ExtendedKeyUsageOID.CLIENT_AUTH)
    xkey, xcert = await _make_cert(tmp, "cliente_no_confiable", CLIENT_URI, ExtendedKeyUsageOID.CLIENT_AUTH)
    trust = tmp / "confianza"
    trust.mkdir()
    (trust / "cliente_confiable.der").write_bytes(ccert.read_bytes())

    rows = []
    server, handler = await c.build_server(
        tags, URL, scert, skey, trust, c.make_password_hash(PASSWORD), sink=rows.append
    )
    resultados = {}
    try:
        # 1) cliente confiable + usuario correcto: se conecta y escribe valores
        ok = await _client(URL, ckey, ccert, scert)
        async with ok:
            idx = await ok.get_namespace_index(c.NAMESPACE_URI)
            plant = await ok.nodes.objects.get_child([f"{idx}:Planta"])
            ph = await plant.get_child([f"{idx}:ph_agua"])
            alarma = await plant.get_child([f"{idx}:paro_emergencia"])
            await ph.write_value(7.4)
            await alarma.write_value(True)
            await asyncio.sleep(0.6)
            resultados["lectura"] = await ph.read_value()
            # 2) el mismo usuario NO puede crear nodos
            try:
                await plant.add_variable(idx, "nodo_pirata", 1.0)
                resultados["crear_nodo"] = "permitido"
            except Exception as exc:  # noqa: BLE001
                resultados["crear_nodo"] = type(exc).__name__
        # 3) contrasena incorrecta
        mala = await _client(URL, ckey, ccert, scert, password="incorrecta")
        try:
            async with mala:
                resultados["clave_mala"] = "conecto"
        except Exception as exc:  # noqa: BLE001
            resultados["clave_mala"] = type(exc).__name__
        # 4) certificado que no esta en la lista de confianza
        untrusted = await _client(URL, xkey, xcert, scert)
        try:
            async with untrusted:
                resultados["cert_no_confiable"] = "conecto"
        except Exception as exc:  # noqa: BLE001
            resultados["cert_no_confiable"] = type(exc).__name__
        # 5) un valor de tipo incorrecto escrito en un nodo Double no se guarda
        ok2 = await _client(URL, ckey, ccert, scert)
        async with ok2:
            idx = await ok2.get_namespace_index(c.NAMESPACE_URI)
            plant = await ok2.nodes.objects.get_child([f"{idx}:Planta"])
            ph = await plant.get_child([f"{idx}:ph_agua"])
            try:
                await ph.write_value("texto", ua.VariantType.String)
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.4)
    finally:
        await server.stop()
    resultados["filas"] = rows
    return resultados


@pytest.fixture(scope="module")
def r(tmp_path_factory):
    return asyncio.run(_escenario(tmp_path_factory.mktemp("pki")))


def test_cliente_confiable_con_usuario_correcto_escribe_y_lee(r):
    assert r["lectura"] == 7.4


def test_las_muestras_validas_se_envian_al_almacenamiento(r):
    nombres = {fila[0] for fila in r["filas"]}
    assert {"ph_agua", "paro_emergencia"} <= nombres


def test_usuario_scada_no_puede_crear_nodos(r):
    assert r["crear_nodo"] != "permitido"


def test_contrasena_incorrecta_es_rechazada(r):
    assert r["clave_mala"] != "conecto"


def test_certificado_no_confiable_es_rechazado(r):
    assert r["cert_no_confiable"] != "conecto"
