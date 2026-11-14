# Collector OPC UA v2 de MaquetaOT

Autor: Moises Falcon Pacheco (A01801140). Proyecto Siemens, expediente de aseguramiento DevSecOps.

## Qué es

El Collector v2 es el servicio de la DMZ que recibe por OPC UA las mediciones de la estación de
bombeo y dosificación (15 tags: 4 Double y 11 Boolean), las valida y las guarda en PostgreSQL con la
hora de origen y la de recepción.

Esta carpeta contiene la **versión 2 del Collector, escrita y probada en este repositorio**. Es una
propuesta mejorada del diseño: la seguridad y la validación están en el código y se comprueban con
pruebas automáticas. **Todavía no se ha desplegado en la VM `historian-lab` ni se ha conectado al
SCADA real**; eso está en la tabla de pendientes.

Qué se asegura en el código (`collector_opcua.py`):

- Solo se ofrece la política `Basic256Sha256` con firma y cifrado. No hay endpoint sin seguridad.
- El certificado del cliente debe estar en el directorio de confianza.
- El usuario `scada` entra con contraseña (se guarda solo su hash PBKDF2, tomado de una variable de
  entorno). Su rol puede leer y escribir valores, pero no crear nodos.
- Cada muestra se valida: un tag que no está en `tags.csv` se rechaza, un tipo incorrecto se rechaza y
  un valor fuera de rango se rechaza si el rango está definido.
- La inserción a PostgreSQL usa consulta parametrizada. No hay secretos en el repositorio.

Los tags de `tags.csv` son los de esta versión v2 (nombres propuestos a partir del proceso de bombeo y
dosificación). Los **límites de pH y caudal no están definidos** porque los establece el responsable del
proceso; por eso las pruebas de rango se hacen con rangos de prueba y no con límites reales.

## Ejecutado vs pendiente

| Control | Estado | Evidencia |
|---|---|---|
| pip-audit sobre requirements del Collector | Ejecutado | `evidencias/pip-audit-collector.txt` |
| pip-audit sobre el entorno completo (directas y transitivas) | Ejecutado | `evidencias/pip-audit-collector-freeze.txt` |
| Bandit sobre `collector_opcua.py` | Ejecutado | `evidencias/bandit-collector.txt` |
| SBOM CycloneDX | Ejecutado | `sbom/collector-sbom.cdx.json` |
| pytest: lógica de tags, validación y contraseña | Ejecutado | `evidencias/pytest-collector.txt` |
| pytest: servidor OPC UA en localhost (cert de confianza, contraseña, sin crear nodos) | Ejecutado en localhost | `evidencias/pytest-collector.txt` |
| Workflow de GitHub Actions del Collector | Ver run en GitHub Actions | pestaña Actions del repositorio |
| Cliente OPC UA no autorizado rechazado con el SCADA y certificados reales | PENDIENTE | n/a |
| Despliegue en la VM `historian-lab` y firewall local (nftables) | PENDIENTE | n/a |
| Dato del SCADA guardado en PostgreSQL con tiempos correctos | PENDIENTE (no hay PostgreSQL en estas pruebas) | n/a |
| Bloqueo IT/DMZ hacia el PLC con logs | PENDIENTE (requiere firewall) | n/a |
| Falla de VPN / Historian sin afectar el control local | PENDIENTE | n/a |
| Límites reales de pH y caudal | PENDIENTE (los define el responsable del proceso) | n/a |

## pip-audit

Fecha: 2026-11-13. Resultado sobre `requirements.txt` y sobre el entorno completo: **No known vulnerabilities
found**. Solo significa que ese día no había avisos conocidos para esas versiones; puede cambiar.

| Paquete | Versión | Aviso | Versión corregida | Decisión |
|---|---|---|---|---|
| asyncua | 2.1.0 | ninguno | n/a | mantener |
| psycopg (+ binary) | 3.3.9 | ninguno | n/a | mantener |

## Bandit

`python -m bandit -r collector_opcua.py`: 227 líneas analizadas, 0 hallazgos. Bandit solo busca patrones
inseguros conocidos; no revisa si la lógica de autorización cumple el requisito. Eso lo cubren las pruebas.

## SBOM

Generado con `cyclonedx-py requirements requirements.txt --of JSON` (CycloneDX 1.6). Contiene las
dependencias **directas** (2). El árbol completo, con las transitivas, quedó en el análisis de
`requirements-freeze.txt` (ese archivo incluye también las herramientas de prueba instaladas en el entorno).

- Fecha: 2026-11-13. Commit base antes de este cambio: `b150022`. El commit de esta versión es el último
  del historial del repositorio.
- SHA-256 `sbom/collector-sbom.cdx.json`: `B6F7A9379FC0978138BD8A6AB46D0EBE7438A512D8CC9932D4255B4269F2D4DC`
- SHA-256 `collector_opcua.py`: `8292574E77D9F340F0A9A8BC92F01C7AEBC7C593B78D5587E6045665B2B76F81`
- SHA-256 `tags.csv`: `71BFBAC3E29C45812FCFBE8CF8065FDFD32F291B03A313D8ED8B590A1B45BBC7`
- SHA-256 `requirements.txt`: `B3D3ADD052861965650B5459E79AE9A0206D802D1D8E20A94B1EA16E63820A77`

## pytest

32 pruebas, todas pasaron (`evidencias/pytest-collector.txt`).

- `tests/test_collector_tags.py` (27): 15 tags, 4 Double y 11 Boolean, sin duplicados; tag no autorizado,
  tipo incorrecto y valores no finitos rechazados; rangos; contraseña correcta e incorrecta; hash mal
  formado; consulta SQL parametrizada.
- `tests/test_collector_opcua_local.py` (5): servidor y clientes en 127.0.0.1 con certificados creados
  en una carpeta temporal durante la prueba. Cliente de confianza con usuario correcto escribe y lee;
  el usuario `scada` no puede crear nodos (`BadUserAccessDenied`); contraseña incorrecta rechazada
  (`BadUserAccessDenied`); certificado fuera de la lista de confianza rechazado
  (`BadCertificateUntrusted`).

Pruebas pendientes: las que requieren SCADA real, certificados reales, VPN, firewall o PostgreSQL (tabla
de arriba).

## Cómo correrlo

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt pytest
python -m pytest -v
```

Para arrancar el servicio hacen falta las variables `COLLECTOR_DB_DSN`, `COLLECTOR_CERT`, `COLLECTOR_KEY`,
`COLLECTOR_TRUST_DIR` y `COLLECTOR_SCADA_PASSWORD_HASH` (el hash se genera con `make_password_hash`).

## Aclaración

El laboratorio individual de la raíz del repositorio (`src/`, `tests/`) es otra práctica y no demuestra que
el Collector haya pasado estas pruebas.
