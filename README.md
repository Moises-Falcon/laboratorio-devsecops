# Laboratorio final individual — ¿Autorizarías este cambio a producción?

Proyecto educativo de un servicio de telemetría IT–OT **simulado**. Contiene dos problemas intencionales: una regresión de autorización y una dependencia con vulnerabilidades conocidas. No se conecta a PLC ni a sistemas industriales.

## Preparación

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Diagnóstico inicial
```bash
python -m pytest -q
python -m bandit -r src -q
python -m pip_audit -r requirements-audit.txt
```

**Esperado inicialmente:** 7 pruebas ejecutadas, 2 fallidas; Bandit sin hallazgos sobre `src` (esto NO significa que la autorización sea correcta); `pip-audit` con hallazgos conocidos en la dependencia auditada. El servicio no necesita instalar la biblioteca vulnerable para este ejercicio.

## Tu reto
1. Identifica el requisito que incumple la prueba fallida y corrige el código de producción, **sin cambiar las pruebas**.
2. Analiza `requirements-audit.txt`. Investiga una versión corregida y compatible, actualiza ese archivo y vuelve a auditar. Si el servicio de auditoría no está disponible, documenta el error de infraestructura y no lo confundas con ausencia de vulnerabilidades.
3. Ejecuta nuevamente las tres verificaciones.
4. Crea un repositorio GitHub individual y sube tu proyecto. El workflow está en `.github/workflows/security-ci.yml`.
5. Comprueba la ejecución de GitHub Actions; no modifiques el workflow para ocultar fallas.
6. Explica tu decisión de integración, distinguiéndola de una autorización para desplegar en OT.

## Evidencias
- Captura inicial de pytest (falla), captura inicial de pip-audit (hallazgos).
- Captura posterior de pytest (aprobado), captura posterior de pip-audit (resultado).
- Enlace al repositorio y captura de GitHub Actions posterior a la corrección.
- Respuestas y decisión técnica según las instrucciones de Canvas.

## Importante
`requirements.txt` contiene solo herramientas del laboratorio; `requirements-audit.txt` representa un manifiesto de una dependencia de un componente hipotético y se **audita, pero no se instala**. No afirmes que el SBOM completo del producto está representado por este archivo. `pip-audit` requiere conectividad a su servicio de vulnerabilidades y su resultado puede cambiar conforme se actualizan los avisos.
