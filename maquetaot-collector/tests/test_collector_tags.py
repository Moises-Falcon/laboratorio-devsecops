"""Pruebas de la logica local del Collector: tags, validacion de muestras y contrasena.

No requieren red, PostgreSQL, certificados reales ni SCADA.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collector_opcua as c  # noqa: E402

TAGS_CSV = Path(__file__).resolve().parents[1] / "tags.csv"


@pytest.fixture(scope="module")
def tags():
    return c.load_tags(TAGS_CSV)


def test_tags_csv_carga_15_tags(tags):
    assert len(tags) == c.EXPECTED_TAG_COUNT == 15


def test_tags_sin_duplicados_y_con_tipos_esperados(tags):
    datatypes = [t.datatype for t in tags.values()]
    assert datatypes.count("Double") == 4
    assert datatypes.count("Boolean") == 11
    assert len(set(tags)) == len(tags)


def test_csv_con_duplicado_se_rechaza(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("name,datatype,unit,description,min,max\na,Double,,,,\na,Boolean,,,,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicado"):
        c.load_tags(f)


def test_csv_con_tipo_no_soportado_se_rechaza(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("name,datatype,unit,description,min,max\na,String,,,,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no soportado"):
        c.load_tags(f)


def test_csv_con_rango_invertido_se_rechaza(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("name,datatype,unit,description,min,max\na,Double,,,5,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invertido"):
        c.load_tags(f)


def test_tag_fuera_de_la_lista_se_rechaza(tags):
    v = c.validate_sample(tags, "tag_inventado", 1.0)
    assert v.ok is False and "no autorizado" in v.reason


def test_boolean_acepta_bool(tags):
    assert c.validate_sample(tags, "paro_emergencia", True).ok is True


@pytest.mark.parametrize("valor", [1, 0, "true", 1.0, None])
def test_boolean_rechaza_otros_tipos(tags, valor):
    assert c.validate_sample(tags, "paro_emergencia", valor).ok is False


def test_double_acepta_numeros(tags):
    assert c.validate_sample(tags, "ph_agua", 7.2).ok is True
    assert c.validate_sample(tags, "ph_agua", 7).ok is True


@pytest.mark.parametrize("valor", ["7.2", None, True, float("nan"), float("inf")])
def test_double_rechaza_tipos_y_valores_invalidos(tags, valor):
    assert c.validate_sample(tags, "ph_agua", valor).ok is False


def test_rango_se_aplica_solo_si_esta_definido(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("name,datatype,unit,description,min,max\nx,Double,,,0,10\n", encoding="utf-8")
    t = c.load_tags(f)
    assert c.validate_sample(t, "x", 5).ok is True
    assert c.validate_sample(t, "x", -0.1).ok is False
    assert c.validate_sample(t, "x", 10.1).ok is False


def test_tags_del_repositorio_no_definen_rangos(tags):
    """Los limites de pH y caudal los define el responsable del proceso: aun no estan definidos."""
    assert all(t.minimum is None and t.maximum is None for t in tags.values())


def test_contrasena_correcta_e_incorrecta():
    stored = c.make_password_hash("clave-de-prueba")
    assert c.verify_password("clave-de-prueba", stored) is True
    assert c.verify_password("otra", stored) is False


@pytest.mark.parametrize("basura", ["", "x", "a$b$c$d", "pbkdf2_sha256$no_es_numero$00$00"])
def test_hash_mal_formado_no_autentica(basura):
    assert c.verify_password("clave", basura) is False


def test_hash_no_contiene_la_contrasena():
    assert "clave-de-prueba" not in c.make_password_hash("clave-de-prueba")


def test_sql_es_parametrizada_y_fila_booleana_y_numerica(tags):
    assert c.INSERT_SQL.count("%s") == 5
    fila_b = c.build_row(tags["paro_emergencia"], True, None, None)
    fila_n = c.build_row(tags["ph_agua"], 7, None, None)
    assert fila_b[1] is None and fila_b[2] is True
    assert fila_n[1] == 7.0 and fila_n[2] is None
