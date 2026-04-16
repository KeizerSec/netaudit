"""
Tests unitaires pour src/history.py
Utilise tmp_path pour isoler la base SQLite de chaque test.
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def history_module(tmp_path, monkeypatch):
    """Recharge history.py avec HISTORY_DB_PATH pointant sur une base jetable."""
    db_file = tmp_path / "test_netaudit.db"
    monkeypatch.setenv("HISTORY_DB_PATH", str(db_file))
    import history
    importlib.reload(history)
    return history


def _sample_scan(ip: str = "192.168.1.10", vulns: int = 2, risk: str = "HIGH") -> dict:
    return {
        "ip":          ip,
        "scan_date":   "2026-04-16 12:00:00 UTC",
        "host_up":     True,
        "total_vulns": vulns,
        "ports":       [{"port": 22, "service": "ssh", "vulns": []}],
        "attack_summary": {"risk_level": risk},
    }


class TestInitDb:
    def test_schema_cree_fichier(self, history_module, tmp_path):
        # Le fichier est créé à l'initialisation du module (init_db au chargement).
        assert os.path.exists(history_module.DB_PATH)

    def test_idempotent(self, history_module):
        # Rejouer init_db ne doit pas lever.
        history_module.init_db()
        history_module.init_db()


class TestRecordScan:
    def test_insertion_retourne_id(self, history_module):
        rowid = history_module.record_scan(_sample_scan())
        assert isinstance(rowid, int) and rowid > 0

    def test_ip_manquante_retourne_none(self, history_module):
        assert history_module.record_scan({"ip": ""}) is None
        assert history_module.record_scan({}) is None

    def test_payload_non_dict_retourne_none(self, history_module):
        assert history_module.record_scan("pas un dict") is None
        assert history_module.record_scan(None) is None

    def test_sans_attack_summary_ok(self, history_module):
        data = _sample_scan()
        data.pop("attack_summary")
        rowid = history_module.record_scan(data)
        assert rowid > 0

    def test_host_up_false_enregistre(self, history_module):
        data = _sample_scan()
        data["host_up"] = False
        rowid = history_module.record_scan(data)
        scans = history_module.scans_for_ip(data["ip"])
        assert scans[0]["host_up"] is False


class TestListScans:
    def test_vide_retourne_liste_vide(self, history_module):
        assert history_module.list_scans() == []

    def test_ordre_decroissant(self, history_module):
        history_module.record_scan(_sample_scan("10.0.0.1"))
        history_module.record_scan(_sample_scan("10.0.0.2"))
        history_module.record_scan(_sample_scan("10.0.0.3"))
        scans = history_module.list_scans()
        assert [s["ip"] for s in scans] == ["10.0.0.3", "10.0.0.2", "10.0.0.1"]

    def test_limit_applique(self, history_module):
        for i in range(5):
            history_module.record_scan(_sample_scan(f"10.0.0.{i}"))
        assert len(history_module.list_scans(limit=3)) == 3

    def test_projection_synthese(self, history_module):
        history_module.record_scan(_sample_scan(vulns=7, risk="CRITICAL"))
        scan = history_module.list_scans()[0]
        # La liste ne doit PAS contenir la data complète (économise la bande passante).
        assert "data" not in scan
        assert scan["total_vulns"] == 7
        assert scan["risk_level"] == "CRITICAL"


class TestScansForIp:
    def test_ip_inconnue_retourne_liste_vide(self, history_module):
        assert history_module.scans_for_ip("192.0.2.1") == []

    def test_filtre_par_ip(self, history_module):
        history_module.record_scan(_sample_scan("10.0.0.1"))
        history_module.record_scan(_sample_scan("10.0.0.2"))
        history_module.record_scan(_sample_scan("10.0.0.1"))
        scans = history_module.scans_for_ip("10.0.0.1")
        assert len(scans) == 2
        assert all(s["ip"] == "10.0.0.1" for s in scans)

    def test_contient_data_complete(self, history_module):
        history_module.record_scan(_sample_scan("10.0.0.1"))
        scans = history_module.scans_for_ip("10.0.0.1")
        assert scans[0]["data"]["ports"][0]["service"] == "ssh"
