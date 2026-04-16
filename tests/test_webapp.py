"""
Tests unitaires pour src/webapp.py
Lance avec : pytest tests/ depuis la racine du projet.
"""
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
import webapp as webapp_module
from webapp import app


@pytest.fixture(autouse=True)
def reset_api_key():
    """Remet API_KEY à vide avant chaque test pour isolation."""
    original = webapp_module.API_KEY
    webapp_module.API_KEY = ""
    yield
    webapp_module.API_KEY = original


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False  # désactiver le rate limiter pendant les tests
    with app.test_client() as c:
        yield c


# ─── Endpoint /health ─────────────────────────────────────────────────────────

class TestHealth:
    def test_retourne_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_retourne_status_ok(self, client):
        data = resp = client.get("/health").get_json()
        assert data["status"] == "ok"


# ─── Endpoint /version ────────────────────────────────────────────────────────

class TestVersion:
    def test_retourne_200(self, client):
        resp = client.get("/version")
        assert resp.status_code == 200

    def test_contient_nom_et_version(self, client):
        data = client.get("/version").get_json()
        assert data["name"] == "NetAudit"
        assert isinstance(data["version"], str)
        assert data["version"]  # non vide
        assert "commit" in data  # clé présente même si valeur vide


# ─── Endpoints /history ───────────────────────────────────────────────────────

class TestHistory:
    def test_liste_retourne_200(self, client):
        with patch("webapp.list_scans", return_value=[]):
            resp = client.get("/history")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_liste_contient_scans(self, client):
        fake = [{"id": 1, "ip": "10.0.0.1", "scan_date": "2026-04-16",
                 "host_up": True, "total_vulns": 3, "risk_level": "HIGH"}]
        with patch("webapp.list_scans", return_value=fake):
            data = client.get("/history").get_json()
        assert data["count"] == 1
        assert data["scans"][0]["ip"] == "10.0.0.1"

    def test_limit_parametre_invalide_utilise_defaut(self, client):
        with patch("webapp.list_scans", return_value=[]) as m:
            client.get("/history?limit=pas-un-nombre")
        m.assert_called_once_with(limit=100)

    def test_history_ip_invalide_retourne_400(self, client):
        resp = client.get("/history/pas-une-ip")
        assert resp.status_code == 400

    def test_history_ip_valide_retourne_scans(self, client):
        fake = [{"id": 1, "ip": "10.0.0.1", "data": {"ports": []}}]
        with patch("webapp.scans_for_ip", return_value=fake):
            resp = client.get("/history/10.0.0.1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ip"] == "10.0.0.1"
        assert data["count"] == 1

    def test_history_ip_auth_requise(self, client):
        webapp_module.API_KEY = "secret"
        resp = client.get("/history/10.0.0.1")
        assert resp.status_code == 401


# ─── Endpoint /scan/<ip> ──────────────────────────────────────────────────────

class TestScan:
    def test_ip_invalide_retourne_400(self, client):
        resp = client.get("/scan/pas-une-ip")
        assert resp.status_code == 400
        assert "invalide" in resp.get_json()["error"].lower()

    def test_ip_avec_injection_retourne_400(self, client):
        resp = client.get("/scan/192.168.1.1;rm-rf")
        assert resp.status_code == 400

    def test_sans_cle_quand_api_key_vide_accepte(self, client):
        mock_data = {
            "ip": "127.0.0.1", "host_up": True,
            "ports": [], "total_vulns": 0, "scan_date": "2024-01-01"
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, "/tmp/r.html")):
            resp = client.get("/scan/127.0.0.1")
        assert resp.status_code == 200

    def test_sans_cle_quand_api_key_configuree_retourne_401(self, client):
        webapp_module.API_KEY = "secret"
        resp = client.get("/scan/127.0.0.1")
        assert resp.status_code == 401
        assert "unauthorized" in resp.get_json()["status"]

    def test_mauvaise_cle_retourne_401(self, client):
        webapp_module.API_KEY = "secret"
        resp = client.get("/scan/127.0.0.1", headers={"X-API-Key": "mauvaise"})
        assert resp.status_code == 401

    def test_bonne_cle_acceptee(self, client):
        webapp_module.API_KEY = "secret"
        mock_data = {
            "ip": "127.0.0.1", "host_up": True,
            "ports": [], "total_vulns": 0, "scan_date": "2024-01-01"
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, "/tmp/r.html")):
            resp = client.get("/scan/127.0.0.1", headers={"X-API-Key": "secret"})
        assert resp.status_code == 200

    def test_reponse_contient_champs_attendus(self, client):
        mock_data = {
            "ip": "10.0.0.1", "host_up": True,
            "ports": [{"port": 80, "protocol": "tcp", "state": "open",
                       "service": "http", "version": "", "vulns": []}],
            "total_vulns": 0, "scan_date": "2024-01-01"
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, "/tmp/r.html")):
            resp = client.get("/scan/10.0.0.1")

        body = resp.get_json()
        assert body["status"] == "ok"
        assert body["ip"] == "10.0.0.1"
        assert "ports" in body
        assert "total_vulns" in body
        assert "rapport_html" in body

    def test_erreur_scan_retourne_500(self, client):
        mock_data = {
            "ip": "10.0.0.1", "error": "Timeout",
            "host_up": False, "ports": [], "total_vulns": 0, "raw": ""
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, None)):
            resp = client.get("/scan/10.0.0.1")
        assert resp.status_code == 500
        assert resp.get_json()["status"] == "failed"

    def test_scan_retourne_none_retourne_500(self, client):
        with patch("webapp.lancer_scan", return_value=(None, None)):
            # lancer_scan retourne None si IP invalide, mais valider_ip filtre avant
            # On simule un cas exceptionnel
            with patch("webapp.valider_ip", return_value=True):
                resp = client.get("/scan/10.0.0.1")
        assert resp.status_code == 500


# ─── Endpoint /rapport/<ip> ───────────────────────────────────────────────────

class TestRapport:
    def test_ip_invalide_retourne_400(self, client):
        resp = client.get("/rapport/pas-une-ip")
        assert resp.status_code == 400

    def test_rapport_absent_retourne_404(self, client):
        with patch("webapp.REPORT_DIR", "/tmp/rapports_inexistants"):
            resp = client.get("/rapport/127.0.0.1")
        assert resp.status_code == 404
        body = resp.get_json()
        assert body["status"] == "not_found"

    def test_rapport_present_retourne_200(self, client, tmp_path):
        ip = "10.10.10.1"
        rapport_file = tmp_path / f"{ip}_scan.html"
        rapport_file.write_text("<html><body>test</body></html>")

        with patch("webapp.REPORT_DIR", str(tmp_path)):
            resp = client.get(f"/rapport/{ip}")
        assert resp.status_code == 200

    def test_auth_requise_si_api_key_configuree(self, client):
        webapp_module.API_KEY = "secret"
        resp = client.get("/rapport/127.0.0.1")
        assert resp.status_code == 401


# ─── Erreurs globales ─────────────────────────────────────────────────────────

class TestErreurs:
    def test_endpoint_inconnu_retourne_404(self, client):
        resp = client.get("/route/inexistante")
        assert resp.status_code == 404
        assert "not_found" in resp.get_json()["status"]
