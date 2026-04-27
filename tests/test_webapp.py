"""
Tests unitaires pour src/webapp.py
Lance avec : pytest tests/ depuis la racine du projet.
"""
import subprocess
import sys
import os
import textwrap
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
        data = client.get("/health").get_json()
        assert data["status"] == "ok"

    def test_expose_etat_db_et_version(self, client):
        """2.7.0 — /health expose history_db et version pour l'observabilité."""
        with patch("webapp.db_health", return_value=True):
            data = client.get("/health").get_json()
        assert data["history_db"] == "ok"
        assert isinstance(data["version"], str) and data["version"]

    def test_db_degradee_signale_sans_500(self, client):
        """Si la DB ne répond pas, /health reste 200 mais signale `degraded`.
        L'agrégateur (Prometheus, etc.) décidera d'alerter — pas de restart loop."""
        with patch("webapp.db_health", return_value=False):
            resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["history_db"] == "degraded"


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


# ─── Endpoint /scan (POST) ────────────────────────────────────────────────────

class TestScan:
    """`POST /scan` body JSON `{"ip": "..."}`. Le `GET` historique a été
    retiré en 2.7.0 — un scan déclenche une action lourde, le verbe HTTP
    correct est `POST`."""

    def _post(self, client, ip, **kwargs):
        return client.post("/scan", json={"ip": ip}, **kwargs)

    def test_get_legacy_retourne_405_ou_404(self, client):
        # Régression : l'ancien `GET /scan/<ip>` ne doit plus être servi.
        resp = client.get("/scan/127.0.0.1")
        assert resp.status_code in (404, 405)

    def test_body_sans_ip_retourne_400(self, client):
        resp = client.post("/scan", json={})
        assert resp.status_code == 400
        assert "ip" in resp.get_json()["error"].lower()

    def test_body_non_json_retourne_400(self, client):
        resp = client.post("/scan", data="pas-du-json", content_type="text/plain")
        assert resp.status_code == 400

    def test_ip_invalide_retourne_400(self, client):
        resp = self._post(client, "pas-une-ip")
        assert resp.status_code == 400
        assert "invalide" in resp.get_json()["error"].lower()

    def test_ip_avec_injection_retourne_400(self, client):
        resp = self._post(client, "192.168.1.1;rm-rf")
        assert resp.status_code == 400

    def test_sans_cle_quand_api_key_vide_accepte(self, client):
        mock_data = {
            "ip": "127.0.0.1", "host_up": True,
            "ports": [], "total_vulns": 0, "scan_date": "2024-01-01"
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, "/tmp/r.html")):
            resp = self._post(client, "127.0.0.1")
        assert resp.status_code == 200

    def test_sans_cle_quand_api_key_configuree_retourne_401(self, client):
        webapp_module.API_KEY = "secret"
        resp = self._post(client, "127.0.0.1")
        assert resp.status_code == 401
        assert "unauthorized" in resp.get_json()["status"]

    def test_mauvaise_cle_retourne_401(self, client):
        webapp_module.API_KEY = "secret"
        resp = self._post(client, "127.0.0.1", headers={"X-API-Key": "mauvaise"})
        assert resp.status_code == 401

    def test_bonne_cle_acceptee(self, client):
        webapp_module.API_KEY = "secret"
        mock_data = {
            "ip": "127.0.0.1", "host_up": True,
            "ports": [], "total_vulns": 0, "scan_date": "2024-01-01"
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, "/tmp/r.html")):
            resp = self._post(client, "127.0.0.1", headers={"X-API-Key": "secret"})
        assert resp.status_code == 200

    def test_reponse_contient_champs_attendus(self, client):
        mock_data = {
            "ip": "10.0.0.1", "host_up": True,
            "ports": [{"port": 80, "protocol": "tcp", "state": "open",
                       "service": "http", "version": "", "vulns": []}],
            "total_vulns": 0, "scan_date": "2024-01-01"
        }
        with patch("webapp.lancer_scan", return_value=(mock_data, "/tmp/r.html")):
            resp = self._post(client, "10.0.0.1")

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
            resp = self._post(client, "10.0.0.1")
        assert resp.status_code == 500
        assert resp.get_json()["status"] == "failed"

    def test_scan_retourne_none_retourne_500(self, client):
        with patch("webapp.lancer_scan", return_value=(None, None)):
            with patch("webapp.valider_ip", return_value=True):
                resp = self._post(client, "10.0.0.1")
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

    def test_format_json_retourne_data(self, client):
        fake = [{"data": {"ip": "10.0.0.1", "ports": [], "total_vulns": 0}}]
        with patch("webapp.scans_for_ip", return_value=fake):
            resp = client.get("/rapport/10.0.0.1?format=json")
        assert resp.status_code == 200
        assert resp.get_json()["ip"] == "10.0.0.1"

    def test_format_json_sans_scan_retourne_404(self, client):
        with patch("webapp.scans_for_ip", return_value=[]):
            resp = client.get("/rapport/10.0.0.1?format=json")
        assert resp.status_code == 404

    def test_format_pdf_retourne_pdf(self, client):
        fake = [{"data": {
            "ip": "10.0.0.1", "scan_date": "2026-04-16",
            "host_up": True, "ports": [], "total_vulns": 0,
        }}]
        with patch("webapp.scans_for_ip", return_value=fake):
            resp = client.get("/rapport/10.0.0.1?format=pdf")
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert resp.data[:5] == b"%PDF-"
        assert "attachment" in resp.headers.get("Content-Disposition", "")

    def test_format_pdf_sans_scan_retourne_404(self, client):
        with patch("webapp.scans_for_ip", return_value=[]):
            resp = client.get("/rapport/10.0.0.1?format=pdf")
        assert resp.status_code == 404


# ─── Erreurs globales ─────────────────────────────────────────────────────────

class TestErreurs:
    def test_endpoint_inconnu_retourne_404(self, client):
        resp = client.get("/route/inexistante")
        assert resp.status_code == 404
        assert "not_found" in resp.get_json()["status"]


# ─── Régression 2.6.2 : ordonnancement load_dotenv ────────────────────────────

class TestDotenvOrdering:
    """Regression test — `load_dotenv` doit s'exécuter **avant** les imports
    applicatifs, sinon les variables lues au module-level dans scan.py et
    history.py (LOG_FILE_PATH, HISTORY_DB_PATH, etc.) sont ignorées.

    On teste dans un sous-processus pour avoir un environnement vierge et un
    import sequence réaliste — impossible à simuler dans le même process où
    webapp est déjà importé.
    """

    def test_env_file_est_honore_par_scan_et_history(self, tmp_path):
        env_file = tmp_path / ".env"
        expected_log = tmp_path / "app.log"
        expected_db  = tmp_path / "app.db"
        env_file.write_text(
            f"LOG_FILE_PATH={expected_log}\n"
            f"HISTORY_DB_PATH={expected_db}\n"
            f"PRIORITIZER_ENABLED=0\n"
            "API_KEY=\n",
            encoding="utf-8",
        )

        src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
        src_dir = os.path.abspath(src_dir)

        script = textwrap.dedent(f"""
            import os, sys
            os.chdir({str(tmp_path)!r})
            sys.path.insert(0, {src_dir!r})
            # Retirer toute valeur potentiellement héritée
            for k in ("LOG_FILE_PATH", "HISTORY_DB_PATH"):
                os.environ.pop(k, None)
            import webapp  # déclenche load_dotenv + imports
            from scan import LOG_FILE_PATH
            from history import DB_PATH
            print("LOG_FILE_PATH=" + LOG_FILE_PATH)
            print("DB_PATH=" + DB_PATH)
        """).strip()

        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert proc.returncode == 0, proc.stderr
        assert f"LOG_FILE_PATH={expected_log}" in proc.stdout
        assert f"DB_PATH={expected_db}" in proc.stdout


# ─── Régression 2.7.0 : REQUIRE_API_KEY fail-fast ─────────────────────────────

class TestRequireApiKey:
    """`REQUIRE_API_KEY=1` doit empêcher le boot si `API_KEY` est vide.
    On teste dans un sous-processus pour que SystemExit propage correctement
    sans polluer l'interpréteur de la suite courante (où webapp est déjà importé).
    """

    def _run(self, env: dict, tmp_path) -> subprocess.CompletedProcess:
        src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
        script = textwrap.dedent(f"""
            import os, sys
            sys.path.insert(0, {src_dir!r})
            os.chdir({str(tmp_path)!r})
            try:
                import webapp
                print("BOOT_OK")
            except SystemExit as e:
                print("SYSTEM_EXIT:" + str(e))
        """).strip()
        e = os.environ.copy()
        e.update(env)
        # On force des chemins jetables pour que webapp ne touche pas la vraie DB.
        e.setdefault("HISTORY_DB_PATH", str(tmp_path / "fake.db"))
        e.setdefault("LOG_FILE_PATH",   str(tmp_path / "fake.log"))
        e.setdefault("REPORT_DIR",      str(tmp_path / "rapports"))
        e.setdefault("CACHE_DIR",       str(tmp_path / "cache"))
        e.setdefault("PRIORITIZER_ENABLED", "0")
        return subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15, env=e,
        )

    def test_require_avec_cle_demarre(self, tmp_path):
        proc = self._run({"REQUIRE_API_KEY": "1", "API_KEY": "secret"}, tmp_path)
        assert proc.returncode == 0, proc.stderr
        assert "BOOT_OK" in proc.stdout

    def test_require_sans_cle_refuse_de_demarrer(self, tmp_path):
        proc = self._run({"REQUIRE_API_KEY": "1", "API_KEY": ""}, tmp_path)
        # Le script de test capture SystemExit pour pouvoir lire le message,
        # donc on assert sur les marqueurs stdout — pas sur returncode.
        assert "BOOT_OK" not in proc.stdout, "L'import aurait dû lever SystemExit"
        assert "SYSTEM_EXIT:" in proc.stdout
        # Le message d'erreur doit citer la clé pour orienter l'opérateur.
        assert "API_KEY" in proc.stdout

    def test_sans_require_demarre_meme_sans_cle(self, tmp_path):
        # Mode dev par défaut : warning logué, pas d'exit.
        proc = self._run({"REQUIRE_API_KEY": "0", "API_KEY": ""}, tmp_path)
        assert proc.returncode == 0, proc.stderr
        assert "BOOT_OK" in proc.stdout
