"""
Test bout-en-bout — exerce la chaîne complète `lancer_scan` avec un seul mock
sur l'I/O Nmap. Tous les enrichissements (attack_mapper, prioritizer en mode
offline, profiler, baseline, history sur SQLite jetable) tournent réellement.

Pourquoi ce test existe
-----------------------
Les tests unitaires couvrent chaque module isolément (dans `test_scan.py`,
`test_attack_mapper.py`, etc.). Ce qu'ils ne couvrent pas — par construction —
c'est le **wiring** entre les modules dans `scan.lancer_scan` :

- l'ordre d'appel (baseline avant `record_scan` pour ne pas se comparer à soi-même),
- la propagation des champs ajoutés à chaque étape (`attack_summary`,
  `priority_summary`, `context`, `baseline`),
- la persistance + relecture SQLite,
- la génération du rapport HTML via Jinja.

Une régression dans le câblage (exemple historique : import circulaire,
init_db oublié, ordre baseline/record inversé) ne serait pas détectée par
les tests unitaires actuels. Ce test attrape ce trou.
"""
from __future__ import annotations

import importlib
import os
import sys
import xml.etree.ElementTree as ET
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# Sortie Nmap XML synthétique : 3 ports ouverts dont 1 base de données.
# Calibré pour déclencher au moins une règle de posture (DB exposée + colocation
# DB+web), un mapping ATT&CK service (T1190 sur http, T1021.004 sur ssh,
# T1210 sur mysql), et une CVE par port pour exercer la priorisation.
_E2E_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9p1"/>
<script id="vulners">
  <table key="cpe:/a:openbsd:openssh:8.9p1">
    <table>
      <elem key="id">CVE-2023-38408</elem>
      <elem key="cvss">9.8</elem>
      <elem key="type">cve</elem>
    </table>
  </table>
</script>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Apache httpd" version="2.4.49"/>
<script id="vulners">
  <table key="cpe:/a:apache:http_server:2.4.49">
    <table>
      <elem key="id">CVE-2021-41773</elem>
      <elem key="cvss">9.8</elem>
      <elem key="type">cve</elem>
    </table>
  </table>
</script>
</port>
<port protocol="tcp" portid="3306">
<state state="open"/>
<service name="mysql" product="MySQL" version="8.0"/>
</port>
</ports>
<os><osmatch name="Linux 5.15"/></os>
</host>
</nmaprun>
"""


@pytest.fixture
def e2e_env(tmp_path, monkeypatch):
    """Isole tous les chemins persistants dans tmp_path et neutralise le réseau."""
    monkeypatch.setenv("HISTORY_DB_PATH", str(tmp_path / "e2e.db"))
    monkeypatch.setenv("REPORT_DIR",      str(tmp_path / "rapports"))
    monkeypatch.setenv("LOG_FILE_PATH",   str(tmp_path / "e2e.log"))
    monkeypatch.setenv("CACHE_DIR",       str(tmp_path / "cache"))
    monkeypatch.setenv("PRIORITIZER_ENABLED", "0")  # KEV/EPSS désactivés
    monkeypatch.setenv("CACHE_SIZE",      "0")      # `lru_cache(maxsize=0)`
    # Recharger les modules pour qu'ils prennent les nouveaux env vars.
    # L'ordre est important : history et scan lisent leurs constantes à l'import.
    import history, scan, prioritizer
    importlib.reload(history)
    importlib.reload(prioritizer)
    importlib.reload(scan)
    return scan, history


@pytest.mark.e2e
class TestEndToEndScanPipeline:
    """Chaîne complète, du Nmap mocké au rapport HTML, en passant par SQLite."""

    def _patched_run(self, *args, **kwargs):
        """Simule subprocess.run(['nmap', ...]) → renvoie le XML fixture."""
        class _R:
            stdout = _E2E_NMAP_XML.encode("utf-8")
            stderr = b""
            returncode = 0
        return _R()

    def test_pipeline_enchaine_tous_les_enrichissements(self, e2e_env):
        scan, _ = e2e_env
        with patch("scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("scan.subprocess.run", side_effect=self._patched_run):
            data, html_path = scan.lancer_scan("127.0.0.1")

        # ── Wiring : tous les enrichissements ont posé leur clé ──────────────
        assert data is not None
        assert data["host_up"] is True
        assert data["ip"] == "127.0.0.1"
        assert "attack_summary"   in data, "attack_mapper a été sauté"
        assert "priority_summary" in data, "prioritizer a été sauté"
        assert "context"          in data, "profiler a été sauté"
        assert "baseline"         in data, "baseline a été sauté"

        # ── Vérifications structurelles minimales par module ────────────────
        # attack_mapper a vu les 3 ports ouverts.
        atk = data["attack_summary"]
        assert atk["phases_count"] >= 1
        assert atk["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

        # prioritizer en mode offline → CVSS seul, pas de KEV/EPSS.
        ps = data["priority_summary"]
        assert ps["sources_used"] == []        # PRIORITIZER_ENABLED=0
        assert ps["max_level"] in {"IMMEDIATE", "HIGH", "MEDIUM", "LOW", "INFO"}
        # 2 CVEs CVSS 9.8 → au moins une vuln triée en tête.
        assert len(ps["top"]) >= 1

        # profiler a détecté un rôle + des findings (DB exposée + colocation web/DB).
        ctx = data["context"]
        assert ctx["role"] != "unknown"
        # 3306 + (80, 22) => règle "DB exposée" CRITICAL + "DB + web colocalisés" HIGH.
        severities = {f["severity"] for f in ctx["findings"]}
        assert "CRITICAL" in severities

        # ── Premier scan : pas de baseline précédente → has_previous False ──
        assert data["baseline"]["has_previous"] is False
        assert data["baseline"]["alerts"] == []

        # ── Rapport HTML écrit + lisible ─────────────────────────────────────
        assert html_path is not None
        assert os.path.isfile(html_path)
        with open(html_path, encoding="utf-8") as f:
            html = f.read()
        assert "127.0.0.1" in html
        assert "OpenSSH"   in html
        assert "MySQL"     in html or "mysql" in html.lower()

    def test_deuxieme_scan_alimente_la_baseline(self, e2e_env):
        """Le diff vs scan précédent doit être renseigné au 2ᵉ passage."""
        scan, history = e2e_env
        with patch("scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("scan.subprocess.run", side_effect=self._patched_run):
            scan.lancer_scan("127.0.0.1")
            data2, _ = scan.lancer_scan("127.0.0.1")

        # 2ᵉ scan : baseline.has_previous doit être True maintenant.
        assert data2["baseline"]["has_previous"] is True
        # Scans identiques → 0 dérive.
        assert data2["baseline"]["summary"]["has_drift"] is False

        # SQLite contient bien les 2 entrées.
        rows = history.scans_for_ip("127.0.0.1")
        assert len(rows) == 2
        # Chaque row a une `data` complète (data_json roundtrip).
        assert rows[0]["data"]["ip"] == "127.0.0.1"
        assert "attack_summary" in rows[0]["data"]

    def test_xml_invalide_ne_casse_pas_le_pipeline(self, e2e_env):
        """Un Nmap qui sort du XML malformé doit dégrader proprement."""
        scan, _ = e2e_env

        def bad_run(*a, **kw):
            class _R:
                stdout = b"<not xml at all"
                stderr = b""
                returncode = 0
            return _R()

        with patch("scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("scan.subprocess.run", side_effect=bad_run):
            data, html_path = scan.lancer_scan("127.0.0.1")

        # XML invalide → host_up False, mais la chaîne complète a continué
        # à poser ses clés cohérentes (pas d'AttributeError ni de KeyError).
        assert data is not None
        assert data["host_up"] is False
        assert data["attack_summary"]["risk_level"] == "LOW"
        assert data["priority_summary"]["max_level"] == "INFO"
        assert data["context"]["role"] == "unknown"
        assert data["baseline"]["has_previous"] is False
        # Un rapport est tout de même généré (utile pour l'opérateur).
        assert html_path is not None
        assert os.path.isfile(html_path)
