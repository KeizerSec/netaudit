"""
Tests unitaires pour src/baseline.py — diff entre deux scans et alertes de dérive.

Les scans sont fabriqués en mémoire : pas de Nmap, pas de réseau, pas de base.
Chaque test exerce une règle de diff isolée (un port apparaît, une CVE patche,
un KEV escalade, etc.) puis vérifie que l'alerte attendue est présente avec
le bon niveau (critical/warning/neutral/positive).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import baseline  # noqa: E402


# ── Helpers de construction ──────────────────────────────────────────────────

def _port(num, service="", version="", protocol="tcp", state="open", vulns=None):
    return {
        "port":     num,
        "protocol": protocol,
        "state":    state,
        "service":  service,
        "version":  version,
        "vulns":    vulns or [],
    }


def _vuln(cve, score=5.0, kev=None):
    return {
        "id":    cve,
        "score": score,
        "url":   f"https://vulners.com/cve/{cve}",
        "kev":   kev,
    }


def _scan(ports=None, context=None):
    return {
        "ip":        "10.0.0.1",
        "scan_date": "2026-04-16 10:00:00 UTC",
        "host_up":   True,
        "ports":     ports or [],
        "context":   context or {},
    }


def _alert_types(result, level=None):
    alerts = result["alerts"]
    if level:
        alerts = [a for a in alerts if a["level"] == level]
    return [a["type"] for a in alerts]


# ── compare_scans — structure générale ──────────────────────────────────────

class TestCompareScansStructure:
    def test_schema_complet(self):
        result = baseline.compare_scans(_scan(), _scan())
        assert "changes" in result
        assert "alerts" in result
        assert "summary" in result
        # Toutes les catégories de changements doivent exister même si vides.
        for key in ("ports_added", "ports_removed", "version_changes",
                    "vulns_added", "vulns_removed", "kev_escalations",
                    "findings_new", "findings_resolved"):
            assert key in result["changes"]
        assert result["summary"]["total"] == 0
        assert result["summary"]["has_drift"] is False

    def test_aucune_modification(self):
        ports = [_port(22, "ssh", "OpenSSH 9.2")]
        result = baseline.compare_scans(_scan(ports), _scan(ports))
        assert result["alerts"] == []
        assert result["summary"]["total"] == 0

    def test_tri_des_alertes(self):
        # Un warning et un critical : critical doit sortir en premier.
        prev = _scan()
        cur = _scan([
            _port(3306, "mysql"),   # → critical (DB)
            _port(8080, "http"),    # → warning (port quelconque)
        ])
        result = baseline.compare_scans(cur, prev)
        levels = [a["level"] for a in result["alerts"]]
        assert levels[0] == "critical"


# ── Diff ports ───────────────────────────────────────────────────────────────

class TestPortDiff:
    def test_port_db_ajoute_critical(self):
        prev = _scan()
        cur = _scan([_port(3306, "mysql")])
        result = baseline.compare_scans(cur, prev)
        assert "port_added" in _alert_types(result, level="critical")

    def test_port_admin_ajoute_critical(self):
        prev = _scan()
        cur = _scan([_port(23, "telnet")])
        result = baseline.compare_scans(cur, prev)
        assert "port_added" in _alert_types(result, level="critical")

    def test_port_quelconque_ajoute_warning(self):
        prev = _scan()
        cur = _scan([_port(8080, "http")])
        result = baseline.compare_scans(cur, prev)
        assert "port_added" in _alert_types(result, level="warning")

    def test_port_ferme_positive(self):
        prev = _scan([_port(8080, "http")])
        cur = _scan()
        result = baseline.compare_scans(cur, prev)
        types = _alert_types(result, level="positive")
        assert "port_removed" in types

    def test_protocole_distingue(self):
        # 80/tcp et 80/udp sont deux entités distinctes.
        prev = _scan([_port(80, "http", protocol="tcp")])
        cur = _scan([_port(80, "http", protocol="tcp"),
                     _port(80, "http", protocol="udp")])
        result = baseline.compare_scans(cur, prev)
        added = result["changes"]["ports_added"]
        assert len(added) == 1
        assert added[0]["protocol"] == "udp"

    def test_port_ferme_ignore_si_state_filtered(self):
        # Un port `filtered` ne doit pas compter comme "ouvert" avant/après.
        prev = _scan([_port(22, "ssh", state="filtered")])
        cur = _scan()
        result = baseline.compare_scans(cur, prev)
        assert result["changes"]["ports_removed"] == []


class TestVersionChange:
    def test_version_changee_sur_port_sensible_warning(self):
        prev = _scan([_port(22, "ssh", "OpenSSH 9.2")])
        cur = _scan([_port(22, "ssh", "OpenSSH 8.0")])
        result = baseline.compare_scans(cur, prev)
        warnings = [a for a in result["alerts"] if a["type"] == "version_change"]
        assert warnings and warnings[0]["level"] == "warning"

    def test_version_changee_sur_port_banal_neutral(self):
        prev = _scan([_port(12345, "x", "1.0")])
        cur = _scan([_port(12345, "x", "1.1")])
        result = baseline.compare_scans(cur, prev)
        changes = [a for a in result["alerts"] if a["type"] == "version_change"]
        assert changes and changes[0]["level"] == "neutral"

    def test_version_identique_aucune_alerte(self):
        prev = _scan([_port(22, "ssh", "OpenSSH 9.2")])
        cur = _scan([_port(22, "ssh", "OpenSSH 9.2")])
        result = baseline.compare_scans(cur, prev)
        assert not any(a["type"] == "version_change" for a in result["alerts"])

    def test_version_toutes_vides_ignore(self):
        prev = _scan([_port(22, "ssh", "")])
        cur = _scan([_port(22, "ssh", "")])
        result = baseline.compare_scans(cur, prev)
        assert not any(a["type"] == "version_change" for a in result["alerts"])


# ── Diff vulnérabilités ──────────────────────────────────────────────────────

class TestVulnDiff:
    def test_cve_critique_ajoutee_warning(self):
        # CVSS ≥ 7 sans KEV → warning.
        prev = _scan([_port(80, "http")])
        cur = _scan([_port(80, "http", vulns=[_vuln("CVE-2024-0001", score=8.5)])])
        result = baseline.compare_scans(cur, prev)
        adds = [a for a in result["alerts"] if a["type"] == "vuln_added"]
        assert adds and adds[0]["level"] == "warning"

    def test_cve_kev_ajoutee_critical(self):
        prev = _scan([_port(80, "http")])
        cur = _scan([_port(80, "http", vulns=[
            _vuln("CVE-2024-0002", score=9.8, kev={"ransomware": False, "due_date": "", "short_desc": ""})
        ])])
        result = baseline.compare_scans(cur, prev)
        adds = [a for a in result["alerts"] if a["type"] == "vuln_added"]
        assert adds and adds[0]["level"] == "critical"

    def test_cve_ransomware_ajoutee_critical(self):
        prev = _scan([_port(80, "http")])
        cur = _scan([_port(80, "http", vulns=[
            _vuln("CVE-2024-0003", score=9.8, kev={"ransomware": True, "due_date": "", "short_desc": ""})
        ])])
        result = baseline.compare_scans(cur, prev)
        adds = [a for a in result["alerts"] if a["type"] == "vuln_added"]
        assert adds and "ransomware" in adds[0]["title"].lower()
        assert adds[0]["level"] == "critical"

    def test_cve_basse_ajoutee_neutral(self):
        prev = _scan([_port(80, "http")])
        cur = _scan([_port(80, "http", vulns=[_vuln("CVE-2024-0004", score=4.0)])])
        result = baseline.compare_scans(cur, prev)
        adds = [a for a in result["alerts"] if a["type"] == "vuln_added"]
        assert adds and adds[0]["level"] == "neutral"

    def test_cve_patche_positive(self):
        prev = _scan([_port(80, "http", vulns=[_vuln("CVE-2024-9999", score=9.8)])])
        cur = _scan([_port(80, "http")])
        result = baseline.compare_scans(cur, prev)
        removals = [a for a in result["alerts"] if a["type"] == "vuln_removed"]
        assert removals and removals[0]["level"] == "positive"

    def test_kev_escalation_critical(self):
        # CVE présente dans les deux scans, pas dans KEV avant, KEV maintenant.
        prev = _scan([_port(443, "https", vulns=[_vuln("CVE-2024-5555", score=7.5, kev=None)])])
        cur = _scan([_port(443, "https", vulns=[_vuln(
            "CVE-2024-5555", score=7.5,
            kev={"ransomware": False, "due_date": "2026-05-01", "short_desc": ""},
        )])])
        result = baseline.compare_scans(cur, prev)
        escalations = [a for a in result["alerts"] if a["type"] == "kev_escalation"]
        assert escalations and escalations[0]["level"] == "critical"

    def test_cve_deja_presente_sans_changement_kev(self):
        # Pas d'alerte si la CVE était déjà là sans bascule KEV.
        vuln = _vuln("CVE-2024-7777", score=6.0)
        prev = _scan([_port(443, "https", vulns=[vuln])])
        cur = _scan([_port(443, "https", vulns=[vuln])])
        result = baseline.compare_scans(cur, prev)
        assert not any(a["type"] in ("vuln_added", "vuln_removed", "kev_escalation")
                       for a in result["alerts"])


# ── Findings et posture ──────────────────────────────────────────────────────

def _ctx(role="web_server", confidence="high", score=100, grade="A", findings=None):
    return {
        "role":            role,
        "role_confidence": confidence,
        "posture_score":   score,
        "posture_grade":   grade,
        "findings":        findings or [],
    }


class TestFindingsDiff:
    def test_finding_critical_ajoute_critical(self):
        prev_ctx = _ctx(findings=[])
        cur_ctx = _ctx(findings=[{"severity": "CRITICAL", "title": "DB exposée"}])
        prev = _scan(context=prev_ctx)
        cur = _scan(context=cur_ctx)
        result = baseline.compare_scans(cur, prev)
        criticals = [a for a in result["alerts"] if a["type"] == "finding_new"]
        assert criticals and criticals[0]["level"] == "critical"

    def test_finding_high_ajoute_warning(self):
        prev = _scan(context=_ctx(findings=[]))
        cur = _scan(context=_ctx(findings=[{"severity": "HIGH", "title": "OS EOL"}]))
        result = baseline.compare_scans(cur, prev)
        adds = [a for a in result["alerts"] if a["type"] == "finding_new"]
        assert adds and adds[0]["level"] == "warning"

    def test_finding_medium_ajoute_neutral(self):
        prev = _scan(context=_ctx(findings=[]))
        cur = _scan(context=_ctx(findings=[{"severity": "MEDIUM", "title": "Ports nombreux"}]))
        result = baseline.compare_scans(cur, prev)
        adds = [a for a in result["alerts"] if a["type"] == "finding_new"]
        assert adds and adds[0]["level"] == "neutral"

    def test_finding_resolu_positive(self):
        prev = _scan(context=_ctx(findings=[{"severity": "HIGH", "title": "OS EOL"}]))
        cur = _scan(context=_ctx(findings=[]))
        result = baseline.compare_scans(cur, prev)
        resolved = [a for a in result["alerts"] if a["type"] == "finding_resolved"]
        assert resolved and resolved[0]["level"] == "positive"

    def test_identite_findings_cle_composite(self):
        # Même titre + même sévérité → considéré identique.
        f = {"severity": "HIGH", "title": "OS EOL"}
        prev = _scan(context=_ctx(findings=[f]))
        cur = _scan(context=_ctx(findings=[f]))
        result = baseline.compare_scans(cur, prev)
        assert not any(a["type"] in ("finding_new", "finding_resolved") for a in result["alerts"])


class TestPostureDrift:
    def test_chute_importante_critical(self):
        prev = _scan(context=_ctx(score=90, grade="A"))
        cur = _scan(context=_ctx(score=60, grade="C"))  # -30
        result = baseline.compare_scans(cur, prev)
        posture = [a for a in result["alerts"] if a["type"] == "posture_change"]
        assert posture and posture[0]["level"] == "critical"

    def test_chute_moderee_warning(self):
        prev = _scan(context=_ctx(score=90, grade="A"))
        cur = _scan(context=_ctx(score=78, grade="B"))  # -12
        result = baseline.compare_scans(cur, prev)
        posture = [a for a in result["alerts"] if a["type"] == "posture_change"]
        assert posture and posture[0]["level"] == "warning"

    def test_chute_faible_neutral(self):
        prev = _scan(context=_ctx(score=90))
        cur = _scan(context=_ctx(score=87))  # -3
        result = baseline.compare_scans(cur, prev)
        posture = [a for a in result["alerts"] if a["type"] == "posture_change"]
        assert posture and posture[0]["level"] == "neutral"

    def test_amelioration_positive(self):
        prev = _scan(context=_ctx(score=60, grade="C"))
        cur = _scan(context=_ctx(score=80, grade="B"))  # +20
        result = baseline.compare_scans(cur, prev)
        posture = [a for a in result["alerts"] if a["type"] == "posture_change"]
        assert posture and posture[0]["level"] == "positive"

    def test_score_identique_pas_dalerte(self):
        prev = _scan(context=_ctx(score=75))
        cur = _scan(context=_ctx(score=75))
        result = baseline.compare_scans(cur, prev)
        assert not any(a["type"] == "posture_change" for a in result["alerts"])


class TestRoleChange:
    def test_changement_de_role_warning(self):
        prev = _scan(context=_ctx(role="web_server"))
        cur = _scan(context=_ctx(role="database"))
        result = baseline.compare_scans(cur, prev)
        role = [a for a in result["alerts"] if a["type"] == "role_change"]
        assert role and role[0]["level"] == "warning"

    def test_meme_role_aucune_alerte(self):
        prev = _scan(context=_ctx(role="web_server"))
        cur = _scan(context=_ctx(role="web_server"))
        result = baseline.compare_scans(cur, prev)
        assert not any(a["type"] == "role_change" for a in result["alerts"])


# ── enrich_baseline ──────────────────────────────────────────────────────────

class TestEnrichBaseline:
    def test_pas_de_scan_precedent(self):
        current = _scan([_port(22, "ssh")])
        baseline.enrich_baseline(current, None)
        assert "baseline" in current
        assert current["baseline"]["has_previous"] is False
        assert current["baseline"]["alerts"] == []
        assert current["baseline"]["summary"]["total"] == 0

    def test_scan_precedent_sans_data(self):
        # Record historique sans payload data → pas de baseline exploitable.
        current = _scan([_port(22, "ssh")])
        baseline.enrich_baseline(current, {"id": 1, "scan_date": "…", "data": None})
        assert current["baseline"]["has_previous"] is False

    def test_avec_precedent_remplit_baseline(self):
        prev_data = _scan([_port(80, "http")])
        prev_record = {"id": 42, "scan_date": "2026-04-15 10:00:00 UTC", "data": prev_data}
        current = _scan([_port(80, "http"), _port(3306, "mysql")])
        baseline.enrich_baseline(current, prev_record)
        assert current["baseline"]["has_previous"] is True
        assert current["baseline"]["previous_id"] == 42
        assert current["baseline"]["previous_date"] == "2026-04-15 10:00:00 UTC"
        # Un port DB ajouté → au moins une alerte critical.
        assert current["baseline"]["summary"]["critical"] >= 1

    def test_mutation_en_place(self):
        current = _scan()
        returned = baseline.enrich_baseline(current, None)
        assert returned is current  # retour de la même référence

    def test_pas_de_bloat_recursif(self):
        # Le scan précédent contient déjà sa propre baseline — on ne la recopie pas.
        prev_data = _scan([_port(80, "http")])
        prev_data["baseline"] = {"has_previous": False, "alerts": ["ancienne"]}
        prev_record = {"id": 1, "scan_date": "…", "data": prev_data}
        current = _scan([_port(80, "http")])
        baseline.enrich_baseline(current, prev_record)
        # Le baseline courant ne doit rien contenir qui ressemble à l'ancien.
        assert current["baseline"]["alerts"] != ["ancienne"]


# ── Scénarios combinés ───────────────────────────────────────────────────────

class TestScenariosCombines:
    def test_scenario_compromission_apparente(self):
        """Hôte stable → apparition d'un port DB + nouvelle CVE KEV + chute posture."""
        prev = _scan(
            [_port(443, "https", "nginx 1.24", vulns=[])],
            _ctx(role="web_server", score=90, grade="A", findings=[]),
        )
        cur = _scan(
            [
                _port(443, "https", "nginx 1.24"),
                _port(3306, "mysql", "MySQL 8.0", vulns=[
                    _vuln("CVE-2024-XXXX", score=9.5,
                          kev={"ransomware": True, "due_date": "2026-06-01", "short_desc": ""}),
                ]),
            ],
            _ctx(role="web_server", score=55, grade="C",
                 findings=[
                     {"severity": "CRITICAL", "title": "DB exposée"},
                     {"severity": "HIGH",     "title": "Web + DB colocalisés"},
                 ]),
        )
        result = baseline.compare_scans(cur, prev)
        # Au moins un port_added critical (DB), un vuln_added critical (ransomware),
        # un finding_new critical, une posture_change critical.
        types_crit = [a["type"] for a in result["alerts"] if a["level"] == "critical"]
        assert "port_added" in types_crit
        assert "vuln_added" in types_crit
        assert "finding_new" in types_crit
        assert "posture_change" in types_crit
        assert result["summary"]["has_drift"] is True
        assert result["summary"]["critical"] >= 4

    def test_scenario_remediation(self):
        """Hôte dégradé → tout est nettoyé : ports fermés, CVE patchée, posture up."""
        prev = _scan(
            [
                _port(23, "telnet"),
                _port(80, "http", vulns=[_vuln("CVE-2023-1234", score=8.0)]),
            ],
            _ctx(score=40, grade="D", findings=[
                {"severity": "CRITICAL", "title": "Telnet actif"},
            ]),
        )
        cur = _scan(
            [_port(80, "http")],
            _ctx(score=90, grade="A", findings=[]),
        )
        result = baseline.compare_scans(cur, prev)
        positives = [a for a in result["alerts"] if a["level"] == "positive"]
        types = {a["type"] for a in positives}
        assert "port_removed" in types
        assert "vuln_removed" in types
        assert "finding_resolved" in types
        assert "posture_change" in types
        assert result["summary"]["positive"] >= 4

    def test_scenario_stabilite_complete(self):
        ports = [
            _port(22, "ssh", "OpenSSH 9.2"),
            _port(443, "https", "nginx 1.24"),
        ]
        ctx = _ctx(role="web_server", score=85, grade="B",
                   findings=[{"severity": "MEDIUM", "title": "trop de ports"}])
        scan = _scan(ports, ctx)
        result = baseline.compare_scans(scan, scan)
        assert result["alerts"] == []
        assert result["summary"]["has_drift"] is False
