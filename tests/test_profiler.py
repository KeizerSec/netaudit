"""
Tests unitaires pour src/profiler.py — classification de rôle et analyse posture.

Le module est pur (pas de réseau, pas d'I/O), donc les tests sont entièrement
hermétiques : on construit des `data` synthétiques et on vérifie les sorties.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from profiler import (
    ROLE_SIGNATURES,
    analyze_posture,
    classify_host,
    enrich_context,
    posture_score,
)


def _open_port(port, service="", version="", proto="tcp"):
    return {"port": port, "protocol": proto, "state": "open",
            "service": service, "version": version, "vulns": []}


class TestClassifyHost:
    def test_aucun_port_retourne_unknown(self):
        out = classify_host({"ports": []})
        assert out["role"] == "unknown"
        assert out["confidence"] == "none"
        assert out["score"] == 0.0

    def test_ports_fermes_ignores(self):
        data = {"ports": [
            {"port": 80, "state": "closed", "service": "http"},
            {"port": 3306, "state": "filtered", "service": "mysql"},
        ]}
        assert classify_host(data)["role"] == "unknown"

    def test_web_server_signature_simple(self):
        data = {"ports": [_open_port(80, "http"), _open_port(443, "https")]}
        out = classify_host(data)
        assert out["role"] == "web_server"
        assert out["confidence"] == "high"

    def test_database_signature_forte(self):
        data = {"ports": [_open_port(3306, "mysql"), _open_port(22, "ssh")]}
        out = classify_host(data)
        # MySQL (poids DB 4*1.2=4.8) > SSH (poids admin 2*0.9=1.8)
        assert out["role"] == "database"

    def test_confidence_low_quand_scores_proches(self):
        # Un setup mixte web+admin ne doit pas claim "high confidence".
        data = {"ports": [_open_port(80, "http"), _open_port(22, "ssh"), _open_port(3389, "ms-wbt-server")]}
        out = classify_host(data)
        assert out["confidence"] in {"low", "medium"}

    def test_signaux_expliquent_le_choix(self):
        data = {"ports": [_open_port(53, "domain", proto="udp")]}
        out = classify_host(data)
        assert out["role"] == "dns_server"
        assert any("53" in s for s in out["signals"])

    def test_voip_detecte(self):
        data = {"ports": [_open_port(5060, "sip"), _open_port(5061, "sip-tls")]}
        out = classify_host(data)
        assert out["role"] == "voip"

    def test_iot_device_detecte_mqtt(self):
        data = {"ports": [_open_port(1883, "mqtt")]}
        out = classify_host(data)
        assert out["role"] == "iot_device"

    def test_directory_services_ldap(self):
        data = {"ports": [_open_port(389, "ldap"), _open_port(88, "kerberos"), _open_port(636, "ldaps")]}
        out = classify_host(data)
        assert out["role"] == "directory_services"

    def test_scores_contient_seulement_roles_positifs(self):
        data = {"ports": [_open_port(80, "http")]}
        out = classify_host(data)
        # Scores expose uniquement les rôles avec score > 0.
        assert all(v > 0 for v in out["scores"].values())

    def test_robuste_aux_ports_mal_formes(self):
        data = {"ports": [{"bogus": True}, _open_port(80, "http"), None]}
        out = classify_host(data)
        assert out["role"] == "web_server"


class TestPostureRules:
    def test_db_exposed_declenche_critical(self):
        data = {"ports": [_open_port(3306, "mysql")]}
        findings = analyze_posture(data, "database")
        titles = [f["title"] for f in findings]
        assert any("Base(s) de données" in t for t in titles)
        # CRITICAL doit être remonté en tête.
        assert findings[0]["severity"] == "CRITICAL"

    def test_telnet_critical(self):
        data = {"ports": [_open_port(23, "telnet")]}
        findings = analyze_posture(data, "admin_host")
        assert any("Telnet" in f["title"] for f in findings)

    def test_ftp_clear_high(self):
        data = {"ports": [_open_port(21, "ftp", version="vsftpd 3.0.3")]}
        findings = analyze_posture(data, "file_server")
        assert any("FTP en clair" in f["title"] for f in findings)

    def test_ftps_ne_declenche_pas_ftp_rule(self):
        # Implémentation explicitement FTPS → faux positif évité.
        data = {"ports": [_open_port(21, "ftps", version="FTPS over TLS")]}
        findings = analyze_posture(data, "file_server")
        assert not any("FTP en clair" in f["title"] for f in findings)

    def test_tftp_high(self):
        data = {"ports": [_open_port(69, "tftp", proto="udp")]}
        findings = analyze_posture(data, "unknown")
        assert any("TFTP" in f["title"] for f in findings)

    def test_snmp_high(self):
        data = {"ports": [_open_port(161, "snmp", proto="udp")]}
        findings = analyze_posture(data, "monitoring")
        assert any("SNMP" in f["title"] for f in findings)

    def test_multi_admin_protocols(self):
        data = {"ports": [
            _open_port(22, "ssh"),
            _open_port(3389, "ms-wbt-server"),
        ]}
        findings = analyze_posture(data, "admin_host")
        assert any("administration multiple" in f["title"] for f in findings)

    def test_un_seul_admin_pas_de_finding(self):
        data = {"ports": [_open_port(22, "ssh")]}
        findings = analyze_posture(data, "admin_host")
        assert not any("administration multiple" in f["title"] for f in findings)

    def test_webserver_sans_https(self):
        data = {"ports": [_open_port(80, "http")]}
        findings = analyze_posture(data, "web_server")
        assert any("sans HTTPS" in f["title"] for f in findings)

    def test_webserver_avec_https_pas_de_finding(self):
        data = {"ports": [_open_port(80, "http"), _open_port(443, "https")]}
        findings = analyze_posture(data, "web_server")
        assert not any("sans HTTPS" in f["title"] for f in findings)

    def test_webserver_rule_ne_sapplique_que_si_role_correspond(self):
        # Rôle admin_host avec port 80 seul : pas de finding "web sans HTTPS".
        data = {"ports": [_open_port(80, "http")]}
        findings = analyze_posture(data, "admin_host")
        assert not any("sans HTTPS" in f["title"] for f in findings)

    def test_os_legacy_windows_xp(self):
        data = {"ports": [_open_port(445, "microsoft-ds")], "os_guess": "Microsoft Windows XP SP3"}
        findings = analyze_posture(data, "file_server")
        assert any("OS en fin de vie" in f["title"] for f in findings)

    def test_os_moderne_pas_de_finding(self):
        data = {"ports": [_open_port(22, "ssh")], "os_guess": "Linux 5.15.0-1 Ubuntu"}
        findings = analyze_posture(data, "admin_host")
        assert not any("OS en fin de vie" in f["title"] for f in findings)

    def test_too_many_ports(self):
        data = {"ports": [_open_port(1000 + i, f"svc{i}") for i in range(20)]}
        findings = analyze_posture(data, "unknown")
        assert any("Surface d'attaque élargie" in f["title"] for f in findings)

    def test_peu_de_ports_pas_de_finding(self):
        data = {"ports": [_open_port(80, "http"), _open_port(443, "https")]}
        findings = analyze_posture(data, "web_server")
        assert not any("Surface d'attaque élargie" in f["title"] for f in findings)

    def test_db_et_web_colocalisees(self):
        data = {"ports": [_open_port(80, "http"), _open_port(3306, "mysql")]}
        findings = analyze_posture(data, "web_server")
        assert any("colocalisée" in f["title"] for f in findings)

    def test_iot_avec_telnet_management(self):
        data = {"ports": [_open_port(1883, "mqtt"), _open_port(23, "telnet")]}
        findings = analyze_posture(data, "iot_device")
        # Double détection : Telnet (universelle) ET IoT management.
        assert any("IoT" in f["title"] for f in findings)

    def test_iot_rule_limited_to_iot_role(self):
        data = {"ports": [_open_port(7547, "cwmp")]}
        findings = analyze_posture(data, "admin_host")
        # CWMP sans rôle IoT → pas déclenché ici.
        assert not any("IoT" in f["title"] for f in findings)

    def test_unsupported_version_apache(self):
        data = {"ports": [_open_port(80, "http", version="Apache httpd 2.2.15")]}
        findings = analyze_posture(data, "web_server")
        assert any("non-supportée" in f["title"] for f in findings)

    def test_version_moderne_pas_de_finding(self):
        data = {"ports": [_open_port(80, "http", version="Apache httpd 2.4.54")]}
        findings = analyze_posture(data, "web_server")
        assert not any("non-supportée" in f["title"] for f in findings)

    def test_regex_boundary_nginx_1_20_pas_un_faux_positif(self):
        # Bug guard : "nginx 1.20" ne doit pas matcher marker "nginx 1.2".
        data = {"ports": [_open_port(80, "http", version="nginx 1.20 (Ubuntu)")]}
        findings = analyze_posture(data, "web_server")
        assert not any("non-supportée" in f["title"] for f in findings)

    def test_regex_boundary_openssh_8_pas_un_faux_positif(self):
        data = {"ports": [_open_port(22, "ssh", version="OpenSSH 8.2p1 Ubuntu")]}
        findings = analyze_posture(data, "admin_host")
        assert not any("non-supportée" in f["title"] for f in findings)


class TestPostureScore:
    def test_aucun_finding_100(self):
        assert posture_score([]) == 100

    def test_un_critical_penalise_25(self):
        assert posture_score([{"severity": "CRITICAL"}]) == 75

    def test_cumul_capped_a_0(self):
        findings = [{"severity": "CRITICAL"}] * 10  # -250 théorique
        assert posture_score(findings) == 0

    def test_info_ne_penalise_pas(self):
        assert posture_score([{"severity": "INFO"}, {"severity": "INFO"}]) == 100

    def test_severity_manquante_traitee_comme_info(self):
        # Robustesse : un dict sans severity ne doit pas crasher.
        assert posture_score([{}, {"severity": "LOW"}]) == 97


class TestEnrichContext:
    def test_context_ajoute_dans_data(self):
        data = {"ports": [_open_port(80, "http"), _open_port(443, "https")]}
        out = enrich_context(data)
        assert "context" in out
        assert out["context"]["role"] == "web_server"
        assert out["context"]["posture_score"] == 100
        assert out["context"]["posture_grade"] == "A"

    def test_summary_compte_par_severite(self):
        data = {"ports": [
            _open_port(3306, "mysql"),   # CRITICAL (DB exposed)
            _open_port(23, "telnet"),    # CRITICAL (telnet)
            _open_port(80, "http"),      # colocation DB+web → HIGH
        ]}
        ctx = enrich_context(data)["context"]
        assert ctx["summary"]["critical"] >= 2
        assert ctx["posture_grade"] in {"F", "D"}

    def test_unknown_hote_silencieux(self):
        data = {"ports": []}
        ctx = enrich_context(data)["context"]
        assert ctx["role"] == "unknown"
        assert ctx["posture_score"] == 100
        assert ctx["findings"] == []

    def test_findings_tries_par_severite(self):
        data = {"ports": [
            _open_port(80, "http"),              # MEDIUM (no TLS)
            _open_port(23, "telnet"),            # CRITICAL
            _open_port(3306, "mysql"),           # CRITICAL
        ]}
        ctx = enrich_context(data)["context"]
        severities = [f["severity"] for f in ctx["findings"]]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [order[s] for s in severities]
        assert ranks == sorted(ranks)

    def test_chaque_finding_contient_les_4_champs(self):
        data = {"ports": [_open_port(23, "telnet")]}
        ctx = enrich_context(data)["context"]
        for f in ctx["findings"]:
            assert {"severity", "title", "description", "recommendation", "evidence"} <= f.keys()


class TestIntegration:
    """Scénarios réalistes — vérifient que plusieurs règles s'enchaînent correctement."""

    def test_scenario_db_exposee_avec_web(self):
        data = {
            "ports": [
                _open_port(80, "http"),
                _open_port(443, "https"),
                _open_port(3306, "mysql", version="MySQL 8.0"),
            ],
            "os_guess": "Ubuntu 22.04",
        }
        ctx = enrich_context(data)["context"]
        titles = [f["title"] for f in ctx["findings"]]
        assert any("Base(s) de données" in t for t in titles)
        assert any("colocalisée" in t for t in titles)
        assert ctx["posture_score"] < 100

    def test_scenario_serveur_mail_clean(self):
        data = {"ports": [
            _open_port(25, "smtp", version="Postfix 3.7"),
            _open_port(465, "smtps"),
            _open_port(993, "imaps"),
        ]}
        ctx = enrich_context(data)["context"]
        assert ctx["role"] == "mail_server"
        # Scénario sain : pas de finding, grade A.
        assert ctx["posture_grade"] == "A"

    def test_scenario_iot_compromis(self):
        data = {"ports": [
            _open_port(23, "telnet"),
            _open_port(1883, "mqtt"),
            _open_port(7547, "cwmp"),
        ]}
        ctx = enrich_context(data)["context"]
        assert ctx["role"] == "iot_device"
        severities = {f["severity"] for f in ctx["findings"]}
        assert "CRITICAL" in severities
        assert ctx["posture_grade"] in {"C", "D", "F"}


def test_role_signatures_bien_formees():
    """Invariant structurel : chaque rôle déclare ports, services, weight numérique."""
    for role, sig in ROLE_SIGNATURES.items():
        assert isinstance(sig.get("ports"), dict), role
        assert isinstance(sig.get("services"), dict), role
        assert isinstance(sig.get("weight"), (int, float)), role
