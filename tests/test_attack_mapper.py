"""
tests/test_attack_mapper.py — Tests unitaires pour attack_mapper.py
"""

import sys
import os

# Assurer que src/ est dans le path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from attack_mapper import (
    _map_service_techniques,
    _map_cve_techniques,
    _map_cwe_techniques,
    _map_known_cve_techniques,
    _heuristic_cve_techniques,
    _deduplicate_techniques,
    _calculate_risk_level,
    _generate_attack_path,
    _generate_detection_priorities,
    enrich_scan_result,
    _TECHNIQUES,
    _KILL_CHAIN,
    _TACTIC_NARRATIVES,
    _SERVICE_MAPPING,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _make_port(port=22, protocol="tcp", state="open", service="ssh",
               version="OpenSSH 7.6", vulns=None):
    return {
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": service,
        "version": version,
        "vulns": vulns or [],
    }


def _make_scan(ports=None, host_up=True):
    return {
        "ip": "192.168.1.1",
        "scan_date": "2024-01-01 00:00:00 UTC",
        "host_up": host_up,
        "ports": ports or [],
        "total_vulns": 0,
        "raw": "",
    }


# ─── Tests _map_service_techniques ───────────────────────────────────────────

class TestMapServiceTechniques:

    def test_ssh_by_name(self):
        techs = _map_service_techniques(22, "ssh")
        ids = [t["id"] for t in techs]
        assert "T1021.004" in ids
        assert "T1133" in ids
        assert "T1110" in ids

    def test_http_by_name(self):
        techs = _map_service_techniques(80, "http")
        ids = [t["id"] for t in techs]
        assert "T1190" in ids
        assert "T1505.003" in ids

    def test_smb_by_name(self):
        techs = _map_service_techniques(445, "smb")
        ids = [t["id"] for t in techs]
        assert "T1021.002" in ids
        assert "T1210" in ids

    def test_rdp_by_port(self):
        # rdp est dans service_mapping sous "rdp", port 3389
        techs = _map_service_techniques(3389, "rdp")
        ids = [t["id"] for t in techs]
        assert "T1021.001" in ids
        assert "T1133" in ids

    def test_mysql_by_port(self):
        techs = _map_service_techniques(3306, "mysql")
        assert len(techs) > 0
        assert all(t["confidence"] == "high" for t in techs)

    def test_unknown_service_and_port(self):
        techs = _map_service_techniques(9999, "unknown-proto")
        assert techs == []

    def test_source_contains_port_and_service(self):
        techs = _map_service_techniques(22, "ssh")
        for t in techs:
            assert "22" in t["source"]

    def test_all_results_are_dicts(self):
        techs = _map_service_techniques(80, "http")
        for t in techs:
            assert isinstance(t, dict)
            assert "id" in t
            assert "confidence" in t
            assert "source" in t


# ─── Tests _map_cve_techniques ───────────────────────────────────────────────

class TestMapCveTechniques:

    def test_critical_web_maps_t1190(self):
        techs = _map_cve_techniques("CVE-2021-0001", 9.8, "http", 80)
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_critical_web_confidence_high(self):
        techs = _map_cve_techniques("CVE-2021-0001", 9.8, "http", 80)
        t1190 = next(t for t in techs if t["id"] == "T1190")
        assert t1190["confidence"] == "high"

    def test_critical_web_maps_t1059_medium(self):
        techs = _map_cve_techniques("CVE-2021-0001", 9.8, "http", 80)
        ids = [t["id"] for t in techs]
        assert "T1059" in ids
        t1059 = next(t for t in techs if t["id"] == "T1059")
        assert t1059["confidence"] == "medium"

    def test_critical_smb_maps_t1210(self):
        techs = _map_cve_techniques("CVE-2017-0144", 9.3, "smb", 445)
        ids = [t["id"] for t in techs]
        assert "T1210" in ids

    def test_critical_smb_does_not_map_t1059(self):
        techs = _map_cve_techniques("CVE-2017-0144", 9.3, "smb", 445)
        ids = [t["id"] for t in techs]
        assert "T1059" not in ids

    def test_critical_generic_maps_t1190(self):
        techs = _map_cve_techniques("CVE-2020-9999", 9.5, "unknown", 12345)
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_high_score_maps_t1078_and_t1068(self):
        techs = _map_cve_techniques("CVE-2020-0001", 7.5, "ssh", 22)
        ids = [t["id"] for t in techs]
        assert "T1078" in ids
        assert "T1068" in ids

    def test_high_web_also_maps_t1190(self):
        techs = _map_cve_techniques("CVE-2020-0001", 8.0, "http", 80)
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_medium_score_maps_t1082(self):
        techs = _map_cve_techniques("CVE-2020-0001", 5.0, "http", 80)
        ids = [t["id"] for t in techs]
        assert "T1082" in ids

    def test_medium_score_confidence_low(self):
        techs = _map_cve_techniques("CVE-2020-0001", 5.0, "http", 80)
        for t in techs:
            assert t["confidence"] == "low"

    def test_low_score_returns_empty(self):
        techs = _map_cve_techniques("CVE-2020-0001", 2.0, "http", 80)
        assert techs == []

    def test_boundary_exactly_9(self):
        techs = _map_cve_techniques("CVE-X", 9.0, "http", 80)
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_boundary_exactly_7(self):
        techs = _map_cve_techniques("CVE-X", 7.0, "ssh", 22)
        ids = [t["id"] for t in techs]
        assert "T1078" in ids

    def test_boundary_exactly_4(self):
        techs = _map_cve_techniques("CVE-X", 4.0, "ssh", 22)
        ids = [t["id"] for t in techs]
        assert "T1082" in ids

    def test_source_contains_cve_id(self):
        techs = _map_cve_techniques("CVE-2021-1234", 9.0, "http", 80)
        for t in techs:
            assert "CVE-2021-1234" in t["source"]


# ─── Tests _map_cwe_techniques ────────────────────────────────────────────────

class TestMapCweTechniques:

    def test_sql_injection_cwe_maps_t1190(self):
        techs = _map_cwe_techniques("CWE-89", "CVE-test")
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_os_command_injection_maps_t1059_and_t1190(self):
        techs = _map_cwe_techniques("CWE-78", "CVE-test")
        ids = [t["id"] for t in techs]
        assert "T1059" in ids
        assert "T1190" in ids

    def test_deserialization_maps_t1190(self):
        techs = _map_cwe_techniques("CWE-502", "CVE-test")
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_hardcoded_credentials_maps_t1078_and_t1552(self):
        techs = _map_cwe_techniques("CWE-798", "CVE-test")
        ids = [t["id"] for t in techs]
        assert "T1078" in ids
        assert "T1552" in ids

    def test_unknown_cwe_returns_empty(self):
        assert _map_cwe_techniques("CWE-99999", "CVE-test") == []

    def test_confidence_propagated_from_catalog(self):
        # CWE-89 (SQLi) → T1190 en confiance haute
        techs = _map_cwe_techniques("CWE-89", "CVE-test")
        t1190 = next(t for t in techs if t["id"] == "T1190")
        assert t1190["confidence"] == "high"

    def test_source_transmise(self):
        techs = _map_cwe_techniques("CWE-89", "my-custom-source")
        assert all(t["source"] == "my-custom-source" for t in techs)


# ─── Tests _map_known_cve_techniques ──────────────────────────────────────────

class TestMapKnownCveTechniques:

    def test_log4shell_maps_via_cwe_502(self):
        techs = _map_known_cve_techniques("CVE-2021-44228")
        ids = [t["id"] for t in techs]
        # CWE-502 → T1190 (high) + T1059 (medium)
        assert "T1190" in ids

    def test_heartbleed_maps_via_cwe_125(self):
        techs = _map_known_cve_techniques("CVE-2014-0160")
        ids = [t["id"] for t in techs]
        # CWE-125 → T1082 (medium)
        assert "T1082" in ids

    def test_shellshock_maps_via_cwe_78(self):
        techs = _map_known_cve_techniques("CVE-2014-6271")
        ids = [t["id"] for t in techs]
        assert "T1059" in ids
        assert "T1190" in ids

    def test_eternalblue_maps_via_cwe_119(self):
        techs = _map_known_cve_techniques("CVE-2017-0144")
        ids = [t["id"] for t in techs]
        # CWE-119 → T1190 (high) + T1068 (medium)
        assert "T1190" in ids
        assert "T1068" in ids

    def test_unknown_cve_returns_empty(self):
        assert _map_known_cve_techniques("CVE-9999-99999") == []

    def test_case_insensitive_lookup(self):
        # Le catalogue normalise en majuscules
        techs = _map_known_cve_techniques("cve-2021-44228")
        assert len(techs) > 0

    def test_source_mentionne_le_nom_commun(self):
        techs = _map_known_cve_techniques("CVE-2021-44228")
        # "Log4Shell" doit figurer dans la source pour être lisible
        assert any("Log4Shell" in t["source"] for t in techs)


# ─── Tests _map_cve_techniques (orchestrateur) ────────────────────────────────

class TestMapCveTechniquesOrchestrator:

    def test_known_cve_combines_cwe_and_heuristic(self):
        # CVE-2017-0144 (EternalBlue) sur SMB 445
        # Attendu : CWE-119 → T1190, T1068  +  heuristique SMB → T1210, T1021.002
        techs = _map_cve_techniques("CVE-2017-0144", 9.3, "smb", 445)
        ids = [t["id"] for t in techs]
        assert "T1068" in ids   # vient du mapping CWE
        assert "T1210" in ids   # vient de l'heuristique SMB

    def test_unknown_cve_falls_back_to_heuristic_only(self):
        techs = _map_cve_techniques("CVE-9999-0001", 9.8, "http", 80)
        ids = [t["id"] for t in techs]
        assert "T1190" in ids

    def test_known_cve_preserves_heuristic_behavior(self):
        # Même test que TestMapCveTechniques.test_critical_smb_maps_t1210
        # doit continuer à fonctionner malgré l'ajout du chemin CWE
        techs = _map_cve_techniques("CVE-2017-0144", 9.3, "smb", 445)
        ids = [t["id"] for t in techs]
        assert "T1210" in ids


# ─── Tests _deduplicate_techniques ───────────────────────────────────────────

class TestDeduplicateTechniques:

    def _tech(self, tech_id, confidence, source):
        return {
            "id": tech_id,
            "name": tech_id,
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "description": "",
            "detection": "",
            "url": "",
            "confidence": confidence,
            "source": source,
        }

    def test_dedup_removes_duplicate_ids(self):
        techs = [
            self._tech("T1190", "high", "http"),
            self._tech("T1190", "medium", "CVE-2021-0001"),
        ]
        result = _deduplicate_techniques(techs)
        assert len(result) == 1
        assert result[0]["id"] == "T1190"

    def test_dedup_keeps_highest_confidence(self):
        techs = [
            self._tech("T1190", "low", "source-a"),
            self._tech("T1190", "high", "source-b"),
            self._tech("T1190", "medium", "source-c"),
        ]
        result = _deduplicate_techniques(techs)
        assert result[0]["confidence"] == "high"

    def test_dedup_accumulates_sources(self):
        techs = [
            self._tech("T1190", "high", "source-a"),
            self._tech("T1190", "medium", "source-b"),
        ]
        result = _deduplicate_techniques(techs)
        assert "source-a" in result[0]["source"]
        assert "source-b" in result[0]["source"]

    def test_dedup_max_3_sources(self):
        techs = [self._tech("T1190", "high", f"source-{i}") for i in range(5)]
        result = _deduplicate_techniques(techs)
        # Sources max 3, séparées par " / "
        assert result[0]["source"].count(" / ") <= 2

    def test_dedup_preserves_unique_techniques(self):
        techs = [
            self._tech("T1190", "high", "http"),
            self._tech("T1078", "medium", "ssh"),
        ]
        result = _deduplicate_techniques(techs)
        assert len(result) == 2

    def test_dedup_empty_input(self):
        assert _deduplicate_techniques([]) == []


# ─── Tests _calculate_risk_level ─────────────────────────────────────────────

class TestCalculateRiskLevel:

    def _tech(self, tactic_id):
        return {"id": "T1000", "tactic_id": tactic_id, "confidence": "high"}

    def test_critical_initial_plus_privesc(self):
        techs = [self._tech("TA0001"), self._tech("TA0004")]
        assert _calculate_risk_level(techs) == "CRITICAL"

    def test_critical_initial_plus_impact(self):
        techs = [self._tech("TA0001"), self._tech("TA0040")]
        assert _calculate_risk_level(techs) == "CRITICAL"

    def test_high_initial_plus_exec(self):
        techs = [self._tech("TA0001"), self._tech("TA0002")]
        assert _calculate_risk_level(techs) == "HIGH"

    def test_high_initial_plus_lateral(self):
        techs = [self._tech("TA0001"), self._tech("TA0008")]
        assert _calculate_risk_level(techs) == "HIGH"

    def test_high_initial_plus_3_tactics(self):
        techs = [self._tech("TA0001"), self._tech("TA0006"), self._tech("TA0007")]
        assert _calculate_risk_level(techs) == "HIGH"

    def test_medium_initial_alone(self):
        techs = [self._tech("TA0001")]
        assert _calculate_risk_level(techs) == "MEDIUM"

    def test_medium_lateral_without_initial(self):
        techs = [self._tech("TA0008")]
        assert _calculate_risk_level(techs) == "MEDIUM"

    def test_low_discovery_only(self):
        techs = [self._tech("TA0007")]
        assert _calculate_risk_level(techs) == "LOW"

    def test_low_credential_only(self):
        techs = [self._tech("TA0006")]
        assert _calculate_risk_level(techs) == "LOW"

    def test_low_empty(self):
        assert _calculate_risk_level([]) == "LOW"


# ─── Tests _generate_attack_path ─────────────────────────────────────────────

class TestGenerateAttackPath:

    def _tech(self, tech_id, tactic_id, tactic_name, confidence="high"):
        return {
            "id": tech_id,
            "name": tech_id,
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "description": "",
            "detection": "Monitor logs",
            "url": "",
            "confidence": confidence,
            "source": "test",
        }

    def test_phases_ordered_by_kill_chain(self):
        techs = [
            self._tech("T1082", "TA0007", "Discovery"),       # position 6
            self._tech("T1190", "TA0001", "Initial Access"),  # position 0
        ]
        result = _generate_attack_path(techs)
        tactic_ids = [p["tactic_id"] for p in result["phases"]]
        assert tactic_ids.index("TA0001") < tactic_ids.index("TA0007")

    def test_phases_count_matches(self):
        techs = [
            self._tech("T1190", "TA0001", "Initial Access"),
            self._tech("T1078", "TA0006", "Credential Access"),
        ]
        result = _generate_attack_path(techs)
        assert result["phases_count"] == len(result["phases"]) == 2

    def test_risk_level_present(self):
        techs = [self._tech("T1190", "TA0001", "Initial Access")]
        result = _generate_attack_path(techs)
        assert result["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_detection_priorities_present(self):
        techs = [self._tech("T1190", "TA0001", "Initial Access")]
        result = _generate_attack_path(techs)
        assert "detection_priorities" in result
        assert isinstance(result["detection_priorities"], list)

    def test_detection_priorities_max_5(self):
        # 10 techniques différentes
        techs = [
            self._tech(f"T100{i}", "TA0001", "Initial Access") for i in range(10)
        ]
        result = _generate_attack_path(techs)
        assert len(result["detection_priorities"]) <= 5

    def test_empty_techniques_returns_no_phases(self):
        result = _generate_attack_path([])
        assert result["phases"] == []
        assert result["phases_count"] == 0
        assert result["risk_level"] == "LOW"

    def test_techniques_in_phase_sorted_high_first(self):
        techs = [
            self._tech("T1190", "TA0001", "Initial Access", confidence="low"),
            self._tech("T1133", "TA0001", "Initial Access", confidence="high"),
            self._tech("T1078", "TA0001", "Initial Access", confidence="medium"),
        ]
        result = _generate_attack_path(techs)
        phase = result["phases"][0]
        confidences = [t["confidence"] for t in phase["techniques"]]
        # "high" doit être en premier
        assert confidences[0] == "high"

    def test_phase_has_narrative(self):
        techs = [self._tech("T1190", "TA0001", "Initial Access")]
        result = _generate_attack_path(techs)
        phase = result["phases"][0]
        assert "narrative" in phase
        assert len(phase["narrative"]) > 0


# ─── Tests enrich_scan_result ─────────────────────────────────────────────────

# ─── Tests d'intégrité du catalogue ATT&CK ────────────────────────────────────

class TestCatalogIntegrity:
    """Garde-fous sur techniques.json et le kill chain — détecte les régressions
    lors de l'ajout ou du nettoyage du catalogue."""

    def test_catalog_contient_au_moins_75_techniques(self):
        # Le catalogue a été étendu en 2.5.0 (62 → 79). On garde une marge de
        # sécurité pour tolérer de petits nettoyages ultérieurs, mais tout
        # retour sous 75 indique une régression majeure.
        assert len(_TECHNIQUES) >= 75

    def test_toutes_techniques_ont_champs_obligatoires(self):
        required = {"id", "name", "tactic_id", "tactic_name",
                    "description", "detection", "mitigations", "url"}
        for tid, data in _TECHNIQUES.items():
            missing = required - set(data.keys())
            assert not missing, f"{tid} manque {missing}"

    def test_toutes_techniques_referencent_une_tactique_connue(self):
        valid_tactics = {tid for tid, _ in _KILL_CHAIN}
        for tid, data in _TECHNIQUES.items():
            assert data["tactic_id"] in valid_tactics, \
                f"{tid} référence une tactique absente du kill chain : {data['tactic_id']}"

    def test_kill_chain_inclut_les_14_tactiques_standards(self):
        expected = {"TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
                    "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
                    "TA0010", "TA0040"}
        actual = {tid for tid, _ in _KILL_CHAIN}
        assert actual == expected

    def test_kill_chain_ordre_recon_avant_impact(self):
        order = [tid for tid, _ in _KILL_CHAIN]
        assert order.index("TA0043") < order.index("TA0001")
        assert order.index("TA0001") < order.index("TA0040")

    def test_chaque_tactique_a_une_narrative(self):
        for tid, _ in _KILL_CHAIN:
            assert tid in _TACTIC_NARRATIVES, f"Narrative manquante pour {tid}"
            assert len(_TACTIC_NARRATIVES[tid]) > 20

    def test_mitigations_propagees_dans_entry(self):
        # Une technique qui a des mitigations dans le catalogue doit les
        # exposer dans le dict de sortie de _map_service_techniques
        techs = _map_service_techniques(22, "ssh")
        assert any(t.get("mitigations", "").strip() for t in techs)

    @pytest.mark.parametrize("tid", [
        # Techniques AD / Windows ajoutées en 2.5.0 — garde-fou anti-régression
        "T1557", "T1558", "T1558.003", "T1558.004", "T1187", "T1550",
        "T1482", "T1087", "T1484.001", "T1134", "T1021.006",
        # Techniques cloud / container
        "T1609", "T1610",
        # Autres expansions
        "T1505.001", "T1105", "T1490", "T1056",
    ])
    def test_techniques_prioritaires_2_5_0_presentes(self, tid):
        assert tid in _TECHNIQUES, f"{tid} absent du catalogue 2.5.0"


class TestServiceCatalogIntegrity:
    """Garde-fous sur service_mapping.json — détecte les régressions sur la
    couverture des services scannés."""

    def test_catalog_contient_au_moins_45_services(self):
        # 2.5.0 ajoute ~16 services modernes (cloud, AD-Kerberos, IoT/OT) :
        # de 30 à 47. Un retour sous 45 indique une régression.
        assert len(_SERVICE_MAPPING) >= 45

    @pytest.mark.parametrize("service", [
        # Kerberos / AD
        "kerberos", "globalcatalog", "winrm", "rpcbind",
        # Cloud / secrets
        "etcd", "vault", "consul", "kibana",
        # Mgmt / data
        "splunk", "rabbitmq-mgmt", "activemq", "zookeeper", "hadoop",
        # Hardware / IoT / ICS
        "ipmi", "mqtt", "modbus", "x11",
    ])
    def test_services_prioritaires_2_5_0_presents(self, service):
        assert service in _SERVICE_MAPPING, f"Service {service} absent du mapping 2.5.0"

    def test_toutes_references_techniques_valides(self):
        """Chaque technique référencée dans service_mapping doit exister dans techniques.json."""
        missing = []
        for svc, info in _SERVICE_MAPPING.items():
            for tid in info.get("techniques", []):
                if tid not in _TECHNIQUES:
                    missing.append(f"{svc} → {tid}")
        assert not missing, f"Références cassées : {missing}"


class TestEnrichScanResult:

    def test_host_down_returns_low_risk(self):
        data = _make_scan(host_up=False)
        result = enrich_scan_result(data)
        assert result["attack_summary"]["risk_level"] == "LOW"
        assert result["attack_summary"]["phases"] == []

    def test_no_ports_returns_low_risk(self):
        data = _make_scan(ports=[])
        result = enrich_scan_result(data)
        assert result["attack_summary"]["risk_level"] == "LOW"

    def test_ssh_port_adds_service_techniques(self):
        port = _make_port(22, service="ssh", state="open")
        data = _make_scan(ports=[port])
        result = enrich_scan_result(data)
        techs = result["ports"][0].get("service_techniques", [])
        assert len(techs) > 0

    def test_closed_port_skipped(self):
        port = _make_port(22, service="ssh", state="closed")
        data = _make_scan(ports=[port])
        result = enrich_scan_result(data)
        techs = result["ports"][0].get("service_techniques", [])
        assert techs == []

    def test_attack_summary_added(self):
        port = _make_port(80, service="http", state="open")
        data = _make_scan(ports=[port])
        result = enrich_scan_result(data)
        assert "attack_summary" in result
        assert "phases" in result["attack_summary"]
        assert "risk_level" in result["attack_summary"]

    def test_vuln_gets_attack_techniques(self):
        vuln = {"id": "CVE-2021-0001", "score": 9.8, "url": "https://vuln.example.com"}
        port = _make_port(80, service="http", state="open", vulns=[vuln])
        data = _make_scan(ports=[port])
        result = enrich_scan_result(data)
        assert "attack_techniques" in result["ports"][0]["vulns"][0]

    def test_multiple_ports_aggregated(self):
        ports = [
            _make_port(22, service="ssh", state="open"),
            _make_port(80, service="http", state="open"),
            _make_port(445, service="smb", state="open"),
        ]
        data = _make_scan(ports=ports)
        result = enrich_scan_result(data)
        # Plusieurs tactiques → risque élevé
        assert result["attack_summary"]["risk_level"] in {"CRITICAL", "HIGH"}

    def test_original_data_preserved(self):
        port = _make_port(22, service="ssh", state="open")
        data = _make_scan(ports=[port])
        result = enrich_scan_result(data)
        assert result["ip"] == "192.168.1.1"
        assert result["host_up"] is True

    def test_does_not_raise_on_malformed_data(self):
        # Données malformées : pas d'exception attendue
        data = {"host_up": True, "ports": [{"state": "open"}]}
        result = enrich_scan_result(data)
        assert "attack_summary" in result

    def test_http_port_triggers_initial_access(self):
        port = _make_port(80, service="http", state="open")
        data = _make_scan(ports=[port])
        result = enrich_scan_result(data)
        tactic_ids = [p["tactic_id"] for p in result["attack_summary"]["phases"]]
        assert "TA0001" in tactic_ids
