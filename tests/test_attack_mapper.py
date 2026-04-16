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
    _deduplicate_techniques,
    _calculate_risk_level,
    _generate_attack_path,
    _generate_detection_priorities,
    enrich_scan_result,
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
