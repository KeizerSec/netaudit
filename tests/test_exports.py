"""Tests unitaires pour src/exports.py — génération PDF depuis la data de scan."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from exports import render_pdf


@pytest.fixture
def scan_data():
    return {
        "ip":          "192.168.1.10",
        "scan_date":   "2026-04-16 12:00:00 UTC",
        "host_up":     True,
        "hostname":    "router.local",
        "os_guess":    "Linux 5.x",
        "total_vulns": 2,
        "ports": [
            {
                "port": 22, "protocol": "tcp", "state": "open",
                "service": "ssh", "version": "OpenSSH 7.6p1",
                "vulns": [
                    {"id": "CVE-2021-28041", "score": 7.8,
                     "url": "https://vulners.com/cve/CVE-2021-28041"},
                ],
            },
            {
                "port": 443, "protocol": "tcp", "state": "open",
                "service": "https", "version": "nginx 1.18",
                "vulns": [],
            },
        ],
        "attack_summary": {
            "risk_level":   "HIGH",
            "phases_count": 3,
            "phases": [
                {"tactic": "Initial Access",
                 "techniques": [{"id": "T1190", "name": "Exploit Public-Facing App"}]},
                {"tactic": "Lateral Movement",
                 "techniques": [{"id": "T1021.004", "name": "SSH"}]},
            ],
            "detection_priorities": [
                "Surveiller les connexions SSH répétées",
                "Alerter sur les User-Agent inhabituels",
            ],
        },
    }


class TestRenderPdf:
    def test_retourne_bytes(self, scan_data):
        pdf = render_pdf(scan_data)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 1000  # un PDF minimal dépasse ~1KB

    def test_magic_number_pdf(self, scan_data):
        # Signature PDF standard : %PDF-
        pdf = render_pdf(scan_data)
        assert pdf[:5] == b"%PDF-"

    def test_sans_attack_summary(self, scan_data):
        scan_data.pop("attack_summary")
        pdf = render_pdf(scan_data)
        assert pdf[:5] == b"%PDF-"

    def test_sans_ports(self, scan_data):
        scan_data["ports"] = []
        pdf = render_pdf(scan_data)
        assert pdf[:5] == b"%PDF-"

    def test_data_minimale(self):
        # Cas extrême : rien que l'IP et la date. Ne doit pas lever.
        minimal = {"ip": "10.0.0.1", "scan_date": "2026-04-16", "host_up": False}
        pdf = render_pdf(minimal)
        assert pdf[:5] == b"%PDF-"

    def test_score_coloration_ne_leve_pas(self, scan_data):
        # Score à 9.9 (CRITICAL), à 0 (LOW), à string invalide
        scan_data["ports"][0]["vulns"] = [
            {"id": "CVE-X", "score": 9.9, "url": "x"},
            {"id": "CVE-Y", "score": 0,   "url": "y"},
            {"id": "CVE-Z", "score": "N/A", "url": "z"},
        ]
        pdf = render_pdf(scan_data)
        assert pdf[:5] == b"%PDF-"
