"""
Tests unitaires pour src/scan.py
Lance avec : pytest tests/ depuis la racine du projet.
"""
import sys
import os

# Ajouter src/ au chemin pour l'import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from scan import valider_ip, parser_nmap_output


# ─── Exemple de sortie Nmap (fictif, format réaliste) ────────────────────────

NMAP_SAMPLE = """\
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| vulners:
|   cpe:/a:openbsd:openssh:7.6p1:
|     CVE-2021-28041 7.8 https://vulners.com/cve/CVE-2021-28041
|     CVE-2019-6111  5.8 https://vulners.com/cve/CVE-2019-6111
|_
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|     CVE-2019-0211  7.2 https://vulners.com/cve/CVE-2019-0211
|_
443/tcp open  https   nginx 1.14.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""

NMAP_HOST_DOWN = """\
Starting Nmap 7.80
Note: Host seems down.
"""

NMAP_EMPTY = """\
Starting Nmap 7.80
Nmap scan report for 10.0.0.1
Host is up.
All 1000 scanned ports are closed.
"""


# ─── valider_ip ──────────────────────────────────────────────────────────────

class TestValiderIp:
    def test_ipv4_classique(self):
        assert valider_ip("192.168.1.1") is True

    def test_ipv4_loopback(self):
        assert valider_ip("127.0.0.1") is True

    def test_ipv4_zeros(self):
        assert valider_ip("0.0.0.0") is True

    def test_ipv4_broadcast(self):
        assert valider_ip("255.255.255.255") is True

    def test_octet_hors_range(self):
        assert valider_ip("256.0.0.1") is False

    def test_lettres(self):
        assert valider_ip("abc.def.ghi.jkl") is False

    def test_vide(self):
        assert valider_ip("") is False

    def test_partiel(self):
        assert valider_ip("192.168.1") is False

    def test_injection_point_virgule(self):
        assert valider_ip("192.168.1.1; rm -rf /") is False

    def test_injection_esperluette(self):
        assert valider_ip("192.168.1.1 && cat /etc/passwd") is False

    def test_string_none(self):
        assert valider_ip("None") is False

    def test_slash(self):
        assert valider_ip("192.168.1.1/24") is False

    def test_ipv6_valide(self):
        assert valider_ip("::1") is True

    def test_ipv6_complet(self):
        assert valider_ip("2001:db8::1") is True


# ─── parser_nmap_output ───────────────────────────────────────────────────────

class TestParserNmapOutput:
    def test_host_up_detecte(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        assert result["host_up"] is True

    def test_ip_dans_result(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        assert result["ip"] == "192.168.1.1"

    def test_scan_date_presente(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        assert "scan_date" in result
        assert len(result["scan_date"]) > 0

    def test_trois_ports_detectes(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        assert len(result["ports"]) == 3

    def test_port_22_ssh(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        assert 22 in ports
        assert ports[22]["service"] == "ssh"
        assert ports[22]["state"] == "open"
        assert ports[22]["protocol"] == "tcp"

    def test_port_80_http(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        assert 80 in ports
        assert ports[80]["service"] == "http"

    def test_port_443_sans_vulns(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        assert 443 in ports
        assert ports[443]["vulns"] == []

    def test_vulns_port_22(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        vulns_22 = ports[22]["vulns"]
        assert len(vulns_22) == 2
        ids = [v["id"] for v in vulns_22]
        assert "CVE-2021-28041" in ids
        assert "CVE-2019-6111" in ids

    def test_score_vuln_float(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        vuln = next(v for v in ports[22]["vulns"] if v["id"] == "CVE-2021-28041")
        assert isinstance(vuln["score"], float)
        assert vuln["score"] == 7.8

    def test_url_vuln_presente(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        vuln = ports[22]["vulns"][0]
        assert vuln["url"].startswith("https://vulners.com")

    def test_total_vulns_calcule(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        # 2 vulns port 22 + 1 vuln port 80 = 3
        assert result["total_vulns"] == 3

    def test_host_down(self):
        result = parser_nmap_output("10.0.0.1", NMAP_HOST_DOWN)
        assert result["host_up"] is False
        assert result["ports"] == []
        assert result["total_vulns"] == 0

    def test_host_up_sans_vulns(self):
        result = parser_nmap_output("10.0.0.1", NMAP_EMPTY)
        assert result["host_up"] is True
        assert result["total_vulns"] == 0

    def test_raw_preserve(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        assert result["raw"] == NMAP_SAMPLE

    def test_cpe_non_inclus_dans_vulns(self):
        result = parser_nmap_output("192.168.1.1", NMAP_SAMPLE)
        for port in result["ports"]:
            for vuln in port["vulns"]:
                assert not vuln["id"].startswith("cpe:")
