"""
Tests unitaires pour src/scan.py
Lance avec : pytest tests/ depuis la racine du projet.
"""
import sys
import os

# Ajouter src/ au chemin pour l'import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from scan import valider_ip, parser_nmap_xml


# ─── Exemples de sortie Nmap XML (fictifs, format réaliste) ──────────────────

NMAP_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap --script vulners -sV -oX - 192.168.1.1" start="1704110400">
<host starttime="1704110400">
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames><hostname name="router.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu 4ubuntu0.3"/>
<script id="vulners" output="ignored">
  <table key="cpe:/a:openbsd:openssh:7.6p1">
    <table>
      <elem key="id">CVE-2021-28041</elem>
      <elem key="cvss">7.8</elem>
      <elem key="type">cve</elem>
    </table>
    <table>
      <elem key="id">CVE-2019-6111</elem>
      <elem key="cvss">5.8</elem>
      <elem key="type">cve</elem>
    </table>
  </table>
</script>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.29" extrainfo="Ubuntu"/>
<script id="vulners" output="ignored">
  <table key="cpe:/a:apache:http_server:2.4.29">
    <table>
      <elem key="id">CVE-2019-0211</elem>
      <elem key="cvss">7.2</elem>
      <elem key="type">cve</elem>
    </table>
  </table>
</script>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.14.0"/>
</port>
</ports>
<os><osmatch name="Linux 4.15 - 5.6" accuracy="95"/></os>
</host>
</nmaprun>
"""

NMAP_XML_HOST_DOWN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<status state="down" reason="no-response"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
</host>
</nmaprun>
"""

NMAP_XML_EMPTY_PORTS = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<status state="up" reason="echo-reply"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports></ports>
</host>
</nmaprun>
"""

NMAP_XML_MALFORMED = "<nmaprun><host><ports><port</nmaprun>"


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


# ─── parser_nmap_xml ──────────────────────────────────────────────────────────

class TestParserNmapXml:
    def test_host_up_detecte(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert result["host_up"] is True

    def test_ip_dans_result(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert result["ip"] == "192.168.1.1"

    def test_scan_date_presente(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert "scan_date" in result
        assert len(result["scan_date"]) > 0

    def test_hostname_extrait(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert result["hostname"] == "router.local"

    def test_os_guess_extrait(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert "Linux" in result["os_guess"]

    def test_trois_ports_detectes(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert len(result["ports"]) == 3

    def test_port_22_ssh(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        assert 22 in ports
        assert ports[22]["service"] == "ssh"
        assert ports[22]["state"] == "open"
        assert ports[22]["protocol"] == "tcp"

    def test_port_22_version_concatenee(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        # product + version + extrainfo doivent apparaître
        assert "OpenSSH" in ports[22]["version"]
        assert "7.6p1" in ports[22]["version"]

    def test_port_80_http(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        assert 80 in ports
        assert ports[80]["service"] == "http"

    def test_port_443_sans_vulns(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        assert 443 in ports
        assert ports[443]["vulns"] == []

    def test_vulns_port_22(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        vulns_22 = ports[22]["vulns"]
        assert len(vulns_22) == 2
        ids = [v["id"] for v in vulns_22]
        assert "CVE-2021-28041" in ids
        assert "CVE-2019-6111" in ids

    def test_score_vuln_float(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        vuln = next(v for v in ports[22]["vulns"] if v["id"] == "CVE-2021-28041")
        assert isinstance(vuln["score"], float)
        assert vuln["score"] == 7.8

    def test_url_vuln_construit_vers_vulners(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        ports = {p["port"]: p for p in result["ports"]}
        vuln = ports[22]["vulns"][0]
        assert vuln["url"].startswith("https://vulners.com/")
        assert vuln["id"] in vuln["url"]

    def test_total_vulns_calcule(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        # 2 vulns port 22 + 1 vuln port 80 = 3
        assert result["total_vulns"] == 3

    def test_host_down(self):
        result = parser_nmap_xml("10.0.0.1", NMAP_XML_HOST_DOWN)
        assert result["host_up"] is False
        assert result["ports"] == []
        assert result["total_vulns"] == 0

    def test_host_up_sans_ports(self):
        result = parser_nmap_xml("10.0.0.1", NMAP_XML_EMPTY_PORTS)
        assert result["host_up"] is True
        assert result["ports"] == []
        assert result["total_vulns"] == 0

    def test_raw_preserve(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        assert result["raw"] == NMAP_XML_SAMPLE

    def test_cpe_non_inclus_dans_vulns(self):
        result = parser_nmap_xml("192.168.1.1", NMAP_XML_SAMPLE)
        for port in result["ports"]:
            for vuln in port["vulns"]:
                assert not vuln["id"].startswith("cpe:")

    def test_xml_malforme_retourne_structure_vide(self):
        result = parser_nmap_xml("1.2.3.4", NMAP_XML_MALFORMED)
        assert result["host_up"] is False
        assert result["ports"] == []
        assert result["total_vulns"] == 0

    def test_structure_coherente_toujours(self):
        """Toutes les clés attendues doivent être présentes, même host down."""
        for xml in (NMAP_XML_SAMPLE, NMAP_XML_HOST_DOWN, NMAP_XML_MALFORMED):
            result = parser_nmap_xml("1.2.3.4", xml)
            for key in ("ip", "scan_date", "host_up", "hostname", "os_guess",
                        "ports", "total_vulns", "raw"):
                assert key in result
