#!/usr/bin/env python3
"""Rend un rapport de démonstration sans exécuter Nmap.

Usage : python3 scripts/render_demo.py <chemin_sortie.html>

Construit un payload de scan synthétique cohérent avec la structure émise
par `scan.lancer_scan` (ports, CVEs, KEV, EPSS, posture, baseline) puis
passe par les modules d'enrichissement réels (prioritizer en mode offline,
profiler, baseline). Le HTML produit est identique à un rapport issu d'un
vrai scan — juste les données sont fabriquées pour la capture d'écran.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

os.environ.setdefault("PRIORITIZER_ENABLED", "1")

from jinja2 import Environment, FileSystemLoader
from attack_mapper import enrich_scan_result
import prioritizer
from prioritizer import enrich_vulns, priority_reasons, priority_score, priority_level
from profiler import enrich_context
from baseline import enrich_baseline


# Fixtures KEV / EPSS pour la démo — évite tout appel réseau tout en
# donnant un rendu représentatif (KEV, ransomware, EPSS élevés visibles).
_DEMO_KEV = {
    "CVE-2021-28041": {"ransomware": False, "due_date": "2023-03-14",
                       "short_desc": "OpenSSH double-free", "date_added": "2023-02-21"},
    "CVE-2023-38408": {"ransomware": True,  "due_date": "2023-08-21",
                       "short_desc": "OpenSSH forwarded agent RCE", "date_added": "2023-07-24"},
    "CVE-2021-41773": {"ransomware": True,  "due_date": "2021-11-17",
                       "short_desc": "Apache path traversal", "date_added": "2021-11-03"},
    "CVE-2021-42013": {"ransomware": False, "due_date": "2021-11-17",
                       "short_desc": "Apache path traversal", "date_added": "2021-11-03"},
    "CVE-2011-2523":  {"ransomware": False, "due_date": "2022-01-01",
                       "short_desc": "vsftpd 2.3.4 backdoor",  "date_added": "2021-11-03"},
}
_DEMO_EPSS = {
    "CVE-2021-28041": {"score": 0.12, "percentile": 0.62},
    "CVE-2023-38408": {"score": 0.78, "percentile": 0.97},
    "CVE-2021-41773": {"score": 0.94, "percentile": 0.99},
    "CVE-2021-42013": {"score": 0.88, "percentile": 0.98},
    "CVE-2021-2307":  {"score": 0.08, "percentile": 0.45},
    "CVE-2011-2523":  {"score": 0.97, "percentile": 0.99},
}


def _install_demo_fetchers():
    prioritizer.fetch_kev = lambda: _DEMO_KEV
    prioritizer.fetch_epss = lambda cve_ids: {k: v for k, v in _DEMO_EPSS.items() if k in cve_ids}


def _build_vuln(cve_id: str, cvss: float):
    """Construit un stub Vulners minimal — enrich_vulns se chargera de l'enrichir."""
    return {
        "id":    cve_id,
        "score": cvss,
        "url":   f"https://vulners.com/cve/{cve_id}",
    }


def demo_data() -> dict:
    """Scan synthétique d'un hôte 'serveur web + BDD colocalisée', posture dégradée."""
    ports = [
        {
            "port": 22, "protocol": "tcp", "state": "open",
            "service": "ssh", "version": "OpenSSH 7.6p1 Ubuntu",
            "vulns": [
                _build_vuln("CVE-2021-28041", 7.8),
                _build_vuln("CVE-2023-38408", 9.8),
            ],
        },
        {
            "port": 80, "protocol": "tcp", "state": "open",
            "service": "http", "version": "Apache httpd 2.4.49",
            "vulns": [
                _build_vuln("CVE-2021-41773", 9.8),
                _build_vuln("CVE-2021-42013", 9.8),
            ],
        },
        {
            "port": 443, "protocol": "tcp", "state": "open",
            "service": "https", "version": "Apache httpd 2.4.49 (TLS)",
            "vulns": [],
        },
        {
            "port": 3306, "protocol": "tcp", "state": "open",
            "service": "mysql", "version": "MySQL 5.7.32",
            "vulns": [
                _build_vuln("CVE-2021-2307", 8.0),
            ],
        },
        {
            "port": 21, "protocol": "tcp", "state": "open",
            "service": "ftp", "version": "vsftpd 2.3.4",
            "vulns": [
                _build_vuln("CVE-2011-2523", 10.0),
            ],
        },
    ]

    data = {
        "ip":          "203.0.113.42",
        "hostname":    "demo.example.net",
        "os_guess":    "Linux 4.15",
        "host_up":     True,
        "scan_date":   "2026-04-25 14:12:00 UTC",
        "ports":       ports,
        "total_vulns": sum(len(p["vulns"]) for p in ports),
    }
    return data


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "docs", "img", "demo_report.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    _install_demo_fetchers()

    data = demo_data()
    data = enrich_scan_result(data)
    data = enrich_vulns(data)
    data = enrich_context(data)

    # Scan précédent fictif pour illustrer la dérive.
    previous = {
        "ip": data["ip"],
        "scan_date": "2026-04-18 10:00:00 UTC",
        "host_up": True,
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
             "version": "OpenSSH 8.9p1", "vulns": []},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https",
             "version": "Apache httpd 2.4.58", "vulns": []},
        ],
        "context": {
            "role": "web_server", "role_confidence": "high",
            "posture_score": 85, "posture_grade": "B",
            "findings": [],
        },
    }
    data = enrich_baseline(data, {"id": 1, "scan_date": previous["scan_date"], "data": previous})

    templates_dir = os.path.join(HERE, "..", "src", "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("rapport.html")
    html = template.render(data=data)

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Écrit : {out}")


if __name__ == "__main__":
    main()
