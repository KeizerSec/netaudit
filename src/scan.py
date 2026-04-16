from __future__ import annotations

import subprocess
import ipaddress
import logging
import os
import shutil
import xml.etree.ElementTree as ET
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

# Répertoire absolu de ce fichier (src/)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Constantes configurables via variables d'environnement
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", os.path.join(BASE_DIR, "..", "scan.log"))
REPORT_DIR    = os.getenv("REPORT_DIR",    os.path.join(BASE_DIR, "..", "rapports"))
NMAP_TIMEOUT  = int(os.getenv("NMAP_TIMEOUT", "300"))
CACHE_SIZE    = int(os.getenv("CACHE_SIZE",   "32"))

# Logging double sortie : fichier rotaté (audit long terme) + stdout (docker logs,
# systemd journal, agrégateurs type Loki/CloudWatch). Les deux handlers partagent
# le même format pour faciliter le grep croisé.
os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE_PATH)), exist_ok=True)
_LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
_file_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=5)
_stream_handler = logging.StreamHandler()
logging.basicConfig(
    handlers=[_file_handler, _stream_handler],
    level=logging.INFO,
    format=_LOG_FORMAT,
)


def verifier_nmap() -> None:
    """Vérifie qu'Nmap est installé et accessible dans le PATH."""
    if not shutil.which("nmap"):
        logging.error("Nmap introuvable dans le PATH.")
        raise EnvironmentError("Nmap n'est pas installé ou introuvable.")


def valider_ip(ip: str) -> bool:
    """
    Valide une adresse IPv4 ou IPv6 via le module ipaddress (RFC-correct).
    Résiste aux injections, aux octets hors-range, aux formats exotiques.

    :param ip: Chaîne à valider.
    :return: True si valide, sinon False.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _empty_result(ip: str, raw: str) -> dict:
    """Squelette de résultat pour un hôte injoignable ou un parse échoué."""
    return {
        "ip":          ip,
        "scan_date":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "host_up":     False,
        "hostname":    "",
        "os_guess":    "",
        "ports":       [],
        "total_vulns": 0,
        "raw":         raw,
    }


def _extract_service_version(service_elem: ET.Element | None) -> tuple[str, str]:
    """Retourne (nom_service, version_lisible) depuis un élément <service>."""
    if service_elem is None:
        return "", ""
    name = service_elem.get("name", "")
    parts = [
        service_elem.get(attr, "").strip()
        for attr in ("product", "version", "extrainfo")
    ]
    version = " ".join(p for p in parts if p)
    return name, version


def _extract_vulners(port_elem: ET.Element) -> list[dict]:
    """Extrait les vulnérabilités de tous les blocs <script id="vulners"> du port."""
    vulns: list[dict] = []
    for script in port_elem.findall("script"):
        if script.get("id") != "vulners":
            continue
        # La structure vulners expose des tables imbriquées :
        # <script>  <table key="cpe:..."> <table> <elem key="id">CVE-…</elem> …
        for cpe_table in script.findall("table"):
            for vuln_table in cpe_table.findall("table"):
                elems = {
                    e.get("key"): (e.text or "").strip()
                    for e in vuln_table.findall("elem")
                }
                vuln_id = elems.get("id", "")
                if not vuln_id or vuln_id.startswith("cpe:"):
                    continue
                try:
                    score = float(elems.get("cvss", "0") or 0)
                except ValueError:
                    score = 0.0
                vuln_type = (elems.get("type") or "cve").lower()
                vulns.append({
                    "id":    vuln_id,
                    "score": score,
                    "url":   f"https://vulners.com/{vuln_type}/{vuln_id}",
                })
    return vulns


def parser_nmap_xml(ip: str, xml_str: str) -> dict:
    """
    Parse la sortie Nmap XML (`-oX -`) en dict structuré.

    Structure retournée :
    {
        "ip":          str,
        "scan_date":   str (UTC),
        "host_up":     bool,
        "hostname":    str,              # reverse DNS si dispo
        "os_guess":    str,              # meilleur match OS si dispo
        "ports": [
            {
                "port":     int,
                "protocol": str,
                "state":    str,
                "service":  str,
                "version":  str,
                "vulns":    [{"id": str, "score": float, "url": str}]
            }
        ],
        "total_vulns": int,
        "raw":         str               # XML brut, conservé pour audit
    }

    En cas de XML malformé ou d'hôte injoignable, retourne une structure vide
    cohérente (jamais d'exception à la surface).
    """
    result = _empty_result(ip, xml_str)

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logging.warning("XML Nmap invalide pour %s : %s", ip, exc)
        return result

    host = root.find("host")
    if host is None:
        return result

    status = host.find("status")
    if status is not None and status.get("state") == "up":
        result["host_up"] = True

    hostname = host.find("./hostnames/hostname")
    if hostname is not None:
        result["hostname"] = hostname.get("name", "")

    osmatch = host.find("./os/osmatch")
    if osmatch is not None:
        result["os_guess"] = osmatch.get("name", "")

    for port_elem in host.findall("./ports/port"):
        state_elem = port_elem.find("state")
        state = state_elem.get("state", "") if state_elem is not None else ""

        service_name, service_version = _extract_service_version(
            port_elem.find("service")
        )

        try:
            port_num = int(port_elem.get("portid", "0"))
        except ValueError:
            continue

        result["ports"].append({
            "port":     port_num,
            "protocol": port_elem.get("protocol", ""),
            "state":    state,
            "service":  service_name,
            "version":  service_version,
            "vulns":    _extract_vulners(port_elem),
        })

    result["total_vulns"] = sum(len(p["vulns"]) for p in result["ports"])
    return result


@lru_cache(maxsize=CACHE_SIZE)
def _scan_cached(ip: str) -> dict:
    """
    Exécute Nmap avec sortie XML et retourne le résultat parsé.
    Les exceptions levées ici ne sont PAS mises en cache par lru_cache,
    ce qui garantit qu'un échec relancera un vrai scan à la prochaine tentative.
    """
    logging.info("Scan démarré pour %s", ip)
    proc = subprocess.run(
        ["nmap", "--script", "vulners", "-sV", "-oX", "-", ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=NMAP_TIMEOUT,
        check=True,
    )
    logging.info("Scan terminé pour %s", ip)
    return parser_nmap_xml(ip, proc.stdout.decode())


def scan_vulnerabilites(ip: str) -> dict:
    """
    Wrapper public autour du cache. Capture les erreurs Nmap et retourne
    toujours un dict (jamais une exception à la surface de l'API).
    """
    try:
        return _scan_cached(ip)
    except subprocess.TimeoutExpired:
        logging.error("Scan expiré pour %s", ip)
        err = _empty_result(ip, "")
        err["error"] = "Timeout — le scan a expiré."
        return err
    except subprocess.CalledProcessError as exc:
        msg = exc.stderr.decode().strip()
        logging.error("Erreur Nmap pour %s : %s", ip, msg)
        err = _empty_result(ip, "")
        err["error"] = f"Erreur Nmap : {msg}"
        return err


def sauvegarder_rapport(ip: str, data: dict) -> str:
    """
    Génère le rapport HTML via le template Jinja2 externe et le sauvegarde.
    :return: Chemin absolu du fichier HTML créé.
    """
    from jinja2 import Environment, FileSystemLoader

    os.makedirs(REPORT_DIR, exist_ok=True)

    templates_dir = os.path.join(BASE_DIR, "templates")
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=True,
    )
    template = env.get_template("rapport.html")
    contenu_html = template.render(data=data)

    chemin = os.path.join(REPORT_DIR, f"{ip}_scan.html")
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(contenu_html)

    logging.info("Rapport sauvegardé pour %s → %s", ip, chemin)
    return chemin


def lancer_scan(ip: str) -> tuple:
    """
    Orchestre validation → scan → rapport.
    :return: (data_dict, chemin_rapport) ou (None, None) si IP invalide.
    """
    if not valider_ip(ip):
        logging.warning("Tentative de scan avec IP invalide : %s", ip)
        return None, None

    verifier_nmap()
    data = scan_vulnerabilites(ip)

    if "error" in data:
        return data, None

    # Enrichissement ATT&CK — mapping CVE/service → techniques + chemin d'attaque
    from attack_mapper import enrich_scan_result
    data = enrich_scan_result(data)

    chemin = sauvegarder_rapport(ip, data)
    return data, chemin


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage : python3 scan.py <IP>")
        sys.exit(1)

    ip_arg = sys.argv[1]
    data, chemin = lancer_scan(ip_arg)

    if data is None:
        print("Erreur : IP invalide.")
        sys.exit(1)

    if "error" in data:
        print(f"Erreur : {data['error']}")
        sys.exit(1)

    print(f"Scan terminé pour     : {ip_arg}")
    print(f"Host actif            : {data['host_up']}")
    print(f"Ports ouverts         : {len(data['ports'])}")
    print(f"Vulnérabilités totales: {data['total_vulns']}")
    for port in data["ports"]:
        print(
            f"  {port['port']}/{port['protocol']}  {port['state']}"
            f"  {port['service']}  {port['version']}"
            f"  [{len(port['vulns'])} vuln(s)]"
        )
    if chemin:
        print(f"\nRapport HTML : {chemin}")
