import subprocess
import ipaddress
import logging
import os
import re
from functools import lru_cache
from logging.handlers import RotatingFileHandler
import shutil
from datetime import datetime, timezone

# Répertoire absolu de ce fichier (src/)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Constantes configurables via variables d'environnement
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", os.path.join(BASE_DIR, "..", "scan.log"))
REPORT_DIR    = os.getenv("REPORT_DIR",    os.path.join(BASE_DIR, "..", "rapports"))
NMAP_TIMEOUT  = int(os.getenv("NMAP_TIMEOUT", "300"))
CACHE_SIZE    = int(os.getenv("CACHE_SIZE",   "32"))

# Logging avec rotation — crée le dossier parent si nécessaire
os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE_PATH)), exist_ok=True)
_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=5)
logging.basicConfig(
    handlers=[_handler],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
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


def parser_nmap_output(ip: str, raw: str) -> dict:
    """
    Transforme la sortie brute de Nmap en dict structuré.

    Structure retournée :
    {
        "ip": str,
        "scan_date": str (ISO-8601 UTC),
        "host_up": bool,
        "ports": [
            {
                "port": int,
                "protocol": str,
                "state": str,
                "service": str,
                "version": str,
                "vulns": [
                    {"id": str, "score": float, "url": str}
                ]
            }
        ],
        "total_vulns": int,
        "raw": str
    }
    """
    result: dict = {
        "ip":         ip,
        "scan_date":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "host_up":    False,
        "ports":      [],
        "total_vulns": 0,
        "raw":        raw,
    }

    if "Host is up" in raw:
        result["host_up"] = True

    # Hôte injoignable → retour anticipé
    if "Host seems down" in raw or "0 hosts up" in raw:
        return result

    # Regex ligne de port : "22/tcp open  ssh  OpenSSH 7.6 ..."
    port_re = re.compile(
        r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$',
        re.MULTILINE,
    )
    # Regex ligne vulners : "|   CVE-2021-28041  7.8  https://..."
    vuln_re = re.compile(
        r'^\|\s+([\w:.\-]+)\s+([\d.]+)\s+(https?://\S+)',
        re.MULTILINE,
    )

    port_data: dict[int, dict] = {}
    port_order: list[int] = []

    # 1re passe : collecter les ports
    for m in port_re.finditer(raw):
        port_num = int(m.group(1))
        port_data[port_num] = {
            "port":     port_num,
            "protocol": m.group(2),
            "state":    m.group(3),
            "service":  m.group(4),
            "version":  m.group(5).strip(),
            "vulns":    [],
        }
        port_order.append(port_num)

    # 2e passe : associer les vulnérabilités au dernier port rencontré
    current_port: int | None = None
    for line in raw.splitlines():
        pm = port_re.match(line.strip())
        if pm:
            current_port = int(pm.group(1))
            continue

        vm = vuln_re.match(line.strip())
        if vm and current_port is not None and current_port in port_data:
            vuln_id = vm.group(1)
            # Ignorer les entrées de métadonnées CPE et NMAP
            if re.match(r"^(cpe:|NMAP)", vuln_id):
                continue
            port_data[current_port]["vulns"].append({
                "id":    vuln_id,
                "score": float(vm.group(2)),
                "url":   vm.group(3),
            })

    result["ports"] = [port_data[p] for p in port_order]
    result["total_vulns"] = sum(len(p["vulns"]) for p in result["ports"])
    return result


@lru_cache(maxsize=CACHE_SIZE)
def _scan_cached(ip: str) -> dict:
    """
    Exécute Nmap et retourne le résultat parsé.
    Les exceptions levées ici ne sont PAS mises en cache par lru_cache,
    ce qui garantit qu'un échec relancera un vrai scan à la prochaine tentative.
    """
    logging.info("Scan démarré pour %s", ip)
    proc = subprocess.run(
        ["nmap", "--script", "vulners", "-sV", ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=NMAP_TIMEOUT,
        check=True,
    )
    logging.info("Scan terminé pour %s", ip)
    return parser_nmap_output(ip, proc.stdout.decode())


def scan_vulnerabilites(ip: str) -> dict:
    """
    Wrapper public autour du cache. Capture les erreurs Nmap et retourne
    toujours un dict (jamais une exception à la surface de l'API).
    """
    try:
        return _scan_cached(ip)
    except subprocess.TimeoutExpired:
        logging.error("Scan expiré pour %s", ip)
        return {
            "ip": ip, "error": "Timeout — le scan a expiré.",
            "host_up": False, "ports": [], "total_vulns": 0, "raw": "",
        }
    except subprocess.CalledProcessError as exc:
        msg = exc.stderr.decode().strip()
        logging.error("Erreur Nmap pour %s : %s", ip, msg)
        return {
            "ip": ip, "error": f"Erreur Nmap : {msg}",
            "host_up": False, "ports": [], "total_vulns": 0, "raw": "",
        }


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
