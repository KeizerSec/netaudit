"""
Détection contextuelle — classification du rôle de l'hôte et analyse de posture.

NetAudit v2.2 remontait des CVEs et un score de priorité, mais restait aveugle
au contexte : un port 3306 ouvert n'a pas la même gravité sur un host dédié
"backend DB interne" que sur un frontal internet-facing. Ce module comble le
trou en produisant une vraie analyse interne à partir des signaux déjà
collectés (ports, services, versions, OS, bannières).

Deux apports combinés :

1. **Classification automatique du rôle** (web server, database, mail server,
   DNS, IoT device, admin host, directory services, file server, monitoring,
   hypervisor, workstation, unknown). Basée sur une table de signatures
   pondérées : chaque port/service connu vote pour un rôle, le meilleur
   score l'emporte, avec un niveau de confiance dérivé de la marge.

2. **Analyse de posture** — catalogue de règles anti-pattern qui produisent
   des findings actionnables, chacun avec severity / evidence / recommandation.
   Les règles sont ciblées : certaines sont universelles (DB exposée = toujours
   critique), d'autres sont conditionnées au rôle inféré (un web-server sans
   HTTPS n'a pas la même signification qu'un admin-host sans HTTPS).

Le score de posture (0–100) agrège les findings pondérés par sévérité. Il
permet de comparer la posture entre hôtes et de tracer une dérive dans le
temps.

Contraintes d'intégration
- 100 % local — aucune dépendance réseau, le module fonctionne offline.
- Jamais d'exception à la surface : un scan incomplet doit toujours produire
  un `context` cohérent, quitte à tomber sur "unknown" avec confiance nulle.
- Déterministe : même entrée → même sortie, pour que les comparaisons de
  posture d'une journée à l'autre soient fiables.
"""
from __future__ import annotations

import logging
import re
from typing import Iterable

# ─── Signatures de rôles ─────────────────────────────────────────────────────
#
# Chaque rôle liste ses indicateurs principaux. `ports` et `services` sont
# indépendants : certaines applis changent de port mais gardent leur nom
# (nmap -sV est souvent fiable là-dessus), d'autres sont reconnaissables au
# port seul. Les poids expriment la spécificité : 5432 compte plus pour "db"
# que 80 pour "web" parce que 80 peut apparaître sur à peu près n'importe
# quel rôle.

ROLE_SIGNATURES: dict[str, dict] = {
    "web_server": {
        "ports":    {80: 2, 443: 3, 8080: 2, 8443: 2, 8000: 1, 8888: 1},
        "services": {"http": 2, "https": 3, "http-proxy": 2, "http-alt": 1, "nginx": 3, "apache": 3},
        "weight":   1.0,
    },
    "database": {
        "ports":    {3306: 4, 5432: 4, 1433: 4, 1521: 4, 27017: 4, 6379: 3,
                     9042: 3, 5984: 3, 7474: 3, 11211: 2, 9200: 3, 5601: 2},
        "services": {"mysql": 4, "postgresql": 4, "postgres": 4, "ms-sql-s": 4,
                     "oracle": 4, "mongod": 4, "redis": 3, "cassandra": 3,
                     "couchdb": 3, "elasticsearch": 3, "memcached": 2},
        "weight":   1.2,
    },
    "mail_server": {
        "ports":    {25: 3, 465: 3, 587: 3, 110: 3, 143: 3, 993: 3, 995: 3, 2525: 2},
        "services": {"smtp": 3, "smtps": 3, "submission": 3, "pop3": 3,
                     "pop3s": 3, "imap": 3, "imaps": 3},
        "weight":   1.2,
    },
    "dns_server": {
        "ports":    {53: 4},
        "services": {"domain": 4, "dns": 4},
        "weight":   1.3,
    },
    "file_server": {
        "ports":    {21: 3, 139: 3, 445: 3, 2049: 3, 548: 2, 873: 2},
        "services": {"ftp": 3, "netbios-ssn": 3, "microsoft-ds": 3, "smb": 3,
                     "nfs": 3, "afp": 2, "rsync": 2},
        "weight":   1.1,
    },
    "directory_services": {
        "ports":    {88: 3, 389: 4, 464: 3, 636: 4, 3268: 3, 3269: 3},
        "services": {"kerberos": 3, "ldap": 4, "ldaps": 4,
                     "kpasswd": 3, "globalcatldap": 3, "globalcatldapssl": 3},
        "weight":   1.3,
    },
    "admin_host": {
        "ports":    {22: 2, 23: 3, 3389: 3, 5985: 3, 5986: 3, 5900: 2, 5901: 2, 2222: 1},
        "services": {"ssh": 2, "telnet": 3, "ms-wbt-server": 3, "wsman": 3,
                     "wsmans": 3, "vnc": 2, "rdp": 3},
        "weight":   0.9,
    },
    "hypervisor": {
        "ports":    {902: 3, 903: 3, 5988: 3, 5989: 3, 8006: 3, 8007: 3, 61000: 2},
        "services": {"iss-realsecure": 2, "vmware-auth": 3, "pve-daemon": 3,
                     "pve-proxy": 3, "proxmox": 3, "wbem-http": 2, "wbem-https": 2},
        "weight":   1.2,
    },
    "monitoring": {
        "ports":    {161: 3, 162: 3, 3000: 2, 9090: 3, 9093: 3, 9100: 3, 9200: 2, 5601: 2},
        "services": {"snmp": 3, "snmptrap": 3, "grafana": 3, "prometheus": 3,
                     "node-exporter": 3, "kibana": 2},
        "weight":   1.0,
    },
    "iot_device": {
        "ports":    {23: 2, 81: 2, 554: 3, 1883: 4, 5683: 4, 8883: 4, 7547: 3, 502: 4, 102: 3},
        "services": {"rtsp": 3, "mqtt": 4, "coap": 4, "modbus": 4, "iso-tsap": 3,
                     "cwmp": 3, "hikvision": 4, "dahua": 4},
        "weight":   1.1,
    },
    "voip": {
        "ports":    {5060: 4, 5061: 4, 2000: 2, 1720: 3, 4569: 3},
        "services": {"sip": 4, "sip-tls": 4, "h323q931": 3, "iax": 3, "sccp": 2},
        "weight":   1.2,
    },
}


# ─── Classification ──────────────────────────────────────────────────────────

def _iter_ports(data: dict) -> Iterable[dict]:
    for port in data.get("ports", []) or []:
        if isinstance(port, dict):
            yield port


def _state_open(port: dict) -> bool:
    return (port.get("state") or "").lower() == "open"


def classify_host(data: dict) -> dict:
    """Déduit le rôle le plus probable de l'hôte et renvoie `{role, confidence, signals, scores}`.

    Algo : chaque port ouvert vote pour les rôles où il apparaît (poids
    multiplicatif du rôle × poids du port/service). Le rôle gagnant est celui
    qui cumule le plus de votes. La `confidence` est dérivée de la marge
    entre le vainqueur et le second, bornée dans [0, 1] :
      - aucun signal → unknown, confidence 0
      - un seul rôle signalé → confidence 0.95
      - marge faible (< 30 %) → low
      - marge moyenne (30–60 %) → medium
      - marge forte (> 60 %) → high
    """
    scores: dict[str, float] = {role: 0.0 for role in ROLE_SIGNATURES}
    signals: list[str] = []

    for port in _iter_ports(data):
        if not _state_open(port):
            continue
        port_num = port.get("port")
        service = (port.get("service") or "").lower()
        for role, sig in ROLE_SIGNATURES.items():
            weight = sig["weight"]
            p_weight = sig["ports"].get(port_num, 0)
            s_weight = sig["services"].get(service, 0)
            best = max(p_weight, s_weight)
            if best > 0:
                scores[role] += weight * best
                signals.append(f"{port_num}/{service or '?'} → {role} (+{best})")

    total = sum(scores.values())
    if total == 0:
        return {
            "role":       "unknown",
            "confidence": "none",
            "score":      0.0,
            "signals":    [],
            "scores":     {r: 0.0 for r in scores},
        }

    sorted_scores = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_role, top_score = sorted_scores[0]
    runner_up = sorted_scores[1][1] if len(sorted_scores) > 1 else 0.0

    margin = (top_score - runner_up) / top_score if top_score else 0.0
    if runner_up == 0:
        confidence = "high"
    elif margin >= 0.6:
        confidence = "high"
    elif margin >= 0.3:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "role":       top_role,
        "confidence": confidence,
        "score":      round(top_score, 2),
        "signals":    signals,
        "scores":     {r: round(s, 2) for r, s in scores.items() if s > 0},
    }


# ─── Règles d'analyse de posture ─────────────────────────────────────────────
#
# Chaque règle est une fonction pure `(data, role) -> Finding | None`.
# Un Finding = dict {severity, title, description, recommendation, evidence}.
# Les sévérités utilisent le même vocabulaire que la priorisation :
# CRITICAL / HIGH / MEDIUM / LOW / INFO.

SEVERITY_PENALTY = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":   8,
    "LOW":      3,
    "INFO":     0,
}

DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 7474, 11211, 9200}
ADMIN_PORTS = {22, 23, 3389, 5985, 5986, 5900, 5901, 2222}
CLEARTEXT_SERVICES = {
    23:  ("Telnet", "telnet"),
    21:  ("FTP",    "ftp"),
    69:  ("TFTP",   "tftp"),
    25:  ("SMTP sans STARTTLS", "smtp"),
    110: ("POP3 non chiffré",   "pop3"),
    143: ("IMAP non chiffré",   "imap"),
    80:  ("HTTP non chiffré",   "http"),
}


def _find_ports(data: dict, port_set: set[int]) -> list[dict]:
    return [p for p in _iter_ports(data) if _state_open(p) and p.get("port") in port_set]


def _rule_database_exposed(data: dict, role: str) -> dict | None:
    dbs = _find_ports(data, DB_PORTS)
    if not dbs:
        return None
    ports_list = ", ".join(f"{p['port']}/{p.get('service') or '?'}" for p in dbs)
    return {
        "severity":       "CRITICAL",
        "title":          "Base(s) de données exposée(s)",
        "description":    (
            "Un ou plusieurs ports de base de données sont accessibles depuis l'extérieur. "
            "Les SGBD sont conçus pour être joignables par leur backend applicatif, pas "
            "directement depuis Internet — les scans opportunistes et les credential stuffing "
            "sur ces ports sont permanents."
        ),
        "recommendation": (
            "Restreindre l'accès via pare-feu / security group au seul backend applicatif. "
            "Si l'accès distant est indispensable, tunnel SSH ou VPN uniquement."
        ),
        "evidence":       f"Port(s) ouvert(s) : {ports_list}",
    }


def _rule_cleartext_admin(data: dict, role: str) -> dict | None:
    telnet = _find_ports(data, {23})
    if not telnet:
        return None
    return {
        "severity":       "CRITICAL",
        "title":          "Telnet actif — credentials en clair",
        "description":    (
            "Le port 23 (Telnet) transmet les identifiants d'administration sans chiffrement. "
            "Un simple sniffer réseau ou une interception man-in-the-middle suffit à capturer "
            "la session complète."
        ),
        "recommendation": "Désactiver Telnet. Utiliser SSH (port 22) avec authentification par clé.",
        "evidence":       "Port 23/telnet détecté ouvert",
    }


def _rule_cleartext_ftp(data: dict, role: str) -> dict | None:
    ftp = _find_ports(data, {21})
    if not ftp:
        return None
    # Si l'implémentation est identifiée comme FTPS/SFTP on évite le faux positif.
    version = (ftp[0].get("version") or "").lower()
    if "ftps" in version or "tls" in version:
        return None
    return {
        "severity":       "HIGH",
        "title":          "FTP en clair",
        "description":    (
            "FTP transmet identifiants et fichiers sans chiffrement. À éviter pour tout "
            "transfert authentifié, et en particulier pour des contenus sensibles."
        ),
        "recommendation": "Remplacer par SFTP (sur SSH) ou FTPS. Désactiver FTP si inutilisé.",
        "evidence":       f"Port 21/ftp détecté ouvert ({ftp[0].get('version') or 'version non identifiée'})",
    }


def _rule_tftp(data: dict, role: str) -> dict | None:
    tftp = _find_ports(data, {69})
    if not tftp:
        return None
    return {
        "severity":       "HIGH",
        "title":          "TFTP actif — aucun contrôle d'accès",
        "description":    (
            "TFTP n'a ni authentification ni chiffrement. Historiquement utilisé pour booter "
            "des équipements réseau ; exposé sur Internet, il permet de lire / écrire des "
            "fichiers arbitraires dans le répertoire publié."
        ),
        "recommendation": "Limiter TFTP au segment de provisioning. Bloquer au firewall.",
        "evidence":       "Port 69/tftp détecté ouvert",
    }


def _rule_snmp_public(data: dict, role: str) -> dict | None:
    snmp = _find_ports(data, {161, 162})
    if not snmp:
        return None
    return {
        "severity":       "HIGH",
        "title":          "SNMP exposé — risque community string par défaut",
        "description":    (
            "SNMPv1/v2c utilisent une community string (souvent 'public' / 'private') "
            "équivalente à un mot de passe en clair. Avec un community par défaut, un "
            "attaquant énumère l'intégralité de la configuration et parfois modifie le device."
        ),
        "recommendation": (
            "Passer en SNMPv3 (auth + chiffrement), ou au minimum restreindre l'accès 161/162 "
            "au serveur de supervision et changer la community par défaut."
        ),
        "evidence":       "Port 161 ou 162 détecté ouvert",
    }


def _rule_multi_admin_protocols(data: dict, role: str) -> dict | None:
    admins = _find_ports(data, ADMIN_PORTS)
    if len(admins) < 2:
        return None
    protocols = sorted({f"{p['port']}/{p.get('service') or '?'}" for p in admins})
    return {
        "severity":       "MEDIUM",
        "title":          "Surface d'administration multiple",
        "description":    (
            "Plusieurs protocoles d'administration sont exposés simultanément. Chaque "
            "interface est un vecteur de credential stuffing ; cumuler les protocoles "
            "multiplie les chances de succès pour un attaquant."
        ),
        "recommendation": (
            "Réduire à un seul protocole d'admin par hôte. Les autres doivent être derrière "
            "un bastion, un VPN ou désactivés."
        ),
        "evidence":       f"Protocoles détectés : {', '.join(protocols)}",
    }


def _rule_webserver_no_tls(data: dict, role: str) -> dict | None:
    if role != "web_server":
        return None
    http_ports = {p["port"] for p in _iter_ports(data) if _state_open(p) and (p.get("port") in {80, 8080, 8000, 8888})}
    https_ports = {p["port"] for p in _iter_ports(data) if _state_open(p) and (p.get("port") in {443, 8443})}
    if http_ports and not https_ports:
        return {
            "severity":       "MEDIUM",
            "title":          "Serveur web sans HTTPS",
            "description":    (
                "Le rôle inféré est « web_server », mais seul le port HTTP est ouvert. "
                "Tout le trafic (y compris les sessions) est transmis en clair."
            ),
            "recommendation": (
                "Activer TLS sur le port 443 (Let's Encrypt si usage public). "
                "Rediriger HTTP → HTTPS et activer HSTS."
            ),
            "evidence":       f"HTTP ouvert sur {sorted(http_ports)}, aucun port HTTPS détecté",
        }
    return None


def _rule_legacy_os(data: dict, role: str) -> dict | None:
    os_guess = (data.get("os_guess") or "").lower()
    legacy_markers = [
        ("windows xp",      "Windows XP (support terminé 2014)"),
        ("windows 2000",    "Windows 2000 (support terminé 2010)"),
        ("windows server 2003", "Windows Server 2003 (support terminé 2015)"),
        ("windows server 2008", "Windows Server 2008 (support terminé 2020)"),
        ("windows 7",       "Windows 7 (support terminé 2020)"),
        ("linux 2.4",       "Linux 2.4 (obsolète)"),
        ("linux 2.6",       "Linux 2.6 (obsolète)"),
        ("centos 5",        "CentOS 5 (support terminé 2017)"),
        ("centos 6",        "CentOS 6 (support terminé 2020)"),
    ]
    for marker, label in legacy_markers:
        if marker in os_guess:
            return {
                "severity":       "HIGH",
                "title":          f"OS en fin de vie : {label}",
                "description":    (
                    "Aucun correctif de sécurité n'est émis pour cet OS. Les CVEs publiées "
                    "après la fin de support restent exploitables à perpétuité."
                ),
                "recommendation": "Planifier la migration vers une version supportée.",
                "evidence":       f"OS détecté par Nmap : {data.get('os_guess')}",
            }
    return None


def _rule_too_many_ports(data: dict, role: str) -> dict | None:
    open_ports = [p for p in _iter_ports(data) if _state_open(p)]
    if len(open_ports) <= 15:
        return None
    return {
        "severity":       "MEDIUM",
        "title":          "Surface d'attaque élargie",
        "description":    (
            f"{len(open_ports)} ports ouverts détectés. Chaque service exposé est une surface "
            "d'attaque potentielle ; au-delà d'une dizaine sur un hôte non-pivot, le principe "
            "de moindre privilège n'est probablement pas appliqué."
        ),
        "recommendation": (
            "Auditer la nécessité de chaque service et fermer ceux non-essentiels. "
            "Appliquer un firewall local (nftables / Windows Firewall) en complément du pare-feu réseau."
        ),
        "evidence":       f"{len(open_ports)} ports ouverts",
    }


def _rule_db_and_web_same_host(data: dict, role: str) -> dict | None:
    dbs = _find_ports(data, DB_PORTS)
    webs = _find_ports(data, {80, 443, 8080, 8443})
    if not (dbs and webs):
        return None
    return {
        "severity":       "HIGH",
        "title":          "Base de données colocalisée avec le serveur web",
        "description":    (
            "Web et BDD sur le même hôte : une compromission côté web (injection, RCE via "
            "une lib PHP/Node, etc.) donne un accès local direct à la base, court-circuitant "
            "les contrôles réseau classiques (firewall, security groups)."
        ),
        "recommendation": (
            "Séparer la base sur un hôte dédié, accessible uniquement depuis le backend web. "
            "Si la séparation est impossible, durcir la conf du SGBD (bind 127.0.0.1, utilisateur "
            "applicatif minimal, pas de super-user partagé)."
        ),
        "evidence":       f"{len(webs)} port(s) web + {len(dbs)} port(s) DB sur la même IP",
    }


def _rule_iot_management(data: dict, role: str) -> dict | None:
    if role != "iot_device":
        return None
    risky = _find_ports(data, {23, 7547, 81})
    if not risky:
        return None
    ports_list = ", ".join(f"{p['port']}/{p.get('service') or '?'}" for p in risky)
    return {
        "severity":       "HIGH",
        "title":          "Appareil IoT avec interface de gestion exposée",
        "description":    (
            "Les IoT grand-public et industriels embarquent souvent des interfaces de "
            "management (Telnet, CWMP/TR-069, web admin sur 81) avec des credentials par "
            "défaut largement documentés. C'est la porte d'entrée principale des botnets "
            "type Mirai."
        ),
        "recommendation": (
            "Changer immédiatement les credentials par défaut, désactiver les interfaces "
            "de gestion inutilisées, isoler l'IoT dans un VLAN dédié."
        ),
        "evidence":       f"Interfaces de gestion détectées : {ports_list}",
    }


# Regex ancrées pour éviter les faux positifs (ex: "nginx 1.2" ne doit pas
# matcher "nginx 1.20"). On exige une frontière après le numéro de version.
_UNSUPPORTED_MARKERS = [
    (re.compile(r"\bapache(?: httpd)? 2\.2(?:\D|$)"), "Apache httpd 2.2 (support terminé 2017)"),
    (re.compile(r"\bopenssh[_ ]?5\.(?:\d|$)"),        "OpenSSH 5.x (release > 10 ans)"),
    (re.compile(r"\bopenssh[_ ]?6\.(?:\d|$)"),        "OpenSSH 6.x (release > 8 ans)"),
    (re.compile(r"\bnginx 0\.(?:\d|$)"),              "Nginx 0.x (obsolète)"),
    (re.compile(r"\bnginx 1\.0(?:\D|$)"),             "Nginx 1.0.x (obsolète)"),
    (re.compile(r"\bnginx 1\.2(?:\D|$)"),             "Nginx 1.2.x (obsolète)"),
    (re.compile(r"\bproftpd 1\.2(?:\D|$)"),           "ProFTPD 1.2 (obsolète)"),
    (re.compile(r"\bvsftpd 2\.(?:\d|$)"),             "vsftpd 2.x (obsolète)"),
    (re.compile(r"\bphp/5(?:\D|$)"),                  "PHP 5 (support terminé 2018)"),
    (re.compile(r"\bpython/2(?:\D|$)"),               "Python 2 (support terminé 2020)"),
    (re.compile(r"\bopenssl/1\.0(?:\D|$)"),           "OpenSSL 1.0.x (support terminé 2019)"),
]


def _rule_unsupported_versions(data: dict, role: str) -> dict | None:
    """Détecte des versions de services majeures connues pour être EOL/unsupported."""
    found: list[str] = []
    for port in _iter_ports(data):
        if not _state_open(port):
            continue
        version = (port.get("version") or "").lower()
        if not version:
            continue
        for pattern, label in _UNSUPPORTED_MARKERS:
            if pattern.search(version) and label not in found:
                found.append(label)
                break
    if not found:
        return None
    return {
        "severity":       "HIGH",
        "title":          "Version(s) de service non-supportée(s)",
        "description":    (
            "Au moins un service expose une version sans correctifs de sécurité. "
            "Les CVEs postérieures à la fin de support restent exploitables indéfiniment "
            "— Vulners peut même ne plus lister les plus récentes pour des produits EOL."
        ),
        "recommendation": "Mettre à jour vers une branche supportée du produit.",
        "evidence":       "; ".join(found),
    }


POSTURE_RULES = [
    _rule_database_exposed,
    _rule_cleartext_admin,
    _rule_cleartext_ftp,
    _rule_tftp,
    _rule_snmp_public,
    _rule_multi_admin_protocols,
    _rule_webserver_no_tls,
    _rule_legacy_os,
    _rule_unsupported_versions,
    _rule_too_many_ports,
    _rule_db_and_web_same_host,
    _rule_iot_management,
]


def analyze_posture(data: dict, role: str) -> list[dict]:
    """Applique toutes les règles applicables et renvoie la liste des findings triés par sévérité."""
    findings: list[dict] = []
    for rule in POSTURE_RULES:
        try:
            result = rule(data, role)
        except Exception:
            # Une règle défaillante ne doit pas faire tomber toute l'analyse,
            # mais on trace le traceback — sans ça, une régression passe muette.
            logging.warning("Règle posture %s a levé une exception", rule.__name__, exc_info=True)
            continue
        if result:
            # rule_id = nom de la fonction, stable à travers les reformulations
            # de titre. Utilisé par baseline._diff_findings pour un diff robuste.
            result.setdefault("rule_id", rule.__name__)
            findings.append(result)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f.get("severity", "INFO"), 4))
    return findings


def posture_score(findings: list[dict]) -> int:
    """Score 0–100. Chaque finding ampute une pénalité fixée par sévérité.

    Le score ne descend pas en dessous de 0. Borne pratique : un hôte avec
    3 findings CRITICAL tombe déjà à 25, ce qui reflète bien une posture
    catastrophique sans être exagéré.
    """
    penalty = sum(SEVERITY_PENALTY.get(f.get("severity", "INFO"), 0) for f in findings)
    return max(0, 100 - penalty)


def _posture_grade(score: int) -> str:
    """Note textuelle du score — utile pour l'UI et le tri visuel."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    return "F"


# ─── Orchestration ───────────────────────────────────────────────────────────

def enrich_context(data: dict) -> dict:
    """Mute `data` en place en ajoutant `data["context"]` :

        {
            "role":             str,             # catégorie inférée
            "role_confidence":  str,             # high|medium|low|none
            "role_score":       float,           # score absolu du vainqueur
            "role_signals":     [str, ...],      # pour expliquer le choix
            "role_scores":      {role: float},   # scores non nuls de tous les rôles
            "findings":         [Finding, ...],  # anti-patterns détectés
            "posture_score":    int,             # 0–100
            "posture_grade":    str,             # A/B/C/D/F
            "summary":          {                # synthèse UI
                 "critical": int, "high": int, "medium": int, "low": int, "info": int
            }
        }

    Si aucun port ouvert : rôle "unknown", posture 100, findings vides —
    un hôte « silencieux » n'a pas de surface visible, c'est neutre.
    """
    classification = classify_host(data)
    findings = analyze_posture(data, classification["role"])
    score = posture_score(findings)

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        summary[f.get("severity", "INFO").lower()] = summary.get(f.get("severity", "INFO").lower(), 0) + 1

    data["context"] = {
        "role":            classification["role"],
        "role_confidence": classification["confidence"],
        "role_score":      classification["score"],
        "role_signals":    classification["signals"],
        "role_scores":     classification["scores"],
        "findings":        findings,
        "posture_score":   score,
        "posture_grade":   _posture_grade(score),
        "summary":         summary,
    }
    return data
