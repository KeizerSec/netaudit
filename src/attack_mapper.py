"""
attack_mapper.py — Enrichissement ATT&CK des résultats de scan NetAudit

Logique :
  1. Pour chaque port détecté  → mapping service/port → techniques ATT&CK (confiance haute)
  2. Pour chaque CVE détectée  → mapping score CVSS + contexte service → techniques (confiance moyenne)
  3. Déduplication et scoring  → une technique issue de plusieurs sources monte en priorité
  4. Génération du chemin      → phases ordonnées selon le kill chain MITRE
  5. Calcul du risk level      → CRITICAL / HIGH / MEDIUM / LOW selon les tactiques présentes

Version future (v2) : enrichissement NVD API pour récupérer les CWEs réels et affiner les mappings.
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict

# ─── Chargement des tables de données ────────────────────────────────────────

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _load_json(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


try:
    _TECHNIQUES: dict      = _load_json("techniques.json")
    _CWE_MAPPING: dict     = _load_json("cwe_mapping.json")
    _SERVICE_MAPPING: dict = _load_json("service_mapping.json")
    _KNOWN_CVES: dict      = _load_json("known_cves.json")
    # Nettoyer les clés de commentaire éventuelles
    _KNOWN_CVES = {k: v for k, v in _KNOWN_CVES.items() if not k.startswith("_")}
except FileNotFoundError as exc:
    logging.error("Fichier de données ATT&CK manquant : %s", exc)
    _TECHNIQUES = {}
    _CWE_MAPPING = {}
    _SERVICE_MAPPING = {}
    _KNOWN_CVES = {}

# ─── Ordre du kill chain MITRE (tactic_id → position) ───────────────────────

_KILL_CHAIN: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

_TACTIC_ORDER = {tid: i for i, (tid, _) in enumerate(_KILL_CHAIN)}

# Narratives par tactique — explications lisibles pour chaque phase
_TACTIC_NARRATIVES: dict[str, str] = {
    "TA0043": "Phase de reconnaissance active ou passive — un attaquant collecte des informations sur la surface exposée.",
    "TA0042": "Préparation d'outils et d'infrastructure offensive (exploits, domaines, certificats) avant campagne.",
    "TA0001": "Point d'entrée probable identifié — un attaquant peut accéder au système via les services exposés.",
    "TA0002": "Exécution de code possible si un accès initial est obtenu (RCE, shell interactif).",
    "TA0003": "Mécanismes de persistence envisageables pour maintenir l'accès après redémarrage.",
    "TA0004": "Élévation de privilèges possible si un accès limité est obtenu (root, SYSTEM).",
    "TA0005": "Techniques d'évasion des défenses disponibles pour masquer l'activité malveillante.",
    "TA0006": "Extraction de credentials possible depuis les services ou la mémoire du système.",
    "TA0007": "Reconnaissance interne envisageable pour cartographier le réseau après compromission.",
    "TA0008": "Propagation latérale possible vers d'autres machines du réseau.",
    "TA0009": "Collecte de données sensibles accessible depuis les services exposés.",
    "TA0011": "Canal de commande & contrôle potentiel via les protocoles sortants autorisés (HTTP/HTTPS/DNS).",
    "TA0010": "Exfiltration de données envisageable via les canaux réseau ouverts.",
    "TA0040": "Impact final possible — destruction, chiffrement (ransomware) ou déni de service.",
}


# ─── Fonctions internes ───────────────────────────────────────────────────────

def _get_technique(tech_id: str) -> dict:
    """Retourne un technique dict complet depuis le catalogue, ou un stub si inconnu."""
    if tech_id in _TECHNIQUES:
        return dict(_TECHNIQUES[tech_id])
    # Stub minimal pour les techniques hors catalogue
    return {
        "id": tech_id,
        "name": tech_id,
        "tactic_id": "TA0001",
        "tactic_name": "Unknown",
        "description": "",
        "detection": "",
        "mitigations": "",
        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
    }


def _build_technique_entry(tech_id: str, confidence: str, source: str) -> dict:
    """Construit une entrée de technique enrichie avec sa source et sa confiance."""
    t = _get_technique(tech_id)
    return {
        "id":           t["id"],
        "name":         t["name"],
        "tactic_id":    t["tactic_id"],
        "tactic_name":  t["tactic_name"],
        "description":  t["description"],
        "detection":    t["detection"],
        "mitigations":  t.get("mitigations", ""),
        "url":          t["url"],
        "confidence":   confidence,   # high / medium / low
        "source":       source,       # ex : "ssh port 22" ou "CVE-2021-28041 (CVSS 7.8)"
    }


def _map_service_techniques(port: int, service: str) -> list[dict]:
    """
    Niveau 1 — Mapping service/port → techniques ATT&CK.
    Confiance haute : la technique est directement liée au service détecté.
    """
    results = []
    service_lower = service.lower().strip()

    # Recherche par nom de service exact ou contenu
    for svc_key, svc_data in _SERVICE_MAPPING.items():
        if svc_key in service_lower or service_lower in svc_key:
            for tech_id in svc_data["techniques"]:
                results.append(_build_technique_entry(
                    tech_id,
                    confidence="high",
                    source=f"{service} (port {port})"
                ))
            return results

    # Recherche par numéro de port si le service n'a pas matché
    for svc_key, svc_data in _SERVICE_MAPPING.items():
        if port in svc_data.get("ports", []):
            for tech_id in svc_data["techniques"]:
                results.append(_build_technique_entry(
                    tech_id,
                    confidence="high",
                    source=f"port {port} ({service})"
                ))
            return results

    return results


def _map_cwe_techniques(cwe_id: str, source: str) -> list[dict]:
    """
    Niveau 2a — Mapping CWE → techniques ATT&CK via cwe_mapping.json.

    Retourne une liste vide si la CWE n'est pas cataloguée.
    La confiance est celle déclarée dans le catalogue (haute pour les CWEs
    directement exploitables type injection, moyenne pour les CWEs plus
    génériques type info disclosure).
    """
    results = []
    cwe_entry = _CWE_MAPPING.get(cwe_id)
    if not cwe_entry:
        return results
    for tech_ref in cwe_entry.get("techniques", []):
        results.append(_build_technique_entry(
            tech_ref["id"],
            confidence=tech_ref.get("confidence", "medium"),
            source=source,
        ))
    return results


def _map_known_cve_techniques(vuln_id: str) -> list[dict]:
    """
    Niveau 2b — Si le CVE est catalogué dans known_cves.json, retourne les
    techniques déduites de sa CWE connue. Plus précis que l'heuristique CVSS.
    """
    known = _KNOWN_CVES.get(vuln_id.upper())
    if not known:
        return []
    cwe_id = known.get("cwe", "")
    if not cwe_id:
        return []
    label = known.get("name", vuln_id)
    source = f"{vuln_id} — {label} ({cwe_id})"
    return _map_cwe_techniques(cwe_id, source)


def _heuristic_cve_techniques(vuln_id: str, score: float, service: str, port: int) -> list[dict]:
    """
    Niveau 2c — Heuristique de repli : score CVSS + contexte service.
    Utilisée quand la CVE n'est pas dans known_cves.json.

    Heuristiques :
      - Score ≥ 9.0 sur service web/réseau  → RCE probable → T1190 haute confiance
      - Score ≥ 9.0 sur SMB/RPC             → exploitation réseau → T1210 haute confiance
      - Score 7.0–8.9                        → auth bypass ou priv esc → T1078 + T1068 moyenne confiance
      - Score 4.0–6.9                        → info disclosure → T1082 basse confiance
      - Score < 4.0                          → non mappé (risque trop faible)
    """
    results = []
    source = f"{vuln_id} (CVSS {score:.1f})"
    service_lower = service.lower()

    # Services web / applicatifs
    web_services = {"http", "https", "tomcat", "jenkins", "apache", "nginx", "iis"}
    # Services réseau
    network_services = {"smb", "netbios", "msrpc", "ldap", "nfs"}
    # Services de base de données
    db_services = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis",
                   "elasticsearch", "cassandra", "ms-sql"}

    is_web = any(s in service_lower for s in web_services) or port in {80, 443, 8080, 8443, 8000}
    is_smb = any(s in service_lower for s in network_services) or port in {445, 139, 135}
    is_db  = any(s in service_lower for s in db_services) or port in {3306, 5432, 1433, 27017, 6379}

    if score >= 9.0:
        if is_web:
            results.append(_build_technique_entry("T1190", "high", source))
            results.append(_build_technique_entry("T1059", "medium", source))
        elif is_smb:
            results.append(_build_technique_entry("T1210", "high", source))
            results.append(_build_technique_entry("T1021.002", "medium", source))
        elif is_db:
            results.append(_build_technique_entry("T1190", "high", source))
        else:
            # Service réseau générique avec score critique
            results.append(_build_technique_entry("T1190", "high", source))
            results.append(_build_technique_entry("T1133", "medium", source))

    elif score >= 7.0:
        # Auth bypass ou priv esc probable
        results.append(_build_technique_entry("T1078", "medium", source))
        results.append(_build_technique_entry("T1068", "medium", source))
        if is_web:
            results.append(_build_technique_entry("T1190", "medium", source))

    elif score >= 4.0:
        # Information disclosure
        results.append(_build_technique_entry("T1082", "low", source))

    # Score < 4.0 : non mappé — bruit trop important

    return results


def _map_cve_techniques(vuln_id: str, score: float, service: str, port: int) -> list[dict]:
    """
    Niveau 2 — Orchestrateur du mapping CVE → techniques ATT&CK.

    Combine deux sources, dont les résultats sont dédupliqués en aval :
      - Mapping précis via CWE connue (known_cves.json → cwe_mapping.json).
        Active uniquement pour les CVEs cataloguées (Log4Shell, EternalBlue, …).
      - Heuristique CVSS + contexte service (toujours appliquée pour capter
        le contexte réseau — SMB, web, DB — qui n'est pas encodé dans la CWE).

    Les deux couches sont volontairement complémentaires : le mapping CWE
    cible la nature de la faille (ex. buffer overflow → T1068), la couche
    heuristique cible le vecteur d'exploitation (ex. via SMB → T1210).
    """
    results: list[dict] = []
    results.extend(_map_known_cve_techniques(vuln_id))
    results.extend(_heuristic_cve_techniques(vuln_id, score, service, port))
    return results


def _deduplicate_techniques(techniques: list[dict]) -> list[dict]:
    """
    Déduplique les techniques. Si la même technique apparaît plusieurs fois,
    on garde l'occurrence avec la confiance la plus haute et on accumule les sources.

    Ordre de confiance : high > medium > low
    """
    _conf_rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, dict] = {}

    for t in techniques:
        tech_id = t["id"]
        if tech_id not in best:
            best[tech_id] = dict(t)
            best[tech_id]["sources"] = [t["source"]]
        else:
            # Garder la confiance la plus haute
            if _conf_rank.get(t["confidence"], 0) > _conf_rank.get(best[tech_id]["confidence"], 0):
                best[tech_id]["confidence"] = t["confidence"]
            # Accumuler les sources (max 3 pour ne pas surcharger le rapport)
            if t["source"] not in best[tech_id]["sources"] and len(best[tech_id]["sources"]) < 3:
                best[tech_id]["sources"].append(t["source"])

    # Mettre à jour le champ "source" avec toutes les sources accumulées
    result = []
    for t in best.values():
        t["source"] = " / ".join(t["sources"])
        del t["sources"]
        result.append(t)

    return result


def _calculate_risk_level(all_techniques: list[dict]) -> str:
    """
    Calcule le niveau de risque global basé sur les tactiques présentes.

    CRITICAL : Initial Access + Privilege Escalation présents simultanément
    HIGH      : Initial Access présent avec ≥ 2 autres tactiques
    MEDIUM    : Initial Access seul ou Lateral Movement sans Initial Access
    LOW       : Uniquement Discovery ou Credential Access
    """
    tactics_present = {t["tactic_id"] for t in all_techniques}

    has_initial  = "TA0001" in tactics_present
    has_privesc  = "TA0004" in tactics_present
    has_lateral  = "TA0008" in tactics_present
    has_impact   = "TA0040" in tactics_present
    has_exec     = "TA0002" in tactics_present

    if has_initial and (has_privesc or has_impact):
        return "CRITICAL"
    if has_initial and (has_lateral or has_exec or len(tactics_present) >= 3):
        return "HIGH"
    if has_initial:
        return "MEDIUM"
    if has_lateral or len(tactics_present) >= 2:
        return "MEDIUM"
    return "LOW"


def _generate_detection_priorities(phases: list[dict]) -> list[str]:
    """
    Extrait les hints de détection les plus pertinents depuis les techniques des phases,
    en priorisant Initial Access, Execution et Privilege Escalation.
    """
    priority_tactics = {"TA0001", "TA0002", "TA0004", "TA0008"}
    seen: set[str] = set()
    priorities: list[str] = []

    for phase in phases:
        if phase["tactic_id"] not in priority_tactics:
            continue
        for tech in phase["techniques"]:
            hint = tech.get("detection", "").strip()
            if hint and hint not in seen:
                seen.add(hint)
                priorities.append(hint)

    # Compléter avec les phases secondaires si moins de 3 priorités
    if len(priorities) < 3:
        for phase in phases:
            if phase["tactic_id"] in priority_tactics:
                continue
            for tech in phase["techniques"]:
                hint = tech.get("detection", "").strip()
                if hint and hint not in seen:
                    seen.add(hint)
                    priorities.append(hint)
                if len(priorities) >= 5:
                    break

    return priorities[:5]  # Maximum 5 priorités


def _generate_attack_path(all_techniques: list[dict]) -> dict:
    """
    Construit le chemin d'attaque hypothétique depuis la liste de techniques collectées.

    Retourne un dict avec :
      - phases   : liste ordonnée des phases du kill chain présentes
      - risk_level : CRITICAL / HIGH / MEDIUM / LOW
      - detection_priorities : liste de hints de détection prioritaires
    """
    # Grouper par tactique
    by_tactic: dict[str, list[dict]] = defaultdict(list)
    for t in all_techniques:
        by_tactic[t["tactic_id"]].append(t)

    # Construire les phases dans l'ordre du kill chain
    phases = []
    for tactic_id, tactic_name in _KILL_CHAIN:
        if tactic_id not in by_tactic:
            continue
        # Dédupliquer les techniques de cette phase
        unique_techs = _deduplicate_techniques(by_tactic[tactic_id])
        # Trier : confiance haute en premier
        _conf_rank = {"high": 3, "medium": 2, "low": 1}
        unique_techs.sort(key=lambda t: _conf_rank.get(t["confidence"], 0), reverse=True)

        phases.append({
            "phase":     len(phases) + 1,
            "tactic_id": tactic_id,
            "tactic":    tactic_name,
            "techniques": unique_techs,
            "narrative":  _TACTIC_NARRATIVES.get(tactic_id, ""),
        })

    risk_level = _calculate_risk_level(all_techniques)
    detection_priorities = _generate_detection_priorities(phases)

    return {
        "phases":               phases,
        "phases_count":         len(phases),
        "risk_level":           risk_level,
        "detection_priorities": detection_priorities,
    }


# ─── Point d'entrée public ───────────────────────────────────────────────────

def enrich_scan_result(data: dict) -> dict:
    """
    Enrichit un résultat de scan NetAudit avec le mapping ATT&CK.

    Modifie `data` en place et le retourne avec :
      - data["ports"][n]["service_techniques"] : techniques liées au service
      - data["ports"][n]["vulns"][m]["attack_techniques"] : techniques liées à la CVE
      - data["attack_summary"] : résumé du chemin d'attaque et risk level

    Ne lève jamais d'exception — en cas d'erreur, le scan original est retourné intact.
    """
    if not data.get("host_up") or not data.get("ports"):
        # Hôte injoignable ou aucun port : pas de mapping pertinent
        data["attack_summary"] = {
            "phases": [],
            "phases_count": 0,
            "risk_level": "LOW",
            "detection_priorities": [],
        }
        return data

    all_techniques: list[dict] = []

    try:
        for port_entry in data["ports"]:
            port    = port_entry.get("port", 0)
            service = port_entry.get("service", "")
            state   = port_entry.get("state", "")

            if state != "open":
                continue

            # Niveau 1 — mapping service
            svc_techs = _map_service_techniques(port, service)
            port_entry["service_techniques"] = svc_techs
            all_techniques.extend(svc_techs)

            # Niveau 2 — mapping CVEs
            for vuln in port_entry.get("vulns", []):
                cve_techs = _map_cve_techniques(
                    vuln_id=vuln.get("id", ""),
                    score=float(vuln.get("score", 0)),
                    service=service,
                    port=port,
                )
                vuln["attack_techniques"] = cve_techs
                all_techniques.extend(cve_techs)

        # Génération du chemin d'attaque global
        data["attack_summary"] = _generate_attack_path(all_techniques)

    except Exception as exc:  # pylint: disable=broad-except
        logging.error("Erreur lors de l'enrichissement ATT&CK", exc_info=True)
        data["attack_summary"] = {
            "phases": [],
            "phases_count": 0,
            "risk_level": "LOW",
            "detection_priorities": [],
            "error": str(exc),
        }

    return data
