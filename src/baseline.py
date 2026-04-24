"""
Baseline historique — détection de dérive entre deux scans d'une même IP.

Pourquoi ce module :
Un scan isolé répond à la question « quelle est la surface actuelle ? ». Il ne
répond pas à la question bien plus opérationnelle « qu'est-ce qui a *changé*
depuis la dernière fois ? ». C'est pourtant cette dernière qui déclenche la
plupart des alertes SOC réelles : un port qui s'ouvre du jour au lendemain,
une CVE qui bascule dans KEV, une base de données qui apparaît sur un frontal
web — autant de signaux faibles invisibles sans comparaison temporelle.

Approche
- Diff purement côté lecture : on ne modifie jamais le scan précédent, on
  produit une liste d'alertes typées en comparant `current` et `previous`.
- Alertes catégorisées (critical / warning / neutral / positive) pour que
  l'UI puisse les trier / colorer / escalader différemment.
- Persistance : le diff est embarqué dans `data["baseline"]` *avant* le
  record_scan, pour que chaque scan historique contienne déjà sa propre
  comparaison au précédent. Pas de recalcul ni de recomposition à l'affichage.
- 100 % local, déterministe, aucune dépendance réseau.

Catégories d'alertes
- **critical** : nouveau port DB/admin, nouvelle CVE KEV, nouvelle CVE
  ransomware, finding CRITICAL nouveau, dérive posture ≤ -20 pts, CVE
  existante qui bascule dans KEV.
- **warning** : autres nouveaux ports, nouvelle CVE HIGH (CVSS ≥ 7), finding
  HIGH nouveau, dérive posture -10 à -19, changement de rôle, régression
  de version.
- **neutral** : CVE MEDIUM/LOW apparues, findings MEDIUM/LOW nouveaux, port
  qui change de version sans régression évidente.
- **positive** : ports fermés, CVEs patchées, findings résolus, amélioration
  de posture ≥ +5.
"""
from __future__ import annotations

from typing import Iterable

# ── Sets de ports sensibles (alignés avec profiler.py) ───────────────────────

_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 7474, 11211, 9200}
_ADMIN_PORTS = {22, 23, 3389, 5985, 5986, 5900, 5901, 2222}
_SENSITIVE_PORTS = _DB_PORTS | _ADMIN_PORTS

# Priorité d'alerte pour tri et agrégation. Plus le chiffre est haut, plus
# l'alerte domine.
_LEVEL_RANK = {"critical": 3, "warning": 2, "neutral": 1, "positive": 0}

# Seuils posture — calibrés sur l'échelle 0-100 de profiler.posture_score.
_POSTURE_DROP_CRITICAL = 20
_POSTURE_DROP_WARNING = 10
_POSTURE_GAIN_POSITIVE = 5


# ── Helpers d'extraction ─────────────────────────────────────────────────────

def _iter_open_ports(data: dict) -> Iterable[dict]:
    """Itère sur les ports ouverts d'un scan. Tolérant aux scans malformés."""
    for port in (data or {}).get("ports", []) or []:
        if isinstance(port, dict) and (port.get("state") or "").lower() == "open":
            yield port


def _port_key(port: dict) -> tuple:
    """Clé d'identité d'un port. Protocole inclus car 80/tcp ≠ 80/udp."""
    return (port.get("port"), (port.get("protocol") or "").lower())


def _index_ports(data: dict) -> dict[tuple, dict]:
    return {_port_key(p): p for p in _iter_open_ports(data)}


def _index_vulns(data: dict) -> dict[str, dict]:
    """CVE → {port, vuln}. Une CVE multi-port n'est indexée qu'une fois —
    l'ancrage au premier port ouvert suffit pour la présentation."""
    out: dict[str, dict] = {}
    for port in _iter_open_ports(data):
        for v in port.get("vulns") or []:
            cve = (v.get("id") or "").strip()
            if cve and cve not in out:
                out[cve] = {"port": port.get("port"), "vuln": v}
    return out


def _port_label(port: dict) -> str:
    svc = port.get("service") or "?"
    return f"{port.get('port')}/{svc}"


# ── Diff ports ───────────────────────────────────────────────────────────────

def _diff_ports(current: dict, previous: dict) -> tuple[list, list, list]:
    """Retourne (added, removed, version_changes)."""
    cur_idx = _index_ports(current)
    prev_idx = _index_ports(previous)

    added = [
        {
            "port":     p.get("port"),
            "protocol": p.get("protocol"),
            "service":  p.get("service"),
            "version":  p.get("version"),
        }
        for key, p in cur_idx.items() if key not in prev_idx
    ]
    removed = [
        {
            "port":     p.get("port"),
            "protocol": p.get("protocol"),
            "service":  p.get("service"),
            "version":  p.get("version"),
        }
        for key, p in prev_idx.items() if key not in cur_idx
    ]

    version_changes = []
    for key, cur_p in cur_idx.items():
        prev_p = prev_idx.get(key)
        if prev_p is None:
            continue
        cur_v = (cur_p.get("version") or "").strip()
        prev_v = (prev_p.get("version") or "").strip()
        if cur_v != prev_v and (cur_v or prev_v):
            version_changes.append({
                "port":    cur_p.get("port"),
                "service": cur_p.get("service"),
                "from":    prev_v or "—",
                "to":      cur_v or "—",
            })
    return added, removed, version_changes


# ── Diff vulnérabilités ──────────────────────────────────────────────────────

def _vuln_summary(entry: dict) -> dict:
    v = entry.get("vuln") or {}
    kev = v.get("kev") or None
    return {
        "cve":            v.get("id"),
        "port":           entry.get("port"),
        "cvss":           v.get("score", 0) or 0,
        "priority_level": v.get("priority_level"),
        "priority_score": v.get("priority_score"),
        "kev":            bool(kev),
        "ransomware":     bool(kev and kev.get("ransomware")),
    }


def _diff_vulns(current: dict, previous: dict) -> tuple[list, list, list]:
    """Retourne (added, removed, kev_escalations).

    kev_escalations : CVEs présentes dans les deux scans mais qui n'étaient
    pas KEV avant et le sont maintenant. Signal fort — la CISA publie dans
    KEV seulement après preuve d'exploitation in-the-wild.
    """
    cur_idx = _index_vulns(current)
    prev_idx = _index_vulns(previous)

    added = [_vuln_summary(cur_idx[cve]) for cve in cur_idx if cve not in prev_idx]
    removed = [
        {"cve": cve, "port": prev_idx[cve].get("port")}
        for cve in prev_idx if cve not in cur_idx
    ]

    escalations = []
    for cve, cur_entry in cur_idx.items():
        prev_entry = prev_idx.get(cve)
        if prev_entry is None:
            continue
        cur_kev = bool((cur_entry["vuln"] or {}).get("kev"))
        prev_kev = bool((prev_entry["vuln"] or {}).get("kev"))
        if cur_kev and not prev_kev:
            kev = cur_entry["vuln"].get("kev") or {}
            escalations.append({
                "cve":        cve,
                "port":       cur_entry.get("port"),
                "ransomware": bool(kev.get("ransomware")),
            })
    return added, removed, escalations


# ── Diff findings / posture / role ───────────────────────────────────────────

def _finding_key(f: dict) -> tuple:
    """Clé stable pour un finding. `rule_id` est figé dans le nom de fonction
    de la règle (profiler.py), donc insensible aux reformulations de titre.
    Fallback (title, severity) pour les scans antérieurs à 2.6 qui n'ont pas
    encore `rule_id`.
    """
    rule_id = f.get("rule_id")
    if rule_id:
        return ("rule", rule_id)
    return ("text", f.get("title"), f.get("severity"))


def _diff_findings(current: dict, previous: dict) -> tuple[list, list]:
    cur_findings = (current.get("context") or {}).get("findings") or []
    prev_findings = (previous.get("context") or {}).get("findings") or []
    cur = {_finding_key(f): f for f in cur_findings}
    prev = {_finding_key(f): f for f in prev_findings}
    new = [
        {"title": f.get("title"), "severity": f.get("severity"), "rule_id": f.get("rule_id")}
        for k, f in cur.items() if k not in prev
    ]
    resolved = [
        {"title": f.get("title"), "severity": f.get("severity"), "rule_id": f.get("rule_id")}
        for k, f in prev.items() if k not in cur
    ]
    return new, resolved


def _diff_posture(current: dict, previous: dict) -> dict | None:
    cur_ctx = current.get("context") or {}
    prev_ctx = previous.get("context") or {}
    if not cur_ctx or not prev_ctx:
        return None
    cur_score = cur_ctx.get("posture_score")
    prev_score = prev_ctx.get("posture_score")
    if cur_score is None or prev_score is None:
        return None
    delta = cur_score - prev_score
    if delta == 0:
        return None
    return {
        "from":       prev_score,
        "to":         cur_score,
        "delta":      delta,
        "from_grade": prev_ctx.get("posture_grade", "?"),
        "to_grade":   cur_ctx.get("posture_grade", "?"),
    }


def _diff_role(current: dict, previous: dict) -> dict | None:
    cur_role = (current.get("context") or {}).get("role")
    prev_role = (previous.get("context") or {}).get("role")
    if not cur_role or not prev_role or cur_role == prev_role:
        return None
    return {"from": prev_role, "to": cur_role}


# ── Construction d'alertes ───────────────────────────────────────────────────

def _alert(level: str, type_: str, title: str, description: str, evidence: str = "") -> dict:
    return {
        "level":       level,
        "type":        type_,
        "title":       title,
        "description": description,
        "evidence":    evidence,
    }


def _level_for_port(port: int | None) -> str:
    if port in _DB_PORTS:
        return "critical"
    if port in _ADMIN_PORTS:
        return "critical"
    return "warning"


def _level_for_cvss(score: float) -> str:
    try:
        s = float(score or 0)
    except (TypeError, ValueError):
        s = 0.0
    if s >= 7.0:
        return "warning"
    return "neutral"


def _level_for_severity(severity: str) -> str:
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        return "critical"
    if sev == "HIGH":
        return "warning"
    return "neutral"


def _build_alerts(changes: dict) -> list[dict]:
    """Transforme un dict de changements en liste d'alertes typées et triées."""
    alerts: list[dict] = []

    # Nouveaux ports — criticité selon la sensibilité du port.
    for p in changes["ports_added"]:
        port_num = p.get("port")
        level = _level_for_port(port_num)
        label = f"{port_num}/{p.get('service') or '?'}"
        if port_num in _DB_PORTS:
            title = f"Nouveau port base de données exposé : {label}"
            desc = ("Une base de données est maintenant accessible, elle ne l'était pas au scan "
                    "précédent. À investiguer immédiatement — exposition accidentelle ou "
                    "déploiement non documenté.")
        elif port_num in _ADMIN_PORTS:
            title = f"Nouveau port d'administration ouvert : {label}"
            desc = ("Un port d'administration est apparu. Vérifier que l'ouverture est "
                    "intentionnelle et protégée (authentification forte, IP autorisées).")
        else:
            title = f"Nouveau port ouvert : {label}"
            desc = "Un service est exposé qui ne l'était pas au scan précédent."
        alerts.append(_alert(level, "port_added", title, desc,
                              f"{label} (version : {p.get('version') or 'non identifiée'})"))

    # Ports fermés — positif.
    for p in changes["ports_removed"]:
        label = f"{p.get('port')}/{p.get('service') or '?'}"
        alerts.append(_alert(
            "positive", "port_removed",
            f"Port fermé : {label}",
            "Réduction de surface — ce service n'est plus exposé.",
            label,
        ))

    # Changements de version — flaggés en warning sur les services sensibles
    # (SSH, web, DB) pour éviter le bruit sur des bumps mineurs de services
    # d'infrastructure peu critiques.
    for ch in changes["version_changes"]:
        port = ch.get("port")
        sensitive = port in _SENSITIVE_PORTS or port in {80, 443, 8080, 8443}
        level = "warning" if sensitive else "neutral"
        alerts.append(_alert(
            level, "version_change",
            f"Version modifiée sur {port}/{ch.get('service') or '?'}",
            ("La version du service a changé depuis le dernier scan. Un downgrade "
             "ou un remplacement par un build moins à jour peut réintroduire des CVEs."),
            f"{ch['from']} → {ch['to']}",
        ))

    # Nouvelles CVEs.
    for v in changes["vulns_added"]:
        if v.get("ransomware"):
            level = "critical"
            prefix = "Nouvelle CVE exploitée par ransomware"
        elif v.get("kev"):
            level = "critical"
            prefix = "Nouvelle CVE dans CISA KEV"
        else:
            level = _level_for_cvss(v.get("cvss", 0))
            prefix = "Nouvelle CVE"
        alerts.append(_alert(
            level, "vuln_added",
            f"{prefix} : {v['cve']}",
            ("Cette vulnérabilité n'était pas présente au scan précédent. "
             "À corréler avec un changement de version ou l'apparition d'un nouveau service."),
            f"CVE {v['cve']} · port {v.get('port')} · CVSS {v.get('cvss')}",
        ))

    # CVEs patchées.
    for v in changes["vulns_removed"]:
        alerts.append(_alert(
            "positive", "vuln_removed",
            f"CVE corrigée : {v['cve']}",
            "La vulnérabilité n'apparaît plus dans le scan courant.",
            f"port {v.get('port')}",
        ))

    # Escalades KEV — CVE connue mais qui vient de basculer dans KEV.
    for e in changes["kev_escalations"]:
        alerts.append(_alert(
            "critical", "kev_escalation",
            f"Escalade KEV : {e['cve']} désormais activement exploitée",
            ("Cette CVE était déjà présente mais sans preuve d'exploitation. "
             "Sa présence dans CISA KEV indique une exploitation avérée in-the-wild "
             "— fenêtre de patching à accélérer."),
            f"CVE {e['cve']} · port {e.get('port')}" +
            (" · ransomware" if e.get("ransomware") else ""),
        ))

    # Findings nouveaux.
    for f in changes["findings_new"]:
        alerts.append(_alert(
            _level_for_severity(f.get("severity")), "finding_new",
            f"Nouveau finding [{f.get('severity')}] : {f.get('title')}",
            "Un anti-pattern de posture est apparu depuis le dernier scan.",
            "",
        ))

    # Findings résolus.
    for f in changes["findings_resolved"]:
        alerts.append(_alert(
            "positive", "finding_resolved",
            f"Finding corrigé : {f.get('title')}",
            "Ce finding de posture n'est plus détecté.",
            f"sévérité initiale : {f.get('severity')}",
        ))

    # Dérive de posture.
    pch = changes["posture_change"]
    if pch:
        delta = pch["delta"]
        if delta <= -_POSTURE_DROP_CRITICAL:
            level = "critical"
        elif delta <= -_POSTURE_DROP_WARNING:
            level = "warning"
        elif delta >= _POSTURE_GAIN_POSITIVE:
            level = "positive"
        else:
            level = "neutral"
        direction = "régression" if delta < 0 else "amélioration"
        alerts.append(_alert(
            level, "posture_change",
            f"Posture en {direction} de {abs(delta)} pts",
            ("Le score de posture agrège les anti-patterns détectés. "
             "Une variation significative reflète un changement concret de configuration."),
            f"{pch['from']}/100 ({pch['from_grade']}) → {pch['to']}/100 ({pch['to_grade']})",
        ))

    # Changement de rôle — neutre, mais à signaler (surface différente).
    rch = changes["role_change"]
    if rch:
        alerts.append(_alert(
            "warning", "role_change",
            f"Rôle de l'hôte reclassifié : {rch['from']} → {rch['to']}",
            ("La classification automatique du rôle a changé. "
             "Cela peut indiquer un repurposing de la machine ou l'apparition de services qui "
             "ont déplacé le vote majoritaire."),
            "",
        ))

    # Tri : critical d'abord, positive en fin.
    alerts.sort(key=lambda a: -_LEVEL_RANK.get(a["level"], 0))
    return alerts


# ── API publique ─────────────────────────────────────────────────────────────

def compare_scans(current: dict, previous: dict) -> dict:
    """Produit un diff typé entre deux scans de la même IP.

    `current` et `previous` sont des payloads de scan complets (tels que
    produits par `scan.lancer_scan`, enrichis par prioritizer et profiler).
    La fonction ne mute ni l'un ni l'autre.
    """
    ports_added, ports_removed, version_changes = _diff_ports(current, previous)
    vulns_added, vulns_removed, kev_escalations = _diff_vulns(current, previous)
    findings_new, findings_resolved = _diff_findings(current, previous)
    posture_change = _diff_posture(current, previous)
    role_change = _diff_role(current, previous)

    changes = {
        "ports_added":       ports_added,
        "ports_removed":     ports_removed,
        "version_changes":   version_changes,
        "vulns_added":       vulns_added,
        "vulns_removed":     vulns_removed,
        "kev_escalations":   kev_escalations,
        "findings_new":      findings_new,
        "findings_resolved": findings_resolved,
        "posture_change":    posture_change,
        "role_change":       role_change,
    }

    alerts = _build_alerts(changes)

    summary = {
        "critical": sum(1 for a in alerts if a["level"] == "critical"),
        "warning":  sum(1 for a in alerts if a["level"] == "warning"),
        "neutral":  sum(1 for a in alerts if a["level"] == "neutral"),
        "positive": sum(1 for a in alerts if a["level"] == "positive"),
    }
    summary["has_drift"] = summary["critical"] > 0 or summary["warning"] > 0
    summary["total"] = len(alerts)

    return {
        "changes": changes,
        "alerts":  alerts,
        "summary": summary,
    }


def _empty_baseline() -> dict:
    """Payload retourné quand il n'y a pas de scan précédent pour cette IP."""
    return {
        "has_previous":  False,
        "previous_date": None,
        "previous_id":   None,
        "changes":       None,
        "alerts":        [],
        "summary":       {
            "critical": 0, "warning": 0, "neutral": 0, "positive": 0,
            "total":    0, "has_drift": False,
        },
    }


def enrich_baseline(current: dict, previous_record: dict | None) -> dict:
    """Mute `current` en place en ajoutant `current["baseline"]`.

    `previous_record` : élément issu de `history.scans_for_ip()` (dict avec
    clés `id`, `scan_date`, `data`). Peut être None si c'est le premier scan
    de cette IP — dans ce cas on renvoie un baseline "vide" cohérent plutôt
    que d'omettre la clé, pour simplifier la logique côté template.

    On ne stocke *pas* les données du scan précédent dans `current` — juste
    une référence (id, date) et le diff. Ça évite le bloat récursif (sinon
    chaque nouveau scan embarquerait toute la chaîne historique).
    """
    if not previous_record or not previous_record.get("data"):
        current["baseline"] = _empty_baseline()
        return current

    previous_data = previous_record["data"]
    diff = compare_scans(current, previous_data)

    current["baseline"] = {
        "has_previous":  True,
        "previous_date": previous_record.get("scan_date"),
        "previous_id":   previous_record.get("id"),
        "changes":       diff["changes"],
        "alerts":        diff["alerts"],
        "summary":       diff["summary"],
    }
    return current
