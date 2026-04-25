"""
Priorisation réelle des vulnérabilités — au-delà du CVSS brut.

NetAudit v2.1 ne faisait que remonter le score CVSS. Or une CVE CVSS 9.8 jamais
exploitée dans la nature est souvent moins urgente qu'une CVSS 7.5 activement
exploitée par des campagnes de ransomware. Ce module corrige ce biais en
croisant deux sources publiques autoritatives :

- **CISA KEV** (Known Exploited Vulnerabilities) — liste officielle US des
  CVEs activement exploitées, mise à jour par la CISA. Présence dans KEV =
  preuve d'exploitation réelle. Flag complémentaire `knownRansomwareCampaignUse`.
- **FIRST EPSS** (Exploit Prediction Scoring System) — score probabiliste
  (0–1) de l'exploitation d'une CVE dans les 30 prochains jours, recalculé
  quotidiennement à partir de signaux threat intel.

Score de priorité combiné :
    priority = CVSS_base
             + 3.0 si présent dans KEV (exploitation avérée)
             + 1.5 si KEV flag ransomware (impact opérationnel élevé)
             + 2.0 × EPSS si EPSS ≥ 0.5 (probabilité forte)
             + 1.0 × EPSS si EPSS < 0.5 (pondération résiduelle)
    → niveau : IMMEDIATE (≥ 13) / HIGH (≥ 10) / MEDIUM (≥ 6) / LOW (≥ 3) / INFO (< 3)

Contraintes d'intégration
- Offline-safe : un échec réseau ne doit jamais casser un scan. Les fetchers
  retournent un dict vide, les vulns sortent sans enrichissement mais le scan
  aboutit.
- Cache sur disque avec TTL 24 h. Le second scan de la journée ne retape pas
  les APIs. Un cache périmé reste utilisable en mode dégradé si la nouvelle
  fetch échoue (mieux que rien).
- Batch EPSS : une seule requête API par scan, tous les CVEs en une fois.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.getenv("CACHE_DIR", os.path.join(BASE_DIR, "..", "cache"))

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

KEV_CACHE_FILE = "kev.json"
KEV_META_FILE = "kev.meta.json"
EPSS_CACHE_FILE = "epss.json"
CACHE_TTL_SECONDS = 24 * 3600
HTTP_TIMEOUT = 10
EPSS_BATCH_SIZE = 80  # Bornage URL ~2 ko ; ~15 caractères par CVE

# Toggle global : permet de désactiver les appels réseau (tests, offline,
# environnements contraints). Dans ces cas, seul le CVSS sert de signal.
PRIORITIZER_ENABLED = os.getenv("PRIORITIZER_ENABLED", "1").lower() not in ("0", "false", "no")


# ── Cache filesystem ─────────────────────────────────────────────────────────

def _cache_path(name: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def _read_cache(name: str) -> tuple[dict | None, bool]:
    """Retourne (contenu, fresh) — `fresh` indique si le cache est encore dans son TTL."""
    path = _cache_path(name)
    if not os.path.isfile(path):
        return None, False
    try:
        age = time.time() - os.path.getmtime(path)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), age < CACHE_TTL_SECONDS
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("Cache %s illisible : %s", name, exc)
        return None, False


def _write_cache(name: str, payload: dict) -> None:
    """Écrit le cache de manière atomique : tempfile dans le même dossier
    puis `os.replace`. Évite la corruption si deux workers refresh en même
    temps — un lecteur ne verra jamais un fichier partiellement écrit.
    `os.replace` est atomique sur POSIX et Windows (même filesystem).
    """
    path = _cache_path(name)
    tmp_path = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp_path, path)
    except OSError as exc:
        logging.warning("Écriture cache %s échouée : %s", name, exc)
        # Nettoyage du tempfile si l'échec est arrivé avant le replace.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _touch_cache(name: str) -> None:
    """Rafraîchit le mtime d'un fichier cache sans toucher son contenu.
    Utilisé après un 304 Not Modified pour reporter le TTL."""
    path = _cache_path(name)
    try:
        os.utime(path, None)
    except OSError as exc:
        logging.warning("Touch cache %s échoué : %s", name, exc)


def _http_get_json(url: str, timeout: int = HTTP_TIMEOUT) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetAudit/2.6.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError) as exc:
        logging.warning("GET %s échoué : %s", url, exc)
        return None


def _http_get_json_conditional(
    url: str,
    last_modified: str | None = None,
    timeout: int = HTTP_TIMEOUT,
) -> tuple[dict | None, str | None, int]:
    """GET conditionnel — envoie `If-Modified-Since` si `last_modified` est fourni.

    Retourne `(data, last_modified, status)`.
    - 200 OK → `(parsed_json, new_last_modified, 200)`
    - 304 Not Modified → `(None, last_modified, 304)` (appelant garde son cache)
    - Échec / erreur → `(None, None, 0)`
    """
    headers = {"User-Agent": "NetAudit/2.6.2"}
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            new_last_modified = resp.headers.get("Last-Modified") or last_modified
            return json.loads(resp.read().decode("utf-8")), new_last_modified, 200
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, last_modified, 304
        logging.warning("GET %s échoué (HTTP %s) : %s", url, exc.code, exc)
        return None, None, 0
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        logging.warning("GET %s échoué : %s", url, exc)
        return None, None, 0


# ── KEV : catalogue CISA ─────────────────────────────────────────────────────

def fetch_kev(force_refresh: bool = False) -> dict[str, dict]:
    """Retourne {cve_id: {ransomware: bool, due_date: str, short_desc: str}}.

    Stratégie :
    1. Cache frais → utilisé directement.
    2. Cache périmé + réseau OK → GET conditionnel (`If-Modified-Since`) :
       - 200 → nouveau contenu, remplace cache + méta.
       - 304 → cache inchangé, on refresh juste son `mtime`.
    3. Cache périmé + réseau KO → dégrade sur le cache périmé (mieux que rien).
    4. Pas de cache + réseau KO → dict vide (scan continue sans enrichissement).

    Le catalogue CISA KEV fait ~1 Mo et ne change pas tous les jours. Le
    `If-Modified-Since` économise la bande passante et la latence quand le
    cache est périmé mais toujours valide côté serveur.
    """
    if not PRIORITIZER_ENABLED:
        return {}

    cached, fresh = _read_cache(KEV_CACHE_FILE)
    if cached is not None and fresh and not force_refresh:
        return cached

    meta, _ = _read_cache(KEV_META_FILE)
    last_modified = (meta or {}).get("last_modified") if meta else None

    raw, new_last_modified, status = _http_get_json_conditional(KEV_URL, last_modified)

    if status == 304 and cached is not None:
        # Serveur confirme : cache toujours valide. On refresh le mtime pour
        # éviter de retaper l'API avant 24 h.
        _touch_cache(KEV_CACHE_FILE)
        return cached

    if raw is None:
        return cached or {}

    index: dict[str, dict] = {}
    for entry in raw.get("vulnerabilities", []):
        cve = entry.get("cveID", "").strip()
        if not cve:
            continue
        index[cve] = {
            "ransomware":  entry.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            "due_date":    entry.get("dueDate", ""),
            "short_desc":  entry.get("shortDescription", ""),
            "date_added":  entry.get("dateAdded", ""),
        }
    _write_cache(KEV_CACHE_FILE, index)
    if new_last_modified:
        _write_cache(KEV_META_FILE, {"last_modified": new_last_modified})
    return index


# ── EPSS : scores FIRST ──────────────────────────────────────────────────────

def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Retourne {cve_id: {score: float, percentile: float}}.

    Stratégie cache :
    - Cache agrégé par CVE, TTL 24 h — on ne retape l'API que pour les CVEs
      absentes ou périmées du cache.
    - Bornage à EPSS_BATCH_SIZE CVEs par requête pour rester sous la limite
      de longueur d'URL du serveur FIRST.
    """
    if not PRIORITIZER_ENABLED:
        return {}

    cached, _ = _read_cache(EPSS_CACHE_FILE)
    cached = cached or {}
    now = time.time()

    out: dict[str, dict] = {}
    missing: list[str] = []
    for cve in cve_ids:
        if not cve.upper().startswith("CVE-"):
            continue
        entry = cached.get(cve)
        if entry and now - entry.get("_ts", 0) < CACHE_TTL_SECONDS:
            out[cve] = {"score": entry["score"], "percentile": entry["percentile"]}
        else:
            missing.append(cve)

    for i in range(0, len(missing), EPSS_BATCH_SIZE):
        batch = missing[i:i + EPSS_BATCH_SIZE]
        qs = urllib.parse.urlencode({"cve": ",".join(batch)})
        raw = _http_get_json(f"{EPSS_URL}?{qs}")
        if raw is None:
            continue
        for item in raw.get("data", []):
            cve = item.get("cve", "")
            try:
                score = float(item.get("epss", 0) or 0)
                pct = float(item.get("percentile", 0) or 0)
            except (TypeError, ValueError):
                continue
            out[cve] = {"score": score, "percentile": pct}
            cached[cve] = {"score": score, "percentile": pct, "_ts": now}

    if missing:
        _write_cache(EPSS_CACHE_FILE, cached)
    return out


# ── Scoring ──────────────────────────────────────────────────────────────────

def priority_score(cvss: float, epss: float | None, in_kev: bool, ransomware: bool) -> float:
    """Combine CVSS (0–10), EPSS (0–1), présence KEV et flag ransomware.

    Le CVSS reste la fondation. KEV et ransomware ajoutent des bumps fixes
    qui reflètent un signal factuel (exploitation avérée, impact opérationnel
    démontré). EPSS est une pondération continue : on double son poids au-delà
    de 0.5 pour bien distinguer « probable » de « marginal ».
    """
    try:
        base = max(0.0, min(float(cvss or 0), 10.0))
    except (TypeError, ValueError):
        base = 0.0

    score = base
    if in_kev:
        score += 3.0
    if ransomware:
        score += 1.5
    if epss is not None:
        try:
            e = max(0.0, min(float(epss), 1.0))
        except (TypeError, ValueError):
            e = 0.0
        score += 2.0 * e if e >= 0.5 else 1.0 * e
    return round(score, 2)


def priority_level(score: float) -> str:
    """Mappe un score numérique vers un label utilisable dans le rapport."""
    if score >= 13.0:
        return "IMMEDIATE"
    if score >= 10.0:
        return "HIGH"
    if score >= 6.0:
        return "MEDIUM"
    if score >= 3.0:
        return "LOW"
    return "INFO"


def priority_reasons(
    cvss: float,
    epss: float | None,
    in_kev: bool,
    ransomware: bool,
) -> list[dict]:
    """Explicabilité du score : raisons lisibles qui ont contribué au niveau.

    Chaque entrée = {"code": ..., "label": ...}. Le `code` permet à l'UI de
    colorer/filtrer ; le `label` est affiché tel quel. Ordre : signaux les
    plus discriminants en premier (KEV > ransomware > EPSS fort > CVSS).
    Sert à désamorcer la critique « score opaque » — le lecteur voit
    directement *pourquoi* le niveau a été émis.
    """
    reasons: list[dict] = []

    if in_kev:
        reasons.append({
            "code":  "kev",
            "label": "Présente dans CISA KEV — exploitation active confirmée",
        })
    if ransomware:
        reasons.append({
            "code":  "ransomware",
            "label": "Utilisée par des campagnes ransomware documentées",
        })

    if epss is not None:
        try:
            e = max(0.0, min(float(epss), 1.0))
        except (TypeError, ValueError):
            e = 0.0
        if e >= 0.5:
            reasons.append({
                "code":  "epss_high",
                "label": f"EPSS {e:.2f} — probabilité forte d'exploitation à 30 jours",
            })
        elif e >= 0.1:
            reasons.append({
                "code":  "epss_medium",
                "label": f"EPSS {e:.2f} — exploitation possible à court terme",
            })

    try:
        c = float(cvss or 0)
    except (TypeError, ValueError):
        c = 0.0
    if c >= 9.0:
        reasons.append({"code": "cvss_critical", "label": f"CVSS {c:.1f} (critique)"})
    elif c >= 7.0:
        reasons.append({"code": "cvss_high",     "label": f"CVSS {c:.1f} (élevée)"})
    elif c >= 4.0:
        reasons.append({"code": "cvss_medium",   "label": f"CVSS {c:.1f} (moyenne)"})
    elif c > 0:
        reasons.append({"code": "cvss_low",      "label": f"CVSS {c:.1f} (faible)"})

    return reasons


# ── Enrichissement du scan ───────────────────────────────────────────────────

def _collect_cve_ids(data: dict) -> list[str]:
    seen: set[str] = set()
    ids: list[str] = []
    for port in data.get("ports", []):
        for v in port.get("vulns", []):
            cve = (v.get("id") or "").strip()
            if cve.upper().startswith("CVE-") and cve not in seen:
                seen.add(cve)
                ids.append(cve)
    return ids


def _level_rank(level: str) -> int:
    return {"IMMEDIATE": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(level, 0)


def enrich_vulns(data: dict) -> dict:
    """Mute `data` en place en ajoutant à chaque vuln :
        - epss       : {score, percentile} ou None
        - kev        : {ransomware, due_date, short_desc} ou None
        - priority_score : float
        - priority_level : IMMEDIATE | HIGH | MEDIUM | LOW | INFO

    Ajoute aussi `data["priority_summary"]` : synthèse pour le rapport.
    """
    cve_ids = _collect_cve_ids(data)
    if not cve_ids:
        data["priority_summary"] = _empty_summary()
        return data

    kev_idx = fetch_kev()
    epss_idx = fetch_epss(cve_ids)

    counts = {"IMMEDIATE": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    max_level = "INFO"
    kev_count = 0
    ransomware_count = 0
    top_vulns: list[dict] = []

    for port in data.get("ports", []):
        for v in port.get("vulns", []):
            cve = (v.get("id") or "").strip()
            kev_entry = kev_idx.get(cve)
            epss_entry = epss_idx.get(cve)

            in_kev = kev_entry is not None
            ransomware = bool(kev_entry and kev_entry.get("ransomware"))
            epss_score = epss_entry["score"] if epss_entry else None

            score = priority_score(
                cvss=v.get("score", 0),
                epss=epss_score,
                in_kev=in_kev,
                ransomware=ransomware,
            )
            level = priority_level(score)
            reasons = priority_reasons(
                cvss=v.get("score", 0),
                epss=epss_score,
                in_kev=in_kev,
                ransomware=ransomware,
            )

            v["epss"] = epss_entry
            v["kev"] = kev_entry
            v["priority_score"] = score
            v["priority_level"] = level
            v["priority_reasons"] = reasons

            counts[level] += 1
            if _level_rank(level) > _level_rank(max_level):
                max_level = level
            if in_kev:
                kev_count += 1
            if ransomware:
                ransomware_count += 1
            top_vulns.append({
                "id": cve, "port": port.get("port"),
                "priority_score": score, "priority_level": level,
                "in_kev": in_kev, "ransomware": ransomware,
                "reasons": reasons,
            })

    top_vulns.sort(key=lambda x: x["priority_score"], reverse=True)

    data["priority_summary"] = {
        "max_level":        max_level,
        "counts":           counts,
        "kev_count":        kev_count,
        "ransomware_count": ransomware_count,
        "top":              top_vulns[:5],
        "sources_used":     _sources_used(kev_idx, epss_idx),
    }
    return data


def _empty_summary() -> dict:
    return {
        "max_level":        "INFO",
        "counts":           {"IMMEDIATE": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "kev_count":        0,
        "ransomware_count": 0,
        "top":              [],
        "sources_used":     [],
    }


def _sources_used(kev_idx: dict, epss_idx: dict) -> list[str]:
    used: list[str] = []
    if kev_idx:
        used.append("CISA KEV")
    if epss_idx:
        used.append("FIRST EPSS")
    return used
