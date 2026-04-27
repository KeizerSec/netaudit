# `load_dotenv` DOIT être appelé avant tout import applicatif — scan.py et
# history.py lisent des variables d'environnement (LOG_FILE_PATH, REPORT_DIR,
# HISTORY_DB_PATH, NMAP_TIMEOUT, CACHE_SIZE) à l'import du module. Si
# `load_dotenv()` arrive après ces imports, le `.env` est silencieusement
# ignoré pour toutes ces variables — seul `API_KEY` (lu ici) serait honoré.
# Régression identifiée en 2.6.2 : on le remet en première position.
from dotenv import load_dotenv
load_dotenv()

import hmac
import os
import logging
from functools import wraps

from flask import Flask, jsonify, send_file, request, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from scan import lancer_scan, valider_ip, REPORT_DIR, setup_logging
from version import version_info, __version__
from history import list_scans, scans_for_ip, init_db, db_health
from exports import render_pdf

# Initialisations explicites au démarrage de l'application :
# - setup_logging configure le root logger (fichier rotaté + stdout) ;
# - init_db crée le schéma SQLite si absent.
# scan.py et history.py ne font plus ces appels à l'import pour éviter
# les side-effects dans les tests, les imports croisés et les analyseurs
# statiques.
setup_logging()
init_db()

app = Flask(__name__)

# Rate limiting global + par endpoint.
#
# Storage in-process par défaut (`memory://`) — adapté au déploiement single-host
# du projet et zéro dépendance d'infra. En multi-instances ou multi-workers stricts,
# régler `RATELIMIT_STORAGE_URI=redis://host:6379` (ou memcached://, etc.) pour
# mutualiser les compteurs ; sinon chaque worker applique son quota localement.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200/day", "60/hour"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

# Clé API — si vide, l'authentification est désactivée (mode dev).
#
# `REQUIRE_API_KEY=1` (ou `true`) impose la présence de la clé : si elle est
# absente, le module refuse d'être importé. Cette variable est destinée aux
# environnements de production où une `API_KEY` oubliée serait un incident
# de sécurité — un `logging.warning` se perd dans les logs, un `SystemExit`
# arrête le boot et garantit que le déploiement échoue visiblement.
API_KEY: str = os.getenv("API_KEY", "")
REQUIRE_API_KEY: bool = os.getenv("REQUIRE_API_KEY", "0").lower() in ("1", "true", "yes")

if REQUIRE_API_KEY and not API_KEY:
    raise SystemExit(
        "REQUIRE_API_KEY=1 mais API_KEY est vide. Refus de démarrer pour "
        "éviter d'exposer un endpoint /scan non authentifié en production."
    )

if not API_KEY:
    logging.warning(
        "API_KEY non définie — authentification désactivée. "
        "Définissez API_KEY en production (ou REQUIRE_API_KEY=1 pour fail-fast)."
    )


def require_api_key(f):
    """Décorateur : vérifie l'en-tête X-API-Key si API_KEY est configurée.

    Utilise hmac.compare_digest pour une comparaison à temps constant,
    évitant les attaques par timing sur la clé.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY:
            provided = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(provided, API_KEY):
                return jsonify({
                    "error":  "Clé API invalide ou manquante.",
                    "status": "unauthorized",
                }), 401
        return f(*args, **kwargs)
    return decorated


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.route("/scan", methods=["POST"])
@require_api_key
@limiter.limit("5/minute", exempt_when=lambda: app.testing)
def scan():
    """Lance un scan Nmap sur l'IP fournie en payload JSON.

    Méthode `POST` plutôt que `GET` parce qu'un scan est une action lourde,
    non-idempotente et avec effet de bord (record SQLite, génération de
    rapport, appel réseau). Un `GET` serait préchargé par les bots, les
    prefetchers de navigateur, les unfurls de messageries et les caches HTTP
    intermédiaires — autant d'occasions de déclencher des scans involontaires.

    Headers requis :
        Content-Type: application/json
        X-API-Key: <votre_clé>           (si API_KEY configurée)

    Body :
        {"ip": "192.168.1.1"}

    Réponse 200 :
        {
            "status": "ok",
            "ip": "...",
            "host_up": bool,
            "scan_date": "...",
            "ports": [...],
            "total_vulns": int,
            "rapport_html": "/rapport/<ip>"
        }
    """
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()

    if not ip:
        return jsonify({
            "error":  "Champ 'ip' requis dans le body JSON.",
            "status": "failed",
        }), 400

    if not valider_ip(ip):
        return jsonify({"error": "Adresse IP invalide.", "status": "failed"}), 400

    data, _ = lancer_scan(ip)

    if data is None:
        return jsonify({"error": "Scan non lancé.", "status": "failed"}), 500

    if "error" in data:
        return jsonify({"error": data["error"], "status": "failed"}), 500

    return jsonify({
        "status":           "ok",
        "ip":               data["ip"],
        "host_up":          data["host_up"],
        "hostname":         data.get("hostname", ""),
        "os_guess":         data.get("os_guess", ""),
        "scan_date":        data.get("scan_date"),
        "ports":            data["ports"],
        "total_vulns":      data["total_vulns"],
        "attack_summary":   data.get("attack_summary"),
        "priority_summary": data.get("priority_summary"),
        "context":          data.get("context"),
        "baseline":         data.get("baseline"),
        "rapport_html":     f"/rapport/{ip}",
    })


@app.route("/rapport/<ip>")
@require_api_key
def rapport(ip: str):
    """
    Retourne le rapport d'un scan précédemment effectué.

    Paramètre `format` (query string) :
      - absent ou `html` → rapport HTML complet (défaut).
      - `json`           → data structurée complète (issue du dernier scan persisté).
      - `pdf`            → rapport PDF A4 téléchargeable.

    Renvoie 404 si le scan n'a pas encore été lancé.
    """
    if not valider_ip(ip):
        return jsonify({"error": "Adresse IP invalide."}), 400

    fmt = (request.args.get("format") or "html").lower()

    if fmt == "json":
        records = scans_for_ip(ip, limit=1)
        if not records:
            return jsonify({"error": "Aucun scan enregistré.", "status": "not_found"}), 404
        return jsonify(records[0].get("data") or {})

    if fmt == "pdf":
        records = scans_for_ip(ip, limit=1)
        if not records or not records[0].get("data"):
            return jsonify({"error": "Aucun scan enregistré.", "status": "not_found"}), 404
        pdf_bytes = render_pdf(records[0]["data"])
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="netaudit_{ip}.pdf"'},
        )

    # Format HTML par défaut — fichier statique généré par sauvegarder_rapport().
    # Construction sécurisée du chemin (protection anti path-traversal)
    chemin = os.path.realpath(os.path.join(REPORT_DIR, f"{ip}_scan.html"))
    reports_real = os.path.realpath(REPORT_DIR)

    if not chemin.startswith(reports_real + os.sep):
        return jsonify({"error": "Accès refusé."}), 403

    if not os.path.isfile(chemin):
        return jsonify({
            "error": "Rapport introuvable. Lancez d'abord /scan/<ip>.",
            "status": "not_found",
        }), 404

    return send_file(chemin)


@app.route("/health")
def health():
    """Endpoint de vérification — utilisé par les probes Docker / load balancer.

    Retourne le statut applicatif et l'état de la persistance, pour que
    l'opérateur distingue « le process répond » de « le process *et* la base
    répondent ». L'endpoint reste 200 même si la DB est dégradée — c'est à
    l'agrégateur (Prometheus, NewRelic, …) de définir une politique d'alerte
    sur le champ `history_db`. Renvoyer 503 ici déclencherait des restarts en
    boucle là où une simple alerte suffirait.
    """
    return jsonify({
        "status":     "ok",
        "history_db": "ok" if db_health() else "degraded",
        "version":    __version__,
    }), 200


@app.route("/version")
def version():
    """Retourne nom, version sémantique et hash commit courant.

    Public (pas d'API key requise) — ces informations sont nécessaires aux
    probes et aux outils de monitoring pour tracer précisément quelle build
    répond. Ne contient aucune donnée sensible.
    """
    return jsonify(version_info()), 200


@app.route("/history")
@require_api_key
def history():
    """Liste synthétique des derniers scans persistés (toutes IPs confondues).

    Paramètre optionnel `limit` (défaut 100, max 500).
    """
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    return jsonify({
        "status": "ok",
        "count":  len(scans := list_scans(limit=limit)),
        "scans":  scans,
    })


@app.route("/history/<ip>")
@require_api_key
def history_for_ip(ip: str):
    """Historique détaillé (data complète) pour une IP donnée."""
    if not valider_ip(ip):
        return jsonify({"error": "Adresse IP invalide.", "status": "failed"}), 400

    scans = scans_for_ip(ip)
    return jsonify({
        "status": "ok",
        "ip":     ip,
        "count":  len(scans),
        "scans":  scans,
    })


# ─── Gestionnaires d'erreurs ──────────────────────────────────────────────────

@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({"error": "Trop de requêtes.", "status": "rate_limited"}), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint introuvable.", "status": "not_found"}), 404


@app.errorhandler(500)
def internal_error(e):
    logging.exception("Erreur interne")
    return jsonify({"error": "Erreur interne du serveur.", "status": "error"}), 500


# ─── Point d'entrée (dev uniquement) ─────────────────────────────────────────

if __name__ == "__main__":
    # Ne jamais utiliser ce mode en production — utiliser Gunicorn.
    app.run(host="127.0.0.1", port=5000, debug=False)
