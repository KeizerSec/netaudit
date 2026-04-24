import hmac
import os
import logging
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, send_file, request, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from scan import lancer_scan, valider_ip, REPORT_DIR, setup_logging
from version import version_info
from history import list_scans, scans_for_ip, init_db
from exports import render_pdf

# Initialisations explicites au démarrage de l'application :
# - setup_logging configure le root logger (fichier rotaté + stdout) ;
# - init_db crée le schéma SQLite si absent.
# scan.py et history.py ne font plus ces appels à l'import pour éviter
# les side-effects dans les tests, les imports croisés et les analyseurs
# statiques.
setup_logging()
init_db()

# Charger le fichier .env s'il existe (sans écraser les variables déjà définies)
load_dotenv()

app = Flask(__name__)

# Rate limiting global + par endpoint
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200/day", "60/hour"],
    storage_uri="memory://",
)

# Clé API — si vide, l'authentification est désactivée (mode dev)
API_KEY: str = os.getenv("API_KEY", "")
if not API_KEY:
    logging.warning(
        "API_KEY non définie — authentification désactivée. "
        "Définissez API_KEY en production."
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

@app.route("/scan/<ip>")
@require_api_key
@limiter.limit("5/minute", exempt_when=lambda: app.testing)
def scan(ip: str):
    """
    Lance un scan Nmap sur l'IP cible.

    Headers requis (si API_KEY configurée) :
        X-API-Key: <votre_clé>

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
    if not valider_ip(ip):
        return jsonify({"error": "Adresse IP invalide.", "status": "failed"}), 400

    data, chemin = lancer_scan(ip)

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
    """Endpoint de vérification — utilisé par les probes Docker / load balancer."""
    return jsonify({"status": "ok"}), 200


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
