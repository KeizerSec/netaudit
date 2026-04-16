# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Installer nmap proprement et nettoyer le cache apt
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# Copier uniquement requirements en premier pour profiter du layer cache
COPY requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du projet
COPY . /app

# Créer les dossiers de données
RUN mkdir -p /app/rapports /app/logs /app/cache

# Variables d'environnement par défaut (surchargeables via --env ou .env)
ENV LOG_FILE_PATH=/app/logs/scan.log
ENV REPORT_DIR=/app/rapports
ENV NMAP_TIMEOUT=300
ENV CACHE_SIZE=32
ENV HISTORY_DB_PATH=/app/netaudit.db
ENV CACHE_DIR=/app/cache
ENV PRIORITIZER_ENABLED=1
# API_KEY est intentionnellement absente — à définir en production

# Hash commit injecté au build via --build-arg BUILD_COMMIT=$(git rev-parse --short HEAD)
# Exposé par l'endpoint /version pour tracer précisément l'image déployée.
ARG BUILD_COMMIT=""
ENV BUILD_COMMIT=$BUILD_COMMIT

EXPOSE 5000

# Healthcheck : probe HTTP via urllib (stdlib) pour éviter d'installer curl
# juste pour ça. Exit 0 si /health répond 200, exit 1 sinon.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).status == 200 else 1)" \
    || exit 1

# Lancer depuis src/ pour que les imports relatifs fonctionnent
WORKDIR /app/src

# Gunicorn : 2 workers, timeout aligné sur NMAP_TIMEOUT + marge
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--timeout", "360", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "webapp:app"]
