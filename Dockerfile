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
RUN mkdir -p /app/rapports /app/logs

# Variables d'environnement par défaut (surchargeables via --env ou .env)
ENV LOG_FILE_PATH=/app/logs/scan.log
ENV REPORT_DIR=/app/rapports
ENV NMAP_TIMEOUT=300
ENV CACHE_SIZE=32
# API_KEY est intentionnellement absente — à définir en production

EXPOSE 5000

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
