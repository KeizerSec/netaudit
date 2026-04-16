# NetAudit

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-REST_API-000000?style=for-the-badge&logo=flask&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Vulners-4682B4?style=for-the-badge&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

**Scanner de vulnérabilités réseau** — donne une IP, reçoit un rapport JSON structuré avec les CVEs détectées par service, et un rapport HTML dark-mode prêt à lire.

> **Usage légal uniquement.** Ne scannez que des hôtes sur lesquels vous avez une autorisation explicite.

---

## Ce que fait NetAudit

```
Vous donnez une IP  →  NetAudit lance Nmap + Vulners  →  Vous obtenez :
  • Une liste des ports ouverts avec services et versions
  • Les CVEs détectées avec leur score CVSS (gravité)
  • Un lien vers chaque vulnérabilité sur vulners.com
  • Un rapport HTML dark-mode consultable dans le navigateur
```

---

## Démarrage rapide

### Option 1 — Docker (recommandé, aucun prérequis technique)

```bash
# 1. Télécharger le projet
git clone https://github.com/KeizerSec/netaudit
cd netaudit

# 2. Construire l'image
docker build -t netaudit .

# 3. Lancer (mode développement — sans clé API)
docker run -p 5000:5000 netaudit

# 4. Lancer en production (avec clé API)
docker run -p 5000:5000 -e API_KEY=votre_cle_secrete netaudit
```

### Option 2 — Local (Python 3.11+ et Nmap requis)

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer le serveur depuis src/
cd src
gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 360 webapp:app
```

---

## Utilisation

### Lancer un scan

```bash
# Sans authentification (mode dev)
curl http://localhost:5000/scan/192.168.1.1

# Avec clé API (production)
curl http://localhost:5000/scan/192.168.1.1 \
     -H "X-API-Key: votre_cle_secrete"
```

### Exemple de réponse

```json
{
  "status": "ok",
  "ip": "192.168.1.1",
  "host_up": true,
  "scan_date": "2024-01-01 12:00:00 UTC",
  "total_vulns": 3,
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "OpenSSH 7.6p1",
      "vulns": [
        {
          "id": "CVE-2021-28041",
          "score": 7.8,
          "url": "https://vulners.com/cve/CVE-2021-28041"
        }
      ]
    }
  ],
  "rapport_html": "/rapport/192.168.1.1"
}
```

### Consulter le rapport HTML

Ouvrez dans votre navigateur :
```
http://localhost:5000/rapport/192.168.1.1
```

Le rapport affiche les ports, services, et vulnérabilités avec les scores CVSS colorisés (vert → rouge selon la gravité).

---

## Endpoints API

| Endpoint | Description | Auth |
|---|---|---|
| `GET /scan/<ip>` | Lance un scan sur l'IP cible | Oui (si `API_KEY` définie) |
| `GET /rapport/<ip>` | Retourne le rapport HTML du dernier scan | Oui |
| `GET /health` | Statut du serveur | Non |

---

## Configuration

Copiez `.env.example` en `.env` et ajustez :

```bash
cp .env.example .env
```

| Variable | Défaut | Description |
|---|---|---|
| `API_KEY` | *(vide)* | Clé d'authentification — laisser vide en dev |
| `NMAP_TIMEOUT` | `300` | Timeout Nmap en secondes |
| `REPORT_DIR` | `/app/rapports` | Dossier de sauvegarde des rapports HTML |
| `CACHE_SIZE` | `32` | Nombre d'IPs mémorisées en cache |
| `LOG_FILE_PATH` | `/app/logs/scan.log` | Chemin du fichier de log |

---

## Fonctionnalités

- **Scan Nmap + Vulners** — détection des CVEs par service et version
- **Parsing structuré** — sortie Nmap convertie en JSON propre (ports, services, vulnérabilités)
- **Rapport HTML dark-mode** — scores CVSS colorisés, sortie brute Nmap repliable
- **Cache LRU** — évite de rescanner une même IP inutilement
- **Rate limiting** — 5 scans par minute par IP
- **Authentification API key** — header `X-API-Key`, désactivable en dev
- **Validation IP robuste** — module `ipaddress` (IPv4 + IPv6, résiste aux injections)
- **Protection path-traversal** — accès aux rapports sécurisé
- **Gunicorn** — serveur de production (remplace le serveur de dev Flask)
- **Docker-ready** — image slim Python 3.11, variables d'env configurables

---

## Lancer les tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

45 tests couvrant la validation IP, le parsing Nmap, et tous les endpoints de l'API.

---

## Structure du projet

```
netaudit/
├── src/
│   ├── scan.py              # Moteur de scan, parsing Nmap → JSON, génération rapports
│   ├── webapp.py            # API REST Flask (endpoints, auth, rate limiting)
│   └── templates/
│       └── rapport.html     # Template HTML Jinja2 (dark-mode, CVSS colorisés)
├── tests/
│   ├── test_scan.py         # Tests unitaires — validation IP, parsing Nmap
│   └── test_webapp.py       # Tests unitaires — endpoints API, auth, erreurs
├── .env.example             # Modèle de configuration
├── Dockerfile               # Image slim Python 3.11 + Nmap, Gunicorn
└── requirements.txt         # Dépendances avec versions fixées
```

---

## Limitations

> NetAudit est un outil d'audit rapide et d'apprentissage.
> Il ne remplace pas des solutions professionnelles comme Nessus ou OpenVAS.

---

## Licence

MIT — Utilisation libre et modifiable. Voir `LICENSE`.
