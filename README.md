# Scan Vulnérabilité Pro

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Docker](https://img.shields.io/badge/Docker-ready-blue)
![License](https://img.shields.io/badge/License-MIT-green)

Outil d'audit réseau qui combine Nmap + le script Vulners pour détecter les services vulnérables sur une cible IP. Expose une API REST Flask servie par Gunicorn, et génère des rapports HTML structurés.

> **Usage légal uniquement.** Ne scannez que des hôtes sur lesquels vous avez une autorisation explicite.

---

## Fonctionnalités

- Scan Nmap avec le script `vulners` (détection de CVEs par service)
- Parsing structuré de la sortie Nmap → JSON + rapport HTML
- Cache LRU configurable (évite de rescanner inutilement)
- Rate limiting par IP (5 scans/minute)
- Authentification par API key (`X-API-Key`)
- Rapports HTML dark-mode avec scores CVSS colorisés
- Serveur Gunicorn (production-ready)
- Chemins absolus, validation IP via le module `ipaddress`

---

## Lancement rapide (Docker)

```bash
# 1. Cloner et construire
git clone https://github.com/KeizerSec/nmap-vuln-scanner
cd nmap-vuln-scanner
docker build -t scan-vuln-pro .

# 2. Lancer (sans authentification — dev)
docker run -p 5000:5000 scan-vuln-pro

# 3. Lancer avec clé API (recommandé)
docker run -p 5000:5000 -e API_KEY=votre_cle_secrete scan-vuln-pro
```

---

## Lancement local (sans Docker)

```bash
# Prérequis : Python 3.11+, nmap installé
pip install -r requirements.txt

cd src
gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 360 webapp:app
```

---

## API

### `GET /scan/<ip>`

Lance un scan Nmap sur l'IP cible.

**Header requis** (si `API_KEY` est définie) :
```
X-API-Key: votre_cle_secrete
```

**Exemple :**
```bash
curl http://localhost:5000/scan/192.168.1.1 \
     -H "X-API-Key: votre_cle_secrete"
```

**Réponse 200 :**
```json
{
  "status": "ok",
  "ip": "192.168.1.1",
  "host_up": true,
  "scan_date": "2024-01-01 12:00:00 UTC",
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
  "total_vulns": 1,
  "rapport_html": "/rapport/192.168.1.1"
}
```

---

### `GET /rapport/<ip>`

Retourne le rapport HTML généré lors du dernier scan de l'IP.
Renvoie `404` si aucun scan n'a encore été effectué.

---

### `GET /health`

Probe de santé. Retourne `{"status": "ok"}` — utilisé par Docker/load balancer.

---

## Configuration

Copiez `.env.example` en `.env` et ajustez les valeurs :

| Variable | Défaut | Description |
|---|---|---|
| `API_KEY` | *(vide)* | Clé API (vide = auth désactivée) |
| `LOG_FILE_PATH` | `/app/logs/scan.log` | Chemin du fichier de log |
| `REPORT_DIR` | `/app/rapports` | Dossier des rapports HTML |
| `NMAP_TIMEOUT` | `300` | Timeout Nmap en secondes |
| `CACHE_SIZE` | `32` | Taille max du cache LRU |

---

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## Structure du projet

```
.
├── src/
│   ├── scan.py          # Moteur de scan, parsing, rapports
│   ├── webapp.py        # API Flask
│   └── templates/
│       └── rapport.html # Template HTML Jinja2
├── tests/
│   ├── test_scan.py     # Tests unitaires scan
│   └── test_webapp.py   # Tests unitaires API
├── .env.example         # Modèle de configuration
├── Dockerfile
└── requirements.txt
```

---

## Licence

MIT — Utilisation libre, sans garantie. Voir `LICENSE`.
