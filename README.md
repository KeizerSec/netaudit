# NetAudit

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-REST_API-000000?style=for-the-badge&logo=flask&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Vulners-4682B4?style=for-the-badge&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Correlation-E8001D?style=for-the-badge&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

**Scanner de vulnérabilités réseau avec corrélation MITRE ATT&CK** — donnez une IP, recevez un rapport JSON structuré avec les CVEs détectées et leur traduction en techniques d'attaque concrètes, un chemin d'attaque hypothétique ordonné par kill chain, et un niveau de risque global (CRITICAL / HIGH / MEDIUM / LOW).

> **Usage légal uniquement.** Ne scannez que des hôtes sur lesquels vous avez une autorisation explicite.

---

## Ce que fait NetAudit

```
Vous donnez une IP  →  NetAudit lance Nmap + Vulners  →  Vous obtenez :

  Couche 1 — Inventaire
  • Ports ouverts avec services et versions détectées
  • CVEs associées avec leur score CVSS et un lien de référence

  Couche 2 — Corrélation MITRE ATT&CK (nouveau)
  • Chaque service → techniques d'attaque liées (confiance haute)
  • Chaque CVE → techniques d'exploitation probables selon le score CVSS
  • Un chemin d'attaque hypothétique ordonné selon le kill chain MITRE
  • Un niveau de risque global : CRITICAL / HIGH / MEDIUM / LOW
  • Jusqu'à 5 priorités de détection concrètes

  Couche 3 — Rapport visuel
  • Rapport HTML dark-mode avec visualisation du kill chain
  • Fiches techniques colorisées selon le niveau de confiance
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
# 1. Installer Nmap sur votre système
#    macOS  : brew install nmap
#    Ubuntu : sudo apt install nmap
#    Windows: https://nmap.org/download.html

# 2. Installer les dépendances Python
pip install -r requirements.txt

# 3. Lancer le serveur depuis src/
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

### Exemple de réponse (extrait)

```json
{
  "status": "ok",
  "ip": "192.168.1.1",
  "host_up": true,
  "total_vulns": 3,
  "ports": [
    {
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 7.6p1",
      "vulns": [
        {
          "id": "CVE-2021-28041",
          "score": 7.8,
          "url": "https://vulners.com/cve/CVE-2021-28041",
          "attack_techniques": [
            { "id": "T1078", "name": "Valid Accounts", "confidence": "medium" },
            { "id": "T1068", "name": "Exploitation for Privilege Escalation", "confidence": "medium" }
          ]
        }
      ],
      "service_techniques": [
        { "id": "T1021.004", "name": "SSH", "confidence": "high" }
      ]
    }
  ],
  "attack_summary": {
    "risk_level": "HIGH",
    "phases_count": 4,
    "phases": [
      {
        "tactic": "Initial Access",
        "techniques": [ { "id": "T1190", "confidence": "high" } ]
      }
    ],
    "detection_priorities": [
      "Surveiller les tentatives de connexion SSH répétées",
      "Alerter sur les connexions depuis des plages IP inhabituelles"
    ]
  },
  "rapport_html": "/rapport/192.168.1.1"
}
```

### Consulter le rapport HTML

```
http://localhost:5000/rapport/192.168.1.1
```

Le rapport affiche : scores CVSS colorisés, visualisation du kill chain MITRE ATT&CK avec les phases actives en surbrillance, fiches techniques avec niveau de confiance, et priorités de détection.

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

**Scan réseau**
- Nmap + script Vulners — détection des CVEs par service et version
- Parsing structuré — sortie Nmap convertie en JSON propre
- Validation IP robuste — module `ipaddress` (IPv4 + IPv6, résiste aux injections)
- Cache LRU — évite de rescanner une même IP inutilement

**Corrélation MITRE ATT&CK**
- Mapping service/port → techniques (confiance haute, 30 services couverts)
- Mapping CVE → techniques en trois couches complémentaires :
  - Catalogue de CVEs célèbres (Log4Shell, EternalBlue, Heartbleed, …) → CWE → techniques précises
  - Mapping CWE → techniques (26 CWEs cataloguées)
  - Heuristique CVSS + contexte service en filet de sécurité
- Chemin d'attaque hypothétique ordonné selon le kill chain MITRE complet (14 tactiques)
- Calcul du niveau de risque global : CRITICAL / HIGH / MEDIUM / LOW
- 5 priorités de détection extraites automatiquement
- Mitigations concrètes proposées par technique
- Base de données locale : 62 techniques ATT&CK, 26 CWEs, 30 services, 40 CVEs connues

**Sécurité & infrastructure**
- Rapport HTML dark-mode avec visualisation kill chain interactive
- Rate limiting — 5 scans par minute par IP
- Authentification API key — header `X-API-Key`, désactivable en dev
- Protection path-traversal — accès aux rapports sécurisé
- Gunicorn — serveur de production (remplace le serveur de dev Flask)
- Docker-ready — image slim Python 3.11

---

## Lancer les tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

131 tests couvrant : validation IP, parsing Nmap XML, endpoints API, corrélation ATT&CK (service mapping, CVE mapping, CWE mapping, catalogue de CVEs connues, déduplication, calcul de risque, génération du chemin d'attaque, intégrité du catalogue).

---

## Structure du projet

```
netaudit/
├── src/
│   ├── scan.py              # Moteur de scan, parsing Nmap → JSON, génération rapports
│   ├── webapp.py            # API REST Flask (endpoints, auth, rate limiting)
│   ├── attack_mapper.py     # Corrélation MITRE ATT&CK — techniques, chemin, risque
│   ├── data/
│   │   ├── techniques.json       # 62 techniques ATT&CK (détection + mitigations)
│   │   ├── service_mapping.json  # 30 services → techniques (confiance haute)
│   │   ├── cwe_mapping.json      # 26 CWEs → techniques
│   │   └── known_cves.json       # 40 CVEs célèbres → CWE (mapping précis)
│   └── templates/
│       └── rapport.html     # Template Jinja2 — dark-mode, kill chain, fiches ATT&CK
├── tests/
│   ├── test_scan.py         # Tests — validation IP, parsing Nmap
│   ├── test_webapp.py       # Tests — endpoints API, auth, erreurs
│   └── test_attack_mapper.py # Tests — corrélation ATT&CK (57 cas)
├── .env.example             # Modèle de configuration
├── Dockerfile               # Image slim Python 3.11 + Nmap, Gunicorn
└── requirements.txt         # Dépendances avec versions fixées
```

---

## Limitations

> NetAudit est un outil d'audit rapide et d'apprentissage.
> La corrélation ATT&CK est heuristique (basée sur le score CVSS et le service) — elle donne des pistes, pas des certitudes.
> Il ne remplace pas des solutions professionnelles comme Nessus, OpenVAS, ou une analyse manuelle des CVEs.

---

## Licence

MIT — Utilisation libre et modifiable. Voir `LICENSE`.
