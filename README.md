# NetAudit

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-REST_API-000000?style=for-the-badge&logo=flask&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Vulners-4682B4?style=for-the-badge&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Correlation-E8001D?style=for-the-badge&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

**Scanner de vulnérabilités réseau avec corrélation MITRE ATT&CK, priorisation EPSS + CISA KEV et détection contextuelle.** Donnez une IP, recevez un rapport structuré — ports ouverts, CVEs détectées, techniques d'attaque ATT&CK associées, chemin d'attaque ordonné selon le kill chain, **priorités d'action basées sur exploitation réelle** (présence dans le catalogue CISA KEV, score probabiliste FIRST EPSS, flag ransomware), **classification automatique du rôle de l'hôte + analyse de posture** (12 règles anti-pattern, score 0–100, grade A–F), niveau de risque global, priorités de détection SIEM. Trois formats de sortie (HTML interactif, JSON, PDF A4) et une API REST protégée par clé.

> **Usage légal uniquement.** Ne scannez que des hôtes sur lesquels vous avez une autorisation explicite.

---

## Sommaire

- [Ce que fait NetAudit](#ce-que-fait-netaudit)
- [Démarrage rapide](#démarrage-rapide)
- [Utilisation](#utilisation)
- [Endpoints API](#endpoints-api)
- [Configuration](#configuration)
- [Fonctionnalités](#fonctionnalités)
- [Tests](#tests)
- [Structure du projet](#structure-du-projet)
- [Limitations](#limitations)

---

## Ce que fait NetAudit

```
Vous donnez une IP  →  NetAudit lance Nmap + Vulners  →  Vous obtenez :

  Couche 1 — Inventaire réseau
  • Ports ouverts, protocoles, services et versions (Nmap -sV)
  • Détection OS et reverse DNS quand disponibles
  • CVEs associées avec score CVSS et lien vers Vulners

  Couche 2 — Corrélation MITRE ATT&CK
  • Chaque service → techniques d'attaque liées (confiance haute, 30 services)
  • Chaque CVE → techniques d'exploitation via CVE→CWE→ATT&CK (3 niveaux)
  • Chemin d'attaque hypothétique ordonné selon les 14 tactiques du kill chain
  • Niveau de risque global : CRITICAL / HIGH / MEDIUM / LOW
  • Jusqu'à 5 priorités de détection SIEM extraites automatiquement
  • Mitigations concrètes proposées par technique

  Couche 3 — Priorisation réelle (EPSS + CISA KEV)
  • Croisement avec CISA KEV — preuve d'exploitation active dans la nature
  • Score FIRST EPSS — probabilité d'exploitation à 30 jours (0–1)
  • Flag ransomware — CVEs utilisées dans des campagnes documentées
  • Score combiné : CVSS + 3.0 (KEV) + 1.5 (ransomware) + EPSS pondéré
  • Niveau : IMMEDIATE / HIGH / MEDIUM / LOW / INFO
  • Top 5 priorités d'action affiché en tête du rapport
  • Cache disque 24 h — offline-safe, dégrade sur cache périmé si réseau KO

  Couche 4 — Détection contextuelle (rôle + posture)
  • Classification automatique du rôle — web, DB, mail, DNS, IoT, admin,
    hypervisor, directory, file, monitoring, VoIP, workstation
  • Catalogue de 12 règles anti-pattern — DB exposée, Telnet clair,
    FTP sans TLS, SNMP public, multi-admin, web sans HTTPS, OS EOL,
    versions non-supportées, DB+web colocalisés, IoT management, etc.
  • Chaque finding = severity + description + recommandation + evidence
  • Score de posture 0–100 → grade A/B/C/D/F, comparable dans le temps
  • 100 % local — aucune dépendance réseau, déterministe

  Couche 5 — Rapport & exports
  • Rapport HTML dark-mode : donut CVSS, kill chain cliquable, filtre ports,
    meta-cards Rôle + Posture (grade + jauge), bloc Top priorités d'action,
    section Posture & recommandations avec findings colorisés par sévérité
  • Export JSON brut pour intégration outils tiers (expose priority_summary
    et context en plus de l'attack_summary)
  • Export PDF A4 généré via reportlab — archivage, audit, rapport formel
    (en-tête + table posture + synthèse ATT&CK + table ports)
  • Bouton « Copier en Markdown » pour ticket / PR / rapport d'incident
    (inclut priorités + findings posture + reco)

  Couche 6 — Historique & observabilité
  • Persistance SQLite — chaque scan survit au redémarrage
  • Endpoints /history et /history/<ip> pour suivi de tendances
  • /version — traçabilité de l'image déployée (semver + hash commit)
  • /health — probe HTTP compatible Docker HEALTHCHECK natif
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
  "hostname": "router.local",
  "os_guess": "Linux 5.4",
  "scan_date": "2026-04-16 12:34:56 UTC",
  "total_vulns": 3,
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "OpenSSH 7.6p1 Ubuntu",
      "vulns": [
        {
          "id": "CVE-2021-28041",
          "score": 7.8,
          "url": "https://vulners.com/cve/CVE-2021-28041",
          "attack_techniques": [
            { "id": "T1078", "name": "Valid Accounts", "confidence": "medium" },
            { "id": "T1068", "name": "Exploitation for Privilege Escalation", "confidence": "medium" }
          ],
          "kev": {
            "ransomware": false,
            "due_date": "2023-03-14",
            "short_desc": "OpenSSH double-free vulnerability",
            "date_added": "2023-02-21"
          },
          "epss": { "score": 0.042, "percentile": 0.91 },
          "priority_score": 10.84,
          "priority_level": "HIGH"
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
        "tactic_id": "TA0001",
        "techniques": [ { "id": "T1190", "confidence": "high" } ]
      }
    ],
    "detection_priorities": [
      "Surveiller les tentatives de connexion SSH répétées",
      "Alerter sur les connexions depuis des plages IP inhabituelles"
    ]
  },
  "priority_summary": {
    "max_level": "HIGH",
    "counts": { "IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 0 },
    "kev_count": 1,
    "ransomware_count": 0,
    "top": [
      { "id": "CVE-2021-28041", "port": 22, "priority_score": 10.84,
        "priority_level": "HIGH", "in_kev": true, "ransomware": false }
    ],
    "sources_used": ["CISA KEV", "FIRST EPSS"]
  },
  "context": {
    "role": "admin_host",
    "role_confidence": "high",
    "role_score": 1.8,
    "posture_score": 72,
    "posture_grade": "C",
    "summary": { "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0 },
    "findings": [
      {
        "severity": "HIGH",
        "title": "Version(s) de service non-supportée(s)",
        "description": "Au moins un service expose une version sans correctifs…",
        "recommendation": "Mettre à jour vers une branche supportée du produit.",
        "evidence": "OpenSSH 6.x (release > 8 ans)"
      }
    ]
  },
  "rapport_html": "/rapport/192.168.1.1"
}
```

### Consulter et exporter le rapport

```bash
# Rapport HTML interactif (navigateur)
open http://localhost:5000/rapport/192.168.1.1

# Data JSON complète du dernier scan (intégration outils tiers)
curl http://localhost:5000/rapport/192.168.1.1?format=json

# PDF A4 téléchargeable (audit, archivage)
curl -OJ http://localhost:5000/rapport/192.168.1.1?format=pdf
```

Le rapport HTML affiche : meta-cards synthétiques (IP, date, ports, donut CVSS, rôle inféré, priorité max KEV/ransomware, grade de posture + jauge 0–100), bloc « Top priorités d'action » basé sur le score combiné CVSS + KEV + EPSS, section « Posture & recommandations » avec findings colorisés par sévérité (titre + description + reco concrète + evidence), badges KEV / RANSOM / priorité et score EPSS par CVE dans le tableau des ports, kill chain MITRE ATT&CK cliquable (chaque phase active scroll vers sa fiche), fiches techniques colorisées par confiance avec détection et mitigations, priorités de détection SIEM, filtre de recherche sur les ports, boutons d'export (JSON / PDF / Markdown presse-papier), styles d'impression dédiés.

### Consulter l'historique

```bash
# Liste synthétique des derniers scans (risk_level, total_vulns, date)
curl http://localhost:5000/history

# Avec une limite explicite (max 500)
curl http://localhost:5000/history?limit=20

# Historique détaillé d'une IP (toutes les data complètes)
curl http://localhost:5000/history/192.168.1.1
```

### Tracer la build déployée

```bash
curl http://localhost:5000/version
# → {"name": "NetAudit", "version": "2.3.0", "commit": "0403e03"}
```

---

## Endpoints API

| Endpoint | Description | Auth |
|---|---|---|
| `GET /scan/<ip>` | Lance un scan sur l'IP cible | Oui (si `API_KEY` définie) |
| `GET /rapport/<ip>` | Rapport HTML (défaut) — `?format=json` ou `?format=pdf` | Oui |
| `GET /history` | Liste synthétique des derniers scans (paramètre `limit`, défaut 100) | Oui |
| `GET /history/<ip>` | Historique détaillé d'une IP (data complète) | Oui |
| `GET /version` | Nom, version sémantique, hash commit | Non |
| `GET /health` | Statut du serveur | Non |

> **Rate limiting.** `GET /scan/<ip>` est limité à 5 requêtes par minute et par IP source (configurable via Flask-Limiter). Les autres endpoints héritent des limites globales `200/jour, 60/heure`.

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
| `HISTORY_DB_PATH` | `/app/netaudit.db` | Base SQLite de l'historique des scans |
| `CACHE_DIR` | `/app/cache` | Dossier cache KEV + EPSS, TTL 24 h |
| `PRIORITIZER_ENABLED` | `1` | Mettre à `0` pour désactiver les appels réseau (offline strict) |
| `BUILD_COMMIT` | *(vide)* | Hash commit injecté au build Docker, exposé par `/version` |

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
- Base de données locale : 62 techniques ATT&CK, 26 CWEs, 30 services, 39 CVEs connues

**Priorisation réelle (EPSS + CISA KEV)**
- Flag CISA KEV — chaque CVE croisée avec le catalogue officiel *Known Exploited Vulnerabilities*
- Score FIRST EPSS (0–1) — probabilité d'exploitation à 30 jours, recalculé quotidiennement
- Flag ransomware distinct — CVEs documentées dans des campagnes actives
- Score de priorité combiné : CVSS + 3.0 (KEV) + 1.5 (ransomware) + 2.0 × EPSS (≥ 0.5) ou 1.0 × EPSS
- Niveaux : IMMEDIATE ≥ 13 / HIGH ≥ 10 / MEDIUM ≥ 6 / LOW ≥ 3 / INFO
- Cache disque agrégé, TTL 24 h — second scan de la journée sans appel réseau
- Offline-safe — échec réseau sans cache = scan continue sans enrichissement, cache périmé réutilisé en mode dégradé
- Bloc « Top priorités d'action » affiché en tête du rapport HTML

**Détection contextuelle (rôle + posture)**
- Classification automatique du rôle de l'hôte — 12 catégories (web, DB, mail, DNS, IoT, admin, monitoring, file, directory, hypervisor, VoIP, workstation)
- Signatures pondérées : ports + services → score par rôle, meilleur gagne, marge → confiance (high / medium / low)
- 12 règles anti-pattern embarquées :
  - DB publiquement exposée *(CRITICAL)*
  - Telnet actif *(CRITICAL)* — credentials en clair
  - FTP sans TLS *(HIGH)* — avec détection FTPS pour éviter le faux positif
  - TFTP exposé *(HIGH)*
  - SNMP public *(HIGH)* — community string par défaut
  - OS en fin de vie *(HIGH)* — XP, 2003, 2008, 7, Linux 2.6, CentOS 5/6, …
  - Version de service non-supportée *(HIGH)* — Apache 2.2, OpenSSH 5/6, PHP 5, OpenSSL 1.0.x, … (regex à frontière)
  - DB + web colocalisés *(HIGH)* — pivot local en cas de RCE web
  - IoT avec management exposé *(HIGH)* — Telnet, CWMP/TR-069
  - Multi-protocole d'admin *(MEDIUM)*
  - Serveur web sans HTTPS *(MEDIUM)* — conditionné au rôle inféré
  - Surface d'attaque élargie *(MEDIUM)* — > 15 ports ouverts
- Chaque finding = sévérité + description + recommandation concrète + evidence
- Score de posture 0–100 (100 − pénalités), grade A (≥ 90) / B (≥ 75) / C (≥ 55) / D (≥ 35) / F
- 100 % local, déterministe — scores comparables entre scans

**Rapport & UX**
- Rapport HTML dark-mode avec donut SVG de répartition des sévérités CVSS
- Meta-cards synthétiques : IP, date, ports, vulnérabilités, **rôle détecté + confiance**, **priorité max + KEV/ransomware count**, **grade de posture (A–F) + jauge 0–100**
- Bloc « Top priorités d'action » en tête du rapport — 5 CVEs les plus urgentes selon le score combiné (CVSS + KEV + EPSS + ransomware)
- Section « Posture & recommandations » — findings triés par sévérité, chaque carte expose description + recommandation concrète + evidence
- Badges KEV / RANSOM / priorité (IMMEDIATE/HIGH/…) et score EPSS affichés à côté de chaque CVE dans le tableau des ports
- Kill chain MITRE ATT&CK cliquable — chaque phase active scroll vers sa fiche
- Filtre de recherche sur les ports (n°, service, version, CVE) — vanilla JS
- Bouton « Copier en Markdown » — rapport complet (priorités + posture + ATT&CK + ports) prêt à coller dans Jira / PR / ticket
- Styles d'impression dédiés (`@media print`) — URLs révélées, couleurs claires
- Exports alternatifs : `?format=json` (data brute avec priority_summary et context) et `?format=pdf` (A4 téléchargeable, généré via reportlab, section posture incluse)

**Historique & persistance**
- Base SQLite locale — scans enregistrés à chaque `/scan/<ip>`, survit au redémarrage
- `GET /history` — liste synthétique avec risk_level et total_vulns
- `GET /history/<ip>` — historique détaillé d'une IP (data complète)

**Sécurité & infrastructure**
- Authentification API key — header `X-API-Key`, comparaison à temps constant via `hmac.compare_digest`
- Rate limiting — 5 scans par minute par IP
- Protection path-traversal — accès aux rapports sécurisé
- Gunicorn — serveur de production (remplace le serveur de dev Flask)
- Docker-ready — image slim Python 3.11, HEALTHCHECK HTTP natif
- Endpoint `/version` — traçabilité précise de l'image déployée (version + hash commit)
- Logs dupliqués fichier rotaté + stdout — compatibles `docker logs` et agrégateurs

---

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

**243 tests** — validation IP, parsing Nmap XML, endpoints API (scan, rapport, history, version, health), corrélation ATT&CK (service mapping, CVE mapping, CWE mapping, catalogue CVEs connues, déduplication, calcul de risque, chemin d'attaque, intégrité du catalogue), persistance SQLite (insertion, lecture, filtrage par IP), génération PDF (smoke test binaire, robustesse aux données partielles), priorisation EPSS + KEV (formule de score, seuils de niveau, cache TTL, batch API, fallback offline, dégradation sur cache périmé), détection contextuelle (classification 12 rôles, 12 règles anti-pattern avec frontières regex pour éviter les faux positifs, scénarios d'intégration).

---

## Structure du projet

```
netaudit/
├── src/
│   ├── scan.py              # Moteur de scan, parser Nmap XML, orchestration
│   ├── webapp.py            # API REST Flask (scan, rapport, history, version, health)
│   ├── attack_mapper.py     # Corrélation MITRE ATT&CK — techniques, chemin, risque
│   ├── history.py           # Persistance SQLite + accès historique
│   ├── prioritizer.py       # Priorisation EPSS + CISA KEV, cache 24 h, offline-safe
│   ├── profiler.py          # Classification rôle + 12 règles anti-pattern, score posture
│   ├── exports.py           # Génération PDF via reportlab
│   ├── version.py           # Version sémantique + hash commit
│   ├── data/
│   │   ├── techniques.json       # 62 techniques ATT&CK (détection + mitigations)
│   │   ├── service_mapping.json  # 30 services → techniques (confiance haute)
│   │   ├── cwe_mapping.json      # 26 CWEs → techniques
│   │   └── known_cves.json       # 39 CVEs célèbres → CWE (mapping précis)
│   └── templates/
│       └── rapport.html     # Template Jinja2 — dark-mode, donut, kill chain, filtre, export MD
├── tests/
│   ├── test_scan.py         # Validation IP, parsing Nmap XML
│   ├── test_webapp.py       # Endpoints API, auth, formats d'export, historique
│   ├── test_attack_mapper.py # Corrélation ATT&CK (81 cas)
│   ├── test_history.py      # Persistance SQLite (14 cas)
│   ├── test_exports.py      # Génération PDF (6 cas)
│   ├── test_prioritizer.py  # Priorisation EPSS + KEV (33 cas)
│   └── test_profiler.py     # Classification rôle + posture (47 cas)
├── .env.example             # Modèle de configuration
├── Dockerfile               # Image slim Python 3.11 + Nmap, Gunicorn, HEALTHCHECK
└── requirements.txt         # Dépendances avec versions fixées
```

---

## Limitations

> NetAudit est un outil d'audit rapide et d'apprentissage.
> La corrélation ATT&CK est heuristique (basée sur le score CVSS et le service) — elle donne des pistes, pas des certitudes.
> La priorisation EPSS + KEV nécessite un accès réseau aux endpoints publics CISA et FIRST ; en mode offline strict (`PRIORITIZER_ENABLED=0`), seul le CVSS est utilisé.
> Il ne remplace pas des solutions professionnelles comme Nessus, OpenVAS, ou une analyse manuelle des CVEs.

---

## Licence

MIT — Utilisation libre et modifiable. Voir `LICENSE`.
