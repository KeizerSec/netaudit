# Changelog

Toutes les évolutions notables du projet sont listées ici.

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versions alignées sur [SemVer](https://semver.org/).

## [2.7.0] — 2026-04-27

Réponses aux 4 points de l'audit externe (Codex, 2026-04-26) qui touchent
au contrat API, à la mutualisation du rate limit et aux garde-fous de
configuration sécurité.

### Modifié — BREAKING

- **`POST /scan` remplace `GET /scan/<ip>`.** Un scan déclenche une action
  lourde non-idempotente (record SQLite, génération de rapport, appel
  réseau) ; un `GET` était préchargé par les bots, prefetchers de
  navigateur, unfurls de messageries et caches HTTP intermédiaires —
  autant de risques de scans involontaires. Le payload est désormais
  `{"ip": "..."}` en JSON, headers inchangés (`X-API-Key`).

### Ajouté

- **`REQUIRE_API_KEY=1`** — refuse de démarrer si `API_KEY` est vide.
  Destiné aux environnements de production : un `logging.warning` se
  perdrait dans les logs, un `SystemExit` arrête le boot et garantit que
  le déploiement échoue visiblement. Mode dev par défaut inchangé.
- **`/health` enrichi** — expose désormais `history_db: ok|degraded` et
  `version` en plus de `status: ok`. La probe DB est un `SELECT 1` avec
  timeout 1 s, sans exception en surface (`history.db_health()`).
  L'endpoint reste 200 même si la DB est dégradée — c'est à l'agrégateur
  (Prometheus, etc.) de définir une politique d'alerte sur ce champ ;
  renvoyer 503 ici déclencherait des restarts en boucle.
- **`RATELIMIT_STORAGE_URI`** — backend du rate limiter configurable.
  Défaut `memory://` (in-process, adapté au single-host) ; régler sur
  `redis://...` ou `memcached://...` en multi-instances stricts.
- Tests de régression dédiés : `TestRequireApiKey` (sous-process, 3 cas),
  `TestDbHealth` (probe OK / probe KO sans lever), `TestHealth` couvre
  les nouveaux champs `history_db` et `version`.

## [2.6.2] — 2026-04-25

### Corrigé

- **webapp.py** — `load_dotenv()` est désormais appelé **avant** tout import
  applicatif. Avant ce correctif, les variables lues au module-level dans
  `scan.py` (`LOG_FILE_PATH`, `REPORT_DIR`, `NMAP_TIMEOUT`, `CACHE_SIZE`) et
  `history.py` (`HISTORY_DB_PATH`) étaient silencieusement ignorées quand
  elles n'étaient définies que dans `.env`. Test de régression subprocess
  dans `TestDotenvOrdering`.
- **history.py** — `PRAGMA journal_mode=WAL` appliqué par `init_db`. La
  docstring annonçait WAL depuis 2.4 mais le pragma n'était jamais exécuté,
  la base tournait en mode `delete`. Impact : lectures et écritures
  concurrentes ne se bloquent plus. Test de régression `test_active_le_mode_wal`.
- **prioritizer.py** — `_write_cache` passe par un tempfile puis
  `os.replace` atomique. Évite la corruption du cache KEV/EPSS si deux
  workers Gunicorn refresh en même temps.
- **scan.py** — ajout du séparateur `--` avant `ip` dans l'appel nmap
  (`subprocess.run([..., "--", ip])`). Défense en profondeur contre une
  injection d'argument si la fonction est appelée sans passer par
  `valider_ip()` (pas exploitable via l'API publique).

### Ajouté

- `.dockerignore` — empêche `.env`, `.git/`, `__pycache__/`, `rapports/`,
  `cache/` et `netaudit.db` d'être copiés dans l'image Docker. Corrige un
  risque de fuite de `API_KEY` si un utilisateur avait un `.env` local au
  moment du `docker build`.

### Documentation

- README : corrige « 335 tests » → « 339 tests » (en réalité **341** après
  les tests de régression 2.6.2 ajoutés).

## [2.6.1] — 2026-04-25

### Modifié

- `history.init_db()` n'est plus appelé à l'import du module. Les appelants
  doivent l'invoquer explicitement au démarrage (`webapp.py` le fait au
  boot, `scan.lancer_scan` le fait avant toute opération, le CLI `scan.py`
  l'appelle via `setup_logging` + implicite). Objectif : supprimer le
  side-effect surprenant à l'import, plus sain pour les tests et les
  analyseurs statiques.
- `scan.py` expose maintenant `setup_logging(force=False)` — la
  configuration du root logger (fichier rotaté + stdout) n'est plus faite
  à l'import. Importer `scan` pour un outil, un test ou un script
  utilitaire ne reconfigure plus le logger du process appelant.
- Tests de régression explicites pour les deux points (`test_history.py:
  test_import_seul_ne_cree_pas_la_db`, `test_scan.py: TestSetupLogging`).

## [2.6.0] — 2026-04-25

### Ajouté

- **Explicabilité par CVE** — champ `priority_reasons` calculé par
  `prioritizer.priority_reasons()` et propagé sur chaque vuln + sur le top-5
  du `priority_summary`. Chaque entrée = `{code, label}` : KEV, ransomware,
  EPSS (fort/moyen), CVSS (critique/élevé/moyen/faible). Affiché dans la
  carte « Top priorités » du rapport HTML, dans l'export Markdown et dans
  une nouvelle section du PDF.
- `SECURITY.md` — politique de signalement et périmètre couvert.
- `CHANGELOG.md` — ce fichier.
- `scripts/refresh_known_cves.py` — synchronise `src/data/known_cves.json`
  avec le catalogue CISA KEV, conservant les CVEs historiques déjà annotées.

### Modifié

- `baseline._diff_findings` utilise maintenant `rule_id` (nom de la règle
  profiler) comme clé stable. Reformuler un titre ou une sévérité ne
  déclenche plus de faux couples « nouveau / résolu ».
- `attack_mapper.enrich_scan_result` loggue désormais le traceback complet
  (`exc_info=True`) au lieu d'un `str(exc)` sans stack.
- `profiler.analyze_posture` loggue explicitement les règles qui plantent au
  lieu de les swallow silencieusement.

### Fixes

- `profiler` — `rule_id` systématiquement injecté sur chaque finding via
  `result.setdefault`, sans régression pour les règles existantes.

## [2.5.0] — 2026-04-17

### Ajouté

- Baseline historique et détection de dérive (`baseline.py`) — diff vs
  scan précédent, alertes typées critical/warning/neutral/positive.
- GET conditionnel `If-Modified-Since` sur le catalogue CISA KEV.
- Expansion catalogue ATT&CK — 79 techniques, 47 services, renforcement AD
  / cloud native / IoT-OT / management out-of-band.
- CI GitHub Actions multi-version Python + build Docker.

## [2.4.0]

### Ajouté

- Détection contextuelle (`profiler.py`) — classification du rôle de
  l'hôte + 12 règles anti-pattern, score de posture 0–100.

## [2.3.0]

### Ajouté

- Priorisation réelle EPSS + CISA KEV (`prioritizer.py`), cache disque 24 h,
  offline-safe.

## [2.2.0]

### Ajouté

- Exports JSON et PDF via reportlab.
- Persistance SQLite des scans, endpoints `/history`.

## [2.1.0]

### Ajouté

- Corrélation MITRE ATT&CK — catalogue local CVE → CWE → technique, chemin
  d'attaque ordonné, niveau de risque global.

## [2.0.0]

### Changé

- Refonte complète : API REST Flask, Dockerfile, Nmap XML parser.
