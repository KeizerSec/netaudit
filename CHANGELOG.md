# Changelog

Toutes les évolutions notables du projet sont listées ici.

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versions alignées sur [SemVer](https://semver.org/).

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
