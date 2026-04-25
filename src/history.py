"""
Persistance légère des scans dans une base SQLite locale.

Pourquoi SQLite plutôt qu'un fichier JSON agrégé :
- Lectures/écritures concurrentes sûres (verrou WAL),
- Requêtes par IP et pagination triviales via SQL,
- Zéro serveur externe à administrer — reste dans l'esprit « outil local » du projet.

Le cache LRU en mémoire (scan.py) sert à éviter de re-scanner une IP dans la
même fenêtre d'exécution ; cette base, elle, persiste l'historique entre
redémarrages pour permettre l'analyse de tendances (CVEs récurrentes, hôtes
récurrents) via les endpoints /history et /history/<ip>.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("HISTORY_DB_PATH", os.path.join(BASE_DIR, "..", "netaudit.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    NOT NULL,
    scan_date    TEXT    NOT NULL,
    host_up      INTEGER NOT NULL,
    total_vulns  INTEGER NOT NULL,
    risk_level   TEXT,
    data_json    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_ip        ON scans(ip);
CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date DESC);
"""


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Ouvre une connexion avec row_factory configurée, ferme proprement.

    Une connexion par appel — sqlite3 n'est pas thread-safe par défaut et
    Gunicorn exécute plusieurs workers. Le coût d'ouverture sur SQLite local
    est négligeable (<1ms).
    """
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Crée le schéma si absent + active le mode WAL. Idempotent.

    **À appeler explicitement** au démarrage de l'application (webapp, CLI) —
    le module ne fait plus ce travail à l'import pour éviter les side-effects
    surprenants dans les tests, les imports croisés et les outils d'analyse
    qui parcourent le code sans intention d'ouvrir la base.

    Le mode WAL (write-ahead logging) permet aux lecteurs et à un écrivain
    de travailler simultanément sans se bloquer — utile avec plusieurs
    workers Gunicorn qui consultent `/history` pendant qu'un `/scan` insère
    un nouveau record. Le `PRAGMA` est persistant : appliqué une seule fois
    sur la base, il reste actif jusqu'à suppression du fichier.
    """
    with _connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(_SCHEMA)


def record_scan(data: dict) -> int | None:
    """Persiste un scan. Retourne l'id inséré, ou None si data invalide.

    N'interrompt jamais le flux applicatif : toute erreur de persistance est
    loggée mais swallowed — un scan qui a réussi ne doit pas échouer parce
    que l'historique est HS.
    """
    if not isinstance(data, dict) or not data.get("ip"):
        return None

    risk_level = ""
    summary = data.get("attack_summary")
    if isinstance(summary, dict):
        risk_level = summary.get("risk_level", "") or ""

    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (ip, scan_date, host_up, total_vulns, risk_level, data_json)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    data["ip"],
                    data.get("scan_date", ""),
                    1 if data.get("host_up") else 0,
                    int(data.get("total_vulns", 0) or 0),
                    risk_level,
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            return cur.lastrowid
    except sqlite3.Error as exc:
        logging.error("Échec d'enregistrement historique pour %s : %s", data.get("ip"), exc)
        return None


def _row_to_summary(row: sqlite3.Row) -> dict:
    """Projection « liste » : pas le data_json complet, uniquement les champs synthèse."""
    return {
        "id":          row["id"],
        "ip":          row["ip"],
        "scan_date":   row["scan_date"],
        "host_up":     bool(row["host_up"]),
        "total_vulns": row["total_vulns"],
        "risk_level":  row["risk_level"] or "",
    }


def list_scans(limit: int = 100) -> list[dict]:
    """Retourne les `limit` scans les plus récents, tous IPs confondues."""
    limit = max(1, min(int(limit), 500))
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, ip, scan_date, host_up, total_vulns, risk_level"
                " FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [_row_to_summary(r) for r in rows]
    except sqlite3.Error as exc:
        logging.error("Échec de lecture historique : %s", exc)
        return []


def scans_for_ip(ip: str, limit: int = 50) -> list[dict]:
    """Retourne l'historique complet (data_json parsé) pour une IP donnée."""
    limit = max(1, min(int(limit), 200))
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, ip, scan_date, host_up, total_vulns, risk_level, data_json"
                " FROM scans WHERE ip = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            ).fetchall()
    except sqlite3.Error as exc:
        logging.error("Échec de lecture historique pour %s : %s", ip, exc)
        return []

    out: list[dict] = []
    for r in rows:
        summary = _row_to_summary(r)
        try:
            summary["data"] = json.loads(r["data_json"])
        except json.JSONDecodeError:
            summary["data"] = None
        out.append(summary)
    return out
