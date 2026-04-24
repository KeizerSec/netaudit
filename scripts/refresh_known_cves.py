#!/usr/bin/env python3
"""
Synchronise src/data/known_cves.json avec le catalogue CISA KEV.

Pourquoi ce script
------------------
`known_cves.json` sert au mapping précis CVE → CWE → technique ATT&CK.
Sans maintenance, il se fige et le mapping précis disparaît pour les CVEs
récentes. Plutôt qu'un refresh manuel, ce script :

1. Télécharge le catalogue CISA KEV (~1 Mo, public, sans clé API).
2. Préserve toutes les entrées déjà annotées manuellement — la liste n'est
   qu'**étendue**, jamais écrasée : l'enrichissement local (CWE exacte,
   nom commun type "Log4Shell") reste sous contrôle humain.
3. Ajoute les CVEs KEV absentes avec un stub `{"name": ..., "cwe": ""}`.
   Une entrée avec `cwe` vide ne contribue qu'au lookup par nom — le
   mapping ATT&CK se fera via l'heuristique CVSS jusqu'à annotation
   manuelle. C'est volontaire : mieux vaut un placeholder qu'une CWE
   inventée.

Usage
-----
    python3 scripts/refresh_known_cves.py           # écrit en place
    python3 scripts/refresh_known_cves.py --dry-run # affiche le diff

Stratégie offline-friendly
--------------------------
Pas de dépendance externe (urllib suffit). Timeout 10 s.
Exit 0 succès, 1 erreur réseau, 2 écriture bloquée.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.normpath(os.path.join(HERE, "..", "src", "data", "known_cves.json"))


def fetch_kev(timeout: int = 10) -> dict:
    """Télécharge le catalogue KEV. Retourne le JSON parsé ou lève."""
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "NetAudit-refresh/2.6"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_existing(path: str) -> dict:
    """Charge le JSON existant. Tolérant : fichier absent → base vide."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def merge(existing: dict, kev: dict) -> tuple[dict, list[str]]:
    """Retourne (fusionné, liste des CVEs nouvellement ajoutées).

    L'existant est prioritaire : on n'écrase **jamais** une CWE déjà
    renseignée. C'est la raison d'être du fichier — l'annotation CWE
    est faite à la main, KEV ne fournit pas ce champ.
    """
    merged = dict(existing)
    added: list[str] = []

    # Conserver les clés de commentaire (`_comment`, etc.)
    for entry in kev.get("vulnerabilities", []):
        cve = (entry.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-") or cve in merged:
            continue
        vendor = (entry.get("vendorProject") or "").strip()
        product = (entry.get("product") or "").strip()
        name = f"{vendor} {product}".strip() or entry.get("vulnerabilityName", cve)
        merged[cve] = {"name": name, "cwe": ""}
        added.append(cve)

    return merged, added


def write_json(path: str, data: dict) -> None:
    """Écrit le JSON avec indentation stable et trailing newline."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synchronise known_cves.json avec CISA KEV")
    parser.add_argument("--dry-run", action="store_true",
                        help="Affiche le diff sans écrire le fichier")
    parser.add_argument("--path", default=TARGET,
                        help=f"Chemin cible (défaut : {TARGET})")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        kev = fetch_kev()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
        logging.error("Impossible de télécharger KEV : %s", exc)
        return 1

    existing = load_existing(args.path)
    merged, added = merge(existing, kev)

    if not added:
        logging.info("Aucune CVE à ajouter — %d déjà cataloguées.", len(existing))
        return 0

    logging.info("CVEs à ajouter : %d (total après merge : %d)", len(added), len(merged))
    for cve in added[:20]:
        logging.info("  + %s", cve)
    if len(added) > 20:
        logging.info("  … (+%d autres)", len(added) - 20)

    if args.dry_run:
        logging.info("--dry-run : pas d'écriture.")
        return 0

    try:
        write_json(args.path, merged)
    except OSError as exc:
        logging.error("Écriture impossible sur %s : %s", args.path, exc)
        return 2

    logging.info("Écrit : %s", args.path)
    logging.info("Pense à annoter les CWEs ajoutées (champ `cwe` vide) pour "
                 "activer le mapping précis vers les techniques ATT&CK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
