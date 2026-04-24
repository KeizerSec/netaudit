"""
Métadonnées de version exposées par l'API (`/version`).

Le numéro sémantique est figé dans le code source.
Le hash commit est résolu au runtime si un dépôt git est accessible, sinon vide —
on ne veut pas que l'endpoint casse dans une image Docker sans `.git`.
"""
from __future__ import annotations

import os
import subprocess

__version__ = "2.6.1"
__name__ = "NetAudit"

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_BASE_DIR)


def get_git_commit() -> str:
    """Retourne le hash commit court (7 caractères) ou chaîne vide si indisponible.

    Utilisé pour identifier précisément une image en production :
    deux builds depuis la même version sémantique peuvent contenir des patches
    différents — le hash commit lève l'ambiguïté.
    """
    # Sentinelle explicite : si BUILD_COMMIT est injecté à la construction de
    # l'image, on l'utilise directement sans dépendre de git au runtime.
    env_commit = os.getenv("BUILD_COMMIT", "").strip()
    if env_commit:
        return env_commit[:7]

    try:
        result = subprocess.run(
            ["git", "-C", _REPO_DIR, "rev-parse", "--short", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=True,
        )
        return result.stdout.decode().strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return ""


def version_info() -> dict:
    """Payload JSON pour l'endpoint /version."""
    return {
        "name":    __name__,
        "version": __version__,
        "commit":  get_git_commit(),
    }
