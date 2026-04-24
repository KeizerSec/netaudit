"""Tests unitaires pour scripts/refresh_known_cves.py.

Focus : la fonction `merge` ne doit jamais écraser une annotation manuelle
(c'est la raison d'être du fichier). Le reste (HTTP, I/O) est trivial.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from refresh_known_cves import merge, write_json, load_existing


def test_merge_ne_surecrit_jamais_une_cwe_annotee():
    existing = {
        "CVE-2021-44228": {"name": "Log4Shell", "cwe": "CWE-502"},
        "_comment": "fixture commentaire",
    }
    kev = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
        ]
    }
    merged, added = merge(existing, kev)
    assert added == []
    assert merged["CVE-2021-44228"]["cwe"] == "CWE-502"
    assert merged["CVE-2021-44228"]["name"] == "Log4Shell"


def test_merge_ajoute_nouvelles_cves_avec_cwe_vide():
    existing = {}
    kev = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget"},
            {"cveID": "cve-2024-0002", "vendorProject": "Foo", "product": "Bar"},  # case insensitive
        ]
    }
    merged, added = merge(existing, kev)
    assert set(added) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert merged["CVE-2024-0001"]["cwe"] == ""
    assert "Acme Widget" == merged["CVE-2024-0001"]["name"]


def test_merge_ignore_non_cve_ids():
    kev = {"vulnerabilities": [{"cveID": "NOT-A-CVE", "vendorProject": "x", "product": "y"}]}
    merged, added = merge({}, kev)
    assert added == []
    assert merged == {}


def test_merge_preserve_commentaires_top_level():
    existing = {"_comment": "à garder", "CVE-2000-0001": {"name": "old", "cwe": ""}}
    merged, _ = merge(existing, {"vulnerabilities": []})
    assert merged["_comment"] == "à garder"


def test_write_and_reload_roundtrip(tmp_path):
    path = tmp_path / "cves.json"
    data = {"CVE-2024-0001": {"name": "x", "cwe": "CWE-78"}}
    write_json(str(path), data)
    assert load_existing(str(path)) == data
    # Trailing newline pour éviter les diffs inutiles avec l'existant.
    assert path.read_text(encoding="utf-8").endswith("\n")


def test_load_existing_fichier_absent_retourne_dict_vide(tmp_path):
    assert load_existing(str(tmp_path / "missing.json")) == {}
