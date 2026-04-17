"""
Tests unitaires pour src/prioritizer.py.

Les appels réseau sont systématiquement montés avec monkeypatch pour garantir
des tests hermétiques, rapides, et reproductibles. CACHE_DIR est redirigé sur
tmp_path pour que chaque test parte d'un cache vierge.
"""
import importlib
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def prio(tmp_path, monkeypatch):
    """Recharge prioritizer.py avec CACHE_DIR isolé + prioritizer activé."""
    monkeypatch.setenv("CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("PRIORITIZER_ENABLED", "1")
    import prioritizer
    importlib.reload(prioritizer)
    return prioritizer


class TestPriorityScore:
    def test_cvss_seul(self, prio):
        assert prio.priority_score(cvss=5.0, epss=None, in_kev=False, ransomware=False) == 5.0

    def test_kev_ajoute_3_points(self, prio):
        assert prio.priority_score(cvss=5.0, epss=None, in_kev=True, ransomware=False) == 8.0

    def test_ransomware_ajoute_1p5(self, prio):
        # Ransomware sans KEV n'arrive pas en prod, mais la fonction doit rester additive.
        assert prio.priority_score(cvss=5.0, epss=None, in_kev=True, ransomware=True) == 9.5

    def test_epss_faible_pondere_faiblement(self, prio):
        # EPSS 0.2 < 0.5 → coefficient 1.0
        assert prio.priority_score(cvss=5.0, epss=0.2, in_kev=False, ransomware=False) == 5.2

    def test_epss_eleve_pondere_fortement(self, prio):
        # EPSS 0.9 ≥ 0.5 → coefficient 2.0 → +1.8
        assert prio.priority_score(cvss=5.0, epss=0.9, in_kev=False, ransomware=False) == 6.8

    def test_combinaison_maximale(self, prio):
        # CVSS 9.8 + KEV (3) + ransomware (1.5) + EPSS 0.95 (1.9) = 16.2
        score = prio.priority_score(cvss=9.8, epss=0.95, in_kev=True, ransomware=True)
        assert score == 16.2

    def test_cvss_borne_a_10(self, prio):
        assert prio.priority_score(cvss=99.0, epss=None, in_kev=False, ransomware=False) == 10.0

    def test_cvss_negatif_borne_a_0(self, prio):
        assert prio.priority_score(cvss=-3.0, epss=None, in_kev=False, ransomware=False) == 0.0

    def test_cvss_invalide_tombe_a_0(self, prio):
        assert prio.priority_score(cvss="N/A", epss=None, in_kev=False, ransomware=False) == 0.0


class TestPriorityLevel:
    @pytest.mark.parametrize("score,expected", [
        (15.0, "IMMEDIATE"),
        (13.0, "IMMEDIATE"),
        (12.99, "HIGH"),
        (10.0, "HIGH"),
        (9.99, "MEDIUM"),
        (6.0, "MEDIUM"),
        (5.99, "LOW"),
        (3.0, "LOW"),
        (2.99, "INFO"),
        (0.0, "INFO"),
    ])
    def test_seuils(self, prio, score, expected):
        assert prio.priority_level(score) == expected


class TestFetchKev:
    def test_disabled_retourne_dict_vide(self, prio, monkeypatch):
        monkeypatch.setenv("PRIORITIZER_ENABLED", "0")
        importlib.reload(prio)
        assert prio.fetch_kev() == {}

    def test_cache_frais_evite_requete(self, prio, monkeypatch):
        cached = {"CVE-2024-9999": {"ransomware": True, "due_date": "2024-12-01",
                                    "short_desc": "x", "date_added": "2024-10-01"}}
        prio._write_cache(prio.KEV_CACHE_FILE, cached)

        called = {"count": 0}
        def fake_get(url, timeout=10):
            called["count"] += 1
            return None
        monkeypatch.setattr(prio, "_http_get_json", fake_get)

        out = prio.fetch_kev()
        assert out == cached
        assert called["count"] == 0

    def test_cache_perime_rafraichit(self, prio, monkeypatch):
        # Cache périmé en reculant la mtime du fichier.
        prio._write_cache(prio.KEV_CACHE_FILE, {"CVE-OLD": {}})
        old = time.time() - prio.CACHE_TTL_SECONDS - 100
        os.utime(os.path.join(prio.CACHE_DIR, prio.KEV_CACHE_FILE), (old, old))

        fake_feed = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-1111", "knownRansomwareCampaignUse": "Known",
                 "dueDate": "2025-01-01", "shortDescription": "foo", "dateAdded": "2024-10-01"},
                {"cveID": "CVE-2024-2222", "knownRansomwareCampaignUse": "Unknown",
                 "dueDate": "2025-02-01", "shortDescription": "bar", "dateAdded": "2024-10-02"},
            ]
        }
        monkeypatch.setattr(
            prio, "_http_get_json_conditional",
            lambda url, last_modified=None, timeout=10: (fake_feed, "Wed, 16 Apr 2026 10:00:00 GMT", 200),
        )
        out = prio.fetch_kev()
        assert set(out.keys()) == {"CVE-2024-1111", "CVE-2024-2222"}
        assert out["CVE-2024-1111"]["ransomware"] is True
        assert out["CVE-2024-2222"]["ransomware"] is False

    def test_reseau_ko_sans_cache_retourne_vide(self, prio, monkeypatch):
        monkeypatch.setattr(
            prio, "_http_get_json_conditional",
            lambda url, last_modified=None, timeout=10: (None, None, 0),
        )
        assert prio.fetch_kev() == {}

    def test_reseau_ko_avec_cache_perime_degrade(self, prio, monkeypatch):
        # Cache périmé mais disponible → doit être réutilisé quand le réseau échoue.
        stale = {"CVE-OLD": {"ransomware": False, "due_date": "", "short_desc": "", "date_added": ""}}
        prio._write_cache(prio.KEV_CACHE_FILE, stale)
        old = time.time() - prio.CACHE_TTL_SECONDS - 100
        os.utime(os.path.join(prio.CACHE_DIR, prio.KEV_CACHE_FILE), (old, old))

        monkeypatch.setattr(
            prio, "_http_get_json_conditional",
            lambda url, last_modified=None, timeout=10: (None, None, 0),
        )
        assert prio.fetch_kev() == stale

    def test_if_modified_since_envoye_au_refresh(self, prio, monkeypatch):
        """Au 2ᵉ refresh, le header `If-Modified-Since` doit être transmis."""
        prio._write_cache(prio.KEV_CACHE_FILE, {"CVE-X": {"ransomware": False,
                                                          "due_date": "", "short_desc": "",
                                                          "date_added": ""}})
        prio._write_cache(prio.KEV_META_FILE, {"last_modified": "Tue, 15 Apr 2026 09:00:00 GMT"})
        old = time.time() - prio.CACHE_TTL_SECONDS - 100
        os.utime(os.path.join(prio.CACHE_DIR, prio.KEV_CACHE_FILE), (old, old))

        captured = {}
        def fake_conditional(url, last_modified=None, timeout=10):
            captured["last_modified"] = last_modified
            return {"vulnerabilities": []}, "Wed, 16 Apr 2026 10:00:00 GMT", 200
        monkeypatch.setattr(prio, "_http_get_json_conditional", fake_conditional)

        prio.fetch_kev()
        assert captured["last_modified"] == "Tue, 15 Apr 2026 09:00:00 GMT"

    def test_304_not_modified_garde_cache_et_refresh_mtime(self, prio, monkeypatch):
        """Réponse 304 → cache inchangé, mtime remonté pour reporter le TTL."""
        stale = {"CVE-KEPT": {"ransomware": False, "due_date": "", "short_desc": "",
                              "date_added": ""}}
        prio._write_cache(prio.KEV_CACHE_FILE, stale)
        prio._write_cache(prio.KEV_META_FILE, {"last_modified": "Tue, 15 Apr 2026 09:00:00 GMT"})

        cache_path = os.path.join(prio.CACHE_DIR, prio.KEV_CACHE_FILE)
        old = time.time() - prio.CACHE_TTL_SECONDS - 100
        os.utime(cache_path, (old, old))

        monkeypatch.setattr(
            prio, "_http_get_json_conditional",
            lambda url, last_modified=None, timeout=10: (None, last_modified, 304),
        )

        out = prio.fetch_kev()
        assert out == stale
        # mtime doit être remontée (le fichier n'est plus « périmé »)
        new_mtime = os.path.getmtime(cache_path)
        assert time.time() - new_mtime < 5


class TestFetchEpss:
    def test_disabled_retourne_dict_vide(self, prio, monkeypatch):
        monkeypatch.setenv("PRIORITIZER_ENABLED", "0")
        importlib.reload(prio)
        assert prio.fetch_epss(["CVE-2024-1"]) == {}

    def test_batch_decoupe_les_requetes(self, prio, monkeypatch):
        ids = [f"CVE-2024-{i:04d}" for i in range(1, prio.EPSS_BATCH_SIZE * 2 + 5)]
        calls = []

        def fake_get(url, timeout=10):
            calls.append(url)
            # Extrait les CVEs du querystring pour répondre cohérent.
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(url).query)
            cves = qs.get("cve", [""])[0].split(",")
            return {"data": [{"cve": c, "epss": "0.1", "percentile": "0.5"} for c in cves]}

        monkeypatch.setattr(prio, "_http_get_json", fake_get)
        out = prio.fetch_epss(ids)
        # Trois batches attendus pour 165 CVEs avec batch=80.
        assert len(calls) == 3
        assert len(out) == len(ids)

    def test_cache_evite_refetch(self, prio, monkeypatch):
        # Premier appel : API mockée → remplit le cache.
        monkeypatch.setattr(prio, "_http_get_json",
                            lambda url, timeout=10: {"data": [{"cve": "CVE-2024-1", "epss": "0.3", "percentile": "0.9"}]})
        first = prio.fetch_epss(["CVE-2024-1"])
        assert first["CVE-2024-1"]["score"] == 0.3

        # Deuxième appel : même CVE → le réseau ne doit PAS être rappelé.
        called = {"count": 0}
        def tripwire(url, timeout=10):
            called["count"] += 1
            return None
        monkeypatch.setattr(prio, "_http_get_json", tripwire)
        second = prio.fetch_epss(["CVE-2024-1"])
        assert second["CVE-2024-1"]["score"] == 0.3
        assert called["count"] == 0

    def test_ignore_ids_non_cve(self, prio, monkeypatch):
        captured = {}
        def fake_get(url, timeout=10):
            captured["url"] = url
            return {"data": []}
        monkeypatch.setattr(prio, "_http_get_json", fake_get)
        prio.fetch_epss(["CVE-2024-1", "msf:exploit/foo", "bugtraq:12345"])
        assert "CVE-2024-1" in captured["url"]
        assert "msf" not in captured["url"]

    def test_reseau_ko_retourne_dict_vide(self, prio, monkeypatch):
        monkeypatch.setattr(prio, "_http_get_json", lambda url, timeout=10: None)
        assert prio.fetch_epss(["CVE-2024-1"]) == {}


class TestEnrichVulns:
    def _scan_sample(self):
        return {
            "ip": "10.0.0.1",
            "ports": [{
                "port": 443,
                "vulns": [
                    {"id": "CVE-2024-AAA", "score": 9.8},
                    {"id": "CVE-2024-BBB", "score": 4.0},
                    {"id": "MSF-xyz",      "score": 7.0},  # ignoré (pas CVE-)
                ],
            }],
        }

    def test_sans_vuln_summary_vide(self, prio):
        data = {"ip": "10.0.0.1", "ports": [{"port": 22, "vulns": []}]}
        out = prio.enrich_vulns(data)
        assert out["priority_summary"]["max_level"] == "INFO"
        assert out["priority_summary"]["top"] == []

    def test_enrichissement_complet(self, prio, monkeypatch):
        monkeypatch.setattr(prio, "fetch_kev", lambda: {
            "CVE-2024-AAA": {"ransomware": True, "due_date": "2025-01-01",
                             "short_desc": "pwn", "date_added": "2024-10-01"},
        })
        monkeypatch.setattr(prio, "fetch_epss", lambda ids: {
            "CVE-2024-AAA": {"score": 0.9, "percentile": 0.98},
            "CVE-2024-BBB": {"score": 0.05, "percentile": 0.3},
        })
        data = prio.enrich_vulns(self._scan_sample())

        vulns = data["ports"][0]["vulns"]
        aaa = next(v for v in vulns if v["id"] == "CVE-2024-AAA")
        bbb = next(v for v in vulns if v["id"] == "CVE-2024-BBB")

        # CVE-AAA : 9.8 + 3 (KEV) + 1.5 (ransom) + 1.8 (EPSS*2) = 16.1
        assert aaa["priority_level"] == "IMMEDIATE"
        assert aaa["kev"]["ransomware"] is True
        assert aaa["priority_score"] == 16.1
        # CVE-BBB : 4.0 + 0.05 (EPSS*1) = 4.05 → LOW
        assert bbb["priority_level"] == "LOW"
        assert bbb["kev"] is None

        summary = data["priority_summary"]
        assert summary["max_level"] == "IMMEDIATE"
        assert summary["kev_count"] == 1
        assert summary["ransomware_count"] == 1
        assert summary["top"][0]["id"] == "CVE-2024-AAA"
        assert "CISA KEV" in summary["sources_used"]
        assert "FIRST EPSS" in summary["sources_used"]

    def test_top_tri_par_score_decroissant(self, prio, monkeypatch):
        monkeypatch.setattr(prio, "fetch_kev", lambda: {})
        monkeypatch.setattr(prio, "fetch_epss", lambda ids: {})
        data = {
            "ip": "10.0.0.1",
            "ports": [{"port": 80, "vulns": [
                {"id": f"CVE-2024-{i:04d}", "score": float(i)} for i in range(1, 8)
            ]}],
        }
        out = prio.enrich_vulns(data)
        scores = [t["priority_score"] for t in out["priority_summary"]["top"]]
        assert scores == sorted(scores, reverse=True)
        assert len(out["priority_summary"]["top"]) == 5

    def test_offline_fallback_score_reste_cvss(self, prio, monkeypatch):
        # Simule un échec réseau complet : ni KEV ni EPSS ne doivent enrichir.
        monkeypatch.setattr(prio, "fetch_kev", lambda: {})
        monkeypatch.setattr(prio, "fetch_epss", lambda ids: {})
        data = prio.enrich_vulns(self._scan_sample())
        aaa = next(v for v in data["ports"][0]["vulns"] if v["id"] == "CVE-2024-AAA")
        # CVSS 9.8 seul → MEDIUM (<10), car le boost KEV manque.
        assert aaa["priority_score"] == 9.8
        assert aaa["priority_level"] == "MEDIUM"
        assert data["priority_summary"]["sources_used"] == []
