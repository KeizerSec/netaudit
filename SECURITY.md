# Politique de sécurité

## Versions supportées

Les correctifs de sécurité sont appliqués uniquement sur la dernière version
mineure publiée. Les branches antérieures ne reçoivent pas de backport.

| Version | Supportée |
|---------|-----------|
| 2.6.x   | ✅        |
| < 2.6   | ❌        |

## Signaler une vulnérabilité

Merci de ne **pas** ouvrir d'issue publique pour une faille de sécurité.
Envoyez un rapport privé via GitHub Security Advisories :

<https://github.com/KeizerSec/netaudit/security/advisories/new>

Indiquez :

- le module affecté (`scan`, `webapp`, `prioritizer`, etc.) ;
- la version testée (`/version` ou `git rev-parse --short HEAD`) ;
- un scénario reproductible (payload, configuration, logs) ;
- l'impact estimé (divulgation, RCE, DoS, etc.).

Vous pouvez vous attendre à :

- un accusé de réception sous **72 heures** ouvrées ;
- un premier diagnostic sous **7 jours** ;
- un correctif ou un plan documenté sous **30 jours** selon la criticité.

## Périmètre

**Dans le périmètre** : tous les modules de `src/`, les templates Jinja, le
Dockerfile, les workflows CI, le schéma SQLite et les scripts `scripts/`.

**Hors périmètre** :

- les vulnérabilités de `nmap` lui-même (upstream) ;
- les failles issues d'une configuration non recommandée explicitement dans
  le README (p. ex. exécution sans `API_KEY` derrière Internet) ;
- les résultats de scan eux-mêmes — NetAudit remonte des CVEs tierces, il ne
  les corrige pas.

## Usage légal

NetAudit exécute `nmap` sur des cibles fournies par l'utilisateur. Scanner
une IP sans autorisation peut être illégal selon la juridiction
(France : art. 323-1 du Code pénal, États-Unis : CFAA, UK : CMA 1990…).
**Utilisez l'outil uniquement sur des hôtes que vous possédez ou pour
lesquels vous avez un mandat écrit.**
