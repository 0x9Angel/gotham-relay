# Gotham — relais volontaires

**Gotham** est le réseau de relais anonyme d'un messager chiffré souverain
(français). Il route les messages comme un mixnet — façon Tor, mais dédié
uniquement à la messagerie. Pour que l'anonymat tienne, il faut **beaucoup de
relais tenus par des gens différents**. Ce dépôt regroupe tout ce qu'il faut
pour en héberger un **en autonomie**.

## Pourquoi héberger un relais ?

Plus il y a de relais indépendants, plus le réseau est solide et impossible à
surveiller. Faire tourner un relais, c'est :

- **Aucun accès aux messages** — tout est chiffré de bout en bout.
- **Aucun moyen de savoir qui parle à qui** — c'est le but du système.
- **Aucun risque légal type « nœud de sortie Tor »** — le réseau est fermé,
  un relais ne se connecte jamais à l'Internet public.
- **Pas d'impact sur ton ping en jeu** — quelques dizaines de kbps au
  démarrage, débit plafonnable.

## Installer un relais en une commande (Linux Ubuntu/Debian)

Sur un hôte **joignable depuis Internet** (VPS, ou PC avec un port UDP
redirigé) :

```bash
curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.sh \
  | sudo GOTHAM_ENROLL_TOKEN=<token-donné-par-l-opérateur> bash
```

Le script télécharge le binaire vérifié, configure l'**auto-enrôlement**
(le relais s'annonce tout seul à l'annuaire), pose un service systemd durci,
ouvre le firewall, et te dit si l'autorité t'a accepté. Détails et options
(tier, port, pays, NAT…) dans **[docs/SETUP.md](docs/SETUP.md)**.

> Il te faut le **token d'enrôlement** (phase de test fermée) — demande-le à
> **Angel**, l'opérateur du réseau.

## Télécharger le binaire (Windows / macOS / install manuelle)

Binaires pré-compilés + empreinte `.sha256` sur la page
**[Releases](https://github.com/0x9Angel/gotham-relay/releases/latest)** :

| Plateforme | Fichier |
|---|---|
| Linux x86-64 | `gotham-relay-linux-x86_64` |
| Windows x86-64 | `gotham-relay-windows-x86_64.exe` |
| macOS (Apple Silicon) | `gotham-relay-macos-aarch64` |

**Vérifie toujours le `.sha256`** avant de lancer (voir [docs/SETUP.md](docs/SETUP.md)).

## Documentation

| Doc | Pour quoi |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | **Installer et lancer un relais** : one-liner, install manuelle, clé, redirection de port, options de débit, auto-enrôlement. |
| [docs/AUDIT.md](docs/AUDIT.md) | **« Je n'ai pas confiance, prouve-le »** — ce qu'un relais peut et ne peut pas faire, avec renvois ligne à ligne au code. |
| [docs/DEPLOY.md](docs/DEPLOY.md) | Déploiement multi-machines / VPS pour les opérateurs avancés. |

## Code source du relais

Le code du relais est dans ce dépôt : [crypto-gotham-relay/](crypto-gotham-relay/).
Tu peux le lire intégralement — c'est exactement le binaire que tu exécutes. La
documentation [docs/AUDIT.md](docs/AUDIT.md) renvoie ligne à ligne aux fichiers
de cette crate pour prouver chaque garantie.

Le **cœur du protocole** (mixnet Sphinx + crypto post-quantique, crate
`crypto-gotham`) reste privé le temps de finaliser l'app : le relais en dépend,
donc cette crate ne **compile pas** de façon autonome depuis ce dépôt. Pour
vérifier le binaire que tu reçois, **compare son empreinte SHA-256** à celle
publiée avec chaque build (le script le fait automatiquement) ; pour un rebuild
complet et indépendant, demande l'accès à la source complète.

---

© 2026 Angel. Documentation publiée pour les volontaires du réseau Gotham.
Le code du relais est distribué sous licence **AGPL-3.0-or-later**.
