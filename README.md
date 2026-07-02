# Gotham — relais volontaires

**Gotham** est le réseau de relais anonyme d'un messager chiffré souverain
(français). Il route les messages comme un mixnet — même famille que Tor / Nym /
Loopix, mais dédié uniquement à la messagerie. Pour que l'anonymat tienne, il
faut **beaucoup de relais tenus par des gens différents, et surtout répartis sur
des réseaux (/16) différents**. Ce dépôt regroupe tout ce qu'il faut pour en
héberger un **en autonomie**.

> **État actuel (honnête) :** l'anonymat au niveau réseau est encore
> **théorique**. Une autorité d'annuaire et 3 relais sont en ligne, mais les 3
> partagent un seul /16 ; la règle de diversité de chemin (opérateur distinct +
> réseau /16 distinct sur tout le trajet, entrée ≠ sortie) **refuse donc de
> construire une route** et **aucun message n'a encore transité le réseau
> réel**. C'est exactement pour ça qu'un volontaire sur un **/16 différent** est
> précieux aujourd'hui. La protection du **contenu** (chiffrement de bout en
> bout) est, elle, solide et testable dès maintenant ; l'anonymat réseau ne sera
> prouvé qu'une fois le réseau étalé sur plusieurs /16 et audité en externe.

## Pourquoi héberger un relais ?

Plus il y a de relais indépendants — et répartis sur des /16 différents — plus
le réseau devient difficile à surveiller. Faire tourner un relais, c'est :

- **Aucun accès aux messages** — tout est chiffré de bout en bout (X3DH +
  Double Ratchet, classe Signal). Cette garantie-là est effective aujourd'hui.
- **Personne ne devrait pouvoir savoir qui parle à qui** — c'est le but du
  système. ⚠️ Cette propriété n'est réellement acquise **qu'une fois le réseau
  étalé sur plusieurs /16** (voir la note d'état plus haut) ; ce n'est pas
  encore prouvé en conditions réelles, ni audité par un tiers indépendant.
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
