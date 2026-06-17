# Gotham — relais volontaires

**Gotham** est le réseau de relais anonyme d'un messager chiffré souverain
(français). Il route les messages comme un mixnet — façon Tor, mais dédié
uniquement à la messagerie. Pour que l'anonymat tienne, il faut **beaucoup de
relais tenus par des gens différents**. Ce dépôt regroupe la documentation
pour les **volontaires** qui veulent en héberger un.

## Pourquoi héberger un relais ?

Plus il y a de relais indépendants, plus le réseau est solide et impossible à
surveiller. Faire tourner un relais, c'est :

- 🔒 **Aucun accès aux messages** — tout est chiffré de bout en bout.
- 🕵️ **Aucun moyen de savoir qui parle à qui** — c'est le but du système.
- ⚖️ **Aucun risque légal type « nœud de sortie Tor »** — le réseau est fermé,
  un relais ne se connecte jamais à l'Internet public.
- 🎮 **Pas d'impact sur ton ping en jeu** — quelques dizaines de kbps au
  démarrage, débit plafonnable.

## Documentation

| Doc | Pour quoi |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | **Installer et lancer un relais** sur ton PC (Windows/macOS/Linux) : binaire, génération de clé, redirection de port, options de débit. |
| [docs/AUDIT.md](docs/AUDIT.md) | **« Je n'ai pas confiance, prouve-le »** — ce qu'un relais peut et ne peut pas faire, avec renvois au code exact + build reproductible. |
| [docs/DEPLOY.md](docs/DEPLOY.md) | Déploiement multi-machines / VPS pour les opérateurs avancés. |

## Comment participer

Le binaire et les clés se distribuent via l'opérateur du réseau (pour
l'instant en phase de démarrage). Contacte **Angel** pour recevoir le binaire,
le guide et être ajouté à l'annuaire signé.

## Auditabilité

La documentation [docs/AUDIT.md](docs/AUDIT.md) renvoie au code source de la
crate `crypto-gotham-relay`. Le binaire est **reproductible** : tu peux le
recompiler depuis la source et comparer son empreinte SHA-256 à celle publiée
avec chaque release. Pour un audit complet du code, demande l'accès au dépôt
source.

---

© 2026 Angel. Documentation publiée pour les volontaires du réseau Gotham.
Le code du relais est distribué sous licence **AGPL-3.0-or-later**.
