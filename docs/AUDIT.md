# Faire tourner un relais Gotham — dossier d'auditabilité

> *« Je veux bien aider, mais comment je sais que ton truc ne va pas lire mes
> messages, espionner les gens, ou me causer des ennuis ? »*

Réponse courte : **tu n'as pas à me croire sur parole.** Le code du relais est
public (AGPL-3.0) et présent dans ce dépôt — tu peux le lire et vérifier chaque
affirmation ci-dessous toi-même. Ce document pointe la **ligne exacte** qui
prouve chaque garantie.

Tout est dans la crate [`crypto-gotham-relay/`](../crypto-gotham-relay/). Les
renvois sont au format `fichier:ligne` et pointent vers les fichiers de cette
crate, juste à côté.

> **Note sur le périmètre** : ce dépôt contient le **code du relais** (le
> binaire que tu exécutes). Le **cœur du protocole** — mixnet Sphinx + crypto
> post-quantique (crate `crypto-gotham`) — reste privé. Le relais l'utilise via
> son API mais n'en contient pas l'implémentation ; cette crate ne compile donc
> pas seule depuis ici (voir « Vérifier toi-même » plus bas).

---

## Garantie 1 — un relais ne voit AUCUN message

Quand un relais transmet un paquet, il **déchiffre uniquement sa propre case
de routage** dans l'en-tête (la couche d'oignon qui lui dit « prochain saut =
X »). Le **contenu** (la charge utile) n'est jamais déchiffré : il est recopié
tel quel vers le saut suivant.

- Déchiffrement limité à l'en-tête de ce saut :
  [process.rs:199](../crypto-gotham-relay/src/process.rs#L199)
  — *« Unwrap (verifies MAC + decrypts this hop's slot) »*.
- Charge utile recopiée **verbatim**, jamais ouverte :
  [process.rs:242](../crypto-gotham-relay/src/process.rs#L242)
  — `next_packet[HEADER_LEN..].copy_from_slice(&packet_bytes[HEADER_LEN..])`.

Et même au **dernier saut** (le relais embarqué du destinataire), ce qui est
extrait reste du **chiffré de bout en bout** (sealed-sender + Double Ratchet) :
[transport.rs:107](../crypto-gotham-relay/src/transport.rs#L107). Le destinataire
seul, dans son app, possède les clés pour lire le texte. Un relais qui
*transmet* ne touche jamais à cette couche.

**Conclusion : un opérateur de relais ne peut pas lire les messages, point.**

---

## Garantie 2 — un relais ne sait PAS qui parle à qui

C'est le cœur de l'anonymat (chiffrement en oignon, façon Tor/mixnet) :

- Chaque relais ne connaît que son **saut précédent** et son **saut suivant**,
  jamais la chaîne complète. L'en-tête est pelé couche par couche
  ([process.rs:199](../crypto-gotham-relay/src/process.rs#L199)).
- **Aucune IP d'expéditeur n'est journalisée.** Au niveau de log par défaut
  (`info`), le relais n'émet **aucune adresse de pair**. Les seules adresses
  qui peuvent apparaître (en `debug`/`trace`, ou en `warn` si un envoi échoue)
  sont celles du **relais suivant** — un nœud public de l'annuaire — jamais
  l'expéditeur, jamais de lien expéditeur↔destinataire :
  [process.rs:33](../crypto-gotham-relay/src/process.rs#L33)
  — *« the relay never logs per-packet identifiers or peer IPs »*.
- Les paquets ont une **taille fixe** (2048 o) : impossible de corréler par la
  taille. Tout paquet de taille différente est jeté :
  [process.rs:160](../crypto-gotham-relay/src/process.rs#L160).
- Un **délai de brassage** (Poisson) décorelle les temps d'arrivée/départ.

**Conclusion : aucun relais seul ne peut relier deux interlocuteurs.**

---

## Garantie 3 — un relais ne se connecte JAMAIS à l'Internet « ouvert »

Contrairement à un **nœud de sortie Tor**, un relais Gotham ne sort jamais
vers le web public. Il ne se connecte **qu'au saut suivant** indiqué dans
l'en-tête chiffré et authentifié (un autre relais Gotham, ou le destinataire).

- Tous les points de connexion sortante visent une adresse issue de la **case
  de routage** du paquet :
  [transport.rs:508](../crypto-gotham-relay/src/transport.rs#L508),
  [pool.rs:189](../crypto-gotham-relay/src/pool.rs#L189).
- L'adresse provient de l'en-tête Sphinx, pas d'une saisie arbitraire :
  [process.rs:242](../crypto-gotham-relay/src/process.rs#L242) (construction du
  paquet sortant) — le `next_addr` vient de `outcome.record`.
- Il n'y a **aucun** client HTTP, `reqwest`, ni connexion arbitraire dans la
  crate (vérifiable : `grep -rE 'reqwest|http|TcpStream' crypto-gotham-relay/src`
  ne renvoie rien de tel).

**Conclusion : aucune plainte d'abus type « exit node » n'est possible. Ton
IP ne servira jamais à se connecter à un site tiers.**

---

## Garantie 4 — le relais protège TA machine

- **Limiteur de débit** intégré (token bucket paquets/s + budget quotidien
  d'octets) : un flood est jeté au coût d'une simple comparaison, **avant**
  tout calcul cryptographique :
  [process.rs:167](../crypto-gotham-relay/src/process.rs#L167),
  module complet [rate_limit.rs](../crypto-gotham-relay/src/rate_limit.rs).
  Tu fixes le plafond (`--max-pps`, `--max-bytes-per-day`).
- **Protection anti-rejeu** bornée en mémoire (cache LRU + TTL) :
  [replay.rs](../crypto-gotham-relay/src/replay.rs).
- **Clé secrète effacée de la mémoire** à la destruction de l'objet (zeroize) :
  [process.rs:91](../crypto-gotham-relay/src/process.rs#L91) (`#[derive(ZeroizeOnDrop)]`),
  champ `identity_sk` à [process.rs:99](../crypto-gotham-relay/src/process.rs#L99).
- **Refus des boucles** (un paquet ne peut pas te renvoyer vers toi-même) :
  [process.rs:249](../crypto-gotham-relay/src/process.rs#L249).
- Code prod **sans `panic`/`unwrap`** (un crash prendrait le relais entier) :
  politique de lint en tête de [lib.rs](../crypto-gotham-relay/src/lib.rs#L21).

---

## Vérifier toi-même

**1. Lis le code.** Toute la logique du relais est ici, et elle est petite :
le cœur tient dans [process.rs](../crypto-gotham-relay/src/process.rs)
(~250 lignes). Chaque garantie ci-dessus renvoie à la ligne exacte. C'est le
moyen le plus direct de savoir ce que fait le binaire.

**2. Vérifie l'empreinte du binaire.** Chaque binaire distribué est accompagné
d'un fichier `.sha256`. Avant de le lancer, compare :

```bash
# Linux / macOS
shasum -a 256 -c gotham-relay-<plateforme>.sha256
# Windows (PowerShell)
(Get-FileHash .\gotham-relay-<plateforme>.exe -Algorithm SHA256).Hash
```

**3. Rebuild complet (sur demande).** Le relais dépend du cœur `crypto-gotham`,
gardé privé — la crate de ce dépôt ne compile donc pas seule. Pour un rebuild
indépendant bit-à-bit et comparer au binaire publié, demande l'accès à la
source complète : la compilation se fait **sur le runner natif de chaque OS**
(pas de cross-compilation « en douce »).

---

## Ce qu'un relais NE fait pas (récap)

| Crainte | Réalité | Preuve |
|---|---|---|
| « Il lit mes messages » | Jamais — contenu E2E, recopié verbatim | process.rs:199, :242 |
| « Il sait qui parle à qui » | Non — oignon, pas d'IP source loggée | process.rs:33, :160 |
| « Mon IP va servir à attaquer des sites » | Non — aucune sortie clearnet | transport.rs:508, pool.rs:189 |
| « Ça va saturer ma connexion » | Plafonné par `--max-pps` / `--max-bytes-per-day` | rate_limit.rs |
| « Un bug va planter / fuiter ma clé » | `panic`-free, clé zeroizée | lib.rs:21, process.rs:91 |

## Limites honnêtes (ce qu'on ne te cache pas)

- **v0.1** : la couche de chiffrement *par saut de la charge utile* (oignon du
  payload) n'est pas encore active ; le contenu reste E2E-chiffré, mais un
  relais pourrait théoriquement distinguer deux payloads par leurs octets
  (menace limitée — c'est déjà du chiffré). Prévu en v0.2.
- Le **réseau est jeune** : plus il y a de relais, plus l'anonymat est fort.
  C'est précisément pourquoi on recrute.
- Le **limiteur est global** au nœud (pas par-source) — suffisant pour
  protéger tes ressources ; l'équité par-source viendra en v0.2.

Une question, un doute, un bout de code pas clair ? Demande — l'audit, c'est
le but.
