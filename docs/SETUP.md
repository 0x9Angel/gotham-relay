# Héberger un relais Gotham — guide volontaire (PC)

Merci de faire tourner un relais . Un relais reçoit des petits paquets
chiffrés de taille fixe, attend quelques millisecondes, et les renvoie au
nœud suivant. C'est tout. Tu ne vois **aucun message** et tu ne sais **pas
qui parle à qui** — c'est garanti par le code (voir [AUDIT.md](AUDIT.md)
si tu veux le vérifier toi-même).

## 1. Pré-requis

- Un PC **allumé le plus possible** (idéalement H24). Windows, macOS ou Linux.
- Une connexion correcte (fibre conseillée). Le trafic est **symétrique**
  (autant d'upload que de download).
- Pouvoir **ouvrir/rediriger un port UDP** sur ta box (voir §4).
- Charge attendue : quelques **dizaines de kbps** au démarrage (comme un
  onglet web), bien en dessous de **1 Mbps** même à plusieurs milliers
  d'utilisateurs.

## 2. Récupérer le binaire et le vérifier

L'opérateur du réseau te fournit le binaire de ta plateforme (avec son
fichier `.sha256`) :

| Plateforme | Fichier |
|---|---|
| Linux x86-64 | `gotham-relay-linux-x86_64` |
| Windows x86-64 | `gotham-relay-windows-x86_64.exe` |
| macOS (Apple Silicon) | `gotham-relay-macos-aarch64` |
| macOS (Intel) | `gotham-relay-macos-x86_64` |

Chaque binaire est publié avec un fichier `.sha256`. **Vérifie-le avant de
lancer** (ne fais jamais confiance à un binaire non vérifié) :

```bash
# Linux / macOS
shasum -a 256 -c gotham-relay-linux-x86_64.sha256

# Windows (PowerShell)
(Get-FileHash .\gotham-relay-windows-x86_64.exe -Algorithm SHA256).Hash
# compare à la valeur du .sha256
```

Tu peux aussi **lire le code du relais** (publié, AGPL) et vérifier le binaire —
voir [AUDIT.md](AUDIT.md).

Sous Linux/macOS, rends-le exécutable : `chmod +x gotham-relay-*`.

## 3. Générer ta clé d'identité

Le relais a une paire de clés X25519. La clé secrète ne quitte **jamais** ta
machine.

```bash
./gotham-relay keygen --key-file relay.key
# Affiche : public key: <64 caractères hex>
```

- Le fichier `relay.key` est créé en lecture seule propriétaire (0600) sous
  Unix. **Sous Windows**, garde-le sur un profil non partagé (il hérite des
  ACL du dossier).
- **Sauvegarde `relay.key`** : si tu le perds, ton relais change d'identité
  et doit être re-signé dans l'annuaire.
- Récupère ta clé publique à tout moment : `./gotham-relay pubkey --key-file relay.key`.

## 4. Ouvrir le port (port forwarding)

Le relais écoute en **UDP**. Par défaut le port est **443** (utile contre la
censure), mais tu peux en choisir un autre avec `--listen-port`.

1. Trouve l'IP locale de ton PC (ex. `192.168.1.42`).
2. Dans l'interface de ta box, crée une **redirection de port UDP** :
   `port externe (ex. 443) → 192.168.1.42 : même port`, protocole **UDP**.
   - **Freebox** : *Paramètres de la Freebox → Gestion des ports → Ajouter
     une redirection*, protocole UDP.
   - **Livebox / SFR / Bbox** : section *NAT/PAT* ou *Redirection de ports*.
3. Repère ton **IP publique** (par ex. via la page d'accueil de la box, ou
   `curl -4 ifconfig.me`). C'est l'adresse que tu communiqueras à l'opérateur.

> Sous Linux, lier un port < 1024 (comme 443) demande des privilèges :
> soit lancer en root, soit `sudo setcap 'cap_net_bind_service=+ep'
> ./gotham-relay`, soit choisir un port ≥ 1024 (ex. `--listen-port 4443`).
>
> Beaucoup d'abonnements **mobiles/4G et certaines fibres en CGNAT** ne
> donnent pas d'IP publique joignable. Si la redirection ne « prend » pas,
> c'est probablement ça.

## 5. Lancer le relais

```bash
./gotham-relay run \
  --key-file relay.key \
  --listen-port 443
```

Knobs utiles (tous optionnels) :

| Flag | Défaut | Rôle |
|---|---|---|
| `--listen-port <n>` | 443 | Port UDP/QUIC d'écoute. |
| `--listen-host <ip>` | `::` | Interface à lier (toutes par défaut). IP numérique uniquement. |
| `--max-pps <n>` | 2000 | Plafond paquets/seconde (anti-flood, protège ton CPU). `0` = illimité. |
| `--max-bytes-per-day <n>` | 0 | **Budget quotidien d'octets** (anti-dépassement de forfait). `0` = illimité. |
| `--delay-micros <n>` | 20000 | Délai moyen de brassage (20 ms). Ne touche pas à ta latence à toi. |

### Protéger ta connexion / ton forfait
- **Connexion limitée (mobile, forfait data, Freebox en data plan)** :
  fixe un budget, ex. `--max-bytes-per-day 5000000000` (~5 Go/jour). Au-delà,
  le relais *jette* le trafic excédentaire au lieu de cramer ton forfait.
- **PC de jeu** : garde `--max-pps` raisonnable (le défaut 2000 est déjà large)
  et, si tu as un routeur avec SQM/fq_codel, active-le — ça évite tout impact
  ping même en cas de pic.

## 6. T'enregistrer dans l'annuaire

Un relais n'est utilisé que s'il est listé dans l'**annuaire signé** par
l'opérateur. Envoie à l'opérateur (par un canal sûr) :

1. ta **clé publique** (`gotham-relay pubkey …`),
2. ton **IP publique + port** (ex. `203.0.113.7:443`),
3. (optionnel) un pseudo d'opérateur et le pays.

L'opérateur t'ajoute à l'annuaire signé et le redistribue. Ton relais est
alors actif dans le réseau.

## 7. Le laisser tourner (service)

- **Linux (systemd)** : crée un service qui relance le binaire au boot et en
  cas de crash (`Restart=on-failure`). Lance-le sous un utilisateur dédié,
  pas root, avec le `setcap` du §4.
- **Windows** : Planificateur de tâches → « Au démarrage de l'ordinateur ».
- **macOS** : un `launchd` `LaunchAgent`.

## En cas de souci
- Le relais log à `info` par défaut. Pour diagnostiquer : `RUST_LOG=debug`.
- Aucune adresse de tes correspondants n'est jamais journalisée
  ([AUDIT.md](AUDIT.md)).
- Pour arrêter proprement : `Ctrl-C` (le binaire capte le signal et s'arrête).

Merci encore — chaque relais agrandit l'anonymity set et rend le réseau plus
résistant.
