# Héberger un relais Gotham — guide volontaire

Merci de faire tourner un relais 🙏. Un relais reçoit des petits paquets
chiffrés de taille fixe, attend quelques millisecondes, et les renvoie au
nœud suivant. C'est tout. Tu ne vois **aucun message** et tu ne sais **pas
qui parle à qui** — c'est garanti par le code (voir [AUDIT.md](AUDIT.md)
si tu veux le vérifier toi-même).

Avec l'**auto-enrôlement**, ton relais s'annonce tout seul à l'annuaire et
rejoint le réseau sans intervention manuelle de l'opérateur.

## 0. Ce qu'il te faut

- Un hôte **joignable depuis Internet** : un petit VPS, **ou** un PC chez toi
  où tu peux **rediriger un port UDP** sur ta box.
- Idéalement allumé **H24** (un relais qui s'éteint disparaît du réseau).
- Le **token d'enrôlement** (closed test) — demande-le à l'opérateur du projet.

> ⚠️ Beaucoup d'abonnements **mobiles/4G et certaines fibres en CGNAT** ne
> donnent pas d'IP publique joignable. Dans ce cas l'auto-enrôlement échouera
> (l'autorité doit pouvoir *te* joindre) — il te faut un hôte avec une vraie
> IP publique.

---

## Installation express (Linux Ubuntu/Debian — recommandé)

Une seule commande installe le binaire vérifié, configure l'auto-enrôlement,
pose un service systemd durci, ouvre le firewall, et te dit si l'autorité t'a
accepté :

```bash
curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.sh \
  | sudo GOTHAM_ENROLL_TOKEN=<token-donné-par-l-opérateur> bash
```

Options (variables d'environnement, toutes facultatives sauf le token) :

| Variable | Défaut | Rôle |
|---|---|---|
| `GOTHAM_ENROLL_TOKEN` | — (**requis**) | Token fourni par l'opérateur. |
| `GOTHAM_TIER` | `mix` | `entry`/`mix`/`exit`. **`mix`** est le plus sûr pour un volontaire (ne voit ni l'expéditeur ni le destinataire). |
| `GOTHAM_PORT` | `443` | Port UDP d'écoute **et** annoncé. |
| `GOTHAM_ADVERTISE_IP` | auto | IP publique sur laquelle on te joint. À fixer si tu es derrière NAT/port-forward. |
| `GOTHAM_COUNTRY` | — | Code pays ISO (ex. `FR`), publié pour la transparence. |
| `GOTHAM_OPERATOR` | — | Pseudo public (transparence uniquement). |

Exemple complet :

```bash
curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.sh \
  | sudo GOTHAM_ENROLL_TOKEN=xxxxx GOTHAM_TIER=mix GOTHAM_COUNTRY=FR GOTHAM_OPERATOR=alice bash
```

> Si tu es **derrière une box**, fais d'abord la redirection de port (§ *Ouvrir
> le port* plus bas), puis lance avec `GOTHAM_ADVERTISE_IP=<ton-IP-publique>`.

C'est tout. Saute directement à la section *Vérifier que ça marche*. Le reste
de ce guide décrit l'installation **manuelle** (autres OS, ou si tu préfères
ne pas utiliser le script).

---

## Installation manuelle

### 1. Récupérer le binaire et le vérifier

Télécharge le binaire de ta plateforme depuis la page *Releases* :

| Plateforme | Fichier |
|---|---|
| Linux x86-64 | `gotham-relay-linux-x86_64` |
| Windows x86-64 | `gotham-relay-windows-x86_64.exe` |
| macOS (Apple Silicon) | `gotham-relay-macos-aarch64` |

Chaque binaire est publié avec un fichier `.sha256`. **Vérifie-le avant de
lancer** (ne fais jamais confiance à un binaire non vérifié) :

```bash
# Linux / macOS
sha256sum -c gotham-relay-linux-x86_64.sha256

# Windows (PowerShell)
(Get-FileHash .\gotham-relay-windows-x86_64.exe -Algorithm SHA256).Hash
# compare à la valeur du .sha256
```

Tu peux aussi **recompiler depuis les sources** (AGPL, publiques) et comparer
le hash — la procédure est dans [AUDIT.md](AUDIT.md).

Sous Linux/macOS, rends-le exécutable : `chmod +x gotham-relay-*`.

### 2. Générer ta clé d'identité

Le relais a une paire de clés X25519. La clé secrète ne quitte **jamais** ta
machine.

```bash
./gotham-relay keygen --key-file relay.key
# Affiche : public key: <64 caractères hex>
```

- Le fichier `relay.key` est créé en lecture seule propriétaire (0600) sous
  Unix. **Sous Windows**, garde-le sur un profil non partagé.
- **Sauvegarde `relay.key`** : si tu le perds, ton relais change d'identité.
- Récupère ta clé publique à tout moment : `./gotham-relay pubkey --key-file relay.key`.

### 3. Ouvrir le port (port forwarding)

Le relais écoute en **UDP**. Par défaut **443** (utile contre la censure),
modifiable avec `--listen-port`.

1. Trouve l'IP locale de ton PC (ex. `192.168.1.42`).
2. Dans l'interface de ta box, crée une **redirection de port UDP** :
   `port externe (ex. 443) → 192.168.1.42 : même port`, protocole **UDP**.
   - **Freebox** : *Paramètres → Gestion des ports → Ajouter une redirection*, UDP.
   - **Livebox / SFR / Bbox** : section *NAT/PAT* ou *Redirection de ports*.
3. Repère ton **IP publique** (`curl -4 ifconfig.me`). C'est ton `advertise-addr`.

> ⚠️ Sous Linux, lier un port < 1024 (comme 443) demande des privilèges : soit
> root, soit `sudo setcap 'cap_net_bind_service=+ep' ./gotham-relay`, soit un
> port ≥ 1024 (ex. `--listen-port 4443`).

### 4. Lancer le relais (avec auto-enrôlement)

```bash
GOTHAM_ENROLL_TOKEN=<token> ./gotham-relay run \
  --key-file relay.key \
  --listen-port 443 \
  --authority-url http://144.24.205.188:8443 \
  --advertise-addr <ton-IP-publique>:443 \
  --tier mix \
  --country FR --operator alice
```

Dès le lancement, le relais s'annonce à l'autorité, qui le **sonde** (elle se
reconnecte à `advertise-addr` pour prouver que tu es joignable et que tu
détiens bien la clé), puis l'ajoute à l'annuaire signé. Il **ré-annonce**
périodiquement (heartbeat) pour rester listé.

Knobs utiles (optionnels) :

| Flag | Défaut | Rôle |
|---|---|---|
| `--tier <entry\|mix\|exit>` | `mix` | Rôle annoncé. |
| `--listen-host <ip>` | `::` | Interface à lier (toutes par défaut). IP numérique. |
| `--heartbeat-secs <n>` | 300 | Intervalle de ré-annonce. |
| `--max-pps <n>` | 2000 | Plafond paquets/seconde (anti-flood). `0` = illimité. |
| `--max-bytes-per-day <n>` | 0 | **Budget quotidien d'octets** (anti-dépassement de forfait). `0` = illimité. |
| `--delay-micros <n>` | 20000 | Délai moyen de brassage (20 ms). N'affecte pas *ta* latence. |

**Protéger ton forfait** : connexion limitée → `--max-bytes-per-day 5000000000`
(~5 Go/jour) ; au-delà, le relais jette le trafic excédentaire.

### 5. Le laisser tourner (service)

- **Linux (systemd)** : le plus simple est le script d'install express ci-dessus
  (il pose un service durci, non-root, qui relance au boot et en cas de crash).
  Le unit de référence est [`../infra/systemd/crypto-gotham-relay.service`](../infra/systemd/crypto-gotham-relay.service).
- **Windows** : Planificateur de tâches → « Au démarrage de l'ordinateur ».
- **macOS** : un `launchd` `LaunchAgent`.

---

## Vérifier que ça marche

```bash
# avec le service systemd
systemctl status crypto-gotham-relay.service
tail -F /var/log/gotham/relay.log
```

- ✅ **Enrôlé** : un message d'annonce acceptée apparaît, et ta clé publique
  apparaît dans l'annuaire : `curl -s http://144.24.205.188:8443/directory`.
- ⚠️ **`probe failed` / `enroll rejected`** : l'autorité n'arrive pas à te
  joindre sur `advertise-addr`. Causes habituelles :
  - port UDP non redirigé sur la box, ou mauvais port/IP annoncés,
  - **CGNAT** (pas d'IP publique joignable),
  - firewall local/cloud qui bloque l'UDP entrant (ouvre le port côté
    fournisseur **et** en local : `ufw allow <port>/udp`).

## Confidentialité & sécurité

- Aucune adresse de correspondant n'est jamais journalisée ([AUDIT.md](AUDIT.md)).
- Le relais ne déchiffre rien d'autre que la couche d'oignon d'un seul saut.
- Un **mix** (défaut) ne voit ni l'expéditeur ni le destinataire — privilégie
  ce rôle si tu héberges depuis chez toi.

Merci encore — chaque relais agrandit l'anonymity set et rend le réseau plus
résistant. 🛡️
