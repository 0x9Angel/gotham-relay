#!/usr/bin/env bash
# install-relay.sh — one-command, AUTONOMOUS Gotham mixnet relay installer.
#
# For volunteer relay operators on a reachable Ubuntu/Debian host (a VPS, or a
# home box where you can port-forward one UDP port). No source build: it
# downloads the prebuilt, checksum-verified relay binary and wires up
# auto-enrollment so the relay announces itself to the directory authority and
# joins the network on its own — no manual directory editing.
#
# USAGE (run as root):
#   curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.sh \
#     | sudo GOTHAM_ENROLL_TOKEN=<token-from-operator> bash
#
# or, after cloning the repo:
#   sudo GOTHAM_ENROLL_TOKEN=<token> bash infra/scripts/install-relay.sh
#
# CONFIG (environment variables):
#   GOTHAM_ENROLL_TOKEN   REQUIRED. Bearer token the operator gives you.
#   GOTHAM_AUTHORITY_URL  Directory authority base URL.
#                         Default: http://144.24.205.188:8443
#   GOTHAM_TIER           entry | mix | exit. Default: mix
#                         (a middle hop sees neither sender nor recipient —
#                          the safest role for a volunteer).
#   GOTHAM_PORT           UDP listen + advertise port. Default: 443
#   GOTHAM_ADVERTISE_IP   Public IP peers reach you on. Default: auto-detected.
#                         Set this explicitly if you are behind NAT/port-forward.
#   GOTHAM_COUNTRY        ISO 3166-1 code to publish (e.g. FR). Optional.
#   GOTHAM_OPERATOR       Public nickname (transparency only). Optional.
#
# What it does:
#   1. Installs minimal deps (curl, ufw, ca-certificates)
#   2. Creates the `gotham` system user (no shell, no home)
#   3. Downloads + sha256-verifies the latest `gotham-relay-linux-x86_64`
#   4. Generates an X25519 identity key if one doesn't exist
#   5. Writes the relay config + installs a hardened systemd unit
#   6. Opens the firewall (SSH + your UDP port), starts the service
#   7. Waits and reports whether the authority accepted the enrollment

set -euo pipefail

# ─── Config + defaults ──────────────────────────────────────────────────
AUTHORITY_URL="${GOTHAM_AUTHORITY_URL:-http://144.24.205.188:8443}"
TIER="${GOTHAM_TIER:-mix}"
PORT="${GOTHAM_PORT:-443}"
COUNTRY="${GOTHAM_COUNTRY:-}"
OPERATOR="${GOTHAM_OPERATOR:-}"
ENROLL_TOKEN="${GOTHAM_ENROLL_TOKEN:-}"

REPO="0x9Angel/gotham-relay"
ASSET="gotham-relay-linux-x86_64"
INSTALL_DIR=/opt/gotham
BIN="$INSTALL_DIR/bin/gotham-relay"
STATE_DIR="$INSTALL_DIR/state"
KEYFILE="$STATE_DIR/relay.key"
ENVFILE=/etc/gotham/relay.env
LOG_DIR=/var/log/gotham
RELAY_USER=gotham

# ─── Sanity checks ──────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo GOTHAM_ENROLL_TOKEN=... bash $0"; exit 1; }
[[ -n "$ENROLL_TOKEN" ]] || {
    echo "[!] GOTHAM_ENROLL_TOKEN is required. Ask the project operator for the"
    echo "    closed-test enrollment token, then run:"
    echo "      sudo GOTHAM_ENROLL_TOKEN=<token> bash $0"
    exit 1
}
case "$TIER" in entry|mix|exit) ;; *) echo "[!] GOTHAM_TIER must be entry|mix|exit (got '$TIER')"; exit 1;; esac
command -v apt-get &>/dev/null || { echo "[!] This installer targets Debian/Ubuntu (apt). For other distros, see docs/SETUP.md."; exit 1; }

echo "[1/7] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -qq -y --no-install-recommends curl ca-certificates ufw libcap2-bin

echo "[2/7] Creating $RELAY_USER system user..."
id "$RELAY_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$RELAY_USER"

echo "[3/7] Downloading + verifying $ASSET (latest release)..."
mkdir -p "$INSTALL_DIR/bin" "$STATE_DIR" "$(dirname "$ENVFILE")" "$LOG_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
base="https://github.com/$REPO/releases/latest/download"
curl -fsSL "$base/$ASSET"        -o "$TMP/$ASSET"
curl -fsSL "$base/$ASSET.sha256" -o "$TMP/$ASSET.sha256"
( cd "$TMP" && sha256sum -c "$ASSET.sha256" ) || { echo "[!] Checksum verification FAILED — refusing to install."; exit 1; }
install -m 0755 -o root -g root "$TMP/$ASSET" "$BIN"
# UDP ports < 1024 need CAP_NET_BIND_SERVICE since we run unprivileged.
if [[ "$PORT" -lt 1024 ]]; then setcap 'cap_net_bind_service=+ep' "$BIN"; fi

echo "[4/7] Generating relay identity (if absent)..."
chown -R "$RELAY_USER:$RELAY_USER" "$STATE_DIR" "$LOG_DIR"
[[ -f "$KEYFILE" ]] || sudo -u "$RELAY_USER" "$BIN" keygen --key-file "$KEYFILE"
PUBKEY="$(sudo -u "$RELAY_USER" "$BIN" pubkey --key-file "$KEYFILE")"

echo "[5/7] Detecting public IP + writing config..."
ADVERTISE_IP="${GOTHAM_ADVERTISE_IP:-$(curl -fsSL --max-time 8 https://api.ipify.org || true)}"
[[ -n "$ADVERTISE_IP" ]] || { echo "[!] Could not auto-detect a public IP. Re-run with GOTHAM_ADVERTISE_IP=<your.public.ip>"; exit 1; }
EXTRA=""
[[ -n "$COUNTRY"  ]] && EXTRA+=" --country $COUNTRY"
[[ -n "$OPERATOR" ]] && EXTRA+=" --operator $OPERATOR"

# relay.env holds the token — keep it readable only by root + the relay user.
cat > "$ENVFILE" <<EOF
GOTHAM_ENROLL_TOKEN=$ENROLL_TOKEN
GOTHAM_AUTHORITY_URL=$AUTHORITY_URL
GOTHAM_ADVERTISE_ADDR=$ADVERTISE_IP:$PORT
GOTHAM_PORT=$PORT
GOTHAM_TIER=$TIER
GOTHAM_EXTRA_ARGS=$EXTRA
EOF
chown root:"$RELAY_USER" "$ENVFILE"
chmod 0640 "$ENVFILE"

echo "[6/7] Installing systemd unit + firewall..."
UNIT_SRC=""
for c in "$(dirname "$0")/../systemd/crypto-gotham-relay.service" /tmp/crypto-src/infra/systemd/crypto-gotham-relay.service; do
    [[ -f "$c" ]] && UNIT_SRC="$c" && break
done
if [[ -n "$UNIT_SRC" ]]; then
    install -m 0644 "$UNIT_SRC" /etc/systemd/system/crypto-gotham-relay.service
else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/infra/systemd/crypto-gotham-relay.service" \
        -o /etc/systemd/system/crypto-gotham-relay.service
fi
ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1 || true
ufw allow "$PORT"/udp comment 'Gotham QUIC relay' >/dev/null 2>&1 || true
yes | ufw enable >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now crypto-gotham-relay.service

echo "[7/7] Waiting for the authority to accept enrollment..."
ENROLLED=0
for _ in $(seq 1 6); do
    sleep 5
    if grep -qi "enroll.*ok\|enrolled\|directory updated\|announced" "$LOG_DIR/relay.log" 2>/dev/null; then ENROLLED=1; break; fi
    if grep -qi "probe failed\|enroll rejected\|liveness" "$LOG_DIR/relay.log" 2>/dev/null; then break; fi
done

echo
echo "============================================================"
if [[ "$ENROLLED" -eq 1 ]]; then
    echo " Gotham relay is LIVE and ENROLLED ✓"
else
    echo " Gotham relay installed — enrollment NOT yet confirmed ⚠"
    echo " Most common cause: your UDP port $PORT is not reachable from the"
    echo " internet (router port-forward missing, or CGNAT). The authority"
    echo " must be able to reach $ADVERTISE_IP:$PORT/udp to accept you."
fi
echo "============================================================"
echo " Public key : $PUBKEY"
echo " Advertised : $ADVERTISE_IP:$PORT/udp   (tier: $TIER)"
echo " Authority  : $AUTHORITY_URL"
echo
echo " Live logs  : tail -F $LOG_DIR/relay.log"
echo " Status     : systemctl status crypto-gotham-relay.service"
echo " Restart    : sudo systemctl restart crypto-gotham-relay.service"
echo "============================================================"
