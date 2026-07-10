#!/usr/bin/env bash
# install-relay-macos.sh — one-command Gotham mixnet relay installer for macOS.
#
# Downloads the checksum-verified prebuilt binary (Apple Silicon or Intel),
# generates an identity key, and installs a launchd LaunchDaemon so the relay
# is boot-persistent and auto-restarts. Run with sudo.
#
#   curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay-macos.sh | sudo bash
#
# Env vars (all optional; same as the Linux installer):
#   GOTHAM_ENROLL_TOKEN  Only if the authority runs in closed/token mode.
#                        Enrollment is OPEN by default — you do NOT need one.
#   GOTHAM_AUTHORITY_URL Directory authority URL. Default http://144.24.205.188:8443
#   GOTHAM_TIER          entry|mix|exit. Default mix.
#   GOTHAM_PORT          UDP listen+advertise port. Default 443.
#   GOTHAM_ADVERTISE_IP  Public IP peers reach you on. If UNSET, the relay
#                        auto-maps its port and detects its public address via
#                        UPnP-IGD (home routers) — no manual port-forward.
set -euo pipefail

AUTHORITY_URL="${GOTHAM_AUTHORITY_URL:-http://144.24.205.188:8443}"
TIER="${GOTHAM_TIER:-mix}"
PORT="${GOTHAM_PORT:-443}"
ENROLL_TOKEN="${GOTHAM_ENROLL_TOKEN:-}"
REPO="0x9Angel/gotham-relay"

BIN=/usr/local/bin/gotham-relay
STATE_DIR=/usr/local/var/gotham-relay
KEYFILE="$STATE_DIR/relay.key"
LOG="$STATE_DIR/relay.log"
PLIST=/Library/LaunchDaemons/org.gotham.relay.plist

[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo: sudo bash $0"; exit 1; }
case "$TIER" in entry|mix|exit) ;; *) echo "[!] GOTHAM_TIER must be entry|mix|exit (got '$TIER')"; exit 1;; esac

case "$(uname -m)" in
  arm64)  ASSET=gotham-relay-macos-aarch64 ;;
  x86_64) ASSET=gotham-relay-macos-x86_64 ;;
  *) echo "[!] unsupported CPU arch: $(uname -m)"; exit 1 ;;
esac

echo "[1/4] Downloading + verifying $ASSET (latest release)…"
mkdir -p "$(dirname "$BIN")" "$STATE_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
base="https://github.com/$REPO/releases/latest/download"
curl -fsSL "$base/$ASSET"        -o "$TMP/$ASSET"
curl -fsSL "$base/$ASSET.sha256" -o "$TMP/$ASSET.sha256"
( cd "$TMP" && shasum -a 256 -c "$ASSET.sha256" ) || { echo "[!] Checksum verification FAILED — refusing to install."; exit 1; }
install -m 0755 "$TMP/$ASSET" "$BIN"

echo "[2/4] Generating relay identity (if absent)…"
[[ -f "$KEYFILE" ]] || "$BIN" keygen --key-file "$KEYFILE"
chmod 600 "$KEYFILE"
PUBKEY="$("$BIN" pubkey --key-file "$KEYFILE")"

# Advertise address: explicit if given, else let the binary auto-map via UPnP.
if [[ -n "${GOTHAM_ADVERTISE_IP:-}" ]]; then
    ADVERTISE_XML="    <string>--advertise-addr</string><string>${GOTHAM_ADVERTISE_IP}:$PORT</string>"
    ADVERTISE_MSG="${GOTHAM_ADVERTISE_IP}:$PORT (manual)"
else
    ADVERTISE_XML="    <!-- no --advertise-addr: the relay auto-maps its UDP port and detects its public IP via UPnP-IGD -->"
    ADVERTISE_MSG="auto (UPnP-IGD)"
fi
if [[ -n "$ENROLL_TOKEN" ]]; then
    TOKEN_XML="    <string>--enroll-token</string><string>$ENROLL_TOKEN</string>"
else
    TOKEN_XML="    <!-- open enrollment: no --enroll-token needed -->"
fi

echo "[3/4] Installing launchd LaunchDaemon…"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.gotham.relay</string>
  <key>ProgramArguments</key><array>
    <string>$BIN</string><string>run</string>
    <string>--key-file</string><string>$KEYFILE</string>
    <string>--listen-host</string><string>0.0.0.0</string>
    <string>--listen-port</string><string>$PORT</string>
    <string>--authority-url</string><string>$AUTHORITY_URL</string>
$ADVERTISE_XML
$TOKEN_XML
    <string>--tier</string><string>$TIER</string>
    <string>--heartbeat-secs</string><string>60</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict></plist>
PLIST
chmod 644 "$PLIST"; chown root:wheel "$PLIST"

echo "[4/4] Loading service…"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable system/org.gotham.relay

echo
echo "============================================================"
echo " Gotham relay installed (launchd: org.gotham.relay)"
echo " Public key : $PUBKEY"
echo " Advertised : $ADVERTISE_MSG   (tier: $TIER, port $PORT/udp)"
echo " Authority  : $AUTHORITY_URL"
echo " Live logs  : tail -F $LOG   (look for 'enrolled with directory authority')"
echo
echo " Keep this Mac awake on power so the relay stays online:"
echo "   sudo pmset -c sleep 0 disablesleep 1"
echo "============================================================"
