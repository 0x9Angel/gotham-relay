# Gotham relay

**Run a node of the Gotham mixnet. One command. No account, no token, no
sign-up.** The network is made of volunteer relays like the one you are about
to start — the more independent operators, the stronger everyone's anonymity.

Gotham is a post-quantum-hybrid mixnet (X25519 + ML-KEM-768 per hop, fixed
2048-byte Sphinx packets, Loopix-style timed mixing). A relay peels exactly one
encryption layer off each packet and forwards it — it never sees who is talking
to whom, and never sees message content.

---

## Install (one command)

You need a machine that is reachable from the internet: a **VPS/cloud host**
(public IP), or a **home computer behind a router that supports UPnP** (most
do). One UDP port is opened for you.

**Linux** (Debian/Ubuntu/Arch/Fedora/openSUSE) — run as root:
```bash
curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.sh | sudo bash
```

**macOS** — run with sudo:
```bash
curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay-macos.sh | sudo bash
```

**Windows** — in an **elevated** PowerShell (Run as Administrator):
```powershell
irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.ps1 | iex
```

That's it. The installer downloads the correct binary for your OS/CPU, verifies
its SHA-256, generates a relay identity key, opens the firewall, and installs a
background service that **starts automatically at every boot**. It then enrolls
with the directory authority and joins the network on its own.

When it finishes it prints your relay's public key and whether enrollment was
accepted. Nothing else to do.

---

## Options (all optional)

Set these as environment variables before running if you want to override the
defaults — you don't need any of them:

| Variable | Default | Meaning |
|---|---|---|
| `GOTHAM_TIER` | `mix` | `entry`, `mix`, or `exit`. **`mix`** (a middle hop that sees neither sender nor recipient) is the safest role for a volunteer. |
| `GOTHAM_PORT` | `443` | UDP port to listen on and advertise. |
| `GOTHAM_ADVERTISE_IP` | auto | Your public IP. Auto-detected (or auto-mapped via UPnP on macOS/Windows). Set it only if you port-forward manually. |
| `GOTHAM_COUNTRY` | — | ISO code to publish for transparency (e.g. `FR`). |
| `GOTHAM_OPERATOR` | — | A public nickname (transparency only). |

Example: `curl -fsSL …/install-relay.sh | sudo GOTHAM_TIER=mix GOTHAM_COUNTRY=FR bash`

---

## Verify before you trust

Every release binary ships a `.sha256` sidecar, which the installer checks
automatically. Because the relay is **open source (AGPL-3.0)**, its source is here for you to
read and audit, and the installer's SHA-256 check is your tamper seal on the
download.

## Requirements & reachability

The authority must be able to reach your advertised `IP:port/UDP` to confirm
your relay is live (a proof-of-presence probe). If enrollment isn't confirmed,
the usual cause is that your UDP port isn't reachable from the internet —
a missing router port-forward, or **CGNAT** (your ISP double-NATs you), which
a home relay can't currently work around.

## Manage the relay

- **Linux:** `systemctl status crypto-gotham-relay` · `journalctl -u crypto-gotham-relay -f`
- **macOS:** `tail -F /usr/local/var/gotham-relay/relay.log`
- **Windows:** `Get-ScheduledTask GothamRelay | Get-ScheduledTaskInfo`

## Uninstall

Removes the service, binary, config, firewall rule, and identity key.

- **Linux:** `curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay.sh | sudo bash`
- **macOS:** `curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay-macos.sh | sudo bash`
- **Windows:** `irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay.ps1 | iex`

Add `GOTHAM_KEEP_KEYS=1` (PowerShell `$env:GOTHAM_KEEP_KEYS='1'`) to keep the
relay's identity key for a later reinstall with the same public key.

---

## Honest status

This is a young network. The relay software is hardened (memory-safe Rust,
`forbid(unsafe)`, fuzzed parsers, CI-tested on Linux/macOS/Windows), but
**anonymity from mixing is only as strong as the number of independent relays
and operators.** Until the network is large and diverse, treat its guarantees
as best-effort, not absolute. There is no such thing as 100% anonymity — run a
relay to help, not to bet your life on it today.

## License

**AGPL-3.0-or-later** — see [`LICENSE`](LICENSE). Running a *modified* relay as
a network service obliges you to publish your modified source under the AGPL.
