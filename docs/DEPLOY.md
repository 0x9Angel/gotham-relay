# Gotham — Multi-Machine Relay Deployment (v0.1)

How to run a **real** Gotham mixnet across separate machines, instead of the
single-machine dev self-loop. This is the deployable counterpart to
`scripts/local-testnet.sh` (which runs 3 relays on `127.0.0.1`).

> **Status — code ready, real-network validation NOT done in this session.**
> The relay daemon, directory tooling, and app wiring below are implemented
> and unit-tested. End-to-end behaviour over a real network (NAT, packet
> loss, MTU, latency, multi-host clock skew) has **not** been exercised — it
> can only be validated on actual distributed hosts. See the checklist at the
> end. Nothing here is marked "done"; it is "implemented, to be validated".

---

## 1. Architecture

```
  App A ──send──>  [ ENTRY relay ]──>[ MIX relay ]──>[ EXIT relay ]──deliver──> App B
  (sender)          machine #1         machine #2       machine #3            (recipient)
                    public IP:port      public IP:port   public IP:port
```

- **Relays** are standalone `gotham-relay run` daemons, one per machine, each
  on its own routable IP. They forward sealed Sphinx packets hop-by-hop over
  QUIC + Noise XK and apply a per-hop mix delay.
- **The signed directory** (`directory.json`) pins the relay set: each relay's
  public key, address, and tier (`entry` / `mix` / `exit`). It is signed by an
  **authority** Ed25519 key. Apps verify it before routing.
- **Apps** load the directory, pick a 3-hop path (entry → mix → exit), and
  route. With `CRYPTO_GOTHAM_DEVMODE=0` they use this external directory
  instead of fabricating a self-loop (see SECURITY-AUDIT.md M-9).

Receiving (App B) requires the recipient's node to be the **exit** the path
terminates at — the "app = relay" model. App→app delivery wiring is tracked
separately (PARTIE A point 7); this guide covers the relay/transport layer.

---

## 2. Prerequisites

- Rust toolchain + this repo, buildable on each relay host (or copy the
  release binary `target/release/gotham-relay`).
- One machine per relay, each with a **reachable** address: a public IP, or a
  LAN IP, or a port-forwarded NAT mapping. Minimum 3 relays (≥1 entry, ≥1 exit).
- One **authority** Ed25519 key, generated once on a trusted machine:
  ```sh
  target/release/gotham-relay keygen --key-file infra/authority.ed25519
  ```

---

## 3. Step 1 — run each relay (on its own host)

On every relay machine:

```sh
# Entry host (203.0.113.1), binding all interfaces on 443:
PUBLIC_ADDR=203.0.113.1:443 scripts/deploy-relay.sh

# To pin a specific NIC / non-privileged port:
LISTEN_HOST=10.8.0.5 LISTEN_PORT=5223 PUBLIC_ADDR=203.0.113.1:5223 \
  KEY_FILE=/etc/gotham/relay.key scripts/deploy-relay.sh
```

The script generates the relay key once, then prints the **ADVERTISE LINE**:

```
ADVERTISE LINE : <pubkey_hex> 203.0.113.1:443 <entry|mix|exit>
```

Collect one advertise line from each host and assign it a tier.

> Port `443` is privileged: `sudo setcap 'cap_net_bind_service=+ep'
> target/release/gotham-relay`, or use a port ≥ 1024.

---

## 4. Step 2 — build + sign the directory (on the authority machine)

Put the collected lines in a file, one relay per line — `pubkey host:port tier`:

```
# infra/relays.txt
<pk1> 203.0.113.1:443 entry
<pk2> 198.51.100.2:443 mix
<pk3> 192.0.2.3:443  exit
```

Then:

```sh
AUTHORITY_KEY=infra/authority.ed25519 RELAYS=infra/relays.txt \
  OUT=infra/directory.json scripts/build-signed-directory.sh
```

This produces a signed `infra/directory.json` valid for 30 days (override with
`VALID_SECS`).

---

## 5. Step 3 — point each app at the directory

In each app's Gotham dir (next to its database, e.g.
`~/.local/share/com.crypto.messenger/gotham/`):

```sh
cp infra/directory.json        "$GOTHAM_DIR/directory.json"
cp infra/authority.ed25519     "$GOTHAM_DIR/authority.ed25519"   # see caveat 6.4
```

Launch the app with the dev self-loop **off** so it routes via the external
directory:

```sh
CRYPTO_GOTHAM_DEVMODE=0 <launch the app>
```

Verify in the app logs: `directory_relays = 3` pointing at your real IPs, and
**no** "dev-mode 3-relay self-loop is live".

---

## 6. Constraints & caveats (v0.1 — read before trusting it)

1. **IPv4-only routing.** The Sphinx routing record addresses the next hop by
   4 raw IPv4 octets (`next_ipv4`). Relay addresses in the directory **must be
   IPv4 `host:port`**. IPv6 relay addresses are not routable yet (the daemon
   can *bind* `::`, but cannot be named as a *next hop*).
2. **No hostname resolution.** Relays are pinned by IP, not DNS. `--listen-host`
   and directory addresses take numeric IPs only.
3. **Public reachability required.** A relay behind NAT must advertise a
   port-forwarded `public-ip:port` (set `PUBLIC_ADDR`). There is no hole
   punching. Bind interface (`LISTEN_HOST`) may differ from the advertised
   address.
4. **Authority key distribution (security gap).** v0.1's directory loader
   derives the authority *public* key from the `authority.ed25519` *secret
   seed* file, so apps currently need that file. **Distributing the signing
   secret to every app is unsafe** — any holder could forge a directory.
   Production must pin the authority **public** key only (offline signing on
   an HSM/YubiKey). Tracked in SECURITY-AUDIT.md (directory authority = SPOF).
5. **Directory validity window.** `valid_secs` is checked against each host's
   wall clock. Large clock skew across machines can reject a fresh directory —
   keep hosts NTP-synced.
6. **App embedded relay binds localhost by default.** The app's own receive
   relay binds `127.0.0.1` unless `gotham_bind_host` is set to a routable IP.
   Needed only for the "app = exit" model; normal senders don't need it.

---

## 7. Real-network validation checklist (to run on distributed hosts)

None of these are validated in-session — each needs real, separated machines:

- [ ] **Reachability**: entry relay accepts a QUIC connection from a sender on
      another network (not same host / same LAN).
- [ ] **End-to-end route**: a packet traverses entry → mix → exit across 3
      hosts; confirm in each relay's log (`RUST_LOG=debug`).
- [ ] **NAT**: a relay behind NAT, advertising a forwarded port, still
      forwards. Test both full-cone and symmetric NAT.
- [ ] **UDP loss / reordering**: introduce loss (`tc qdisc ... netem loss 5%`)
      and confirm QUIC recovers or the packet is cleanly dropped (no hang).
- [ ] **MTU / fragmentation**: 2048 B packets over paths with MTU < 1500
      (PPPoE, VPN). Confirm no silent black-holing; check QUIC PMTUD.
- [ ] **Latency**: measure added per-hop mix delay vs the configured Poisson
      mean under real RTT; confirm delivery within app timeouts.
- [ ] **Clock skew**: skew one host's clock and confirm directory
      `valid_after`/`valid_until` behave as intended.
- [ ] **Relay failover**: kill the mix relay mid-session; confirm the sender
      fails cleanly and recovers when a new directory is published.
- [ ] **Anti-correlation (research-grade)**: the property the mix delays exist
      for — unlinkability of entry-ingress vs exit-egress timing — needs a
      traffic-analysis harness over many flows. **Distribution is unit-tested;
      anti-correlation is NOT proven here.**

---

*Generated as part of PARTIE A point 9 (multi-machine relay support). Code +
tooling implemented and unit-tested; network behaviour to be validated
out-of-session per the checklist above.*
