// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 Lisan al-Gaib & ARRAKIS contributors.

//! `gotham-relay` — standalone Gotham mixnet relay daemon.
//!
//! v0.1 status: configuration + key management + relay loop scaffold.
//! Transport layer (QUIC + Noise XK) lands in P2.next — until then the
//! relay binary boots, exposes its public key, and stays idle.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crypto_gotham::directory::{DirectoryDoc, RelayDescriptor, RelayTier, SignedDirectory};
use crypto_gotham_relay::Relay;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(name = "gotham-relay", version, about = "Gotham mixnet relay")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Verbosity (set `RUST_LOG=info|debug|trace`).
    #[arg(long, env = "RUST_LOG", default_value = "info", global = true)]
    log: String,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh X25519 identity keypair and write it to `--key-file`.
    Keygen {
        /// Destination path. Aborts if file already exists.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Print the public key associated with `--key-file` (hex).
    Pubkey {
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Run the relay daemon.
    Run {
        /// Path to the X25519 identity secret key.
        #[arg(long)]
        key_file: PathBuf,

        /// UDP/QUIC listen port (will become the QUIC port in P2.next).
        #[arg(long, default_value_t = 443)]
        listen_port: u16,

        /// Interface to bind, as a numeric IP. Default `::` = all
        /// interfaces (dual-stack, reachable from other machines). Pin to a
        /// specific LAN/public IP to restrict the NIC. Hostnames are NOT
        /// resolved — the routing layer addresses relays by IP. The address
        /// you ADVERTISE in the signed directory must be reachable by peers
        /// (a public IP or port-forwarded NAT mapping), which may differ
        /// from the bind interface.
        #[arg(long, default_value = "::")]
        listen_host: String,

        /// Mean Poisson delay in microseconds.
        #[arg(long, default_value_t = 20_000)]
        delay_micros: u64,

        /// Max entries in the replay cache.
        #[arg(long, default_value_t = 1_000_000)]
        replay_size: usize,

        /// TTL of replay cache entries, seconds.
        #[arg(long, default_value_t = 300)]
        replay_ttl_secs: u64,

        /// Max inbound packets/sec before shedding (token bucket, burst =
        /// 2×). Protects CPU and connection from a flood. `0` = unlimited.
        /// Default 2000 pps (~4 MB/s) is far above any realistic per-relay
        /// load yet caps egregious abuse.
        #[arg(long, default_value_t = 2000.0)]
        max_pps: f64,

        /// Rolling 24 h wire-byte budget before shedding. The real guard
        /// for metered/capped links (mobile, Freebox data plans). `0` =
        /// unlimited (default). Example: `--max-bytes-per-day 5000000000`
        /// caps the relay at ~5 GB/day.
        #[arg(long, default_value_t = 0)]
        max_bytes_per_day: u64,

        /// Directory authority base URL (e.g. `https://dir.example.org`). When
        /// set, the relay auto-enrolls and heartbeats so the network forms
        /// itself — no manual directory editing. Requires `--advertise-addr`.
        #[arg(long)]
        authority_url: Option<String>,

        /// Public `ip:port` peers should reach this relay on (e.g.
        /// `203.0.113.7:443`). May differ from `--listen-host` under
        /// NAT/port-forward. Required when `--authority-url` is set.
        #[arg(long)]
        advertise_addr: Option<String>,

        /// Bearer token for the authority's `/enroll` (closed test). Also read
        /// from `GOTHAM_ENROLL_TOKEN`.
        #[arg(long, env = "GOTHAM_ENROLL_TOKEN")]
        enroll_token: Option<String>,

        /// Tier to advertise: `entry|mix|exit`. Default `mix` (a middle hop
        /// sees neither the client nor the recipient — safest for volunteers).
        #[arg(long, default_value = "mix")]
        tier: String,

        /// Optional ISO 3166-1 country code to publish (e.g. `FR`).
        #[arg(long)]
        country: Option<String>,

        /// Optional operator nickname to publish (transparency only).
        #[arg(long)]
        operator: Option<String>,

        /// Seconds between enrollment heartbeats.
        #[arg(long, default_value_t = 300)]
        heartbeat_secs: u64,
    },
    /// Sign a directory document (Ed25519) from a JSON list of relays.
    /// Used by `infra/scripts/sign-directory.sh` to produce a
    /// `gotham-bootstrap.json` that each Crypto app instance trusts.
    SignDirectory {
        /// Ed25519 signing key (X25519 secret key reinterpreted as
        /// Ed25519 seed). Generate with `keygen`.
        #[arg(long)]
        authority_key: PathBuf,
        /// Input JSON: a list of `{ node_id_hex, addr, capabilities }`
        /// objects (one per relay).
        #[arg(long)]
        relays: PathBuf,
        /// Output path for the signed directory JSON.
        #[arg(long)]
        output: PathBuf,
        /// How long the directory is valid (seconds). Default: 30 days.
        #[arg(long, default_value_t = 2_592_000)]
        valid_secs: u64,
    },
}

/// Build the relay's listen [`SocketAddr`] from a numeric host + port.
/// Accepts IPv4 or IPv6 literals; `::` binds all interfaces (dual-stack).
/// Hostnames are deliberately NOT resolved — the Sphinx routing record
/// addresses the next hop by raw IPv4 octets, so relays are pinned by IP.
fn parse_listen_addr(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let ip: IpAddr = host.trim().parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("--listen-host must be a numeric IP (v4/v6), got `{host}`"),
        )
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn init_logging(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .try_init();
}

fn read_key_file(path: &PathBuf) -> std::io::Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad hex: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "secret key file must be 64 hex chars (32 bytes)",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn write_key_file(path: &PathBuf, sk: &[u8; 32]) -> std::io::Result<()> {
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "key file already exists — refusing to overwrite",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // On Unix, lock the secret key to owner-only (0600) at creation time.
    // On Windows the file inherits the directory ACL — operators must keep
    // it on a non-shared profile (documented in RELAY-SETUP.md).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write;
    let hex = hex::encode(sk);
    f.write_all(hex.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log);

    match cli.cmd {
        Cmd::Keygen { key_file } => {
            let mut sk = [0u8; 32];
            OsRng.fill_bytes(&mut sk);
            // X25519 clamping.
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            write_key_file(&key_file, &sk)?;
            let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
            sk.zeroize();
            println!("public key: {}", hex::encode(pk));
            info!("wrote secret key to {}", key_file.display());
            Ok(())
        }

        Cmd::Pubkey { key_file } => {
            let sk = read_key_file(&key_file)?;
            let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
            // sk is plain [u8; 32] — drop will leave bytes on the stack. For
            // a one-shot CLI invocation this is acceptable.
            println!("{}", hex::encode(pk));
            Ok(())
        }

        Cmd::Run {
            key_file,
            listen_port,
            listen_host,
            delay_micros,
            replay_size,
            replay_ttl_secs,
            max_pps,
            max_bytes_per_day,
            authority_url,
            advertise_addr,
            enroll_token,
            tier,
            country,
            operator,
            heartbeat_secs,
        } => {
            let sk = read_key_file(&key_file)?;
            let relay = Relay::new(
                sk,
                replay_size,
                Duration::from_secs(replay_ttl_secs),
                delay_micros,
            )
            .with_rate_limit(max_pps, max_bytes_per_day);

            let pk_hex = hex::encode(relay.identity_public_key());

            // Auto-enrollment: if an authority URL is configured, announce
            // ourselves (and heartbeat) so the network self-forms. Never fatal.
            if let Some(url) = authority_url {
                let advertise = advertise_addr.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--advertise-addr is required with --authority-url",
                    )
                })?;
                // Reject an unreachable advertise address early (clear error).
                let _: SocketAddr = advertise.parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("--advertise-addr must be ip:port, got `{advertise}`"),
                    )
                })?;
                let tier = crypto_gotham_relay::enroll_client::parse_tier(&tier)
                    .map_err(std::io::Error::other)?;
                let cfg = crypto_gotham_relay::enroll_client::EnrollConfig {
                    authority_url: url,
                    advertise_addr: advertise,
                    kem_pubkey_hex: pk_hex.clone(),
                    tier,
                    token: enroll_token,
                    country,
                    operator,
                    heartbeat: Duration::from_secs(heartbeat_secs.max(1)),
                };
                info!("auto-enrollment enabled — announcing to directory authority");
                tokio::spawn(crypto_gotham_relay::enroll_client::run_enrollment_loop(cfg));
            }
            info!(
                listen_port,
                delay_micros,
                replay_size,
                replay_ttl_secs,
                max_pps,
                max_bytes_per_day,
                "gotham-relay starting"
            );
            info!("identity public key: {pk_hex}");

            let listen_addr = parse_listen_addr(&listen_host, listen_port)?;
            info!(%listen_addr, "binding QUIC listener");

            // Run the QUIC listener and the SIGINT watcher concurrently;
            // the first to complete shuts the process down.
            tokio::select! {
                res = crypto_gotham_relay::run_relay_listener(listen_addr, sk, relay, None) => {
                    if let Err(e) = res {
                        warn!(error = ?e, "listener exited with error");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("shutdown signal received");
                }
            }

            Ok(())
        }

        Cmd::SignDirectory {
            authority_key,
            relays,
            output,
            valid_secs,
        } => {
            // Read authority key — accepts either 64-hex or 32-byte raw.
            let auth_bytes = read_ed25519_seed(&authority_key)?;
            let signing_key = SigningKey::from_bytes(&auth_bytes);

            // Parse the relays JSON. Format matches what
            // `infra/scripts/sign-directory.sh` produces.
            let raw = std::fs::read_to_string(&relays)?;
            let entries: Vec<RelayJsonEntry> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("relays JSON: {e}"))
            })?;
            if entries.len() < 3 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "need at least 3 relays for a working mixnet",
                ));
            }

            // Map JSON entries → RelayDescriptor. Capability strings:
            //   "entry" | "mix" | "exit" | "all" (rotated across all 3 tiers).
            let mut descriptors = Vec::with_capacity(entries.len());
            for (i, e) in entries.iter().enumerate() {
                let tier = match e.capabilities.as_str() {
                    "entry" => RelayTier::Entry,
                    "mix" => RelayTier::Mix,
                    "exit" => RelayTier::Exit,
                    "all" | "" => match i % 3 {
                        0 => RelayTier::Entry,
                        1 => RelayTier::Mix,
                        _ => RelayTier::Exit,
                    },
                    other => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("unknown capability `{other}` — use entry|mix|exit|all"),
                        ))
                    }
                };
                descriptors.push(RelayDescriptor {
                    id_pubkey_hex: e.node_id_hex.clone(),
                    kem_pubkey_hex: e.node_id_hex.clone(),
                    addr: e.addr.clone(),
                    tier,
                    country: e.country.clone(),
                    asn: e.asn,
                    operator: e.operator.clone(),
                    uptime_pct: Some(100.0),
                });
            }

            let doc = DirectoryDoc::new(descriptors, Duration::from_secs(valid_secs))
                .map_err(|e| std::io::Error::other(format!("DirectoryDoc::new: {e:?}")))?;
            let signed = SignedDirectory::sign(doc, &signing_key)
                .map_err(|e| std::io::Error::other(format!("SignedDirectory::sign: {e:?}")))?;
            let json = signed
                .to_json_pretty()
                .map_err(|e| std::io::Error::other(format!("to_json_pretty: {e:?}")))?;
            std::fs::write(&output, json)?;
            info!(
                relays = entries.len(),
                valid_secs,
                "wrote signed directory to {}",
                output.display()
            );
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
struct RelayJsonEntry {
    node_id_hex: String,
    addr: String,
    #[serde(default)]
    capabilities: String,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    operator: Option<String>,
}

/// Read an Ed25519 seed from `path`. Accepts either a 32-byte raw file
/// or a 64-hex-char text file (with optional trailing newline).
fn read_ed25519_seed(path: &PathBuf) -> std::io::Result<[u8; 32]> {
    let raw = std::fs::read(path)?;
    let trimmed: Vec<u8> = if raw
        .iter()
        .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
    {
        let s = std::str::from_utf8(&raw)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8"))?
            .trim();
        hex::decode(s).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad hex: {e}"))
        })?
    } else {
        raw
    };
    if trimmed.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authority key must be 32 bytes (or 64 hex chars)",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&trimmed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_addr_accepts_v4_v6_and_all_interfaces() {
        let v4 = parse_listen_addr("203.0.113.7", 443).unwrap();
        assert_eq!(v4.to_string(), "203.0.113.7:443");

        // Default `::` = all interfaces (dual-stack), preserves prior bind.
        let any = parse_listen_addr("::", 5223).unwrap();
        assert!(any.ip().is_unspecified());
        assert_eq!(any.port(), 5223);

        let v6 = parse_listen_addr("2001:db8::1", 443).unwrap();
        assert_eq!(v6.port(), 443);
    }

    #[test]
    fn listen_addr_rejects_hostnames() {
        // The routing layer pins relays by IP — hostnames are not resolved.
        assert!(parse_listen_addr("relay.example.com", 443).is_err());
        assert!(parse_listen_addr("", 443).is_err());
    }
}
