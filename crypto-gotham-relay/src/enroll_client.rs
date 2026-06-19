// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 Lisan al-Gaib & ARRAKIS contributors.

//! Relay-side auto-enrollment client.
//!
//! When `--authority-url` is set, the relay POSTs a [`RelayEnrollment`] to the
//! directory authority on startup and re-POSTs it as a heartbeat on an
//! interval. This is what makes the network self-forming: the operator no
//! longer hand-edits a directory — the relay announces itself.
//!
//! Failures are never fatal: the relay keeps forwarding packets regardless of
//! whether the authority is reachable, and simply retries on the next tick.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypto_gotham::directory::RelayTier;
use crypto_gotham::enroll::RelayEnrollment;
use tracing::{info, warn};

/// Everything the enrollment loop needs.
#[derive(Debug, Clone)]
pub struct EnrollConfig {
    /// Base URL of the directory authority, e.g. `https://dir.example.org`.
    pub authority_url: String,
    /// The publicly reachable address peers should use, e.g. `203.0.113.7:443`.
    /// May differ from the bind interface (NAT / port-forward).
    pub advertise_addr: String,
    /// This relay's X25519 public key (hex) — its routing + KEM identity.
    pub kem_pubkey_hex: String,
    /// Tier the operator is willing to serve.
    pub tier: RelayTier,
    /// Optional bearer token issued by the operator for the closed test.
    pub token: Option<String>,
    /// Optional ISO country code.
    pub country: Option<String>,
    /// Optional operator nickname.
    pub operator: Option<String>,
    /// Interval between heartbeats.
    pub heartbeat: Duration,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

/// Run the enrollment loop forever: enroll now, then heartbeat every
/// `cfg.heartbeat`, bumping `seq` each round.
///
/// `seq` is seeded from the wall clock so that a relay which restarts always
/// presents a higher `seq` than its previous (not-yet-pruned) entry — the
/// authority rejects non-increasing `seq` as replay.
pub async fn run_enrollment_loop(cfg: EnrollConfig) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "enroll: cannot build HTTP client; auto-enroll disabled");
            return;
        }
    };
    let endpoint = format!("{}/enroll", cfg.authority_url.trim_end_matches('/'));
    let mut seq: u64 = now_unix();

    loop {
        let enrollment = RelayEnrollment::new(
            cfg.kem_pubkey_hex.clone(),
            cfg.advertise_addr.clone(),
            cfg.tier,
            cfg.country.clone(),
            cfg.operator.clone(),
            seq,
        );
        let mut req = client.post(&endpoint).json(&enrollment);
        if let Some(tok) = &cfg.token {
            req = req.bearer_auth(tok);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                info!(seq, "enrolled with directory authority");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(%status, body = %body, "enroll rejected by authority (will retry)");
            }
            Err(e) => {
                warn!(error = %e, "enroll request failed (will retry)");
            }
        }
        seq = seq.saturating_add(1);
        tokio::time::sleep(cfg.heartbeat).await;
    }
}

/// Parse a `--tier` string into a [`RelayTier`]. A single relay serves one
/// tier; `mix` (middle hop, sees neither client nor recipient) is the
/// privacy-safest default for volunteers.
pub fn parse_tier(s: &str) -> Result<RelayTier, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "entry" => Ok(RelayTier::Entry),
        "mix" | "" => Ok(RelayTier::Mix),
        "exit" => Ok(RelayTier::Exit),
        other => Err(format!("unknown tier `{other}` — use entry|mix|exit")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tier_maps_known_values() {
        assert_eq!(parse_tier("entry").unwrap(), RelayTier::Entry);
        assert_eq!(parse_tier("MIX").unwrap(), RelayTier::Mix);
        assert_eq!(parse_tier("").unwrap(), RelayTier::Mix);
        assert_eq!(parse_tier(" exit ").unwrap(), RelayTier::Exit);
        assert!(parse_tier("all").is_err());
    }
}
