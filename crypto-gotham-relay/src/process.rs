// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 Lisan al-Gaib & ARRAKIS contributors.

//! Stateless packet processor.
//!
//! [`Relay::process`] takes a 2048 B packet and returns one of:
//!
//! - [`ProcessOutcome::Drop`] — silently discard (replay, bad MAC, malformed)
//! - [`ProcessOutcome::Forward`] — forward to the next hop after a Poisson delay
//! - [`ProcessOutcome::DeliverLocal`] — this hop is the recipient
//!
//! No I/O is performed here — the caller (the transport layer in
//! `main.rs`) is responsible for actually sending the bytes. This keeps
//! the relay testable without spinning up sockets.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crypto_gotham::header::{derive_hop_subkeys, unwrap_header, Header, HEADER_LEN, RECORD_LEN};
use crypto_gotham::Error as GothamError;
use rand::{CryptoRng, RngCore};
use tracing::{debug, trace};
use x25519_dalek::{x25519, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::delay::PoissonScheduler;
use crate::rate_limit::RateLimiter;
use crate::replay::{ReplayCache, ReplayCheck};

/// Reason a packet was dropped. Used for *counter* metrics only — the
/// relay never logs per-packet identifiers or peer IPs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// Header MAC failed verification.
    BadMac,
    /// Packet's γ was already seen within the TTL window.
    Replay,
    /// Header could not be parsed (version, hop_count, etc).
    Malformed,
    /// Policy denied the route (e.g. self-loop, unknown next hop).
    PolicyDenied,
    /// Operator-configured rate limit (packets/sec or daily byte quota)
    /// was exceeded — the packet is shed to protect the volunteer's
    /// machine and connection.
    RateLimited,
}

/// Outcome of processing a single packet.
pub enum ProcessOutcome {
    /// Silently drop the packet.
    Drop(DropReason),
    /// Forward to the next hop after `delay`.
    Forward {
        /// Destination socket of the next hop.
        next_addr: SocketAddrV4,
        /// Identity fingerprint (X25519 pubkey) of the next hop.
        next_node_id: [u8; 32],
        /// Poisson-sampled hold time before transmission.
        delay: Duration,
        /// The full 2048 B packet to forward.
        packet: Box<[u8]>,
    },
    /// Local delivery — this hop is the final recipient.
    DeliverLocal {
        /// Poisson-sampled hold time before processing.
        delay: Duration,
        /// The packet's payload (header stripped).
        payload: Box<[u8]>,
    },
}

impl ProcessOutcome {
    /// Convenience: did the packet get dropped?
    #[must_use]
    pub fn is_drop(&self) -> bool {
        matches!(self, ProcessOutcome::Drop(_))
    }
}

/// A Gotham relay's runtime state.
///
/// Holds:
/// - the relay's long-term X25519 identity secret key
/// - the replay cache
/// - the Poisson delay scheduler
///
/// `&mut self` is required for `process` because the replay cache is
/// updated on every fresh packet.
#[derive(ZeroizeOnDrop)]
pub struct Relay {
    #[zeroize(skip)]
    replay_cache: ReplayCache,
    #[zeroize(skip)]
    scheduler: PoissonScheduler,
    #[zeroize(skip)]
    rate_limiter: RateLimiter,
    identity_sk: [u8; 32],
}

impl Relay {
    /// Construct a relay from an existing X25519 secret key.
    ///
    /// `mean_delay_micros = 0` disables the Poisson scheduler (useful in
    /// tests and benchmarks).
    #[must_use]
    pub fn new(
        identity_sk: [u8; 32],
        replay_max_size: usize,
        replay_ttl: Duration,
        mean_delay_micros: u64,
    ) -> Self {
        Self {
            identity_sk,
            replay_cache: ReplayCache::new(replay_max_size, replay_ttl),
            scheduler: PoissonScheduler::new(mean_delay_micros),
            rate_limiter: RateLimiter::unlimited(),
        }
    }

    /// Attach an inbound rate limiter (packets/sec ceiling + rolling daily
    /// wire-byte quota). Either bound may be `0` to disable it; the default
    /// from [`Relay::new`] is fully unlimited. Returns `self` for chaining.
    ///
    /// This is how a volunteer caps the load a relay can place on their
    /// machine and connection — see `RELAY-SETUP.md`.
    #[must_use]
    pub fn with_rate_limit(mut self, max_pps: f64, max_bytes_per_day: u64) -> Self {
        self.rate_limiter = RateLimiter::new(max_pps, max_bytes_per_day);
        self
    }

    /// Read-only access to the configured scheduler.
    #[must_use]
    pub fn scheduler(&self) -> &PoissonScheduler {
        &self.scheduler
    }

    /// Current size of the replay cache (for metrics).
    #[must_use]
    pub fn replay_cache_len(&self) -> usize {
        self.replay_cache.len()
    }

    /// Derive the X25519 public key matching this relay's identity.
    #[must_use]
    pub fn identity_public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&StaticSecret::from(self.identity_sk)).to_bytes()
    }

    /// Process one inbound packet.
    ///
    /// `packet_bytes.len()` must equal [`crypto_gotham::PACKET_SIZE`] (2048).
    pub fn process<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        packet_bytes: &[u8],
    ) -> ProcessOutcome {
        if packet_bytes.len() != crypto_gotham::PACKET_SIZE {
            return ProcessOutcome::Drop(DropReason::Malformed);
        }

        // ── 0. Rate limit (cheapest possible flood shedding) ──────────────
        // Checked before any X25519/Sphinx work so a flood costs the
        // operator only a token-bucket comparison, never crypto CPU.
        if !self.rate_limiter.check(packet_bytes.len()).is_allowed() {
            debug!("dropped: rate limited");
            return ProcessOutcome::Drop(DropReason::RateLimited);
        }

        // ── 1. Parse header ───────────────────────────────────────────────
        let header_arr: &[u8; HEADER_LEN] = match packet_bytes[..HEADER_LEN].try_into() {
            Ok(a) => a,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };
        let header = match Header::decode(header_arr) {
            Ok(h) => h,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };

        // ── 2. Derive per-hop sub-keys (X25519 DH) ────────────────────────
        let shared = x25519(self.identity_sk, header.alpha);
        let sub_keys = match derive_hop_subkeys(&shared) {
            Ok(s) => s,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };

        // ── 3. Replay check using γ as the unique tag ─────────────────────
        if self.replay_cache.check_and_insert(header.gamma) == ReplayCheck::Replay {
            debug!("dropped: replay");
            return ProcessOutcome::Drop(DropReason::Replay);
        }

        // ── 4. Unwrap (verifies MAC + decrypts this hop's slot) ───────────
        let outcome = match unwrap_header(&header, &sub_keys) {
            Ok(o) => o,
            Err(GothamError::BadMac) => {
                debug!("dropped: bad MAC");
                return ProcessOutcome::Drop(DropReason::BadMac);
            }
            Err(_) => {
                debug!("dropped: malformed");
                return ProcessOutcome::Drop(DropReason::Malformed);
            }
        };

        // ── 5. Mix delay ──────────────────────────────────────────────────
        // Honor the sender-chosen per-hop delay (Loopix sender-chosen delays:
        // the sender samples each hold from Exp(λ) and encodes it). A `0`
        // record leaves it unset — fall back to this relay's own Poisson
        // scheduler (cover traffic, or legacy/0-mean senders).
        let delay = match outcome.record.delay_micros {
            0 => self.scheduler.next_delay(rng),
            micros => Duration::from_micros(u64::from(micros)),
        };

        // ── 6. Forward vs deliver decision ────────────────────────────────
        if outcome.record.is_last_hop() {
            trace!(?delay, "deliver-local");
            let payload = packet_bytes[HEADER_LEN..].to_vec().into_boxed_slice();
            return ProcessOutcome::DeliverLocal { delay, payload };
        }

        // Construct the outgoing packet: new header || payload-as-is.
        //
        // **v0.1 caveat:** the payload AEAD-layer peeling is NOT yet
        // implemented at the per-hop level (the end-to-end Double Ratchet
        // handles content confidentiality between Alice and Bob). A
        // future v0.2 will add per-hop payload onion encryption with
        // `k_payload`; for now hops simply forward payload bytes
        // verbatim. This is safe (content remains E2E-encrypted) but
        // does mean a hop could distinguish packets by payload content
        // (limited threat — payload is already ciphertext).
        let next_header_bytes = outcome.next_header.encode();
        let mut next_packet = vec![0u8; crypto_gotham::PACKET_SIZE].into_boxed_slice();
        next_packet[..HEADER_LEN].copy_from_slice(&next_header_bytes);
        next_packet[HEADER_LEN..].copy_from_slice(&packet_bytes[HEADER_LEN..]);

        let next_addr = SocketAddrV4::new(
            Ipv4Addr::from(outcome.record.next_ipv4),
            outcome.record.next_port,
        );

        // Sanity policy: refuse self-loops.
        let our_pk = self.identity_public_key();
        if outcome.record.next_node_id == our_pk {
            debug!("dropped: self-loop");
            return ProcessOutcome::Drop(DropReason::PolicyDenied);
        }

        // Anonymity hard-rule: never log routing fields (next port/addr).
        trace!(?delay, "forward");
        let _ = RECORD_LEN; // silence unused-import warning when not in test
        ProcessOutcome::Forward {
            next_addr,
            next_node_id: outcome.record.next_node_id,
            delay,
            packet: next_packet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::header::{
        derive_route_secrets, flag, mode, wrap_header, RoutingRecord, TRAILER_LEN,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xFEED_FACE)
    }

    /// Build a Gotham packet through `n` relays.
    fn build_packet_for_relays(
        rng: &mut ChaCha20Rng,
        relay_sks: &[[u8; 32]],
    ) -> (Vec<u8>, Vec<[u8; 32]>) {
        let pks: Vec<[u8; 32]> = relay_sks
            .iter()
            .map(|sk| PublicKey::from(&StaticSecret::from(*sk)).to_bytes())
            .collect();
        let (alphas, sub_keys) = derive_route_secrets(rng, &pks).unwrap();
        let n = relay_sks.len();
        let records: Vec<RoutingRecord> = (0..n)
            .map(|i| RoutingRecord {
                next_ipv4: [10, 0, 0, i as u8 + 1],
                next_port: 9000 + i as u16,
                next_node_id: if i + 1 < n {
                    PublicKey::from(&StaticSecret::from(relay_sks[i + 1])).to_bytes()
                } else {
                    [0xEE; 32] // last hop has dummy next_node_id
                },
                next_gamma: [0; 16],
                delay_micros: 0,
                flag: if i + 1 == n { flag::IS_LAST_HOP } else { 0 },
                _padding: [0; 5],
            })
            .collect();
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header =
            wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer).unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        // Fill payload with some bytes (would normally be sealed-sender + AEAD).
        for (i, byte) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        (packet, pks)
    }

    #[test]
    fn forwards_a_packet_through_three_hops() {
        let mut rng = rng();
        // Three relays.
        let sks: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
        let (mut packet, _pks) = build_packet_for_relays(&mut rng, &sks);

        // Hop 0
        let mut relay0 = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let r0 = relay0.process(&mut rng, &packet);
        let next0 = match r0 {
            ProcessOutcome::Forward { packet, .. } => packet,
            other => panic!("hop 0: expected Forward, got {:?}", outcome_kind(&other)),
        };
        packet = next0.into_vec();

        // Hop 1
        let mut relay1 = Relay::new(sks[1], 1000, Duration::from_secs(60), 0);
        let r1 = relay1.process(&mut rng, &packet);
        let next1 = match r1 {
            ProcessOutcome::Forward { packet, .. } => packet,
            other => panic!("hop 1: expected Forward, got {:?}", outcome_kind(&other)),
        };
        packet = next1.into_vec();

        // Hop 2 (last)
        let mut relay2 = Relay::new(sks[2], 1000, Duration::from_secs(60), 0);
        let r2 = relay2.process(&mut rng, &packet);
        match r2 {
            ProcessOutcome::DeliverLocal { payload, .. } => {
                assert_eq!(payload.len(), crypto_gotham::PACKET_SIZE - HEADER_LEN);
            }
            other => panic!(
                "hop 2: expected DeliverLocal, got {:?}",
                outcome_kind(&other)
            ),
        }
    }

    #[test]
    fn replayed_packet_is_dropped() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);

        let mut relay = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let r1 = relay.process(&mut rng, &packet);
        assert!(!r1.is_drop(), "first delivery should succeed");

        let r2 = relay.process(&mut rng, &packet);
        assert!(matches!(r2, ProcessOutcome::Drop(DropReason::Replay)));
    }

    #[test]
    fn malformed_size_dropped() {
        let mut rng = rng();
        let mut relay = Relay::new([7u8; 32], 100, Duration::from_secs(60), 0);
        let short = vec![0u8; 1024];
        assert!(matches!(
            relay.process(&mut rng, &short),
            ProcessOutcome::Drop(DropReason::Malformed)
        ));
    }

    #[test]
    fn tampered_mac_dropped() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (mut packet, _) = build_packet_for_relays(&mut rng, &sks);
        // Flip a bit inside γ (offset 356..372 of header).
        packet[360] ^= 0x02;
        let mut relay = Relay::new(sks[0], 100, Duration::from_secs(60), 0);
        assert!(matches!(
            relay.process(&mut rng, &packet),
            ProcessOutcome::Drop(DropReason::BadMac)
        ));
    }

    #[test]
    fn replay_cache_len_observable() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let mut relay = Relay::new(sks[0], 100, Duration::from_secs(60), 0);
        assert_eq!(relay.replay_cache_len(), 0);
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);
        let _ = relay.process(&mut rng, &packet);
        assert_eq!(relay.replay_cache_len(), 1);
    }

    #[test]
    fn rate_limit_sheds_a_flood_before_crypto() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);

        // Tight cap: 5 pps ⇒ burst 10. A 200-packet flood fired in a tight
        // loop (wall clock barely advances → negligible refill) must shed
        // the overflow as RateLimited.
        let mut relay =
            Relay::new(sks[0], 100_000, Duration::from_secs(60), 0).with_rate_limit(5.0, 0);
        let mut rate_limited = 0usize;
        for _ in 0..200 {
            if matches!(
                relay.process(&mut rng, &packet),
                ProcessOutcome::Drop(DropReason::RateLimited)
            ) {
                rate_limited += 1;
            }
        }
        assert!(
            rate_limited > 150,
            "expected the bulk of a 200-packet flood to be rate-limited, got {rate_limited}"
        );
    }

    #[test]
    fn unlimited_relay_never_rate_limits() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);
        // Default relay (no with_rate_limit) must behave exactly as before.
        let mut relay = Relay::new(sks[0], 100_000, Duration::from_secs(60), 0);
        for _ in 0..500 {
            assert!(!matches!(
                relay.process(&mut rng, &packet),
                ProcessOutcome::Drop(DropReason::RateLimited)
            ));
        }
    }

    fn outcome_kind(o: &ProcessOutcome) -> &'static str {
        match o {
            ProcessOutcome::Drop(_) => "Drop",
            ProcessOutcome::Forward { .. } => "Forward",
            ProcessOutcome::DeliverLocal { .. } => "DeliverLocal",
        }
    }
}
