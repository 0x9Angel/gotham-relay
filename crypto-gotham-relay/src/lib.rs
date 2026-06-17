// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 Lisan al-Gaib & ARRAKIS contributors.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in the crypto-gotham crate root.

//! # crypto-gotham-relay — public library
//!
//! Implements the *core relay logic* for a Gotham mixnet node:
//!
//! - [`ReplayCache`] — bounded LRU + 5-min TTL cache of `γ` MACs to drop replays
//! - [`PoissonScheduler`] — per-hop exponential-delay sampler (Loopix-style)
//! - [`Relay`] — combines an X25519 identity, a replay cache, and a scheduler
//!   to process incoming packets into [`ProcessOutcome`]s
//!
//! The transport layer (QUIC / TLS) is intentionally *not* in this library —
//! it lives in `main.rs` so that this crate can be reused by tests, fuzz
//! harnesses, and alternative transport implementations.

// Same lint policy as `crypto-gotham`: prod code panic-free, tests allowed
// to unwrap. A panic in `process()` or the QUIC accept loop takes the
// whole relay down — strictly enforced outside #[cfg(test)].
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![warn(missing_docs)]

pub mod client;
pub mod cover_loop;
pub mod delay;
pub mod pool;
pub mod process;
pub mod rate_limit;
pub mod replay;
pub mod transport;

pub use client::{ClientError, GothamClient, MAX_PAYLOAD_SIZE};
pub use cover_loop::{spawn_cover_loop, CoverLoopHandle, QueuedMessage};
pub use delay::PoissonScheduler;
pub use pool::ConnectionPool;
pub use process::{DropReason, ProcessOutcome, Relay};
pub use rate_limit::{RateDecision, RateLimiter, ThrottleReason};
pub use replay::{ReplayCache, ReplayCheck};
pub use transport::{
    make_unsealing_delivery_handler, run_relay_listener, serve_endpoint, DeliveryHandler,
    TransportError,
};

/// Install the rustls `ring` crypto provider as the process-wide
/// default. Idempotent — safe to call multiple times. Callers MUST run
/// this once before constructing any [`GothamClient`] or QUIC endpoint
/// because rustls 0.23 refuses to build a `ServerConfig` / `ClientConfig`
/// without a default provider.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
