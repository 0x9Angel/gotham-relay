// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 Lisan al-Gaib & ARRAKIS contributors.

//! QUIC transport with per-link Noise XK encryption.
//!
//! ## Stack
//!
//! ```text
//!   Gotham packet (2048 B fixed)
//!     │
//!     ▼
//!   Noise XK (snow) — per-link symmetric ChaCha20-Poly1305
//!     │  + 16 B AEAD tag  →  2064 B on the wire
//!     ▼
//!   QUIC bi-stream over TLS 1.3 (rustls)
//!     │  TLS cert is self-signed; Noise XK provides the real authentication
//!     │  so we use a custom rustls verifier that accepts any cert.
//!     ▼
//!   UDP (default port 443)
//! ```
//!
//! ## Why two crypto layers?
//!
//! - **QUIC + TLS 1.3** gives us reliable streams, 0-RTT resumption,
//!   modern congestion control, NAT traversal, and packets that look
//!   identical to vanilla HTTPS on the wire (DPI-resistance for free).
//! - **Noise XK on top** pins the relay's long-term X25519 identity (the
//!   same key advertised in the directory) and prevents TLS-cert-MITM
//!   attacks. The client is anonymous to the relay (XK pattern: client
//!   not authenticated at the Noise layer; identity proven at the
//!   Gotham-packet layer instead).
//!
//! ## v0.1 status
//!
//! - One inbound bi-stream per connection (multiplexing left to v0.2)
//! - One outbound connection per forwarded packet (pooling left to v0.2)
//! - Cert verification skipped on client side (Noise XK provides auth)
//! - Fixed packet size 2048 + 16 B tag = 2064 B per Noise frame
//!
//! Mutable relay state is shared between connection-handler tasks via an
//! `Arc<Mutex<Relay>>`. Mutex contention is fine for the v0.1 single-relay
//! workload; v0.2 can shard the replay cache + scheduler if needed.

use std::net::SocketAddr;
use std::sync::Arc;

use crypto_gotham::PACKET_SIZE;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use snow::TransportState;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::pool::ConnectionPool;
use crate::process::{ProcessOutcome, Relay};

/// Callback invoked on `ProcessOutcome::DeliverLocal` — i.e. when a
/// Gotham packet reaches its final destination at this relay.
///
/// The handler receives the raw payload bytes (everything after the
/// 384 B header). For payloads wrapped in a sealed-sender envelope,
/// use [`make_unsealing_delivery_handler`] to compose with an
/// `unseal` step that yields `(sender_pk, body)`.
///
/// Implementations must be cheap to clone (the wrapped `Arc` makes
/// this O(1)) and safe to call from any tokio worker.
pub type DeliveryHandler = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Build a [`DeliveryHandler`] that automatically unseals incoming
/// payloads before dispatching them. The wrapped `inner` callback
/// receives `(sender_pk, body)` for valid envelopes; envelopes that
/// fail to unseal (wrong recipient, tampered, malformed) are dropped
/// silently — the relay never logs the failure with packet content.
///
/// **Wire format**: expects `GothamClient::send_sealed` framing — a
/// 4 B big-endian length prefix followed by the variable-length sealed
/// envelope, then zero-padding up to the 1664 B Gotham payload region.
pub fn make_unsealing_delivery_handler<F>(recipient_sk: [u8; 32], inner: F) -> DeliveryHandler
where
    F: Fn([u8; 32], Vec<u8>) + Send + Sync + 'static,
{
    Arc::new(move |payload: Vec<u8>| {
        // 1. Parse 4 B length prefix.
        if payload.len() < 4 {
            debug!("framed payload shorter than length prefix");
            return;
        }
        // The slice is exactly 4 B (we just checked `payload.len() >= 4`),
        // so `try_into` cannot fail here — but we avoid `.expect()` to
        // honour the crate-wide `deny(clippy::expect_used)` and to keep
        // the type-system honesty even when the policy lint is lifted.
        let len_bytes: [u8; 4] = match payload[..4].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let env_len = u32::from_be_bytes(len_bytes) as usize;
        if 4 + env_len > payload.len() {
            debug!("framed envelope length exceeds payload region");
            return;
        }
        let envelope = &payload[4..4 + env_len];

        // 2. Unseal (also validates the AEAD tag).
        match crypto_gotham::sealed::unseal(&recipient_sk, envelope) {
            Ok((sender_pk, body)) => inner(sender_pk, body),
            Err(_) => {
                debug!("sealed-sender unseal failed — dropping");
            }
        }
    })
}

const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";
const NOISE_TAG_LEN: usize = 16;

/// Wire size of one Noise-encapsulated Gotham packet.
pub const FRAME_LEN: usize = PACKET_SIZE + NOISE_TAG_LEN;

/// Max size of a Noise handshake message we'll accept.
const MAX_HANDSHAKE_MSG: usize = 1024;

/// Errors that can arise in the transport layer. We collapse the various
/// quinn/snow/rustls errors into a single category because production
/// callers never need to distinguish them — they either succeed or drop
/// the connection.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Underlying I/O failure (socket bind, read, write).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// QUIC connection-establishment failure.
    #[error("quic connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// QUIC connection-level error (peer reset, idle timeout, etc.).
    #[error("quic connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// QUIC stream write error.
    #[error("quic write: {0}")]
    Write(#[from] quinn::WriteError),
    /// QUIC stream read error (EOF before required byte count).
    #[error("quic read: {0}")]
    Read(#[from] quinn::ReadExactError),
    /// rustls TLS error.
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    /// Self-signed cert generation failure (rcgen).
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// Noise XK handshake / transport-state error.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    /// Caller-supplied data violated a Gotham protocol invariant
    /// (over-length handshake msg, bad packet size, …).
    #[error("malformed handshake message")]
    BadHandshake,
}

// ─── Self-signed TLS cert (Noise XK provides real auth) ─────────────────────

/// Generate a fresh self-signed certificate for the QUIC TLS layer.
///
/// The Subject Alternative Name is irrelevant — the client-side verifier
/// (see [`SkipServerVerification`]) accepts any cert. Real peer
/// authentication happens at the Noise XK layer where the static
/// X25519 key is pinned against the directory entry.
pub fn make_self_signed_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec!["gotham-relay.local".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    Ok((cert_der, key_der))
}

// ─── Client-side: skip cert verification ────────────────────────────────────

/// A `rustls::ServerCertVerifier` that accepts any certificate.
///
/// **This is intentional.** The Gotham model relies on Noise XK at the
/// next layer for peer authentication; TLS at the QUIC level only
/// provides transport encryption + DPI resistance. Skipping verification
/// here removes the requirement for a PKI hierarchy among relays.
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ─── QUIC endpoint construction ─────────────────────────────────────────────

/// Build a QUIC server endpoint bound to `addr` with a self-signed cert.
pub fn build_server_endpoint(addr: SocketAddr) -> Result<Endpoint, TransportError> {
    let (cert, key) = make_self_signed_cert()?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![b"gotham/1".to_vec()];
    let quic_server_config =
        QuicServerConfig::try_from(server_crypto).map_err(|_| TransportError::BadHandshake)?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

/// Build a QUIC client endpoint. Uses 0.0.0.0:0 by default (ephemeral
/// source port). Cert verification is skipped — Noise XK does the auth.
pub fn build_client_endpoint() -> Result<Endpoint, TransportError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"gotham/1".to_vec()];
    let quic_client_config =
        QuicClientConfig::try_from(client_crypto).map_err(|_| TransportError::BadHandshake)?;
    let client_config = ClientConfig::new(Arc::new(quic_client_config));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().map_err(|_| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "bad client bind addr",
        ))
    })?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// ─── Length-prefixed handshake I/O ──────────────────────────────────────────

async fn write_handshake_msg(send: &mut SendStream, msg: &[u8]) -> Result<(), TransportError> {
    if msg.len() > MAX_HANDSHAKE_MSG {
        return Err(TransportError::BadHandshake);
    }
    let len = msg.len() as u16;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(msg).await?;
    Ok(())
}

async fn read_handshake_msg(
    recv: &mut RecvStream,
    buf: &mut [u8; MAX_HANDSHAKE_MSG],
) -> Result<usize, TransportError> {
    let mut len_bytes = [0u8; 2];
    recv.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len > MAX_HANDSHAKE_MSG {
        return Err(TransportError::BadHandshake);
    }
    recv.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

// ─── Noise XK handshake (responder = server, initiator = client) ────────────

/// Run the responder side of a Noise XK handshake over the supplied
/// stream pair, using `static_sk` as the responder's static private key.
///
/// On success, returns the symmetric transport state used for subsequent
/// frame encryption/decryption.
pub async fn noise_responder_handshake(
    static_sk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<TransportState, TransportError> {
    let params = NOISE_PARAMS.parse()?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(static_sk)
        .build_responder()?;

    let mut rx = [0u8; MAX_HANDSHAKE_MSG];
    let mut tx = [0u8; MAX_HANDSHAKE_MSG];
    let mut scratch = [0u8; MAX_HANDSHAKE_MSG];

    // XK pattern: <- e, es | -> e, ee | <- s, se
    // (Responder reads first message, writes second, reads third.)

    // 1. Read client's first message
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    // 2. Write our response
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    // 3. Read client's static-key message
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let transport = hs.into_transport_mode()?;
    Ok(transport)
}

/// Run the initiator side of a Noise XK handshake. `server_static_pk` is
/// the responder's pinned public key (obtained from the directory).
pub async fn noise_initiator_handshake(
    initiator_sk: &[u8; 32],
    server_static_pk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<TransportState, TransportError> {
    let params = NOISE_PARAMS.parse()?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(initiator_sk)
        .remote_public_key(server_static_pk)
        .build_initiator()?;

    let mut tx = [0u8; MAX_HANDSHAKE_MSG];
    let mut rx = [0u8; MAX_HANDSHAKE_MSG];
    let mut scratch = [0u8; MAX_HANDSHAKE_MSG];

    // 1. Send first XK message
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    // 2. Read server response
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    // 3. Send static-key message
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let transport = hs.into_transport_mode()?;
    Ok(transport)
}

// ─── Noise-encrypted Gotham frame I/O ───────────────────────────────────────

/// Encrypt one Gotham packet and write the resulting `FRAME_LEN` bytes
/// to the stream.
pub async fn write_noise_frame(
    transport: &mut TransportState,
    send: &mut SendStream,
    packet: &[u8],
) -> Result<(), TransportError> {
    if packet.len() != PACKET_SIZE {
        return Err(TransportError::BadHandshake);
    }
    let mut frame = vec![0u8; FRAME_LEN];
    let n = transport.write_message(packet, &mut frame)?;
    debug_assert_eq!(n, FRAME_LEN);
    send.write_all(&frame).await?;
    Ok(())
}

/// Read one Noise-encrypted Gotham frame from the stream and return the
/// `PACKET_SIZE`-byte plaintext packet.
pub async fn read_noise_frame(
    transport: &mut TransportState,
    recv: &mut RecvStream,
) -> Result<Vec<u8>, TransportError> {
    let mut frame = vec![0u8; FRAME_LEN];
    recv.read_exact(&mut frame).await?;
    let mut packet = vec![0u8; PACKET_SIZE];
    let n = transport.read_message(&frame, &mut packet)?;
    debug_assert_eq!(n, PACKET_SIZE);
    Ok(packet)
}

// ─── Server: serve one incoming connection ──────────────────────────────────

/// Handle one inbound QUIC connection: complete the Noise handshake then
/// process each frame the client sends, dispatching the resulting
/// [`ProcessOutcome`] (drop / forward / deliver-local).
///
/// Forwarding goes through the shared [`ConnectionPool`] — repeated
/// hops to the same next-hop reuse a single QUIC + Noise XK
/// connection, amortising the per-packet handshake cost.
///
/// `delivery` is invoked for every `DeliverLocal` outcome; pass `None`
/// to discard local-delivery packets (useful for pure-relay nodes that
/// never act as recipients).
pub async fn serve_connection(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    relay: Arc<Mutex<Relay>>,
    pool: Arc<ConnectionPool>,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut noise = noise_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    debug!("noise handshake completed for inbound conn");

    loop {
        let packet = match read_noise_frame(&mut noise, &mut recv).await {
            Ok(p) => p,
            Err(TransportError::Read(_)) | Err(TransportError::Io(_)) => break,
            Err(e) => return Err(e),
        };

        // Process under the lock — held only for the time of one
        // `relay.process()` call (≪ 1 ms typical).
        let outcome = {
            let mut r = relay.lock().await;
            // Each call needs a fresh RNG seed for the Poisson sample. We
            // use thread_rng so concurrent connections don't share state.
            let mut rng = rand::thread_rng();
            r.process(&mut rng, &packet)
        };

        match outcome {
            ProcessOutcome::Drop(reason) => {
                debug!(?reason, "dropped");
            }
            ProcessOutcome::DeliverLocal { delay, payload } => {
                tokio::time::sleep(delay).await;
                debug!(payload_len = payload.len(), "delivered locally");
                if let Some(handler) = &delivery {
                    // Handler runs synchronously on the same tokio worker —
                    // it should be a quick `send` to an mpsc channel or
                    // Tauri event emission, NOT a blocking call.
                    handler(payload.into_vec());
                }
                // v0.2 will perform the Sealed-Sender unwrap + Double-
                // Ratchet decrypt here, then hand the plaintext to the
                // handler instead of the raw onion'd payload.
            }
            ProcessOutcome::Forward {
                next_addr,
                next_node_id,
                delay,
                packet,
            } => {
                debug!(?next_addr, "forward outcome");
                let pool = Arc::clone(&pool);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    match pool
                        .send(std::net::SocketAddr::V4(next_addr), next_node_id, &packet)
                        .await
                    {
                        Ok(()) => debug!(?next_addr, "forward via pool ok"),
                        Err(e) => warn!(error = ?e, ?next_addr, "forward via pool failed"),
                    }
                });
            }
        }
    }

    Ok(())
}

/// Open a fresh QUIC connection to `addr`, complete a Noise XK handshake
/// against the peer's pinned `peer_pk`, send the packet, and close.
///
/// v0.1 opens one connection per forwarded packet — costly but correct.
/// v0.2 will introduce a connection pool keyed by `(addr, peer_pk)`.
pub async fn forward_packet(
    endpoint: &Endpoint,
    addr: SocketAddr,
    peer_pk: &[u8; 32],
    my_sk: &[u8; 32],
    packet: &[u8],
) -> Result<(), TransportError> {
    let conn = endpoint
        .connect(addr, "gotham-relay.local")
        .map_err(TransportError::Connect)?
        .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut noise = noise_initiator_handshake(my_sk, peer_pk, &mut send, &mut recv).await?;
    write_noise_frame(&mut noise, &mut send, packet).await?;
    send.finish().ok();
    // Wait for the peer to acknowledge all stream data before letting
    // `conn` drop. Without this, dropping the Connection right after
    // write_all+finish races the CONNECTION_CLOSE frame against the
    // in-flight stream bytes and the peer may never see them.
    let _ = send.stopped().await;
    Ok(())
}

// ─── Public listener entrypoint ─────────────────────────────────────────────

/// Bind a QUIC server endpoint on `listen_addr`, then accept connections
/// forever, dispatching each to [`serve_connection`].
///
/// `delivery` is plumbed through to every `serve_connection` call —
/// pass `Some(handler)` to receive local-delivery payloads (typical
/// for hybrid relay+client nodes), or `None` for pure relays.
///
/// Returns only on fatal endpoint error (e.g. socket close).
pub async fn run_relay_listener(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server = build_server_endpoint(listen_addr)?;
    serve_endpoint(server, static_sk, relay, delivery).await
}

/// Run the accept loop against an already-built server `endpoint`. Use
/// this when the caller needs to learn the bound address (e.g. with
/// `listen_addr.port() == 0`) *before* spawning the listener as a
/// background task — `build_server_endpoint` + `endpoint.local_addr()` +
/// `serve_endpoint` avoids the rebind race that a port-0 retry would
/// otherwise introduce.
pub async fn serve_endpoint(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = build_client_endpoint()?;
    let relay = Arc::new(Mutex::new(relay));
    let pool = Arc::new(ConnectionPool::new(client, static_sk));
    let bound = endpoint.local_addr().ok();
    info!(
        ?bound,
        "gotham-relay QUIC listener accepting (pooled forwards)"
    );

    while let Some(connecting) = endpoint.accept().await {
        let relay = Arc::clone(&relay);
        let pool = Arc::clone(&pool);
        let sk = static_sk;
        let delivery = delivery.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(e) = serve_connection(conn, sk, relay, pool, delivery).await {
                        debug!(error = ?e, "connection ended");
                    }
                }
                Err(e) => debug!(error = ?e, "incoming connection failed"),
            }
        });
    }
    Ok(())
}

// ─── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::header::{
        derive_route_secrets, flag, mode, wrap_header, RoutingRecord, HEADER_LEN, TRAILER_LEN,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::net::SocketAddrV4;
    use std::sync::Once;
    use x25519_dalek::{PublicKey, StaticSecret};

    static CRYPTO_PROVIDER: Once = Once::new();
    fn init_crypto_provider() {
        CRYPTO_PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xBADC0FFEE)
    }

    /// Build a 2-hop Gotham packet whose last hop is `last_relay_sk`.
    fn build_2hop_packet(
        rng: &mut ChaCha20Rng,
        relay1_sk: [u8; 32],
        relay2_sk: [u8; 32],
        relay2_addr: SocketAddrV4,
    ) -> Vec<u8> {
        let pks = [
            PublicKey::from(&StaticSecret::from(relay1_sk)).to_bytes(),
            PublicKey::from(&StaticSecret::from(relay2_sk)).to_bytes(),
        ];
        let (alphas, sub_keys) = derive_route_secrets(rng, &pks).unwrap();

        let records = vec![
            RoutingRecord {
                next_ipv4: relay2_addr.ip().octets(),
                next_port: relay2_addr.port(),
                next_node_id: pks[1],
                delay_micros: 0,
                ..RoutingRecord::default()
            },
            RoutingRecord {
                flag: flag::IS_LAST_HOP,
                ..RoutingRecord::default()
            },
        ];
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);

        let header =
            wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer).unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        for (i, b) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        packet
    }

    /// Spawn a relay binding to an ephemeral port; return its actual bound
    /// address.
    async fn spawn_relay(sk: [u8; 32]) -> (SocketAddrV4, tokio::task::JoinHandle<()>) {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Relay::new(
            sk,
            1000,
            std::time::Duration::from_secs(60),
            0, // no Poisson delay in tests
        );
        let relay = Arc::new(Mutex::new(relay));

        let pool_for_handle = Arc::new(ConnectionPool::new(client, sk));
        let handle = tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let relay = Arc::clone(&relay);
                let pool = Arc::clone(&pool_for_handle);
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, None).await;
                    }
                });
            }
        });

        let v4 = match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("expected v4"),
        };
        (v4, handle)
    }

    /// Spawn a relay with a delivery handler. Returns the bound address
    /// and a receiver for delivered payloads.
    async fn spawn_relay_with_delivery(
        sk: [u8; 32],
    ) -> (SocketAddrV4, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let handler: DeliveryHandler = Arc::new(move |payload: Vec<u8>| {
            let _ = tx.send(payload);
        });
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Relay::new(sk, 1000, std::time::Duration::from_secs(60), 0);
        let relay = Arc::new(Mutex::new(relay));
        let pool = Arc::new(ConnectionPool::new(client, sk));
        tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let relay = Arc::clone(&relay);
                let pool = Arc::clone(&pool);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, Some(handler)).await;
                    }
                });
            }
        });
        let v4 = match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("expected v4"),
        };
        (v4, rx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deliver_local_hook_fires_at_last_hop() {
        init_crypto_provider();
        let mut r = rng();
        let mut sk = [0u8; 32];
        r.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;

        let (addr, mut rx) = spawn_relay_with_delivery(sk).await;

        // Build a 1-hop packet whose only hop is this relay (last hop).
        let pks = [PublicKey::from(&StaticSecret::from(sk)).to_bytes()];
        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records = vec![RoutingRecord {
            flag: flag::IS_LAST_HOP,
            ..RoutingRecord::default()
        }];
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);
        let header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        let marker = b"deliver-this-please";
        packet[HEADER_LEN..HEADER_LEN + marker.len()].copy_from_slice(marker);

        // Send it.
        let client_ep = build_client_endpoint().unwrap();
        let conn = client_ep
            .connect(SocketAddr::V4(addr), "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut client_sk = [0u8; 32];
        r.fill_bytes(&mut client_sk);
        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;
        let server_pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        let mut noise = noise_initiator_handshake(&client_sk, &server_pk, &mut send, &mut recv)
            .await
            .unwrap();
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();
        send.finish().ok();

        // Wait for the delivery callback to fire.
        let payload = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("delivery handler timed out")
            .expect("channel closed");
        assert_eq!(payload.len(), crypto_gotham::PACKET_SIZE - HEADER_LEN);
        assert_eq!(&payload[..marker.len()], marker);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn end_to_end_2hop_forward() {
        init_crypto_provider();
        let mut r = rng();

        // Use clamped X25519 secret keys (snow validates this).
        let mut sk1 = [0u8; 32];
        let mut sk2 = [0u8; 32];
        r.fill_bytes(&mut sk1);
        r.fill_bytes(&mut sk2);
        for sk in [&mut sk1, &mut sk2] {
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
        }

        // Start relay 2 first (so we know its address before building
        // relay 1's routing record).
        let (addr2, _h2) = spawn_relay(sk2).await;
        let (addr1, _h1) = spawn_relay(sk1).await;

        // Build a packet routed: client → relay1 → relay2 (deliver-local).
        let packet = build_2hop_packet(&mut r, sk1, sk2, addr2);

        // Open a client connection to relay 1, do Noise XK, send.
        let client = build_client_endpoint().unwrap();
        let conn = client
            .connect(SocketAddr::V4(addr1), "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // The client's Noise XK identity isn't pinned (Gotham's anonymity
        // model) — we generate an ephemeral keypair just for the XK
        // handshake's `s, se` step.
        let mut client_sk = [0u8; 32];
        r.fill_bytes(&mut client_sk);
        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;
        let server_pk = PublicKey::from(&StaticSecret::from(sk1)).to_bytes();

        let mut noise = noise_initiator_handshake(&client_sk, &server_pk, &mut send, &mut recv)
            .await
            .unwrap();
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();
        send.finish().ok();

        // Give the relays time to forward + deliver. (No assertion on the
        // payload because we don't have a hook for "deliver-local" yet in
        // v0.1; the test passes if no panic or error reaches us.)
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn noise_handshake_roundtrip() {
        init_crypto_provider();
        let mut r = rng();
        let mut server_sk = [0u8; 32];
        r.fill_bytes(&mut server_sk);
        server_sk[0] &= 248;
        server_sk[31] &= 127;
        server_sk[31] |= 64;

        let server_pk = PublicKey::from(&StaticSecret::from(server_sk)).to_bytes();

        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Some(connecting) = server.accept().await {
                let conn = connecting.await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let mut noise = noise_responder_handshake(&server_sk, &mut send, &mut recv)
                    .await
                    .unwrap();
                // Echo one frame back to the client.
                let packet = read_noise_frame(&mut noise, &mut recv).await.unwrap();
                write_noise_frame(&mut noise, &mut send, &packet)
                    .await
                    .unwrap();
                // Keep the stream open: do NOT call finish(). The client
                // signals completion by dropping the connection, which
                // we observe via `conn.closed().await`.
                let _ = conn.closed().await;
            }
        });

        let client = build_client_endpoint().unwrap();
        let conn = client
            .connect(bound, "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let mut client_sk = [0u8; 32];
        r.fill_bytes(&mut client_sk);
        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;

        let mut noise = noise_initiator_handshake(&client_sk, &server_pk, &mut send, &mut recv)
            .await
            .unwrap();

        // Send a packet of known shape.
        let mut packet = vec![0u8; PACKET_SIZE];
        for (i, b) in packet.iter_mut().enumerate() {
            *b = ((i * 31) % 256) as u8;
        }
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();

        // Read echo.
        let echoed = read_noise_frame(&mut noise, &mut recv).await.unwrap();
        assert_eq!(echoed, packet);

        // Drop the client side to let the server's `conn.closed()` await
        // resolve, then await the spawned task.
        drop(send);
        drop(recv);
        drop(conn);
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
    }
}
