//! V9-FS forward-secret onion relay handler (Phase 4).
//!
//! Handles `FsInitFrame` (entry hop, chain_position == 0) and
//! `FsRelayInitFrame` (inner hops, chain_position > 0).
//!
//! Flow per accepted connection:
//! 1. Read the init frame (Init or RelayInit based on chain_position).
//! 2. Negotiate suite, generate a per-session ephemeral.
//! 3. Call `peel_onion_fs_layer` → (layer_key, server_eph_pub, transcript_hash).
//! 4. Send `FsCreatedFrame` back toward the client.
//! 5. If more hops remain: enter the "relay extend loop":
//!    - Read an encrypted `FsExtendFrame` from the client.
//!    - Peel the AEAD layer using `layer_key`.
//!    - Decode the `FsExtendFrame`, build `FsRelayInitFrame`, forward to next hop.
//!    - Read next hop's `FsCreatedFrame`, relay it back (wrapped in our layer key).
//! 6. After circuit is fully established, enter the data relay loop
//!    (`forward_fs_relay_loop`, below).
//!
//! This handler is only reached when `relay::onion_peel`'s dispatcher
//! detects a forward-secret first byte (`WIRE_VERSION_FS`,
//! `WIRE_VERSION_FS_LEGACY`, or `MSG_FS_RELAY_INIT`). Anything else is
//! refused there — the non-forward-secret onion envelope this comment used
//! to call "V8" was deleted 2026-09-02 (see `relay::onion_peel`'s module
//! doc), not routed around.

use std::net::SocketAddr;
use std::sync::Arc;

use mirage_core::{
    config::TransportCamouflage,
    crypto::{AeadSuite, KeyPair},
    error::MirageError,
};
use mirage_protocol::camouflage::pipeline::{wrap_tcp_client, BidiStream};
use mirage_protocol::onion::{
    builder::peel_onion_fs_layer,
    fs_frame::{
        FsCreatedFrame, FsCreatedStatus, FsExtendFrame, FsInitFrame, FsRelayInitFrame,
        MSG_FS_CREATED, WIRE_VERSION_FS,
    },
    layer::wrap_reply_layer_v7,
};

use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use x25519_dalek::EphemeralSecret;

/// Maximum frame size we accept in one read (same as V8 relay).
const MAX_FRAME_BYTES: usize = 65_536;

/// Server's AEAD suite preference, in priority order.
const SERVER_SUITE_PREFERENCE: &[AeadSuite] = &[
    AeadSuite::ChaCha20Poly1305,
    AeadSuite::Aes256Gcm,
    AeadSuite::Aes128Gcm,
];

/// Configuration passed in at accept time for an FS relay hop.
pub struct OnionFsRelayConfig {
    /// Node's static keypair — used for node identity only; NOT used in FS key derivation.
    pub hop_keypair: Arc<KeyPair>,
    /// This hop's position in the circuit (0 = entry).
    pub chain_position: u8,
    /// Total number of hops in the circuit.
    pub chain_length: u8,
    /// This node's identity string (used in transcript binding).
    pub node_id: String,
    /// Outgoing camouflage to apply when dialing the next hop.
    pub outgoing_camouflage: Option<TransportCamouflage>,
    /// Long-term X25519 pubkey of the next hop (for Reality camouflage).
    /// All-zero → raw TCP forward.
    pub next_hop_pubkey: [u8; 32],
    /// SNI / host hint for TLS-based outgoing camouflages.
    pub outgoing_sni: String,
}

fn negotiate_suite(client_suites: &[AeadSuite]) -> Option<AeadSuite> {
    SERVER_SUITE_PREFERENCE
        .iter()
        .find(|s| client_suites.contains(s))
        .copied()
}

/// Send an `FsCreatedFrame` error response toward the client.
async fn send_fs_error<W>(
    stream: &mut W,
    chain_position: u8,
    suite: AeadSuite,
    status: FsCreatedStatus,
    peer: SocketAddr,
    reason: &str,
) where
    W: AsyncWrite + Unpin,
{
    warn!(%peer, chain_position, status = status.name(), reason, "v9-fs relay: handshake error");
    let frame = FsCreatedFrame {
        chain_position,
        suite,
        status,
        server_eph_pub: [0u8; 32],
        transcript_hash: [0u8; 32],
        auth_tag: [0u8; 32],
    };
    let _ = stream.write_all(&frame.encode()).await;
}

/// Read a length-prefixed frame `[4B BE len][bytes]` from `stream`.
async fn read_length_framed<R>(stream: &mut R) -> Result<Vec<u8>, MirageError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
        return Err(MirageError::Protocol(format!(
            "v9-fs relay: invalid frame length {frame_len}"
        )));
    }
    let mut buf = vec![0u8; frame_len];
    stream.read_exact(&mut buf).await.map_err(MirageError::Io)?;
    Ok(buf)
}

/// Write a length-prefixed frame `[4B BE len][bytes]` to `stream`.
async fn write_length_framed<W>(stream: &mut W, data: &[u8]) -> Result<(), MirageError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await.map_err(MirageError::Io)?;
    stream.write_all(data).await.map_err(MirageError::Io)
}

/// Write a well-formed [`V9ClientHello`] to `stream` before this hop's own
/// relay-extend dial — the opening a chain-data-plane-over-faces perimeter
/// face will accept.
///
/// Relocated from `relay::onion_peel` on 2026-09-02 when that file's
/// non-forward-secret onion envelope was deleted: this function dials the
/// NEXT hop, which is exclusively this file's job now that the FS circuit
/// is the only onion path left, so it has one caller and belongs where that
/// caller is.
///
/// # Why a relay-to-relay dial needs a client's hello
///
/// Hop N no longer dials hop N+1's own bound port; it dials hop N+1's
/// PERIMETER FACE, an ordinary port the face also serves ordinary clients
/// on. `classify_v9_hello` (`mirage-perimeter::classify`) refuses anything
/// whose first byte is not `WIRE_VERSION_V9`, and the very first thing this
/// relay used to write after connecting was its own length-prefixed FS
/// frame — a shape the classifier has never seen and does not accept.
/// Without this hello the face would reject every relay-to-relay dial on
/// sight, which is precisely the connection this cutover has to keep
/// working.
///
/// # The node on the other end throws this away, and that is correct
///
/// `core::chain_splice::handle_one` skips exactly `CLIENT_HELLO_LEN` bytes
/// without parsing them. This hello authenticates nothing: the onion
/// layer's own per-hop AEAD is what authenticates a hop, both before this
/// change and after it. This hello exists SOLELY so that a relay's
/// connection is indistinguishable, at the face, from a client's — the
/// face's classifier is shape-only and must stay that way for every
/// caller, relay or client.
///
/// Making hop-to-hop a genuine wire session — the co-located monitor behind
/// the face actually running the V9 handshake against this hello instead of
/// the chain splice discarding it — was considered and deliberately NOT
/// taken here: it would add a full round-trip handshake to every hop of
/// every chain in exchange for a property (cryptographic mutual auth
/// between adjacent relays) the per-hop onion AEAD already provides for
/// this shape of connection. A later arc that wants hop-to-hop wire auth
/// can build on this hello's wire format without changing what a face
/// admits — recorded here so the omission reads as a decision, not a gap.
///
/// EVERY field is drawn from the distribution a genuine client's hello draws
/// from, not just the ones something checks. Both keypairs are real and
/// freshly generated per dial, and the proof is a truncated BLAKE3 because
/// that is what a real proof is. Nothing here validates any of it — the
/// classifier does not look and the node discards the hello whole — so the
/// temptation is to zero the fields nobody reads. That would put 48 bytes of
/// zeros at fixed offsets in the middle of every relay-to-relay opening and
/// nowhere else, which is a landmark for anyone who ever sees this plaintext:
/// a perimeter, a future log path, an operator holding the face's TLS key. The
/// whole reason to send a hello at all is that a relay's connection must not
/// be separable from a client's, and a field left zero because it is unchecked
/// separates it. Two X25519 keygens and a hash is what that costs.
async fn write_face_hello<W>(stream: &mut W) -> Result<(), MirageError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    // One construction, both dialers. This body used to live here, and the
    // CLIENT dialing the entry hop's face had no counterpart at all — so a
    // relay's opening and a client's opening were not the same bytes, on the
    // one seam whose entire purpose is that they should be. It now lives in
    // `mirage_protocol::auth::v9` where both call it.
    mirage_protocol::auth::v9::write_face_hello(stream).await
}

/// Handle a V9-FS relay (entry or inner hop) connection.
///
/// The dispatcher in `onion_peel.rs` calls this after detecting `WIRE_VERSION_FS`
/// as the first byte. The V8 `handle_onion_peel` path is untouched.
///
/// `frame_rest_len` is the number of bytes the dispatcher already buffered
/// after the type/version byte — `frame_body.len() - 1` in `onion_peel.rs`'s
/// own read. It exists so [`read_init_frame_rest_len`] and
/// [`read_relay_init_frame_rest`] — which reconstruct the frame one field at
/// a time from a stream rather than a slice — know whether the optional
/// selector-token trailer follows the credential trailer or the frame simply
/// ends there. Without it, a trailer present on the wire is silently left
/// unread in the `PrefixStream`'s buffer and served as the FIRST bytes of
/// whatever this hop reads next (the extend loop's own length prefix),
/// corrupting the handshake for any peer that actually sends a token — the
/// same bound `onion_peel.rs` already knows because it read the whole frame
/// as one `[4B len][body]` unit before this function ever saw it.
pub async fn handle_onion_fs_peel<S>(
    cfg: OnionFsRelayConfig,
    mut client_stream: S,
    peer: SocketAddr,
    prefix_byte: Option<u8>,
    frame_rest_len: usize,
) -> Result<(), MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(
        %peer,
        hop_position = cfg.chain_position,
        total_hops = cfg.chain_length,
        node_id = %cfg.node_id,
        "v9-fs relay: incoming FS onion connection"
    );

    // ── 1. Read the init frame ────────────────────────────────────────────────
    // Entry hop (chain_position == 0) receives `FsInitFrame` directly from client.
    // Inner hops (chain_position > 0) receive `FsRelayInitFrame` forwarded by entry.
    //
    // Both frames are NOT length-prefixed at this level — the first bytes are the
    // frame body starting with the wire version / type byte. For entry hop the
    // prefix_byte (already consumed by the dispatcher peek) is the WIRE_VERSION_FS byte.
    // For inner hops the TCP connection arrives with MSG_FS_RELAY_INIT as first byte.

    /// Timeout for the pre-circuit handshake read phase (15 seconds).
    const FS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    // credential_scheme + credential are carried from FsInitFrame (entry hop) or
    // FsRelayInitFrame (inner hops) and forwarded verbatim to the next hop.
    // Relays do NOT verify credentials — only the exit does.
    let (mesh_id, chain_id, chain_length, chain_position, client_suites, client_eph_pub,
         prev_transcript, incoming_credential_scheme, incoming_credential) = if cfg.chain_position == 0 {
        // Entry hop: re-assemble the full FsInitFrame bytes including the already-read prefix byte.
        let rest_len = match tokio::time::timeout(
            FS_HANDSHAKE_TIMEOUT,
            read_init_frame_rest_len(&mut client_stream, frame_rest_len),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                warn!(%peer, error = %e, "v9-fs relay: FsInit rest read failed");
                return Err(e);
            }
            Err(_) => {
                warn!(%peer, "v9-fs relay: handshake init read timed out (15s)");
                return Err(MirageError::Protocol("v9-fs relay: handshake timed out".into()));
            }
        };
        let mut full_buf = Vec::with_capacity(1 + rest_len.len());
        let first = prefix_byte.unwrap_or(WIRE_VERSION_FS);
        full_buf.push(first);
        full_buf.extend_from_slice(&rest_len);

        let (init, _) = match FsInitFrame::decode(&full_buf) {
            Ok(v) => v,
            Err(e) => {
                send_fs_error(
                    &mut client_stream,
                    cfg.chain_position,
                    AeadSuite::ChaCha20Poly1305,
                    FsCreatedStatus::BadVersion,
                    peer,
                    &format!("FsInitFrame parse: {e}"),
                )
                .await;
                return Err(e);
            }
        };

        if init.chain_length != cfg.chain_length {
            send_fs_error(
                &mut client_stream,
                cfg.chain_position,
                AeadSuite::ChaCha20Poly1305,
                FsCreatedStatus::BadVersion,
                peer,
                &format!(
                    "chain_length mismatch: frame={} server={}",
                    init.chain_length, cfg.chain_length
                ),
            )
            .await;
            return Ok(());
        }

        // Entry hop: prev_transcript = base transcript (computed from mesh_id + chain_id).
        use mirage_protocol::onion::builder::compute_fs_transcript_base;
        let base_transcript = compute_fs_transcript_base(&init.mesh_id, &init.chain_id);

        (
            init.mesh_id,
            init.chain_id,
            init.chain_length,
            init.chain_position,
            init.client_suites,
            init.client_eph_pub,
            base_transcript,
            init.credential_scheme,
            init.credential,
        )
    } else {
        // Inner hop: receives FsRelayInitFrame.
        // The dispatcher already consumed [4B len][frame body]. It passed:
        //   - prefix_byte = Some(MSG_FS_RELAY_INIT = 0x92)
        //   - stream prefixed with frame_body[1..] (everything after the type byte)
        // Read the rest of the FsRelayInitFrame fields from the stream.
        let rest = match tokio::time::timeout(
            FS_HANDSHAKE_TIMEOUT,
            read_relay_init_frame_rest(&mut client_stream, frame_rest_len),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                send_fs_error(
                    &mut client_stream,
                    cfg.chain_position,
                    AeadSuite::ChaCha20Poly1305,
                    FsCreatedStatus::BadVersion,
                    peer,
                    &format!("FsRelayInitFrame read: {e}"),
                )
                .await;
                return Err(e);
            }
            Err(_) => {
                warn!(%peer, "v9-fs relay: handshake relay-init read timed out (15s)");
                return Err(MirageError::Protocol(
                    "v9-fs relay: handshake timed out".into(),
                ));
            }
        };

        let first = prefix_byte.unwrap_or(mirage_protocol::onion::fs_frame::MSG_FS_RELAY_INIT);
        let mut full = Vec::with_capacity(1 + rest.len());
        full.push(first);
        full.extend_from_slice(&rest);

        let (relay_init, _) = match FsRelayInitFrame::decode(&full) {
            Ok(v) => v,
            Err(e) => {
                send_fs_error(
                    &mut client_stream,
                    cfg.chain_position,
                    AeadSuite::ChaCha20Poly1305,
                    FsCreatedStatus::BadVersion,
                    peer,
                    &format!("FsRelayInitFrame parse: {e}"),
                )
                .await;
                return Err(e);
            }
        };

        if relay_init.chain_length != cfg.chain_length {
            send_fs_error(
                &mut client_stream,
                cfg.chain_position,
                AeadSuite::ChaCha20Poly1305,
                FsCreatedStatus::BadVersion,
                peer,
                &format!(
                    "chain_length mismatch: frame={} server={}",
                    relay_init.chain_length, cfg.chain_length
                ),
            )
            .await;
            return Ok(());
        }

        (
            relay_init.mesh_id,
            relay_init.chain_id,
            relay_init.chain_length,
            relay_init.chain_position,
            relay_init.client_suites,
            relay_init.client_eph_pub,
            relay_init.prev_transcript,
            relay_init.credential_scheme,
            relay_init.credential,
        )
    };

    // ── 2. Suite negotiation ──────────────────────────────────────────────────
    let suite = match negotiate_suite(&client_suites) {
        Some(s) => s,
        None => {
            send_fs_error(
                &mut client_stream,
                chain_position,
                AeadSuite::ChaCha20Poly1305,
                FsCreatedStatus::NoCommonSuite,
                peer,
                &format!("no common suite in {:?}", client_suites),
            )
            .await;
            return Ok(());
        }
    };

    // ── 3. Generate per-session ephemeral, peel FS layer ─────────────────────
    let server_eph = EphemeralSecret::random_from_rng(OsRng);
    let (layer_key, server_eph_pub, transcript_hash, auth_tag) = peel_onion_fs_layer(
        server_eph,
        &cfg.hop_keypair,
        &client_eph_pub,
        chain_position,
        &prev_transcript,
        &cfg.node_id,
        suite,
    );

    // ── 4. Send FsCreatedFrame toward client ──────────────────────────────────
    let created = FsCreatedFrame {
        chain_position,
        suite,
        status: FsCreatedStatus::Ok,
        server_eph_pub,
        transcript_hash,
        auth_tag,
    };
    if let Err(e) = client_stream.write_all(&created.encode()).await {
        warn!(%peer, error = %e, "v9-fs relay: write FsCreated failed");
        return Err(MirageError::Io(e));
    }
    debug!(%peer, chain_position, "v9-fs relay: FsCreated sent");

    // ── 5. Relay extend loop (for hops that are not the last hop) ─────────────
    // We need to determine if there are more hops after this one. Each hop only
    // knows chain_length and chain_position. If chain_position < chain_length - 1,
    // there are hops to come. The entry hop (position 0) handles relaying the
    // extend frames to subsequent hops. However, inner hops (position > 0 but
    // not exit) also do the same thing.
    //
    // Architectural note: In telescopic design, every relay hop participates in the
    // extend loop. The entry hop receives the extend frame encrypted with key_0 from
    // the client, decrypts it, and forwards an FsRelayInitFrame to the next hop.
    // The next hop may itself forward further. This handler covers both entry and
    // inner relay hops (not the exit). The exit is in onion_fs.rs.
    //
    // However: this relay handler in mirage2node is configured per-listener with a
    // fixed chain_position. If chain_position < chain_length - 1, we are NOT the exit
    // and we must relay extends. If chain_position == chain_length - 1, we ARE the exit
    // but that is handled by onion_fs.rs. So here we always are a relay (not exit).

    // The entry hop will receive FsExtendFrame payloads (encrypted with layer_key)
    // for each subsequent hop. We handle them one by one.
    let remaining_hops = (chain_length as usize).saturating_sub(chain_position as usize + 1);

    if remaining_hops > 0 {
        // Telescopic extend loop: run once per remaining hop.
        //
        // Iteration 0 (ext_idx == 0):
        //   - Read one FsExtendFrame from client (encrypted with our layer_key).
        //   - Peel our AEAD layer → decode FsExtendFrame → dial next hop → send
        //     FsRelayInitFrame → read+verify FsCreated from next hop → forward
        //     FsCreated raw to client.
        //   - Establish `upstream` (persists across the loop).
        //
        // Iterations 1..remaining_hops-1 (ext_idx >= 1):
        //   - Read the next FsExtendFrame from client (still encrypted with our
        //     layer_key, but the plaintext is itself wrapped for a deeper hop).
        //   - Peel our AEAD layer only — do NOT decode (the deeper hop's layer
        //     is still intact inside).
        //   - Forward the peeled inner bytes opaquely to the already-established
        //     `upstream` via write_length_framed.
        //   - Read FsCreated from upstream → forward raw to client.
        //
        // After the loop: enter the data relay loop.

        let mut upstream_opt: Option<Box<dyn BidiStream>> = None;
        let mut next_addr_opt: Option<SocketAddr> = None;

        for ext_idx in 0..remaining_hops {
            // Read the extend frame from the client (15s timeout).
            let extend_bytes = match tokio::time::timeout(
                FS_HANDSHAKE_TIMEOUT,
                read_length_framed(&mut client_stream),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    warn!(%peer, ext_idx, error = %e, "v9-fs relay: extend frame read failed");
                    return Err(e);
                }
                Err(_) => {
                    warn!(%peer, ext_idx, "v9-fs relay: extend frame read timed out (15s)");
                    return Err(MirageError::Protocol(
                        "v9-fs relay: extend frame read timed out".into(),
                    ));
                }
            };

            // Peel our AEAD layer.
            // The extend is a FORWARD-direction frame (client -> node): the client
            // wraps it with `wrap_layer_v7` (NextHop::Terminal AAD), so we peel it
            // with the matching `peel_layer_v7` (NOT the reply variant). peel_layer_v7
            // returns (NextHop, inner) — we ignore the NextHop for routing purposes
            // (real next hop for iter 0 comes from the decoded FsExtendFrame.next_hop_addr;
            // for iter >= 1 the inner bytes carry the deeper hop's address opaquely).
            let (_extend_next, inner) = match mirage_protocol::onion::layer::peel_layer_v7(
                suite,
                &extend_bytes,
                &layer_key,
            ) {
                Ok(v) => v,
                Err(e) => {
                    warn!(%peer, ext_idx, error = %e, "v9-fs relay: extend AEAD peel failed");
                    return Err(e);
                }
            };

            if ext_idx == 0 {
                // First extend: decode FsExtendFrame, dial the next hop, send
                // FsRelayInitFrame to establish `upstream`.

                // Decode the FsExtendFrame.
                let (extend_frame, _) = match FsExtendFrame::decode(&inner) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(%peer, error = %e, "v9-fs relay: FsExtendFrame decode failed");
                        return Err(e);
                    }
                };

                // Build FsRelayInitFrame to send to next hop.
                // Credential is propagated verbatim from the original FsInitFrame
                // (captured in incoming_credential_scheme / incoming_credential).
                // selector_token is propagated from the FsExtendFrame we just
                // peeled — it was addressed to the NEXT hop's listener by the
                // client (or the entry, for a deeper extend), not to us, so we
                // forward it unread and unmodified. Without this the token
                // never reaches any hop past the one that peels it here.
                let relay_init = FsRelayInitFrame {
                    mesh_id: mesh_id.clone(),
                    chain_id: chain_id.clone(),
                    chain_length,
                    chain_position: extend_frame.chain_position,
                    client_suites: extend_frame.client_suites,
                    client_eph_pub: extend_frame.client_eph_pub,
                    expected_peer_table_generation: extend_frame.expected_peer_table_generation,
                    prev_transcript: extend_frame.prev_transcript,
                    credential_scheme: incoming_credential_scheme,
                    credential: incoming_credential.clone(),
                    selector_token: extend_frame.selector_token.clone(),
                };

                let relay_init_bytes = match relay_init.encode() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(%peer, error = %e, "v9-fs relay: FsRelayInitFrame encode failed");
                        return Err(e);
                    }
                };

                // Resolve next hop address.
                let next_hop_addr = extend_frame.next_hop_addr.clone();
                let next_addr: SocketAddr = match next_hop_addr.parse() {
                    Ok(a) => a,
                    Err(_) => {
                        use tokio::net::lookup_host;
                        let mut iter = lookup_host(next_hop_addr.as_str())
                            .await
                            .map_err(MirageError::Io)?;
                        iter.next().ok_or_else(|| {
                            MirageError::Protocol(format!(
                                "v9-fs relay: no DNS for {next_hop_addr}"
                            ))
                        })?
                    }
                };

                // SSRF guard — next hop in a legit FS circuit is always a public VPS IP.
                if crate::family::mirage::exit::policy::is_blocked(next_addr.ip()) {
                    warn!(ip = %next_addr.ip(), %peer, "v9-fs relay extend: SSRF blocked next-hop target");
                    return Err(MirageError::Protocol(format!(
                        "SSRF: blocked next-hop target {}",
                        next_addr.ip()
                    )));
                }

                info!(%peer, %next_addr, "v9-fs relay: dialing next hop for extend");

                let use_cam = cfg
                    .outgoing_camouflage
                    .as_ref()
                    .filter(|_| cfg.next_hop_pubkey != [0u8; 32]);

                let mut upstream: Box<dyn BidiStream> = if let Some(cam) = use_cam {
                    match wrap_tcp_client(next_addr, cam, &cfg.next_hop_pubkey, &cfg.outgoing_sni)
                        .await
                    {
                        Ok(mut s) => {
                            // Half A of the chain-data-plane-over-faces
                            // cutover: this dials the next hop's PERIMETER
                            // FACE, not its own bound port, and the face's
                            // classifier rejects an opening that is not a V9
                            // hello. See `write_face_hello` above for the
                            // full reasoning, including why the node
                            // discards this hello and why hop-to-hop wire
                            // auth was deliberately not built here.
                            if let Err(e) = write_face_hello(&mut s).await {
                                warn!(%peer, %next_addr, error = %e, "v9-fs relay: face hello write failed");
                                return Err(e);
                            }
                            s
                        }
                        Err(e) => {
                            warn!(%peer, %next_addr, error = %e, "v9-fs relay: camouflage wrap failed");
                            return Err(MirageError::NodeUnreachable(format!(
                                "v9-fs camouflage wrap {next_addr}: {e}"
                            )));
                        }
                    }
                } else {
                    match TcpStream::connect(next_addr).await {
                        Ok(s) => Box::new(s),
                        Err(e) => {
                            warn!(%peer, %next_addr, error = %e, "v9-fs relay: connect next hop failed");
                            return Err(MirageError::NodeUnreachable(format!(
                                "{next_addr}: {e}"
                            )));
                        }
                    }
                };

                // Send FsRelayInitFrame to next hop length-prefixed.
                write_length_framed(upstream.as_mut(), &relay_init_bytes).await?;

                // Read + verify + forward FsCreated from next hop.
                let mut next_created_buf = [0u8; FsCreatedFrame::ENCODED_LEN];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    upstream.read_exact(&mut next_created_buf),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(%peer, %next_addr, error = %e, "v9-fs relay: read next FsCreated failed");
                        return Err(MirageError::Io(e));
                    }
                    Err(_) => {
                        warn!(%peer, %next_addr, "v9-fs relay: next hop FsCreated timed out");
                        return Err(MirageError::Protocol(
                            "v9-fs relay: next hop FsCreated timed out (15s)".into(),
                        ));
                    }
                }
                if next_created_buf[0] != MSG_FS_CREATED {
                    warn!(
                        %peer, %next_addr,
                        got = next_created_buf[0],
                        "v9-fs relay: next hop replied with unexpected type byte"
                    );
                    return Err(MirageError::Protocol(format!(
                        "v9-fs relay: expected FsCreated (0x{:02x}) from next hop, got 0x{:02x}",
                        MSG_FS_CREATED, next_created_buf[0]
                    )));
                }
                // Forward the next hop's FsCreatedFrame to the client as RAW fixed-size
                // bytes — the SAME framing the client used to read hop-0's FsCreated
                // (FsCreatedFrame::ENCODED_LEN, no length prefix, no onion wrap). The
                // FsCreated fields (server ephemeral pub, transcript_hash, auth_tag) are
                // all public, so the telescopic SETUP reply needs no per-segment
                // encryption; only the post-circuit DATA path is onion-wrapped
                // (forward_fs_relay_loop below). Wrapping here diverged from the client
                // read (which expects raw bytes) and caused a setup-phase desync.
                client_stream
                    .write_all(&next_created_buf)
                    .await
                    .map_err(MirageError::Io)?;

                next_addr_opt = Some(next_addr);
                upstream_opt = Some(upstream);
            } else {
                // Subsequent extends (ext_idx >= 1): forward the peeled inner bytes
                // opaquely to the already-established upstream. The inner bytes are
                // still wrapped by a deeper hop's layer — the next hop in the chain
                // peels that layer itself.
                let upstream = upstream_opt
                    .as_mut()
                    .expect("upstream established on ext_idx 0, still live for subsequent extends");
                let next_addr = next_addr_opt
                    .expect("next_addr set on ext_idx 0");

                write_length_framed(upstream.as_mut(), &inner).await?;

                // Read + verify + forward FsCreated from upstream.
                let mut next_created_buf = [0u8; FsCreatedFrame::ENCODED_LEN];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    upstream.read_exact(&mut next_created_buf),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(%peer, %next_addr, ext_idx, error = %e, "v9-fs relay: read next FsCreated failed (deep extend)");
                        return Err(MirageError::Io(e));
                    }
                    Err(_) => {
                        warn!(%peer, %next_addr, ext_idx, "v9-fs relay: next hop FsCreated timed out (deep extend)");
                        return Err(MirageError::Protocol(
                            "v9-fs relay: next hop FsCreated timed out (15s, deep extend)".into(),
                        ));
                    }
                }
                if next_created_buf[0] != MSG_FS_CREATED {
                    warn!(
                        %peer, %next_addr, ext_idx,
                        got = next_created_buf[0],
                        "v9-fs relay: next hop replied with unexpected type byte (deep extend)"
                    );
                    return Err(MirageError::Protocol(format!(
                        "v9-fs relay: expected FsCreated (0x{:02x}) from next hop, got 0x{:02x} (deep extend idx {ext_idx})",
                        MSG_FS_CREATED, next_created_buf[0]
                    )));
                }
                client_stream
                    .write_all(&next_created_buf)
                    .await
                    .map_err(MirageError::Io)?;
            }
        }

        // remaining_hops > 0 guarantees at least one iteration ran.
        let upstream = upstream_opt.expect("upstream established during extend loop");
        let next_addr = next_addr_opt.expect("next_addr set during extend loop");

        debug!(%peer, chain_position, remaining_hops, "v9-fs relay: all extends relayed, entering data loop");

        // ── 6. Data relay loop ────────────────────────────────────────────────
        // After circuit establishment, forward data frames using the same V7
        // reply-wrapping pattern as the V8 relay.
        forward_fs_relay_loop(client_stream, upstream, layer_key, suite, peer, next_addr).await;
        Ok(())
    } else {
        // This relay hop is actually the exit (remaining_hops == 0).
        // This shouldn't happen if the listener is configured correctly (exit goes
        // to onion_fs.rs), but handle gracefully.
        warn!(%peer, chain_position, chain_length, "v9-fs relay: no remaining hops — chain misconfigured (should use exit handler)");
        Err(MirageError::Protocol(
            "v9-fs relay: called at terminal position (use exit handler)".into(),
        ))
    }
}

/// Maximum byte length for `mesh_id` / `chain_id` fields read before AEAD auth.
const MAX_FS_ID_LEN: usize = 256;

/// Maximum byte length for the credential payload in the FS frame trailer.
/// An EpochHmac token is 52 bytes; cap generously to reject an out-of-spec oversized trailer.
const MAX_FS_CRED_LEN: usize = 1024;

/// Read the selector-token trailer, if the frame's declared length says one
/// follows `buf` (which already holds everything through the credential
/// trailer). `rest_len` is `frame_rest_len` from
/// [`handle_onion_fs_peel`][super::handle_onion_fs_peel] — the whole frame's
/// length after the type byte, known upfront because `onion_peel.rs`
/// buffered the entire `[4B len][body]` unit before this code ever ran.
///
/// The trailer is genuinely optional on the wire — written only when the
/// selector token is non-empty — so a STREAM reader cannot peek ahead to
/// decide whether it is there without either blocking on live data that a
/// legitimate no-token peer will never send, or worse, stealing the first
/// bytes of whatever this hop reads next (the extend loop's own length
/// prefix). `rest_len` removes the guess: read raw bytes verbatim up to the
/// frame's own declared end and hand them to `decode()`, which already knows
/// how to read the trailer's `[1B len][bytes]` shape from a buffer — this
/// function does not re-parse it, only positions the stream cursor
/// correctly past it.
async fn read_optional_selector_trailer<R>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    rest_len: usize,
) -> Result<(), MirageError>
where
    R: AsyncRead + Unpin,
{
    match rest_len.checked_sub(buf.len()) {
        Some(0) => Ok(()),
        Some(trailer_len) => {
            let mut trailer = vec![0u8; trailer_len];
            stream.read_exact(&mut trailer).await.map_err(MirageError::Io)?;
            buf.extend_from_slice(&trailer);
            Ok(())
        }
        None => Err(MirageError::Protocol(format!(
            "v9-fs: declared frame length {rest_len} is shorter than the {} bytes \
             this frame's fixed fields already required",
            buf.len()
        ))),
    }
}

/// Read the body of an `FsRelayInitFrame` after the first (already-consumed) type byte.
///
/// Wire layout after the type byte:
/// ```text
/// [2B mesh_id_len BE][N B mesh_id]
/// [2B chain_id_len BE][N B chain_id]
/// [1B chain_length][1B chain_position]
/// [1B suite_count][N B suites]
/// [32B client_eph_pub]
/// [8B  expected_peer_table_generation]
/// [32B prev_transcript]
/// [1B credential_scheme][2B credential_len][N B credential]
/// [1B selector_token_len][N B selector_token]   ← only when non-empty
/// ```
///
/// `rest_len` is the total byte count expected after the type byte — see
/// [`read_optional_selector_trailer`] for why the last field needs it.
async fn read_relay_init_frame_rest<R>(stream: &mut R, rest_len: usize) -> Result<Vec<u8>, MirageError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();

    // mesh_id
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&len_buf);
    let mesh_id_len = u16::from_be_bytes(len_buf) as usize;
    if mesh_id_len > MAX_FS_ID_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs: oversized field len {} (max {})",
            mesh_id_len, MAX_FS_ID_LEN
        )));
    }
    let mut mesh_id_buf = vec![0u8; mesh_id_len];
    stream.read_exact(&mut mesh_id_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&mesh_id_buf);

    // chain_id
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&len_buf);
    let chain_id_len = u16::from_be_bytes(len_buf) as usize;
    if chain_id_len > MAX_FS_ID_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs: oversized field len {} (max {})",
            chain_id_len, MAX_FS_ID_LEN
        )));
    }
    let mut chain_id_buf = vec![0u8; chain_id_len];
    stream.read_exact(&mut chain_id_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&chain_id_buf);

    // chain_length + chain_position + suite_count
    let mut fixed = [0u8; 3];
    stream.read_exact(&mut fixed).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&fixed);
    let suite_count = fixed[2] as usize;
    if suite_count == 0 {
        return Err(MirageError::Protocol(
            "v9-fs: empty client_suites in FsRelayInitFrame".into(),
        ));
    }

    // suites
    let mut suites = vec![0u8; suite_count];
    stream.read_exact(&mut suites).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&suites);

    // eph_pub (32B) + generation (8B) + prev_transcript (32B)
    let mut tail = [0u8; 72];
    stream.read_exact(&mut tail).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&tail);

    // Credential trailer (WIRE_VERSION_FS 0x0B): [1B scheme][2B cred_len BE][cred_len bytes].
    // The encoder always writes 0x0B, so the trailer is always present. Reading it here
    // keeps the reassembled buffer complete for FsRelayInitFrame::decode and leaves the
    // stream cursor correctly positioned for the next frame.
    let mut cred_hdr = [0u8; 3];
    stream.read_exact(&mut cred_hdr).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&cred_hdr);
    let cred_len = u16::from_be_bytes([cred_hdr[1], cred_hdr[2]]) as usize;
    if cred_len > MAX_FS_CRED_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs: oversized credential trailer {} (max {})",
            cred_len, MAX_FS_CRED_LEN
        )));
    }
    if cred_len > 0 {
        let mut cred = vec![0u8; cred_len];
        stream.read_exact(&mut cred).await.map_err(MirageError::Io)?;
        buf.extend_from_slice(&cred);
    }

    read_optional_selector_trailer(stream, &mut buf, rest_len).await?;

    Ok(buf)
}

/// Read the body of an FsInitFrame after the first (already-consumed) wire_version byte.
///
/// Since FsInitFrame is variable-length with no outer length prefix at the TCP level,
/// we read it by reading the variable-length fields in sequence. We do this by reading
/// enough bytes to reconstruct the full frame — we read byte by byte only for the
/// variable parts (mesh_id, chain_id), then fixed parts (chain_length, position,
/// suite_count, suites, eph_pub, generation), then the credential trailer and the
/// optional selector-token trailer — see [`read_optional_selector_trailer`] for why
/// the latter needs `rest_len`.
///
/// Returns everything AFTER the first byte (the byte was already consumed by the peek).
async fn read_init_frame_rest_len<R>(stream: &mut R, rest_len: usize) -> Result<Vec<u8>, MirageError>
where
    R: AsyncRead + Unpin,
{
    // mesh_id_len (2B) + mesh_id + chain_id_len (2B) + chain_id +
    // chain_length (1B) + chain_position (1B) + suite_count (1B) + suites + eph_pub (32B) + gen (8B)

    let mut buf = Vec::new();

    // mesh_id
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&len_buf);
    let mesh_id_len = u16::from_be_bytes(len_buf) as usize;
    if mesh_id_len > MAX_FS_ID_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs: oversized field len {} (max {})",
            mesh_id_len, MAX_FS_ID_LEN
        )));
    }
    let mut mesh_id_buf = vec![0u8; mesh_id_len];
    stream.read_exact(&mut mesh_id_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&mesh_id_buf);

    // chain_id
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&len_buf);
    let chain_id_len = u16::from_be_bytes(len_buf) as usize;
    if chain_id_len > MAX_FS_ID_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs: oversized field len {} (max {})",
            chain_id_len, MAX_FS_ID_LEN
        )));
    }
    let mut chain_id_buf = vec![0u8; chain_id_len];
    stream.read_exact(&mut chain_id_buf).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&chain_id_buf);

    // chain_length + chain_position + suite_count
    let mut fixed = [0u8; 3];
    stream.read_exact(&mut fixed).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&fixed);
    let suite_count = fixed[2] as usize;
    if suite_count == 0 {
        return Err(MirageError::Protocol("v9-fs: empty client_suites in init".into()));
    }

    // suites
    let mut suites = vec![0u8; suite_count];
    stream.read_exact(&mut suites).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&suites);

    // eph_pub (32B) + generation (8B)
    let mut tail = [0u8; 40];
    stream.read_exact(&mut tail).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&tail);

    // Credential trailer (WIRE_VERSION_FS 0x0B): [1B scheme][2B cred_len BE][cred_len bytes].
    // The encoder always writes 0x0B, so the trailer is always present. Reading it here
    // keeps the reassembled buffer complete for FsInitFrame::decode and leaves the
    // stream cursor correctly positioned for the next frame.
    let mut cred_hdr = [0u8; 3];
    stream.read_exact(&mut cred_hdr).await.map_err(MirageError::Io)?;
    buf.extend_from_slice(&cred_hdr);
    let cred_len = u16::from_be_bytes([cred_hdr[1], cred_hdr[2]]) as usize;
    if cred_len > MAX_FS_CRED_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs: oversized credential trailer {} (max {})",
            cred_len, MAX_FS_CRED_LEN
        )));
    }
    if cred_len > 0 {
        let mut cred = vec![0u8; cred_len];
        stream.read_exact(&mut cred).await.map_err(MirageError::Io)?;
        buf.extend_from_slice(&cred);
    }

    read_optional_selector_trailer(stream, &mut buf, rest_len).await?;

    Ok(buf)
}

/// Data relay loop after FS circuit is established.
///
/// Forward path: read raw bytes from client, forward to upstream unchanged.
/// Reply path: read framed chunks from upstream, wrap in `layer_key`, forward to client.
async fn forward_fs_relay_loop<S>(
    client_stream: S,
    mut upstream: Box<dyn BidiStream>,
    layer_key: [u8; 32],
    suite: AeadSuite,
    peer: SocketAddr,
    next_addr: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::split as tio_split;

    let (mut client_read, mut client_write) = tio_split(client_stream);
    let (mut up_read, mut up_write) = tio_split(upstream.as_mut());

    let fwd = async {
        let mut buf = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let reply_loop = async {
        // Reused across iterations to avoid a per-packet alloc storm on this
        // hot data-plane path (runs once per hop, per reply packet).
        let mut chunk: Vec<u8> = Vec::new();
        let mut inner_framed: Vec<u8> = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            match up_read.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => break,
            }
            let chunk_len = u32::from_be_bytes(len_buf) as usize;
            if chunk_len > MAX_FRAME_BYTES {
                warn!(%peer, %next_addr, chunk_len, "v9-fs relay: reply chunk too large");
                break;
            }
            chunk.clear();
            chunk.resize(chunk_len, 0u8);
            if up_read.read_exact(&mut chunk).await.is_err() {
                break;
            }
            inner_framed.clear();
            inner_framed.extend_from_slice(&len_buf);
            inner_framed.extend_from_slice(&chunk);
            match wrap_reply_layer_v7(suite, &layer_key, &inner_framed) {
                Err(e) => {
                    warn!(%peer, %next_addr, error = %e, "v9-fs relay: reply wrap error");
                    break;
                }
                Ok(wrapped) => {
                    let outer_len = (wrapped.len() as u32).to_be_bytes();
                    if client_write.write_all(&outer_len).await.is_err() {
                        break;
                    }
                    if client_write.write_all(&wrapped).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    tokio::join!(fwd, reply_loop);
}

#[cfg(test)]
mod tests {
    use super::{read_init_frame_rest_len, read_relay_init_frame_rest};
    use mirage_core::crypto::AeadSuite;
    use mirage_protocol::onion::fs_frame::{FsInitFrame, FsRelayInitFrame, WIRE_VERSION_FS};
    use std::io::Cursor;

    // ── read_init_frame_rest_len ─────────────────────────────────────────────

    #[tokio::test]
    async fn init_frame_reader_roundtrip_with_credential() {
        // scheme=0x01 (EpochHmac), 52 bytes: epoch_id[4] + nonce[16] + mac[32].
        let mut cred = vec![0u8; 52];
        cred[0..4].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        for b in &mut cred[4..20] { *b = 0xAA; }
        for b in &mut cred[20..52] { *b = 0xBB; }

        let original = FsInitFrame {
            mesh_id: b"staging-v2".to_vec(),
            chain_id: b"c-fs-test".to_vec(),
            chain_length: 3,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm],
            client_eph_pub: [0xCCu8; 32],
            expected_peer_table_generation: 42,
            credential_scheme: 0x01,
            credential: cred,
            // Non-empty on purpose: this is the trailer AFTER the credential
            // trailer, and the reader must not stop short of it — a reader
            // that did would leave these bytes queued for whatever this hop
            // reads next, corrupting the handshake.
            selector_token: b"init-selector-token".to_vec(),
        };

        let encoded = original.encode().unwrap();
        assert_eq!(encoded[0], WIRE_VERSION_FS);

        // Simulate dispatcher having consumed the first byte.
        let mut cursor = Cursor::new(&encoded[1..]);
        let rest = read_init_frame_rest_len(&mut cursor, encoded.len() - 1).await.unwrap();

        // Reassemble the full frame as the caller does.
        let mut full = vec![encoded[0]];
        full.extend_from_slice(&rest);

        let (decoded, consumed) = FsInitFrame::decode(&full).unwrap();
        assert_eq!(consumed, full.len(), "no leftover bytes");
        assert_eq!(decoded, original);

        // Stream cursor must be fully consumed.
        let pos = cursor.position() as usize;
        assert_eq!(pos, encoded.len() - 1, "stream cursor at end");
    }

    #[tokio::test]
    async fn init_frame_reader_roundtrip_no_credential() {
        let original = FsInitFrame {
            mesh_id: b"mesh-x".to_vec(),
            chain_id: b"chain-y".to_vec(),
            chain_length: 2,
            chain_position: 0,
            client_suites: vec![AeadSuite::Aes128Gcm],
            client_eph_pub: [0x11u8; 32],
            expected_peer_table_generation: 0,
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };

        let encoded = original.encode().unwrap();
        let mut cursor = Cursor::new(&encoded[1..]);
        let rest = read_init_frame_rest_len(&mut cursor, encoded.len() - 1).await.unwrap();

        let mut full = vec![encoded[0]];
        full.extend_from_slice(&rest);

        let (decoded, consumed) = FsInitFrame::decode(&full).unwrap();
        assert_eq!(consumed, full.len(), "no leftover bytes");
        assert_eq!(decoded, original);

        let pos = cursor.position() as usize;
        assert_eq!(pos, encoded.len() - 1, "stream cursor at end");
    }

    // ── read_relay_init_frame_rest ────────────────────────────────────────────

    #[tokio::test]
    async fn relay_init_frame_reader_roundtrip_with_credential() {
        let mut cred = vec![0u8; 52];
        cred[0..4].copy_from_slice(&0x0000_0007u32.to_be_bytes());
        for b in &mut cred[4..20] { *b = 0xDE; }
        for b in &mut cred[20..52] { *b = 0xAD; }

        let original = FsRelayInitFrame {
            mesh_id: b"staging-v2".to_vec(),
            chain_id: b"c-relay-test".to_vec(),
            chain_length: 3,
            chain_position: 1,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0x55u8; 32],
            expected_peer_table_generation: 7,
            prev_transcript: [0x22u8; 32],
            credential_scheme: 0x01,
            credential: cred,
            // Non-empty on purpose — see the matching note on the init-frame
            // roundtrip above; the same trailer sits after the credential
            // trailer here too.
            selector_token: b"relay-selector-token".to_vec(),
        };

        let encoded = original.encode().unwrap();

        // FsRelayInitFrame first byte is MSG_FS_RELAY_INIT (0x92), not wire_version.
        // read_relay_init_frame_rest is called after that first byte is consumed.
        let mut cursor = Cursor::new(&encoded[1..]);
        let rest = read_relay_init_frame_rest(&mut cursor, encoded.len() - 1).await.unwrap();

        let mut full = vec![encoded[0]];
        full.extend_from_slice(&rest);

        let (decoded, consumed) = FsRelayInitFrame::decode(&full).unwrap();
        assert_eq!(consumed, full.len(), "no leftover bytes");
        assert_eq!(decoded, original);

        let pos = cursor.position() as usize;
        assert_eq!(pos, encoded.len() - 1, "stream cursor at end");
    }

    #[tokio::test]
    async fn relay_init_frame_reader_roundtrip_no_credential() {
        let original = FsRelayInitFrame {
            mesh_id: b"mesh-z".to_vec(),
            chain_id: b"chain-w".to_vec(),
            chain_length: 2,
            chain_position: 1,
            client_suites: vec![AeadSuite::Aes256Gcm, AeadSuite::Aes128Gcm],
            client_eph_pub: [0x99u8; 32],
            expected_peer_table_generation: 100,
            prev_transcript: [0xFFu8; 32],
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };

        let encoded = original.encode().unwrap();
        let mut cursor = Cursor::new(&encoded[1..]);
        let rest = read_relay_init_frame_rest(&mut cursor, encoded.len() - 1).await.unwrap();

        let mut full = vec![encoded[0]];
        full.extend_from_slice(&rest);

        let (decoded, consumed) = FsRelayInitFrame::decode(&full).unwrap();
        assert_eq!(consumed, full.len(), "no leftover bytes");
        assert_eq!(decoded, original);

        let pos = cursor.position() as usize;
        assert_eq!(pos, encoded.len() - 1, "stream cursor at end");
    }
}
