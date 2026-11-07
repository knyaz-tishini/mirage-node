//! V9-FS forward-secret onion relay handler — DATAGRAM carriage (U5 Slice 4).
//!
//! `docs/mirage/plans/u5-datagram-telescopic-design-2026-09-09.md`. This is
//! the datagram twin of [`crate::family::mirage::relay::onion_fs_peel`]:
//! same key agreement, same per-hop telescopic extend loop, same silence
//! doctrine — but one frame per datagram, no `[4B len]` wrapper (the
//! datagram already is the frame boundary), and every rejection on this
//! path answers with NOTHING, never `send_fs_error`'s error `FsCreatedFrame`
//! (see the module doc's "Non-negotiable properties": a malformed frame and
//! a failed credential are one silence, same as a selector miss — this hop
//! writing an error frame back would make the FS-chain branch tellable apart
//! from a plain rejection on a signal the plane otherwise never gives an
//! unauthenticated dialer).
//!
//! Reached only from [`crate::core::udp_chain_splice::try_handle_fs_chain`],
//! which has already: peeled the classifier-token hello off, read this
//! hop's own opening datagram (`first_frame`), and resolved the listener
//! spec that names this hop as a `Relay`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mirage_core::crypto::AeadSuite;
use mirage_core::error::MirageError;
use mirage_core::local_dgram_endpoint::{DgramEnvelope, LocalDgramSocket};
use mirage_protocol::auth::v9::build_face_hello_bytes;
use mirage_protocol::core::udp_handshake::{FS_CHAIN_HELLO_FLAG, SAFE_UDP_HANDSHAKE_PAYLOAD_LEN};
use mirage_protocol::onion::builder::{compute_fs_transcript_base, peel_onion_fs_layer};
use mirage_protocol::onion::fs_frame::{
    FsCreatedFrame, FsCreatedStatus, FsExtendFrame, FsInitFrame, FsRelayInitFrame, MSG_FS_CREATED,
};
use mirage_protocol::onion::layer::{peel_layer_v7, wrap_reply_layer_v7};
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use x25519_dalek::EphemeralSecret;

use crate::core::udp_chain_splice::FsCreatedCache;
use crate::family::mirage::exit::policy;
use crate::family::mirage::relay::onion_fs_peel::OnionFsRelayConfig;

/// Server's AEAD suite preference, in priority order. Duplicated from
/// [`crate::family::mirage::relay::onion_fs_peel`]'s own copy rather than
/// shared — the stream relay and the stream exit already each carry an
/// independent copy of the identical list (`onion_fs_peel.rs`,
/// `onion_fs.rs`), so a third copy here for the datagram plane matches this
/// codebase's own established precedent rather than breaking it to save one
/// `use`.
const SERVER_SUITE_PREFERENCE: &[AeadSuite] =
    &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm, AeadSuite::Aes128Gcm];

fn negotiate_suite(client_suites: &[AeadSuite]) -> Option<AeadSuite> {
    SERVER_SUITE_PREFERENCE.iter().find(|s| client_suites.contains(s)).copied()
}

/// Bound on the pre-circuit handshake reads this hop makes off `inbound` —
/// the extend frame for each remaining hop, and the reply from whatever this
/// hop itself dials. Named sibling of `onion_fs_peel::handle_onion_fs_peel`'s
/// own function-local `FS_HANDSHAKE_TIMEOUT` (15s): duplicated rather than
/// imported because that constant is function-scoped in the stream file, not
/// a module item — the same value, the same reasoning (a slow/stuck peer
/// must not pin this hop's task indefinitely), reused as a named sibling per
/// the design doc's own naming convention for constants of this shape.
const FS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-session relay state, held on the stack of this function's own task —
/// no registry entry, no new table. Mirrors the stream relay's own "the
/// session state IS the task's local variables" (design doc Q2).
struct UdpFsRelaySession {
    layer_key: [u8; 32],
    suite: AeadSuite,
    /// Ephemeral, `.connect()`-ed to the next hop's face — one per session,
    /// never shared. A connected UDP socket is its own demux (design doc
    /// Q2): `.connect()` filters to exactly one peer at the kernel level, so
    /// `upstream.recv()` cannot return another session's bytes.
    upstream: UdpSocket,
}

/// Handle a V9-FS relay (entry or middle) hop's circuit setup and data relay
/// over datagram carriage.
///
/// `first_frame` is the whole datagram [`crate::core::udp_chain_splice::try_handle_fs_chain`]
/// already read and used to resolve this hop's spec — an `FsInitFrame`
/// (`cfg.chain_position == 0`) or an `FsRelayInitFrame` (forwarded by the
/// hop before this one).
pub(crate) async fn handle_udp_fs_peel(
    cfg: OnionFsRelayConfig,
    client_socket: &Arc<LocalDgramSocket>,
    face_port: u16,
    peer: SocketAddr,
    inbound: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    first_frame: Vec<u8>,
    fs_cache: &Arc<FsCreatedCache>,
) -> Result<(), MirageError> {
    debug!(
        %peer, hop_position = cfg.chain_position, total_hops = cfg.chain_length,
        "v9-fs udp relay: incoming FS-chain datagram session"
    );

    // ── 1. Decode the opening frame ───────────────────────────────────────
    // Whole-datagram decode, no incremental reader — see the module doc:
    // this is the one place datagram carriage is genuinely easier than
    // stream at (design doc Q1).
    let (
        mesh_id,
        chain_id,
        chain_length,
        chain_position,
        client_suites,
        client_eph_pub,
        prev_transcript,
        credential_scheme,
        credential,
    ) = if cfg.chain_position == 0 {
        let (init, _) = match FsInitFrame::decode(&first_frame) {
            Ok(v) => v,
            Err(e) => {
                warn!(%peer, error = %e, "v9-fs udp relay: FsInitFrame decode failed — answering nothing");
                return Ok(());
            }
        };
        if init.chain_length != cfg.chain_length {
            warn!(
                %peer, frame_length = init.chain_length, spec_length = cfg.chain_length,
                "v9-fs udp relay: chain_length mismatch — answering nothing"
            );
            return Ok(());
        }
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
        let (relay_init, _) = match FsRelayInitFrame::decode(&first_frame) {
            Ok(v) => v,
            Err(e) => {
                warn!(%peer, error = %e, "v9-fs udp relay: FsRelayInitFrame decode failed — answering nothing");
                return Ok(());
            }
        };
        if relay_init.chain_length != cfg.chain_length {
            warn!(
                %peer, frame_length = relay_init.chain_length, spec_length = cfg.chain_length,
                "v9-fs udp relay: chain_length mismatch — answering nothing"
            );
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

    // ── 2. Retransmit cache — before any new crypto or dial work ─────────
    // Keyed on `client_eph_pub`, the retry-loop-stable identity for THIS
    // hop's own setup request (design doc Q1). A cache hit means this hop's
    // own `FsCreatedFrame` for this session already went out once and the
    // client is retrying because it never arrived — resend the byte-
    // identical reply rather than re-deriving a second, different server
    // ephemeral for what is really one attempt.
    if let Some(cached) = fs_cache.get(&client_eph_pub) {
        client_socket
            .send_envelope(DgramEnvelope { face_port, peer }, &cached)
            .await
            .map_err(MirageError::Io)?;
        return Ok(());
    }

    // ── 3. Suite negotiation ──────────────────────────────────────────────
    let suite = match negotiate_suite(&client_suites) {
        Some(s) => s,
        None => {
            warn!(%peer, offered = ?client_suites, "v9-fs udp relay: no common suite — answering nothing");
            return Ok(());
        }
    };

    // ── 4. Peel this hop's own FS layer, send FsCreated ───────────────────
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
    let created = FsCreatedFrame {
        chain_position,
        suite,
        status: FsCreatedStatus::Ok,
        server_eph_pub,
        transcript_hash,
        auth_tag,
    };
    let created_bytes = created.encode();
    fs_cache.insert(client_eph_pub, created_bytes.to_vec());
    client_socket
        .send_envelope(DgramEnvelope { face_port, peer }, &created_bytes)
        .await
        .map_err(MirageError::Io)?;
    debug!(%peer, chain_position, "v9-fs udp relay: FsCreated sent");

    // ── 5. Extend loop — one iteration per remaining hop ───────────────────
    let remaining_hops = (chain_length as usize).saturating_sub(chain_position as usize + 1);
    if remaining_hops == 0 {
        // This hop is actually the exit; the listener resolved a Relay spec
        // at a terminal position, which the monitor should never mint. Not a
        // rejection — the client already got a valid FsCreated above — but
        // there is no next hop to extend to, so the session cannot proceed.
        warn!(%peer, chain_position, chain_length, "v9-fs udp relay: no remaining hops — chain misconfigured");
        return Err(MirageError::Protocol(
            "v9-fs udp relay: called at terminal position (use the exit handler)".into(),
        ));
    }

    let mut session: Option<UdpFsRelaySession> = None;

    for ext_idx in 0..remaining_hops {
        let extend_bytes = match tokio::time::timeout(FS_HANDSHAKE_TIMEOUT, inbound.recv()).await {
            Ok(Some((_, payload))) => payload,
            Ok(None) => return Ok(()),
            Err(_) => {
                debug!(%peer, ext_idx, "v9-fs udp relay: extend frame timed out — session ends");
                return Ok(());
            }
        };

        let (_next_hop, inner) = match peel_layer_v7(suite, &extend_bytes, &layer_key) {
            Ok(v) => v,
            Err(e) => {
                warn!(%peer, ext_idx, error = %e, "v9-fs udp relay: extend AEAD peel failed — answering nothing");
                return Ok(());
            }
        };

        if ext_idx == 0 {
            let (extend_frame, _) = match FsExtendFrame::decode(&inner) {
                Ok(v) => v,
                Err(e) => {
                    warn!(%peer, error = %e, "v9-fs udp relay: FsExtendFrame decode failed — answering nothing");
                    return Ok(());
                }
            };

            let relay_init = FsRelayInitFrame {
                mesh_id: mesh_id.clone(),
                chain_id: chain_id.clone(),
                chain_length,
                chain_position: extend_frame.chain_position,
                client_suites: extend_frame.client_suites,
                client_eph_pub: extend_frame.client_eph_pub,
                expected_peer_table_generation: extend_frame.expected_peer_table_generation,
                prev_transcript: extend_frame.prev_transcript,
                credential_scheme,
                credential: credential.clone(),
                selector_token: extend_frame.selector_token.clone(),
            };
            let relay_init_bytes = match relay_init.encode() {
                Ok(b) => b,
                Err(e) => {
                    warn!(%peer, error = %e, "v9-fs udp relay: FsRelayInitFrame encode failed");
                    return Err(e);
                }
            };

            let next_hop_addr = extend_frame.next_hop_addr.clone();
            let next_addr: SocketAddr = match next_hop_addr.parse() {
                Ok(a) => a,
                Err(_) => {
                    use tokio::net::lookup_host;
                    match lookup_host(next_hop_addr.as_str()).await {
                        Ok(mut iter) => match iter.next() {
                            Some(a) => a,
                            None => {
                                warn!(%peer, %next_hop_addr, "v9-fs udp relay: no DNS result for next hop — answering nothing");
                                return Ok(());
                            }
                        },
                        Err(e) => {
                            warn!(%peer, %next_hop_addr, error = %e, "v9-fs udp relay: DNS lookup for next hop failed — answering nothing");
                            return Ok(());
                        }
                    }
                }
            };

            if policy::is_blocked(next_addr.ip()) {
                warn!(ip = %next_addr.ip(), %peer, "v9-fs udp relay: SSRF blocked next-hop target — answering nothing");
                return Ok(());
            }

            debug!(%peer, %next_addr, "v9-fs udp relay: dialing next hop for extend");

            let (upstream, next_created) =
                match dial_next_hop(next_addr, &relay_init_bytes, FS_HANDSHAKE_TIMEOUT).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(%peer, %next_addr, error = %e, "v9-fs udp relay: next hop dial/handshake failed — answering nothing more");
                        return Err(e);
                    }
                };
            // Forward RAW fixed-size bytes — the SAME framing the client
            // used to read hop-0's own FsCreated. `FsCreatedFrame`'s fields
            // are all public, so the telescopic setup reply needs no
            // per-segment wrap at setup time (mirrors
            // `onion_fs_peel.rs`'s own step 5 comment).
            client_socket
                .send_envelope(DgramEnvelope { face_port, peer }, &next_created)
                .await
                .map_err(MirageError::Io)?;

            session = Some(UdpFsRelaySession { layer_key, suite, upstream });
        } else {
            let upstream = &session
                .as_ref()
                .expect("upstream established on ext_idx 0, still live for subsequent extends")
                .upstream;
            if let Err(e) = upstream.send(&inner).await {
                warn!(%peer, ext_idx, error = %e, "v9-fs udp relay: forward deep extend failed");
                return Err(MirageError::Io(e));
            }
            let next_created = match recv_fs_created(upstream, FS_HANDSHAKE_TIMEOUT).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(%peer, ext_idx, error = %e, "v9-fs udp relay: deep-extend FsCreated not received — answering nothing more");
                    return Err(e);
                }
            };
            client_socket
                .send_envelope(DgramEnvelope { face_port, peer }, &next_created)
                .await
                .map_err(MirageError::Io)?;
        }
    }

    let session = session.expect("upstream established during the extend loop above");
    debug!(%peer, chain_position, remaining_hops, "v9-fs udp relay: circuit established, entering data relay loop");
    forward_udp_fs_relay_loop(client_socket, face_port, peer, inbound, session).await;
    Ok(())
}

/// Bind an ephemeral socket, `.connect()` it to `next_addr`, send the
/// datagram twin of the classifier-token hello followed by
/// `relay_init_bytes`, and read+verify one `FsCreatedFrame` reply.
///
/// `next_addr` MUST already be SSRF-cleared by the caller — this function
/// does not check it. `pub(crate)`, mirroring
/// `udp_chain_splice::relay_to_target`'s own established precedent in this
/// crate: `policy::is_blocked` unconditionally refuses loopback (see that
/// function's own module for why), which would make the DIAL MECHANICS this
/// function adds impossible to prove end to end against a loopback fixture.
/// The SSRF gate itself stays in the caller, exercised on its own
/// (`a_relay_hop_whose_next_hop_dial_fails_answers_nothing_beyond_its_own_created_frame`);
/// this seam proves the mechanics are independent of how the address was
/// cleared.
pub(crate) async fn dial_next_hop(
    next_addr: SocketAddr,
    relay_init_bytes: &[u8],
    timeout: Duration,
) -> Result<(UdpSocket, Vec<u8>), MirageError> {
    let upstream = UdpSocket::bind("0.0.0.0:0").await.map_err(MirageError::Io)?;
    upstream
        .connect(next_addr)
        .await
        .map_err(|e| MirageError::NodeUnreachable(format!("{next_addr}: {e}")))?;

    // The datagram twin of `write_face_hello` — one throwaway
    // classifier-token datagram so the next hop's face admits this dial
    // exactly like a real client's, then the FsRelayInitFrame as a SEPARATE
    // raw datagram (design doc Q3, item 2-3).
    let mut hello = build_face_hello_bytes();
    hello[92] |= FS_CHAIN_HELLO_FLAG;

    // Retransmit the (hello, relay-init) PAIR, the way the client
    // retransmits its own opening pair, because this is UDP and a lost
    // datagram is ordinary rather than exceptional.
    //
    // This dial had exactly one attempt until 2026-09-09, and the client had
    // five. The asymmetry decided how deep a chain could get: a client that
    // treats loss as normal sits behind relays that treat it as fatal, so
    // every relay leg was a single point of failure and the failure rate
    // compounded with depth. Measured on a lab mesh that afternoon — 1 hop (no
    // relay dial at all) always carried bytes, 2 hops (one relay dial)
    // carried them about half the time, and 3-4 hops (two and three relay
    // dials) almost never did, with the failure point moving between
    // attempts. A moving failure point is what loss looks like; a broken
    // code path does not wander.
    //
    // Both datagrams go again on each attempt: the far side admits the flow
    // on the hello, so a relay-init that arrived without its hello would be
    // read by a face that never opened a session for it.
    // Fast and few, NOT slow and many. This budget nests inside the client's
    // own per-step wait, and the client is the one that gives up first: it
    // waits `500ms * (hop_index + 1)` for a step whose answer crosses every
    // relay in between. If a relay spent the whole 15s handshake timeout
    // retrying, the client would abandon the step long before the relay
    // finished — measured 2026-09-09, that is exactly what a 3-hop dial did,
    // failing at hop[2] while the middle relay was still patiently resending.
    //
    // Three attempts at the client's own 500ms cadence bounds one relay leg
    // at 1.5s, so a chain of N legs costs at most N * 1.5s and the client's
    // step budget (below, in `onion_tunnel_fs_udp.rs`) is sized to cover it.
    // Loss is absorbed once per leg rather than compounding into a wait
    // nobody upstream is willing to sit through.
    const DIAL_ATTEMPTS: u32 = 3;
    // Longer than the receiving perimeter's refused-session drain window,
    // deliberately.
    //
    // If the relay-init overtakes the hello on the wire, the far face
    // classifies it as not-wire and opens a 1000ms drain
    // (`REFUSED_SESSION_DRAIN_MS`, mirage-perimeter's `udp_relay.rs`), during
    // which EVERY datagram from this source is discarded without
    // reclassification — including the correct hello that follows. A retry
    // cadence shorter than that window spends all its attempts inside it and
    // cannot succeed no matter how many there are.
    //
    // Measured on a lab mesh 2026-09-09: at 500ms all three attempts landed inside
    // one drain window, the dialling relay reported a timeout, and the
    // receiving node logged nothing at all — because nothing reached it.
    // 1300ms puts each attempt past the window rather than racing it.
    const DIAL_ATTEMPT_INTERVAL: Duration = Duration::from_millis(1300);
    let per_attempt = DIAL_ATTEMPT_INTERVAL.min(timeout / DIAL_ATTEMPTS);
    let mut last_err: Option<MirageError> = None;
    // Space the two datagrams so the frame cannot overtake its own hello.
    //
    // They are sent back to back, and on some paths the second arrives
    // first. The far face then classifies a bare FsRelayInitFrame as
    // not-wire and opens a one-second drain in which every datagram from
    // this source is discarded — including the hello that was actually
    // ahead of it. Retrying does not help if the reordering is a property of
    // the path rather than luck: each attempt just opens a fresh drain.
    //
    // Measured on a lab mesh 2026-09-09: ru-hostkey could not complete a dial to
    // us-example-203.0.113.25 across three attempts, while the SAME destination
    // served an exit for a 3-hop chain in the same minute from a different
    // predecessor. The destination was fine; that one path reorders.
    //
    // 150ms is above the 42-156ms inter-box RTT measured that day, so the
    // hello is admitted before the frame is even sent. It costs one 150ms
    // pause per relay leg, paid once, against a failure mode no number of
    // retries can clear.
    const HELLO_SETTLE: Duration = Duration::from_millis(150);

    for attempt in 0..DIAL_ATTEMPTS {
        upstream.send(&hello).await.map_err(MirageError::Io)?;
        tokio::time::sleep(HELLO_SETTLE).await;
        upstream.send(relay_init_bytes).await.map_err(MirageError::Io)?;

        match recv_fs_created(&upstream, per_attempt).await {
            Ok(created) => return Ok((upstream, created)),
            Err(e) => {
                debug!(
                    %next_addr,
                    attempt,
                    error = %e,
                    "v9-fs udp relay: next hop did not answer this attempt — resending"
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        MirageError::HandshakeTimedOut(format!(
            "v9-fs udp relay: next hop {next_addr} sent no FsCreated in {DIAL_ATTEMPTS} attempts"
        ))
    }))
}

/// Read one reply datagram off `upstream` with a bounded timeout, and verify
/// it is a whole, correctly-typed `FsCreatedFrame` — the datagram twin of
/// `onion_fs_peel.rs`'s own "read + verify + forward" step, minus the
/// length-prefix that transport needs and this one does not.
async fn recv_fs_created(upstream: &UdpSocket, timeout: Duration) -> Result<Vec<u8>, MirageError> {
    let mut buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
    let n = match tokio::time::timeout(timeout, upstream.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(MirageError::Io(e)),
        Err(_) => {
            return Err(MirageError::HandshakeTimedOut(
                "v9-fs udp relay: next hop FsCreated timed out".into(),
            ))
        }
    };
    if n != FsCreatedFrame::ENCODED_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs udp relay: next hop's reply datagram had unexpected length {n} (expected {})",
            FsCreatedFrame::ENCODED_LEN
        )));
    }
    if buf[0] != MSG_FS_CREATED {
        return Err(MirageError::Protocol(format!(
            "v9-fs udp relay: expected FsCreated (0x{:02x}) from next hop, got 0x{:02x}",
            MSG_FS_CREATED, buf[0]
        )));
    }
    Ok(buf[..n].to_vec())
}

/// Data relay loop after the circuit is established: forward direction reads
/// a raw datagram from `inbound` (the party that dialed THIS hop — the
/// client if entry, the previous relay if a middle hop) and forwards it
/// bytes-unchanged to `upstream` — forward data carries only the EXIT
/// layer's own wrap (design doc's client module doc), so an intermediate
/// relay never touches it. Reply direction reads a raw datagram from
/// `upstream`, wraps it ONCE more with this hop's own `layer_key` (with a
/// `[4B len]` prefix inside the plaintext, matching
/// `OnionFsSession::unwrap_reply`'s own per-layer stripping contract on the
/// client), and forwards it to whoever dialed this hop.
async fn forward_udp_fs_relay_loop(
    client_socket: &Arc<LocalDgramSocket>,
    face_port: u16,
    peer: SocketAddr,
    inbound: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    session: UdpFsRelaySession,
) {
    let UdpFsRelaySession { layer_key, suite, upstream } = session;
    let mut up_buf = vec![0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN.max(4096)];
    loop {
        tokio::select! {
            forward = inbound.recv() => match forward {
                Some((_, payload)) => {
                    if let Err(e) = upstream.send(&payload).await {
                        warn!(%peer, error = %e, "v9-fs udp relay: forward data send failed");
                        break;
                    }
                }
                None => break,
            },
            result = upstream.recv(&mut up_buf) => match result {
                Ok(n) => {
                    let mut inner_framed = Vec::with_capacity(4 + n);
                    inner_framed.extend_from_slice(&(n as u32).to_be_bytes());
                    inner_framed.extend_from_slice(&up_buf[..n]);
                    match wrap_reply_layer_v7(suite, &layer_key, &inner_framed) {
                        Ok(wrapped) => {
                            if client_socket
                                .send_envelope(DgramEnvelope { face_port, peer }, &wrapped)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(%peer, error = %e, "v9-fs udp relay: reply wrap failed");
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!(%peer, error = %e, "v9-fs udp relay: upstream ended");
                    break;
                }
            },
        }
    }
}
