//! V9-FS forward-secret onion exit handler — DATAGRAM carriage (U5 Slice 4).
//!
//! `docs/mirage/plans/u5-datagram-telescopic-design-2026-09-09.md`. Datagram
//! twin of [`crate::family::mirage::exit::onion_fs`]: same credential gate,
//! same terminal-layer peel, same "relays do not verify credentials, only
//! the exit does" rule — but one frame per datagram, no length prefix
//! anywhere, and every rejection answers with NOTHING (see the module doc's
//! "Non-negotiable properties" — a credential rejection is silent here,
//! unlike the stream exit's `send_fs_error`, because writing an error frame
//! back would make the FS-chain branch's admission cost tellable apart from
//! zero on a plane whose whole rejection contract is silence).
//!
//! Reached only from [`crate::core::udp_chain_splice::try_handle_fs_chain`].
//! No mux support on this path — mux (`b"MUX\0"` upgrade to a yamux session)
//! is a stream-shaped multiplexing scheme with no datagram counterpart in
//! this design; out of scope here, not silently dropped.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mirage_core::crypto::{verify_credential_bound, AeadSuite};
use mirage_core::error::MirageError;
use mirage_core::local_dgram_endpoint::{DgramEnvelope, LocalDgramSocket};
use mirage_protocol::onion::builder::{compute_fs_transcript_base, peel_onion_fs_layer};
use mirage_protocol::onion::fs_frame::{FsCreatedFrame, FsCreatedStatus, FsInitFrame, FsRelayInitFrame};
use mirage_protocol::onion::layer::{peel_reply_layer_v7, wrap_reply_layer_v7};
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use x25519_dalek::EphemeralSecret;

use crate::core::doh::DoHResolver;
use crate::family::mirage::exit::direct::resolve_udp_target;
use crate::family::mirage::exit::onion::OnionExitV7Config;

/// Server's AEAD suite preference. Duplicated from
/// [`crate::family::mirage::exit::onion_fs`]'s own copy — see
/// `udp_fs_peel.rs`'s identical note for why a third copy here matches this
/// codebase's own established precedent.
const SERVER_SUITE_PREFERENCE: &[AeadSuite] =
    &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm, AeadSuite::Aes128Gcm];

fn negotiate_suite(client_suites: &[AeadSuite]) -> Option<AeadSuite> {
    SERVER_SUITE_PREFERENCE.iter().find(|s| client_suites.contains(s)).copied()
}

/// Bound on the pre-data-loop reads this hop makes off `inbound` — named
/// sibling of `onion_fs.rs`'s own function-local 15s read timeout; see
/// `udp_fs_peel.rs`'s identical constant for the full reasoning.
const FS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Idle timeout for the post-setup data relay loop — this exit's own real-
/// target leg. Named sibling of `udp_chain_splice::UDP_SESSION_TIMEOUT`
/// (60s): the identical value and reasoning apply verbatim (bound the
/// return-path wait so a target that stops answering does not pin this
/// task's task forever), duplicated because that constant is private to its
/// own module.
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Handle a V9-FS exit hop's circuit setup and data relay over datagram
/// carriage — the terminal position of a chain.
///
/// `first_frame` is the whole datagram [`crate::core::udp_chain_splice::try_handle_fs_chain`]
/// already read and used to resolve this hop's spec — an `FsInitFrame`
/// (`cfg.chain_position == 0`, a one-hop chain that is its own exit — see
/// `onion_fs.rs`'s own step-1 doc for why this shape is handled here too) or
/// an `FsRelayInitFrame` forwarded by the preceding relay hop.
pub async fn handle_udp_fs_exit(
    cfg: OnionExitV7Config,
    client_socket: &Arc<LocalDgramSocket>,
    face_port: u16,
    peer: SocketAddr,
    inbound: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    first_frame: Vec<u8>,
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    debug!(
        %peer, chain_position = cfg.chain_position, total_hops = cfg.chain_length,
        "v9-fs udp exit: incoming FS-chain datagram session"
    );

    // ── 1. Decode the opening frame ───────────────────────────────────────
    let relay_init = if cfg.chain_position == 0 {
        let (init, _) = match FsInitFrame::decode(&first_frame) {
            Ok(v) => v,
            Err(e) => {
                warn!(%peer, error = %e, "v9-fs udp exit: FsInitFrame decode failed — answering nothing");
                return Ok(());
            }
        };
        let prev_transcript = compute_fs_transcript_base(&init.mesh_id, &init.chain_id);
        FsRelayInitFrame {
            mesh_id: init.mesh_id,
            chain_id: init.chain_id,
            chain_length: init.chain_length,
            chain_position: init.chain_position,
            client_suites: init.client_suites,
            client_eph_pub: init.client_eph_pub,
            expected_peer_table_generation: init.expected_peer_table_generation,
            prev_transcript,
            credential_scheme: init.credential_scheme,
            credential: init.credential,
            selector_token: init.selector_token,
        }
    } else {
        match FsRelayInitFrame::decode(&first_frame) {
            Ok((v, _)) => v,
            Err(e) => {
                warn!(%peer, error = %e, "v9-fs udp exit: FsRelayInitFrame decode failed — answering nothing");
                return Ok(());
            }
        }
    };

    if relay_init.chain_length != cfg.chain_length {
        warn!(
            %peer, frame_length = relay_init.chain_length, spec_length = cfg.chain_length,
            "v9-fs udp exit: chain_length mismatch — answering nothing"
        );
        return Ok(());
    }

    // ── 2. Suite negotiation ──────────────────────────────────────────────
    let suite = match negotiate_suite(&relay_init.client_suites) {
        Some(s) => s,
        None => {
            warn!(%peer, offered = ?relay_init.client_suites, "v9-fs udp exit: no common suite — answering nothing");
            return Ok(());
        }
    };

    // ── 3. Credential verification, unconditional — before key derivation ─
    // Mirrors `onion_fs.rs`'s own step 3a verbatim in logic; the ONLY
    // difference from the stream exit is the outcome of a failure: no
    // `send_fs_error` datagram, ever — see this module's own doc.
    {
        let now_ms = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
        };
        let guard = cfg.credential_params.load();
        let cred_ok = match guard.as_ref().as_ref() {
            None => {
                warn!(%peer, "v9-fs udp exit: rejecting dial — credentials mandatory but no params configured — answering nothing");
                false
            }
            Some(p) => {
                if relay_init.credential_scheme == 0x00 {
                    warn!(%peer, "v9-fs udp exit: rejecting no-credential dial — answering nothing");
                    false
                } else if relay_init.credential_scheme
                    == mirage_core::mirage::wire::CredentialScheme::RoleSigned.as_u8()
                {
                    // Self-vouched, not authority-keyed — see
                    // `core::role_signed_gate`'s own doc.
                    let operator_pub = crate::core::bootstrap::operator_pubkey();
                    match crate::core::role_signed_gate::check_role_signed_dial(
                        &relay_init.credential,
                        &cfg.node_id,
                        &cfg.mesh_id,
                        now_ms,
                        &operator_pub,
                        &cfg.role_signed_replay,
                        |_self_id| None,
                    ) {
                        Ok(_self_id) => true,
                        Err(refusal) => {
                            warn!(%peer, %refusal, "v9-fs udp exit: role_signed credential refused — answering nothing");
                            false
                        }
                    }
                } else {
                    match verify_credential_bound(
                        p,
                        relay_init.credential_scheme,
                        &relay_init.credential,
                        now_ms,
                        cfg.node_id.as_bytes(),
                    ) {
                        Ok(cred_id) => {
                            let epoch_id = if relay_init.credential.len() >= 4 {
                                u32::from_be_bytes([
                                    relay_init.credential[0],
                                    relay_init.credential[1],
                                    relay_init.credential[2],
                                    relay_init.credential[3],
                                ])
                            } else {
                                0
                            };
                            let mut s =
                                cfg.spent_set.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                            let fresh = s.record_and_check(epoch_id, cred_id);
                            if !fresh {
                                warn!(%peer, "v9-fs udp exit: rejecting replayed credential — answering nothing");
                            }
                            fresh
                        }
                        Err(e) => {
                            warn!(%peer, error = %e, "v9-fs udp exit: credential verify failed — answering nothing");
                            false
                        }
                    }
                }
            }
        };
        if !cred_ok {
            return Ok(());
        }
    }

    // ── 4. Peel this hop's own FS layer, send FsCreated ────────────────────
    let server_eph = EphemeralSecret::random_from_rng(OsRng);
    let (layer_key, server_eph_pub, transcript_hash, auth_tag) = peel_onion_fs_layer(
        server_eph,
        &cfg.hop_keypair,
        &relay_init.client_eph_pub,
        relay_init.chain_position,
        &relay_init.prev_transcript,
        &cfg.node_id,
        suite,
    );
    let created = FsCreatedFrame {
        chain_position: relay_init.chain_position,
        suite,
        status: FsCreatedStatus::Ok,
        server_eph_pub,
        transcript_hash,
        auth_tag,
    };
    client_socket
        .send_envelope(DgramEnvelope { face_port, peer }, &created.encode())
        .await
        .map_err(MirageError::Io)?;
    debug!(%peer, chain_position = relay_init.chain_position, "v9-fs udp exit: FsCreated sent");

    // ── 5. Read the initial data frame ─────────────────────────────────────
    // One raw datagram, exit-layer-wrapped: the DATAGRAM plane's own
    // convention (`udp_chain_splice::parse_target_datagram`'s doc — bare,
    // trimmed ASCII `host:port`, no length prefix, no `udp:` prefix), the
    // same shape `udp_chain_splice::handle_udp_wire_exit`'s direct datagram
    // exit already reads and `OnionFsUdpTunnel::connect` / `mirage-dial-core`'s
    // `run_datagram_udp_session` already send — NOT the stream onion plane's
    // `[2B len][target]` framing. This exit used to read the stream plane's
    // shape here; that was the bug two conventions on one plane produced —
    // see this function's own module doc.
    let initial_frame = match tokio::time::timeout(FS_HANDSHAKE_TIMEOUT, inbound.recv()).await {
        Ok(Some((_, payload))) => payload,
        Ok(None) => return Ok(()),
        Err(_) => {
            debug!(%peer, "v9-fs udp exit: initial data frame timed out — session ends");
            return Ok(());
        }
    };

    // ── 6. Peel the exit layer ──────────────────────────────────────────────
    let user_data = match peel_reply_layer_v7(suite, &layer_key, &initial_frame) {
        Ok(v) => v,
        Err(e) => {
            warn!(%peer, error = %e, "v9-fs udp exit: AEAD peel of initial data failed — answering nothing");
            return Ok(());
        }
    };

    // ── 7. Parse the destination address ────────────────────────────────────
    // The datagram plane's own convention, reused rather than re-implemented
    // — see step 5's doc. The destination is not exposed by this: on an
    // FS chain this first datagram travelled inside the terminal onion
    // layer exactly like every later payload datagram (the AEAD open above
    // already peeled it), so it is as protected in transit as the payload
    // itself, never sent or read in the clear.
    let dest_str = match crate::core::udp_chain_splice::parse_target_datagram(&user_data) {
        Ok(s) => s,
        Err(e) => {
            warn!(%peer, error = %e, "v9-fs udp exit: first datagram is not a valid target — answering nothing");
            return Ok(());
        }
    };

    // ── 8. Resolve and SSRF-check the destination ───────────────────────────
    let dest_addr = match resolve_udp_target(dest_str, doh).await {
        Ok(a) => a,
        Err(e) => {
            warn!(%peer, target = %dest_str, error = %e, "v9-fs udp exit: destination resolution refused — answering nothing");
            return Ok(());
        }
    };

    // ── 9. Open the real target socket ────────────────────────────────────────
    // No buffered payload to forward here: the target is the WHOLE first
    // datagram on this plane, never `[target][payload]` packed together —
    // any real payload arrives as a later datagram through the relay loop
    // below, exactly like `udp_chain_splice::handle_udp_wire_exit`'s own
    // direct datagram exit.
    info_dial(&peer, &dest_addr);
    let target_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return Err(MirageError::Io(e)),
    };
    if let Err(e) = target_sock.connect(dest_addr).await {
        return Err(MirageError::Io(e));
    }

    // ── 10. Data relay loop ─────────────────────────────────────────────────
    forward_udp_fs_exit_loop(client_socket, face_port, peer, inbound, &target_sock, layer_key, suite).await;
    Ok(())
}

/// One `info!` call, split out only so the format string does not clutter
/// step 9 above.
fn info_dial(peer: &SocketAddr, dest_addr: &SocketAddr) {
    tracing::info!(%peer, %dest_addr, "v9-fs udp exit: connecting to destination");
}

/// Data relay loop after the circuit is established and the destination
/// socket is open.
///
/// Forward: read a raw datagram from `inbound` (single exit-layer wrapped —
/// forward data is never onion-wrapped, only the reply path is), peel with
/// this hop's own `layer_key`, forward the plaintext to the real target.
/// Reply: read a raw datagram from the target, wrap ONCE with the exit
/// layer's own key — no `[4B len]` framing inside, unlike a relay's own
/// reply wrap, because the exit is the LAST layer `OnionFsSession::unwrap_reply`
/// peels and expects nothing further inside it — and forward it to whoever
/// dialed this exit.
async fn forward_udp_fs_exit_loop(
    client_socket: &Arc<LocalDgramSocket>,
    face_port: u16,
    peer: SocketAddr,
    inbound: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    target_sock: &UdpSocket,
    layer_key: [u8; 32],
    suite: AeadSuite,
) {
    let mut target_buf = vec![0u8; 65_507];
    loop {
        tokio::select! {
            forward = inbound.recv() => match forward {
                Some((_, payload)) => match peel_reply_layer_v7(suite, &layer_key, &payload) {
                    Ok(plaintext) => {
                        if let Err(e) = target_sock.send(&plaintext).await {
                            warn!(%peer, error = %e, "v9-fs udp exit: send to target failed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(%peer, error = %e, "v9-fs udp exit: forward data AEAD peel failed");
                        break;
                    }
                },
                None => break,
            },
            result = tokio::time::timeout(UDP_SESSION_TIMEOUT, target_sock.recv(&mut target_buf)) => match result {
                Ok(Ok(n)) => match wrap_reply_layer_v7(suite, &layer_key, &target_buf[..n]) {
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
                        warn!(%peer, error = %e, "v9-fs udp exit: reply wrap failed");
                        break;
                    }
                },
                Ok(Err(e)) => {
                    warn!(%peer, error = %e, "v9-fs udp exit: recv from target failed");
                    break;
                }
                Err(_) => {
                    debug!(%peer, "v9-fs udp exit: idle timeout");
                    break;
                }
            },
        }
    }
}
