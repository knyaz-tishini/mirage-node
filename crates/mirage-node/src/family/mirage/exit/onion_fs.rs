//! V9-FS forward-secret onion exit handler (Phase 5).
//!
//! Handles the terminal (exit) hop of a V9-FS circuit, identified by receiving an
//! `FsRelayInitFrame` (`MSG_FS_RELAY_INIT = 0x92`) after the wire-version peek.
//!
//! Flow:
//! 1. Read `FsRelayInitFrame` (relayed by the preceding hop).
//! 2. Negotiate suite, generate a per-session ephemeral.
//! 3. Call `peel_onion_fs_layer` → (layer_key, server_eph_pub, transcript_hash).
//! 4. Send `FsCreatedFrame` back upstream (which the relay chain will forward to the client).
//! 5. Read the first data frame (the client's initial user_data, encrypted through
//!    all N layer keys with the exit layer innermost).
//! 6. Peel our exit layer with `peel_reply_layer_v7`.
//! 7. Check for MUX magic (`b"MUX\0"`) — mirror the V8 exit mux upgrade.
//! 8. Read the `[2B len][target_utf8]` destination address.
//! 9. Apply the SSRF guard (`policy::is_blocked`).
//! 10. Connect to the destination and run bidirectional copy, wrapping replies
//!     with `wrap_reply_layer_v7` using the exit layer key.
//!
//! This handler is only reached when the dispatcher in `exit/onion.rs`
//! detects `MSG_FS_RELAY_INIT = 0x92`; that dispatcher's non-forward-secret
//! fallback was deleted 2026-09-02 (see its own module doc) and has no
//! bearing on this file.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use mirage_core::{
    crypto::{AeadSuite, CredentialParams, KeyPair, SpentSet, verify_credential_bound},
    error::MirageError,
};
use mirage_mux::tokio_compat::{SessionHandle, TokioIoCompat, TokioMuxStream};
use mirage_protocol::onion::{
    builder::peel_onion_fs_layer,
    fs_frame::{FsCreatedFrame, FsCreatedStatus, FsInitFrame, FsRelayInitFrame},
    layer::{peel_reply_layer_v7, wrap_reply_layer_v7},
};

use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use x25519_dalek::EphemeralSecret;

use crate::family::mirage::exit::policy;

/// Magic prefix that signals the client wants a mux session.
/// Must match the client-side constant exactly (same as V8 exit).
const MUX_MAGIC: &[u8] = b"MUX\0";

/// Server's AEAD suite preference, in priority order.
const SERVER_SUITE_PREFERENCE: &[AeadSuite] = &[
    AeadSuite::ChaCha20Poly1305,
    AeadSuite::Aes256Gcm,
    AeadSuite::Aes128Gcm,
];

/// Maximum frame size we accept.
const MAX_FRAME_BYTES: usize = 65_536;

/// Buffer size for per-chunk reply reading.
const REPLY_BUF_SIZE: usize = 32768;

/// Configuration passed in at accept time for an FS exit hop.
pub struct OnionFsExitConfig {
    /// Node's static keypair — used for node identity only; NOT used in FS key derivation.
    pub hop_keypair: Arc<KeyPair>,
    /// This hop's position in the circuit.
    pub chain_position: u8,
    /// Total number of hops in the circuit.
    pub chain_length: u8,
    /// This node's identity string (used in transcript binding).
    pub node_id: String,
    /// Hot-swappable credential parameters (gossip-updated). Credential
    /// enforcement is unconditional — `None` fails closed (nothing to verify
    /// against) rather than opening the relay.
    pub credential_params: Arc<ArcSwap<Option<CredentialParams>>>,
    /// Replay guard: tracks spent (epoch_id, credential_id) pairs.
    pub spent_set: Arc<Mutex<SpentSet>>,
    /// This node's own mesh — see `OnionExitV7Config::mesh_id`'s own doc.
    pub mesh_id: Vec<u8>,
    /// Shared, bounded single-use cache for `CredentialScheme::RoleSigned`
    /// dials — same Arc-identity requirement as `spent_set`.
    pub role_signed_replay: Arc<Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
}

fn negotiate_suite(client_suites: &[AeadSuite]) -> Option<AeadSuite> {
    SERVER_SUITE_PREFERENCE
        .iter()
        .find(|s| client_suites.contains(s))
        .copied()
}

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
    warn!(%peer, chain_position, status = status.name(), reason, "v9-fs exit: handshake error");
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

/// Read a `[2B BE len][target_utf8]` address from `stream`.
async fn read_length_prefixed_target<R>(stream: &mut R) -> Result<String, MirageError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    let target_len = u16::from_be_bytes(len_buf) as usize;
    if target_len == 0 {
        return Err(MirageError::Protocol(
            "v9-fs exit: zero-length target address".into(),
        ));
    }
    let mut target_buf = vec![0u8; target_len];
    stream.read_exact(&mut target_buf).await.map_err(MirageError::Io)?;
    std::str::from_utf8(&target_buf)
        .map(|s| s.to_owned())
        .map_err(|_| {
            MirageError::Protocol("v9-fs exit: target address is not valid UTF-8".into())
        })
}

/// Read a `[2B BE len][target_utf8]` address from a mux stream.
async fn read_mux_stream_target(stream: &mut TokioMuxStream) -> Result<String, MirageError> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    let target_len = u16::from_be_bytes(len_buf) as usize;
    if target_len == 0 {
        return Err(MirageError::Protocol(
            "v9-fs mux exit: zero-length target on stream".into(),
        ));
    }
    let mut target_buf = vec![0u8; target_len];
    stream.read_exact(&mut target_buf).await.map_err(MirageError::Io)?;
    std::str::from_utf8(&target_buf)
        .map(|s| s.to_owned())
        .map_err(|_| {
            MirageError::Protocol("v9-fs mux exit: stream target not valid UTF-8".into())
        })
}

/// Resolve a `host:port` string (or bare `SocketAddr`) to a `SocketAddr`.
///
/// Collects ALL resolved addresses and rejects the whole target if ANY address
/// is blocked by the SSRF policy.  An untrusted caller who mixes a public A-record with
/// a private one must not be able to connect.
async fn resolve_target_to_addr(target: &str) -> Result<SocketAddr, MirageError> {
    if let Ok(sa) = target.parse::<SocketAddr>() {
        if policy::is_blocked(sa.ip()) {
            warn!(ip = %sa.ip(), %target, "v9-fs mux exit: SSRF guard rejected literal addr");
            return Err(MirageError::Protocol(format!(
                "SSRF: blocked exit target {} (literal {})",
                sa.ip(), target
            )));
        }
        return Ok(sa);
    }

    use tokio::net::lookup_host;
    let addrs: Vec<SocketAddr> = lookup_host(target)
        .await
        .map_err(MirageError::Io)?
        .collect();
    if addrs.is_empty() {
        return Err(MirageError::Protocol(format!("v9-fs mux exit: no DNS result for {target}")));
    }
    for a in &addrs {
        if policy::is_blocked(a.ip()) {
            warn!(ip = %a.ip(), %target, "v9-fs mux exit: SSRF guard rejected target (mixed or private DNS)");
            return Err(MirageError::Protocol(format!(
                "SSRF: blocked exit target {} (resolved from {target})",
                a.ip()
            )));
        }
    }
    // Safety: non-empty checked above; no blocked addrs confirmed.
    Ok(addrs[0])
}

/// Run a single mux stream to completion (mirrors V8 `handle_mux_stream`).
async fn handle_mux_stream(mut mux_stream: TokioMuxStream) {
    let target = match read_mux_stream_target(&mut mux_stream).await {
        Ok(t) => t,
        Err(e) => {
            debug!(error = %e, "v9-fs mux exit: failed to read stream target");
            return;
        }
    };

    let dest_addr: SocketAddr = match resolve_target_to_addr(&target).await {
        Ok(a) => a,
        Err(e) => {
            debug!(target = %target, error = %e, "v9-fs mux exit: cannot resolve stream target");
            return;
        }
    };
    if policy::is_blocked(dest_addr.ip()) {
        warn!(ip = %dest_addr.ip(), target = %target, "v9-fs mux exit: SSRF blocked exit target");
        return;
    }

    let mut upstream = match TcpStream::connect(dest_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target = %target, error = %e, "v9-fs mux exit: stream target connect failed");
            return;
        }
    };

    debug!(target = %target, dest = %dest_addr, "v9-fs mux exit: stream connected");
    if let Err(e) = tokio::io::copy_bidirectional(&mut mux_stream, &mut upstream).await {
        debug!(target = %target, error = %e, "v9-fs mux exit: stream copy ended");
    }
}

/// V9-FS mux mode with wrapped reply path (mirrors V8 `run_mux_server_session_wrapped_v7`).
async fn run_fs_mux_server_session<S>(
    client_stream: S,
    suite: AeadSuite,
    layer_key: [u8; 32],
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(client_stream);
    let transport = FsWrapStream {
        reader,
        writer,
        suite,
        layer_key,
        write_pending: Vec::new(),
        write_offset: 0,
        read_frame: Vec::new(),
        read_plain: Vec::new(),
        read_plain_off: 0,
    };
    let compat = TokioIoCompat(transport);
    let session = SessionHandle::server(compat);
    loop {
        match session.accept_stream().await {
            Ok(stream) => {
                tokio::spawn(handle_mux_stream(TokioMuxStream(stream)));
            }
            Err(_) => {
                debug!("v9-fs mux exit: session closed");
                break;
            }
        }
    }
}

/// `AsyncRead + AsyncWrite` adapter that wraps writes with `wrap_reply_layer_v7`.
/// Mirrors V8 `WrapForwardingStreamV7`.
struct FsWrapStream<S> {
    reader: tokio::io::ReadHalf<S>,
    writer: tokio::io::WriteHalf<S>,
    suite: AeadSuite,
    layer_key: [u8; 32],
    write_pending: Vec<u8>,
    write_offset: usize,
    /// Partial inbound frame being assembled: `[4B BE len][body]`.
    read_frame: Vec<u8>,
    /// Peeled plaintext awaiting delivery to the mux session.
    read_plain: Vec<u8>,
    /// Bytes of `read_plain` already delivered.
    read_plain_off: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for FsWrapStream<S> {
    /// Forward path = inverse of `poll_write`. The client wraps every forward
    /// write with the exit layer key (`OnionFsTunnel::send`:
    /// `[4B BE len][wrap_reply_layer_v7(exit_key, data)]`). The mux session
    /// underneath us expects PLAINTEXT yamux bytes, so we must read one framed
    /// envelope, peel the exit layer with `peel_reply_layer_v7`, and serve the
    /// plaintext. Without this peel the yamux driver reads AEAD ciphertext as a
    /// frame header → "frame body is too large" → the onion-mux carry never
    /// flows (the 2026-06 data-plane regression). Symmetric to the reply wrap
    /// in `poll_write`.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // 1. Serve any peeled plaintext still buffered.
            if self.read_plain_off < self.read_plain.len() {
                let start = self.read_plain_off;
                let n = (self.read_plain.len() - start).min(buf.remaining());
                let chunk = self.read_plain[start..start + n].to_vec();
                buf.put_slice(&chunk);
                self.read_plain_off += n;
                if self.read_plain_off >= self.read_plain.len() {
                    self.read_plain.clear();
                    self.read_plain_off = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. How many more bytes does the current frame need? Read the 4-byte
            //    length prefix first, then exactly `len` body bytes — never
            //    overshoot into the next frame.
            let need = if self.read_frame.len() < 4 {
                4 - self.read_frame.len()
            } else {
                let len = u32::from_be_bytes([
                    self.read_frame[0],
                    self.read_frame[1],
                    self.read_frame[2],
                    self.read_frame[3],
                ]) as usize;
                if len == 0 || len > MAX_FRAME_BYTES {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "v9-fs mux: invalid forward frame length",
                    )));
                }
                (4 + len) - self.read_frame.len()
            };

            // 3. Pull up to `need` bytes from the underlying reader.
            let mut tmp = vec![0u8; need];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.reader).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        // Clean EOF — leave buf empty to signal it upstream.
                        return Poll::Ready(Ok(()));
                    }
                    self.read_frame.extend_from_slice(&tmp[..filled]);
                    // Full frame assembled? Peel the exit layer.
                    if self.read_frame.len() >= 4 {
                        let len = u32::from_be_bytes([
                            self.read_frame[0],
                            self.read_frame[1],
                            self.read_frame[2],
                            self.read_frame[3],
                        ]) as usize;
                        if self.read_frame.len() == 4 + len {
                            let body = self.read_frame[4..].to_vec();
                            match peel_reply_layer_v7(self.suite, &self.layer_key, &body) {
                                Ok(plain) => {
                                    self.read_plain = plain;
                                    self.read_plain_off = 0;
                                    self.read_frame.clear();
                                    // Loop to serve the freshly peeled plaintext.
                                }
                                Err(_) => {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "v9-fs mux: forward AEAD peel failed",
                                    )));
                                }
                            }
                        }
                        // else: need more body bytes — loop reads again.
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FsWrapStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_offset < self.write_pending.len() {
            let pending: Vec<u8> = self.write_pending[self.write_offset..].to_vec();
            match Pin::new(&mut self.writer).poll_write(cx, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    self.write_offset += n;
                    if self.write_offset < self.write_pending.len() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    self.write_pending.clear();
                    self.write_offset = 0;
                }
            }
        }

        let wrapped = match wrap_reply_layer_v7(self.suite, &self.layer_key, src) {
            Ok(w) => w,
            Err(_) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "v9-fs: wrap_reply_layer_v7 AEAD failed",
                )))
            }
        };
        let len = wrapped.len() as u32;
        let mut framed = Vec::with_capacity(4 + wrapped.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&wrapped);

        match Pin::new(&mut self.writer).poll_write(cx, &framed) {
            Poll::Pending => {
                self.write_pending = framed;
                self.write_offset = 0;
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                if n < framed.len() {
                    self.write_pending = framed[n..].to_vec();
                    self.write_offset = 0;
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Ok(src.len()))
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.write_offset < self.write_pending.len() {
            let pending: Vec<u8> = self.write_pending[self.write_offset..].to_vec();
            match Pin::new(&mut self.writer).poll_write(cx, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    self.write_offset += n;
                }
            }
        }
        self.write_pending.clear();
        self.write_offset = 0;
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// Handle a V9-FS exit hop connection.
///
/// The dispatcher in `exit/onion.rs` calls this after detecting `MSG_FS_RELAY_INIT`
/// as the first byte. The full frame body (including the leading type byte) has
/// already been read into `frame_body` by the dispatcher's version-peek.
/// `client_stream` is used only for writing the response back.
///
/// The dispatcher's non-forward-secret fallback is gone — see
/// `exit/onion.rs`'s module doc.
pub async fn handle_onion_fs_exit<S>(
    cfg: OnionFsExitConfig,
    mut client_stream: S,
    peer: SocketAddr,
    frame_body: Vec<u8>,
) -> Result<(), MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(
        %peer,
        chain_position = cfg.chain_position,
        total_hops = cfg.chain_length,
        "v9-fs exit: incoming FS circuit"
    );

    // ── 1. Parse the opening frame from the pre-read body ─────────────────────
    //
    // The dispatcher already read [4B len][frame_body]. WHICH frame that is
    // depends on where this node sits:
    //
    //   position > 0 — a relay forwarded `FsRelayInitFrame` (0x92);
    //   position == 0 — this node is the entry AND the exit, so there is no
    //                   relay in front of it and the CLIENT's own
    //                   `FsInitFrame` (0x0b) arrives here directly.
    //
    // Only the first case was handled, so a one-hop chain was answered with
    // BAD_VERSION — "wrong msg type 0x0b (expected 0x92)" — no matter what
    // else was correct. The relay path has always handled both shapes at this
    // seam (`onion_fs_peel`'s own position-0 branch); the exit had not.
    //
    // The two frames carry the same fields but one: `prev_transcript`, which a
    // relay forwards and the client never sends because at position 0 there is
    // nothing before it. That value is the base transcript, derived from
    // mesh_id and chain_id exactly as the relay derives it.
    let relay_init = if cfg.chain_position == 0 {
        let (init, _) = match FsInitFrame::decode(&frame_body) {
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
        let prev_transcript = mirage_protocol::onion::builder::compute_fs_transcript_base(
            &init.mesh_id,
            &init.chain_id,
        );
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
        match FsRelayInitFrame::decode(&frame_body) {
            Ok((v, _)) => v,
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

    // ── 2. Suite negotiation ──────────────────────────────────────────────────
    let suite = match negotiate_suite(&relay_init.client_suites) {
        Some(s) => s,
        None => {
            send_fs_error(
                &mut client_stream,
                cfg.chain_position,
                AeadSuite::ChaCha20Poly1305,
                FsCreatedStatus::NoCommonSuite,
                peer,
                &format!("no common suite in {:?}", relay_init.client_suites),
            )
            .await;
            return Ok(());
        }
    };

    // ── 3a. Credential verification (before key derivation / internet connect) ─
    // Mirrors `make_credential_auth` from `core/listener.rs`. Credential
    // enforcement is unconditional (no `require` toggle):
    //   params=None    → reject (fail closed — nothing to verify against)
    //   scheme=0x00    → reject (no-credential dial, always)
    //   scheme=non-zero → verify_credential_bound + replay check
    {
        let now_ms = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        };
        let guard = cfg.credential_params.load();
        let cred_ok = match guard.as_ref().as_ref() {
            None => {
                warn!(%peer, "v9-fs exit: rejecting dial — credentials mandatory but no params configured (fail closed)");
                false
            }
            Some(p) => {
                if relay_init.credential_scheme == 0x00 {
                    warn!(%peer, "v9-fs exit: rejecting no-credential dial (credentials mandatory)");
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
                            warn!(%peer, %refusal, "v9-fs exit: role_signed credential refused");
                            false
                        }
                    }
                } else {
                    // Bind the credential to THIS exit's node_id: a ring proof
                    // minted for another exit (or lifted by a malicious exit)
                    // fails here. The client mints against the exit hop's node_id;
                    // schemes without dial-context binding ignore it.
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
                            let mut s = match cfg.spent_set.lock() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            let fresh = s.record_and_check(epoch_id, cred_id);
                            if !fresh {
                                warn!(%peer, "v9-fs exit: rejecting replayed credential");
                            }
                            fresh
                        }
                        Err(e) => {
                            warn!(%peer, error = %e, "v9-fs exit: credential verify failed");
                            false
                        }
                    }
                }
            }
        };

        if !cred_ok {
            send_fs_error(
                &mut client_stream,
                cfg.chain_position,
                suite,
                FsCreatedStatus::CredentialRejected,
                peer,
                "credential rejected",
            )
            .await;
            return Ok(());
        }
    }

    // ── 3b. Generate per-session ephemeral, peel FS layer ────────────────────
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

    // ── 4. Send FsCreatedFrame back upstream ──────────────────────────────────
    let created = FsCreatedFrame {
        chain_position: relay_init.chain_position,
        suite,
        status: FsCreatedStatus::Ok,
        server_eph_pub,
        transcript_hash,
        auth_tag,
    };
    if let Err(e) = client_stream.write_all(&created.encode()).await {
        warn!(%peer, error = %e, "v9-fs exit: write FsCreated failed");
        return Err(MirageError::Io(e));
    }
    debug!(%peer, chain_position = relay_init.chain_position, "v9-fs exit: FsCreated sent");

    // ── 5. Read the first data frame (initial user_data) ─────────────────────
    // The client sends [4B len][AEAD-wrapped initial payload] after circuit setup.
    // Wrapped in a 15s timeout: a slow/stuck client must not pin the task indefinitely
    // before the circuit is fully established.
    let initial_frame = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        read_length_framed(&mut client_stream),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            warn!(%peer, error = %e, "v9-fs exit: initial data frame read failed");
            return Err(e);
        }
        Err(_) => {
            warn!(%peer, "v9-fs exit: initial data frame read timed out (15s)");
            return Err(MirageError::Protocol(
                "v9-fs exit: handshake timed out".into(),
            ));
        }
    };

    // ── 6. Peel our exit layer ────────────────────────────────────────────────
    // The exit layer is the innermost; peel_reply_layer_v7 removes it.
    let user_data = match peel_reply_layer_v7(suite, &layer_key, &initial_frame) {
        Ok(v) => v,
        Err(e) => {
            warn!(%peer, error = %e, "v9-fs exit: AEAD peel of initial data failed");
            return Err(e);
        }
    };

    // ── 7. MUX magic check ────────────────────────────────────────────────────
    if user_data.starts_with(MUX_MAGIC) {
        info!(%peer, suite = %suite.name(), "v9-fs exit: mux magic — upgrading to mux session");
        run_fs_mux_server_session(client_stream, suite, layer_key).await;
        return Ok(());
    }

    // ── 8. Read destination address ───────────────────────────────────────────
    // The destination arrives as [2B len][target_utf8] on the raw stream after
    // the initial user_data (which is empty in the FS case — user_data carries
    // just the routing prefix).
    //
    // In FS design the user_data from the peeled initial frame IS the target address
    // wrapped as [2B len][host:port]. We parse it directly from user_data bytes.
    let dest_str = {
        let mut cursor = std::io::Cursor::new(&user_data);
        let mut len_buf = [0u8; 2];
        std::io::Read::read_exact(&mut cursor, &mut len_buf).map_err(|e| {
            MirageError::Protocol(format!("v9-fs exit: read target len: {e}"))
        })?;
        let target_len = u16::from_be_bytes(len_buf) as usize;
        if target_len == 0 || target_len > user_data.len() - 2 {
            return Err(MirageError::Protocol(
                "v9-fs exit: invalid target length in user_data".into(),
            ));
        }
        let target_bytes = &user_data[2..2 + target_len];
        std::str::from_utf8(target_bytes)
            .map(|s| s.to_owned())
            .map_err(|_| {
                MirageError::Protocol("v9-fs exit: target address is not valid UTF-8".into())
            })?
    };

    // ── 9. SSRF guard ─────────────────────────────────────────────────────────
    let dest_addr = {
        use tokio::net::lookup_host;
        if let Ok(sa) = dest_str.parse::<SocketAddr>() {
            sa
        } else {
            let mut iter = lookup_host(dest_str.as_str())
                .await
                .map_err(MirageError::Io)?;
            iter.next().ok_or_else(|| {
                MirageError::Protocol(format!("v9-fs exit: no DNS for {dest_str}"))
            })?
        }
    };

    if policy::is_blocked(dest_addr.ip()) {
        warn!(ip = %dest_addr.ip(), %peer, "v9-fs exit: SSRF blocked exit target");
        return Err(MirageError::Protocol(format!(
            "v9-fs SSRF: blocked exit target {}",
            dest_addr.ip()
        )));
    }

    // ── 10. Connect to destination and relay ──────────────────────────────────
    info!(%peer, %dest_addr, "v9-fs exit: connecting to destination");
    let mut upstream = TcpStream::connect(dest_addr)
        .await
        .map_err(|e| MirageError::NodeUnreachable(format!("{dest_addr}: {e}")))?;

    // The remainder of user_data after the target address prefix is the actual initial payload.
    let initial_payload_start = 2 + {
        let len_bytes: [u8; 2] = user_data[..2].try_into().map_err(|_| {
            MirageError::Protocol("v9-fs exit: user_data too short for target".into())
        })?;
        u16::from_be_bytes(len_bytes) as usize
    };
    if initial_payload_start < user_data.len() {
        let payload = &user_data[initial_payload_start..];
        if !payload.is_empty() {
            upstream.write_all(payload).await.map_err(MirageError::Io)?;
        }
    }

    // Bidirectional relay. Two INDEPENDENT tasks joined (not select!) so that
    // `read_length_framed` on the forward path is never cancelled mid-frame — a
    // select! would drop a partially-read length-prefixed frame and desync the
    // stream. Mirrors the entry's `forward_fs_relay_loop`.
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut up_read, mut up_write) = upstream.into_split();

    // Forward path: each client frame is `[4B len][wrap_reply(exit_key, data)]`
    // (single exit-layer, transparently forwarded by intermediate hops). Peel our
    // layer and write the plaintext to the destination.
    let fwd = async {
        loop {
            match read_length_framed(&mut client_read).await {
                Err(_) => break,
                Ok(frame) => match peel_reply_layer_v7(suite, &layer_key, &frame) {
                    Ok(plaintext) => {
                        if up_write.write_all(&plaintext).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(%peer, error = %e, "v9-fs exit: forward data AEAD peel failed");
                        break;
                    }
                },
            }
        }
    };

    // Reply path: read raw bytes from the destination, wrap in the exit layer key,
    // length-frame, and send to the client (the relay chain adds its own layers).
    let reply = async {
        let mut rbuf = vec![0u8; REPLY_BUF_SIZE];
        loop {
            match up_read.read(&mut rbuf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => match wrap_reply_layer_v7(suite, &layer_key, &rbuf[..n]) {
                    Ok(wrapped) => {
                        let len = (wrapped.len() as u32).to_be_bytes();
                        if client_write.write_all(&len).await.is_err() {
                            break;
                        }
                        if client_write.write_all(&wrapped).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    };

    tokio::join!(fwd, reply);
    Ok(())
}

/// Read a length-prefixed frame `[4B BE len][bytes]`.
async fn read_length_framed<R>(stream: &mut R) -> Result<Vec<u8>, MirageError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(MirageError::Io)?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
        return Err(MirageError::Protocol(format!(
            "v9-fs exit: invalid frame length {frame_len}"
        )));
    }
    let mut buf = vec![0u8; frame_len];
    stream.read_exact(&mut buf).await.map_err(MirageError::Io)?;
    Ok(buf)
}
