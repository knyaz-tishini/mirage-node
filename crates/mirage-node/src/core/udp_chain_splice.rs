//! The native-datagram counterpart of `family::mirage::exit::direct`'s
//! `[2B len]`-framed UDP exit — the datagram data-plane consumer named in
//! `docs/mirage/plans/datagram-data-plane-consumer-2026-09-05.md`.
//!
//! ## The defect this replaces, and why it lives in a new file
//!
//! `exit::direct::handle_udp_exit_tunnel` reads `[2B len][payload]` off a
//! `Box<dyn Tunnel>` and only then sends the payload as a real datagram —
//! correct for the SOCKS5 UDP-ASSOCIATE case, where the underlying tunnel
//! genuinely IS a reliable, ordered byte stream and a length prefix is the
//! only way to recover datagram boundaries that were never there. It is
//! wrong for a tunnel that already preserves datagram boundaries on its
//! own: a 2-byte read against a `MirageCoreUdpTunnel::recv_datagram()`
//! result either errors outright (the whole decrypted payload does not fit
//! a 2-byte caller buffer — see `MirageCoreUdpTunnel::recv`'s own
//! "truncation-proof" doc) or, even granted the length, the NEXT read
//! returns the next datagram entirely rather than the rest of this one.
//! That framed path is left completely alone — it stays for stream
//! tunnels, unchanged, in its own file. This module is its datagram
//! counterpart: one `MirageCoreUdpTunnel::recv_datagram` is one real UDP
//! datagram out, and one real UDP datagram in is one `Tunnel::send` back
//! through the tunnel. No length prefix anywhere, no accumulation across
//! reads, no buffering for reassembly.
//!
//! ## Fixed destination for the session, not carried per datagram
//!
//! The target travels once, as the session's first WHOLE datagram — an
//! ASCII `host:port` string, read via `MirageCoreUdpTunnel::recv_datagram`
//! exactly like every later payload datagram, never partially (a real
//! datagram tunnel has no partial reads to make). Every datagram after the
//! first is opaque payload from its first byte; it is never re-parsed for a
//! destination, and the first datagram is never itself forwarded as
//! payload.
//!
//! This is a decision, not the only option, and it has a cost. Carrying a
//! destination on every datagram was rejected because it would reintroduce
//! per-packet header parsing on the one path whose entire point is to avoid
//! that, and would spend wire bytes on every packet of a flow that is
//! overwhelmingly one-destination-per-session already (DNS, this exit's
//! flagship case, is one resolver for the life of many queries). The cost
//! of fixing the destination for the session's whole life is exactly what a
//! real `UdpSocket::connect` already commits to: a caller that needs a
//! DIFFERENT destination mid-session needs a new session, not a new
//! datagram shape — there is no way to redirect one already open.
//!
//! ## What this deliberately does NOT do
//!
//! No retransmit. No reordering guarantee — datagrams reach the real target
//! socket in the order [`MirageCoreUdpTunnel::recv_datagram`] returns them
//! (arrival order), and nothing here reorders before that. No reassembly —
//! there is no multi-datagram message concept anywhere in this module; one
//! tunnel datagram is one target datagram, full stop. No deduplication — a
//! legitimately duplicated application payload (the far side's own UDP
//! client retransmitted a query, say) is forwarded twice, because that is
//! indistinguishable from two genuine messages at this layer, and inventing
//! de-duplication here would be guessing at application semantics this exit
//! does not have. Losses, reordering and duplicates that occur upstream of
//! this module reach the real target exactly as delivered — that is the
//! contract, not a defect. A caller that needs ordering, retransmission or
//! reassembly wants `exit::direct::handle_exit` / `handle_exit_with_prefix`
//! over a `TunnelTcp` chain instead, which already gives exactly those
//! guarantees, at the per-packet cost this exit exists to avoid paying.
//!
//! ## Type separation from the framed exit
//!
//! [`handle_udp_wire_exit`] takes a concrete [`MirageCoreUdpTunnel`] **by
//! value** — never `Box<dyn Tunnel>` — and this module never boxes one into
//! a `dyn Tunnel` anywhere. The framed exit's entry points
//! (`exit::direct::handle_exit`, `handle_exit_with_prefix`) take
//! `Box<dyn Tunnel>` and are reachable only from TCP-listener call sites.
//! There is no shared function, no config flag and no runtime branch
//! between the two: a `MirageCoreUdpTunnel` built for this path has no
//! `Box<dyn Tunnel>` value it could be confused for, because nothing on
//! this path ever converts it into one. The two exits are kept apart by the
//! type graph itself, which a misconfiguration cannot defeat the way a
//! shared dispatch function guarded by a flag could be.
//!
//! ## The server: binding, demultiplexing, the handshake, and the session table
//!
//! Everything above this point takes a `MirageCoreUdpTunnel` as GIVEN. This
//! section is what builds one: [`serve`] binds the node's own
//! `NodeChainDgram` (`mirage_core::local_dgram_endpoint`) — the socket the
//! perimeter's `NodeChain`-purpose UDP face relays a classified-wire
//! datagram session into — and demultiplexes what arrives by
//! `(face_port, peer)`, mirroring `mirage_perimeter::udp_face::run_dispatcher`'s
//! own shape on the node's inward leg instead of the perimeter's public one.
//!
//! A datagram from an unknown key starts a session: its first datagram is
//! handed to [`run_server_handshake_v9_datagram`] against a shared
//! [`ServerHelloCache`] (so a retransmitted `ClientHello` re-sends the
//! identical reply rather than starting a second attempt); on success this
//! builds the [`UdpPeerSocket`] via `from_relay` and the tunnel via
//! `MirageCoreUdpTunnel::new`, and hands the tunnel to
//! [`handle_udp_wire_exit`] above.
//!
//! ### Which listener serves it
//!
//! Read off the `ClientHello` itself, BEFORE the handshake, because the AEAD
//! suite the handshake negotiates comes off the resolved spec. A hello
//! carrying a chain block names one hop of one chain and resolves through
//! `ListenerRegistry::resolve_datagram`; a hello without one is a plain
//! direct UDP exit and resolves through `single_udp_direct_exit` by mesh_id,
//! which is all this plane could express before the block existed.
//!
//! Resolving before authenticating is safe here and would not be on a
//! stream: every rejection on this path answers with nothing at all, so a
//! selector miss and a failed proof are one silence and the ordering leaks
//! nothing. That is a property the code owes, not one it inherits — a
//! rejection that ever writes a byte breaks it.
//!
//! This server authenticates nothing before a handshake completes, and the
//! peer address comes from a datagram the perimeter merely relayed on, so
//! the same forged-source spray that threatened the perimeter's own peer
//! map threatens this one — the session table is bounded the way that was
//! settled there ([`sweep_and_batch_evict`]): idle entries swept first, then
//! least-recently-seen evicted down to a low-water mark, never a hard
//! admission cap. This crate's own copy, not a cross-crate dependency on
//! `mirage-perimeter` — see that crate's `udp_face.rs` for the shape and the
//! reasoning this copies.
//!
//! ### The credential, and the one gap it does not close
//!
//! See [`datagram_client_auth`]'s own doc for the mechanics: a credential, when
//! the client offers one, rides appended directly after the fixed 97-byte
//! `ClientHello` in the same datagram — `[97B ClientHello][credential bytes]`,
//! no length prefix, one round trip. This exit runs the same
//! `make_credential_auth` gate as every other exit in the fleet, and that gate
//! can now actually be satisfied here, the same way it is everywhere else.
//!
//! What it does not close: the client proof and transcript bind `e_pub_c`, the
//! server's static key, the mesh id, the offered suites and the timestamp —
//! never the credential bytes, on this path any more than on the stream path
//! it was inherited from. An on-path party can therefore strip or swap a
//! credential without invalidating the proof; whatever protects against that
//! has to come from the credential scheme's own binding, not from this
//! handshake layer. Closing it here means changing the proof formula itself —
//! a wire-format change needing a coordinated fleet-wide version bump — and is
//! explicitly out of scope for this splice. Named, not silently absorbed.
//!
//! ### Lifecycle
//!
//! [`serve`]/[`run_server`] take a `CancellationToken`. Cancelling it stops
//! [`run_dispatcher`]'s own read loop AND every live session: `run_dispatcher`
//! drops its session table (and every entry's send half) on the way out,
//! which closes every live session's own inbound channel, which every
//! `UdpPeerSocket::recv`/`recv_datagram` call observes as a closed channel —
//! `MirageError::Io(ConnectionAborted)` — ending it. `run_server` tracks
//! every spawned session in a `JoinSet` and does not return until every one
//! of them has, which is the caller's proof that cancellation reached them
//! all, not merely that they were asked to stop.
//!
//! A session whose handshake fails is disposed of far sooner than that: the
//! handshake attempt itself is bounded (no I/O wait — the server side never
//! reads the socket during the handshake, see
//! `run_server_handshake_v9_datagram`'s own doc), so [`try_handle`] returns
//! and [`handle_udp_session`] evicts the table entry within, at most, a few
//! milliseconds — nowhere near [`PEER_IDLE_EVICT`]'s ten minutes.

use crate::family::mirage::exit::direct::resolve_udp_target;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mirage_core::error::MirageError;
use mirage_core::local_dgram_endpoint::{LocalDgramChannel, LocalDgramSocket};
use mirage_core::mirage::wire::{ExitMode, ListenerRole};
use mirage_protocol::auth::AuthMode;
use mirage_protocol::core::udp_handshake::{
    is_fs_chain_hello, parse_datagram_hello, run_server_handshake_v9_datagram, ServerHelloCache,
};
use mirage_protocol::core::MirageCoreUdpTunnel;
use mirage_protocol::onion::fs_frame::{
    FsInitFrame, FsRelayInitFrame, MSG_FS_RELAY_INIT, WIRE_VERSION_FS, WIRE_VERSION_FS_LEGACY,
};
use mirage_protocol::traits::{TransportInfo, Tunnel};
use mirage_protocol::transport::udp::UdpPeerSocket;
use mirage_protocol::ClientAuthContext;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::core::chain_splice::{warn_unaddressable, DisposalCause};
use crate::core::doh::DoHResolver;
use crate::core::registry::registry::ListenerRegistry;
use crate::core::registry::selector::ChainSelector;
use crate::core::runtime::NodeRuntime;
use crate::family::mirage::exit::udp_fs::handle_udp_fs_exit;
use crate::family::mirage::listener::tunnel_tcp::{
    bundle_from_spec, resolve_onion_exit_config, resolve_onion_relay_config, RelayDialResolution,
};
use crate::family::mirage::relay::onion_fs_peel::OnionFsRelayConfig;
use crate::family::mirage::relay::udp_fs_peel::handle_udp_fs_peel;

/// Practical UDP datagram ceiling for the real, internet-facing socket this
/// module opens. Restated rather than imported: the same 65507 fact already
/// lives independently as `exit::direct::MAX_UDP_DATAGRAM` (`pub(super)`,
/// not reachable from here) and as `mirage_protocol::core::udp_tunnel`'s own
/// `MAX_DGRAM` — a UDP wire fact, not application logic, so a third copy of
/// the same constant does not create a second source of truth for any
/// actual behaviour.
const MAX_UDP_DATAGRAM: usize = 65_507;

/// Idle timeout for the return-path relay loop in production, threaded into
/// [`relay_to_target`] as a parameter rather than read as a bare constant
/// there, so a test can drive the loop's idle-exit branch in milliseconds
/// instead of the real 60s.
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// The native-datagram counterpart of `exit::direct::handle_exit` — see this
/// module's own doc for what "native-datagram" buys and costs. Reads the
/// session's fixed destination off the tunnel's first whole datagram,
/// resolves it exactly as the framed exit does (DoH-aware, SSRF-checked),
/// then relays every later datagram in both directions, unframed.
pub async fn handle_udp_wire_exit(
    mut tunnel: MirageCoreUdpTunnel,
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    let first = tunnel.recv_datagram().await?;
    let target = parse_target_datagram(&first)?;

    let dest_addr = resolve_udp_target(target, doh).await?;
    debug!(target = %target, resolved = %dest_addr, "udp wire exit: opening UDP socket");

    relay_to_target(&mut tunnel, dest_addr, UDP_SESSION_TIMEOUT).await
}

/// Interpret the session's first whole datagram as an ASCII `host:port`
/// target string. Touches no socket and no policy — kept separate so "the
/// first datagram is read as the destination selector, not as payload" is
/// provable as a plain, deterministic function of its bytes alone.
///
/// `pub(crate)` so `family::mirage::exit::udp_fs::handle_udp_fs_exit` — the
/// FS-chain twin of [`handle_udp_wire_exit`] — reuses this SAME function for
/// its own first-datagram target parse instead of a second, divergent
/// implementation of the identical datagram-plane convention. Reused, not
/// copied: this is the one place "the first datagram is the destination
/// selector, not payload" is provable, plane-wide.
pub(crate) fn parse_target_datagram(first: &[u8]) -> Result<&str, MirageError> {
    let target = std::str::from_utf8(first)
        .map_err(|_| {
            MirageError::Protocol(
                "udp wire exit: first datagram is not a valid UTF-8 target".into(),
            )
        })?
        .trim();
    Ok(target)
}

/// Bind an ephemeral local socket, connect it to the already-resolved,
/// already-SSRF-cleared `dest_addr`, and relay.
///
/// `pub(crate)` so this module's own tests can drive the actual
/// datagram-splice mechanics (byte-for-byte relay, boundary preservation,
/// the return path, task lifecycle) directly against a real loopback
/// target. `exit::direct::resolve_udp_target`, which this module now CALLS rather
/// than restates, unconditionally refuses loopback —
/// which makes the FULL entry point impossible to exercise end-to-end
/// against a loopback bind in a test. The splice mechanics this module adds
/// are independent of how the destination was resolved, so they are proven
/// against this seam instead; the SSRF gate itself is exercised separately
/// (see the module's test for the first-datagram/destination behaviour).
pub(crate) async fn relay_to_target(
    tunnel: &mut MirageCoreUdpTunnel,
    dest_addr: SocketAddr,
    idle_timeout: Duration,
) -> Result<(), MirageError> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(MirageError::Io)?;
    sock.connect(dest_addr).await.map_err(MirageError::Io)?;
    udp_wire_relay_loop(tunnel, &sock, idle_timeout).await
}


/// Bidirectional relay between a `MirageCoreUdpTunnel` and a connected
/// `UdpSocket` — no framing on either side, because both already preserve
/// message boundaries.
///
/// This one future owns the whole session's life once [`relay_to_target`]
/// hands off to it: it ends the instant either side signals end-of-session
/// (a tunnel read/write error — including the `Relayed` backend's
/// `recv_relayed` returning `MirageError::Io` the moment whatever feeds
/// this tunnel's inbound channel drops it, e.g. a demux table entry being
/// evicted upstream), the real socket erroring, or `idle_timeout` elapsing
/// with nothing from the target. There is no separately spawned task on
/// this path — one future runs both directions through `tokio::select!`, so
/// "the session's task" and "this function's own caller" are the same
/// task, and it cannot outlive the session: it returns exactly when the
/// session ends, by construction, not by a separate cleanup step that could
/// be skipped or forgotten.
async fn udp_wire_relay_loop(
    tunnel: &mut MirageCoreUdpTunnel,
    sock: &UdpSocket,
    idle_timeout: Duration,
) -> Result<(), MirageError> {
    let mut out_buf = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            result = tunnel.recv_datagram() => match result {
                Ok(payload) => {
                    if let Err(e) = sock.send(&payload).await {
                        warn!("udp wire exit: send to target failed: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("udp wire exit: tunnel ended: {e}");
                    break;
                }
            },
            result = tokio::time::timeout(idle_timeout, sock.recv(&mut out_buf)) => match result {
                Ok(Ok(n)) => {
                    if tunnel.send(&out_buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    warn!("udp wire exit: recv from target failed: {e}");
                    break;
                }
                Err(_) => {
                    debug!("udp wire exit: idle timeout");
                    break;
                }
            },
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// The server: bind, demultiplex, handshake, hand off — see this module's
// own doc, "The server: binding, demultiplexing, the handshake, and the
// session table".
// ─────────────────────────────────────────────────────────────────────────

/// When the session table grows past this, idle entries are swept first; if
/// that alone does not bring it back under the trigger, least-recently-seen
/// entries are evicted next ([`evict_least_recent_until`]) down to
/// [`PEER_LOW_WATER_MARK`] — never a hard admission cap. This crate's own
/// copy of `mirage_perimeter::udp_face::PEER_SWEEP_TRIGGER` and its
/// reasoning: this server authenticates nothing before a handshake
/// completes, and the peer address comes from a datagram the perimeter
/// merely relayed on, so the identical forged-source spray threatens this
/// table. Duplicated rather than imported across crates — this crate has no
/// dependency on `mirage-perimeter` to share a helper with, and widening
/// that crate's API surface to save one `use` here is out of scope.
const PEER_SWEEP_TRIGGER: usize = 8192;

/// Low-water mark the least-recent fallback evicts DOWN TO once it runs at
/// all — not back to [`PEER_SWEEP_TRIGGER`] itself. See
/// `mirage_perimeter::udp_face::PEER_LOW_WATER_MARK`'s own doc for why
/// landing exactly on the trigger would make a sustained spray pay the whole
/// eviction cost on every subsequent admission instead of roughly once per
/// `PEER_SWEEP_TRIGGER / 8`.
const PEER_LOW_WATER_MARK: usize = PEER_SWEEP_TRIGGER - PEER_SWEEP_TRIGGER / 8;

/// A session that has sent nothing for this long is dropped by the sweep —
/// same value and reasoning as `mirage_perimeter::udp_face::PEER_IDLE_EVICT`.
const PEER_IDLE_EVICT: Duration = Duration::from_secs(600);

/// Bound on one session's own inbound channel.
const PEER_CHANNEL_CAPACITY: usize = 64;

/// Bound on the channel [`run_dispatcher`] announces new sessions over.
const SESSION_ANNOUNCE_CAPACITY: usize = 64;

/// One `(face_port, peer)` key's slot in [`run_dispatcher`]'s own session
/// table.
struct PeerEntry {
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    last_seen: Instant,
}

/// Evict entries from the session table, least-recently-seen first, until at
/// most `trigger` remain. Returns how many were removed.
///
/// This crate's own copy of `mirage_perimeter::udp_face::evict_least_recent_until`
/// — identical reasoning, keyed on `(u16, SocketAddr)` rather than a bare
/// `SocketAddr` because this table also carries the face port. Call this
/// AFTER the idle sweep and only when the sweep did not already clear the
/// trigger: a spoofed source-address spray mints a FRESH entry per packet,
/// and a fresh entry has a fresh `last_seen`, so the idle sweep frees none of
/// it.
fn evict_least_recent_until(
    peers: &mut HashMap<(u16, SocketAddr), PeerEntry>,
    trigger: usize,
) -> usize {
    if peers.len() <= trigger {
        return 0;
    }
    let mut by_age: Vec<((u16, SocketAddr), Instant)> =
        peers.iter().map(|(key, entry)| (*key, entry.last_seen)).collect();

    let to_remove = peers.len() - trigger;
    if to_remove < by_age.len() {
        by_age.select_nth_unstable_by_key(to_remove - 1, |(_, last_seen)| *last_seen);
    }

    let mut evicted = 0usize;
    for (key, _) in by_age.into_iter().take(to_remove) {
        if peers.remove(&key).is_some() {
            evicted += 1;
        }
    }
    evicted
}

/// Idle sweep, then — ONLY if the idle sweep did not already bring the table
/// back under `trigger` — batch-evict by least-recent `last_seen` down to
/// `low_water`. Returns `(idle_swept, lru_evicted)`.
///
/// This crate's own copy of `mirage_perimeter::udp_face::sweep_and_batch_evict`
/// — see that function's own doc for why the second stage targets
/// `low_water` rather than `trigger` itself.
fn sweep_and_batch_evict(
    peers: &mut HashMap<(u16, SocketAddr), PeerEntry>,
    trigger: usize,
    idle_evict: Duration,
    low_water: usize,
) -> (usize, usize) {
    let now = Instant::now();
    let before = peers.len();
    peers.retain(|_, e| now.duration_since(e.last_seen) < idle_evict);
    let idle_swept = before - peers.len();

    let lru_evicted = if peers.len() > trigger {
        evict_least_recent_until(peers, low_water)
    } else {
        0
    };
    (idle_swept, lru_evicted)
}

/// One demultiplexed `(face_port, peer)` session, announced the moment
/// [`run_dispatcher`] sees a key it has never seen before — this crate's own
/// narrower copy of `mirage_perimeter::udp_face::UdpSession`: there is
/// exactly one bound socket here (the node's own `NodeChainDgram`, box-local,
/// no IPv4-vs-IPv6 dual-stack split to carry), so the `socket`/`family`
/// fields that struct carries for the perimeter's own public-facing bind do
/// not apply.
struct NodeChainDgramSession {
    face_port: u16,
    peer: SocketAddr,
    /// The datagram that created this session — read once, directly, by
    /// [`try_handle`] as the V9 `ClientHello`. Never replayed through
    /// [`Self::inbound`].
    first_datagram: Vec<u8>,
    /// Every LATER datagram from this same `(face_port, peer)` — the exact
    /// shape [`UdpPeerSocket::from_relay`] consumes on its own `inbound`
    /// parameter, so a session's handshake hands this straight to it with no
    /// adapter in between.
    inbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    /// Ask [`run_dispatcher`]'s own table to drop this session's entry now,
    /// whether or not this peer ever speaks again — see that function's own
    /// doc for why dropping [`Self::inbound`] alone is not enough (the
    /// dispatcher would only notice on the NEXT datagram from this source,
    /// which may never come).
    evict: mpsc::UnboundedSender<(u16, SocketAddr)>,
}

/// Read [`LocalDgramChannel::NodeChainDgram`] forever, demultiplexing by
/// `(face_port, peer)` — the whole dispatcher. One task owns `socket`'s
/// receive half, matching `mirage_perimeter::udp_face::run_dispatcher`'s own
/// reasoning: the underlying socket is shared by every session, so exactly
/// one task may own it.
///
/// A brand new key is announced on `sessions` with its first datagram
/// attached; every later datagram for an already-announced key is forwarded
/// into that session's own inbound channel. A channel that is full (reader
/// stalled) or closed (session ended) is evicted at once and the SAME
/// datagram that discovered that falls through to start a fresh session —
/// matching `run_dispatcher`'s own "channel full or closed removes the entry
/// and this datagram starts a fresh attempt" rule.
///
/// `sweep_trigger`/`sweep_idle_evict`/`sweep_low_water` are parameters
/// rather than the bare constants above purely so this module's own tests
/// can exercise the sweep/evict logic in milliseconds against a handful of
/// peers instead of ten real minutes and 8192 real peers; [`run_server`]
/// always calls this with [`PEER_SWEEP_TRIGGER`]/[`PEER_IDLE_EVICT`]/
/// [`PEER_LOW_WATER_MARK`].
///
/// Ends when `cancel` fires, `sessions`'s receiving end is gone, or the
/// socket itself reports a fatal error — see the recv arm below for why a
/// malformed-but-short datagram does NOT end the loop while anything else
/// does: a closed or peer-less socket can never yield a live datagram again,
/// so retrying it forever would spin this task without ever serving
/// anything, rather than ending it the same way cancellation does. Either
/// way every entry still in the table — including its `tx` half — is
/// dropped on the way out, so any session still blocked on its own
/// `inbound.recv()` observes the channel close and ends on its own; see this
/// module's "Lifecycle" doc.
async fn run_dispatcher(
    socket: Arc<LocalDgramSocket>,
    sessions: mpsc::Sender<NodeChainDgramSession>,
    cancel: CancellationToken,
    sweep_trigger: usize,
    sweep_idle_evict: Duration,
    sweep_low_water: usize,
) {
    let mut peers: HashMap<(u16, SocketAddr), PeerEntry> = HashMap::new();
    let (evict_tx, mut evict_rx) = mpsc::unbounded_channel::<(u16, SocketAddr)>();
    // Consecutive malformed-datagram rejections (see the recv arm below).
    // The first one in a streak is logged at `warn`; every one after it —
    // the same source keeps sending garbage, or a rebind's own liveness
    // probe keeps landing here — drops to `debug` instead of spamming one
    // `warn!` per datagram. Reset on every datagram that DOES decode, so a
    // fresh run of malformed traffic is still announced once.
    let mut malformed_streak: u64 = 0;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                info!("[udp-chain-splice] retiring — no longer dispatching, releasing the socket");
                break;
            }
            Some(key) = evict_rx.recv() => {
                peers.remove(&key);
                continue;
            }
            recvd = socket.recv_envelope() => {
                let (envelope, mut payload) = match recvd {
                    Ok(pair) => pair,
                    // `DgramEnvelope::decode` is the ONLY source of
                    // `InvalidData` on this path — a datagram that arrived
                    // fine at the socket level but is too short to be one
                    // of ours (e.g. the zero-length probe a rebind attempt
                    // sends at this same path to test liveness). The socket
                    // itself is still alive; back off the logging instead
                    // of ending the loop.
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        malformed_streak += 1;
                        if malformed_streak == 1 {
                            warn!(
                                error = %e,
                                "[udp-chain-splice] recv: malformed datagram — socket still live, \
                                 continuing (further ones in this streak are logged at debug)"
                            );
                        } else {
                            debug!(error = %e, streak = malformed_streak, "[udp-chain-splice] recv: malformed datagram");
                        }
                        continue;
                    }
                    // Anything else is a fatal socket-level failure. A
                    // closed or peer-less socket cannot ever produce a live
                    // datagram again, so retrying it here forever would
                    // spin this task without ever serving anything — end
                    // the dispatcher the same way cancellation does.
                    Err(e) => {
                        warn!(error = %e, "[udp-chain-splice] recv failed fatally — retiring, releasing the socket");
                        break;
                    }
                };
                malformed_streak = 0;
                let key = (envelope.face_port, envelope.peer);

                if let Some(entry) = peers.get_mut(&key) {
                    entry.last_seen = Instant::now();
                    let tx = entry.tx.clone();
                    match tx.try_send((envelope.peer, payload)) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full((_, returned))) => {
                            debug!(
                                peer = %envelope.peer, face_port = envelope.face_port,
                                "[udp-chain-splice] session channel full (reader stalled) — evicting; \
                                 the next datagram from this source starts a fresh session"
                            );
                            peers.remove(&key);
                            payload = returned;
                            // Fall through: this datagram creates the fresh session.
                        }
                        Err(mpsc::error::TrySendError::Closed((_, returned))) => {
                            debug!(
                                peer = %envelope.peer, face_port = envelope.face_port,
                                "[udp-chain-splice] session channel closed (session ended) — the next \
                                 datagram from this source starts a fresh session"
                            );
                            peers.remove(&key);
                            payload = returned;
                            // Fall through: this datagram creates the fresh session.
                        }
                    }
                }

                if peers.len() > sweep_trigger {
                    let (idle_swept, lru_evicted) =
                        sweep_and_batch_evict(&mut peers, sweep_trigger, sweep_idle_evict, sweep_low_water);
                    if idle_swept > 0 || lru_evicted > 0 {
                        debug!(
                            idle_swept, lru_evicted, remaining = peers.len(),
                            "[udp-chain-splice] session table pressure — swept"
                        );
                    }
                }

                let (tx, rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
                peers.insert(key, PeerEntry { tx, last_seen: Instant::now() });

                let session = NodeChainDgramSession {
                    face_port: envelope.face_port,
                    peer: envelope.peer,
                    first_datagram: payload,
                    inbound: rx,
                    evict: evict_tx.clone(),
                };
                if sessions.send(session).await.is_err() {
                    debug!(
                        "[udp-chain-splice] session announce channel closed — nobody is consuming new \
                         sessions, stopping the dispatcher"
                    );
                    break;
                }
            }
        }
    }
    // Whether this ended by cancellation or the consumer going away, every
    // entry still in the table is dropped here — including its `tx` — so
    // any session still blocked on its own `inbound.recv()` observes the
    // channel close and ends on its own. See this module's "Lifecycle" doc.
    drop(peers);
}

/// Bind the node's inward UDP chain relay and serve it until `cancel` fires.
///
/// Mirrors `core::chain_splice::serve`'s own shape (bind, then serve) with
/// one addition this server's own brief calls for: a [`CancellationToken`]
/// that actually stops the reader AND every live session — see this
/// module's "Lifecycle" doc.
pub async fn serve(registry: Arc<ListenerRegistry>, cancel: CancellationToken) -> std::io::Result<()> {
    let socket = Arc::new(LocalDgramChannel::NodeChainDgram.bind().await?);
    info!(
        channel = LocalDgramChannel::NodeChainDgram.label(),
        endpoint = %LocalDgramChannel::NodeChainDgram.endpoint(),
        "[udp-chain-splice] serving the node's inward UDP chain relay"
    );
    run_server(socket, registry, cancel).await;
    Ok(())
}

/// The consumer loop proper — split from [`serve`] so a test can drive it
/// against a loopback-bound [`LocalDgramSocket`] instead of the fixed
/// production rendezvous socket [`LocalDgramChannel::NodeChainDgram::bind`]
/// insists on. Spawns [`run_dispatcher`] (sharing `cancel`), reads the
/// sessions it announces and spawns [`handle_udp_session`] for each,
/// tracking every spawn in a `JoinSet` — the mechanism that makes
/// cancellation provable: this function does not return until every session
/// it ever spawned has too.
async fn run_server(socket: Arc<LocalDgramSocket>, registry: Arc<ListenerRegistry>, cancel: CancellationToken) {
    let (sessions_tx, mut sessions_rx) = mpsc::channel(SESSION_ANNOUNCE_CAPACITY);
    let cache = Arc::new(ServerHelloCache::new());
    let fs_cache = Arc::new(FsCreatedCache::new());
    let dispatcher = tokio::spawn(run_dispatcher(
        Arc::clone(&socket),
        sessions_tx,
        cancel.clone(),
        PEER_SWEEP_TRIGGER,
        PEER_IDLE_EVICT,
        PEER_LOW_WATER_MARK,
    ));

    let mut live = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            maybe_session = sessions_rx.recv() => match maybe_session {
                Some(session) => {
                    live.spawn(handle_udp_session(
                        Arc::clone(&socket),
                        session,
                        Arc::clone(&registry),
                        Arc::clone(&cache),
                        Arc::clone(&fs_cache),
                    ));
                }
                None => break,
            },
        }
    }

    // Every session this server ever spawned is tracked above — joining
    // here is the proof that cancellation stops not just the reader but
    // every live session too, not merely that they were asked to.
    while live.join_next().await.is_some() {}
    let _ = dispatcher.await;
}

/// Run one session end to end: handshake, then tunnel, then exit. Always
/// asks [`run_dispatcher`]'s own table to drop this session's entry on the
/// way out, whether it ever built a tunnel or not — the same disposal path a
/// short-lived (handshake-failed) session and a long-lived (relaying)
/// session both take, so neither waits on the idle sweep.
///
/// # The FS-chain branch
///
/// [`is_fs_chain_hello`] is a length-and-one-bit peek at the session's own
/// FIRST-EVER datagram — never re-checked against anything later in the
/// session — so a session is either FS-chain for its whole life or never is;
/// see U5 design doc decision (A). The classifier-token hello itself is
/// discarded here exactly as it is: its content is never parsed, only its
/// shape.
async fn handle_udp_session(
    socket: Arc<LocalDgramSocket>,
    session: NodeChainDgramSession,
    registry: Arc<ListenerRegistry>,
    cache: Arc<ServerHelloCache>,
    fs_cache: Arc<FsCreatedCache>,
) {
    let NodeChainDgramSession { face_port, peer, first_datagram, inbound, evict } = session;
    let result = if is_fs_chain_hello(&first_datagram) {
        try_handle_fs_chain(&socket, face_port, peer, inbound, &registry, &fs_cache).await
    } else {
        try_handle(&socket, face_port, peer, first_datagram, inbound, &registry, &cache).await
    };
    if let Err(e) = result {
        debug!(
            %peer, face_port, error = %e,
            "[udp-chain-splice] session ended without a live tunnel"
        );
    }
    let _ = evict.send((face_port, peer));
}

/// This crate's own per-listener cache of the last `FsCreatedFrame` sent for
/// a given `client_eph_pub` — a renamed, generically-typed clone of
/// [`ServerHelloCache`]'s existing `Mutex<HashMap<[u8; 32], Vec<u8>>>` shape
/// (U5 design doc Q1). One instance per FS-capable listener PROCESS
/// (constructed once in [`run_server`], mirroring [`ServerHelloCache`]'s own
/// lifetime), not per hop or per session — every FS-chain session this node
/// ever serves shares the one instance.
///
/// Entries are inserted only after a successful peel of THIS hop's own FS
/// layer — the FS plane's own proof — mirroring [`ServerHelloCache`]'s
/// identical "inserted only after proof verification" rule. A cache hit lets
/// a retransmitted setup datagram (the client's step-0 pair, or a bare
/// step-`i` frame) get the byte-identical reply resent instead of this hop
/// deriving a second, different server ephemeral for what is really one
/// attempt — see the design doc's own "a stale reply racing a fresh one
/// cannot desync the client" reasoning.
pub(crate) struct FsCreatedCache {
    inner: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl FsCreatedCache {
    pub(crate) fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub(crate) fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(key).cloned()
    }

    pub(crate) fn insert(&self, key: [u8; 32], value: Vec<u8>) {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key, value);
    }
}

/// The datagram analogue of `core::chain_splice::resolve_chain_frame` +
/// `handle_one`'s role dispatch, collapsed into one function — this one
/// already lives inside the UDP-specific session machinery and has no reason
/// to be elsewhere (U5 design doc Q2).
///
/// Reads *one more* datagram off `inbound` (the classifier-token hello was
/// already consumed as this session's own `first_datagram` — see
/// [`handle_udp_session`]), bounded by [`FS_CHAIN_HANDSHAKE_TIMEOUT`], peeks
/// byte 0 to tell an `FsInitFrame` from an `FsRelayInitFrame`, resolves the
/// listener via [`ListenerRegistry::resolve_for_frame_udp`], and dispatches
/// by the RESOLVED SPEC'S ROLE — never by anything the frame claimed, the
/// identical doctrine `chain_splice::handle_one` already enforces on the
/// stream plane.
///
/// Every rejection on this path returns `Ok(())` and writes nothing to the
/// peer — a selector miss, a malformed frame, and a role this node does not
/// serve on this path are one silence (see the module's own "Non-negotiable
/// properties").
async fn try_handle_fs_chain(
    socket: &Arc<LocalDgramSocket>,
    face_port: u16,
    peer: SocketAddr,
    mut inbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    registry: &Arc<ListenerRegistry>,
    fs_cache: &Arc<FsCreatedCache>,
) -> Result<(), MirageError> {
    /// Bound on the ONE extra read this function makes before dispatching —
    /// named sibling of `onion_fs_peel.rs`'s own function-local 15s
    /// pre-circuit handshake timeout; duplicated rather than imported for
    /// the same reason `udp_fs_peel.rs`'s and `udp_fs.rs`'s own copies are:
    /// that constant is function-scoped in the stream file, not a module
    /// item.
    const FS_CHAIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

    // Read forward until an opening FRAME arrives, skipping repeats of the
    // classifier hello.
    //
    // A relay dials by sending two datagrams — the hello, then the opening
    // frame — and retransmits BOTH when the frame goes missing (see
    // `udp_fs_peel::dial_next_hop`). The hello is admitted by the face and
    // spliced through to here like any other datagram, so on a retransmit
    // this loop sees hello, hello, frame rather than just the frame.
    //
    // Until 2026-09-09 the first datagram was taken as the opening frame
    // unconditionally: a repeat hello hit the `other =>` arm below, was
    // refused by wire byte, and the session was torn down — so the relay's
    // retransmit could not work even once the wire delivered it. Measured on
    // MESH1: 3- and 4-hop chains failed with the dialling relay reporting a
    // timeout and this node logging a refusal for wire_byte=9, the hello's
    // own version byte.
    //
    // Bounded by the same handshake timeout, and every skipped datagram must
    // be exactly a hello — anything else still falls through to the byte
    // check, so this widens what a retransmit may look like without widening
    // what this node will act on.
    let frame = loop {
        let candidate = match tokio::time::timeout(FS_CHAIN_HANDSHAKE_TIMEOUT, inbound.recv()).await {
            Ok(Some((_, payload))) => payload,
            Ok(None) => return Ok(()),
            Err(_) => {
                debug!(%peer, face_port, "[udp-chain-splice] FS-chain session: no opening frame — answering nothing");
                return Ok(());
            }
        };
        if is_fs_chain_hello(&candidate) {
            debug!(
                %peer,
                "[udp-chain-splice] FS-chain session: repeat classifier hello — waiting for the frame behind it"
            );
            continue;
        }
        break candidate;
    };

    let Some(&first_byte) = frame.first() else {
        warn!(%peer, "[udp-chain-splice] FS-chain session: empty opening datagram — answering nothing");
        return Ok(());
    };

    let (chain_id, chain_position, chain_length, selector_token) = match first_byte {
        WIRE_VERSION_FS | WIRE_VERSION_FS_LEGACY => match FsInitFrame::decode(&frame) {
            Ok((init, _)) => (init.chain_id, init.chain_position, init.chain_length, init.selector_token),
            Err(e) => {
                warn!(%peer, error = %e, "[udp-chain-splice] FS-chain session: FsInitFrame decode failed — answering nothing");
                return Ok(());
            }
        },
        MSG_FS_RELAY_INIT => match FsRelayInitFrame::decode(&frame) {
            Ok((relay, _)) => (relay.chain_id, relay.chain_position, relay.chain_length, relay.selector_token),
            Err(e) => {
                warn!(%peer, error = %e, "[udp-chain-splice] FS-chain session: FsRelayInitFrame decode failed — answering nothing");
                return Ok(());
            }
        },
        other => {
            warn!(%peer, wire_byte = other, "[udp-chain-splice] FS-chain session: not a forward-secret opening frame — answering nothing");
            return Ok(());
        }
    };

    let runtime = registry.runtime();
    let spec = match registry
        .resolve_for_frame_udp(&chain_id, chain_position, chain_length, &selector_token)
        .await
    {
        Some(spec) => spec,
        None => {
            let selector = ChainSelector::from_frame(&selector_token, &chain_id, chain_position);
            let bound = registry.chain_spec_count().await;
            warn_unaddressable(&peer.to_string(), DisposalCause::NoSuchListener, &selector, chain_position, bound);
            return Ok(());
        }
    };

    let bundle = bundle_from_spec(&spec);
    let own_node_id = runtime.snapshot.load().node_config.node_id.clone();
    let chain_id_str = spec.chain_role.as_ref().map(|r| r.chain_id.as_str());

    match &spec.role {
        ListenerRole::Exit { .. } => {
            let cfg =
                resolve_onion_exit_config(bundle.chain_position, bundle.chain_length, &bundle.chain_node_ids, &runtime);
            handle_udp_fs_exit(cfg, socket, face_port, peer, &mut inbound, frame, registry.ctx_doh()).await
        }
        ListenerRole::Relay { .. } => {
            match resolve_onion_relay_config(
                bundle.chain_position,
                bundle.chain_length,
                &bundle.chain_node_ids,
                chain_id_str,
                own_node_id.as_str(),
                &runtime,
            ) {
                RelayDialResolution::Dial(cfg) => {
                    // Same field-by-field conversion `onion_peel::handle_onion_peel`
                    // already does before calling the stream relay handler —
                    // `resolve_onion_relay_config` is reused UNMODIFIED (U5
                    // design doc Q2), so its `OnionRelayConfig` return type is
                    // exactly what it already was; the FS handler's own
                    // config type is a separate struct with the same fields.
                    let fs_cfg = OnionFsRelayConfig {
                        hop_keypair: cfg.hop_keypair,
                        chain_position: cfg.chain_position,
                        chain_length: cfg.chain_length,
                        node_id: cfg.node_id,
                        outgoing_camouflage: cfg.outgoing_camouflage,
                        next_hop_pubkey: cfg.next_hop_pubkey,
                        outgoing_sni: cfg.outgoing_sni,
                    };
                    handle_udp_fs_peel(fs_cfg, socket, face_port, peer, &mut inbound, frame, fs_cache).await
                }
                RelayDialResolution::Refused { reason } => {
                    warn!(
                        peer = %peer,
                        chain_id = ?chain_id_str,
                        reason = %reason,
                        "[udp-chain-splice] FS-chain session: refusing relay hop — next hop has no dialable chain face — answering nothing"
                    );
                    Ok(())
                }
            }
        }
    }
}

/// The authorization gate for a V9 datagram handshake attempt.
///
/// # The same gate as every other exit — now satisfiable here too
///
/// Every OTHER data-plane path in this fleet enforces mandatory credentials
/// via `crate::core::listener::make_credential_auth`, which rejects
/// `scheme_byte == 0x00` UNCONDITIONALLY (`params == None` fails closed;
/// `params == Some` still refuses a no-credential dial). The datagram
/// handshake used to be the one path that could never satisfy it —
/// `run_server_handshake_v9_datagram` could only ever see `cred_scheme ==
/// 0x00`, because the wire had nowhere to put a credential. Wiring
/// `make_credential_auth` in under that constraint would not have secured
/// this path, it would have refused every real client unconditionally: dead
/// on arrival, not defended.
///
/// That constraint is gone. A credential, when the client sends one, rides
/// appended directly after the fixed 97-byte `ClientHello` in the SAME
/// datagram — `[97B ClientHello][credential bytes]`, no length prefix, the
/// datagram boundary is the frame, one round trip. `run_server_handshake_v9_datagram`
/// splits that prefix off itself and hands everything past byte 97 into the
/// [`ClientAuthContext`] this closure receives — the identical fields the
/// stream path builds. So this closure is exactly `make_credential_auth`,
/// unmodified, the same gate every other exit in the fleet runs, and a real
/// client presenting a real credential now passes it here too.
///
/// # What this gate still does not prove
///
/// Checked BEFORE this closure ever runs, inside
/// `run_server_handshake_v9_datagram` itself: the cryptographic proof, which
/// establishes only that the caller holds SOME X25519 keypair and knows this
/// mesh's id. `make_credential_auth` is what turns that into "an AUTHORIZED
/// client" by checking the credential handed to this closure — but it cannot
/// check whether that credential is the one THIS caller's own proof committed
/// to, because it isn't: the client proof and transcript
/// (`compute_client_proof` / `transcript_0`) bind `e_pub_c`, the server's
/// static key, the mesh id, the offered suites and the timestamp, never the
/// credential bytes. An on-path party can therefore strip or swap a
/// credential without invalidating the proof it rides beside; what defends
/// against that has to be the credential scheme's own binding, not this
/// handshake layer. This is inherited unchanged from the live stream V9 path,
/// not introduced here — closing it means changing the proof formula itself,
/// a wire-format change needing a coordinated fleet-wide version bump, and is
/// explicitly out of scope for this closure.
fn datagram_client_auth(
    runtime: &Arc<NodeRuntime>,
    peer: std::net::SocketAddr,
    node_id: Vec<u8>,
) -> impl for<'a> Fn(&ClientAuthContext<'a>) -> bool + Send + 'static {
    crate::core::listener::make_credential_auth(
        Arc::clone(&runtime.credential_params),
        Arc::clone(&runtime.spent_set),
        peer,
        node_id,
        runtime.mesh_id.as_bytes().to_vec(),
        Arc::clone(&runtime.role_signed_replay),
    )
}

/// One session, start to finish: parse the first datagram as a V9
/// `ClientHello`, run the server handshake, and on success build the
/// concrete tunnel and hand it to [`handle_udp_wire_exit`].
///
/// # `AuthMode::Hmac`, not `None`/`Blake3` — a stated decision
///
/// The sliding HMAC receive window (`mirage_protocol::core::udp_tunnel`) is
/// the one mechanism in `MirageCoreUdpTunnel` that tolerates the reordered,
/// duplicated datagrams a real UDP path delivers without desyncing;
/// `None`/`Blake3` use a bare monotonic counter that module's own doc marks
/// "bookkeeping" for those modes. `Hmac` is the only mode this splice can
/// assert is correct for a transport that reorders and drops by design.
async fn try_handle(
    socket: &Arc<LocalDgramSocket>,
    face_port: u16,
    peer: SocketAddr,
    first: Vec<u8>,
    inbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    registry: &Arc<ListenerRegistry>,
    cache: &ServerHelloCache,
) -> Result<(), MirageError> {
    let runtime = registry.runtime();

    // Read the addressing off the hello BEFORE the handshake, because the
    // AEAD suite the handshake negotiates comes off the spec this resolves
    // to. `parse_datagram_hello` is the same parser the handshake itself
    // runs, so the split acted on here and the split it uses cannot drift.
    //
    // A datagram that does not parse is disposed of the way every rejection
    // on this path is disposed of — by answering nothing at all. That is
    // also what makes resolving this early safe: a selector miss and a
    // failed proof are the same silence to whoever sent the datagram, so
    // the ordering leaks nothing the way it would on a stream.
    let addressed = match parse_datagram_hello(&first) {
        Ok(parsed) => parsed.chain_address,
        Err(e) => {
            warn!(
                peer = %peer,
                error = %e,
                "[udp-chain-splice] refusing a datagram whose ClientHello did not parse — answering nothing"
            );
            return Ok(());
        }
    };

    let spec = match &addressed {
        // Chain-addressed: the hello names WHICH hop of WHICH chain, and
        // that is the only thing allowed to decide.
        Some(addr) => match registry.resolve_datagram(addr).await {
            Some(spec) => spec,
            None => {
                // Same doctrine as the stream splice: the node's own journal
                // says what happened, the peer learns nothing. The selector
                // is a client's addressing choice — its digest and its
                // length, never its value.
                warn!(
                    peer = %peer,
                    cause = "no-such-listener",
                    chain_position = addr.chain_position,
                    chain_length = addr.chain_length,
                    selector_len = addr.selector_bytes().len(),
                    selector_hash = %crate::core::chain_splice::selector_digest(&addr.selector_bytes()),
                    "[udp-chain-splice] a datagram addressed a chain hop this node does not serve — answering nothing"
                );
                return Ok(());
            }
        },
        // No chain block: a plain direct UDP exit, the only thing this plane
        // could express before the block existed. Unchanged.
        None => registry
            .single_udp_direct_exit(runtime.mesh_id.as_ref())
            .await
            .map_err(|e| MirageError::Config(e.to_string()))?,
    };

    // The role the monitor minted this listener for, checked BEFORE the
    // handshake — a session this node will not serve costs it no X25519, and
    // the refusal is the same silence a selector miss produces.
    //
    // This check is not decoration. `handle_udp_wire_exit` was called
    // unconditionally: the resolved `spec.role` was read by nothing. That was
    // harmless only while `single_udp_direct_exit` was the sole resolver,
    // because it filters to `Exit { Direct }` itself. `resolve_datagram`
    // resolves by selector and does not, so a chain-addressed datagram
    // naming a RELAY hop would have been served as an exit — the first hop
    // of a chain sending the client's traffic straight out to the internet
    // while the client believed it had two more hops to go.
    //
    // **Updated 2026-09-09 (U5 Slice 4): a datagram relay leg now exists —
    // it is NOT reachable through this function.** `try_handle` runs only
    // for a datagram that opened with a REAL V9 `ClientHello` (a plain
    // direct exit, or the pre-existing `DatagramChainAddress`-addressed
    // path); U5 decision (A) never runs a real V9 handshake for a chain
    // session, so nothing that could resolve to a `Relay` spec here is ever
    // meant to be served by THIS handshake. The relay leg this datagram
    // names lives on the FS-chain branch instead
    // (`is_fs_chain_hello`/`try_handle_fs_chain`, dispatched one level up in
    // `handle_udp_session`, before `try_handle` is ever called) — a refusal
    // here is therefore still correct, not a stale gap: this path has
    // nothing to hand a `Relay` spec to, by design, not by omission.
    match &spec.role {
        ListenerRole::Exit { exit_mode: ExitMode::Direct } => {}
        other => {
            warn!(
                peer = %peer,
                cause = "role-not-served-on-datagrams",
                role = ?other,
                "[udp-chain-splice] this listener is not a direct datagram exit — the datagram relay leg is served by the FS-chain branch, not by a real V9 handshake — answering nothing rather than serving it as an exit"
            );
            return Ok(());
        }
    }

    let mut peer_socket = UdpPeerSocket::from_relay(Arc::clone(socket), face_port, peer, inbound);

    let result = run_server_handshake_v9_datagram(
        &mut peer_socket,
        &runtime.keypair,
        runtime.mesh_id.as_bytes(),
        &[spec.aead_suite],
        datagram_client_auth(
            &runtime,
            peer,
            runtime.snapshot.load().node_config.node_id.as_bytes().to_vec(),
        ),
        &first,
        cache,
    )
    .await?;

    let Some(result) = result else {
        // Rejected, or a retransmit already answered from cache — either
        // way no NEW tunnel starts on THIS call, and nothing beyond what
        // `run_server_handshake_v9_datagram` itself already sent (or did
        // not) is ever written here.
        return Ok(());
    };

    let info = TransportInfo::udp_raw(peer);
    let tunnel = MirageCoreUdpTunnel::new(peer_socket, &result.session_keys, false, info, AuthMode::Hmac);

    handle_udp_wire_exit(tunnel, registry.ctx_doh()).await
}

#[cfg(test)]
mod tests {
    //! Proof for this module — loopback only, no fleet box, no handshake.
    //!
    //! `paired_tunnels()` mirrors `mirage-protocol`'s own
    //! `tests/udp_tunnel_datagram_safety.rs` harness: `SessionKeys::derive`
    //! on both sides instead of a real V9 handshake, since these tests are
    //! only concerned with the datagram-splice mechanics this module adds,
    //! not handshake machinery.

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use mirage_core::config::NodeConfig;
    use mirage_core::crypto::{
        issue_epoch_hmac, random_nonce16, AeadCipher, AeadSuite, CredentialParams, CredentialScheme,
        EpochEntry, EpochHmacKey, KeyPair, SessionKeys, SpentSet,
    };
    use mirage_core::frame::{CamouflageType, Frame, FrameCodec};
    use mirage_core::local_dgram_endpoint::{DgramEnvelope, LocalDgramEndpoint, LocalDgramSocket};
    use mirage_core::local_endpoint::{plan_from_resolution, AccountResolution};
    use mirage_core::mirage::wire::{ExitMode, Framing, ListenerRole, MirageListenerKind, SpecFingerprint};
    use mirage_protocol::auth::v9::SERVER_HELLO_LEN;
    use mirage_protocol::auth::AuthMode;
    use mirage_protocol::core::dgram_chain_addr::DatagramChainAddress;
    use mirage_protocol::core::udp_handshake::{
        run_client_handshake_v9_datagram, run_client_handshake_v9_datagram_with_chain,
        run_client_handshake_v9_datagram_with_credential,
    };
    use mirage_protocol::traits::TransportInfo;
    use mirage_protocol::transport::udp::UdpPeerSocket;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    use crate::core::registry::registry::ActivationContext;
    use crate::core::registry::spec::{ListenerId, ListenerSpec};
    use crate::core::runtime::{NodeRuntime, NodeRuntimeSnapshot};

    use super::*;

    /// The UDP face the crafted-frame tests stand in for. Arbitrary — at
    /// most one exists in any test in this module.
    const FACE_PORT: u16 = 4433;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// Deterministic test session keys — both sides derive from the same
    /// `shared`/`salt` bytes, so calling this twice yields identical keys
    /// without running a real handshake (matches
    /// `udp_tunnel_datagram_safety.rs`'s own `test_keys`).
    fn test_keys() -> SessionKeys {
        SessionKeys::derive(
            b"udp-chain-splice-test-shared-secret",
            b"udp-chain-splice-test-salt",
            AeadSuite::ChaCha20Poly1305,
        )
    }

    /// Two `MirageCoreUdpTunnel`s pointed at each other over real loopback
    /// UDP sockets — no handshake, no relay, no perimeter.
    async fn paired_tunnels() -> (MirageCoreUdpTunnel, MirageCoreUdpTunnel) {
        let a = UdpPeerSocket::bind_client(loopback(0))
            .await
            .expect("bind first loopback peer socket");
        let b = UdpPeerSocket::bind_client(loopback(0))
            .await
            .expect("bind second loopback peer socket");
        let port_a = a.local_addr().expect("peer a local addr").port();
        let port_b = b.local_addr().expect("peer b local addr").port();

        let mut a = a;
        let mut b = b;
        a.set_remote(loopback(port_b));
        b.set_remote(loopback(port_a));

        let keys = test_keys();
        let client = MirageCoreUdpTunnel::new(
            a,
            &keys,
            true,
            TransportInfo::udp_raw(loopback(port_b)),
            AuthMode::None,
        );
        let server = MirageCoreUdpTunnel::new(
            b,
            &keys,
            false,
            TransportInfo::udp_raw(loopback(port_a)),
            AuthMode::None,
        );
        (client, server)
    }

    /// Bind two `LocalDgramSocket`s pointed at each other on loopback UDP —
    /// the box-local relay a real `UdpPeerSocket::from_relay` session would
    /// be fed from, standing in for `mirage-perimeter`'s own bound socket.
    /// Mirrors `mirage-protocol`'s own `tests/udp_relayed_backend.rs::bind_relay_pair`.
    async fn bind_relay_pair() -> (Arc<LocalDgramSocket>, Arc<LocalDgramSocket>) {
        let plan = plan_from_resolution(AccountResolution::NotRequested);
        let unbound = LocalDgramEndpoint::UdpLoopback(loopback(0));

        let mut node_side = LocalDgramSocket::bind(unbound.clone(), unbound.clone(), None, &plan)
            .await
            .expect("bind node-side relay socket");
        let LocalDgramEndpoint::UdpLoopback(node_addr) = *node_side.local_endpoint() else {
            unreachable!("the loopback-UDP arm always binds a UdpLoopback endpoint")
        };

        let peer_side = LocalDgramSocket::bind(
            unbound,
            LocalDgramEndpoint::UdpLoopback(node_addr),
            None,
            &plan,
        )
        .await
        .expect("bind peer-side relay socket");
        let LocalDgramEndpoint::UdpLoopback(peer_addr) = *peer_side.local_endpoint() else {
            unreachable!("the loopback-UDP arm always binds a UdpLoopback endpoint")
        };

        node_side.set_peer_endpoint(LocalDgramEndpoint::UdpLoopback(peer_addr));
        (Arc::new(node_side), Arc::new(peer_side))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers for §"The server" tests below.
    // ─────────────────────────────────────────────────────────────────────

    /// Fixed EpochHmac epoch/secret every credentialed-handshake fixture in
    /// this module shares — [`test_runtime`] installs it as this mesh's real,
    /// operative `credential_params` (the same params `make_credential_auth`
    /// reads on every dial), and [`mint_test_credential`] mints tokens against
    /// the identical secret for the client side to present. Mirrors
    /// `listener.rs`'s own `credential_auth_tests::make_params`/`make_token`
    /// shape, collapsed to one fixed epoch: every test in this module dials
    /// the same mesh, so there is nothing a second epoch would prove here.
    const TEST_CRED_EPOCH_ID: u32 = 1;
    const TEST_CRED_SECRET: [u8; 32] = [0x77u8; 32];

    /// Mint a fresh, single-use EpochHmac token against
    /// [`TEST_CRED_EPOCH_ID`]/[`TEST_CRED_SECRET`] — the credential a real
    /// client appends after its `ClientHello` to satisfy
    /// `datagram_client_auth`'s `make_credential_auth` gate now that the wire
    /// carries one. Present it with `CredentialScheme::EpochHmac as u8`.
    fn mint_test_credential() -> Vec<u8> {
        let key = EpochHmacKey::from_bytes(TEST_CRED_SECRET);
        let nonce = random_nonce16();
        issue_epoch_hmac(&key, TEST_CRED_EPOCH_ID, nonce).to_vec()
    }

    /// A runtime just complete enough to construct a [`ListenerRegistry`] and
    /// run a real V9 datagram handshake against it — mirrors
    /// `core::chain_splice::tests::test_runtime` (same JSON shape), plus the
    /// node's own keypair the caller generated so it can compute the
    /// server's public key before the runtime consumes it.
    ///
    /// `credential_params` carries real, operative EpochHmac params
    /// ([`TEST_CRED_EPOCH_ID`]/[`TEST_CRED_SECRET`]) rather than `None` —
    /// `make_credential_auth` fails every dial closed on `None` regardless of
    /// what the client presents, so a runtime built for a REAL handshake
    /// attempt needs real params to gate against, exactly as a live mesh
    /// does once its operator has pushed a credential policy.
    fn test_runtime(mesh_id: &str, keypair: KeyPair) -> Arc<NodeRuntime> {
        let node_config: NodeConfig = serde_json::from_value(serde_json::json!({
            "node_id": "test-udp-chain-splice-node",
            "listen_addr": "127.0.0.1:0",
            "mode": {"Relay": {"fallback_dest": "", "fallback_sni": "", "upstreams": []}},
            "protocols": [],
            "admin_endpoint": null,
            "health_interval_secs": 30,
            "psk": null,
        }))
        .expect("test NodeConfig must deserialize");

        let credential_params = CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(TEST_CRED_EPOCH_ID, u64::MAX, TEST_CRED_SECRET)],
        );

        let snapshot = NodeRuntimeSnapshot {
            protocols: Vec::new(),
            pools: Vec::new(),
            relay_metrics: None,
            node_config,
            credential_params: Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(credential_params)))),
            spent_set: Arc::new(std::sync::Mutex::new(SpentSet::new())),
            role_signed_replay: Arc::new(std::sync::Mutex::new(
                crate::core::role_signed_gate::RoleSignedReplayCache::new(),
            )),
            allow_legacy_v8: true,
        };

        NodeRuntime::new(snapshot, keypair, Arc::from(mesh_id), None, None)
    }

    /// A registry with exactly one `TunnelUdp`/`Exit{Direct}` spec registered
    /// for `mesh_id` — the resolution [`try_handle`] needs from
    /// [`ListenerRegistry::single_udp_direct_exit`]. Returns the registry and
    /// the node's own X25519 public key bytes, which every handshake test in
    /// this module addresses.
    async fn test_registry_with_udp_direct_exit(mesh_id: &str) -> (Arc<ListenerRegistry>, [u8; 32]) {
        let keypair = KeyPair::generate();
        let server_pub = keypair.public.to_bytes();
        let runtime = test_runtime(mesh_id, keypair);
        let registry = Arc::new(ListenerRegistry::new(ActivationContext {
            runtime,
            outbound_protocol: None,
            doh: None,
        }));

        let spec = ListenerSpec {
            id: ListenerId("udp-direct-exit-test".to_string()),
            mesh_id: mesh_id.to_string(),
            kind: MirageListenerKind::TunnelUdp,
            role: ListenerRole::Exit { exit_mode: ExitMode::Direct },
            framing: Framing::Plain,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            bind_port: None,
            chain_role: None,
            control_target: None,
            payload: None,
            fingerprint: SpecFingerprint([0u8; 32]),
        }
        .with_recomputed_fingerprint();
        registry
            .activate(spec)
            .await
            .expect("a TunnelUdp/Direct spec registers rather than binds");

        (registry, server_pub)
    }

    /// A minimal stand-in for the perimeter's own dispatcher: reads
    /// `relay.recv_envelope()` forever and forwards each `(source, payload)`
    /// into whichever test-side client registered for that source via
    /// [`fake_client_socket`] — just enough fidelity to drive a REAL
    /// client-side V9 datagram handshake
    /// (`run_client_handshake_v9_datagram`) against this module's server
    /// without standing up `mirage-perimeter` itself.
    type FakeClientRoutes = Arc<std::sync::Mutex<HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>>>>;

    fn spawn_fake_perimeter(relay: Arc<LocalDgramSocket>) -> (tokio::task::JoinHandle<()>, FakeClientRoutes) {
        let routes: FakeClientRoutes = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let routes_for_task = Arc::clone(&routes);
        let handle = tokio::spawn(async move {
            loop {
                match relay.recv_envelope().await {
                    Ok((envelope, payload)) => {
                        let tx = routes_for_task
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get(&envelope.peer)
                            .cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send((envelope.peer, payload)).await;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        (handle, routes)
    }

    /// Register a fake client's own address in `routes` and hand back the
    /// `UdpPeerSocket` it should drive its own handshake through — the
    /// `from_relay` backend fed by this client's own slice of
    /// [`spawn_fake_perimeter`]'s demux table.
    fn fake_client_socket(
        relay: Arc<LocalDgramSocket>,
        routes: &FakeClientRoutes,
        face_port: u16,
        fake_peer: SocketAddr,
    ) -> UdpPeerSocket {
        let (tx, rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(fake_peer, tx);
        UdpPeerSocket::from_relay(relay, face_port, fake_peer, rx)
    }

    /// Drive a REAL client-side V9 datagram handshake attempt just far
    /// enough to capture the exact datagram it sends — the bare 97-byte
    /// `ClientHello` when `credential` is `None`, or
    /// `[97B ClientHello][credential bytes]` (via
    /// `run_client_handshake_v9_datagram_with_credential`,
    /// `CredentialScheme::EpochHmac`) when it is `Some` — then abort it: this
    /// module's tests need genuine, cryptographically valid hello bytes
    /// (bound to `server_pub`/`mesh_id`), not a full completed handshake, and
    /// the client's own retry loop would otherwise run for seconds waiting on
    /// a reply nobody sends.
    async fn craft_real_client_hello(
        perimeter_side: Arc<LocalDgramSocket>,
        node_side: Arc<LocalDgramSocket>,
        server_pub: [u8; 32],
        mesh_id: &[u8],
        credential: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let fake_peer = loopback(59999);
        let (_tx, rx) = mpsc::channel(4);
        let mut client_socket = UdpPeerSocket::from_relay(perimeter_side, FACE_PORT, fake_peer, rx);
        // Same construction `KeyPair::generate()` uses internally — a fresh
        // client static key, thrown away once the hello bytes are captured.
        let client_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        let mesh_id = mesh_id.to_vec();
        let handle = tokio::spawn(async move {
            let _ = match credential {
                Some(cred) => {
                    run_client_handshake_v9_datagram_with_credential(
                        &mut client_socket,
                        &server_pub,
                        &client_priv,
                        &mesh_id,
                        &[AeadSuite::ChaCha20Poly1305],
                        CredentialScheme::EpochHmac as u8,
                        &cred,
                    )
                    .await
                }
                None => {
                    run_client_handshake_v9_datagram(
                        &mut client_socket,
                        &server_pub,
                        &client_priv,
                        &mesh_id,
                        &[AeadSuite::ChaCha20Poly1305],
                    )
                    .await
                }
            };
        });

        let (_envelope, hello_bytes) = node_side
            .recv_envelope()
            .await
            .expect("capture the real ClientHello datagram the client relayed toward the node");
        handle.abort();
        hello_bytes
    }

    // ── 1. Byte-identical, whole delivery — including oversized and zero-length ──

    #[tokio::test]
    async fn payload_arrives_byte_identical_and_whole_including_oversized_and_zero_length() {
        let target = UdpSocket::bind(loopback(0)).await.expect("bind real target socket");
        let target_addr = target.local_addr().expect("target addr");

        let (mut client_tunnel, mut server_tunnel) = paired_tunnels().await;
        let handle = tokio::spawn(async move {
            relay_to_target(&mut server_tunnel, target_addr, Duration::from_secs(5)).await
        });

        // Large enough that the old `[2B len]`-framed path's own 2-byte
        // length-prefix read against a `MirageCoreUdpTunnel` would have
        // errored rather than delivered it (see this module's own "the
        // defect this replaces" doc).
        let big: Vec<u8> = (0..60_000u32).map(|i| (i % 256) as u8).collect();
        client_tunnel.send(&big).await.expect("send big payload");
        let mut buf = vec![0u8; 65536];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .expect("target must receive the big payload")
            .expect("recv_from must succeed");
        assert_eq!(&buf[..n], &big[..], "the payload must arrive byte-identical and whole");

        // The old framed path's own `read_udp_frame` treats a zero-length
        // frame as end-of-session; this path must forward a genuine empty
        // datagram as the legitimate empty message it is.
        client_tunnel.send(&[]).await.expect("send empty payload");
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .expect("target must receive the empty payload")
            .expect("recv_from must succeed");
        assert_eq!(n2, 0, "an empty datagram must arrive as an empty datagram, never swallowed");

        handle.abort();
    }

    // ── 2. Three in, three out — boundaries preserved, no coalescing ──

    #[tokio::test]
    async fn three_datagrams_in_produce_exactly_three_out_with_boundaries_preserved() {
        let target = UdpSocket::bind(loopback(0)).await.expect("bind real target socket");
        let target_addr = target.local_addr().expect("target addr");

        let (mut client_tunnel, mut server_tunnel) = paired_tunnels().await;
        let handle = tokio::spawn(async move {
            relay_to_target(&mut server_tunnel, target_addr, Duration::from_secs(5)).await
        });

        let msgs: [&[u8]; 3] = [b"first message", b"a second, differently sized message", b"3rd"];
        for m in msgs {
            client_tunnel.send(m).await.expect("send message");
        }

        let mut buf = vec![0u8; 4096];
        for expected in msgs {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut buf))
                .await
                .expect("target must receive each message in turn")
                .expect("recv_from must succeed");
            assert_eq!(&buf[..n], expected, "message boundaries must be preserved, not coalesced");
        }

        // Nothing beyond the three sent may ever arrive.
        let extra = tokio::time::timeout(Duration::from_millis(200), target.recv_from(&mut buf)).await;
        assert!(
            extra.is_err(),
            "exactly three datagrams must arrive — a fourth would mean coalescing or duplication"
        );

        handle.abort();
    }

    // ── 3. A reply returns through the tunnel as one whole datagram ──

    #[tokio::test]
    async fn a_reply_from_the_real_target_returns_through_the_tunnel_as_one_whole_datagram() {
        let target = UdpSocket::bind(loopback(0)).await.expect("bind real target socket");
        let target_addr = target.local_addr().expect("target addr");

        let (mut client_tunnel, mut server_tunnel) = paired_tunnels().await;
        let handle = tokio::spawn(async move {
            relay_to_target(&mut server_tunnel, target_addr, Duration::from_secs(5)).await
        });

        client_tunnel.send(b"ping").await.expect("send ping");
        let mut buf = [0u8; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .expect("target must receive ping")
            .expect("recv_from must succeed");
        assert_eq!(&buf[..n], b"ping");

        let reply = b"pong, whole and unframed";
        target.send_to(reply, from).await.expect("send reply from target");

        let received = tokio::time::timeout(Duration::from_secs(2), client_tunnel.recv_datagram())
            .await
            .expect("the reply must arrive through the tunnel")
            .expect("recv_datagram must succeed");
        assert_eq!(received, reply, "the reply must arrive as one whole datagram, no framing");

        handle.abort();
    }

    // ── 4. The first datagram sets the destination, never forwarded as payload ──

    #[tokio::test]
    async fn the_first_datagram_sets_the_destination_and_is_never_forwarded_as_payload() {
        let (mut client_tunnel, server_tunnel) = paired_tunnels().await;

        // A loopback destination — refused by the same SSRF policy
        // `exit::direct::resolve_udp_target` applies, and this module calls
        // that one function rather than keeping a copy. That refusal is exactly what makes
        // this assertion possible without a live non-loopback target: the
        // error names the precise host parsed out of THIS datagram's own
        // bytes, proving it was read and resolved as the destination
        // selector — not skipped, and not forwarded anywhere.
        let target_str = "127.0.0.1:9";
        client_tunnel.send(target_str.as_bytes()).await.expect("send target datagram");

        // A second datagram that must never be reachable at all:
        // `handle_udp_wire_exit` returns (with an error) while resolving
        // datagram #1, strictly before any real socket that could forward
        // datagram #2 as payload is ever created.
        client_tunnel
            .send(b"must never be treated as the destination or forwarded")
            .await
            .expect("send payload datagram");

        let err = handle_udp_wire_exit(server_tunnel, None)
            .await
            .expect_err("a loopback destination named in datagram #1 must be refused by policy");
        let rendered = err.to_string();
        assert!(
            rendered.contains("127.0.0.1"),
            "the rejection must name the exact address parsed out of datagram #1's own bytes: {rendered}"
        );
    }

    // ── 5. No task outlives the session ──

    #[tokio::test]
    async fn the_relay_task_ends_when_its_route_is_torn_down_and_does_not_outlive_the_session() {
        let (node_relay, peer_relay) = bind_relay_pair().await;
        let client_identity = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 51234);
        let keys = test_keys();

        // Craft one wire frame as if a real peer had sent it, without
        // running a handshake — the server tunnel below has `is_client =
        // false`, so it DECODES with the client write key; encode with that
        // same key to stand in for "the peer's own send_codec" (mirrors
        // `udp_tunnel_datagram_safety.rs::dummy_cover_frame_is_still_skipped`).
        let craft_key: [u8; 32] = *keys.client_write_key;
        let mut craft_codec =
            FrameCodec::new(AeadCipher::with_suite(keys.suite, &craft_key), vec![1024]);
        let payload = b"one relayed payload before the route is torn down".to_vec();
        let wire = craft_codec
            .encode(&Frame { cam_type: CamouflageType::Raw, payload: payload.clone() })
            .expect("encode crafted frame");

        peer_relay
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: client_identity }, &wire)
            .await
            .expect("relay the crafted frame to the node side");

        // Forward exactly that one envelope into the channel
        // `UdpPeerSocket::from_relay` reads, then drop the sender — the
        // test's stand-in for the node-side demux dropping this peer's
        // route once its session ends (`udp_chain_splice`'s own evict path,
        // per the plan this module implements). No background task and no
        // timing dependency: the channel is closed before the relay loop
        // is even spawned, and the one already-buffered message is still
        // delivered first (`mpsc` drains its buffer before reporting
        // closed).
        let (tx, rx) = mpsc::channel(4);
        let (envelope, relayed_payload) =
            node_relay.recv_envelope().await.expect("recv the relayed frame");
        tx.send((envelope.peer, relayed_payload)).await.expect("forward into the peer channel");
        drop(tx);

        let server_socket =
            UdpPeerSocket::from_relay(Arc::clone(&node_relay), FACE_PORT, client_identity, rx);
        let mut server_tunnel = MirageCoreUdpTunnel::new(
            server_socket,
            &keys,
            false,
            TransportInfo::udp_raw(client_identity),
            AuthMode::None,
        );

        let target = UdpSocket::bind(loopback(0)).await.expect("bind stand-in target");
        let target_addr = target.local_addr().expect("stand-in target addr");

        // A generous idle timeout — the point of this test is that the
        // task ends via the torn-down route, not via idle expiry.
        let handle = tokio::spawn(async move {
            relay_to_target(&mut server_tunnel, target_addr, Duration::from_secs(5)).await
        });

        // `relay_to_target` reports the same `Ok(())` regardless of which
        // branch broke the loop (the plan this module implements does not
        // distinguish "why" in the return type) — the proof that it ended
        // via the torn-down route rather than the 5s idle timeout is the
        // bound below: it must finish well inside that window.
        let joined = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect(
                "the session's own task must end on its own once its route is torn down — \
                 it must not be left running forever, and 2s is far under the 5s idle timeout \
                 passed to it, so finishing here proves the route teardown ended it, not idleness",
            )
            .expect("the task must not panic");
        assert!(joined.is_ok(), "the relay loop must not report a spurious failure: {joined:?}");

        // The one payload relayed before the route died must still have
        // gone through — ending promptly must not mean dropping work that
        // was already in flight.
        let mut buf = [0u8; 128];
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), target.recv_from(&mut buf))
            .await
            .expect("the one relayed payload must have reached the target before the route ended")
            .expect("recv_from must succeed");
        assert_eq!(&buf[..n], &payload[..]);
    }

    // ─────────────────────────────────────────────────────────────────────
    // §"The server" — bind, demultiplex, handshake, hand off. Proof for the
    // brief this section implements.
    // ─────────────────────────────────────────────────────────────────────

    // ── 6. Two sessions are demultiplexed, each seeing only its own datagrams ──

    #[tokio::test]
    async fn two_sessions_are_demultiplexed_each_seeing_only_its_own_datagrams() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let dispatch = tokio::spawn(run_dispatcher(
            Arc::clone(&node_side),
            sessions_tx,
            cancel.clone(),
            PEER_SWEEP_TRIGGER,
            PEER_IDLE_EVICT,
            PEER_LOW_WATER_MARK,
        ));

        let addr_a = loopback(51001);
        let addr_b = loopback(51002);

        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: addr_a }, b"hello-a")
            .await
            .expect("send a's first datagram");
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: addr_b }, b"hello-b")
            .await
            .expect("send b's first datagram");

        let mut sessions = HashMap::new();
        for _ in 0..2 {
            let s = sessions_rx.recv().await.expect("two sessions must be announced");
            sessions.insert(s.peer, s);
        }
        assert_eq!(sessions[&addr_a].first_datagram, b"hello-a");
        assert_eq!(sessions[&addr_b].first_datagram, b"hello-b");

        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: addr_a }, b"again-a")
            .await
            .expect("send a's second datagram");
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: addr_b }, b"again-b")
            .await
            .expect("send b's second datagram");

        let mut session_a = sessions.remove(&addr_a).expect("session a exists");
        let mut session_b = sessions.remove(&addr_b).expect("session b exists");
        let (from, payload) = session_a.inbound.recv().await.expect("session a receives its own datagram");
        assert_eq!(from, addr_a);
        assert_eq!(payload, b"again-a");
        let (from, payload) = session_b.inbound.recv().await.expect("session b receives its own datagram");
        assert_eq!(from, addr_b);
        assert_eq!(payload, b"again-b");

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── 7. A retransmitted ClientHello produces the identical ServerHello, no second handshake ──

    #[tokio::test]
    async fn a_retransmitted_client_hello_produces_the_identical_server_hello_and_derives_no_new_keys() {
        let (registry, server_pub) = test_registry_with_udp_direct_exit("TESTMESH").await;
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let hello = craft_real_client_hello(
            Arc::clone(&perimeter_side),
            Arc::clone(&node_side),
            server_pub,
            b"TESTMESH",
            Some(mint_test_credential()),
        )
        .await;
        let cache = Arc::new(ServerHelloCache::new());

        // First "session": a fresh (face_port, peer) key, no data datagram
        // available afterward — `try_handle` must therefore run the REAL
        // handshake, succeed, build the tunnel, and then fail promptly
        // trying to read the very next (never-sent) datagram. That failure
        // is the proof a full handshake+tunnel attempt happened here, not a
        // cache hit.
        let peer_1 = loopback(61001);
        let (tx1, rx1) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        drop(tx1);
        let outcome1 =
            try_handle(&node_side, FACE_PORT, peer_1, hello.to_vec(), rx1, &registry, &cache).await;
        assert!(
            outcome1.is_err(),
            "the first attempt must proceed past a REAL handshake into the exit path and fail there \
             (no data datagram was ever supplied): {outcome1:?}"
        );
        let (envelope1, server_hello_1) =
            perimeter_side.recv_envelope().await.expect("a ServerHello must have been sent for attempt 1");
        assert_eq!(envelope1.peer, peer_1);
        assert_eq!(server_hello_1.len(), SERVER_HELLO_LEN);

        // Second "session": a DIFFERENT (face_port, peer) key, but the
        // IDENTICAL ClientHello bytes (same e_pub_c) — the shape a
        // retransmit takes when it lands on a session slot the first
        // attempt no longer occupies, sharing the SAME cache `run_server`
        // would hand every session it spawns.
        let peer_2 = loopback(61002);
        let (tx2, rx2) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        drop(tx2);
        let outcome2 =
            try_handle(&node_side, FACE_PORT, peer_2, hello.to_vec(), rx2, &registry, &cache).await;
        assert!(
            outcome2.is_ok(),
            "a cache hit must return Ok(()) at once — try_handle's own Ok(None)-from-the-handshake \
             branch, never a tunnel/exit attempt: {outcome2:?}"
        );
        let (envelope2, server_hello_2) = tokio::time::timeout(
            Duration::from_secs(2),
            perimeter_side.recv_envelope(),
        )
        .await
        .expect("the cache-hit reply must still be sent")
        .expect("recv_envelope must succeed");
        assert_eq!(envelope2.peer, peer_2);
        assert_eq!(
            server_hello_1, server_hello_2,
            "the ServerHello reply must be byte-identical — resent from the cache, not derived from \
             a fresh set of session keys"
        );
    }

    // ── 8. A session whose handshake fails is disposed of on a bound far below the idle sweep ──

    #[tokio::test]
    async fn a_session_whose_handshake_fails_is_disposed_of_well_before_the_idle_sweep() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, _server_pub) = test_registry_with_udp_direct_exit("TESTMESH").await;
        let cache = Arc::new(ServerHelloCache::new());
        let cancel = CancellationToken::new();
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let dispatch = tokio::spawn(run_dispatcher(
            Arc::clone(&node_side),
            sessions_tx,
            cancel.clone(),
            PEER_SWEEP_TRIGGER,
            PEER_IDLE_EVICT,
            PEER_LOW_WATER_MARK,
        ));

        let peer = loopback(62001);
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer }, b"not a real V9 client hello")
            .await
            .expect("send garbage first datagram");

        let session1 = sessions_rx.recv().await.expect("a session must be announced for the garbage datagram");
        assert_eq!(session1.peer, peer);
        let started = std::time::Instant::now();
        tokio::spawn(handle_udp_session(
            Arc::clone(&node_side),
            session1,
            Arc::clone(&registry),
            Arc::clone(&cache),
            Arc::new(FsCreatedCache::new()),
        ));

        // A bound far below `PEER_IDLE_EVICT` (600s): parsing a 97-byte
        // hello out of these bytes fails synchronously (no I/O wait), so
        // this is generous, not tight.
        tokio::time::sleep(Duration::from_millis(200)).await;

        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer }, b"a second garbage datagram")
            .await
            .expect("send second garbage datagram");
        let session2 = tokio::time::timeout(Duration::from_secs(2), sessions_rx.recv())
            .await
            .expect(
                "a SECOND session must be announced for the same key well before the 600s idle \
                 sweep could ever reach it — proving the failed handshake's own entry was already \
                 gone",
            )
            .expect("the dispatcher must still be running");
        assert_eq!(session2.peer, peer);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "disposal must be near-instant, not merely eventual"
        );

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── 9. A spray of fresh forged sources leaves the table bounded ──

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spray_of_fresh_forged_sources_leaves_the_session_table_bounded() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (sessions_tx, mut sessions_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let trigger = 16;
        let low_water = trigger - trigger / 8;
        let dispatch = tokio::spawn(run_dispatcher(
            Arc::clone(&node_side),
            sessions_tx,
            cancel.clone(),
            trigger,
            Duration::from_secs(60), // large — every sprayed source is fresh, so the idle sweep alone must not clear it
            low_water,
        ));

        // Keep every announced session alive (a dropped session's `evict`
        // sender still lives on the announced value itself; we just must
        // not let the sessions channel's own buffer fill and stall the
        // dispatcher).
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<SocketAddr>();
        let drain = tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Some(session) = sessions_rx.recv().await {
                let _ = seen_tx.send(session.peer);
                kept.push(session);
            }
            kept
        });

        let spray_count = trigger * 10;
        for i in 0..spray_count {
            perimeter_side
                .send_envelope(
                    DgramEnvelope { face_port: FACE_PORT, peer: loopback(20000 + i as u16) },
                    format!("spray-{i}").as_bytes(),
                )
                .await
                .expect("send spray datagram");
        }
        for _ in 0..spray_count {
            tokio::time::timeout(Duration::from_secs(5), seen_rx.recv())
                .await
                .expect("every sprayed source must be announced promptly")
                .expect("the announce channel must still be open");
        }

        // The oldest sprayed sources must have been evicted — a resend from
        // one starts a brand new session rather than silently vanishing.
        let oldest = loopback(20000);
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: oldest }, b"resend-old")
            .await
            .expect("resend from the oldest sprayed source");
        let reannounced = tokio::time::timeout(Duration::from_secs(5), seen_rx.recv())
            .await
            .expect("an evicted source's next datagram must start a fresh session, not vanish")
            .expect("the announce channel must still be open");
        assert_eq!(reannounced, oldest);

        // The most-recently-seen sprayed sources must still be resident —
        // proven by the ABSENCE of a re-announcement for one of them.
        let newest = loopback(20000 + spray_count as u16 - 1);
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: newest }, b"resend-new")
            .await
            .expect("resend from the newest sprayed source");
        let extra = tokio::time::timeout(Duration::from_millis(300), seen_rx.recv()).await;
        assert!(extra.is_err(), "the most-recently-seen sprayed source must still be resident, not re-announced");

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
        drop(drain);
    }

    // ── 9b. An actively-sending session survives a spray larger than the whole table ──

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_actively_sending_session_survives_a_spray_larger_than_the_whole_table() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (sessions_tx, mut sessions_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let trigger = 5;
        let low_water = trigger - trigger / 8;
        let dispatch = tokio::spawn(run_dispatcher(
            Arc::clone(&node_side),
            sessions_tx,
            cancel.clone(),
            trigger,
            Duration::from_secs(60),
            low_water,
        ));

        let active = loopback(30000);
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: active }, b"hello-active")
            .await
            .expect("active session's first datagram");
        let active_session = sessions_rx.recv().await.expect("the active session must be announced");
        assert_eq!(active_session.peer, active);

        // Drain the active session's own inbound channel continuously — an
        // undrained real consumer would trip the pre-existing "reader
        // stalled" eviction, unrelated to the fallback under test.
        let (active_reads_tx, mut active_reads_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let active_reader = tokio::spawn(async move {
            let mut inbound = active_session.inbound;
            while let Some((_from, payload)) = inbound.recv().await {
                if active_reads_tx.send(payload).is_err() {
                    return;
                }
            }
        });

        let spray_count = trigger * 50;
        let mut kept = Vec::new();
        for i in 0..spray_count {
            perimeter_side
                .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: active }, b"keepalive")
                .await
                .expect("active session keepalive");
            perimeter_side
                .send_envelope(
                    DgramEnvelope { face_port: FACE_PORT, peer: loopback(31000 + i as u16) },
                    format!("spray-{i}").as_bytes(),
                )
                .await
                .expect("send spray datagram");
            let session = sessions_rx.recv().await.expect("each sprayed source must still be announced");
            kept.push(session);
        }

        let reannounced = tokio::time::timeout(Duration::from_millis(300), sessions_rx.recv()).await;
        assert!(
            reannounced.is_err(),
            "the actively-sending session must never have been evicted, so no second session for it exists"
        );

        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer: active }, b"still-here")
            .await
            .expect("active session final datagram");
        let found = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match active_reads_rx.recv().await {
                    Some(payload) if payload == b"still-here" => return true,
                    Some(_) => continue,
                    None => return false,
                }
            }
        })
        .await
        .expect("reading the original session must not hang");
        assert!(
            found,
            "the original session's own inbound channel must still be the one receiving this source's traffic"
        );

        drop(kept);
        active_reader.abort();
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── 10. Cancelling stops the reader and every live session — the join proves it ──

    #[tokio::test]
    async fn cancelling_stops_the_reader_and_every_session_and_the_join_proves_it() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) = test_registry_with_udp_direct_exit("TESTMESH").await;
        let cancel = CancellationToken::new();

        let LocalDgramEndpoint::UdpLoopback(node_addr) = *node_side.local_endpoint() else {
            unreachable!("the loopback-UDP arm always binds a UdpLoopback endpoint")
        };

        let server_task = tokio::spawn(run_server(Arc::clone(&node_side), Arc::clone(&registry), cancel.clone()));

        // Drive one REAL client handshake all the way to a live session that
        // stays blocked waiting for its next (never-sent) datagram — the
        // shape most likely to still be running at the moment cancellation
        // fires.
        let (fake_perimeter, routes) = spawn_fake_perimeter(Arc::clone(&perimeter_side));
        let client_addr = loopback(63001);
        let mut client_socket = fake_client_socket(Arc::clone(&perimeter_side), &routes, FACE_PORT, client_addr);
        let client_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        run_client_handshake_v9_datagram_with_credential(
            &mut client_socket,
            &server_pub,
            &client_priv,
            b"TESTMESH",
            &[AeadSuite::ChaCha20Poly1305],
            CredentialScheme::EpochHmac as u8,
            &mint_test_credential(),
        )
        .await
        .expect("the real handshake against the running server must succeed — a credentialed \
                 client dialling a mesh whose credential_params are configured must still be \
                 admitted");

        // Give the server's own session task a moment to reach its blocked
        // read inside `handle_udp_wire_exit`.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = std::time::Instant::now();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect(
                "run_server must return once cancelled, not hang on the live session — 5s is far \
                 under the 60s idle timeout its own relay loop would otherwise wait out, so \
                 finishing here proves cancellation ended it, not idleness",
            )
            .expect("run_server must not panic");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cancellation must stop every live session promptly"
        );

        // Nothing outlives the join: `run_server` awaits `run_dispatcher`
        // and every spawned session's own JoinSet entry before returning, so
        // by the time `server_task` above completed, every `Arc<LocalDgramSocket>`
        // clone it ever handed out is already gone. This test's own
        // `node_side` binding is therefore the ONLY remaining strong
        // reference — dropping it must release the underlying UDP socket,
        // provable the same way `mirage-perimeter`'s own cancellation test
        // proves it: rebind the exact same port.
        drop(node_side);
        let rebound = tokio::net::UdpSocket::bind(node_addr).await;
        assert!(
            rebound.is_ok(),
            "the port must be free once every session and the dispatcher stop — a socket that \
             merely forgot a live task would still hold it and fail this exact rebind: {:?}",
            rebound.err()
        );

        fake_perimeter.abort();
    }

    // ── 10b. Capsule rotation on the REAL `AF_UNIX SOCK_DGRAM` rendezvous path ──
    //
    // Section 10 above proves `run_server` releases its socket on
    // cancellation using the loopback-UDP arm, which never exercises
    // `bind_unix_dgram`'s own stale-socket-file check — that check is
    // `#[cfg(unix)]`, and it is exactly what the live 2026-09-23 defect hit.
    // `configurator_main::run_configurator`'s rotation arm used to abort this
    // task without awaiting it, so a fresh generation's own `NodeChainDgram`
    // bind raced the previous generation's socket actually closing and lost:
    // `remove_stale_dgram_socket_if_dead`'s liveness probe found a
    // still-open socket and refused with `AddrInUse` ("a live listener
    // already owns …"), the exact production log line these two tests
    // reproduce and disprove — on the exact code path that hit it, not the
    // cross-platform loopback stand-in.

    /// A private scratch directory — `/run/mirage` is not writable in a
    /// test, matching `local_dgram_endpoint.rs`'s own `scratch()`.
    #[cfg(unix)]
    fn rotation_scratch_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("mirage-node-udp-chain-splice-rotation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Bind one generation's own `AF_UNIX SOCK_DGRAM` rendezvous socket at
    /// `path`, exactly as `LocalDgramChannel::NodeChainDgram::bind` does in
    /// production (root-only grant, matching `AccountResolution::NotRequested`'s
    /// own root-only plan) — except at a scratch path instead of the fixed
    /// `/run/mirage/node/chain-dgram.sock`, which a test may not write to.
    #[cfg(unix)]
    async fn bind_rotation_generation(path: &std::path::Path) -> LocalDgramSocket {
        let plan = plan_from_resolution(AccountResolution::NotRequested);
        // The peer end is never dialled in this test — only the bind and
        // its own stale-socket check are under test.
        let endpoint = LocalDgramEndpoint::UnixDgram(path.to_path_buf());
        LocalDgramSocket::bind(endpoint.clone(), endpoint, path.parent(), &plan)
            .await
            .expect("bind the generation's own chain-dgram socket")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_capsule_rotation_rebinds_the_dgram_channel() {
        let dir = rotation_scratch_dir();
        let path = dir.join("chain-dgram.sock");

        // ── Generation N: bind, serve, hold a live dispatcher ──
        let gen_n_socket = Arc::new(bind_rotation_generation(&path).await);
        let (registry, _server_pub) = test_registry_with_udp_direct_exit("TESTMESH").await;
        let gen_n_cancel = CancellationToken::new();
        let gen_n_task = tokio::spawn(run_server(
            Arc::clone(&gen_n_socket),
            Arc::clone(&registry),
            gen_n_cancel.clone(),
        ));

        // Give the dispatcher a moment to actually start reading — proves
        // this is a LIVE listener, not merely a bound-and-idle socket,
        // matching what the fleet defect actually hit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // ── Rotation: exactly what `run_configurator`'s rotation arm now
        // does — cancel, THEN join, before the next generation ever calls
        // bind (see `configurator_main.rs`'s rotation-teardown comment). ──
        gen_n_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), gen_n_task)
            .await
            .expect("generation N's udp-chain-splice task must join within 5s of cancellation")
            .expect("generation N's udp-chain-splice task must not panic");

        // `run_server` already dropped its own copy on the way out; this
        // binding is the only strong reference left. Drop it explicitly so
        // the fd is closed before the next bind, mirroring the Arc going
        // out of scope for real once `run_configurator` returns.
        drop(gen_n_socket);

        // ── Generation N+1: the fresh generation's own bind, at the
        // IDENTICAL path — the exact call `remove_stale_dgram_socket_if_dead`
        // guards, and the exact call that returned `AddrInUse` in the live
        // defect. ──
        let gen_n_plus_1 = tokio::time::timeout(Duration::from_secs(5), bind_rotation_generation(&path))
            .await
            .expect("rebinding the chain-dgram path must not hang");
        assert_eq!(
            gen_n_plus_1.local_endpoint().clone(),
            LocalDgramEndpoint::UnixDgram(path.clone()),
            "the fresh generation must be bound at the SAME rendezvous path the previous \
             generation held — that is the whole point of a fixed rendezvous socket"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Narrower than the rebind test above: proves the CLAIM the rebind
    /// depends on directly — once the generation's own task has been
    /// cancelled and joined, nothing still holds a clone of its socket.
    /// `run_server` does not return until `run_dispatcher` and every
    /// session it ever spawned have too (see this module's own "Lifecycle"
    /// doc), so a strong count of exactly one — this test's own binding —
    /// is the proof, not an inference from a successful rebind alone.
    #[cfg(unix)]
    #[tokio::test]
    async fn generation_teardown_releases_the_dgram_task() {
        let dir = rotation_scratch_dir();
        let path = dir.join("chain-dgram.sock");

        let socket = Arc::new(bind_rotation_generation(&path).await);
        let (registry, _server_pub) = test_registry_with_udp_direct_exit("TESTMESH").await;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_server(Arc::clone(&socket), Arc::clone(&registry), cancel.clone()));

        tokio::time::sleep(Duration::from_millis(50)).await;

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect(
                "the generation's udp-chain-splice task must join within 5s of cancellation — a \
                 task that only requested a stop (abort without join) would leave this hanging",
            )
            .expect("the generation's udp-chain-splice task must not panic");

        assert_eq!(
            Arc::strong_count(&socket),
            1,
            "once the generation's own task has been joined, this test's binding must be the ONLY \
             remaining strong reference to the socket — the dispatcher and every session it spawned \
             held their own clone, and `run_server` does not return until all of them have too"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 11. A dial with no credential is refused — no ServerHello, no tunnel, session disposed ──

    /// The proof this whole arc's honesty rests on: a REAL, cryptographically
    /// valid `ClientHello` (genuine proof, genuine timestamp, genuine suite
    /// offer) with NO credential appended (`cred_scheme = 0x00`, the plain
    /// [`run_client_handshake_v9_datagram`] a legitimate but uncredentialed
    /// client would send) must still be refused once `credential_params` are
    /// configured — exactly the same `make_credential_auth` gate every other
    /// exit runs. Without this test, a future change that silently made this
    /// exit admit everyone (e.g. the truncation defect this file's own doc
    /// once described) could still leave every OTHER test in this module
    /// green, because none of them dial with no credential at all.
    #[tokio::test]
    async fn a_dial_with_no_credential_is_refused_no_server_hello_no_tunnel_session_disposed() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) = test_registry_with_udp_direct_exit("TESTMESH").await;
        let hello = craft_real_client_hello(
            Arc::clone(&perimeter_side),
            Arc::clone(&node_side),
            server_pub,
            b"TESTMESH",
            None,
        )
        .await;
        let cache = Arc::new(ServerHelloCache::new());
        let cancel = CancellationToken::new();
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let dispatch = tokio::spawn(run_dispatcher(
            Arc::clone(&node_side),
            sessions_tx,
            cancel.clone(),
            PEER_SWEEP_TRIGGER,
            PEER_IDLE_EVICT,
            PEER_LOW_WATER_MARK,
        ));

        let peer = loopback(64001);
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer }, &hello)
            .await
            .expect("send the real, credential-less ClientHello as this peer's first datagram");

        let session1 = sessions_rx.recv().await.expect("a session must be announced for a well-formed hello");
        assert_eq!(session1.peer, peer);
        tokio::spawn(handle_udp_session(
            Arc::clone(&node_side),
            session1,
            Arc::clone(&registry),
            Arc::clone(&cache),
            Arc::new(FsCreatedCache::new()),
        ));

        // No ServerHello: `make_credential_auth` rejects `scheme_byte == 0x00`
        // unconditionally once `credential_params` are configured, so
        // `run_server_handshake_v9_datagram`'s own `client_auth` check fails
        // and it never calls `socket.send` on this path — nothing must reach
        // the client-facing side at all.
        let no_reply = tokio::time::timeout(Duration::from_millis(300), perimeter_side.recv_envelope()).await;
        assert!(no_reply.is_err(), "a credential-less dial must get no ServerHello reply at all: {no_reply:?}");

        // No tunnel: the same absence is the proof — a tunnel only exists
        // once `try_handle` builds one from a `Some(result)` handshake
        // outcome, and `handle_udp_wire_exit` would itself first try to READ
        // a datagram (the destination selector) before doing anything else;
        // nothing was ever sent for it to read, and nothing besides the
        // refused hello arrived on this session's own inbound channel.
        //
        // Session disposed: `handle_udp_session` always evicts its own table
        // entry on the way out regardless of outcome (see its own doc), so
        // resending from this SAME peer must start a BRAND NEW session, not
        // be silently absorbed by a still-live one.
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer }, &hello)
            .await
            .expect("resend from the same peer after the refused attempt");
        let session2 = tokio::time::timeout(Duration::from_secs(2), sessions_rx.recv())
            .await
            .expect(
                "a second session must be announced for the same key — proving the refused \
                 attempt's own table entry was already evicted, not left live and absorbing this \
                 datagram",
            )
            .expect("the dispatcher must still be running");
        assert_eq!(session2.peer, peer);

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // -- 12. Chain addressing on the datagram plane -------------------------

    /// The selector token this module's chain-addressed fixtures use. 16
    /// bytes, the width the monitor mints.
    const TEST_SELECTOR_TOKEN: [u8; 16] = [0x5Au8; 16];
    const TEST_CHAIN_ID: &str = "auto-deadbeef";

    fn chain_hop_spec(
        mesh_id: &str,
        kind: MirageListenerKind,
        role: ListenerRole,
        position: u8,
        length: u8,
    ) -> ListenerSpec {
        ListenerSpec {
            id: ListenerId(format!("{TEST_CHAIN_ID}-h{position}")),
            mesh_id: mesh_id.to_string(),
            kind,
            role,
            framing: Framing::Plain,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            bind_port: None,
            chain_role: Some(mirage_core::mirage::wire::ChainRole {
                chain_id: TEST_CHAIN_ID.to_string(),
                chain_position: position,
                chain_length: length,
                chain_node_ids: Vec::new(),
                next_hop_addr: None,
                selector_token_hex: Some(hex::encode(TEST_SELECTOR_TOKEN)),
            }),
            control_target: None,
            payload: None,
            fingerprint: SpecFingerprint([0u8; 32]),
        }
        .with_recomputed_fingerprint()
    }

    /// A registry holding one chain hop of `kind` under
    /// [`TEST_SELECTOR_TOKEN`] -- and NO direct UDP exit, so a datagram that
    /// resolves at all resolved through the chain block and not through the
    /// mesh-id fallback.
    async fn test_registry_with_chain_hop(
        mesh_id: &str,
        kind: MirageListenerKind,
    ) -> (Arc<ListenerRegistry>, [u8; 32]) {
        test_registry_with_chain_hop_role(
            mesh_id,
            kind,
            ListenerRole::Exit { exit_mode: ExitMode::Direct },
        )
        .await
    }

    async fn test_registry_with_chain_hop_role(
        mesh_id: &str,
        kind: MirageListenerKind,
        role: ListenerRole,
    ) -> (Arc<ListenerRegistry>, [u8; 32]) {
        let keypair = KeyPair::generate();
        let server_pub = keypair.public.to_bytes();
        let runtime = test_runtime(mesh_id, keypair);
        let registry = Arc::new(ListenerRegistry::new(ActivationContext {
            runtime,
            outbound_protocol: None,
            doh: None,
        }));
        registry
            .activate(chain_hop_spec(mesh_id, kind, role, 0, 1))
            .await
            .expect("a chain hop spec registers rather than binds");
        (registry, server_pub)
    }

    /// Capture the exact datagram a REAL chain-addressed client sends, the
    /// same way [`craft_real_client_hello`] captures an unaddressed one.
    async fn craft_chain_addressed_hello(
        perimeter_side: Arc<LocalDgramSocket>,
        node_side: Arc<LocalDgramSocket>,
        server_pub: [u8; 32],
        mesh_id: &[u8],
        address: DatagramChainAddress,
    ) -> Vec<u8> {
        let fake_peer = loopback(59998);
        let (_tx, rx) = mpsc::channel(4);
        let mut client_socket = UdpPeerSocket::from_relay(perimeter_side, FACE_PORT, fake_peer, rx);
        let client_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        let mesh_id = mesh_id.to_vec();
        let credential = mint_test_credential();
        let handle = tokio::spawn(async move {
            let _ = run_client_handshake_v9_datagram_with_chain(
                &mut client_socket,
                &server_pub,
                &client_priv,
                &mesh_id,
                &[AeadSuite::ChaCha20Poly1305],
                Some(&address),
                CredentialScheme::EpochHmac as u8,
                &credential,
            )
            .await;
        });
        let (_envelope, hello_bytes) = node_side
            .recv_envelope()
            .await
            .expect("capture the chain-addressed ClientHello the client relayed toward the node");
        handle.abort();
        hello_bytes
    }

    fn address_for(position: u8, length: u8, token: Vec<u8>) -> DatagramChainAddress {
        DatagramChainAddress {
            chain_id: TEST_CHAIN_ID.as_bytes().to_vec(),
            chain_position: position,
            chain_length: length,
            selector_token: token,
        }
    }

    /// Drive one chain-addressed datagram through the real dispatcher and
    /// session handler, and report whether anything at all came back.
    async fn dial_chain_addressed(
        registry: Arc<ListenerRegistry>,
        server_pub: [u8; 32],
        node_side: Arc<LocalDgramSocket>,
        perimeter_side: Arc<LocalDgramSocket>,
        address: DatagramChainAddress,
        peer_port: u16,
    ) -> bool {
        let hello = craft_chain_addressed_hello(
            Arc::clone(&perimeter_side),
            Arc::clone(&node_side),
            server_pub,
            b"TESTMESH",
            address,
        )
        .await;
        let cache = Arc::new(ServerHelloCache::new());
        let cancel = CancellationToken::new();
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let dispatch = tokio::spawn(run_dispatcher(
            Arc::clone(&node_side),
            sessions_tx,
            cancel.clone(),
            PEER_SWEEP_TRIGGER,
            PEER_IDLE_EVICT,
            PEER_LOW_WATER_MARK,
        ));

        let peer = loopback(peer_port);
        perimeter_side
            .send_envelope(DgramEnvelope { face_port: FACE_PORT, peer }, &hello)
            .await
            .expect("send the chain-addressed ClientHello as this peer's first datagram");
        let session = sessions_rx.recv().await.expect("a session must be announced");
        tokio::spawn(handle_udp_session(
            Arc::clone(&node_side),
            session,
            registry,
            cache,
            Arc::new(FsCreatedCache::new()),
        ));

        let replied =
            tokio::time::timeout(Duration::from_millis(400), perimeter_side.recv_envelope())
                .await
                .is_ok();
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
        replied
    }

    /// The positive half. A datagram naming a UDP chain hop this node DOES
    /// serve completes the handshake -- proving the chain block is what
    /// resolved it, because this registry holds no direct UDP exit for the
    /// mesh-id fallback to find.
    #[tokio::test]
    async fn a_datagram_naming_a_udp_hop_this_node_serves_is_answered() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) =
            test_registry_with_chain_hop("TESTMESH", MirageListenerKind::TunnelUdp).await;
        assert!(
            dial_chain_addressed(
                registry,
                server_pub,
                node_side,
                perimeter_side,
                address_for(0, 1, TEST_SELECTOR_TOKEN.to_vec()),
                64101,
            )
            .await,
            "a datagram addressing a registered UDP hop must get a ServerHello"
        );
    }

    /// The discriminating half, and the reason the positive test above is
    /// not self-satisfied: the SAME live dial, with a token this node minted
    /// for nobody, must get nothing. Without this, a resolver that ignored
    /// the block entirely would pass the test above.
    #[tokio::test]
    async fn a_datagram_naming_a_hop_this_node_does_not_serve_is_answered_with_nothing() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) =
            test_registry_with_chain_hop("TESTMESH", MirageListenerKind::TunnelUdp).await;
        assert!(
            !dial_chain_addressed(
                registry,
                server_pub,
                node_side,
                perimeter_side,
                address_for(0, 1, vec![0xEEu8; 16]),
                64102,
            )
            .await,
            "an unknown selector must produce no reply at all -- the miss and an auth failure are \
             one silence, and a reply here would make them tellable apart"
        );
    }

    /// A datagram may not be served by a hop the monitor minted for the
    /// STREAM transport, even when it names that hop's selector exactly.
    /// The transport a hop was minted for is the monitor's statement, and a
    /// caller does not get to reinterpret it by choosing a socket type.
    #[tokio::test]
    async fn a_datagram_naming_a_tcp_hops_selector_is_answered_with_nothing() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) =
            test_registry_with_chain_hop("TESTMESH", MirageListenerKind::TunnelTcp).await;
        assert!(
            !dial_chain_addressed(
                registry,
                server_pub,
                node_side,
                perimeter_side,
                address_for(0, 1, TEST_SELECTOR_TOKEN.to_vec()),
                64103,
            )
            .await,
            "the selector matches, so only the kind check can be refusing this -- if it ever \
             stops, a datagram session gets served against a stream listener's spec"
        );
    }

    /// A chain length the spec disagrees with is a topology this node was
    /// not told to serve. Same rule the stream side already enforces in
    /// `ChainRouting::resolve`, reached here through the datagram path.
    #[tokio::test]
    async fn a_datagram_claiming_a_deeper_chain_than_the_spec_is_answered_with_nothing() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) =
            test_registry_with_chain_hop("TESTMESH", MirageListenerKind::TunnelUdp).await;
        assert!(
            !dial_chain_addressed(
                registry,
                server_pub,
                node_side,
                perimeter_side,
                address_for(0, 3, TEST_SELECTOR_TOKEN.to_vec()),
                64104,
            )
            .await,
            "the spec says this hop is a chain of 1; a datagram calling it hop 0 of 3 describes \
             a topology the monitor never pushed"
        );
    }

    /// A chain-addressed datagram naming a RELAY hop must not be served as
    /// an exit.
    ///
    /// This is not a hypothetical. `try_handle` resolved `spec.role` and
    /// called `handle_udp_wire_exit` unconditionally; that was survivable
    /// only while `single_udp_direct_exit` — which filters to
    /// `Exit { Direct }` itself — was the only resolver. `resolve_datagram`
    /// resolves by selector and does not filter by role, so without the
    /// check this test guards, the FIRST hop of a datagram chain would open
    /// the client's traffic straight out to the internet while the client
    /// believed two more hops stood between.
    #[tokio::test]
    async fn a_datagram_naming_a_relay_hop_is_not_served_as_an_exit() {
        let (node_side, perimeter_side) = bind_relay_pair().await;
        let (registry, server_pub) = test_registry_with_chain_hop_role(
            "TESTMESH",
            MirageListenerKind::TunnelUdp,
            ListenerRole::Relay {
                position: mirage_core::mirage::wire::EntryHop::Entry,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
            },
        )
        .await;
        assert!(
            !dial_chain_addressed(
                registry,
                server_pub,
                node_side,
                perimeter_side,
                address_for(0, 1, TEST_SELECTOR_TOKEN.to_vec()),
                64105,
            )
            .await,
            "the selector and the kind both match, so only the role check can be refusing this \
             — if it ever stops, a relay hop becomes an exit and the chain is one hop long \
             without anyone being told"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // §"FS-chain datagram sessions" — U5 Slice 4 proof.
    //
    // Two real node fixtures (an entry `Relay` hop and an exit), wired
    // entry→exit over loopback exactly as a real relay's own outbound dial
    // would be, driven by a hand-rolled test client (NOT `OnionFsUdpTunnel`
    // — that type lives in mirage2web's mirage-dial-core, which this crate
    // does not depend on). The client replicates its wire-level behavior
    // using only `mirage-protocol` primitives this crate already depends on.
    // ─────────────────────────────────────────────────────────────────────
    mod fs_chain_udp_tests {
        use super::*;
        use mirage_core::config::TransportCamouflage;
        use mirage_core::mirage::mesh::{
            ChainBinding, ChainBindings, ChainExit, ChainFace, ChainId, ChainLeg, MeshId, NodeId,
            PeerTable, PeerTableEntry,
        };
        use mirage_core::mirage::wire::{EntryHop, RelayMode};
        use mirage_protocol::auth::v9::build_face_hello_bytes;
        use mirage_protocol::core::udp_handshake::{FS_CHAIN_HELLO_FLAG, SAFE_UDP_HANDSHAKE_PAYLOAD_LEN};
        use mirage_protocol::onion::builder::{
            compute_fs_auth_tag, compute_fs_transcript_base, derive_layer_key_v9_fs, extend_fs_transcript,
            OnionFsSession,
        };
        use mirage_protocol::onion::fs_frame::{FsCreatedFrame, FsExtendFrame};
        use mirage_protocol::onion::layer::{wrap_layer_v7, wrap_reply_layer_v7, NextHop};
        use x25519_dalek::{PublicKey, StaticSecret};

        const FS_TEST_CHAIN_ID: &str = "auto-fs-udp-e2e";
        const FS_EXIT_FACE_PORT: u16 = 4434;
        /// The face a THREE-hop fixture's middle relay publishes for the
        /// entry's own real outbound dial to land on — sibling of
        /// [`FS_EXIT_FACE_PORT`], same reasoning
        /// ([`spawn_bare_udp_bridge`]'s own doc): a middle hop is, from the
        /// dialer's point of view, exactly the same kind of real perimeter
        /// face a real exit's is.
        const FS_MIDDLE_FACE_PORT: u16 = 4435;

        /// [`test_runtime`] with a caller-chosen `node_id` instead of the
        /// fixed one that helper hardcodes. Every FS-chain fixture below
        /// needs its OWN identity (`resolve_onion_relay_config`'s
        /// `own_node_id` is read straight off this), which the shared
        /// stream/plain-UDP fixtures never needed since they are always the
        /// only hop in their own test. A new function rather than adding a
        /// parameter to `test_runtime`: that helper has six existing call
        /// sites, none of which care what the node_id is.
        fn fs_test_runtime(node_id: &str, mesh_id: &str, keypair: KeyPair) -> Arc<NodeRuntime> {
            let node_config: NodeConfig = serde_json::from_value(serde_json::json!({
                "node_id": node_id,
                "listen_addr": "127.0.0.1:0",
                "mode": {"Relay": {"fallback_dest": "", "fallback_sni": "", "upstreams": []}},
                "protocols": [],
                "admin_endpoint": null,
                "health_interval_secs": 30,
                "psk": null,
            }))
            .expect("test NodeConfig must deserialize");

            let credential_params = CredentialParams::single(
                1,
                CredentialScheme::EpochHmac,
                vec![EpochEntry::with_secret(TEST_CRED_EPOCH_ID, u64::MAX, TEST_CRED_SECRET)],
            );

            let snapshot = NodeRuntimeSnapshot {
                protocols: Vec::new(),
                pools: Vec::new(),
                relay_metrics: None,
                node_config,
                credential_params: Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(credential_params)))),
                spent_set: Arc::new(std::sync::Mutex::new(SpentSet::new())),
                role_signed_replay: Arc::new(std::sync::Mutex::new(
                    crate::core::role_signed_gate::RoleSignedReplayCache::new(),
                )),
                allow_legacy_v8: true,
            };

            NodeRuntime::new(snapshot, keypair, Arc::from(mesh_id), None, None)
        }

        /// Populate `runtime.chain_bindings`/`runtime.peer_table` so
        /// `resolve_onion_relay_config` finds a real, dialable next hop.
        /// Mirrors `tunnel_tcp::resolve_onion_relay_config_tests`'s own
        /// `two_hop_binding`/`peer_entry` shape exactly (that module's own
        /// proof that this shape resolves to `RelayDialResolution::Dial`).
        /// `next_hop_dial` is carried only in `PeerTableEntry.addr` for
        /// realism; this hop's own outbound dial (Slice 4's own MVP) reads
        /// the address from the client's `FsExtendFrame.next_hop_addr`
        /// instead, never from the peer table. See `udp_fs_peel.rs`'s own
        /// doc for why (Slice 6, camouflage wiring, is what would read this
        /// field; not built yet).
        fn install_next_hop(
            runtime: &Arc<NodeRuntime>,
            own_node_id: &str,
            next_node_id: &str,
            next_hop_dial: SocketAddr,
        ) {
            runtime.chain_bindings.store(Arc::new(ChainBindings {
                generation: 1,
                bindings: vec![ChainBinding {
                    mesh_id: MeshId::new("TESTMESH"),
                    chain_id: ChainId::new(FS_TEST_CHAIN_ID),
                    legs: vec![ChainLeg {
                        node_id: NodeId::new(own_node_id),
                        relay_mode: RelayMode::OnionPeel,
                        aead_suite: AeadSuite::ChaCha20Poly1305,
                        byte_cipher: None,
                        selector_token_hex: None,
                    }],
                    exit: ChainExit {
                        node_id: NodeId::new(next_node_id),
                        exit_mode: ExitMode::Onion,
                        aead_suite: AeadSuite::ChaCha20Poly1305,
                        selector_token_hex: None,
                    },
                    onion_reply_mode: None,
                    handshake: None,
                }],
            }));
            runtime.peer_table.store(Arc::new(PeerTable {
                generation: 1,
                peers: vec![PeerTableEntry {
                    mesh_id: MeshId::new("TESTMESH"),
                    responsible_monitor_id: String::new(),
                    node_id: NodeId::new(next_node_id),
                    pubkey_hex: "11".repeat(32),
                    addr: next_hop_dial.to_string(),
                    labels: Vec::new(),
                    updated_at_ms: 0,
                    aead_suite_preference: Vec::new(),
                    chain_face: Some(ChainFace { port: next_hop_dial.port(), camouflage: TransportCamouflage::None }),
                    chain_face_udp: None,
                }],
            }));
        }

        /// A chain-hop spec with NO minted selector token: every frame this
        /// module's test client crafts carries an empty `selector_token`, so
        /// resolution always goes through the derived-name fallback
        /// (`ChainSelector::from_chain_position`), matching a peer that
        /// predates the token.
        ///
        /// `id` MUST be `{chain_id}-h{position}` — the no-token fallback on
        /// the SPEC side (`ChainSelector::for_spec`) is the `ListenerId`'s
        /// own bytes, and the no-token fallback on the WIRE side
        /// (`ChainSelector::from_frame` → `from_chain_position`) is the
        /// derived `{chain_id}-h{position}` name; the two only agree because
        /// every real spec-minting call site names listeners that way
        /// (`selector.rs`'s own `the_wire_derivation_matches_the_registry_key`
        /// pins exactly this). An arbitrary id here would silently make
        /// every FS-chain fixture in this module unaddressable.
        ///
        /// `chain_node_ids` is the FULL ordered per-position identity list —
        /// `resolve_onion_relay_config`/`resolve_onion_exit_config` read
        /// `chain_node_ids[position]` as the `node_id` handed to
        /// `peel_onion_fs_layer`'s own transcript binding, and this test
        /// client independently computes the same transcript from the SAME
        /// node_id string (`dial_fs_chain_hop0`/`extend_fs_chain_hop`'s own
        /// `hop_node_id` argument) — an empty list here (this file's other
        /// chain fixtures leave it empty, since their tests never run a real
        /// FS handshake past resolution) would silently desync the two
        /// sides' transcripts.
        fn fs_chain_hop_spec(
            mesh_id: &str,
            kind: MirageListenerKind,
            role: ListenerRole,
            position: u8,
            length: u8,
            chain_node_ids: Vec<String>,
        ) -> ListenerSpec {
            ListenerSpec {
                id: ListenerId(format!("{FS_TEST_CHAIN_ID}-h{position}")),
                mesh_id: mesh_id.to_string(),
                kind,
                role,
                framing: Framing::Plain,
                ingress_layer: None,
                outgoing_layer: None,
                aead_suite: AeadSuite::ChaCha20Poly1305,
                bind_port: None,
                chain_role: Some(mirage_core::mirage::wire::ChainRole {
                    chain_id: FS_TEST_CHAIN_ID.to_string(),
                    chain_position: position,
                    chain_length: length,
                    chain_node_ids,
                    next_hop_addr: None,
                    selector_token_hex: None,
                }),
                control_target: None,
                payload: None,
                fingerprint: SpecFingerprint([0u8; 32]),
            }
            .with_recomputed_fingerprint()
        }

        async fn fs_chain_registry(
            runtime: Arc<NodeRuntime>,
            kind: MirageListenerKind,
            role: ListenerRole,
            position: u8,
            length: u8,
            chain_node_ids: Vec<String>,
        ) -> Arc<ListenerRegistry> {
            let registry =
                Arc::new(ListenerRegistry::new(ActivationContext { runtime, outbound_protocol: None, doh: None }));
            registry
                .activate(fs_chain_hop_spec("TESTMESH", kind, role, position, length, chain_node_ids))
                .await
                .expect("an FS-chain hop spec registers rather than binds");
            registry
        }

        /// This machine's own real (non-loopback) local IPv4 address.
        ///
        /// `UdpSocket::connect` only performs a routing-table lookup for a
        /// UDP socket — it never sends a packet — so this needs no network
        /// reachability at all, only a configured non-loopback interface,
        /// which every real OS install has (even an unplugged/private one).
        /// Used ONLY to give the relay's own outbound dial (Slice 4's own
        /// MVP, no camouflage, raw next-hop UDP) an address that clears
        /// `policy::is_blocked` the way a real next hop's address would —
        /// see [`spawn_bare_udp_bridge`]'s own doc for why `127.0.0.1`
        /// cannot.
        async fn discover_local_nonloopback_ip() -> std::net::IpAddr {
            let probe = UdpSocket::bind("0.0.0.0:0").await.expect("bind ip-discovery probe socket");
            probe.connect("8.8.8.8:80").await.expect("route lookup toward a public address");
            probe.local_addr().expect("probe local addr").ip()
        }

        /// A minimal stand-in for a REAL public perimeter face: binds one
        /// real, bare loopback `UdpSocket` and bridges it to `bridge_side`
        /// (the OTHER half of a [`bind_relay_pair`] pair from the node under
        /// test's own `LocalDgramSocket`), translating in both directions.
        ///
        /// Needed only for the leg a relay's OWN outbound dial reaches:
        /// `handle_udp_fs_peel` binds a REAL `tokio::net::UdpSocket` and
        /// `.connect()`s it to an address it expects to be able to reach
        /// with bare UDP, exactly as it would dial a real box's real
        /// perimeter face. Every OTHER leg in this module's fixtures (the
        /// test client dialing the entry) reuses the existing
        /// `LocalDgramSocket`-only pattern (`bind_relay_pair`/
        /// `fake_client_socket`) unchanged, because nothing on that leg ever
        /// needs a real, independently-dialable socket address.
        ///
        /// Binds the real socket on the CALLER's own task, before spawning
        /// anything — a single-threaded `#[tokio::test]` runtime has exactly
        /// one worker thread, and a synchronous, blocking hand-off (a
        /// `std::sync::mpsc` reply channel a spawned task's own bind would
        /// need to answer through) would starve that ONE thread the spawned
        /// task itself needs to run on, deadlocking the caller against its
        /// own child. Binding here and moving the already-bound socket into
        /// the spawned loop needs no cross-task signal at all.
        ///
        /// Binds ALL interfaces (`0.0.0.0`), not loopback specifically, and
        /// reports [`discover_local_nonloopback_ip`]'s address rather than
        /// the bind's own — `policy::is_blocked` unconditionally refuses
        /// loopback as an exit-side dial target (see
        /// `family::mirage::exit::policy::is_blocked_exit_target`'s own
        /// doc), so a relay's REAL outbound dial — the exact code path this
        /// fixture exists to drive — can never complete against a `127.0.0.1`
        /// next-hop address no matter how the receiving socket is bound. The
        /// caller must also call
        /// `family::mirage::exit::policy::set_allow_private_exit_targets(true)`
        /// once per process, since the discovered address is very likely
        /// RFC-1918 private, which that gate blocks by default too.
        async fn spawn_bare_udp_bridge(
            bridge_side: Arc<LocalDgramSocket>,
            face_port: u16,
        ) -> (tokio::task::JoinHandle<()>, SocketAddr) {
            let real_sock = UdpSocket::bind("0.0.0.0:0").await.expect("bind bare udp bridge socket");
            let port = real_sock.local_addr().expect("bare udp bridge addr").port();
            let addr = SocketAddr::new(discover_local_nonloopback_ip().await, port);
            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    tokio::select! {
                        recvd = real_sock.recv_from(&mut buf) => match recvd {
                            Ok((n, from)) => {
                                if bridge_side
                                    .send_envelope(DgramEnvelope { face_port, peer: from }, &buf[..n])
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        },
                        recvd = bridge_side.recv_envelope() => match recvd {
                            Ok((envelope, payload)) => {
                                if real_sock.send_to(&payload, envelope.peer).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        },
                    }
                }
            });
            (handle, addr)
        }

        /// Dial hop 0 (the entry) directly: send the classifier-token hello
        /// plus `FsInitFrame`, read and verify `FsCreatedFrame(0)`, derive
        /// layer key 0. Returns `(key0, suite, transcript0)`.
        ///
        /// `socket` must already be wired through [`spawn_fake_perimeter`]
        /// (via [`fake_client_socket`]) — a `UdpPeerSocket::from_relay` built
        /// against a throwaway, never-fed channel would never observe a
        /// reply at all: the perimeter relay's OWN demux is what forwards
        /// `entry_perimeter_side.recv_envelope()` results into THIS peer's
        /// channel by matching `envelope.peer`, and nothing else does that
        /// wiring. This module's own client fixtures reuse that existing
        /// harness piece rather than reinventing it.
        #[allow(clippy::too_many_arguments)]
        async fn dial_fs_chain_hop0(
            socket: &UdpPeerSocket,
            mesh_id: &[u8],
            chain_length: u8,
            hop0_pubkey: [u8; 32],
            hop0_node_id: &str,
            credential: Option<Vec<u8>>,
        ) -> Result<([u8; 32], AeadSuite, [u8; 32]), MirageError> {
            let suite = AeadSuite::ChaCha20Poly1305;
            let mut hello = build_face_hello_bytes();
            hello[92] |= FS_CHAIN_HELLO_FLAG;
            socket.send(&hello).await?;

            let client_eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let client_eph_pub = PublicKey::from(&client_eph).to_bytes();

            let (cred_scheme, cred_bytes) = match credential {
                Some(c) => (CredentialScheme::EpochHmac as u8, c),
                None => (0x00, Vec::new()),
            };
            let init = FsInitFrame {
                mesh_id: mesh_id.to_vec(),
                chain_id: FS_TEST_CHAIN_ID.as_bytes().to_vec(),
                chain_length,
                chain_position: 0,
                client_suites: vec![suite],
                client_eph_pub,
                expected_peer_table_generation: 0,
                credential_scheme: cred_scheme,
                credential: cred_bytes,
                selector_token: Vec::new(),
            };
            socket.send(&init.encode()?).await?;

            let mut buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
            let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
                .await
                .map_err(|_| MirageError::HandshakeTimedOut("hop 0: no FsCreated".into()))??;
            let created = FsCreatedFrame::decode(&buf[..n])?;
            if !created.status.is_ok() {
                return Err(MirageError::Protocol(format!(
                    "hop 0: {} (code {})",
                    created.status.name(),
                    created.status.as_u32()
                )));
            }

            let base = compute_fs_transcript_base(mesh_id, FS_TEST_CHAIN_ID.as_bytes());
            let transcript0 = extend_fs_transcript(
                &base,
                0,
                hop0_node_id,
                &client_eph_pub,
                &created.server_eph_pub,
                &hop0_pubkey,
                suite,
            );
            if created.transcript_hash != transcript0 {
                return Err(MirageError::Protocol("hop 0: transcript mismatch".into()));
            }

            let ee = client_eph.diffie_hellman(&PublicKey::from(created.server_eph_pub)).to_bytes();
            let es = client_eph.diffie_hellman(&PublicKey::from(hop0_pubkey)).to_bytes();
            let key0 = derive_layer_key_v9_fs(&ee, &es, 0, &transcript0, suite);
            let expected_auth = compute_fs_auth_tag(&key0, &transcript0, &created.server_eph_pub);
            if created.auth_tag != expected_auth {
                return Err(MirageError::Protocol("hop 0: auth_tag mismatch".into()));
            }

            Ok((key0, suite, transcript0))
        }

        /// Extend the circuit to `position` (>= 1): wrap an `FsExtendFrame`
        /// through every already-established layer, send it, read and
        /// verify `FsCreatedFrame(position)`, derive the new layer key.
        /// Returns `(new_key, new_transcript)`.
        #[allow(clippy::too_many_arguments)]
        async fn extend_fs_chain_hop(
            socket: &UdpPeerSocket,
            position: u8,
            layer_keys: &[[u8; 32]],
            layer_suites: &[AeadSuite],
            prev_transcript: [u8; 32],
            hop_pubkey: [u8; 32],
            hop_node_id: &str,
            next_hop_addr: SocketAddr,
        ) -> Result<([u8; 32], [u8; 32]), MirageError> {
            let suite = AeadSuite::ChaCha20Poly1305;
            let client_eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let client_eph_pub = PublicKey::from(&client_eph).to_bytes();

            let extend = FsExtendFrame {
                chain_position: position,
                next_hop_addr: next_hop_addr.to_string(),
                client_eph_pub,
                expected_peer_table_generation: 0,
                client_suites: vec![suite],
                prev_transcript,
                selector_token: Vec::new(),
            };
            let mut wire_bytes = extend.encode()?;
            for j in (0..layer_keys.len()).rev() {
                wire_bytes = wrap_layer_v7(layer_suites[j], &NextHop::Terminal, &layer_keys[j], &wire_bytes)?;
            }
            socket.send(&wire_bytes).await?;

            let mut buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
            let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
                .await
                .map_err(|_| MirageError::HandshakeTimedOut(format!("hop {position}: no FsCreated")))??;
            let created = FsCreatedFrame::decode(&buf[..n])?;
            if !created.status.is_ok() {
                return Err(MirageError::Protocol(format!(
                    "hop {position}: {} (code {})",
                    created.status.name(),
                    created.status.as_u32()
                )));
            }

            let transcript_i = extend_fs_transcript(
                &prev_transcript,
                position,
                hop_node_id,
                &client_eph_pub,
                &created.server_eph_pub,
                &hop_pubkey,
                suite,
            );
            if created.transcript_hash != transcript_i {
                return Err(MirageError::Protocol(format!("hop {position}: transcript mismatch")));
            }

            let ee = client_eph.diffie_hellman(&PublicKey::from(created.server_eph_pub)).to_bytes();
            let es = client_eph.diffie_hellman(&PublicKey::from(hop_pubkey)).to_bytes();
            let key_i = derive_layer_key_v9_fs(&ee, &es, position, &transcript_i, suite);
            let expected_auth = compute_fs_auth_tag(&key_i, &transcript_i, &created.server_eph_pub);
            if created.auth_tag != expected_auth {
                return Err(MirageError::Protocol(format!("hop {position}: auth_tag mismatch")));
            }

            Ok((key_i, transcript_i))
        }

        // -- 1. Full E2E: client -> entry(relay) -> exit -> real target -> back --

        #[tokio::test]
        async fn an_fs_chain_datagram_session_carries_client_bytes_through_two_hops_to_a_real_target_and_back()
        {
            // The relay's own outbound dial (to the exit's bridge, below)
            // must clear `policy::is_blocked` exactly like a real next-hop
            // address would — see `spawn_bare_udp_bridge`'s own doc for why
            // that means a real, non-loopback local address, which is very
            // likely RFC-1918 private and needs this relaxed once per
            // process.
            crate::family::mirage::exit::policy::set_allow_private_exit_targets(true);

            // The real internet-facing UDP target both hops eventually
            // reach. Bound on ALL interfaces and addressed by a real
            // non-loopback local IP for the identical reason the exit's own
            // dial-to-next-hop bridge is, above: `resolve_udp_target`
            // (`exit::direct`) runs the SAME `policy::is_blocked` gate on
            // the exit's own destination, and a `127.0.0.1` target would be
            // refused there exactly like a chain-internal loopback hop.
            let target = UdpSocket::bind("0.0.0.0:0").await.expect("bind real target socket");
            let target_addr =
                SocketAddr::new(discover_local_nonloopback_ip().await, target.local_addr().expect("target port").port());
            let target_task = tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let (n, from) = target.recv_from(&mut buf).await.expect("target recv");
                assert_eq!(&buf[..n], b"hello through two fs hops");
                target.send_to(b"reply from real target", from).await.expect("target reply");
            });

            // -- Exit fixture --
            let exit_kp = KeyPair::generate();
            let exit_pub = exit_kp.public.to_bytes();
            let exit_runtime = fs_test_runtime("exit-node", "TESTMESH", exit_kp);
            let chain_node_ids = vec!["entry-node".to_string(), "exit-node".to_string()];
            let exit_registry = fs_chain_registry(
                Arc::clone(&exit_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Exit { exit_mode: ExitMode::Onion },
                1,
                2,
                chain_node_ids.clone(),
            )
            .await;
            let (exit_node_side, exit_bridge_side) = bind_relay_pair().await;
            let (bridge_handle, exit_dial_addr) = spawn_bare_udp_bridge(exit_bridge_side, FS_EXIT_FACE_PORT).await;
            let exit_cancel = CancellationToken::new();
            let exit_server = tokio::spawn(run_server(Arc::clone(&exit_node_side), exit_registry, exit_cancel.clone()));

            // -- Entry fixture (relay) --
            let entry_kp = KeyPair::generate();
            let entry_pub = entry_kp.public.to_bytes();
            let entry_runtime = fs_test_runtime("entry-node", "TESTMESH", entry_kp);
            install_next_hop(&entry_runtime, "entry-node", "exit-node", exit_dial_addr);
            let entry_registry = fs_chain_registry(
                Arc::clone(&entry_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Entry, relay_mode: RelayMode::OnionPeel },
                0,
                2,
                chain_node_ids,
            )
            .await;
            let (entry_node_side, entry_perimeter_side) = bind_relay_pair().await;
            let entry_cancel = CancellationToken::new();
            let entry_server =
                tokio::spawn(run_server(Arc::clone(&entry_node_side), entry_registry, entry_cancel.clone()));

            // -- Client dials the entry, then extends to the exit --
            let (fake_perimeter, routes) = spawn_fake_perimeter(Arc::clone(&entry_perimeter_side));
            let client_peer = loopback(58001);
            let socket = fake_client_socket(Arc::clone(&entry_perimeter_side), &routes, FACE_PORT, client_peer);
            let (key0, suite0, transcript0) = dial_fs_chain_hop0(
                &socket,
                b"TESTMESH",
                2,
                entry_pub,
                "entry-node",
                Some(mint_test_credential()),
            )
            .await
            .expect("hop 0 (entry) handshake must succeed");

            let (key1, _transcript1) = extend_fs_chain_hop(
                &socket,
                1,
                &[key0],
                &[suite0],
                transcript0,
                exit_pub,
                "exit-node",
                exit_dial_addr,
            )
            .await
            .expect("hop 1 (exit) handshake must succeed through the entry's own relay dial");

            let layer_keys = vec![key0, key1];
            let layer_suites = vec![suite0, suite0];

            // -- First datagram: the bare, trimmed target -- the DATAGRAM
            // plane's own convention (`parse_target_datagram`'s doc), the
            // same shape a real client (`OnionFsUdpTunnel::connect` /
            // `mirage-dial-core`'s `run_datagram_udp_session`) sends and the
            // same shape `handle_udp_wire_exit`'s direct datagram exit reads
            // -- NOT the stream onion plane's `[2B len][target]` framing this
            // test used to drive.
            let target_str = target_addr.to_string();
            let wrapped_target = wrap_reply_layer_v7(layer_suites[1], &layer_keys[1], target_str.as_bytes())
                .expect("wrap target datagram");
            socket.send(&wrapped_target).await.expect("send target datagram");

            // -- Second datagram: raw payload, relayed exactly like every
            // later datagram -- never packed alongside the target.
            let wrapped_payload =
                wrap_reply_layer_v7(layer_suites[1], &layer_keys[1], b"hello through two fs hops")
                    .expect("wrap payload datagram");
            socket.send(&wrapped_payload).await.expect("send payload datagram");

            target_task.await.expect("target task must not panic");

            // -- The reply must round-trip back through both layers --
            let session = OnionFsSession {
                layer_keys: layer_keys.clone(),
                layer_aead_suites: layer_suites.clone(),
                client_eph_pubs: Vec::new(),
                server_eph_pubs: Vec::new(),
                transcripts: Vec::new(),
            };
            let mut reply_buf = [0u8; 512];
            let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut reply_buf))
                .await
                .expect("the reply must arrive")
                .expect("recv must succeed");
            let plaintext = session.unwrap_reply(&reply_buf[..n]).expect("unwrap the two-layer reply");
            assert_eq!(
                plaintext, b"reply from real target",
                "the real target's own reply must round-trip through both onion layers unchanged"
            );

            entry_cancel.cancel();
            exit_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), entry_server).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), exit_server).await;
            bridge_handle.abort();
            fake_perimeter.abort();
        }

        // -- 1b. Full E2E through a MIDDLE relay hop: client -> entry ->
        //        middle -> exit -> real target -> back --

        /// The THREE-hop twin of
        /// [`an_fs_chain_datagram_session_carries_client_bytes_through_two_hops_to_a_real_target_and_back`]:
        /// same shape, one more layer. Every OTHER fixture in this module
        /// only ever builds `ListenerRole::Relay { position: EntryHop::Entry,
        /// .. }` hops — `EntryHop::Hop` (a MIDDLE relay, one that is both
        /// the target of another relay's own real outbound dial AND the
        /// dialer of a further hop) had never been driven through a live
        /// [`handle_udp_fs_peel`] call by any test before this one. That gap
        /// is why a real 3/4-hop chain failure on a lab mesh could not be told
        /// apart from a middle-hop defect by this suite alone — see the U5
        /// design doc's own dated note and `dial_next_hop`'s doc for the
        /// actual (already-fixed) root cause.
        #[tokio::test]
        async fn an_fs_chain_datagram_session_carries_client_bytes_through_a_middle_relay_hop_to_a_real_target_and_back()
        {
            // Both relay legs' own outbound dials (entry->middle,
            // middle->exit) need this relaxed for the same reason the
            // two-hop test above does.
            crate::family::mirage::exit::policy::set_allow_private_exit_targets(true);

            let target = UdpSocket::bind("0.0.0.0:0").await.expect("bind real target socket");
            let target_addr = SocketAddr::new(
                discover_local_nonloopback_ip().await,
                target.local_addr().expect("target port").port(),
            );
            let target_task = tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let (n, from) = target.recv_from(&mut buf).await.expect("target recv");
                assert_eq!(&buf[..n], b"hello through three fs hops, one of them a middle relay");
                target
                    .send_to(b"reply from real target through three hops", from)
                    .await
                    .expect("target reply");
            });

            let chain_node_ids = vec![
                "entry-node-3h".to_string(),
                "middle-node-3h".to_string(),
                "exit-node-3h".to_string(),
            ];

            // -- Exit fixture --
            let exit_kp = KeyPair::generate();
            let exit_pub = exit_kp.public.to_bytes();
            let exit_runtime = fs_test_runtime("exit-node-3h", "TESTMESH", exit_kp);
            let exit_registry = fs_chain_registry(
                Arc::clone(&exit_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Exit { exit_mode: ExitMode::Onion },
                2,
                3,
                chain_node_ids.clone(),
            )
            .await;
            let (exit_node_side, exit_bridge_side) = bind_relay_pair().await;
            let (exit_bridge_handle, exit_dial_addr) = spawn_bare_udp_bridge(exit_bridge_side, FS_EXIT_FACE_PORT).await;
            let exit_cancel = CancellationToken::new();
            let exit_server = tokio::spawn(run_server(Arc::clone(&exit_node_side), exit_registry, exit_cancel.clone()));

            // -- Middle fixture (relay, `EntryHop::Hop`) -- a real,
            // dialable perimeter face the entry's own outbound dial lands
            // on, which in turn makes its OWN real outbound dial to the
            // exit above: the exact position this module's other fixtures
            // never exercised.
            let middle_kp = KeyPair::generate();
            let middle_pub = middle_kp.public.to_bytes();
            let middle_runtime = fs_test_runtime("middle-node-3h", "TESTMESH", middle_kp);
            install_next_hop(&middle_runtime, "middle-node-3h", "exit-node-3h", exit_dial_addr);
            let middle_registry = fs_chain_registry(
                Arc::clone(&middle_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Hop, relay_mode: RelayMode::OnionPeel },
                1,
                3,
                chain_node_ids.clone(),
            )
            .await;
            let (middle_node_side, middle_bridge_side) = bind_relay_pair().await;
            let (middle_bridge_handle, middle_dial_addr) =
                spawn_bare_udp_bridge(middle_bridge_side, FS_MIDDLE_FACE_PORT).await;
            let middle_cancel = CancellationToken::new();
            let middle_server =
                tokio::spawn(run_server(Arc::clone(&middle_node_side), middle_registry, middle_cancel.clone()));

            // -- Entry fixture (relay, `EntryHop::Entry`) --
            let entry_kp = KeyPair::generate();
            let entry_pub = entry_kp.public.to_bytes();
            let entry_runtime = fs_test_runtime("entry-node-3h", "TESTMESH", entry_kp);
            install_next_hop(&entry_runtime, "entry-node-3h", "middle-node-3h", middle_dial_addr);
            let entry_registry = fs_chain_registry(
                Arc::clone(&entry_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Entry, relay_mode: RelayMode::OnionPeel },
                0,
                3,
                chain_node_ids,
            )
            .await;
            let (entry_node_side, entry_perimeter_side) = bind_relay_pair().await;
            let entry_cancel = CancellationToken::new();
            let entry_server =
                tokio::spawn(run_server(Arc::clone(&entry_node_side), entry_registry, entry_cancel.clone()));

            // -- Client dials the entry, extends to the middle, extends to the exit --
            let (fake_perimeter, routes) = spawn_fake_perimeter(Arc::clone(&entry_perimeter_side));
            let client_peer = loopback(58004);
            let socket = fake_client_socket(Arc::clone(&entry_perimeter_side), &routes, FACE_PORT, client_peer);
            let (key0, suite0, transcript0) = dial_fs_chain_hop0(
                &socket,
                b"TESTMESH",
                3,
                entry_pub,
                "entry-node-3h",
                Some(mint_test_credential()),
            )
            .await
            .expect("hop 0 (entry) handshake must succeed");

            let (key1, transcript1) = extend_fs_chain_hop(
                &socket,
                1,
                &[key0],
                &[suite0],
                transcript0,
                middle_pub,
                "middle-node-3h",
                middle_dial_addr,
            )
            .await
            .expect("hop 1 (middle relay) handshake must succeed through the entry's own relay dial");

            let (key2, _transcript2) = extend_fs_chain_hop(
                &socket,
                2,
                &[key0, key1],
                &[suite0, suite0],
                transcript1,
                exit_pub,
                "exit-node-3h",
                exit_dial_addr,
            )
            .await
            .expect("hop 2 (exit) handshake must succeed through the middle relay's own relay dial");

            let layer_keys = vec![key0, key1, key2];
            let layer_suites = vec![suite0, suite0, suite0];

            // Forward data carries only the EXIT layer's own wrap — an
            // intermediate relay (entry or middle) never touches it, exactly
            // like the two-hop fixture above.
            let target_str = target_addr.to_string();
            let wrapped_target = wrap_reply_layer_v7(layer_suites[2], &layer_keys[2], target_str.as_bytes())
                .expect("wrap target datagram");
            socket.send(&wrapped_target).await.expect("send target datagram");

            let wrapped_payload = wrap_reply_layer_v7(
                layer_suites[2],
                &layer_keys[2],
                b"hello through three fs hops, one of them a middle relay",
            )
            .expect("wrap payload datagram");
            socket.send(&wrapped_payload).await.expect("send payload datagram");

            target_task.await.expect("target task must not panic");

            // -- The reply must round-trip back through all THREE layers —
            // the exit's own bare wrap, then the middle relay's own
            // `[4B len]`-framed wrap, then the entry's own — proving the
            // middle hop's reply-path wrap is exercised too, not just its
            // setup-time dial.
            let session = OnionFsSession {
                layer_keys: layer_keys.clone(),
                layer_aead_suites: layer_suites.clone(),
                client_eph_pubs: Vec::new(),
                server_eph_pubs: Vec::new(),
                transcripts: Vec::new(),
            };
            let mut reply_buf = [0u8; 512];
            let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut reply_buf))
                .await
                .expect("the reply must arrive")
                .expect("recv must succeed");
            let plaintext = session.unwrap_reply(&reply_buf[..n]).expect("unwrap the three-layer reply");
            assert_eq!(
                plaintext, b"reply from real target through three hops",
                "the real target's own reply must round-trip through all three onion layers \
                 unchanged, including the middle relay's own reply-wrap"
            );

            entry_cancel.cancel();
            middle_cancel.cancel();
            exit_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), entry_server).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), middle_server).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), exit_server).await;
            exit_bridge_handle.abort();
            middle_bridge_handle.abort();
            fake_perimeter.abort();
        }

        // -- 2. A relay hop whose next-hop dial fails answers nothing more --

        #[tokio::test]
        async fn a_relay_hop_whose_next_hop_dial_fails_answers_nothing_beyond_its_own_created_frame() {
            let entry_kp = KeyPair::generate();
            let entry_pub = entry_kp.public.to_bytes();
            let entry_runtime = fs_test_runtime("entry-node-2", "TESTMESH", entry_kp);
            // A real, dialable next hop as far as `resolve_onion_relay_config`
            // is concerned. The failure this test proves is the SOCKET-level
            // dial to the address the CLIENT names, not a missing chain face.
            install_next_hop(&entry_runtime, "entry-node-2", "exit-node-2", loopback(1));
            let entry_registry = fs_chain_registry(
                Arc::clone(&entry_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Entry, relay_mode: RelayMode::OnionPeel },
                0,
                2,
                vec!["entry-node-2".to_string(), "exit-node-2".to_string()],
            )
            .await;
            let (entry_node_side, entry_perimeter_side) = bind_relay_pair().await;
            let entry_cancel = CancellationToken::new();
            let entry_server =
                tokio::spawn(run_server(Arc::clone(&entry_node_side), entry_registry, entry_cancel.clone()));

            let (fake_perimeter, routes) = spawn_fake_perimeter(Arc::clone(&entry_perimeter_side));
            let client_peer = loopback(58002);
            let socket = fake_client_socket(Arc::clone(&entry_perimeter_side), &routes, FACE_PORT, client_peer);
            let (key0, suite0, transcript0) = dial_fs_chain_hop0(
                &socket,
                b"TESTMESH",
                2,
                entry_pub,
                "entry-node-2",
                None,
            )
            .await
            .expect("hop 0's own peel must succeed -- this test proves what happens AFTER it");

            // A destination `policy::is_blocked` refuses on sight -- the same
            // address this file's own test 4 already proves is SSRF-blocked
            // (`the_first_datagram_sets_the_destination_and_is_never_forwarded_as_payload`).
            let blocked_next_hop: SocketAddr = "127.0.0.1:9".parse().expect("valid addr");
            let result = extend_fs_chain_hop(
                &socket,
                1,
                &[key0],
                &[suite0],
                transcript0,
                [0u8; 32],
                "exit-node-2",
                blocked_next_hop,
            )
            .await;
            assert!(
                result.is_err(),
                "the next hop's dial is SSRF-blocked, so no FsCreated(1) can ever arrive: {result:?}"
            );

            // Nothing more must ever arrive on this same socket: the relay's
            // own contract is silence beyond what it already sent for its
            // own hop (`FsCreated(0)`, already consumed by `dial_fs_chain_hop0`
            // above).
            let mut buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
            let extra = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await;
            assert!(
                extra.is_err(),
                "a relay whose next-hop dial fails must answer nothing beyond its own \
                 already-sent FsCreated(0) -- got: {extra:?}"
            );

            entry_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), entry_server).await;
            fake_perimeter.abort();
        }

        // -- 2b. A MIDDLE relay hop whose own next-hop dial fails answers nothing more --

        /// The `EntryHop::Hop` twin of
        /// [`a_relay_hop_whose_next_hop_dial_fails_answers_nothing_beyond_its_own_created_frame`]:
        /// the entry's own dial to the middle succeeds for real, and it is
        /// the MIDDLE relay's own next-hop dial (to what would be the exit)
        /// that is SSRF-blocked. Proves the silence-on-failure contract
        /// holds one hop deeper than the entry-only sibling test can show.
        #[tokio::test]
        async fn a_middle_relay_hop_whose_next_hop_dial_fails_answers_nothing_beyond_its_own_created_frame() {
            crate::family::mirage::exit::policy::set_allow_private_exit_targets(true);

            let chain_node_ids = vec![
                "entry-node-2h".to_string(),
                "middle-node-2h".to_string(),
                "exit-node-2h".to_string(),
            ];

            // -- Middle fixture: a real, dialable relay hop the entry's own
            // dial reaches. Its OWN next-hop dial (below, to a name that
            // resolves but is SSRF-blocked) is what this test proves fails
            // silently.
            let middle_kp = KeyPair::generate();
            let middle_pub = middle_kp.public.to_bytes();
            let middle_runtime = fs_test_runtime("middle-node-2h", "TESTMESH", middle_kp);
            // A real, dialable next hop as far as `resolve_onion_relay_config`
            // is concerned -- same reasoning as the entry-only sibling
            // test's own `install_next_hop` call: the failure this test
            // proves is the SOCKET-level dial to the address the CLIENT
            // names, not a missing chain face.
            install_next_hop(&middle_runtime, "middle-node-2h", "exit-node-2h", loopback(1));
            let middle_registry = fs_chain_registry(
                Arc::clone(&middle_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Hop, relay_mode: RelayMode::OnionPeel },
                1,
                3,
                chain_node_ids.clone(),
            )
            .await;
            let (middle_node_side, middle_bridge_side) = bind_relay_pair().await;
            let (middle_bridge_handle, middle_dial_addr) =
                spawn_bare_udp_bridge(middle_bridge_side, FS_MIDDLE_FACE_PORT).await;
            let middle_cancel = CancellationToken::new();
            let middle_server =
                tokio::spawn(run_server(Arc::clone(&middle_node_side), middle_registry, middle_cancel.clone()));

            // -- Entry fixture --
            let entry_kp = KeyPair::generate();
            let entry_pub = entry_kp.public.to_bytes();
            let entry_runtime = fs_test_runtime("entry-node-2h", "TESTMESH", entry_kp);
            install_next_hop(&entry_runtime, "entry-node-2h", "middle-node-2h", middle_dial_addr);
            let entry_registry = fs_chain_registry(
                Arc::clone(&entry_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Entry, relay_mode: RelayMode::OnionPeel },
                0,
                3,
                chain_node_ids,
            )
            .await;
            let (entry_node_side, entry_perimeter_side) = bind_relay_pair().await;
            let entry_cancel = CancellationToken::new();
            let entry_server =
                tokio::spawn(run_server(Arc::clone(&entry_node_side), entry_registry, entry_cancel.clone()));

            let (fake_perimeter, routes) = spawn_fake_perimeter(Arc::clone(&entry_perimeter_side));
            let client_peer = loopback(58005);
            let socket = fake_client_socket(Arc::clone(&entry_perimeter_side), &routes, FACE_PORT, client_peer);
            let (key0, suite0, transcript0) =
                dial_fs_chain_hop0(&socket, b"TESTMESH", 3, entry_pub, "entry-node-2h", None)
                    .await
                    .expect("hop 0 (entry) handshake must succeed");

            let (key1, transcript1) = extend_fs_chain_hop(
                &socket,
                1,
                &[key0],
                &[suite0],
                transcript0,
                middle_pub,
                "middle-node-2h",
                middle_dial_addr,
            )
            .await
            .expect("hop 1 (middle) handshake must succeed -- this test proves what happens AFTER its own dial");

            // A destination `policy::is_blocked` refuses on sight -- the
            // same address this file's own tests already prove is
            // SSRF-blocked.
            let blocked_next_hop: SocketAddr = "127.0.0.1:9".parse().expect("valid addr");
            let result = extend_fs_chain_hop(
                &socket,
                2,
                &[key0, key1],
                &[suite0, suite0],
                transcript1,
                [0u8; 32],
                "exit-node-2h",
                blocked_next_hop,
            )
            .await;
            assert!(
                result.is_err(),
                "the middle relay's own next-hop dial is SSRF-blocked, so no FsCreated(2) can \
                 ever arrive: {result:?}"
            );

            // Nothing more must ever arrive on this same socket: the middle
            // relay's own contract is silence beyond what it (and the entry,
            // forwarding for it) already sent -- `FsCreated(0)` and
            // `FsCreated(1)`, both already consumed above.
            let mut buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
            let extra = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await;
            assert!(
                extra.is_err(),
                "a middle relay whose own next-hop dial fails must answer nothing beyond what \
                 already went out for its own hop -- got: {extra:?}"
            );

            entry_cancel.cancel();
            middle_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), entry_server).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), middle_server).await;
            middle_bridge_handle.abort();
            fake_perimeter.abort();
        }

        // -- 3. A frame naming a hop this node does not serve answers nothing --

        #[tokio::test]
        async fn a_frame_naming_an_fs_chain_hop_this_node_does_not_serve_is_answered_with_nothing() {
            let entry_kp = KeyPair::generate();
            let entry_runtime = fs_test_runtime("entry-node-3", "TESTMESH", entry_kp);
            let entry_registry = fs_chain_registry(
                Arc::clone(&entry_runtime),
                MirageListenerKind::TunnelUdp,
                ListenerRole::Relay { position: EntryHop::Entry, relay_mode: RelayMode::OnionPeel },
                0,
                2,
                vec!["entry-node-3".to_string(), "exit-node-3".to_string()],
            )
            .await;
            let (entry_node_side, entry_perimeter_side) = bind_relay_pair().await;
            let entry_cancel = CancellationToken::new();
            let entry_server =
                tokio::spawn(run_server(Arc::clone(&entry_node_side), entry_registry, entry_cancel.clone()));

            let (fake_perimeter, routes) = spawn_fake_perimeter(Arc::clone(&entry_perimeter_side));
            let client_peer = loopback(58003);
            let socket = fake_client_socket(Arc::clone(&entry_perimeter_side), &routes, FACE_PORT, client_peer);
            let mut hello = build_face_hello_bytes();
            hello[92] |= FS_CHAIN_HELLO_FLAG;
            socket.send(&hello).await.expect("send classifier hello");

            // Names a chain_id nothing on this registry ever registered.
            let init = FsInitFrame {
                mesh_id: b"TESTMESH".to_vec(),
                chain_id: b"auto-nobody-here".to_vec(),
                chain_length: 2,
                chain_position: 0,
                client_suites: vec![AeadSuite::ChaCha20Poly1305],
                client_eph_pub: [0x55u8; 32],
                expected_peer_table_generation: 0,
                credential_scheme: 0x00,
                credential: Vec::new(),
                selector_token: Vec::new(),
            };
            socket.send(&init.encode().expect("encode FsInitFrame")).await.expect("send FsInitFrame");

            let mut buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
            let reply = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await;
            assert!(
                reply.is_err(),
                "a chain_id this node never registered must produce no reply at all -- a selector \
                 miss and an authentication failure are one silence: {reply:?}"
            );

            entry_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), entry_server).await;
            fake_perimeter.abort();
        }
    }
}
