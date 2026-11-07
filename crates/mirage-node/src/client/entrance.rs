//! The client entrance: accepts on `LocalChannel::EdgeChainSplice` (the
//! perimeter splices every `FacePurpose::EdgeEntrance` face here), runs the
//! V9 server handshake with `mirage-subscriber-gate`'s subscriber auth, then
//! speaks the edge-session wire
//! (`mirage_control_plane::edge_session`: `EdgeHello` / `EdgeWelcome` /
//! `StreamOpen`) the customer's own `mirage-subscriber-client` speaks byte
//! for byte — see `mirage2app/crates/subscriber-client/src/session.rs`,
//! which this module must interoperate with exactly.
//!
//! # Sequence per accepted connection
//!
//! 1. When the first 6 bytes are `MIRPRE`, consume an optional
//!    `PerimeterPreamble` first (not one byte past the body); otherwise
//!    replay those bytes. Then run `handshake_server_stream_with_auth`
//!    directly against this box's own real `fleet_mesh_id` (no ClientHello
//!    peek needed any more — see
//!    `mirage_subscriber_gate::entrance_auth`'s own doc, "Admission moved
//!    into the handshake predicate itself": the per-key `personal_mesh_id`
//!    concept is dropped for edges, so every subscriber's handshake verifies
//!    against the SAME real mesh id a mesh-credential dial would) with
//!    `make_entrance_auth(|_| false, ...)` — the mesh-credential gate always
//!    refuses: an edge's entrance is a subscriber entrance ONLY, never a
//!    mesh-credential relay hop ("no client ever reaches an ordinary node
//!    any more" extends to the edge's own entrance). The subscriber branch
//!    of that predicate is where admission (presence, expiry, scope) is
//!    actually decided, and where the admitted entry's own `not_after_ms` is
//!    captured for step 4.
//! 2. Read [`EdgeHello`], decide [`EdgeOutcome`] against
//!    [`crate::client::exit_port::ExitCountryOracle::servable_exit_countries`],
//!    send [`EdgeWelcome`]. A refused hello is a version-1 welcome with no
//!    port trailer and closes the tunnel; nothing past this point runs for
//!    it. Version 1 of an accepted hello is today's path (welcome version 1,
//!    no port, always mux, no face-load change). Version 2 and version 3
//!    offer TCP ports; [`assign_face`] picks the session port. A redirect
//!    welcome names that port and closes without demand or mux. A stay
//!    welcome names the arrival port and continues. A version-3 welcome
//!    also says this exit carries datagrams.
//!    The packet plane (version 4) is refused here by name: this entrance
//!    speaks the mux wire only, so the peer falls back to version 3. The
//!    rules themselves live in `mirage_control_plane::peer`, shared with the
//!    commercial box and the client.
//! 3. On a stay: record demand for the accepted [`ExitChoice`]
//!    (`HeldChainStore::record_demand`) and upgrade the SAME tunnel to a mux
//!    server session (`mirage_mux::tokio_compat::SessionHandle::server`) —
//!    no extra magic byte, the client upgrades unconditionally on
//!    `Accepted` too. A version-2 or version-3 stay counts against the arrival face's load.
//! 4. Register this connection's admitted `not_after_ms` in
//!    [`crate::client::live_sessions::LiveSessionRegistry`] and race the mux accept
//!    loop against [`crate::client::live_sessions::wait_for_deadline`] — the moment
//!    the deadline passes (natural expiry, OR an early revocation moved it
//!    to now — see that module's own doc), the session closes (mux, every
//!    open stream including UDP flows) rather than waiting for the next
//!    handshake. A reload of the box's subscriber set rechecks every LIVE
//!    session the same way (`LiveSessionRegistry::recheck_all`, driven from
//!    `crate::run`'s own hot-reload wiring).
//! 5. Every accepted mux stream reads its own [`StreamOpen`] header.
//!    `Tcp` dials `stream_opener.open_stream` for this subscriber's exit choice
//!    and pumps both directions, charging the subscriber's bandwidth cap and
//!    byte counters. `Udp` becomes one flow (`crate::client::udp_flow`): admitted
//!    against `crate::client::udp_flow::UdpFlowLimiter`'s per-subscriber/
//!    process-wide caps, dialled through `crate::client::exit_port::DatagramFlowOpener`,
//!    then pumped `[2B BE len][payload]` frames off the mux stream to
//!    datagrams into the mesh and back, same bandwidth cap and byte
//!    counters as the TCP path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use arc_swap::ArcSwapOption;
use mirage_control_plane::{
    CountryCode, EdgeHello, EdgeOutcome, EdgeSessionError as WireError, EdgeWelcome,
    ExitPreference, StreamKind, StreamOpen,
};
use mirage_core::config::{AuthMode, SubscriberEntranceConfig};
use mirage_core::crypto::credential::subscriber_set::{EdgeScopeView, SubscriberSetEntry};
use mirage_core::crypto::KeyPair;
use mirage_core::local_endpoint::LocalChannel;
use mirage_core::perimeter_preamble::{PerimeterPreamble, PREAMBLE_HEADER_LEN, PREAMBLE_MAGIC};
use mirage_mux::tokio_compat::{SessionHandle, TokioIoCompat, TokioMuxStream};
use mirage_protocol::driver::{convert_auth, handshake_server_stream_with_auth};
use mirage_protocol::traits::Tunnel;
use mirage_subscriber_gate::bandwidth_cap::SubscriberBandwidthRegistry;
use mirage_subscriber_gate::entrance_auth::make_entrance_auth;
use mirage_subscriber_gate::entrance_dispatch::resolve_subscriber_cap;
use mirage_subscriber_gate::subscriber_keys::{SubscriberKey, SubscriberKeyStore};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, info, warn};

use crate::client::chain_store::{ExitChoice, HeldChainStore};
use crate::client::exit_port::{DatagramFlowOpener, ExitCountryOracle, StreamOpener};
use crate::client::live_sessions::{wait_for_deadline, LiveSessionRegistry};
use crate::client::pump::{pump_stream_to_stream_capped, ByteCounterRegistry, SubscriberKeyId};
use crate::client::udp_flow::UdpFlowLimiter;

/// The wire this entrance speaks: the mux wire of versions 1 to 3.
///
/// The fleet box cannot serve the packet plane yet, so a peer that asks for
/// the plane here is refused by name and falls back to version 3.
///
/// The version numbers live in `mirage_control_plane::peer` -- with every
/// other wire version -- so that this entrance, the commercial box and the
/// client cannot drift apart.
const EDGE_PROFILE: mirage_control_plane::peer::PeerProfile =
    mirage_control_plane::peer::PeerProfile::MUX_WITH_DATAGRAMS;

/// Read/recv buffer for accumulating a not-yet-complete fixed-shape message
/// (`EdgeHello`, `StreamOpen`'s header) off a raw tunnel or mux stream.
const ACCUMULATE_CHUNK: usize = 512;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Error)]
pub enum EntranceError {
    #[error("bind EdgeChainSplice: {0}")]
    Bind(std::io::Error),
}

/// Everything one accepted connection's handling needs — cloned (cheap,
/// every field is an `Arc`) into each spawned connection task.
#[derive(Clone)]
pub struct EntranceDeps {
    /// The TCP onion-chain store — demand is recorded on it for every
    /// accepted session.
    pub chain_store: Arc<HeldChainStore>,
    /// This box's own UDP-flow chain store — a UDP-native FS chain is a
    /// structurally different held object from a TCP onion chain, so it
    /// lives in a store of its own. `record_demand` is called on it
    /// alongside `chain_store` (see `handle_connection`): demand for an
    /// exit choice is shared across transports.
    pub chain_store_udp: Arc<HeldChainStore>,
    /// Opens a TCP stream into the mesh — the fleet's `MeshLeg` behind the
    /// [`StreamOpener`] port.
    pub stream_opener: Arc<dyn StreamOpener>,
    /// Opens a datagram flow into the mesh — the fleet's `DgramMeshLeg`
    /// behind the [`DatagramFlowOpener`] port.
    pub datagram_opener: Arc<dyn DatagramFlowOpener>,
    /// The exit countries this box can serve right now — the fleet's
    /// `MonitorSessionSet` behind the [`ExitCountryOracle`] port.
    pub exit_countries: Arc<dyn ExitCountryOracle>,
    pub subscriber_keys: Arc<SubscriberKeyStore>,
    pub subscriber_bandwidth: Arc<SubscriberBandwidthRegistry>,
    pub subscriber_cfg: Arc<SubscriberEntranceConfig>,
    pub byte_counters: Arc<ByteCounterRegistry>,
    /// Per-subscriber and process-wide caps on concurrently open UDP flows
    /// — see `crate::client::udp_flow`'s own module doc.
    pub udp_flow_limiter: Arc<UdpFlowLimiter>,
    pub wire_keypair: Arc<KeyPair>,
    /// This box's own fleet `mesh_id` bytes — every V9 handshake on this
    /// entrance verifies against this SAME value now, subscriber or not
    /// (`mirage_subscriber_gate::entrance_auth`'s own doc: the per-key
    /// `personal_mesh_id` concept is dropped for edges).
    pub fleet_mesh_id: Arc<Vec<u8>>,
    /// This box's own admission scope — resolved once at boot
    /// (`crate::client::edge_scope::resolve`, from the capsule's `edge_scope`) and handed to every accepted
    /// connection's `SubscriberKeyStore::admit` check.
    pub own_scope: EdgeScopeView,
    /// Currently-admitted subscriber sessions' own expiry deadlines — see
    /// `crate::client::live_sessions`'s own module doc.
    pub live_sessions: Arc<LiveSessionRegistry>,
    /// Sessions currently muxed on each arrival face. Version-2 stays
    /// increment the port they reached and decrement when the mux session
    /// returns. The lock is not held across `.await`.
    pub face_loads: Arc<Mutex<HashMap<u16, u32>>>,
    /// Monotonic input mixed into [`assign_face`]'s draw. Not a `rand` source.
    pub face_draw: Arc<AtomicU64>,
}

/// Accept loop — never returns except on a bind failure. Every accepted
/// connection is handled on its own spawned task; one connection's error
/// never takes down the loop or any other connection.
pub async fn run(deps: EntranceDeps) -> Result<(), EntranceError> {
    let listener = LocalChannel::EdgeChainSplice.bind().await.map_err(EntranceError::Bind)?;
    info!("edge entrance: listening on LocalChannel::EdgeChainSplice");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let deps = deps.clone();
                tokio::spawn(async move {
                    debug!(peer = ?peer, "edge entrance: accepted a splice from the perimeter");
                    if let Err(e) = handle_connection(stream, deps).await {
                        debug!(error = %e, "edge entrance: connection ended");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "edge entrance: accept failed on EdgeChainSplice");
            }
        }
    }
}

/// Handle ONE accepted connection over a byte stream this crate did not bind.
///
/// [`run`] is the box's own front door: it binds the perimeter's splice and
/// takes the customer's bytes off it. A box that holds a UDP endpoint of its
/// OWN — a QUIC mask on UDP 443, say — has no perimeter splice under it: the
/// camouflage IS the outer layer, and what comes out of it is a plain byte
/// stream. This is the door for that stream, and it is the SAME admission
/// path: the V9 handshake, the subscriber gate, the mux session.
///
/// `peer` is the address the camouflage layer saw, and `arrival_face` is the
/// port the bytes came in on — the two facts the perimeter's preamble would
/// otherwise have carried. There is no preamble on this path: the stream
/// opens with the V9 hello itself.
pub async fn handle_stream<S>(
    stream: S,
    peer: SocketAddr,
    arrival_face: u16,
    deps: EntranceDeps,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    handle_connection_from(stream, Some((peer, arrival_face)), deps).await
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mirage: {0}")]
    Mirage(#[from] mirage_core::error::MirageError),
    #[error("handshake refused (auth predicate rejected the dial)")]
    HandshakeRefused,
    #[error("accepted a dial that never classified as a subscriber (mesh gate always refuses here)")]
    NotASubscriber,
    #[error(
        "accepted a subscriber dial but its admitted entry was never captured (invariant \
         violation -- entrance_auth::make_entrance_auth sets both carriers in the same branch)"
    )]
    MissingAdmittedEntry,
    #[error("closed before EdgeHello arrived: {0}")]
    ClosedBeforeEdgeHello(WireError),
    #[error("EdgeWelcome encode: {0}")]
    Welcome(WireError),
}

/// Bytes already read off a stream that did not open with [`PREAMBLE_MAGIC`].
///
/// Tests and a root dial speak V9 with no frame, so those 6 bytes belong to
/// the hello and must be replayed. Only the magic is held — nothing past it
/// was read.
struct Replay<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

/// One stream type for both preamble branches. The handshake takes `S` by value.
enum Ingress<S> {
    Plain(S),
    Prefixed(Replay<S>),
}

impl<S: Unpin> Unpin for Replay<S> {}
impl<S: Unpin> Unpin for Ingress<S> {}

impl<S> Ingress<S> {
    fn project_inner(self: Pin<&mut Self>) -> Pin<&mut S>
    where
        S: Unpin,
    {
        match self.get_mut() {
            Ingress::Plain(inner) => Pin::new(inner),
            Ingress::Prefixed(replay) => Pin::new(&mut replay.inner),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Ingress<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Ingress::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
            Ingress::Prefixed(replay) => {
                let held = replay.prefix.get_ref().len() as u64;
                let pos = replay.prefix.position();
                if pos < held {
                    let start = pos as usize;
                    let take = buf.remaining().min(held as usize - start);
                    buf.put_slice(&replay.prefix.get_ref()[start..start + take]);
                    replay.prefix.set_position((start + take) as u64);
                    return Poll::Ready(Ok(()));
                }
                Pin::new(&mut replay.inner).poll_read(cx, buf)
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Ingress<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.project_inner().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project_inner().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project_inner().poll_shutdown(cx)
    }
}

fn invalid_preamble(err: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

/// Peel a [`PerimeterPreamble`] only when the connection opens with `MIRPRE`.
///
/// The perimeter writes that frame and then the client's own bytes. Tests and
/// a root dial do not, so a non-magic prefix is pushed back, the peer stays
/// `127.0.0.1:0`, and the arrival face port is `0`. A matching frame is
/// consumed exactly — the body length, and not one byte more, because the
/// next bytes are the V9 hello — and its `face_port` is the arrival face.
///
/// A caller that already knows the peer and the arrival face passes them in
/// `known`: the perimeter's own path learns both from the preamble, while a
/// box that holds a UDP endpoint of its own has no preamble to learn them
/// from.
async fn read_optional_preamble_with<S>(
    mut stream: S,
    known: Option<(SocketAddr, u16)>,
) -> Result<(Ingress<S>, SocketAddr, u16), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut magic = [0u8; PREAMBLE_MAGIC.len()];
    stream.read_exact(&mut magic).await?;
    if magic != PREAMBLE_MAGIC {
        let (peer, arrival) = known.unwrap_or((([127, 0, 0, 1], 0).into(), 0));
        return Ok((
            Ingress::Prefixed(Replay { prefix: std::io::Cursor::new(magic.to_vec()), inner: stream }),
            peer,
            arrival,
        ));
    }

    let mut header = [0u8; PREAMBLE_HEADER_LEN];
    header[..PREAMBLE_MAGIC.len()].copy_from_slice(&magic);
    stream.read_exact(&mut header[PREAMBLE_MAGIC.len()..]).await?;
    let body_len = PerimeterPreamble::parse_header(&header).map_err(invalid_preamble)?;
    let mut body = vec![0u8; body_len as usize];
    stream.read_exact(&mut body).await?;
    let preamble = PerimeterPreamble::decode_body(&body).map_err(invalid_preamble)?;
    let peer_addr = preamble.peer.parse().unwrap_or_else(|_| ([127, 0, 0, 1], 0).into());
    Ok((Ingress::Plain(stream), peer_addr, preamble.face_port))
}

/// Generic over the accepted stream type so it is directly testable over a
/// `tokio::io::duplex` pipe with a real V9 client handshake driving the
/// other end — see this module's own tests. Production callers always pass
/// a `mirage_core::local_endpoint::LocalStream` (the perimeter's own splice).
async fn handle_connection<S>(stream: S, deps: EntranceDeps) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    handle_connection_from(stream, None, deps).await
}

/// The same, for a caller that already knows the peer and the arrival face.
///
/// See [`read_optional_preamble_with`].
async fn handle_connection_from<S>(
    stream: S,
    known: Option<(SocketAddr, u16)>,
    deps: EntranceDeps,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let subscriber_hit = Arc::new(AtomicBool::new(false));
    let subscriber_key_out: Arc<ArcSwapOption<SubscriberKey>> = Arc::new(ArcSwapOption::from(None));
    let subscriber_entry_out: Arc<ArcSwapOption<SubscriberSetEntry>> = Arc::new(ArcSwapOption::from(None));
    let auth = make_entrance_auth(
        // An edge entrance is subscriber-only -- never a mesh-credential
        // relay hop. See this module's own doc.
        |_ctx| false,
        Arc::clone(&deps.subscriber_keys),
        deps.own_scope.clone(),
        Arc::clone(&subscriber_hit),
        Arc::clone(&subscriber_key_out),
        Arc::clone(&subscriber_entry_out),
    );

    let proto_auth = convert_auth(&AuthMode::Blake3);
    // A unix-socket peer has no TCP address of its own. When the first 6
    // bytes are MIRPRE, the perimeter's PerimeterPreamble names the real
    // client; tests and a root dial have no frame, so those bytes are
    // replayed and the peer stays 127.0.0.1:0.
    let (stream, peer_addr, arrival) = read_optional_preamble_with(stream, known).await?;

    // 1. V9 handshake -- always against this box's own real fleet mesh id.
    // See this module's own doc: the personal-mesh-id peek is retired.
    let tunnel = handshake_server_stream_with_auth(
        stream,
        &deps.wire_keypair,
        &proto_auth,
        peer_addr,
        &deps.fleet_mesh_id,
        auth,
        false,
    )
    .await?;
    let Some(mut tunnel) = tunnel else {
        return Err(ConnectionError::HandshakeRefused);
    };

    let Some(subscriber_key) = subscriber_key_out.load_full() else {
        let _ = tunnel.close().await;
        return Err(ConnectionError::NotASubscriber);
    };
    let subscriber_key = *subscriber_key;
    let Some(admitted_entry) = subscriber_entry_out.load_full() else {
        let _ = tunnel.close().await;
        return Err(ConnectionError::MissingAdmittedEntry);
    };

    // 2. EdgeHello / EdgeWelcome.
    let hello = match read_edge_hello(tunnel.as_mut()).await {
        Ok(hello) => hello,
        Err(e) => {
            let _ = tunnel.close().await;
            return Err(e);
        }
    };

    let countries = deps.exit_countries.servable_exit_countries().await;
    let country_codes: Vec<CountryCode> = countries.iter().filter_map(|c| CountryCode::new(c).ok()).collect();
    let catalog = mirage_control_plane::peer::ExitCatalog::Countries(&country_codes);

    let outcome = EDGE_PROFILE.decide_outcome(&hello, &catalog);
    let EdgeOutcome::Accepted { exit: accepted_exit } = outcome else {
        let welcome = EDGE_PROFILE
            .welcome_for(&hello, &outcome, &catalog, None, None)
            .map_err(ConnectionError::Welcome)?;
        send_welcome(tunnel.as_mut(), &welcome).await?;
        if let EdgeOutcome::Refused(reason) = outcome {
            info!(?reason, "edge entrance: refused EdgeHello");
        }
        let _ = tunnel.close().await;
        return Ok(());
    };

    // Version 1: today's path. No port, no load change, always mux on accept.
    if hello.version == mirage_control_plane::peer::MUX_VERSION_V1 {
        let welcome = EDGE_PROFILE
            .welcome_for(&hello, &outcome, &catalog, None, None)
            .map_err(ConnectionError::Welcome)?;
        send_welcome(tunnel.as_mut(), &welcome).await?;
        return serve_accepted_session(
            tunnel,
            deps,
            exit_choice_from_preference(accepted_exit),
            subscriber_key,
            admitted_entry.not_after_ms,
            None,
        )
        .await;
    }

    // Version 2 and version 3 (decide_outcome already refused anything else).
    // Same face assignment. Version 3 says this exit carries datagrams; a
    // later UDP dial with no chain still shuts that stream.
    let commit = hello.flags & EdgeHello::FLAG_COMMIT != 0;
    let loads = load_snapshot(&deps.face_loads);
    let picked = assign_face(arrival, &hello.offered_ports, commit, &loads, next_face_draw(&deps.face_draw));
    let redirect = must_redirect(arrival, picked, commit);
    let advertised = if redirect { picked } else { arrival };
    let welcome = EDGE_PROFILE
        .welcome_for(&hello, &outcome, &catalog, Some(advertised), None)
        .map_err(ConnectionError::Welcome)?;
    send_welcome(tunnel.as_mut(), &welcome).await?;
    if redirect {
        info!(arrival, assigned = advertised, "edge entrance: redirecting session to the assigned face");
        let _ = tunnel.close().await;
        return Ok(());
    }
    info!(arrival, "edge entrance: session stays on the arrival face");
    serve_accepted_session(
        tunnel,
        deps,
        exit_choice_from_preference(accepted_exit),
        subscriber_key,
        admitted_entry.not_after_ms,
        Some(arrival),
    )
    .await
}

async fn send_welcome(tunnel: &mut dyn Tunnel, welcome: &EdgeWelcome) -> Result<(), ConnectionError> {
    let encoded = welcome.encode().map_err(ConnectionError::Welcome)?;
    tunnel.send(&encoded).await?;
    Ok(())
}

/// Record demand and mux an accepted session. `load_port` is `Some` only for
/// a version-2 or version-3 stay: that arrival port's load rises for the mux
/// session and falls when [`run_mux_session`] returns.
async fn serve_accepted_session(
    tunnel: Box<dyn Tunnel>,
    deps: EntranceDeps,
    exit: ExitChoice,
    subscriber_key: SubscriberKey,
    not_after_ms: u64,
    load_port: Option<u16>,
) -> Result<(), ConnectionError> {
    deps.chain_store.record_demand(exit.clone(), now_ms()).await;
    // Demand for an exit choice is shared across transports -- a subscriber
    // who picked "NL" wants both his TCP and his UDP traffic to exit
    // through NL -- so the UDP-chain store records the SAME demand.
    deps.chain_store_udp.record_demand(exit.clone(), now_ms()).await;

    // Mux upgrade -- unconditional on a stay, matching the client's own
    // "no magic byte" comment (`subscriber-client::session::EdgeSession::connect`).
    let (io, _pump) = crate::client::tunnel_io::tunnel_into_io(tunnel);
    let compat = TokioIoCompat(io);
    let session = SessionHandle::server(compat);

    let device_pubkey_hex = hex::encode(subscriber_key);
    let (session_handle, deadline_rx) = deps.live_sessions.register(device_pubkey_hex, not_after_ms).await;
    if let Some(port) = load_port {
        adjust_face_load(&deps.face_loads, port, true);
    }
    run_mux_session(session, deadline_rx, deps.clone(), exit, subscriber_key).await;
    if let Some(port) = load_port {
        adjust_face_load(&deps.face_loads, port, false);
    }
    deps.live_sessions.deregister(&session_handle).await;
    Ok(())
}

/// Drives one accepted mux session's stream-accept loop, racing it against
/// [`wait_for_deadline`] so the session closes (mux + every open stream)
/// the moment its admitted entry's own deadline passes or is revoked,
/// rather than only at the next handshake.
async fn run_mux_session(
    session: SessionHandle,
    deadline_rx: tokio::sync::watch::Receiver<u64>,
    deps: EntranceDeps,
    exit: ExitChoice,
    subscriber_key: SubscriberKey,
) {
    tokio::pin! {
        let deadline = wait_for_deadline(deadline_rx);
    }
    // Demand for an exit choice is otherwise recorded ONCE, when the session
    // is accepted (see `serve_accepted_session`). A long-lived mux session
    // streams for hours and never re-accepts, so the pool's idle clock kept
    // running and the pool was dropped 30 minutes in -- taking healthy
    // chains with it (the blackout of 2026-10-21:
    // `docs/mirage/audits/edge-idle-demand-drop-blackout-2026-10-21.md`).
    // Refreshing on a timer, WHILE this session is alive, makes the idle
    // clock mean "no session is asking" instead of "no session was accepted
    // recently".
    let mut demand_refresh = tokio::time::interval(std::time::Duration::from_millis(
        crate::client::chain_store::DEMAND_REFRESH_INTERVAL_MS,
    ));
    demand_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                info!(
                    device_pubkey_prefix = %hex::encode(&subscriber_key[..4]),
                    "edge entrance: session's admitted entry expired or was revoked -- closing"
                );
                let _ = session.close().await;
                return;
            }
            _ = demand_refresh.tick() => {
                let now = now_ms();
                deps.chain_store.record_demand(exit.clone(), now).await;
                // Demand is shared across transports (see
                // `serve_accepted_session`), so the UDP-chain store gets the
                // same clock -- otherwise UDP flows die with TCP.
                deps.chain_store_udp.record_demand(exit.clone(), now).await;
            }
            accepted = session.accept_stream() => match accepted {
                Ok(mux_stream) => {
                    let deps = deps.clone();
                    let exit = exit.clone();
                    tokio::spawn(async move {
                        handle_mux_stream(mux_stream, deps, exit, subscriber_key).await;
                    });
                }
                Err(e) => {
                    debug!(error = %e, "edge entrance: mux session ended");
                    return;
                }
            },
        }
    }
}

/// Weight of one offered face. A missing load is 0. A hot face weighs less
/// and is never zero, so it can still be drawn.
fn face_weight(load: u32) -> u32 {
    1024 / (1 + load.min(1023))
}

/// Pick the session face.
///
/// `commit` or an empty `offered` list keeps `arrival`. Otherwise each
/// offered port is weighted by [`face_weight`] and `draw % sum(weights)`
/// selects one, walking the offered list in order. Equal loads are uniform.
/// The caller does not offer UDP ports; this function does not filter them.
fn assign_face(arrival: u16, offered: &[u16], commit: bool, loads: &HashMap<u16, u32>, draw: u64) -> u16 {
    if commit || offered.is_empty() {
        return arrival;
    }
    let weights: Vec<u32> = offered
        .iter()
        .map(|port| face_weight(loads.get(port).copied().unwrap_or(0)))
        .collect();
    let sum: u64 = weights.iter().map(|weight| u64::from(*weight)).sum();
    if sum == 0 {
        return arrival;
    }
    let mut cursor = draw % sum;
    for (port, weight) in offered.iter().zip(weights.iter()) {
        let weight = u64::from(*weight);
        if cursor < weight {
            return *port;
        }
        cursor -= weight;
    }
    arrival
}

/// A version-2 accept that is not the session: the edge already picked a
/// different face, this dial is not the commit, and a real preamble named
/// the arrival port. `arrival == 0` (no preamble) stays.
fn must_redirect(arrival: u16, assigned: u16, commit: bool) -> bool {
    !commit && assigned != arrival && arrival != 0
}

fn load_snapshot(loads: &Mutex<HashMap<u16, u32>>) -> HashMap<u16, u32> {
    loads.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

fn next_face_draw(counter: &AtomicU64) -> u64 {
    let n = counter.fetch_add(1, Ordering::Relaxed);
    n.wrapping_mul(0x9E3779B97F4A7C15)
}

fn adjust_face_load(loads: &Mutex<HashMap<u16, u32>>, port: u16, up: bool) {
    let mut map = loads.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let slot = map.entry(port).or_insert(0);
    if up {
        *slot = slot.saturating_add(1);
    } else {
        *slot = slot.saturating_sub(1);
    }
}

fn exit_choice_from_preference(exit: ExitPreference) -> ExitChoice {
    match exit {
        ExitPreference::Auto => ExitChoice::Auto,
        ExitPreference::Country(cc) => ExitChoice::Country(cc.as_str().to_string()),
    }
}

/// Accumulate `tunnel.recv()` chunks until a full [`EdgeHello`] decodes.
async fn read_edge_hello(tunnel: &mut dyn Tunnel) -> Result<EdgeHello, ConnectionError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; ACCUMULATE_CHUNK];
    loop {
        match EdgeHello::decode(&buf) {
            Ok((hello, _consumed)) => return Ok(hello),
            Err(WireError::Truncated { .. }) => {}
            Err(other) => return Err(ConnectionError::ClosedBeforeEdgeHello(other)),
        }
        let n = tunnel.recv(&mut chunk).await?;
        if n == 0 {
            return Err(ConnectionError::ClosedBeforeEdgeHello(WireError::Truncated {
                context: "EdgeHello",
                need: EdgeHello::ENCODED_LEN,
                have: buf.len(),
            }));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Accumulate reads off a mux stream until a full [`StreamOpen`] header
/// decodes. Generic over the stream type for the same reason
/// [`handle_connection`] is — directly testable over a plain duplex pipe.
///
/// Returns the header AND the bytes that arrived with it.
///
/// Those extra bytes are the CLIENT'S OWN PAYLOAD: a client that writes the
/// header and the first bytes of its flow back to back puts both in one
/// segment, and the mux hands them over in one read. Dropping them would
/// lose the first bytes of every flow that starts immediately — a request
/// header, for most protocols — and the flow would hang or answer wrongly.
/// The caller replays them into the target socket before pumping.
async fn read_stream_open<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(StreamOpen, Vec<u8>), WireError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; ACCUMULATE_CHUNK];
    loop {
        match StreamOpen::decode(&buf) {
            Ok((open, consumed)) => {
                return Ok((open, buf[consumed..].to_vec()));
            }
            Err(WireError::Truncated { .. }) => {}
            Err(other) => return Err(other),
        }
        let n = stream.read(&mut chunk).await.map_err(|_| WireError::Truncated {
            context: "StreamOpen",
            need: 3,
            have: buf.len(),
        })?;
        if n == 0 {
            return Err(WireError::Truncated { context: "StreamOpen", need: 3, have: buf.len() });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A stream that yields `prefix` first and then the bytes of `inner`.
///
/// The bytes that arrived WITH the `StreamOpen` header are the client's own
/// payload — a client that writes the header and the first bytes of its flow
/// back to back puts both in one segment, and the mux hands them over in one
/// read. Carrying them as a prefix keeps the flow whole, and keeps the fix
/// out of the pump: the pump sees one ordinary stream.
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = std::cmp::min(buf.remaining(), this.prefix.len() - this.pos);
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn handle_mux_stream(mux_stream: mirage_mux::MuxStream, deps: EntranceDeps, exit: ExitChoice, subscriber_key: SubscriberKey) {
    let mut stream = Prefixed::new(Vec::new(), TokioMuxStream(mux_stream));
    let (open, leading) = match read_stream_open(&mut stream).await {
        Ok(parsed) => parsed,
        Err(e) => {
            debug!(error = %e, "edge entrance: mux stream closed before a StreamOpen header arrived");
            return;
        }
    };
    // The client's own payload, which arrived with the header, goes back in
    // front of the stream — the pump then carries it to the target like any
    // other byte.
    let mut stream = Prefixed::new(leading, stream);

    match open.kind {
        StreamKind::Udp => {
            let _flow_guard = match deps.udp_flow_limiter.try_acquire(subscriber_key) {
                Ok(guard) => guard,
                Err(refusal) => {
                    warn!(target = %open.target, error = %refusal, "edge entrance: UDP flow refused");
                    let _ = stream.shutdown().await;
                    return;
                }
            };
            match deps.datagram_opener.open_datagram_flow(&exit, open.target.as_str()).await {
                Ok((sender, receiver)) => {
                    let cap = resolve_subscriber_cap(Some(subscriber_key), &deps.subscriber_cfg, &deps.subscriber_bandwidth);
                    let counters = deps.byte_counters.counters_for(&SubscriberKeyId(hex::encode(subscriber_key))).await;
                    if let Err(e) =
                        crate::client::udp_flow::pump_mux_udp_datagrams(stream, sender, receiver, cap.as_ref(), Some(&counters)).await
                    {
                        debug!(error = %e, target = %open.target, "edge entrance: udp flow pump ended");
                    }
                }
                Err(e) => {
                    warn!(error = %e, target = %open.target, "edge entrance: dgram leg dial failed for this udp flow");
                    let _ = stream.shutdown().await;
                }
            }
        }
        StreamKind::Tcp => match deps.stream_opener.open_stream(&exit, open.target.as_str()).await {
            Ok(chain_stream) => {
                let cap = resolve_subscriber_cap(Some(subscriber_key), &deps.subscriber_cfg, &deps.subscriber_bandwidth);
                let counters = deps.byte_counters.counters_for(&SubscriberKeyId(hex::encode(subscriber_key))).await;
                if let Err(e) = pump_stream_to_stream_capped(stream, chain_stream, cap.as_ref(), Some(&counters)).await {
                    debug!(error = %e, target = %open.target, "edge entrance: mux stream pump ended");
                }
            }
            Err(e) => {
                warn!(error = %e, target = %open.target, "edge entrance: mesh leg dial failed for this stream");
                let _ = stream.shutdown().await;
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use ed25519_dalek::SigningKey;
    use mirage_control_plane::EdgeOutcome as WireOutcome;
    use mirage_control_plane::EdgeRefusal;
    use mirage_core::config::{AuthMode as CoreAuthMode, MirageEndpointConfig, SubscriberEntranceConfig, TransportKind};
    use mirage_protocol::driver::run_client_tcp_v9;
    use mirage_subscriber_gate::bandwidth_cap::SubscriberBandwidthRegistry;
    use rand::rngs::OsRng;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;
    use x25519_dalek::{PublicKey, StaticSecret};

    // ── decide_outcome / exit_choice_from_preference: pure ───────────────

    /// The wire versions this entrance speaks, under the names the tests
    /// have always used.
    use mirage_control_plane::peer::{
        MUX_VERSION_V1 as SUPPORTED_EDGE_SESSION_VERSION,
        MUX_VERSION_V2 as EDGE_SESSION_WIRE_VERSION_V2,
        MUX_VERSION_V3 as EDGE_SESSION_WIRE_VERSION_V3,
    };

    fn cc(code: &str) -> CountryCode {
        CountryCode::new(code).expect("valid country code")
    }

    fn hello(version: u8, exit: ExitPreference) -> EdgeHello {
        EdgeHello { version, exit, flags: 0, offered_ports: Vec::new() }
    }

    fn encode_hello(hello: &EdgeHello) -> Vec<u8> {
        hello.encode().expect("test hello encodes")
    }

    /// The outcome this entrance decides for a hello: the shared rules, with
    /// this box's country table.
    fn decide_outcome(hello: &EdgeHello, countries: &[CountryCode]) -> WireOutcome {
        EDGE_PROFILE.decide_outcome(hello, &mirage_control_plane::peer::ExitCatalog::Countries(countries))
    }

    #[test]
    fn decide_outcome_rejects_an_unsupported_version() {
        let hello = hello(9, ExitPreference::Auto);
        let outcome = decide_outcome(&hello, &[]);
        assert_eq!(
            outcome,
            WireOutcome::Refused(EdgeRefusal::UnsupportedVersion {
                requested: 9,
                supported: EDGE_SESSION_WIRE_VERSION_V3
            })
        );
    }

    #[test]
    fn decide_outcome_refuses_the_plane() {
        // The fleet box cannot serve the packet plane: a peer that asks for
        // it is refused by name and falls back to version 3.
        let hello = hello(mirage_control_plane::peer::PLANE_VERSION, ExitPreference::Auto);
        let outcome = decide_outcome(&hello, &[]);
        assert_eq!(
            outcome,
            WireOutcome::Refused(EdgeRefusal::UnsupportedVersion {
                requested: mirage_control_plane::peer::PLANE_VERSION,
                supported: EDGE_SESSION_WIRE_VERSION_V3
            })
        );
    }

    #[test]
    fn decide_outcome_accepts_auto_regardless_of_countries() {
        let hello = hello(SUPPORTED_EDGE_SESSION_VERSION, ExitPreference::Auto);
        let outcome = decide_outcome(&hello, &[]);
        assert_eq!(outcome, WireOutcome::Accepted { exit: ExitPreference::Auto });
    }

    #[test]
    fn decide_outcome_accepts_a_servable_country() {
        let hello =
            hello(SUPPORTED_EDGE_SESSION_VERSION, ExitPreference::Country(cc("NL")));
        let outcome = decide_outcome(&hello, &[cc("NL"), cc("US")]);
        assert_eq!(outcome, WireOutcome::Accepted { exit: ExitPreference::Country(cc("NL")) });
    }

    #[test]
    fn decide_outcome_refuses_an_unservable_country() {
        let hello =
            hello(SUPPORTED_EDGE_SESSION_VERSION, ExitPreference::Country(cc("ZZ")));
        let outcome = decide_outcome(&hello, &[cc("NL"), cc("US")]);
        assert_eq!(
            outcome,
            WireOutcome::Refused(EdgeRefusal::CountryUnavailable { requested: cc("ZZ") })
        );
    }

    #[test]
    fn decide_outcome_accepts_version_2() {
        let hello = EdgeHello {
            version: EDGE_SESSION_WIRE_VERSION_V2,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: vec![80, 443],
        };
        assert_eq!(
            decide_outcome(&hello, &[]),
            WireOutcome::Accepted { exit: ExitPreference::Auto }
        );
    }

    #[test]
    fn decide_outcome_accepts_version_3_auto() {
        let hello = hello(EDGE_SESSION_WIRE_VERSION_V3, ExitPreference::Auto);
        assert_eq!(
            decide_outcome(&hello, &[]),
            WireOutcome::Accepted { exit: ExitPreference::Auto }
        );
    }

    #[test]
    fn assign_face_equal_loads_hit_every_offered_port() {
        let offered = [80u16, 443, 8080];
        let loads = HashMap::new();
        let mut hits = [0u32; 3];
        for draw in 0..3072 {
            match assign_face(80, &offered, false, &loads, draw) {
                80 => hits[0] += 1,
                443 => hits[1] += 1,
                8080 => hits[2] += 1,
                other => panic!("picker returned {other}, which was not offered"),
            }
        }
        assert_eq!(hits, [1024, 1024, 1024]);
    }

    #[test]
    fn assign_face_hot_face_is_chosen_less_often_but_not_never() {
        let mut loads = HashMap::new();
        loads.insert(80, 100);
        loads.insert(443, 0);
        let mut hot = 0u32;
        let mut cold = 0u32;
        for draw in 0..400 {
            match assign_face(80, &[80, 443], false, &loads, draw) {
                80 => hot += 1,
                443 => cold += 1,
                other => panic!("picker returned {other}, which was not offered"),
            }
        }
        assert!(hot > 0, "a hot face must remain reachable");
        assert!(cold > hot, "load 100 must be chosen less often than load 0, hot={hot} cold={cold}");
    }

    #[test]
    fn assign_face_capped_load_is_still_chosen() {
        let mut loads = HashMap::new();
        loads.insert(80, 5000);
        loads.insert(443, 0);
        let mut hot = 0u32;
        for draw in 0..1025 {
            if assign_face(80, &[80, 443], false, &loads, draw) == 80 {
                hot += 1;
            }
        }
        assert_eq!(hot, 1);
    }

    #[test]
    fn assign_face_commit_returns_arrival_even_if_it_is_not_the_lightest() {
        let mut loads = HashMap::new();
        loads.insert(80, 1000);
        loads.insert(443, 0);
        assert_eq!(assign_face(80, &[443, 80], true, &loads, 0), 80);
        assert_eq!(assign_face(80, &[443], true, &loads, 0), 80);
    }

    #[test]
    fn assign_face_empty_offered_returns_arrival() {
        assert_eq!(assign_face(5060, &[], false, &HashMap::new(), 0), 5060);
    }

    #[test]
    fn assign_face_returns_whatever_ports_the_caller_offered() {
        let offered = [5060u16, 853];
        let loads = HashMap::new();
        let mut seen = [false; 2];
        for draw in 0..2048 {
            match assign_face(1, &offered, false, &loads, draw) {
                5060 => seen[0] = true,
                853 => seen[1] = true,
                other => panic!("picker returned {other}, which was not offered"),
            }
        }
        assert_eq!(seen, [true, true]);
    }

    #[test]
    fn assign_face_missing_load_is_zero() {
        let mut loads = HashMap::new();
        loads.insert(443, 0);
        let mut hits = [0u32; 2];
        for draw in 0..2048 {
            match assign_face(80, &[80, 443], false, &loads, draw) {
                80 => hits[0] += 1,
                443 => hits[1] += 1,
                other => panic!("picker returned {other}"),
            }
        }
        assert_eq!(hits, [1024, 1024]);
    }

    #[test]
    fn redirect_only_when_a_real_arrival_was_not_committed() {
        assert!(must_redirect(80, 443, false));
        assert!(!must_redirect(80, 443, true));
        assert!(!must_redirect(0, 443, false));
        assert!(!must_redirect(80, 80, false));
    }

    #[test]
    fn exit_choice_from_preference_maps_both_variants() {
        assert_eq!(exit_choice_from_preference(ExitPreference::Auto), ExitChoice::Auto);
        assert_eq!(
            exit_choice_from_preference(ExitPreference::Country(cc("DE"))),
            ExitChoice::Country("DE".to_string())
        );
    }

    // ── read_edge_hello: bounded accumulation over a mock Tunnel ─────────

    struct MockTunnel {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        info: mirage_protocol::traits::TransportInfo,
    }

    #[async_trait::async_trait]
    impl Tunnel for MockTunnel {
        async fn send(&mut self, _data: &[u8]) -> mirage_core::error::Result<()> {
            Ok(())
        }
        async fn recv(&mut self, buf: &mut [u8]) -> mirage_core::error::Result<usize> {
            match self.inbound.recv().await {
                Some(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }
        async fn close(&mut self) -> mirage_core::error::Result<()> {
            Ok(())
        }
        fn transport_info(&self) -> &mirage_protocol::traits::TransportInfo {
            &self.info
        }
    }

    #[tokio::test]
    async fn read_edge_hello_accumulates_across_several_recv_calls() {
        let hello = hello(1, ExitPreference::Country(cc("US")));
        let encoded = encode_hello(&hello);
        let mid = encoded.len() / 2;
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(encoded[..mid].to_vec()).expect("send first half");
        tx.send(encoded[mid..].to_vec()).expect("send second half");
        let mut tunnel = MockTunnel {
            inbound: rx,
            info: mirage_protocol::traits::TransportInfo::tcp_raw("127.0.0.1:1".parse().expect("addr")),
        };

        let got = read_edge_hello(&mut tunnel).await.expect("must decode once both halves arrive");
        assert_eq!(got, hello);
    }

    #[tokio::test]
    async fn read_edge_hello_keeps_a_version_2_tail_from_a_later_read() {
        let hello = EdgeHello {
            version: EDGE_SESSION_WIRE_VERSION_V2,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: vec![80, 443, 8080],
        };
        let encoded = encode_hello(&hello);
        assert!(encoded.len() > 4);
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(encoded[..4].to_vec()).expect("send prefix");
        tx.send(encoded[4..].to_vec()).expect("send tail");
        let mut tunnel = MockTunnel {
            inbound: rx,
            info: mirage_protocol::traits::TransportInfo::tcp_raw("127.0.0.1:1".parse().expect("addr")),
        };
        let got = read_edge_hello(&mut tunnel).await.expect("version 2 tail must not be dropped");
        assert_eq!(got, hello);
    }

    // ── read_stream_open: bounded accumulation over a plain duplex pipe ──

    #[tokio::test]
    async fn read_stream_open_accumulates_across_a_plain_stream() {
        let open = StreamOpen { kind: StreamKind::Tcp, target: mirage_control_plane::StreamTarget::new("1.2.3.4:443").expect("valid target") };
        let encoded = open.encode();
        let (mut app, mut server) = tokio::io::duplex(4096);
        let mid = encoded.len() / 2;
        app.write_all(&encoded[..mid]).await.expect("write first half");
        app.flush().await.expect("flush");
        let write_rest = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            app.write_all(&encoded[mid..]).await.expect("write second half");
        });

        let (got, leading) = read_stream_open(&mut server).await.expect("must decode once both halves arrive");
        assert_eq!(got.kind, StreamKind::Tcp);
        assert_eq!(got.target.as_str(), "1.2.3.4:443");
        assert!(
            leading.is_empty(),
            "a header that arrived on its own carries no payload behind it, got {leading:?}"
        );
        write_rest.await.expect("writer task must not panic");
    }

    /// The prefix comes first, then the inner stream's bytes — in that order,
    /// with nothing dropped between them.
    #[tokio::test]
    async fn prefixed_yields_its_prefix_before_the_inner_stream() {
        let (mut app, mut server) = tokio::io::duplex(64);
        app.write_all(b"inner").await.expect("write inner");
        app.flush().await.expect("flush");
        let mut prefixed = Prefixed::new(b"prefix".to_vec(), server);
        let mut buf = vec![0u8; 11];
        tokio::io::AsyncReadExt::read_exact(&mut prefixed, &mut buf)
            .await
            .expect("read prefix and inner");
        assert_eq!(&buf[..], b"prefixinner");
    }

    /// The bytes that arrive WITH the header are the client's own payload —
    /// they must come back out, not be swallowed.
    #[tokio::test]
    async fn read_stream_open_returns_the_bytes_that_arrived_with_the_header() {
        let open = StreamOpen { kind: StreamKind::Tcp, target: mirage_control_plane::StreamTarget::new("1.2.3.4:443").expect("valid target") };
        let mut encoded = open.encode();
        encoded.extend_from_slice(b"the client's first payload bytes");
        let (mut app, mut server) = tokio::io::duplex(4096);
        app.write_all(&encoded).await.expect("write header and payload");
        app.flush().await.expect("flush");

        let (got, leading) = read_stream_open(&mut server).await.expect("must decode");
        assert_eq!(got.kind, StreamKind::Tcp);
        assert_eq!(
            leading,
            b"the client's first payload bytes".to_vec(),
            "the payload that arrived with the header must not be dropped"
        );
    }

    // ── end-to-end over real loopback TCP: real V9 handshake + EdgeHello/EdgeWelcome ──

    /// A [`StreamOpener`] stub — these tests exercise the ENTRANCE, never
    /// the mesh: no chain is ever held, so every open fails the same way
    /// the fleet's own leg reports for an empty chain store.
    struct StubStreamOpener;

    #[async_trait::async_trait]
    impl StreamOpener for StubStreamOpener {
        async fn open_stream(
            &self,
            exit: &ExitChoice,
            _target: &str,
        ) -> Result<crate::client::exit_port::MeshStream, crate::client::exit_port::StreamOpenError> {
            Err(crate::client::exit_port::StreamOpenError::NoChainHeld(exit.clone()))
        }
    }

    /// A [`DatagramFlowOpener`] stub — see [`StubStreamOpener`].
    struct StubDatagramOpener;

    #[async_trait::async_trait]
    impl DatagramFlowOpener for StubDatagramOpener {
        async fn open_datagram_flow(
            &self,
            exit: &ExitChoice,
            _target: &str,
        ) -> Result<
            (
                crate::client::exit_port::DatagramSinkBox,
                crate::client::exit_port::DatagramSourceBox,
            ),
            crate::client::exit_port::DatagramFlowError,
        > {
            Err(crate::client::exit_port::DatagramFlowError::NoChainHeld(exit.clone()))
        }
    }

    /// An [`ExitCountryOracle`] stub — no monitor session is live in these
    /// tests, so no exit country is servable.
    struct StubExitCountries;

    #[async_trait::async_trait]
    impl ExitCountryOracle for StubExitCountries {
        async fn servable_exit_countries(&self) -> Vec<String> {
            Vec::new()
        }
    }

    /// Builds a `SubscriberKeyStore` with exactly one admitted, non-expired,
    /// `Public`-scope entry for `subscriber_pub`, signed by a freshly
    /// generated test issuer key -- the store's own `issuer_pub` is that
    /// same fresh key, so [`SubscriberKeyStore::install`] succeeds.
    fn store_admitting(subscriber_pub: [u8; 32]) -> Arc<SubscriberKeyStore> {
        let issuer = SigningKey::generate(&mut OsRng);
        let store = SubscriberKeyStore::empty(issuer.verifying_key());
        let entry = mirage_core::crypto::credential::subscriber_set::SubscriberSetEntry {
            device_pubkey_hex: hex::encode(subscriber_pub),
            scope: mirage_core::crypto::credential::subscriber_set::SubscriberScope::Public,
            not_after_ms: u64::MAX / 2,
            subscription_ref: "sub-test".to_string(),
        };
        store
            .install(mirage_core::crypto::credential::subscriber_set::sign(vec![entry], 0, &issuer))
            .expect("test set must install");
        store
    }

    fn empty_entrance_deps(
        wire_keypair: Arc<KeyPair>,
        subscriber_pub: [u8; 32],
        fleet_mesh_id: Vec<u8>,
    ) -> EntranceDeps {
        let subscriber_keys = store_admitting(subscriber_pub);

        EntranceDeps {
            chain_store: Arc::new(HeldChainStore::new()),
            chain_store_udp: Arc::new(HeldChainStore::new()),
            stream_opener: Arc::new(StubStreamOpener),
            datagram_opener: Arc::new(StubDatagramOpener),
            exit_countries: Arc::new(StubExitCountries),
            subscriber_keys,
            subscriber_bandwidth: SubscriberBandwidthRegistry::new(),
            subscriber_cfg: Arc::new(SubscriberEntranceConfig {
                legacy_socks_addr: None,
                aggregate_rate_bytes_per_sec: None,
                aggregate_burst_bytes: None,
                per_connection_rate_bytes_per_sec: None,
                monthly_volume_bytes: None,
                degraded_floor_bytes_per_sec: None,
            }),
            byte_counters: Arc::new(crate::client::pump::ByteCounterRegistry::new()),
            udp_flow_limiter: UdpFlowLimiter::new(
                crate::client::udp_flow::MAX_UDP_STREAMS_PER_SESSION,
                crate::client::udp_flow::MAX_LIVE_UDP_FLOWS_PER_PROCESS,
            ),
            wire_keypair,
            fleet_mesh_id: Arc::new(fleet_mesh_id),
            own_scope: mirage_core::crypto::credential::subscriber_set::EdgeScopeView::Public,
            live_sessions: crate::client::live_sessions::LiveSessionRegistry::new(),
            face_loads: Arc::new(Mutex::new(HashMap::new())),
            face_draw: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Drives a real client-side V9 handshake plus the edge-session wire
    /// over an actual loopback TCP connection, with `handle_connection`
    /// running server-side on the accepted socket — the same function
    /// production code calls, over a stream type it also actually accepts
    /// (`handle_connection` is generic over any `AsyncRead + AsyncWrite`).
    async fn dial_test_server(
        addr: SocketAddr,
        server_pub: [u8; 32],
        client_priv: [u8; 32],
        mesh_id: &[u8],
    ) -> Box<dyn Tunnel> {
        let config = MirageEndpointConfig {
            transport: TransportKind::Tcp,
            auth: CoreAuthMode::Blake3,
            camouflage: mirage_core::mirage::wire::TransportCamouflage::None,
            byte_cipher: None,
            byte_cipher_mode: None,
        };
        run_client_tcp_v9(&config, addr, &server_pub, &client_priv, "", mesh_id, None)
            .await
            .expect("client V9 handshake must succeed")
    }

    #[tokio::test]
    async fn end_to_end_accepts_a_subscriber_requesting_auto_exit() {
        let wire_keypair = Arc::new(KeyPair::generate());
        let server_pub = wire_keypair.public.to_bytes();
        let subscriber_secret = StaticSecret::random_from_rng(OsRng);
        let subscriber_priv = subscriber_secret.to_bytes();
        let subscriber_pub = PublicKey::from(&subscriber_secret).to_bytes();
        let fleet_mesh_id = b"v3-staging".to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let deps = empty_entrance_deps(Arc::clone(&wire_keypair), subscriber_pub, fleet_mesh_id.clone());
        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            handle_connection(stream, deps).await
        });

        let mut tunnel =
            dial_test_server(addr, server_pub, subscriber_priv, &fleet_mesh_id).await;
        let hello = hello(SUPPORTED_EDGE_SESSION_VERSION, ExitPreference::Auto);
        tunnel.send(&encode_hello(&hello)).await.expect("send EdgeHello");

        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 256];
        let welcome = loop {
            match EdgeWelcome::decode(&buf) {
                Ok((w, _)) => break w,
                Err(WireError::Truncated { .. }) => {}
                Err(e) => panic!("EdgeWelcome did not decode: {e}"),
            }
            let n = tunnel.recv(&mut chunk).await.expect("recv EdgeWelcome");
            assert!(n > 0, "tunnel closed before EdgeWelcome arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_eq!(welcome.outcome, WireOutcome::Accepted { exit: ExitPreference::Auto });

        let _ = tunnel.close().await;
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server task must not hang")
            .expect("server task must not panic");
        assert!(result.is_ok(), "handle_connection must end cleanly once the client closes: {result:?}");
    }

    /// The door a box's own UDP endpoint uses: a stream this crate did not
    /// bind, with the peer and the arrival face handed in by the caller
    /// instead of carried by the perimeter's preamble.
    ///
    /// The same client, the same handshake, the same gate — only the door is
    /// different. A QUIC mask on UDP 443 brings a stream out of the
    /// camouflage, and that stream must be admitted exactly like the
    /// perimeter's splice is.
    #[tokio::test]
    async fn handle_stream_admits_a_subscriber_without_a_preamble() {
        let wire_keypair = Arc::new(KeyPair::generate());
        let server_pub = wire_keypair.public.to_bytes();
        let subscriber_secret = StaticSecret::random_from_rng(OsRng);
        let subscriber_priv = subscriber_secret.to_bytes();
        let subscriber_pub = PublicKey::from(&subscriber_secret).to_bytes();
        let fleet_mesh_id = b"v3-staging".to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let deps = empty_entrance_deps(Arc::clone(&wire_keypair), subscriber_pub, fleet_mesh_id.clone());
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            // No preamble here: the caller knows the peer and the face the
            // bytes came in on, because it owns the endpoint they arrived on.
            handle_stream(stream, peer, 8443, deps).await
        });

        let mut tunnel =
            dial_test_server(addr, server_pub, subscriber_priv, &fleet_mesh_id).await;
        let hello = EdgeHello {
            version: EDGE_SESSION_WIRE_VERSION_V2,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: vec![8443],
        };
        tunnel.send(&encode_hello(&hello)).await.expect("send EdgeHello");

        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 256];
        let welcome = loop {
            match EdgeWelcome::decode(&buf) {
                Ok((w, _)) => break w,
                Err(WireError::Truncated { .. }) => {}
                Err(e) => panic!("EdgeWelcome did not decode: {e}"),
            }
            let n = tunnel.recv(&mut chunk).await.expect("recv EdgeWelcome");
            assert!(n > 0, "tunnel closed before EdgeWelcome arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_eq!(welcome.outcome, WireOutcome::Accepted { exit: ExitPreference::Auto });
        assert_eq!(
            welcome.assigned_face_port,
            Some(8443),
            "the arrival face the caller handed in must be the face the welcome names"
        );

        let _ = tunnel.close().await;
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server task must not hang")
            .expect("server task must not panic");
        assert!(result.is_ok(), "handle_stream must end cleanly once the client closes: {result:?}");
    }

    #[tokio::test]
    async fn preamble_then_v9_handshake_accepts_auto_exit() {
        let wire_keypair = Arc::new(KeyPair::generate());
        let server_pub = wire_keypair.public.to_bytes();
        let subscriber_secret = StaticSecret::random_from_rng(OsRng);
        let subscriber_priv = subscriber_secret.to_bytes();
        let subscriber_pub = PublicKey::from(&subscriber_secret).to_bytes();
        let fleet_mesh_id = b"v3-staging".to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().expect("addr");
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

        let deps = empty_entrance_deps(Arc::clone(&wire_keypair), subscriber_pub, fleet_mesh_id.clone());
        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            handle_connection(stream, deps).await
        });

        // Production order: the perimeter writes the preamble and flushes it
        // before any client byte. The next bytes are the V9 hello.
        tokio::spawn(async move {
            let (client, _peer) = proxy_listener.accept().await.expect("proxy accept");
            let mut upstream = tokio::net::TcpStream::connect(server_addr).await.expect("upstream");
            let preamble = PerimeterPreamble {
                peer: "203.0.113.50:40000".to_string(),
                face_port: 443,
                face_camouflage: "tls_real".to_string(),
                verdict: mirage_core::local_security_event::InwardDest::NodeChain,
                first_bytes: vec![0x09],
                observed_at_ms: 1,
            };
            let frame = preamble.encode().expect("preamble encodes");
            upstream.write_all(&frame).await.expect("write preamble");
            upstream.flush().await.expect("flush preamble");
            let (mut client_r, mut client_w) = client.into_split();
            let (mut up_r, mut up_w) = upstream.into_split();
            let to_upstream = async move {
                let _ = tokio::io::copy(&mut client_r, &mut up_w).await;
                let _ = up_w.shutdown().await;
            };
            let to_client = async move {
                let _ = tokio::io::copy(&mut up_r, &mut client_w).await;
                let _ = client_w.shutdown().await;
            };
            tokio::join!(to_upstream, to_client);
        });

        let mut tunnel = dial_test_server(proxy_addr, server_pub, subscriber_priv, &fleet_mesh_id).await;
        let hello = hello(SUPPORTED_EDGE_SESSION_VERSION, ExitPreference::Auto);
        tunnel.send(&encode_hello(&hello)).await.expect("send EdgeHello");

        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 256];
        let welcome = loop {
            match EdgeWelcome::decode(&buf) {
                Ok((w, _)) => break w,
                Err(WireError::Truncated { .. }) => {}
                Err(e) => panic!("EdgeWelcome did not decode: {e}"),
            }
            let n = tunnel.recv(&mut chunk).await.expect("recv EdgeWelcome");
            assert!(n > 0, "tunnel closed before EdgeWelcome arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_eq!(welcome.outcome, WireOutcome::Accepted { exit: ExitPreference::Auto });

        let _ = tunnel.close().await;
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server task must not hang")
            .expect("server task must not panic");
        assert!(result.is_ok(), "handle_connection must end cleanly once the client closes: {result:?}");
    }

    #[tokio::test]
    async fn end_to_end_refuses_an_unservable_country() {
        let wire_keypair = Arc::new(KeyPair::generate());
        let server_pub = wire_keypair.public.to_bytes();
        let subscriber_secret = StaticSecret::random_from_rng(OsRng);
        let subscriber_priv = subscriber_secret.to_bytes();
        let subscriber_pub = PublicKey::from(&subscriber_secret).to_bytes();
        let fleet_mesh_id = b"v3-staging".to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let deps = empty_entrance_deps(Arc::clone(&wire_keypair), subscriber_pub, fleet_mesh_id.clone());
        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            handle_connection(stream, deps).await
        });

        let mut tunnel =
            dial_test_server(addr, server_pub, subscriber_priv, &fleet_mesh_id).await;
        // No monitor session ever registered any country, so ANY specific
        // country request is unservable -- `Auto` is the only request that
        // does not depend on the (empty) roster.
        let hello = hello(SUPPORTED_EDGE_SESSION_VERSION, ExitPreference::Country(cc("ZZ")));
        tunnel.send(&encode_hello(&hello)).await.expect("send EdgeHello");

        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 256];
        let welcome = loop {
            match EdgeWelcome::decode(&buf) {
                Ok((w, _)) => break w,
                Err(WireError::Truncated { .. }) => {}
                Err(e) => panic!("EdgeWelcome did not decode: {e}"),
            }
            let n = tunnel.recv(&mut chunk).await.expect("recv EdgeWelcome");
            assert!(n > 0, "tunnel closed before EdgeWelcome arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_eq!(
            welcome.outcome,
            WireOutcome::Refused(EdgeRefusal::CountryUnavailable { requested: cc("ZZ") })
        );

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server task must not hang")
            .expect("server task must not panic");
        assert!(result.is_ok());
    }
}
