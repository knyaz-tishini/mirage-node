//! The node's inward chain splice: connections the perimeter classified as
//! wire on a face this box declared for chain traffic.
//!
//! # Why the node needs its own splice server
//!
//! The monitor already has one (`mirage_mesh_client::wire_splice`), and it is
//! not reusable here. That one is built around a `FrameHandler` and an
//! `HttpHandler` because everything reaching a monitor over the wire is a
//! control-plane frame or an HTTP request. Nothing reaching a node over the
//! chain splice is either: it is a chain hop's traffic, and what the node does
//! with it depends on which listener it belongs to.
//!
//! # What this replaces
//!
//! One bound TCP port per listener. Under that model a connection could not
//! arrive at the wrong listener, because each had its own socket and the
//! kernel did the addressing. The port is going away — it is a port outside
//! the perimeter, which the fleet no longer has — so the addressing has to be
//! carried by something else and checked here instead of by the kernel. See
//! `docs/mirage/plans/chain-data-plane-over-faces-2026-09-02.md`.
//!
//! # The peer check is not in this file, and that is deliberate
//!
//! `LocalChannel::NodeChainSplice` resolves the perimeter's account, and
//! `LocalListener::accept` enforces it: the `SO_PEERCRED` uid check and the
//! running-binary check both happen inside `accept`, BEFORE this module sees a
//! stream and therefore before a single byte is read. Hand-rolling the check
//! here would be a second implementation of a rule that already has one, and
//! the second one is the one that rots. The socket's mode and group are set by
//! the channel's own bind plan, not by anything here.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mirage_core::local_endpoint::LocalChannel;
use mirage_core::mirage::wire::ListenerRole;
use mirage_core::perimeter_preamble::{PerimeterPreamble, PREAMBLE_HEADER_LEN};
use mirage_protocol::auth::v9::CLIENT_HELLO_LEN;
use mirage_protocol::onion::fs_frame::{
    FsInitFrame, FsRelayInitFrame, MSG_FS_RELAY_INIT, WIRE_VERSION_FS, WIRE_VERSION_FS_LEGACY,
};
use mirage_protocol::PrefixStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::core::listener::make_credential_auth;
use crate::core::registry::registry::ListenerRegistry;
use crate::core::registry::selector::ChainSelector;
use crate::core::registry::spec::ListenerSpec;
use crate::family::mirage::exit::direct::handle_exit;
use crate::family::mirage::exit::onion::handle_onion_exit;
use crate::family::mirage::listener::tunnel_tcp::{
    bundle_from_spec, resolve_onion_exit_config, resolve_onion_relay_config, RelayDialResolution,
};
use crate::family::mirage::relay::onion_peel::handle_onion_peel;

/// Maximum frame body size accepted in one read on the chain splice,
/// `[4B BE len][body]`.
///
/// `pub(crate)` so `relay::onion_peel::handle_onion_peel`'s own
/// wire-version-peek — which reads this exact same shape of frame a second
/// time, after this module has already replayed it in — enforces the
/// identical bound rather than inventing a second one that could silently
/// drift from it. Defined here rather than in `onion_peel` because this
/// splice layer is where the frame is read FIRST, before either side knows
/// whether it names a forward-secret circuit or anything else.
pub(crate) const MAX_ENVELOPE_BYTES: usize = 65_536;

/// Decision budget for telling a forward-secret mesh/chain frame apart from
/// an ordinary V9 entrance dial arriving on the same splice (see
/// `resolve_chain_frame` step 3 and
/// `docs/mirage/plans/subscriber-gate-and-fork-2026-09-17.md`'s "Open
/// questions" — this number is proposed, not measured against real fleet
/// inter-box latency). An FS/mesh dial bursts its whole `[len][body]`
/// envelope in one write right after the decoy hello; a subscriber's real V9
/// ClientHello sends nothing further until it has read ServerHello, so
/// "nothing more arrives within budget" is itself the signal that this is
/// not an FS frame — generous for same-datacenter FS dials, short enough
/// that a subscriber does not notice it.
const CHAIN_FRAME_DECISION_TIMEOUT_MS: u64 = 500;

/// How long an unaddressable connection is held before it is closed.
///
/// Matched to the perimeter's `jail::DEFAULT_HOLD_MS`, and matched on purpose:
/// a connection that named no listener here and a connection the perimeter
/// jailed must be indistinguishable from the far end. If this closed faster,
/// the difference in timing would answer the question the silence exists to
/// refuse — "does this box have a listener by that name?" — and an enumerator
/// would read the answer off a stopwatch.
pub const UNADDRESSABLE_HOLD_MS: u64 = 30_000;

/// Dispose of a connection that named no listener.
///
/// **It never writes.** Not a byte, not a reset, not a protocol-level "no" —
/// the same contract as `mirage_perimeter::jail::dispose`, for the same
/// reason. It holds, reading and discarding whatever arrives, and then closes.
///
/// There is no fallback here and there must never be one. The node has two
/// existing fallback paths — `core::listener`'s forward to `fallback_dest` and
/// the decoy's forward to `decoy_forward_addr`, whose comment calls it "a
/// safer default than dropping" — and NEITHER may be reached from this path.
/// It is safer there because the connection was never addressed to anything in
/// particular; here it was addressed to something that does not exist, and
/// forwarding it would mean an unaddressable connection silently becoming
/// traffic on some other listener. That is the failure this whole cutover
/// exists to remove.
pub async fn dispose_unaddressable<S>(mut stream: S, hold_ms: u64)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(std::time::Duration::from_millis(hold_ms), async {
        // Small buffer on purpose, as in the perimeter's jail: this path
        // exists to consume, and a large per-connection buffer multiplied by
        // the hold budget is memory spent on somebody else's scan.
        let mut scratch = [0u8; 512];
        loop {
            match stream.read(&mut scratch).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    })
    .await;
    let _ = stream.shutdown().await;
}

/// Why a spliced connection is being disposed of.
///
/// Two causes, ONE exit. An authentication failure and a selector miss leave
/// through the same hold-then-close with identical timing and zero bytes
/// written, because the difference between them is exactly what a prober is
/// trying to learn: "is there a listener by that name here" and "is my
/// credential accepted here" are different questions, and answering either by
/// how the connection ends answers both.
///
/// The variant exists to shape the node's OWN log line, which the peer never
/// sees. It must never reach the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisposalCause {
    /// The frame did not authenticate — bad envelope, refused credential.
    NotAuthenticated,
    /// The frame authenticated and named a listener this node does not have,
    /// or one whose chain_length disagrees with the spec.
    NoSuchListener,
}

impl DisposalCause {
    fn label(self) -> &'static str {
        match self {
            DisposalCause::NotAuthenticated => "not-authenticated",
            DisposalCause::NoSuchListener => "no-such-listener",
        }
    }

    /// A dense index for this variant, used to pick this cause's slot in
    /// [`DISPOSAL_RATE_GATES`] without a `HashMap` lookup on the hot
    /// disposal path. Every variant needs exactly one arm here — kept
    /// exhaustive on purpose so a new [`DisposalCause`] fails to compile
    /// until it is given a slot, rather than silently sharing one.
    fn index(self) -> usize {
        match self {
            DisposalCause::NotAuthenticated => 0,
            DisposalCause::NoSuchListener => 1,
        }
    }
}

/// How many [`DisposalCause`] variants exist — the size of
/// [`DISPOSAL_RATE_GATES`] and the bound [`DisposalCause::index`] promises to
/// stay under.
const DISPOSAL_CAUSE_COUNT: usize = 2;

/// How long a `warn!` for one cause stays gated after firing, before the next
/// disposal of that same cause is allowed to escalate to `warn!` again.
///
/// Measured on the fleet at ~990 disposal lines/h for one cause (one every
/// ~3.6s); at this window a hot cause still reaches `warn!` at most once a
/// minute — inside any operator's polling window — while the busy box stops
/// being its own log-volume denial-of-service. The per-event line never
/// disappears; it keeps logging every disposal at `debug!` regardless of this
/// gate (see [`warn_unaddressable`]).
const DISPOSAL_WARN_GATE_MS: u64 = 60_000;

/// Per-cause rate gate for escalating a disposal from `debug!` to `warn!`.
///
/// Two atomics and a running total, no lock: the hot path is every spliced
/// connection this node disposes of, and a `Mutex` there would make
/// contention scale with disposal traffic instead of with the number of
/// distinct causes, which [`DisposalCause`] fixes at
/// [`DISPOSAL_CAUSE_COUNT`].
struct RateGate {
    /// Epoch-ms timestamp of the last `warn!` this gate let through. `0` is
    /// an explicit "never fired yet" sentinel checked by
    /// [`RateGate::record`] before any arithmetic on it — the first
    /// disposal of a cause always warns.
    last_warn_ms: AtomicU64,
    /// Disposals of this cause since the last `warn!` fired, not counting
    /// the one that is about to fire. Reset to `0` every time a `warn!`
    /// fires; read out by [`RateGate::record`] as `suppressed_since_last`.
    suppressed: AtomicU64,
    /// Every disposal of this cause, ever — never gated, never reset. Feeds
    /// [`chain_splice_disposal_counts`].
    total: AtomicU64,
}

impl RateGate {
    const fn new() -> Self {
        Self {
            last_warn_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// Record one disposal at `now_ms`.
    ///
    /// Returns `Some(suppressed_since_last)` if THIS disposal is the one
    /// that should escalate to `warn!` — carrying how many disposals of the
    /// same cause were swallowed since the previous `warn!` — or `None` if
    /// `window_ms` has not elapsed since the last `warn!`, in which case
    /// this disposal has already been folded into that count.
    ///
    /// The compare-exchange on `last_warn_ms` is what keeps this correct
    /// under concurrency: several disposals of the same cause can call this
    /// from different `tokio::spawn`ed tasks in the same instant, and only
    /// one of them may win a given window — the rest must fall through to
    /// the suppressed count instead of each firing its own `warn!`.
    fn record(&self, now_ms: u64, window_ms: u64) -> Option<u64> {
        self.total.fetch_add(1, Ordering::Relaxed);
        let last = self.last_warn_ms.load(Ordering::Relaxed);
        // `last == 0` is the explicit "never fired" sentinel, checked before
        // the arithmetic rather than folded into it — `now_ms` is caller-
        // supplied (epoch-ms in production, small synthetic values in unit
        // tests), and `now_ms.saturating_sub(0) >= window_ms` is only true
        // by coincidence of magnitude, not by the meaning "never fired".
        let due = last == 0 || now_ms.saturating_sub(last) >= window_ms;
        if due
            && self
                .last_warn_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// One [`RateGate`] per [`DisposalCause`] variant, indexed by
/// [`DisposalCause::index`].
static DISPOSAL_RATE_GATES: [RateGate; DISPOSAL_CAUSE_COUNT] = [RateGate::new(), RateGate::new()];

/// Milliseconds since the Unix epoch, saturating to `0` rather than panicking
/// if the system clock ever reads before it. This only feeds a rate gate, not
/// a correctness path: a wrong `now_ms` costs at most one extra or one missed
/// `warn!`, never a wrong disposal.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Snapshot of how many connections have been disposed of, per cause label,
/// since this process started.
///
/// Monotonic and independent of the `warn!` rate gate above: every disposal
/// increments [`RateGate::total`] regardless of whether that disposal's own
/// `warn!` was gated, so this always answers the real volume even while the
/// log itself is throttled. Exists for the node's metrics/telemetry surface
/// to poll; nothing in this module calls it yet.
pub fn chain_splice_disposal_counts() -> Vec<(String, u64)> {
    [DisposalCause::NotAuthenticated, DisposalCause::NoSuchListener]
        .into_iter()
        .map(|cause| {
            let total = DISPOSAL_RATE_GATES[cause.index()].total.load(Ordering::Relaxed);
            (cause.label().to_string(), total)
        })
        .collect()
}

/// Report a spliced connection being disposed of.
///
/// The selector's LENGTH and the peer, never the selector's value. The value
/// is a client's addressing choice, and a journal that printed it would hand
/// whoever reads the journal the map of which chains ran through this box.
/// Hash it if correlation is ever needed; do not print it.
///
/// Every disposal logs at `debug!`, unconditionally — the line this fleet
/// needed at `warn!` two days into an outage never disappears, it only moves
/// to a level an operator has to ask for. What stays at `warn!` by default is
/// gated per cause (see [`RateGate`]): the fleet was seeing ~990 of these an
/// hour for one cause, effectively a WARN-level flood off one busy box's own
/// disposal path, which is a symptom worth surfacing once per minute per
/// cause, not once per connection. The `warn!` that does fire carries
/// `suppressed_since_last` — how many disposals of the SAME cause were
/// swallowed since the previous `warn!` — plus this disposal's own peer and
/// selector hash as the sample.
pub fn warn_unaddressable(
    peer: &str,
    cause: DisposalCause,
    selector: &ChainSelector,
    chain_position: u8,
    bound_listeners: usize,
) {
    let selector_hash = selector_hash(selector);
    debug!(
        peer,
        cause = cause.label(),
        chain_position,
        selector_len = selector.len(),
        selector_hash = %selector_hash,
        bound_listeners,
        "[chain-splice] disposing of a spliced connection — holding, then closing; nothing is written and nothing is forwarded"
    );

    let gate = &DISPOSAL_RATE_GATES[cause.index()];
    if let Some(suppressed_since_last) = gate.record(now_ms(), DISPOSAL_WARN_GATE_MS) {
        warn!(
            peer,
            cause = cause.label(),
            chain_position,
            selector_len = selector.len(),
            selector_hash = %selector_hash,
            bound_listeners,
            suppressed_since_last,
            "[chain-splice] disposing of spliced connections — holding, then closing; nothing is written and nothing is forwarded"
        );
    }
}

/// A short digest of the selector, for correlating two log lines about the
/// same chain without printing the chain.
///
/// The selector is `{chain_id}-h{position}`, and `chain_id` is a client's
/// addressing choice: a journal that printed it would hand whoever reads the
/// journal the map of which chains ran through this box. Eight hex characters
/// of BLAKE3 is enough to tell two chains apart in one operator's window and
/// far too little to enumerate from.
fn selector_hash(selector: &ChainSelector) -> String {
    selector_digest(selector.as_bytes())
}

/// The same digest over raw selector bytes, for a caller that holds the
/// bytes without a [`ChainSelector`] around them — the datagram splice,
/// whose addressing arrives as a `DatagramChainAddress` rather than as an FS
/// frame.
///
/// One function so two planes' log lines about ONE chain correlate. Two
/// digests would make the correlation silently impossible exactly when a
/// chain runs over both transports, which is the case worth reading.
pub fn selector_digest(selector_bytes: &[u8]) -> String {
    let digest = blake3::hash(selector_bytes);
    hex::encode(&digest.as_bytes()[..4])
}

/// Bind the chain splice and serve it until `cancel` fires.
///
/// Returns on a bind failure, or once `cancel` fires — mirrors
/// `core::udp_chain_splice::serve`'s own cancellation shape so a capsule
/// rotation can retire this listener the same provable way it retires its
/// datagram counterpart, instead of the caller aborting this task mid-poll
/// and racing the next generation's own bind against this one's socket
/// actually closing. An accept error while still running is logged and
/// retried: the perimeter is the only peer, and one refused connection is
/// not a reason to stop serving the rest.
pub async fn serve(registry: Arc<ListenerRegistry>, cancel: CancellationToken) -> std::io::Result<()> {
    let listener = LocalChannel::NodeChainSplice.bind().await?;
    info!(
        channel = LocalChannel::NodeChainSplice.label(),
        endpoint = %LocalChannel::NodeChainSplice.endpoint(),
        "[chain-splice] serving the node's inward chain splice"
    );

    loop {
        // `accept` returns only ADMITTED peers: the uid and running-binary
        // checks are inside it, so nothing below has to re-ask who this is.
        // The unix-socket peer itself is not carried any further — the
        // preamble `handle_one` reads gives the connection's REAL client
        // address, and that is what every log line downstream uses instead.
        let (stream, _peer) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                info!("[chain-splice] retiring — no longer accepting, releasing the socket");
                break;
            }
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "[chain-splice] accept failed; continuing to serve");
                    continue;
                }
            },
        };

        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            handle_one(stream, registry).await;
        });
    }
    Ok(())
}

/// §2.5.3 of the plan, resolved: the selector is carried by the chain
/// envelope, which every FS wire frame already has. Primarily that is the
/// `selector_token` trailer the monitor mints per hop; a frame from a peer
/// that predates it (or a listener with no minted token) carries none, and
/// falls back to the `chain_id` plus explicit `chain_position` the client
/// (or the relaying hop) states directly — see
/// `registry::selector::ChainSelector::from_frame` for the one place that
/// choice is made. See this module's doc for why the bind port this replaces
/// cannot come back to carry it instead.
///
/// One spliced connection, start to finish:
/// 1. Read the perimeter's preamble — the real client address.
/// 2. Capture the hello the perimeter already replayed inward (no longer
///    discarded — see [`ChainFrameOutcome::Entrance`]).
/// 3. Read the chain frame under a short decision budget and resolve it to a
///    registered listener, OR — when nothing more arrives within budget, or
///    a full frame arrives naming no FS variant — hand off to the ordinary
///    V9 entrance handshake (`docs/mirage/plans/2026-09-24-edge-as-entry.md`:
///    the node keeps no subscriber-entrance code path, so this handoff is
///    unconditionally a mesh-credential dial).
/// 4. On a resolved chain listener, hand the connection to that listener's
///    own serving path with the consumed bytes replayed, dispatched to the
///    EXIT handler or the RELAY handler by the resolved spec's own role —
///    never unconditionally to one of them, since only the spec (not the
///    frame) says which this connection actually is. On an entrance handoff,
///    run the real V9 handshake and, once it accepts, dispatch straight to
///    the exit handler ([`dispatch_entrance`]). On any OTHER failure,
///    dispose without a byte — see [`dispose_unaddressable`] and this
///    module's doc on why the causes
///    must be indistinguishable from the peer's side.
async fn handle_one<S>(mut stream: S, registry: Arc<ListenerRegistry>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let resolved = match resolve_chain_frame(&mut stream, &registry).await {
        ChainFrameOutcome::Chain(resolved) => resolved,
        ChainFrameOutcome::Entrance(handoff) => {
            // The replay always starts with the whole 97-byte ClientHello
            // (both `EntranceHandoff` constructors below put it there first)
            // so the real V9 handshake `dispatch_entrance` runs sees the
            // connection's ACTUAL opening bytes.
            let prefixed = PrefixStream::new(stream, handoff.replay);
            dispatch_entrance(prefixed, handoff.real_peer, &registry).await;
            return;
        }
        ChainFrameOutcome::Reject(rejected) => {
            let bound = registry.chain_spec_count().await;
            let peer_str = rejected
                .peer
                .map(|p| p.to_string())
                .unwrap_or_else(|| "pre-preamble".to_string());
            warn_unaddressable(
                &peer_str,
                rejected.cause,
                &rejected.selector,
                rejected.chain_position,
                bound,
            );
            dispose_unaddressable(stream, UNADDRESSABLE_HOLD_MS).await;
            return;
        }
    };

    let bundle = bundle_from_spec(&resolved.spec);
    let runtime = registry.runtime();
    let own_node_id = runtime.snapshot.load().node_config.node_id.clone();
    let chain_id_str = resolved.spec.chain_role.as_ref().map(|r| r.chain_id.as_str());

    // Hand off to the listener's own serving path with the bytes this
    // function consumed replayed, so the handler sees the connection's
    // original bytes — the same `PrefixStream` shape `handle_onion_peel` and
    // `handle_onion_exit` already use to reconstruct a stream peeked ahead
    // of.
    let prefixed = PrefixStream::new(stream, resolved.replay);

    // Dispatch on the RESOLVED SPEC'S ROLE, not on anything the frame
    // claimed — the frame is a client's addressing choice, authenticated by
    // nothing at this point; the spec is what the monitor pushed. An exit
    // reached through `handle_onion_peel` fails one step later anyway (see
    // `relay::onion_fs_peel`'s own terminal-position guard), so the miss
    // this replaces was never a security hole, only a chain that could
    // never complete.
    let result = match &resolved.spec.role {
        ListenerRole::Exit { .. } => {
            let cfg = resolve_onion_exit_config(
                bundle.chain_position,
                bundle.chain_length,
                &bundle.chain_node_ids,
                &runtime,
            );
            handle_onion_exit(cfg, prefixed, resolved.real_peer).await
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
                    handle_onion_peel(cfg, prefixed, resolved.real_peer, None).await
                }
                RelayDialResolution::Refused { reason } => {
                    warn!(
                        peer = %resolved.real_peer,
                        chain_id = ?chain_id_str,
                        reason = %reason,
                        "[chain-splice] refusing relay hop — next hop has no dialable chain face"
                    );
                    dispose_unaddressable(prefixed, UNADDRESSABLE_HOLD_MS).await;
                    Ok(())
                }
            }
        }
    };

    if let Err(e) = result {
        warn!(peer = %resolved.real_peer, error = %e, "[chain-splice] onion handler error");
    }
}

/// Run the ordinary V9 handshake for a spliced connection that did not turn
/// out to be a forward-secret mesh/chain frame (see
/// [`ChainFrameOutcome::Entrance`]). The node keeps no subscriber-entrance
/// code path (`docs/mirage/plans/2026-09-24-edge-as-entry.md`: "the
/// subscriber gate moves out of `mirage-node`") — every accepted dial here
/// is unconditionally a mesh-credential chain-hop dial, verified by the same
/// `mesh_auth` closure the pipelined V9 exit path uses
/// (`make_credential_auth`), against the fleet's own real `mesh_id`. A
/// caller with no valid mesh credential fails the handshake exactly like any
/// other rejected dial.
///
/// `allow_legacy_v8 = false`: the same rule `core::listener`'s own V9 exit
/// dispatch already applies — V8 carries no credential channel, so a V8
/// dial here could never present one.
async fn dispatch_entrance<S>(stream: S, real_peer: SocketAddr, registry: &ListenerRegistry)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let runtime = registry.runtime();
    let snap = runtime.snapshot.load_full();

    let mesh_auth = make_credential_auth(
        snap.credential_params.clone(),
        snap.spent_set.clone(),
        real_peer,
        snap.node_config.node_id.as_bytes().to_vec(),
        runtime.mesh_id.as_bytes().to_vec(),
        runtime.role_signed_replay.clone(),
    );

    let proto_auth = mirage_protocol::driver::convert_auth(&mirage_core::config::AuthMode::Blake3);

    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        mirage_protocol::driver::handshake_server_stream_with_auth(
            stream,
            &runtime.keypair,
            &proto_auth,
            real_peer,
            runtime.mesh_id.as_bytes(),
            mesh_auth,
            false, // allow_legacy_v8 — see doc above
        ),
    )
    .await;

    let tunnel = match handshake {
        Ok(Ok(Some(tunnel))) => tunnel,
        // client_auth rejected, or the hello did not parse/verify — the
        // driver has already returned before ServerHello, nothing was
        // written (`handshake_server_stream_with_auth`'s own INVARIANT doc;
        // verified by reading `run_server_handshake_v9_inner`, which returns
        // `Ok(None)` before computing `server_proof` or writing anything).
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            debug!(peer = %real_peer, error = %e, "[chain-splice] entrance handshake error");
            return;
        }
        Err(_elapsed) => {
            debug!(peer = %real_peer, "[chain-splice] entrance handshake timeout");
            return;
        }
    };

    if let Err(e) = handle_exit(tunnel, runtime.doh.load_full()).await {
        warn!(peer = %real_peer, error = %e, "[chain-splice] entrance dispatch error");
    }
}

/// What [`resolve_chain_frame`] found: a registered listener, the bytes
/// already consumed (to replay into the handler), and the client's real
/// address off the preamble.
struct ResolvedChain {
    spec: ListenerSpec,
    real_peer: SocketAddr,
    /// `[4B BE length][frame body]`, exactly as read off the wire.
    replay: Vec<u8>,
}

/// What [`resolve_chain_frame`] found when a spliced connection was NOT a
/// forward-secret mesh/chain frame: everything captured so far (to replay
/// into the real V9 handshake `dispatch_entrance` runs) and the client's real
/// address off the preamble.
struct EntranceHandoff {
    /// `hello ++ whatever prefix bytes were read while deciding this was not
    /// an FS frame` — replayed into `dispatch_entrance`'s stream so the V9
    /// handshake it runs sees the connection's ACTUAL opening bytes, exactly
    /// as [`ResolvedChain::replay`] does for the FS path.
    replay: Vec<u8>,
    real_peer: SocketAddr,
}

/// What [`resolve_chain_frame`] decided a spliced connection is.
enum ChainFrameOutcome {
    /// A registered FS/mesh chain hop, resolved against a pushed spec —
    /// dispatch to that spec's own exit/relay handler exactly as before this
    /// change.
    Chain(ResolvedChain),
    /// Not an FS frame — either nothing more arrived within the decision
    /// budget, or a full clean frame arrived whose first byte names none of
    /// the FS variants. Hand off to the ordinary V9 entrance handshake; a
    /// genuine scanner fails that handshake the same way any other V9 face's
    /// noise does, with no special-casing needed here.
    Entrance(EntranceHandoff),
    /// Malformed on the wire — preamble corrupt, hello short, or a framed
    /// message that started but did not finish arriving. Disposed of exactly
    /// as before this change: held, then closed, nothing written.
    Reject(RejectedFrame),
}

/// Why [`resolve_chain_frame`] rejected a connection, and enough to log it
/// through [`warn_unaddressable`] without a second implementation of what a
/// disposal looks like.
#[derive(Debug)]
struct RejectedFrame {
    cause: DisposalCause,
    /// Best-effort correlation handle for our OWN log line. Empty when the
    /// rejection happened before any selector could be read at all — see
    /// [`ChainSelector::from_bytes`].
    selector: ChainSelector,
    chain_position: u8,
    /// The client's real address, once the preamble decoded far enough to
    /// give one. `None` for a rejection that happened before or during the
    /// preamble read itself — there is no address to log yet.
    peer: Option<SocketAddr>,
}

impl RejectedFrame {
    /// A rejection before the preamble decoded — no address, no selector.
    fn early(cause: DisposalCause) -> Self {
        Self {
            cause,
            selector: ChainSelector::from_bytes(&[]),
            chain_position: 0,
            peer: None,
        }
    }
}

/// Read `[4B BE len][body]`, bounded by [`MAX_ENVELOPE_BYTES`] — exactly the
/// FS frame shape this splice has always read at this step. Split out so
/// `resolve_chain_frame`'s short decision budget can wrap the whole read in
/// one `tokio::time::timeout` rather than only its first four bytes: an
/// FS/mesh dial bursts the whole envelope in one write, so "did the full,
/// well-formed frame arrive in time" is the question the budget answers, not
/// "did the length prefix alone arrive".
async fn read_len_prefixed_frame<S>(stream: &mut S) -> std::io::Result<([u8; 4], Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_ENVELOPE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "chain-splice: frame length out of bounds",
        ));
    }
    let mut frame_body = vec![0u8; frame_len];
    stream.read_exact(&mut frame_body).await?;
    Ok((len_buf, frame_body))
}

/// Read the perimeter's preamble, capture the hello, read the chain frame
/// under a short decision budget, and resolve it to a registered listener —
/// everything up to the point where the connection is handed off (to the
/// resolved chain listener, or to the ordinary V9 entrance path) or disposed
/// of.
///
/// Reads through `&mut S` rather than consuming `stream`: every outcome
/// leaves the SAME stream value available to the caller (for disposal, or to
/// build a [`PrefixStream`] for the entrance handoff), and a function that
/// consumed it would force the caller to reconstruct one.
async fn resolve_chain_frame<S>(stream: &mut S, registry: &ListenerRegistry) -> ChainFrameOutcome
where
    S: AsyncRead + Unpin,
{
    // 1. The perimeter's preamble: real client address, length-prefixed.
    // Every splice on this face carries one — written by the perimeter
    // itself for both our own nodes' FS dials and a subscriber's V9 dial —
    // so a failure here is a protocol violation neither caller class can
    // produce; it stays a disposal, never an entrance handoff.
    let mut header = [0u8; PREAMBLE_HEADER_LEN];
    if stream.read_exact(&mut header).await.is_err() {
        return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
    }
    let body_len = match PerimeterPreamble::parse_header(&header) {
        Ok(len) => len,
        Err(_) => {
            return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
        }
    };
    let mut body = vec![0u8; body_len as usize];
    if stream.read_exact(&mut body).await.is_err() {
        return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
    }
    let preamble = match PerimeterPreamble::decode_body(&body) {
        Ok(p) => p,
        Err(_) => {
            return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
        }
    };
    let real_peer: SocketAddr = match preamble.peer.parse() {
        Ok(p) => p,
        Err(_) => {
            return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
        }
    };

    // 2. Capture exactly the hello the perimeter already replayed inward.
    // The shared constant from `mirage_protocol::auth::v9` — never a literal
    // 97 — so this and `relay::onion_fs_peel::write_face_hello` cannot drift
    // apart. Historically discarded here (an FS/mesh dial's hello is a decoy
    // both sides fake); now CAPTURED, because a real subscriber's V9
    // ClientHello IS these exact bytes, and if this connection turns out not
    // to be an FS frame it must be replayed whole into `dispatch_entrance`.
    let mut hello = [0u8; CLIENT_HELLO_LEN];
    if stream.read_exact(&mut hello).await.is_err() {
        return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
    }

    // 3. `[4B BE len][body]` under a short decision budget
    // (`CHAIN_FRAME_DECISION_TIMEOUT_MS`): an FS/mesh dial bursts this whole
    // envelope in one write right after the decoy hello, while a real V9
    // entrance dial sends nothing more until it has read ServerHello.
    //
    //   - Timeout, or a full clean frame whose first byte names no FS
    //     variant → not this connection's shape; fall through to the
    //     ordinary V9 entrance path instead of disposing of it.
    //   - The read starts but fails structurally (short/truncated/oversized)
    //     before completing → this claimed to be a framed message and broke
    //     one; that stays a disposal, exactly as before this change — a
    //     truncated FS frame is not "maybe a subscriber", it is malformed.
    let frame_read = tokio::time::timeout(
        std::time::Duration::from_millis(CHAIN_FRAME_DECISION_TIMEOUT_MS),
        read_len_prefixed_frame(stream),
    )
    .await;

    let (len_buf, frame_body) = match frame_read {
        Err(_elapsed) => {
            return ChainFrameOutcome::Entrance(EntranceHandoff {
                replay: hello.to_vec(),
                real_peer,
            });
        }
        Ok(Ok(pair)) => pair,
        Ok(Err(_)) => {
            return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
        }
    };

    // 4. Peek `body[0]`, exactly as `relay::onion_peel::handle_onion_peel`
    // already does, and pull the selector's three fields out of whichever
    // frame shape this is.
    let first = match frame_body.first() {
        Some(b) => *b,
        None => {
            return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
        }
    };
    let (chain_id, chain_position, chain_length, selector_token) = if first == WIRE_VERSION_FS
        || first == WIRE_VERSION_FS_LEGACY
    {
        match FsInitFrame::decode(&frame_body) {
            Ok((init, _)) => (init.chain_id, init.chain_position, init.chain_length, init.selector_token),
            Err(_) => {
                return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
            }
        }
    } else if first == MSG_FS_RELAY_INIT {
        match FsRelayInitFrame::decode(&frame_body) {
            Ok((relay, _)) => (relay.chain_id, relay.chain_position, relay.chain_length, relay.selector_token),
            Err(_) => {
                return ChainFrameOutcome::Reject(RejectedFrame::early(DisposalCause::NotAuthenticated));
            }
        }
    } else {
        // Not a forward-secret frame. This used to decode a non-FS
        // `V9EnvelopeHeader` here, resolve a listener for it, and hand it to
        // `handle_one` — which reached the onion-peel handler one step
        // later only to have it refuse the connection anyway (see
        // `family::mirage::relay::onion_peel`'s module doc for why that
        // envelope is gone). This is now the entrance handoff instead: a
        // full, clean frame arrived, but names none of the FS variants —
        // exactly the shape a subscriber's real V9 dial produces once its
        // ClientHello is followed by a credential frame instead of an FS
        // envelope.
        let mut replay = Vec::with_capacity(hello.len() + len_buf.len() + frame_body.len());
        replay.extend_from_slice(&hello);
        replay.extend_from_slice(&len_buf);
        replay.extend_from_slice(&frame_body);
        return ChainFrameOutcome::Entrance(EntranceHandoff { replay, real_peer });
    };

    // 5. Resolve through the registry's existing routing table. The token
    // is authoritative when the frame carries one; a frame with none
    // resolves exactly as it always has, through the derived name — see
    // `ChainSelector::from_frame`.
    let selector = ChainSelector::from_frame(&selector_token, &chain_id, chain_position);
    let spec = match registry
        .resolve_for_frame(&chain_id, chain_position, chain_length, &selector_token)
        .await
    {
        Some(spec) => spec,
        None => {
            return ChainFrameOutcome::Reject(RejectedFrame {
                cause: DisposalCause::NoSuchListener,
                selector: selector.clone(),
                chain_position,
                peer: Some(real_peer),
            });
        }
    };

    let mut replay = Vec::with_capacity(4 + frame_body.len());
    replay.extend_from_slice(&len_buf);
    replay.extend_from_slice(&frame_body);

    ChainFrameOutcome::Chain(ResolvedChain {
        spec,
        real_peer,
        replay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::registry::ActivationContext;
    use crate::core::registry::spec::ListenerId;
    use crate::core::runtime::{NodeRuntime, NodeRuntimeSnapshot};
    use mirage_core::config::NodeConfig;
    use mirage_core::crypto::{AeadSuite as CryptoAeadSuite, KeyPair, SpentSet};
    use mirage_core::mirage::wire::{
        AeadSuite, ChainRole, EntryHop, ExitMode, Framing, ListenerRole, MirageListenerKind,
        RelayMode, SpecFingerprint,
    };
    use mirage_core::perimeter_preamble::Verdict;

    /// A runtime just complete enough to construct a [`ListenerRegistry`].
    /// `credential_params` is deliberately left at its `None` default — the
    /// exit-vs-relay routing test below depends on that to tell the two
    /// handlers apart by which one fails closed on it.
    fn test_runtime(node_id: &str) -> Arc<NodeRuntime> {
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

        let snapshot = NodeRuntimeSnapshot {
            protocols: Vec::new(),
            pools: Vec::new(),
            relay_metrics: None,
            node_config,
            credential_params: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            spent_set: Arc::new(std::sync::Mutex::new(SpentSet::new())),
            role_signed_replay: Arc::new(std::sync::Mutex::new(
                crate::core::role_signed_gate::RoleSignedReplayCache::new(),
            )),
            allow_legacy_v8: true,
        };

        NodeRuntime::new(snapshot, KeyPair::generate(), Arc::from("test-mesh"), None, None)
    }

    fn test_registry(node_id: &str) -> Arc<ListenerRegistry> {
        Arc::new(ListenerRegistry::new(ActivationContext {
            runtime: test_runtime(node_id),
            outbound_protocol: None,
            doh: None,
        }))
    }

    /// A chain-hop `ListenerSpec`, registered (not bound) the way a real one
    /// arrives from the monitor. Mirrors `selector::chain_routing_tests::hop_spec`.
    fn hop_spec(chain_id: &str, position: u8, length: u8, chain_node_ids: Vec<String>) -> ListenerSpec {
        ListenerSpec {
            id: ListenerId(format!("{chain_id}-h{position}")),
            mesh_id: "MESH1".into(),
            kind: MirageListenerKind::TunnelTcp,
            role: if position + 1 == length {
                ListenerRole::Exit { exit_mode: ExitMode::Onion }
            } else {
                ListenerRole::Relay {
                    position: if position == 0 { EntryHop::Entry } else { EntryHop::Hop },
                    relay_mode: RelayMode::OnionPeel,
                }
            },
            framing: Framing::Onion,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            bind_port: None,
            chain_role: Some(ChainRole {
                chain_id: chain_id.into(),
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

    /// A minimal, well-formed `FsRelayInitFrame` body naming `chain_id` at
    /// `chain_position`/`chain_length`. This is the shape a relayed FS
    /// circuit-setup frame takes on the wire (`MSG_FS_RELAY_INIT = 0x92`) —
    /// the only frame shape `resolve_chain_frame` still decodes for a
    /// non-entry hop. No data frame trails it; `resolve_chain_frame` never
    /// reads past the init frame.
    fn fs_relay_init_body(chain_id: &str, chain_position: u8, chain_length: u8) -> Vec<u8> {
        let frame = FsRelayInitFrame {
            mesh_id: b"MESH1".to_vec(),
            chain_id: chain_id.as_bytes().to_vec(),
            chain_length,
            chain_position,
            client_suites: vec![CryptoAeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0u8; 32],
            expected_peer_table_generation: 0,
            prev_transcript: [0u8; 32],
            credential_scheme: 0,
            credential: Vec::new(),
            selector_token: Vec::new(),
        };
        frame.encode().expect("FsRelayInitFrame must encode")
    }

    /// `[preamble][hello][4B BE len][frame_body]` — a whole connection's
    /// worth of bytes, as they arrive on the real chain splice socket.
    fn connection_bytes(frame_body: &[u8], peer: &str) -> Vec<u8> {
        let preamble = PerimeterPreamble {
            peer: peer.into(),
            face_port: 443,
            face_camouflage: "tls_real".into(),
            verdict: Verdict::NodeChain,
            first_bytes: vec![0x09],
            observed_at_ms: 1_700_000_000_000,
        };
        let mut out = preamble.encode().expect("preamble encodes");
        out.extend(std::iter::repeat(0u8).take(CLIENT_HELLO_LEN));
        out.extend_from_slice(&(frame_body.len() as u32).to_be_bytes());
        out.extend_from_slice(frame_body);
        out
    }

    /// A well-formed preamble + hello + FS relay-init frame naming a
    /// registered chain listener resolves to that spec.
    #[tokio::test]
    async fn a_registered_fs_chain_hop_resolves_to_its_spec() {
        let registry = test_registry("own-node");
        let chain_node_ids = vec!["entry-node".to_string(), "own-node".to_string()];
        let spec = hop_spec("auto-resolves", 1, 2, chain_node_ids);
        registry
            .activate(spec.clone())
            .await
            .expect("a chain hop registers rather than binds");

        let frame_body = fs_relay_init_body("auto-resolves", 1, 2);
        let bytes = connection_bytes(&frame_body, "203.0.113.9:51234");

        let (mut client_side, mut node_side) = tokio::io::duplex(65536);
        client_side.write_all(&bytes).await.expect("test write");

        let resolved = match resolve_chain_frame(&mut node_side, &registry).await {
            ChainFrameOutcome::Chain(resolved) => resolved,
            ChainFrameOutcome::Entrance(_) => {
                panic!("a registered FS frame must resolve to the chain, not the entrance path")
            }
            ChainFrameOutcome::Reject(rejected) => {
                panic!("a registered FS frame must resolve; got Reject({:?})", rejected.cause)
            }
        };
        assert_eq!(resolved.spec.id, spec.id, "must resolve to the pushed spec");
        assert_eq!(
            resolved.real_peer.to_string(),
            "203.0.113.9:51234",
            "the preamble's real client address must survive into the resolution"
        );
    }

    /// Nothing more arrives after the hello within the decision budget — the
    /// shape a subscriber's real V9 dial takes (it waits for ServerHello
    /// before sending anything else). `resolve_chain_frame` must hand off to
    /// the entrance path with just the hello captured as the replay, not
    /// treat it as a malformed FS frame.
    #[tokio::test]
    async fn nothing_after_the_hello_within_budget_hands_off_to_the_entrance_path() {
        let registry = test_registry("own-node");
        let preamble = PerimeterPreamble {
            peer: "203.0.113.9:51234".into(),
            face_port: 443,
            face_camouflage: "tls_real".into(),
            verdict: Verdict::NodeChain,
            first_bytes: vec![0x09],
            observed_at_ms: 1_700_000_000_000,
        };
        let mut bytes = preamble.encode().expect("preamble encodes");
        let hello = [0x09u8; CLIENT_HELLO_LEN];
        bytes.extend_from_slice(&hello);
        // No length prefix, no frame body follows — the client is waiting
        // for ServerHello, exactly like a real V9 entrance dial.

        let (mut client_side, mut node_side) = tokio::io::duplex(65536);
        client_side.write_all(&bytes).await.expect("test write");

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            resolve_chain_frame(&mut node_side, &registry),
        )
        .await
        .expect("must not hang past the decision budget");

        match outcome {
            ChainFrameOutcome::Entrance(handoff) => {
                assert_eq!(
                    handoff.replay,
                    hello.to_vec(),
                    "the captured hello must be the whole replay when nothing else arrived"
                );
                assert_eq!(handoff.real_peer.to_string(), "203.0.113.9:51234");
            }
            _ => panic!("expected an entrance handoff when nothing followed the hello in time"),
        }
    }

    /// The same shape of connection, naming a `chain_id` no listener on this
    /// node answers to, disposes — and writes no byte.
    #[tokio::test]
    async fn an_unregistered_chain_id_disposes_without_a_byte() {
        let registry = test_registry("own-node");
        // Never registered — a chain this node was never told to serve.
        let frame_body = fs_relay_init_body("auto-nowhere", 1, 2);
        let bytes = connection_bytes(&frame_body, "203.0.113.9:51234");

        let (mut client_side, node_side) = tokio::io::duplex(65536);
        client_side.write_all(&bytes).await.expect("test write");
        // Once the buffered bytes above are drained, this lets the disposal
        // path's hold end on EOF immediately rather than waiting out the
        // real 30-second budget.
        client_side.shutdown().await.expect("test shutdown");

        handle_one(node_side, registry).await;

        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client_side.read_to_end(&mut got))
            .await
            .expect("disposal must complete once the peer has gone")
            .expect("read to end must succeed");
        assert_eq!(got.len(), 0, "an unresolvable chain_id must write no byte");
    }

    /// A frame shorter than its declared length disposes rather than
    /// hanging forever waiting for bytes that are never coming, or panicking
    /// on the short read.
    #[tokio::test]
    async fn a_truncated_frame_disposes_instead_of_hanging_or_panicking() {
        let registry = test_registry("own-node");
        let full_body = fs_relay_init_body("auto-truncated", 1, 2);

        // The length prefix promises the WHOLE body; only half of it follows.
        let mut bytes = connection_bytes(&full_body, "203.0.113.9:51234");
        let short_by = full_body.len() / 2;
        bytes.truncate(bytes.len() - short_by);

        let (mut client_side, node_side) = tokio::io::duplex(65536);
        client_side.write_all(&bytes).await.expect("test write");
        client_side.shutdown().await.expect("test shutdown");

        tokio::time::timeout(std::time::Duration::from_secs(5), handle_one(node_side, registry))
            .await
            .expect("a truncated frame must not hang forever");

        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client_side.read_to_end(&mut got))
            .await
            .expect("disposal must complete")
            .expect("read to end must succeed");
        assert_eq!(got.len(), 0, "a truncated frame must write no byte");
    }

    /// A first byte that names neither an `FsInitFrame` nor an
    /// `FsRelayInitFrame` no longer disposes without resolving — it hands off
    /// to the ordinary V9 entrance handshake (`ChainFrameOutcome::Entrance`,
    /// `dispatch_entrance`), the same path a genuine mesh-credential dial
    /// that is not itself an FS frame takes. These particular bytes are not
    /// a real V9 ClientHello (first byte `0x00`, not `0x09`), so the
    /// entrance handshake refuses them the same way every other
    /// `allow_legacy_v8=false` V9 face in the fleet
    /// already refuses a non-V9 first byte: one `VERSION_REJECT` (`0xFF`)
    /// byte, then close — fast, not the 30s unaddressable hold this
    /// connection used to take.
    #[tokio::test]
    async fn a_non_fs_first_byte_dispatches_to_the_entrance_path_instead_of_disposing() {
        let registry = test_registry("own-node");
        // Not WIRE_VERSION_FS, not WIRE_VERSION_FS_LEGACY, not MSG_FS_RELAY_INIT.
        let frame_body = vec![0x00u8, 1, 2, 3, 4];
        let bytes = connection_bytes(&frame_body, "203.0.113.9:51234");

        let (mut client_side, node_side) = tokio::io::duplex(65536);
        client_side.write_all(&bytes).await.expect("test write");
        client_side.shutdown().await.expect("test shutdown");

        tokio::time::timeout(std::time::Duration::from_secs(5), handle_one(node_side, registry))
            .await
            .expect("the entrance handshake attempt must not hang forever");

        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client_side.read_to_end(&mut got))
            .await
            .expect("the connection must close quickly — no 30s unaddressable hold on this path")
            .expect("read to end must succeed");
        assert_eq!(
            got,
            vec![0xFFu8],
            "a non-V9 first byte on the entrance path gets the ordinary VERSION_REJECT \
             byte, not the silent unaddressable-hold disposal"
        );
    }

    /// Pins the Part 2 defect and its fix: a chain listener whose resolved
    /// spec is `ListenerRole::Exit` must be handed to
    /// `family::mirage::exit::onion::handle_onion_exit`, never to
    /// `relay::onion_peel::handle_onion_peel`, even though both accept the
    /// identical `MSG_FS_RELAY_INIT` wire byte and even though `handle_one`
    /// resolves the listener the same way regardless of role.
    ///
    /// Proven through the REAL production handler chain (`handle_one`
    /// end-to-end), not a mock: the two handlers are driven to diverge on
    /// the very first thing that differs between them — credential
    /// enforcement, which only the exit performs (relays "do NOT verify
    /// credentials", per `exit/onion_fs.rs`'s own comment) — and the
    /// divergence is read off the wire, not off which function was called.
    ///
    /// With no `credential_params` configured (the test runtime's default),
    /// the OLD unconditional-`handle_onion_peel` bug and the fix produce
    /// OBSERVABLY DIFFERENT acks for the identical bytes:
    /// - Old bug (routed to the relay): the relay has no credential check,
    ///   so it runs straight through to the terminal-position guard,
    ///   sending `FsCreatedFrame{status: Ok}` on its way there before
    ///   erroring out one step later (`onion_fs_peel.rs`'s own guard).
    /// - Fixed (routed to the exit): the exit's credential gate runs BEFORE
    ///   it would send an Ok ack, and fails closed on the absent params,
    ///   sending `FsCreatedFrame{status: CredentialRejected}` instead.
    ///
    /// So decoding the ack's `status` tells us which handler actually ran,
    /// with no need to complete a real handshake on either side.
    #[tokio::test]
    async fn an_exit_role_listener_reaches_the_exit_handler_not_the_relay_one() {
        use mirage_protocol::onion::fs_frame::{FsCreatedFrame, FsCreatedStatus};

        let registry = test_registry("own-node");
        let chain_node_ids = vec!["entry-node".to_string(), "exit-node".to_string()];
        // position 1 of 2 == the terminal position == `ListenerRole::Exit`
        // (see `hop_spec`'s own role derivation) — the exact shape of chain
        // the brief's defect describes: an exit addressed by face.
        let spec = hop_spec("auto-exit-routing", 1, 2, chain_node_ids);
        assert!(
            matches!(spec.role, ListenerRole::Exit { .. }),
            "test fixture must actually exercise the Exit role"
        );
        registry
            .activate(spec.clone())
            .await
            .expect("a chain hop registers rather than binds");

        let frame_body = fs_relay_init_body("auto-exit-routing", 1, 2);
        let bytes = connection_bytes(&frame_body, "203.0.113.9:51234");

        let (mut client_side, node_side) = tokio::io::duplex(65536);
        client_side.write_all(&bytes).await.expect("test write");

        tokio::spawn(handle_one(node_side, registry));

        let mut ack = [0u8; FsCreatedFrame::ENCODED_LEN];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_side.read_exact(&mut ack),
        )
        .await
        .expect("an ack must arrive")
        .expect("read_exact must succeed");

        let created = FsCreatedFrame::decode(&ack).expect("a well-formed FsCreatedFrame ack");
        assert_eq!(
            created.status,
            FsCreatedStatus::CredentialRejected,
            "status {:?}: an Ok ack here means the RELAY handler ran (it has no \
             credential check and would have sent Ok on its way to the terminal- \
             position guard) — the exit-role spec must reach the EXIT handler instead",
            created.status,
        );
    }

    #[tokio::test]
    async fn disposal_never_writes_a_byte() {
        // The property, and the only one that matters here. A prober must
        // learn nothing from the response, because there is none — not an
        // error frame, not a reset, not a protocol-level refusal.
        let (node_side, mut client_side) = tokio::io::duplex(1024);

        let disposer = tokio::spawn(async move {
            dispose_unaddressable(node_side, 150).await;
        });

        let mut got = [0u8; 64];
        let n = client_side
            .read(&mut got)
            .await
            .expect("the client's read must complete, by EOF");
        assert_eq!(n, 0, "the disposal path wrote {n} bytes; it must write none");
        disposer.await.expect("disposer must not panic");
    }

    #[tokio::test]
    async fn disposal_holds_rather_than_closing_at_once() {
        // An instant close is itself an answer: it separates "no such
        // listener" from "listener exists but is busy", which is exactly the
        // question the silence exists to refuse. The hold is the mechanism,
        // so a regression that dropped it would be a regression in secrecy
        // and would otherwise look like a harmless simplification.
        let (node_side, _client_side) = tokio::io::duplex(1024);
        let started = std::time::Instant::now();
        dispose_unaddressable(node_side, 200).await;
        let held = started.elapsed();
        assert!(
            held >= std::time::Duration::from_millis(150),
            "held only {held:?}; the disposal must hold for its budget, not close at once"
        );
    }

    /// The two causes must be INDISTINGUISHABLE from the peer's side.
    ///
    /// Asserted as a comparison of the two paths, not as "the connection
    /// closes" — a test that only checks closure would pass while one path
    /// closed in 2ms and the other in 30s, which is the whole leak. What a
    /// prober can measure is bytes and time, so both are compared.
    #[tokio::test]
    async fn an_auth_failure_and_a_selector_miss_are_indistinguishable() {
        async fn run(cause: DisposalCause) -> (usize, std::time::Duration) {
            let (node_side, mut client_side) = tokio::io::duplex(1024);
            // The cause shapes the node's own log line and nothing else; it is
            // passed here to prove exactly that.
            warn_unaddressable(
                "203.0.113.9:44321",
                cause,
                &ChainSelector::from_chain_position(b"auto-fa291277", 0),
                0,
                3,
            );
            let started = std::time::Instant::now();
            let disposer = tokio::spawn(async move {
                dispose_unaddressable(node_side, 120).await;
            });
            let mut got = [0u8; 64];
            let n = client_side.read(&mut got).await.expect("read completes by EOF");
            disposer.await.expect("disposer must not panic");
            (n, started.elapsed())
        }

        // Several rounds, compared by their MINIMUM rather than by a single
        // sample. A loaded box — a parallel test binary, a build in another
        // container — can only ever make one of these slower, never faster,
        // so a lone pair of samples measures the scheduler as much as the
        // code and fails on a machine that is merely busy. Taking the floor
        // of each side removes exactly that noise while keeping the property:
        // if one path had been given its own timing, its floor would move.
        const ROUNDS: usize = 5;
        let mut auth_floor = std::time::Duration::MAX;
        let mut miss_floor = std::time::Duration::MAX;
        for _ in 0..ROUNDS {
            let (auth_bytes, auth_took) = run(DisposalCause::NotAuthenticated).await;
            let (miss_bytes, miss_took) = run(DisposalCause::NoSuchListener).await;
            assert_eq!(auth_bytes, 0, "the auth-failure path wrote {auth_bytes} bytes");
            assert_eq!(miss_bytes, 0, "the selector-miss path wrote {miss_bytes} bytes");
            auth_floor = auth_floor.min(auth_took);
            miss_floor = miss_floor.min(miss_took);
        }

        // Same code path, so the budgets are equal by construction; the
        // assertion is that nobody has since given one of them its own timing.
        let skew = auth_floor.abs_diff(miss_floor);
        assert!(
            skew < std::time::Duration::from_millis(60),
            "the two disposal paths differ by {skew:?} at their floors              (auth {auth_floor:?}, miss {miss_floor:?}) — a prober can tell them apart"
        );
    }

    /// The first disposal of a cause must always escalate to `warn!` — there
    /// is nothing to suppress yet, so `suppressed_since_last` on that first
    /// line must read `0`.
    #[test]
    fn rate_gate_first_disposal_of_a_cause_always_warns() {
        let gate = RateGate::new();
        assert_eq!(
            gate.record(1_000, 60_000),
            Some(0),
            "the first disposal of a cause must warn with nothing suppressed yet"
        );
    }

    /// A second disposal of the same cause inside the window must NOT
    /// escalate — and must still be counted, so the next `warn!` that does
    /// fire can report how many were swallowed.
    #[test]
    fn rate_gate_suppresses_and_counts_within_the_window() {
        let gate = RateGate::new();
        assert_eq!(gate.record(1_000, 60_000), Some(0), "first disposal warns");
        assert_eq!(
            gate.record(1_500, 60_000),
            None,
            "a disposal inside the window must not warn"
        );
        assert_eq!(
            gate.record(30_000, 60_000),
            None,
            "still inside the window"
        );
        assert_eq!(
            gate.suppressed.load(Ordering::Relaxed),
            2,
            "both suppressed disposals must be counted toward the next warn's total"
        );
    }

    /// Once the window elapses, the next disposal escalates again and its
    /// `warn!` must carry exactly how many were suppressed since the last
    /// one — then the count must reset for the next window.
    #[test]
    fn rate_gate_warns_again_after_the_window_and_carries_the_suppressed_count() {
        let gate = RateGate::new();
        assert_eq!(gate.record(1_000, 60_000), Some(0), "first disposal warns");
        assert_eq!(gate.record(2_000, 60_000), None, "suppressed #1");
        assert_eq!(gate.record(3_000, 60_000), None, "suppressed #2");
        assert_eq!(
            gate.record(61_000, 60_000),
            Some(2),
            "once the window elapses, the next warn must carry how many were \
             suppressed since the last one"
        );
        assert_eq!(
            gate.suppressed.load(Ordering::Relaxed),
            0,
            "the suppressed count must reset once a warn fires"
        );
    }

    /// `total` counts every disposal regardless of the gate — the metrics
    /// surface must see the real volume even while `warn!` is throttled.
    #[test]
    fn rate_gate_total_counts_every_disposal_regardless_of_the_gate() {
        let gate = RateGate::new();
        gate.record(1_000, 60_000);
        gate.record(1_500, 60_000);
        gate.record(2_000, 60_000);
        assert_eq!(
            gate.total.load(Ordering::Relaxed),
            3,
            "total must count every disposal, gated or not"
        );
    }

    /// `chain_splice_disposal_counts` must report both causes by label, for
    /// the metrics surface to poll.
    #[test]
    fn chain_splice_disposal_counts_reports_both_causes() {
        let counts = chain_splice_disposal_counts();
        let labels: Vec<&str> = counts.iter().map(|(label, _)| label.as_str()).collect();
        assert!(labels.contains(&"not-authenticated"), "missing not-authenticated: {labels:?}");
        assert!(labels.contains(&"no-such-listener"), "missing no-such-listener: {labels:?}");
    }

    #[tokio::test]
    async fn disposal_stops_early_when_the_peer_leaves() {
        // Holding is for the prober's benefit, not the node's: once the peer
        // is gone there is nobody left to tell nothing to, and continuing to
        // hold would spend a task per abandoned scan.
        let (node_side, client_side) = tokio::io::duplex(1024);
        drop(client_side);
        let started = std::time::Instant::now();
        dispose_unaddressable(node_side, 30_000).await;
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a departed peer must end the hold immediately, not wait out the budget"
        );
    }
}
#[cfg(test)]
mod selector_hash_join_tests {
    use super::*;
    use crate::core::registry::selector::ChainSelector;

    /// The hop prints this digest beside the cause it chose; the CLIENT prints
    /// the same one beside its bare timeout, because the hop deliberately
    /// answers nothing — a selector miss and a refused credential must stay
    /// indistinguishable to whoever is probing. The join is how an operator
    /// still gets the cause without the peer getting it too, and it only works
    /// while both sides spell the digest identically.
    ///
    /// `mirage-control-plane`'s `selector_digest` pins this same vector. If
    /// either drifts, one of the two tests fails instead of the diagnosis
    /// quietly disappearing while both sides still look right alone.
    #[test]
    fn the_join_digest_matches_the_client_side_spelling() {
        let selector = ChainSelector::from_chain_position(b"auto-deadbeef", 1);
        assert_eq!(selector.as_bytes(), b"auto-deadbeef-h1");
        assert_eq!(selector_hash(&selector), "40cb86a3");
    }
}
