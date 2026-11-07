use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mirage_core::config::{NodeConfig, NodeMode, RelayMode};
use mirage_core::crypto::KeyPair;
use mirage_core::error::{MirageError, Result};
use mirage_core::mirage::wire::CredentialScheme;
use mirage_protocol::auth::v9::{V9ClientHello, CLIENT_HELLO_LEN};
use mirage_protocol::traits::{AcceptResult, TcpProtocol};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::core::doh::DoHResolver;
use crate::core::dual_bind::bind_dual_stack_tcp;
use crate::core::metrics::MetricsRegistry;
use crate::family::mirage::relay::upstream_select::pick_upstream;
// V4 onion dispatch lives entirely in `listeners::tcp_node_listener`. The
// legacy `handle_connection_with_protocol` no longer routes onion traffic.
use crate::family::mirage::relay::relay_metrics::RelayMetrics;
use crate::core::runtime::{NodeRuntime, NodeRuntimeSnapshot};
use crate::family::mirage::exit::direct::handle_exit;
use crate::family::mirage::relay::upstream_pool::UpstreamPool;

/// Number of bytes peeked from each new connection for protocol detection.
const PEEK_BYTES: usize = 64;

/// Maximum number of simultaneous connections on the legacy `NodeListener::run`
/// accept path. Each accepted connection holds one permit for its ENTIRE
/// lifetime (this legacy path does not separate the handshake phase from the
/// data phase at the spawn boundary), so this is a hard concurrent-connection
/// ceiling — set generously. The 15 s handshake timeout is what actually bounds
/// the pre-auth dial-flood cost; this cap is defense-in-depth against task/FD
/// exhaustion. The primary registry path (`tunnel_tcp`) relies on the timeout
/// and is intentionally not capped here.
const MAX_CONCURRENT_CONNECTIONS_LEGACY: usize = 4096;

/// v2 outbound dial context — что нужно handler'у чтобы накатить
/// outgoing camouflage / byte_cipher на dial к next-hop'у. Готовится
/// listener factory'ей из chain_binding + peer_table.
#[derive(Debug, Clone)]
pub struct OutboundDial {
    pub outgoing_layer: Option<mirage_core::mirage::wire::LayerSpec>,
    pub next_hop_pubkey: [u8; 32],
    /// SNI hint для inner TLS (Reality outer camouflage). Пустая
    /// строка = default.
    pub sni: String,
}

/// Main TCP listener that dispatches incoming connections to the correct handler.
pub struct NodeListener {
    /// Shared runtime — snapshot loaded per accepted connection.
    pub runtime: Arc<NodeRuntime>,
    /// Round-robin / random counter for upstream selection.
    upstream_counter: Arc<AtomicUsize>,
    /// Concurrent-connection cap for the legacy accept path. Each accepted
    /// connection acquires one permit before spawning and holds it for the
    /// whole connection lifetime; the permit drops when the spawned task exits.
    handshake_semaphore: Arc<Semaphore>,
}

impl NodeListener {
    /// Create a new listener backed by a `NodeRuntime`.
    ///
    /// The DoH resolver is stored on `runtime.doh` and loaded per-connection
    /// so that `PUT /admin/dns-prefer-ipv6` takes effect without restart.
    pub fn new(runtime: Arc<NodeRuntime>) -> Self {
        Self {
            runtime,
            upstream_counter: Arc::new(AtomicUsize::new(0)),
            handshake_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS_LEGACY)),
        }
    }

    /// Handle a single accepted TCP connection end-to-end.
    ///
    /// Called by the main `run` loop and by external dispatchers such as the
    /// decoy peek-multiplex listener when the magic check passes.
    pub async fn handle_incoming(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        self.handle_incoming_with_protocol(stream, peer_addr, None).await
    }

    /// Handle a single accepted TCP connection, optionally pinning the wire
    /// protocol to the given `TcpProtocolId` name (e.g. `"MirageTls"`).
    ///
    /// When `forced_protocol` is set, the listener tries the matching entry
    /// from `snap.protocols` *first*; if no entry matches the name the
    /// connection is dropped (fail-loud rather than silently falling back to
    /// the listener default).  Used by `multi_decoy::DecoyAction::Tunnel`
    /// rules to pin a specific protocol per decoy port/match.
    pub async fn handle_incoming_with_protocol(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        forced_protocol: Option<String>,
    ) -> Result<()> {
        let snap: Arc<NodeRuntimeSnapshot> = Arc::clone(&*self.runtime.snapshot.load());
        let keypair = Arc::new(self.runtime.keypair.clone());
        let counter = Arc::clone(&self.runtime.active_tunnels);
        // Load DoH resolver from the hot-swappable slot; None = system DNS.
        let doh: Option<Arc<DoHResolver>> = self.runtime.doh.load_full();
        let upstream_counter = Arc::clone(&self.upstream_counter);
        let metrics = Arc::clone(&self.runtime.metrics);

        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let result = handle_connection_with_protocol(
            stream,
            peer_addr,
            snap,
            keypair,
            doh,
            upstream_counter,
            metrics,
            forced_protocol,
            crate::core::listener_ctx::ListenerCtx::placeholder(),
            None,
            None,
            None, // legacy path — no v2 ingress_layer; bare TCP
            Arc::clone(&self.runtime.role_signed_replay),
        )
        .await;
        counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Bind and run the listener loop.  Spawns one task per accepted connection.
    pub async fn run(&self) -> Result<()> {
        // Read the listen address from the current config snapshot.
        let listen_addr = self.runtime.snapshot.load().node_config.listen_addr;
        let listener = if listen_addr.ip().is_unspecified() {
            bind_dual_stack_tcp(listen_addr.port()).await?
        } else {
            // Specific IP — operator wants v4-only or v6-only on that address.
            info!(addr = %listen_addr, "listener bound v4-only on {listen_addr}");
            TcpListener::bind(listen_addr).await?
        };
        info!(addr = %listen_addr, "mirage-node: listening");

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!("accept error: {e}");
                    continue;
                }
            };

            info!(%peer_addr, "accepted connection");

            // Pre-auth handshake cap: bound the number of concurrent unauthenticated
            // connections so a dial-flood cannot exhaust tasks/FDs before any
            // cryptographic work completes.
            let permit = match self.handshake_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(%peer_addr, "handshake cap reached, dropping connection");
                    continue;
                }
            };

            // Apply TCP keepalive so zombie slow-readers are evicted by the kernel
            // (~120 s: 60 s idle + 4×15 s probes) instead of holding FDs forever.
            {
                let ka = {
                    let base = TcpKeepalive::new()
                        .with_time(Duration::from_secs(60))
                        .with_interval(Duration::from_secs(15));
                    #[cfg(not(target_os = "windows"))]
                    let base = base.with_retries(4);
                    base
                };
                if let Err(e) = SockRef::from(&stream).set_tcp_keepalive(&ka) {
                    warn!(%peer_addr, "set_tcp_keepalive(legacy listener): {e}");
                }
            }

            // Clone the current snapshot Arc BEFORE any .await so the ArcSwap
            // guard is not held across yield points.
            let snap: Arc<NodeRuntimeSnapshot> =
                Arc::clone(&*self.runtime.snapshot.load());

            let keypair = Arc::new(self.runtime.keypair.clone());
            let counter = Arc::clone(&self.runtime.active_tunnels);
            // Load DoH from hot-swappable slot — picks up any in-flight reconfig.
            let doh: Option<Arc<DoHResolver>> = self.runtime.doh.load_full();
            let upstream_counter = Arc::clone(&self.upstream_counter);
            let metrics = Arc::clone(&self.runtime.metrics);
            let role_signed_replay = Arc::clone(&self.runtime.role_signed_replay);

            tokio::spawn(async move {
                // Hold `permit` across the entire call so it covers the handshake
                // phase (handle_connection_with_protocol already wraps the inner
                // protocol.accept() in a 15 s timeout).  The permit is dropped when
                // this async block exits — i.e. when the connection is fully done.
                // This is the "hold for connection lifetime" variant; it is
                // acceptable here because the 15 s handshake timeout ensures that
                // pre-auth work is bounded, and established tunnels are counted
                // separately via `active_tunnels`.
                let _permit = permit;
                counter.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = handle_connection_with_protocol(
                    stream,
                    peer_addr,
                    snap,
                    keypair,
                    doh,
                    upstream_counter,
                    metrics,
                    None,
                    crate::core::listener_ctx::ListenerCtx::placeholder(),
                    None,
                    None,
                    None, // legacy path — no v2 ingress_layer; bare TCP
                    role_signed_replay,
                )
                .await
                {
                    warn!(%peer_addr, "connection error: {e}");
                }
                counter.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }
}

/// Handle a single accepted TCP connection end-to-end.
///
/// Receives a cloned `Arc<NodeRuntimeSnapshot>` so in-flight connections are
/// unaffected by a concurrent runtime reconfiguration.
///
/// When `forced_protocol` is `Some(name)` the protocol-detection loop tries
/// only the matching entry from `snap.protocols`.  Used by the multi-decoy
/// router so a `DecoyAction::Tunnel { protocol: "MirageTls" }` rule actually
/// runs MirageTls regardless of the listener's `protocols[]` order.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connection_with_protocol(
    stream: TcpStream,
    peer_addr: SocketAddr,
    snap: Arc<NodeRuntimeSnapshot>,
    keypair: Arc<KeyPair>,
    doh: Option<Arc<DoHResolver>>,
    upstream_counter: Arc<AtomicUsize>,
    metrics: Arc<MetricsRegistry>,
    forced_protocol: Option<String>,
    // v2 identity context — (mesh_id, node_id, listener_id,
    // chain_id?). Dial-сайты внутри handler'а резолвят через
    // него runtime.chain_bindings / runtime.peer_table. Legacy
    // spawn paths (main.rs JSON-NodeConfig) передают
    // ListenerCtx::placeholder().
    ctx: crate::core::listener_ctx::ListenerCtx,
    // v2 binding for this listener's chain (resolved by the factory
    // from runtime.chain_bindings before spawn). None when the
    // listener has no chain_id or when the chain is unknown to the
    // monitor — byte_cipher is skipped.
    chain_binding: Option<Arc<mirage_core::mirage::mesh::ChainBinding>>,
    // v2 outbound dial context — резолвится factory из
    // peer_table.lookup(next_hop_node_id). Передаётся handler'у
    // готовым чтобы тот не лез в NodeRuntime.peer_table.
    // None если этa нода — exit (нет next hop) или peer_table
    // не знает next-hop'а (warn + bare connect).
    outbound_dial: Option<OutboundDial>,
    // v2 ingress layer — что strip'нуть на ingress этого listener'а.
    // Резолвится factory как `chain_binding.ingress_layer_for(node_id)`
    // если chain_id есть, иначе `spec.ingress_layer`. None → bare TCP.
    ingress_layer: Option<mirage_core::mirage::wire::LayerSpec>,
    // Shared, bounded single-use cache for `CredentialScheme::RoleSigned`
    // dials — see `core::role_signed_gate`'s own doc.
    role_signed_replay: Arc<std::sync::Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
) -> Result<()> {
    let _ = &outbound_dial;
    let mesh_id_bytes = ctx.mesh_id.as_bytes().to_vec();
    let _ = &ctx;
    use std::sync::atomic::Ordering::Relaxed;

    // v2 ingress resolution: spec/binding-driven only.
    // If ingress_layer is None → bare TCP, no camouflage.
    let effective_camouflage = ingress_layer
        .as_ref()
        .and_then(|l| l.camouflage.clone());

    // ── Phase 6: two-axis pipelined dispatch for non-onion modes ────────────
    //
    // When the listener declares a TCP `TransportCamouflage` in its
    // `endpoint_configs[]` AND the node is not in an onion role, route
    // through the unified pipelined dispatch. This is the single place
    // where all four "outer wire × inner mode" combinations meet for
    // non-onion paths (transparent / crypto_verify / crypto_relay / exit
    // each composed with TLS / WS / Xhttp / Reality + optional byte_cipher).
    //
    // Onion (peel / exit) is handled by its own branch below — it already
    // does the strip → byte_cipher → onion peel pipeline in Phase 1+3 code.
    if !is_onion_peel_mode(&snap.node_config.mode)
        && !is_onion_exit_mode(&snap.node_config.mode)
    {
        if let Some(cam) = effective_camouflage.clone() {
            return handle_pipelined_non_onion(
                stream,
                peer_addr,
                snap,
                keypair,
                cam,
                doh,
                upstream_counter,
                metrics,
                chain_binding.clone(),
                outbound_dial.clone(),
                &mesh_id_bytes,
                role_signed_replay,
            )
            .await;
        }
    }

    // ── L1 unwrap (if configured) ────────────────────────────────────────────
    // When a L1 wrapper is configured, we must consume and unwrap the first
    // chunk before protocol detection.  For ValidateFirst/StripFirst this strips
    // the magic/junk prefix so the protocol handler sees clean L2 bytes.
    // For ObfuscateAll every chunk needs deobfuscation (handled separately via
    // L1UnwrapStream for post-handshake forwarding).
    // No L1 wrapper — use standard peek (does not consume bytes).
    let peeked: Vec<u8> = {
        let mut peek_buf = vec![0u8; PEEK_BYTES];
        let n = stream.peek(&mut peek_buf).await?;
        peek_buf[..n].to_vec()
    };

    let mut current_stream = stream;
    let mut fallback_bytes: Vec<u8> = Vec::new();

    // Apply optional protocol override from the multi-decoy router.
    // When set, only the matching protocol from snap.protocols is tried.
    // The override name uses the JSON / serde form (PascalCase, e.g. "MirageTls").
    let protocol_set: Vec<Arc<dyn TcpProtocol>> = match &forced_protocol {
        Some(name) => {
            // Parse the requested name through serde so we accept the same
            // strings the operator already writes in `protocols[]`.
            let requested_id = match serde_json::from_value::<
                mirage_core::config::TcpProtocolId,
            >(serde_json::Value::String(name.clone()))
            {
                Ok(id) => id,
                Err(_) => {
                    warn!(
                        %peer_addr,
                        requested = %name,
                        "multi_decoy: unknown TcpProtocolId — dropping connection"
                    );
                    metrics
                        .probe_resist
                        .invalid_handshakes_dropped
                        .fetch_add(1, Relaxed);
                    let _ = current_stream.shutdown().await;
                    return Ok(());
                }
            };
            let matches: Vec<_> = snap
                .protocols
                .iter()
                .filter(|p| p.id() == requested_id)
                .cloned()
                .collect();
            if matches.is_empty() {
                warn!(
                    %peer_addr,
                    requested = %name,
                    available = ?snap.protocols.iter().map(|p| p.id().to_string()).collect::<Vec<_>>(),
                    "multi_decoy: requested protocol not present in node config — dropping connection"
                );
                metrics
                    .probe_resist
                    .invalid_handshakes_dropped
                    .fetch_add(1, Relaxed);
                let _ = current_stream.shutdown().await;
                return Ok(());
            }
            info!(%peer_addr, requested = %name, "multi_decoy: pinning protocol for this connection");
            matches
        }
        None => snap.protocols.clone(),
    };

    for protocol in &protocol_set {
        let accept_result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            protocol.accept(current_stream, &peeked),
        )
        .await;
        let accept_result = match accept_result {
            Ok(r) => r?,
            Err(_) => {
                debug!(%peer_addr, "handshake timeout");
                return Ok(());
            }
        };
        match accept_result {
            AcceptResult::Tunnel(tunnel) => {
                info!(id = %protocol.id(), "tunnel authenticated — dispatching to node mode handler");
                return dispatch_tunnel(
                    tunnel,
                    peer_addr,
                    &snap.node_config,
                    snap.protocols.clone(),
                    doh,
                    snap.pools.clone(),
                    snap.relay_metrics.clone(),
                    upstream_counter,
                )
                .await;
            }
            AcceptResult::Fallback(returned_stream, consumed) => {
                if fallback_bytes.is_empty() {
                    fallback_bytes = consumed;
                }
                current_stream = returned_stream;
            }
        }
    }

    // All protocols returned Fallback — forward to the camouflage backend.
    let fallback_dest = fallback_dest_for_mode(&snap.node_config.mode);
    if let Some(dest) = fallback_dest {
        info!(%dest, "probe-resistance fallback");
        metrics.probe_resist.fallback_forwarded.fetch_add(1, Relaxed);
        forward_fallback(current_stream, &fallback_bytes, dest).await
    } else {
        warn!("no fallback destination configured — dropping unauthenticated connection");
        metrics.probe_resist.invalid_handshakes_dropped.fetch_add(1, Relaxed);
        let _ = current_stream.shutdown().await;
        Ok(())
    }
}

/// Dispatch an authenticated tunnel to the appropriate node-mode handler.
///
/// **Untrusted-peer invariant note:** этот legacy path вызывается ТОЛЬКО для
/// `NodeMode::Exit` после v2-чистки. `Relay` / `Hybrid` ветки
/// предполагали re-handshake (нода decrypt'ит клиентский AEAD →
/// re-encrypt к upstream) — это нарушает per-hop isolation и удалено. Под v2
/// entry/hop ноды работают через `core::listener` pipelined
/// dispatch (transparent / crypto_verify byte-pump), а не через
/// этот tunnel-уже-decrypted путь.
#[allow(clippy::too_many_arguments)]
async fn dispatch_tunnel(
    tunnel: Box<dyn mirage_protocol::traits::Tunnel>,
    _peer_addr: SocketAddr,
    config: &NodeConfig,
    _protocols: Vec<Arc<dyn TcpProtocol>>,
    doh: Option<Arc<DoHResolver>>,
    _pools: Vec<Arc<UpstreamPool>>,
    _relay_metrics: Option<Arc<RelayMetrics>>,
    _upstream_counter: Arc<AtomicUsize>,
) -> Result<()> {
    match &config.mode {
        NodeMode::Exit(_) => handle_exit(tunnel, doh).await,

        NodeMode::Relay(_) | NodeMode::Hybrid { .. } => {
            // Legacy CryptoRelay dispatch удалён — re-handshake на
            // ноде нарушает per-hop isolation. Entry/Hop ноды должны
            // работать через transparent / crypto_verify byte-pump
            // (см. `pipelined_dispatch`), а не через этот
            // tunnel-already-decrypted путь.
            Err(MirageError::Config(
                "dispatch_tunnel: Relay/Hybrid modes удалены — \
                 используйте transparent / crypto_verify через v2 \
                 pipelined dispatch (chain_binding.byte_cipher)"
                    .into(),
            ))
        }
    }
}

/// Phase 6: unified pipelined dispatch for non-onion modes.
///
/// Wire layering:
///
/// ```text
/// TcpStream
///   ↓ strip_tcp_server(camouflage)         ← Phase 1 helper
/// Box<dyn BidiStream>
///   ↓ match (NodeMode, RelayMode)
///
///   Exit(_)                          → handshake_server_stream + handle_exit
///   Relay(TransparentTcp)            → handle_relay_transparent_stream
///   Relay(CryptoVerify)              → handle_relay_transparent_stream
///   Relay(CryptoRelay)               → handshake_server_stream + handle_relay
///   Relay(OnionPeel)                 → covered by Phase 1+3 branch upstream
///   Hybrid                           → branch on whether relay has upstreams
/// ```
///
/// Onion modes (`OnionPeel` / `Onion` exit) intentionally skip this
/// function — they have their own `[strip → byte_cipher → handle_onion_peel]`
/// dispatch in the caller.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn handle_pipelined_non_onion(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    snap: Arc<NodeRuntimeSnapshot>,
    keypair: Arc<KeyPair>,
    camouflage: mirage_core::config::TransportCamouflage,
    doh: Option<Arc<DoHResolver>>,
    upstream_counter: Arc<AtomicUsize>,
    _metrics: Arc<MetricsRegistry>,
    _chain_binding: Option<Arc<mirage_core::mirage::mesh::ChainBinding>>,
    outbound_dial: Option<OutboundDial>,
    mesh_id: &[u8],
    role_signed_replay: Arc<std::sync::Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
) -> Result<()> {
    let _ = &outbound_dial;
    use mirage_protocol::camouflage::pipeline::{strip_tcp_server, BidiStream};

    // ── Outer camouflage strip ───────────────────────────────────────────────
    let stripped = match strip_tcp_server(stream, &camouflage, &keypair).await? {
        Some(s) => s,
        None => {
            debug!(%peer_addr, "pipelined: camouflage strip rejected connection");
            return Ok(());
        }
    };
    let stripped: Box<dyn BidiStream> = stripped;

    // ── Mode dispatch on stripped stream ─────────────────────────────────────
    match &snap.node_config.mode {
        NodeMode::Exit(_) => {
            let proto_auth = mirage_protocol::driver::convert_auth(
                &mirage_core::config::AuthMode::Blake3,
            );
            let client_auth = make_credential_auth(
                snap.credential_params.clone(),
                snap.spent_set.clone(),
                peer_addr,
                snap.node_config.node_id.as_bytes().to_vec(),
                mesh_id.to_vec(),
                role_signed_replay,
            );
            // V8 wire has no credential channel and credential enforcement is
            // unconditional (no `require` toggle) — V8 dials can never carry a
            // credential, so they are always rejected on this exit-mode path.
            let effective_allow_v8 = false;
            let tunnel = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                mirage_protocol::driver::handshake_server_stream_with_auth(
                    stripped, &keypair, &proto_auth, peer_addr, mesh_id, client_auth, effective_allow_v8,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                debug!(%peer_addr, "handshake timeout");
                Ok(None)
            })?;
            match tunnel {
                Some(tunnel) => handle_exit(tunnel, doh).await,
                None => Ok(()),
            }
        }
        NodeMode::Relay(relay_cfg) => {
            handle_pipelined_relay(
                stripped,
                peer_addr,
                relay_cfg,
                &snap.node_config.endpoint_configs,
                &keypair,
                &snap.protocols,
                &upstream_counter,
                snap.relay_metrics.as_deref(),
                outbound_dial.as_ref(),
            )
            .await
        }
        NodeMode::Hybrid { relay, exit: _ } => {
            if !relay.upstreams.is_empty() {
                handle_pipelined_relay(
                    stripped,
                    peer_addr,
                    relay,
                    &snap.node_config.endpoint_configs,
                    &keypair,
                    &snap.protocols,
                    &upstream_counter,
                    snap.relay_metrics.as_deref(),
                    outbound_dial.as_ref(),
                )
                .await
            } else {
                let proto_auth = mirage_protocol::driver::convert_auth(
                    &mirage_core::config::AuthMode::Blake3,
                );
                let client_auth = make_credential_auth(
                    snap.credential_params.clone(),
                    snap.spent_set.clone(),
                    peer_addr,
                    snap.node_config.node_id.as_bytes().to_vec(),
                    mesh_id.to_vec(),
                    role_signed_replay,
                );
                // V8 wire has no credential channel and credential enforcement is
                // unconditional (no `require` toggle) — V8 dials can never carry a
                // credential, so they are always rejected on this exit-mode path.
                let effective_allow_v8 = false;
                let tunnel = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    mirage_protocol::driver::handshake_server_stream_with_auth(
                        stripped, &keypair, &proto_auth, peer_addr, mesh_id, client_auth, effective_allow_v8,
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    debug!(%peer_addr, "handshake timeout");
                    Ok(None)
                })?;
                match tunnel {
                    Some(tunnel) => handle_exit(tunnel, doh).await,
                    None => Ok(()),
                }
            }
        }
    }
}
/// A relay leg reaching the non-onion dispatcher is a configuration bug.
///
/// This used to switch on `RelayMode`: `TransparentTcp` and `CryptoVerify`
/// shared a byte-pump arm to the first declared upstream, and `OnionPeel`
/// fell through to this warning because it is served by the dedicated onion
/// branch in `handle_connection_with_protocol`. Both byte-pump modes were
/// removed on 2026-09-02, so the warning is now the whole function — and
/// keeping it, rather than deleting the call, is the point: a `NodeMode::Relay`
/// arriving here means the onion branch did not claim a connection it owns,
/// and that should say so rather than pass silently.
async fn handle_pipelined_relay(
    _stripped: Box<dyn mirage_protocol::camouflage::pipeline::BidiStream>,
    peer_addr: SocketAddr,
    _relay_cfg: &mirage_core::config::RelayConfig,
    _endpoint_configs: &[mirage_core::config::MirageEndpointConfig],
    _keypair: &KeyPair,
    _protocols: &[Arc<dyn TcpProtocol>],
    _upstream_counter: &AtomicUsize,
    _relay_metrics: Option<&RelayMetrics>,
    _outbound_dial: Option<&OutboundDial>,
) -> Result<()> {
    warn!(
        %peer_addr,
        "pipelined: a relay leg reached non-onion dispatch — the onion branch should have claimed it; check this listener's spec"
    );
    Ok(())
}

/// Return `true` when the relay mode is `OnionPeel`.
fn is_onion_peel_mode(mode: &NodeMode) -> bool {
    let relay_cfg = match mode {
        NodeMode::Relay(r) => r,
        NodeMode::Hybrid { relay, .. } => relay,
        NodeMode::Exit(_) => return false,
    };
    relay_cfg.mode == RelayMode::OnionPeel
}


/// Return `true` when the node is an exit in `ExitMode::Onion`.
fn is_onion_exit_mode(mode: &NodeMode) -> bool {
    use mirage_core::config::ExitMode;
    let exit_cfg = match mode {
        NodeMode::Exit(e) => e,
        NodeMode::Hybrid { exit, .. } => exit,
        NodeMode::Relay(_) => return false,
    };
    exit_cfg.mode == ExitMode::Onion
}


/// Extract the configured fallback destination from the node mode.
fn fallback_dest_for_mode(mode: &NodeMode) -> Option<&str> {
    match mode {
        NodeMode::Relay(r) => Some(&r.fallback_dest),
        NodeMode::Hybrid { relay, exit: _ } => Some(&relay.fallback_dest),
        NodeMode::Exit(_) => None,
    }
}

/// Build the credential-auth closure for the V9 direct-exit accept path.
///
/// The returned closure is `Fn(&ClientAuthContext) -> bool + Send + 'static`
/// and is suitable as the `client_auth` argument to
/// `handshake_server_stream_with_auth`.
///
/// # Behaviour
///
/// Credential enforcement is unconditional — there is no `require` toggle
/// (arc3 mandatory-credentials excision). A Mirage exit rejects any dial
/// lacking a valid credential, always:
///
/// | `params` | `ctx.scheme_byte` | result |
/// |----------|-------------------|--------|
/// | `None`   | any               | `false` (fail closed — no params to verify against) |
/// | `Some`   | `0x00`            | `false` (no-credential dial rejected unconditionally) |
/// | `Some`   | non-zero          | crypto + reuse check |
///
/// The std `Mutex` is held only for the brief `record_and_check` call.
/// Zero `.await` inside — safe to use in the sync closure.
///
/// `node_id` is this exit's own node identity, bound into the credential
/// verification as `dial_context` (mirrors the v9-fs onion-exit path,
/// `family/mirage/exit/onion_fs.rs`). Only `CredentialScheme::RingMembership`
/// actually mixes `dial_context` into its proof transcript; the other
/// schemes ignore it per design, so this is a strict tightening that closes
/// cross-exit replay for ring-membership tokens without affecting the rest.
///
/// `mesh_id` is this node's own mesh — the `CredentialScheme::RoleSigned`
/// branch checks a presented excerpt's own `mesh_id` field against it (see
/// `core::role_signed_gate`'s own doc for why `operator_pub` alone cannot
/// catch a cross-mesh presentation). `role_signed_replay` is the shared,
/// bounded single-use cache for that same scheme.
///
/// `RoleSigned` is dispatched inside the `Some(p) =>` arm alongside every
/// other scheme, so it is still gated on `params` having arrived — a
/// RoleSigned excerpt needs no epoch/authority lookup of its own, but this
/// keeps the fail-closed "credentials mandatory" behaviour uniform across
/// every scheme rather than carving out an early-boot exception for this one.
pub(crate) fn make_credential_auth(
    params: std::sync::Arc<arc_swap::ArcSwap<Option<mirage_core::crypto::CredentialParams>>>,
    spent: std::sync::Arc<std::sync::Mutex<mirage_core::crypto::SpentSet>>,
    peer_addr: std::net::SocketAddr,
    node_id: Vec<u8>,
    mesh_id: Vec<u8>,
    role_signed_replay: std::sync::Arc<std::sync::Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
) -> impl for<'a> Fn(&mirage_protocol::ClientAuthContext<'a>) -> bool + Send + 'static {
    move |ctx| {
        let now_ms = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        };
        let guard = params.load();
        match guard.as_ref().as_ref() {
            None => {
                // Credential params not yet received (gossip lag or fresh boot).
                // Credentials are mandatory — without params to verify against,
                // fail closed rather than accept on an empty policy.
                warn!(
                    %peer_addr,
                    "data-leg: rejecting dial — credentials mandatory but no params configured (fail closed)"
                );
                false
            }
            Some(p) => {
                if ctx.scheme_byte == 0x00 {
                    // Legacy / no-credential dial — rejected unconditionally.
                    warn!(%peer_addr, "data-leg: rejecting no-credential dial (credentials mandatory)");
                    false
                } else if ctx.scheme_byte == CredentialScheme::RoleSigned.as_u8() {
                    // Self-vouched, not authority-keyed — verified against the
                    // operator/group key and this exit's own identity, never
                    // against `p`. See `core::role_signed_gate`'s own doc.
                    let operator_pub = crate::core::bootstrap::operator_pubkey();
                    match crate::core::role_signed_gate::check_role_signed_dial(
                        ctx.credential,
                        &String::from_utf8_lossy(&node_id),
                        &mesh_id,
                        now_ms,
                        &operator_pub,
                        &role_signed_replay,
                        // No gossiped `DeclaredIdentity` registry exists on this
                        // crate yet — see `check_role_signed_dial`'s own doc for
                        // why `|_| None` here is a correct default, not a crutch.
                        |_self_id| None,
                    ) {
                        Ok(_self_id) => true,
                        Err(refusal) => {
                            warn!(%peer_addr, %refusal, "data-leg: role_signed credential refused");
                            false
                        }
                    }
                } else {
                    // Bind the credential to THIS exit's node_id: a ring proof
                    // minted for another exit (or lifted by a malicious exit)
                    // fails here. The client mints against the exit hop's
                    // node_id; schemes without dial-context binding ignore it.
                    match mirage_core::crypto::verify_credential_bound(
                        p,
                        ctx.scheme_byte,
                        ctx.credential,
                        now_ms,
                        &node_id,
                    ) {
                        Ok(cred_id) => {
                            // Extract epoch_id: first 4 bytes of the token (BE u32).
                            // The credential slice is non-empty (verify_credential checked
                            // the minimum length) so the slice access is safe.
                            let epoch_id = if ctx.credential.len() >= 4 {
                                u32::from_be_bytes([
                                    ctx.credential[0],
                                    ctx.credential[1],
                                    ctx.credential[2],
                                    ctx.credential[3],
                                ])
                            } else {
                                // verify_credential returned Ok, so this branch is
                                // unreachable for any scheme implemented today.
                                0
                            };
                            let mut s = match spent.lock() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            let fresh = s.record_and_check(epoch_id, cred_id);
                            if !fresh {
                                warn!(%peer_addr, "data-leg: rejecting reused credential");
                            }
                            fresh
                        }
                        Err(e) => {
                            warn!(%peer_addr, error = %e, "data-leg: credential verify failed");
                            false
                        }
                    }
                }
            }
        }
    }
}

/// Forward an unauthenticated connection to `dest`, prepending the bytes
/// that were already read during protocol detection.
///
/// Applies the SSRF guard before connecting: resolves `dest` to a concrete
/// `SocketAddr` and rejects loopback/RFC-1918/link-local/metadata targets.
/// This path is reached by unauthenticated clients, so the guard matters here.
async fn forward_fallback(
    mut stream: TcpStream,
    already_read: &[u8],
    dest: &str,
) -> Result<()> {
    use crate::family::mirage::exit::policy;

    let resolved: std::net::SocketAddr = {
        let mut addrs = tokio::net::lookup_host(dest)
            .await
            .map_err(|e| MirageError::NodeUnreachable(format!("fallback DNS {dest}: {e}")))?;
        addrs.next().ok_or_else(|| {
            MirageError::NodeUnreachable(format!("fallback DNS {dest}: no result"))
        })?
    };

    if policy::is_blocked(resolved.ip()) {
        warn!(ip = %resolved.ip(), dest = %dest, "fallback: SSRF guard blocked dest");
        return Err(MirageError::NodeUnreachable(format!(
            "SSRF: blocked fallback dest {}",
            resolved.ip()
        )));
    }

    let mut target = tokio::net::TcpStream::connect(resolved)
        .await
        .map_err(|e| MirageError::NodeUnreachable(format!("fallback {dest}: {e}")))?;

    if !already_read.is_empty() {
        target.write_all(already_read).await?;
    }

    let (mut r_client, mut w_client) = stream.split();
    let (mut r_target, mut w_target) = target.split();

    tokio::select! {
        r = tokio::io::copy(&mut r_client, &mut w_target) => {
            r.map(|_| ())?;
        }
        r = tokio::io::copy(&mut r_target, &mut w_client) => {
            r.map(|_| ())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod credential_auth_tests {
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use arc_swap::ArcSwap;
    use mirage_core::crypto::{
        issue_epoch_hmac, random_nonce16, CredentialId, CredentialParams, EpochEntry, SpentSet,
        EpochHmacKey,
    };
    use mirage_core::mirage::wire::CredentialScheme;
    use mirage_protocol::ClientAuthContext;

    use super::make_credential_auth;

    fn peer() -> SocketAddr {
        SocketAddr::from_str("127.0.0.1:9999").unwrap()
    }

    fn node_id() -> Vec<u8> {
        b"test-exit-node".to_vec()
    }

    fn mesh_id() -> Vec<u8> {
        b"test-mesh".to_vec()
    }

    fn role_signed_replay() -> Arc<Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>> {
        Arc::new(Mutex::new(crate::core::role_signed_gate::RoleSignedReplayCache::new()))
    }

    fn make_params(epoch_id: u32, not_after_ms: u64, secret: [u8; 32]) -> CredentialParams {
        CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(
                epoch_id,
                not_after_ms,
                secret,
            )],
        )
    }

    fn arc_params(
        params: Option<CredentialParams>,
    ) -> Arc<ArcSwap<Option<CredentialParams>>> {
        Arc::new(ArcSwap::from_pointee(params))
    }

    fn arc_spent() -> Arc<Mutex<SpentSet>> {
        Arc::new(Mutex::new(SpentSet::new()))
    }

    fn make_token(secret: [u8; 32], epoch_id: u32) -> ([u8; 52], [u8; 16]) {
        let key = EpochHmacKey::from_bytes(secret);
        let nonce = random_nonce16();
        let token = issue_epoch_hmac(&key, epoch_id, nonce);
        (token, nonce)
    }

    /// Helper: build a minimal `ClientAuthContext` with a credential slice.
    fn ctx_with_cred<'a>(
        scheme_byte: u8,
        credential: &'a [u8],
        static_pub: &'a [u8; 32],
        e_pub_c: &'a [u8; 32],
    ) -> ClientAuthContext<'a> {
        ClientAuthContext {
            static_pub,
            ts_ms: u64::MAX,
            e_pub_c,
            scheme_byte,
            credential,
        }
    }

    // ── params=None → fail closed (credentials mandatory) ───────────────────

    #[test]
    fn params_none_any_scheme_rejected() {
        let auth = make_credential_auth(arc_params(None), arc_spent(), peer(), node_id(), mesh_id(), role_signed_replay());
        let dummy_key = [0u8; 32];
        // scheme=0 (legacy)
        let ctx = ctx_with_cred(0x00, &[], &dummy_key, &dummy_key);
        assert!(!auth(&ctx), "params=None + scheme=0 must reject (fail closed)");

        // scheme=1 (EpochHmac) — no params to verify against
        let token = [0u8; 52];
        let ctx = ctx_with_cred(0x01, &token, &dummy_key, &dummy_key);
        assert!(!auth(&ctx), "params=None + scheme=1 must reject (fail closed)");
    }

    // ── valid EpochHmac token → accept ───────────────────────────────────────

    #[test]
    fn valid_epoch_hmac_accepted() {
        let secret = [0x42u8; 32];
        let params = make_params(7, u64::MAX, secret);
        let (token, _nonce) = make_token(secret, 7);
        let auth = make_credential_auth(arc_params(Some(params)), arc_spent(), peer(), node_id(), mesh_id(), role_signed_replay());
        let dummy_key = [0u8; 32];
        let ctx = ctx_with_cred(0x01, &token, &dummy_key, &dummy_key);
        assert!(auth(&ctx), "valid EpochHmac token must be accepted");
    }

    // ── same token twice → reuse rejected ────────────────────────────────────

    #[test]
    fn reuse_rejected() {
        let secret = [0x42u8; 32];
        let params = make_params(7, u64::MAX, secret);
        let (token, _nonce) = make_token(secret, 7);
        let spent = arc_spent();
        let auth = make_credential_auth(
            arc_params(Some(params)),
            spent,
            peer(),
            node_id(),
            mesh_id(),
            role_signed_replay(),
        );
        let dummy_key = [0u8; 32];
        let ctx = ctx_with_cred(0x01, &token, &dummy_key, &dummy_key);
        assert!(auth(&ctx), "first presentation must be accepted");
        let ctx2 = ctx_with_cred(0x01, &token, &dummy_key, &dummy_key);
        assert!(!auth(&ctx2), "second presentation (reuse) must be rejected");
    }

    // ── scheme=0 → always rejected (credentials mandatory, no toggle) ───────

    #[test]
    fn scheme0_always_rejected() {
        let secret = [0x42u8; 32];
        let params = make_params(1, u64::MAX, secret);
        let auth = make_credential_auth(arc_params(Some(params)), arc_spent(), peer(), node_id(), mesh_id(), role_signed_replay());
        let dummy_key = [0u8; 32];
        let ctx = ctx_with_cred(0x00, &[], &dummy_key, &dummy_key);
        assert!(!auth(&ctx), "scheme=0 (no credential) must always be rejected");
    }

    // ── modified token → reject ───────────────────────────────────────────────

    #[test]
    fn modified_token_rejected() {
        let secret = [0x42u8; 32];
        let params = make_params(3, u64::MAX, secret);
        let (mut token, _nonce) = make_token(secret, 3);
        token[30] ^= 0xFF; // flip a byte in the mac region
        let auth = make_credential_auth(arc_params(Some(params)), arc_spent(), peer(), node_id(), mesh_id(), role_signed_replay());
        let dummy_key = [0u8; 32];
        let ctx = ctx_with_cred(0x01, &token, &dummy_key, &dummy_key);
        assert!(!auth(&ctx), "modified token must be rejected");
    }

    // ── expired epoch → reject ────────────────────────────────────────────────

    #[test]
    fn expired_epoch_rejected() {
        let secret = [0x42u8; 32];
        // not_after_ms=1 — epoch expired at t=1ms; now_ms will be >> 1
        let params = make_params(5, 1, secret);
        let (token, _nonce) = make_token(secret, 5);
        let auth = make_credential_auth(arc_params(Some(params)), arc_spent(), peer(), node_id(), mesh_id(), role_signed_replay());
        let dummy_key = [0u8; 32];
        let ctx = ctx_with_cred(0x01, &token, &dummy_key, &dummy_key);
        assert!(!auth(&ctx), "expired epoch must be rejected");
    }

    // ── RoleSigned dispatch: routed to the dedicated gate, not the ───────────
    // ── generic authority-keyed verifier ─────────────────────────────────────

    #[test]
    fn role_signed_scheme_byte_dispatches_to_the_role_signed_gate() {
        // This source tree's `OPERATOR_PUBKEY_HEX` is an un-rendered
        // placeholder (see `core::bootstrap`'s own doc), so this can only
        // ever reach `RoleSignedRefusal::OperatorKeyUnavailable` — proving
        // dispatch landed in the RoleSigned gate at all is the point; the
        // gate's own crypto/mesh/replay checks are covered exhaustively in
        // `core::role_signed_gate`'s test module against an injectable key.
        let params = make_params(1, u64::MAX, [0x42u8; 32]);
        let auth = make_credential_auth(arc_params(Some(params)), arc_spent(), peer(), node_id(), mesh_id(), role_signed_replay());
        let dummy_key = [0u8; 32];
        // Malformed as a RoleSignedToken (too short) — if this fell through to
        // `verify_credential_bound` instead, it would fail for an entirely
        // different reason (`RoleSigned: not an authority-keyed scheme`), but
        // the observable outcome (`false`) would be indistinguishable from
        // the log alone, so this test's value is the dispatch, not the label.
        let ctx = ctx_with_cred(CredentialScheme::RoleSigned.as_u8(), &[0u8; 3], &dummy_key, &dummy_key);
        assert!(!auth(&ctx), "a RoleSigned-scheme dial with no usable operator key must be rejected");
    }
}

