//! Unified UDP listener using the new `MirageEndpointConfig` API.
//!
//! Replaces the 9 individual UDP listener modules with a single dispatcher
//! that uses `mirage_protocol::driver::run_server_udp`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{atomic::Ordering, Arc, RwLock};

use mirage_core::{
    config::{MirageEndpointConfig, NodeConfig, NodeMode, TransportKind},
    crypto::KeyPair,
    error::{MirageError, Result},
};
use mirage_protocol::{driver::run_server_udp_with_auth, traits::TcpProtocol, ClientAuthContext};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::core::doh::DoHResolver;
use crate::family::mirage::exit::direct::handle_exit;

/// Pool registry — был UDP re-handshake инфра для CryptoRelay UDP
/// пути. После v2 чистки re-handshake удалён; тип оставлен пустым
/// alias'ом чтобы существующие сигнатуры скомпилировались без
/// массовой переписки. Под v2 UDP-relay должен идти через
/// `udp_transparent` / `udp_crypto_verify` (отдельные listener
/// factories), не через decrypted Tunnel в этом модуле.
type UdpPoolRegistry = Arc<Mutex<HashMap<(SocketAddr, [u8; 32]), ()>>>;

/// Spawn UDP listeners for all UDP entries in `config.endpoint_configs`.
///
/// For each UDP-transport endpoint config, binds a UDP socket on its configured
/// `bind_addr` and dispatches authenticated tunnels to the node mode handler.
///
/// `client_auth` — credential-verify closure (same one used by the TCP listener).
///   Wrapped in an `Arc` so it can be cloned into each per-peer spawned task.
/// `allow_legacy_v8` — when `false`, non-V9 dials are rejected with VERSION_REJECT.
///
/// Returns the number of UDP listeners spawned.
pub fn spawn_udp_listeners(
    config: &NodeConfig,
    keypair: &KeyPair,
    mesh_id: &[u8],
    active_tunnels: &Arc<std::sync::atomic::AtomicU32>,
    doh: &Option<Arc<DoHResolver>>,
    outbound_protocol: &Arc<dyn TcpProtocol>,
    client_auth: Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync>,
    allow_legacy_v8: bool,
) -> usize {
    let mut count = 0;

    for endpoint in &config.endpoint_configs {
        if endpoint.transport != TransportKind::Udp {
            continue;
        }

        let bind_addr = match extract_bind_addr(endpoint) {
            Some(a) => a,
            None => {
                warn!(?endpoint.transport, "UDP endpoint config missing bind_addr — skipping");
                continue;
            }
        };

        let (tunnel_tx, tunnel_rx) = mpsc::channel(64);

        let keypair_clone = keypair.clone();
        let mesh_id_clone = mesh_id.to_vec();
        let endpoint_clone = endpoint.clone();
        let client_auth_clone = Arc::clone(&client_auth);
        tokio::spawn(async move {
            if let Err(e) = run_server_udp_with_auth(
                &endpoint_clone,
                &keypair_clone,
                bind_addr,
                tunnel_tx,
                &mesh_id_clone,
                client_auth_clone,
                allow_legacy_v8,
            )
            .await
            {
                tracing::error!(%bind_addr, "UDP listener error: {e}");
            }
        });

        let config_clone = config.clone();
        let endpoint_for_dispatch = endpoint.clone();
        let counter_clone = Arc::clone(active_tunnels);
        let doh_clone = doh.clone();
        let outbound_clone = Arc::clone(outbound_protocol);
        let bind_addr_str = bind_addr.to_string();
        // Per-listener pool registry — lazy-created on first relay dispatch.
        let udp_pool_registry: UdpPoolRegistry =
            Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(async move {
            dispatch_tunnel_stream(
                tunnel_rx,
                config_clone,
                endpoint_for_dispatch,
                counter_clone,
                doh_clone,
                outbound_clone,
                udp_pool_registry,
                bind_addr_str,
            )
            .await;
        });

        info!(%bind_addr, "UDP listener (new API) spawned");
        count += 1;
    }

    count
}

/// Hot-swappable state for one UDP endpoint listener.
///
/// Held in an `ArcSwap<UdpHotState>` so the dispatch loop loads it per
/// tunnel — `byte_cipher_mode`, `upstream_addr`, full `NodeConfig` and
/// `MirageEndpointConfig` can all be swapped at runtime without
/// re-binding the UDP socket.
#[derive(Clone)]
pub(crate) struct UdpHotState {
    pub config: NodeConfig,
    pub endpoint: MirageEndpointConfig,
    pub outbound_protocol: Arc<dyn TcpProtocol>,
    pub doh: Option<Arc<DoHResolver>>,
}

/// Hot-reconfigurable variant of [`dispatch_tunnel_stream`] — loads
/// every dispatch decision from an `ArcSwap<UdpHotState>` so runtime
/// reconfigure can swap upstream / byte_cipher / endpoint between
/// tunnels.
///
/// `listener_id` and `dial_activity` are used for Wave 5b per-listener
/// last_dial_ms tracking. Every received tunnel stamps the current
/// timestamp so the WS scheduler can report it to the monitor.
pub(crate) async fn dispatch_tunnel_stream_hot(
    mut rx: mpsc::Receiver<Box<dyn mirage_protocol::traits::Tunnel>>,
    state: Arc<arc_swap::ArcSwap<UdpHotState>>,
    active_tunnels: Arc<std::sync::atomic::AtomicU32>,
    udp_pools: UdpPoolRegistry,
    label: String,
    listener_id: String,
    dial_activity: Arc<RwLock<HashMap<String, u64>>>,
) {
    while let Some(tunnel) = rx.recv().await {
        // Wave 5b: stamp dial activity on every received UDP tunnel.
        {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Ok(mut map) = dial_activity.write() {
                map.insert(listener_id.clone(), now_ms);
            }
        }

        let snap: Arc<UdpHotState> = state.load_full();
        let counter = Arc::clone(&active_tunnels);
        let pools = Arc::clone(&udp_pools);
        let label = label.clone();

        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            let remote_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            if let Err(e) = dispatch_to_mode(
                tunnel,
                &snap.config,
                &snap.endpoint,
                snap.doh.clone(),
                Arc::clone(&snap.outbound_protocol),
                pools,
                remote_addr,
            )
            .await
            {
                warn!(%label, "UDP tunnel error: {e}");
            }
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Receive tunnels from the driver channel and dispatch each to exit/relay.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_tunnel_stream(
    mut rx: mpsc::Receiver<Box<dyn mirage_protocol::traits::Tunnel>>,
    config: NodeConfig,
    endpoint: MirageEndpointConfig,
    active_tunnels: Arc<std::sync::atomic::AtomicU32>,
    doh: Option<Arc<DoHResolver>>,
    outbound_protocol: Arc<dyn TcpProtocol>,
    udp_pools: UdpPoolRegistry,
    label: String,
) {
    while let Some(tunnel) = rx.recv().await {
        let config_clone = config.clone();
        let endpoint_clone = endpoint.clone();
        let counter = Arc::clone(&active_tunnels);
        let doh_clone = doh.clone();
        let outbound = Arc::clone(&outbound_protocol);
        let pools = Arc::clone(&udp_pools);
        let label = label.clone();

        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            // Use a placeholder remote addr — the tunnel's transport_info has the real one.
            let remote_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            if let Err(e) = dispatch_to_mode(
                tunnel,
                &config_clone,
                &endpoint_clone,
                doh_clone,
                outbound,
                pools,
                remote_addr,
            )
            .await
            {
                warn!(%label, "UDP tunnel error: {e}");
            }
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_to_mode(
    tunnel: Box<dyn mirage_protocol::traits::Tunnel>,
    config: &NodeConfig,
    endpoint: &MirageEndpointConfig,
    doh: Option<Arc<DoHResolver>>,
    outbound_protocol: Arc<dyn TcpProtocol>,
    udp_pools: UdpPoolRegistry,
    remote_addr: SocketAddr,
) -> Result<()> {
    let _ = (endpoint, outbound_protocol, udp_pools, remote_addr);
    match &config.mode {
        NodeMode::Exit(_) => handle_exit(tunnel, doh).await,
        NodeMode::Relay(_) | NodeMode::Hybrid { .. } => {
            // Re-handshake UDP relay path удалён вместе с
            // RelayMode::CryptoRelay (нарушает per-hop isolation).
            // UDP-relay должен идти через `udp_transparent` /
            // `udp_crypto_verify` listener factories — там нет
            // decrypted Tunnel, чисто datagram-pump.
            Err(mirage_core::error::MirageError::Config(
                "udp_listener relay path удалён — переключите ноду на \
                 udp_transparent / udp_crypto_verify listener factories"
                    .into(),
            ))
        }
    }
}

/// Extract the `bind_addr` from a `MirageEndpointConfig`'s camouflage.
pub(crate) fn extract_bind_addr(config: &MirageEndpointConfig) -> Option<SocketAddr> {
    use mirage_core::config::TransportCamouflage;
    match &config.camouflage {
        TransportCamouflage::Quic { bind_addr, .. }
        | TransportCamouflage::Http3 { bind_addr, .. }
        | TransportCamouflage::Hysteria2 { bind_addr, .. }
        | TransportCamouflage::WireGuard { bind_addr, .. }
        | TransportCamouflage::RawUdp { bind_addr, .. } => Some(*bind_addr),
        _ => None,
    }
}

/// Error helper for missing upstreams.
fn _no_upstream() -> MirageError {
    MirageError::NodeUnreachable("no upstream configured".into())
}
