use std::sync::Arc;

use mirage_core::{
    config::{
        AuthMode, MirageEndpointConfig, MirageListenerConfig, NodeConfig, NodeMode, NodeRole,
        ProtocolId, RelayMode, TcpProtocolId, TransportCamouflage, TransportKind,
    },
    crypto::KeyPair,
};
use mirage_protocol::traits::TcpProtocol;
use tracing::info;

use crate::core::endpoint_protocol::{CredentialAuthState, EndpointProtocol};
use crate::family::mirage::relay::relay_metrics::RelayMetrics;
use crate::family::mirage::relay::upstream_pool::UpstreamPool;
use crate::core::util;

/// Error type for protocol/infrastructure build failures.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("listener bind_addr parse failed: {0}")]
    BindAddrParse(String),
}

/// Result of [`build_protocols`].
pub struct BuildProtocolsResult {
    /// Ordered list of TCP protocols for the inbound listener chain.
    pub protocols: Vec<Arc<dyn TcpProtocol>>,
}

/// Build the single Mirage bare-wire TCP protocol for this node.
///
/// After Phase 1+2 cleanup only `TcpProtocolId::Mirage` (bare AEAD,
/// Blake3 auth, no outer camouflage) exists as the node handshake wire.
/// Outer camouflage is an orthogonal axis — it arrives per-listener via
/// `ingress_layer.camouflage` on each pushed `ListenerSpec` and is
/// stripped before this handshake handler is invoked.
///
/// `mesh_id` — the mesh identifier bytes baked into every BLAKE3 confirm
/// label.  Callers pass `node_toml.mesh_id.as_str()`.
///
/// `node_id` — this node's own identity, bound into credential
/// verification as `dial_context` when `credential_auth` is `Some` (closes
/// cross-exit replay for `RingMembership`-scheme tokens).
///
/// `credential_auth` — when `Some`, threads credential-verify state into
/// the `EndpointProtocol` accept path so that bare (camouflage=None) direct
/// exits enforce the same anonymous-credential policy as camouflaged exits
/// (Phase C gap closure).  The `Arc`s inside `CredentialAuthState` MUST be
/// clones of the SAME allocations stored on `NodeRuntime.credential_params`
/// / `NodeRuntime.spent_set` so that gossip-driven param updates are
/// immediately visible to the accept closure without a protocol rebuild.
/// When `None`, the accept path is byte-identical to the pre-Phase-C state.
pub fn build_protocols(
    keypair: &KeyPair,
    mesh_id: &str,
    node_id: &str,
    credential_auth: Option<CredentialAuthState>,
    allow_legacy_v8: bool,
) -> Result<BuildProtocolsResult, BuildError> {
    let config = MirageEndpointConfig {
        transport: TransportKind::Tcp,
        auth: AuthMode::Blake3,
        camouflage: TransportCamouflage::None,
        byte_cipher: None,
        byte_cipher_mode: None,
    };
    let ep = EndpointProtocol::new(
        config,
        keypair.clone(),
        TcpProtocolId::Mirage,
        mesh_id.as_bytes().to_vec(),
        node_id.as_bytes().to_vec(),
    )
    .with_allow_legacy_v8(allow_legacy_v8);
    let protocol: Arc<dyn TcpProtocol> = if let Some(ca) = credential_auth {
        Arc::new(ep.with_credential_auth(ca))
    } else {
        Arc::new(ep)
    };
    info!("TCP protocol chain built: [Mirage bare-wire]");
    Ok(BuildProtocolsResult { protocols: vec![protocol] })
}

/// Build upstream connection pools and relay metrics.
///
/// Returns `(pools, relay_metrics)`.  Both are empty / `None` for Exit mode or
/// Transparent relay mode (no pre-warmed pool needed).
pub fn build_relay_infrastructure(
    config: &NodeConfig,
    protocols: &[Arc<dyn TcpProtocol>],
) -> (Vec<Arc<UpstreamPool>>, Option<Arc<RelayMetrics>>) {
    let relay_cfg = match &config.mode {
        NodeMode::Relay(r) => r,
        NodeMode::Hybrid { relay, .. } => relay,
        NodeMode::Exit(_) => return (Vec::new(), None),
    };

    // The `TransparentTcp => no upstream pool` early return that stood here
    // went with that mode (2026-09-02). It changes NOTHING for `OnionPeel`,
    // which never matched the condition and always fell through to build the
    // pool below — the arm was reachable only by a mode that no longer exists.

    let upstream_addrs: Vec<_> = relay_cfg.upstreams.iter().map(|u| u.addr).collect();
    let relay_metrics = Arc::new(RelayMetrics::new(&upstream_addrs));

    let mut pools = Vec::with_capacity(relay_cfg.upstreams.len());

    for upstream in &relay_cfg.upstreams {
        let pk = match util::decode_hex_key(&upstream.public_key) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    addr = %upstream.addr,
                    error = %e,
                    "relay: skipping upstream — invalid public key"
                );
                continue;
            }
        };

        let outbound_protocol = protocols
            .iter()
            .find(|p| matches!(upstream.protocol, ProtocolId::Tcp(id) if id == p.id()))
            .cloned()
            .unwrap_or_else(|| {
                tracing::warn!(
                    addr = %upstream.addr,
                    protocol = %upstream.protocol,
                    "relay: no matching protocol for upstream — falling back to protocols[0]"
                );
                Arc::clone(&protocols[0])
            });

        let metrics = relay_metrics
            .for_addr(upstream.addr)
            .expect("metrics slot was just created for this addr");

        let pool = UpstreamPool::new(
            upstream.addr,
            pk,
            relay_cfg.upstream_pool_size,
            relay_cfg.upstream_pool_max_idle_secs,
            outbound_protocol,
            metrics,
        );

        info!(
            addr = %upstream.addr,
            pool_size = relay_cfg.upstream_pool_size,
            protocol = %upstream.protocol,
            "relay: upstream pool created"
        );

        pools.push(pool);
    }

    (pools, Some(relay_metrics))
}

/// Walk `NodeRole.mirage_listeners` (when set) and report the declared
/// [`MirageListenerConfig`] list for the current node — drives the per-listener
/// dispatch in `main.rs::run`. Empty for nodes that pre-date the role-split
/// (defaulted to `HopNode { mirage_listeners: vec![] }`).
#[allow(dead_code)]
pub fn mirage_listeners(config: &NodeConfig) -> &[MirageListenerConfig] {
    match &config.role {
        NodeRole::EntryNode { mirage_listeners, .. } => mirage_listeners,
        NodeRole::HopNode { mirage_listeners } => mirage_listeners,
        NodeRole::ExitNode { mirage_listeners, .. } => mirage_listeners,
    }
}
