//! Factory for one UDP endpoint listener — the unit replacement for one
//! entry in [`mirage_core::config::NodeConfig::endpoint_configs`] of
//! transport=UDP.
//!
//! UDP intentionally uses the abort-on-shutdown handle: the
//! `run_server_udp` driver in `mirage-protocol` owns the socket in a
//! tight `recv_from` loop with no cancellation hook. Aborting closes the
//! socket via Drop; per-tunnel tasks already spawned remain under the
//! runtime's `active_tunnels` counter and finish on their own.
//!
//! Hot-reconfig: dispatch state (config / endpoint / outbound protocol
//! / doh resolver) is held in an [`arc_swap::ArcSwap`] and reloaded on
//! every tunnel. Reconfigure can therefore swap byte_cipher mode,
//! upstream addr, exit DNS resolver, etc. without re-binding the UDP
//! socket. Changing `bind_port` or the camouflage shape (anything that
//! affects `extract_bind_addr` or what `run_server_udp` will accept)
//! forces a rebind.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use mirage_core::config::{MirageEndpointConfig, NodeConfig, TransportKind};
use mirage_protocol::{driver::run_server_udp_with_auth, traits::TcpProtocol, ClientAuthContext};
use tokio::sync::{mpsc, Mutex};
use tracing::info;

use crate::core::doh::DoHResolver;
use crate::core::registry::handle::{ListenerHandle, ReconfigureOutcome};
use crate::core::registry::handle_impl::{
    AbortListenerHandle, AtomicListenerStats, ReconfigureFn,
};
use crate::core::registry::spec::{ListenerId, ListenerSpec};
use crate::core::runtime::NodeRuntime;
use crate::family::mirage::relay::udp_listener::{
    dispatch_tunnel_stream_hot, extract_bind_addr, UdpHotState,
};

/// Bind one UDP endpoint and dispatch its tunnels.
pub async fn activate(
    id: ListenerId,
    endpoint: MirageEndpointConfig,
    node_config: NodeConfig,
    runtime: Arc<NodeRuntime>,
    outbound_protocol: Arc<dyn TcpProtocol>,
    doh: Option<Arc<DoHResolver>>,
    spec: ListenerSpec,
) -> Result<Box<dyn ListenerHandle>, Box<dyn std::error::Error + Send + Sync>> {
    if endpoint.transport != TransportKind::Udp {
        return Err(format!(
            "udp_endpoint_listener.activate: endpoint {id} has transport={:?}, expected Udp",
            endpoint.transport
        )
        .into());
    }

    let bind_addr = extract_bind_addr(&endpoint).ok_or_else(|| {
        format!(
            "udp_endpoint_listener.activate: endpoint {id} has no bind_addr in its camouflage"
        )
    })?;

    let stats = Arc::new(AtomicListenerStats::default());
    let (tunnel_tx, tunnel_rx) = mpsc::channel(64);

    // Captured before `node_config` moves into `hot_state` below — bound into
    // credential verification as `dial_context` (see `client_auth` below).
    let node_id_bytes = node_config.node_id.as_bytes().to_vec();

    let hot_state = Arc::new(ArcSwap::new(Arc::new(UdpHotState {
        config: node_config,
        endpoint: endpoint.clone(),
        outbound_protocol,
        doh,
    })));

    // Driver task — owns the UDP socket, no cancellation point.
    // Reads the bind_addr that was extracted at activate time; rebinding
    // (port change, camouflage shape change) is a deactivate+activate.
    let keypair = runtime.keypair.clone();
    let mesh_id = runtime.mesh_id.as_bytes().to_vec();
    let endpoint_for_driver = endpoint.clone();
    let id_for_driver = id.clone();
    // Build credential-auth closure from runtime's live credential state.
    // Uses a dummy peer_addr (INADDR_ANY:0) for the log sink — the actual
    // peer_addr is only available inside the spawned per-peer task inside
    // run_server_udp_with_auth; the warn! in make_credential_auth uses it
    // only for a log annotation, so INADDR_ANY is an acceptable placeholder.
    let dummy_peer: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    // Bind the credential to THIS exit's node_id (mirrors the v9-fs onion-exit
    // path and the TCP `make_credential_auth` call sites) — closes cross-exit
    // replay for `RingMembership`-scheme tokens on the UDP data leg too.
    // Credential enforcement is unconditional (no `require` toggle) — every
    // scheme=0x00 dial is rejected regardless of `allow_legacy_v8`.
    let client_auth: Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync> =
        Arc::new(crate::core::listener::make_credential_auth(
            Arc::clone(&runtime.credential_params),
            Arc::clone(&runtime.spent_set),
            dummy_peer,
            node_id_bytes,
            runtime.mesh_id.as_bytes().to_vec(),
            Arc::clone(&runtime.role_signed_replay),
        ));
    let allow_legacy_v8 = runtime.allow_legacy_v8;
    let driver_task = tokio::spawn(async move {
        if let Err(e) = run_server_udp_with_auth(
            &endpoint_for_driver,
            &keypair,
            bind_addr,
            tunnel_tx,
            &mesh_id,
            client_auth,
            allow_legacy_v8,
        )
        .await
        {
            tracing::error!(%id_for_driver, %bind_addr, "UDP driver error: {e}");
        }
    });

    // Dispatch task — receives tunnels and routes per node mode.
    // Reads hot_state per-tunnel so reconfigure can swap upstream /
    // byte_cipher / doh without re-binding.
    let counter = Arc::clone(&runtime.active_tunnels);
    let udp_pool_registry = Arc::new(Mutex::new(HashMap::new()));
    let bind_label = bind_addr.to_string();
    let id_for_dispatch = id.clone();
    let hot_state_dispatch = Arc::clone(&hot_state);
    let dial_activity_udp = Arc::clone(&runtime.dial_activity);
    let listener_id_udp = id.0.clone();
    let dispatch_task = tokio::spawn(async move {
        dispatch_tunnel_stream_hot(
            tunnel_rx,
            hot_state_dispatch,
            counter,
            udp_pool_registry,
            bind_label,
            listener_id_udp,
            dial_activity_udp,
        )
        .await;
        tracing::debug!(%id_for_dispatch, "UDP dispatch loop exited");
    });

    info!(%id, %bind_addr, "udp_endpoint_listener bound");

    // Reconfigure: bind_port + wire identity + transport must match for
    // hot-swap. Everything else (byte_cipher, upstream, doh) can be
    // applied by swapping the ArcSwap<UdpHotState>.
    let hot_for_reconfigure = Arc::clone(&hot_state);
    let runtime_for_reconfigure = Arc::clone(&runtime);
    let reconfigure_fn: ReconfigureFn = Arc::new(move |current: &ListenerSpec,
                                                       new_spec: &ListenerSpec| {
        let hot = Arc::clone(&hot_for_reconfigure);
        let runtime = Arc::clone(&runtime_for_reconfigure);
        let current_port = current.bind_port;
        let new_port = new_spec.bind_port;
        // v2: read camouflage / byte_cipher from ingress_layer.
        let (new_camouflage, new_byte_cipher) = (
            new_spec.ingress_layer.as_ref().and_then(|l| l.camouflage.clone()),
            new_spec.ingress_layer.as_ref().and_then(|l| l.byte_cipher.clone()),
        );
        // Derive endpoint from new_spec ingress_layer axes — same logic as
        // registry::derive_udp_endpoint.  This must be Some so that
        // same-port same-camouflage upserts can be applied hot (Applied)
        // instead of always forcing a RebindRequired cycle.
        let new_endpoint: Option<mirage_core::config::MirageEndpointConfig> = {
            let bind_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                new_spec.bind_port.unwrap_or(0),
            );
            let camouflage = new_spec
                .ingress_layer
                .as_ref()
                .and_then(|l| l.camouflage.clone())
                .unwrap_or(mirage_core::config::TransportCamouflage::RawUdp { bind_addr });
            let byte_cipher_mode = new_spec
                .ingress_layer
                .as_ref()
                .and_then(|l| l.byte_cipher.clone());
            Some(mirage_core::config::MirageEndpointConfig {
                transport: mirage_core::config::TransportKind::Udp,
                auth: mirage_core::config::AuthMode::Blake3,
                camouflage,
                byte_cipher: None,
                byte_cipher_mode,
            })
        };
        Box::pin(async move {
            if current_port != new_port {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    ReconfigureOutcome::RebindRequired,
                );
            }

            // Sanity: a UDP endpoint reconfigure must carry a new
            // udp_endpoint payload. Without it we cannot derive the
            // wire-specific settings the driver expects.
            let Some(mut next_endpoint) = new_endpoint else {
                return Ok(ReconfigureOutcome::RebindRequired);
            };

            // If the camouflage shape changed in a way that moves the
            // bind_addr (i.e. extract_bind_addr returns a different
            // value than the one the driver is still bound to), we must
            // rebind. Same-shape camouflage with parameter tweaks is
            // OK because the driver only uses bind_addr at startup;
            // every subsequent dispatch reads from hot_state.
            if let Some(addr) = extract_bind_addr(&next_endpoint) {
                let bound = hot.load().endpoint.clone();
                if let Some(prev) = extract_bind_addr(&bound) {
                    if addr != prev {
                        return Ok(ReconfigureOutcome::RebindRequired);
                    }
                }
            }

            // Apply byte_cipher / camouflage changes carried on the
            // spec onto the endpoint we'll publish. The endpoint that
            // arrived on `new_spec.udp_endpoint` is authoritative;
            // these two writes only enforce that the spec-level axes
            // win if the caller forgot to align them.
            next_endpoint.byte_cipher_mode = new_byte_cipher.clone();
            if let Some(cam) = new_camouflage {
                next_endpoint.camouflage = cam;
            }

            let prev = hot.load_full();
            hot.store(Arc::new(UdpHotState {
                config: prev.config.clone(),
                endpoint: next_endpoint,
                outbound_protocol: Arc::clone(&prev.outbound_protocol),
                doh: runtime.doh.load_full(),
            }));
            Ok(ReconfigureOutcome::Applied)
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
    });

    Ok(Box::new(AbortListenerHandle::new(
        id,
        bind_addr,
        stats,
        vec![driver_task, dispatch_task],
        spec,
        Some(reconfigure_fn),
    )))
}
