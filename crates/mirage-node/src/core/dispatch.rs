//! Single dispatch point — maps `(kind, position)` from a Mirage
//! [`ListenerSpec`] to the matching activation helper on
//! [`ListenerRegistry`].
//!
//! `mirage-node` is a **Mirage-only** binary.

use std::net::SocketAddr;

use mirage_core::mirage::wire::{MirageListenerKind as ListenerKind, MirageListenerSpec as ListenerSpec};

use super::registry::handle::ListenerHandle;
use super::registry::{ListenerRegistry, RegistryError};

/// Resolve the activation handler for a Mirage `spec` and run it.
pub(crate) async fn dispatch_spec(
    registry: &ListenerRegistry,
    spec: &ListenerSpec,
    listen_addr: SocketAddr,
) -> Result<Box<dyn ListenerHandle>, RegistryError> {
    match spec.kind {
        ListenerKind::Decoy => registry.activate_decoy(spec).await,
        ListenerKind::DecoyMulti => registry.activate_multi_decoy(spec).await,
        ListenerKind::UdpRelay => registry.activate_udp_relay(spec).await,
        ListenerKind::TunnelTcp | ListenerKind::TunnelControl => {
            registry.activate_mirage_tcp(spec, listen_addr).await
        }
        ListenerKind::TunnelUdp => registry.activate_mirage_udp(spec).await,
    }
}
