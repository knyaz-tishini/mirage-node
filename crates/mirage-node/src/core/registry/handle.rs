//! [`ListenerHandle`] — one bound listener slot's lifecycle handle.
//!
//! Every concrete listener kind (TCP NodeListener, UDP listener bank,
//! decoy peek-multiplex, udp_relay binding) will implement this trait
//! in step 3 of the rollout. Today only the trait surface lives here.

use std::net::SocketAddr;

use async_trait::async_trait;
use serde::Serialize;

use super::spec::{ListenerSpec, SpecFingerprint};
use super::spec::ListenerId;

/// Outcome of [`ListenerHandle::reconfigure`].
///
/// `Applied` — the listener accepted the new spec in-place (e.g. swapped
/// protocols, upstream pool, byte_cipher mode) without touching the
/// bound socket. The registry updates its fingerprint cache and does
/// nothing else.
///
/// `RebindRequired` — the spec diff requires re-binding the socket
/// (bind_port changed, wire shape changed, transport changed, …). The
/// registry will `deactivate` this handle and `activate` a fresh one
/// from the new spec. The listener MUST leave its state unchanged on
/// `RebindRequired` so the registry's deactivate runs on the old
/// configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconfigureOutcome {
    Applied,
    RebindRequired,
}

/// Lightweight counters reported back to the monitor.
///
/// Per-listener stats are intentionally minimal — full per-tunnel
/// observability stays on [`crate::core::runtime::NodeRuntime`]; this
/// surface only carries what the monitor needs to make scheduling /
/// reconcile decisions.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ListenerStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_conns: u32,
    pub accepted_total: u64,
    pub rejected_total: u64,
}

/// Lifecycle handle for one bound listener.
///
/// Implementors own the spawn task(s), the bound socket(s), and any
/// per-listener state (e.g. per-peer UDP session table). `shutdown` MUST
/// drain in-flight accepts and join the spawn task before returning;
/// callers may drop the box without waiting if the registry is itself
/// shutting down.
#[async_trait]
pub trait ListenerHandle: Send + Sync {
    /// Stable id matching the [`ListenerSpec`](super::spec::ListenerSpec)
    /// that produced this handle.
    fn id(&self) -> &ListenerId;

    /// Address the listener actually bound to. For a hypothetical
    /// TUN-style listener with no real socket this would be
    /// informational — the registry still needs a unique value for the
    /// reconcile report.
    fn bound_addr(&self) -> SocketAddr;

    /// Current per-listener counters. Cheap; called on every stats push.
    fn stats(&self) -> ListenerStats;

    /// Drain and stop. Idempotent — calling twice MUST NOT panic; the
    /// second call returns immediately. Returning an error is allowed
    /// but the registry treats the handle as unbound regardless.
    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Try to apply `new_spec` to this already-bound listener.
    ///
    /// Implementations must:
    /// 1. Compare every axis of `new_spec` against the spec used to bind
    ///    this listener; any change to `bind_port`, `wire`, `transport`,
    ///    or other socket-affecting axis MUST return `RebindRequired`.
    /// 2. For runtime-mutable axes (TCP: protocols/relay_mode/upstreams/dns;
    ///    UDP endpoint: byte_cipher/upstream; decoy: backends list), swap
    ///    the relevant `ArcSwap`/`ArcSwapOption` slot and return `Applied`.
    ///
    /// The default implementation rejects every diff — concrete listeners
    /// override to declare what they support.
    async fn reconfigure(
        &self,
        new_spec: &ListenerSpec,
    ) -> Result<ReconfigureOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let _ = new_spec;
        Ok(ReconfigureOutcome::RebindRequired)
    }

    /// Fingerprint of the spec this listener was bound with. Used by the
    /// registry to skip reconcile work when the spec is byte-identical.
    fn spec_fingerprint(&self) -> SpecFingerprint;

    /// Snapshot of the spec currently driving this listener. Used by
    /// `PushChainBindings` handling to synthesise an updated spec
    /// when a chain config changes — the registry takes the current
    /// spec, overlays the new byte_cipher/camouflage from the
    /// chain binding, and runs reconcile to trigger the hot-swap
    /// path. Cheap clone — `Arc<ListenerSpec>` under the hood.
    fn current_spec(&self) -> ListenerSpec;
}
