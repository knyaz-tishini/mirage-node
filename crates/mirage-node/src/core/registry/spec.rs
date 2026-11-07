//! Re-exports of listener spec types from canonical `mirage_core::mirage::wire`.
//!
//! Thin indirection so existing imports under `crate::core::registry::spec::*`
//! keep working unchanged after the Phase 1.6 shim removal.

pub use mirage_core::mirage::wire::{
    ChainRole as ChainRoleHint,
    DecoyRef,
    ListenerId,
    MirageListenerKind as ListenerKind,
    MirageListenerSpec as ListenerSpec,
    SpecFingerprint,
    UpstreamRef,
};
