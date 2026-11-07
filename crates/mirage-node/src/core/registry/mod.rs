//! Runtime listener registry — target architecture for monitor-pushed listener
//! sets (see `mirage2node/docs/runtime-configurator-spec.md`).
//!
//! This module currently provides only the trait + data-model surface. No
//! existing call sites have been ported; the legacy spawn paths in
//! [`crate::core::configurator_main`] still own the lifecycle of every bound
//! socket. Step 3 of the rollout (factory port) will replace those direct
//! spawn sites with [`ListenerRegistry::activate`] calls.
//!
//! `#[allow(dead_code)]` is applied here while the surface is unused — it
//! will be removed in step 3 when the factory port lands and every item
//! gains real call sites.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod spec;
pub mod handle;
pub mod handle_impl;
pub mod axes;
pub mod decoy;
pub mod registry;
pub mod selector;

pub use axes::{
    byte_cipher_kind, camouflage_kind, ByteCipherKind, CamouflageKind, SupportedAxes,
};
pub use handle::{ListenerHandle, ListenerStats, ReconfigureOutcome};
pub use handle_impl::{
    AbortListenerHandle, AtomicListenerStats, ReconfigureFn, TaskListenerHandle,
};
pub use registry::{ActivationContext, ListenerRegistry, ReconcileReport, RegistryError};
pub use spec::{
    ChainRoleHint, DecoyRef, ListenerId, ListenerKind,
    ListenerSpec, SpecFingerprint, UpstreamRef,
};
