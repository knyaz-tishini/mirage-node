//! The decoy seam — the OSS node knows the decoy LISTENER KIND, the fleet
//! owns the decoy FRONT.
//!
//! A decoy listener is fleet policy: where to plant a front, which backends
//! it answers from, how it rate-limits a prober. None of that is data-plane
//! machinery the OSS node should own, and the standalone server must not be
//! able to serve one at all.
//!
//! So the OSS registry keeps the *kind* (`ListenerKind::Decoy` /
//! `ListenerKind::DecoyMulti`) and calls through this seam, and the fleet
//! crate installs an activator that binds the actual front. A node with no
//! activator installed refuses a decoy spec outright — it never silently
//! accepts one and serves nothing.
//!
//! The activator is process-wide on purpose: there is exactly one node
//! runtime per process, and the decoy front is chosen once at boot, before
//! any listener spec arrives.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use super::handle::ListenerHandle;
use super::registry::RegistryError;
use super::spec::ListenerSpec;

/// What a decoy activation returns — the bound listener's lifecycle handle.
pub type DecoyActivation = Result<Box<dyn ListenerHandle>, RegistryError>;

/// The future a decoy activator returns.
pub type DecoyActivationFuture = Pin<Box<dyn Future<Output = DecoyActivation> + Send>>;

/// The fleet-installed decoy activator: given a decoy listener spec, bind
/// the decoy front it describes.
pub type DecoyActivator = dyn Fn(ListenerSpec) -> DecoyActivationFuture + Send + Sync;

static ACTIVATOR: OnceLock<Arc<DecoyActivator>> = OnceLock::new();

/// Install the fleet's decoy activator.
///
/// Returns `true` when this call installed it, `false` when one was already
/// installed (the first installation wins — a node serves one decoy front).
pub fn install_decoy_activator(activator: Arc<DecoyActivator>) -> bool {
    ACTIVATOR.set(activator).is_ok()
}

/// The installed activator, if the fleet installed one.
pub fn decoy_activator() -> Option<&'static Arc<DecoyActivator>> {
    ACTIVATOR.get()
}

/// Activate a decoy listener through the installed activator.
///
/// A node with no activator installed refuses the spec — loudly, as an
/// unsupported axis, never as a silent no-op.
pub async fn activate(spec: &ListenerSpec) -> DecoyActivation {
    let activator = ACTIVATOR.get().ok_or_else(|| RegistryError::UnsupportedAxis {
        reason: format!(
            "spec {} is a decoy listener, and this node has no decoy front installed",
            spec.id
        ),
    })?;
    (activator)(spec.clone()).await
}
