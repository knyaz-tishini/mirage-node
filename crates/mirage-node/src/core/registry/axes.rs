//! Re-export of [`mirage_core::mirage::wire::supported_axes`].
//!
//! The catalog types live in `mirage-core` so the monitor's
//! `mirage-mesh-config-gen` can use the same enum tags when it
//! validates a spec against a node's declared capabilities. Keep this
//! thin file so existing imports under `crate::core::registry::axes::*`
//! keep working unchanged.

pub use mirage_core::mirage::wire::supported_axes::{
    byte_cipher_kind, camouflage_kind, ByteCipherKind, CamouflageKind, SupportedAxes,
};
