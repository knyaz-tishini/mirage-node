//! Mirage Exit dispatch — one module per `ExitMode` variant.
//!
//! - [`direct`] — `ExitMode::Direct`. Read `host:port`, dial, bidi copy.
//!   DNS sub-handler ([`dns_handler`]) invoked inline when dst port=53.
//! - [`onion`] — `ExitMode::Onion`. Peel terminal AEAD, optional mux upgrade.
//! - [`control`] — `ExitMode::Control`. Bridge to monitor over-chain :19445.
#![allow(dead_code)]

pub mod control;
pub mod direct;
pub mod dns_handler;
pub mod onion;
pub mod onion_fs;
pub mod policy;
pub mod udp_fs;
