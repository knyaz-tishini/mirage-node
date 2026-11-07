//! Mirage listener factories — one per `ListenerKind`.
//!
//! - [`tunnel_tcp`] / [`tunnel_udp`] — main TCP / UDP Mirage AEAD listeners.
//! - [`tunnel_control`] — exit-bridge to monitor :19445 (control plane data).
//! - [`udp_relay`] — multi-hop UDP relay (no Mirage AEAD on this hop).
//!
//! The decoy peek-multiplex front is NOT here: it is fleet policy and lives
//! in the `mirage-node-fleet` crate, which installs it into
//! [`crate::core::registry::decoy`].
#![allow(dead_code)]

pub mod tunnel_tcp;
pub mod tunnel_udp;
pub mod udp_relay;
