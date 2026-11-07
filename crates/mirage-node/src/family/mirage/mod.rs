//! Mirage native family — three orthogonal axes:
//!
//! - [`listener`] — what binds on the socket (TunnelTcp/Udp/Control,
//!   UdpRelay, Decoy/DecoyMulti).
//! - [`relay`] — Entry/Hop dispatch (Transparent / CryptoVerify / OnionPeel).
//! - [`exit`] — Exit dispatch (Direct / Onion / Control, with
//!   `dns_handler` as a sub-handler inside `direct`).
//!
//! Each axis has its own module. Single dispatch sites compose them
//! through `core::dispatch::dispatch`.
#![allow(dead_code)]

pub mod exit;
pub mod listener;
pub mod relay;
